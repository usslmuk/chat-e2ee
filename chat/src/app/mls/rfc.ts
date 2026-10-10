import { gcm } from "@noble/ciphers/aes.js";
import { Buf, Writer } from "./wire.ts";
import { NK, NN } from "./hpke.ts";
import { expandWithLabel } from "./schedule.ts";
import { readPskId } from "./psk.ts";

export type GroupSecrets = {
  joiner: Uint8Array;
  pathSecret: Uint8Array | null;
  psks: Uint8Array[];
};

export function readGroupSecrets(b: Buf): GroupSecrets {
  const joiner = b.vec();
  const pathSecret = b.none() ? null : b.vec();
  const pb = new Buf(b.vec());
  const psks: Uint8Array[] = [];
  while (!pb.done) {
    const start = pb.pos;
    readPskId(pb);
    psks.push(pb.slice(start, pb.pos));
  }
  return { joiner, pathSecret, psks };
}

export function writeGroupSecrets(g: GroupSecrets): Uint8Array {
  const w = new Writer().vec(g.joiner);
  if (g.pathSecret) w.none(true).vec(g.pathSecret);
  else w.none(false);
  const pb = new Writer();
  for (const p of g.psks) pb.raw(p);
  return w.vec(pb.out()).out();
}

export function welcomeKey(welcomeSecret: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  return {
    key: expandWithLabel(welcomeSecret, "key", new Uint8Array(0), NK),
    nonce: expandWithLabel(welcomeSecret, "nonce", new Uint8Array(0), NN),
  };
}

export function openGroupInfo(welcomeSecret: Uint8Array, encrypted: Uint8Array): Uint8Array {
  const { key, nonce } = welcomeKey(welcomeSecret);
  const pt = gcm(key, nonce, new Uint8Array(0)).decrypt(encrypted);
  key.fill(0);
  nonce.fill(0);
  return pt;
}

export function sealGroupInfo(welcomeSecret: Uint8Array, groupInfo: Uint8Array): Uint8Array {
  const { key, nonce } = welcomeKey(welcomeSecret);
  const ct = gcm(key, nonce, new Uint8Array(0)).encrypt(groupInfo);
  key.fill(0);
  nonce.fill(0);
  return ct;
}

export const WIRE_WELCOME = 3;
export const WIRE_GROUP_INFO = 4;
export const WIRE_KEY_PACKAGE = 5;

export type WelcomeSecret = {
  ref: Uint8Array;
  kemOutput: Uint8Array;
  ciphertext: Uint8Array;
};

export type WelcomeRfc = {
  version: number;
  suite: number;
  secrets: WelcomeSecret[];
  encryptedGroupInfo: Uint8Array;
};

export function writeWelcome(w: WelcomeRfc): Uint8Array {
  const body = new Writer();
  for (const s of w.secrets) {
    body.vec(s.ref).vec(s.kemOutput).vec(s.ciphertext);
  }
  return new Writer()
    .u16(w.version)
    .u16(WIRE_WELCOME)
    .u16(w.suite)
    .vec(body.out())
    .vec(w.encryptedGroupInfo)
    .out();
}

export function readWelcome(b: Buf): WelcomeRfc {
  const version = b.u16();
  const wire = b.u16();
  if (wire !== WIRE_WELCOME) throw new Error("not a welcome");
  const suite = b.u16();
  const secretsBuf = b.vec();
  const encryptedGroupInfo = b.vec();
  const sb = new Buf(secretsBuf);
  const secrets: WelcomeSecret[] = [];
  while (!sb.done) {
    const ref = sb.vec();
    const kemOutput = sb.vec();
    const ciphertext = sb.vec();
    secrets.push({ ref, kemOutput, ciphertext });
  }
  return { version, suite, secrets, encryptedGroupInfo };
}

export function welcomeSecretLabel(encryptedGroupInfo: Uint8Array): Uint8Array {
  return new Writer().vec(encryptedGroupInfo).out();
}

export type GroupInfoRfc = {
  version: number;
  suite: number;
  groupId: Uint8Array;
  epoch: number;
  treeHash: Uint8Array;
  confirmedTranscriptHash: Uint8Array;
  contextExtensions: Uint8Array;
  infoExtensions: Uint8Array;
  confirmationTag: Uint8Array;
  signer: number;
  signature: Uint8Array;
  extensions: Uint8Array[];
  tree: Uint8Array | null;
};

const EXT_RATCHET_TREE = 2;

export function groupInfoTbs(g: Omit<GroupInfoRfc, "signature">): Uint8Array {
  return new Writer()
    .u16(g.version)
    .u16(g.suite)
    .vec(g.groupId)
    .u64(g.epoch)
    .vec(g.treeHash)
    .vec(g.confirmedTranscriptHash)
    .vec(g.contextExtensions)
    .vec(g.infoExtensions)
    .vec(g.confirmationTag)
    .u32(g.signer)
    .out();
}

export function writeGroupInfoRfc(g: GroupInfoRfc): Uint8Array {
  return new Writer()
    .u16(g.version)
    .u16(g.suite)
    .raw(groupInfoTbs(g))
    .vec(g.signature)
    .out();
}

export function readGroupInfoRfc(b: Buf): GroupInfoRfc {
  const version = b.u16();
  const suite = b.u16();
  const groupId = b.vec();
  const epoch = b.u64();
  const treeHash = b.vec();
  const confirmedTranscriptHash = b.vec();
  const contextExtensions = b.vec();
  const infoExtensions = b.vec();
  const confirmationTag = b.vec();
  const signer = b.u32();
  const signature = b.vec();

  const extensions: Uint8Array[] = [];
  let tree: Uint8Array | null = null;
  const eb = new Buf(infoExtensions);
  while (!eb.done) {
    const start = eb.pos;
    const id = eb.u16();
    const data = eb.vec();
    extensions.push(eb.slice(start, eb.pos));
    if (id === EXT_RATCHET_TREE) tree = data;
  }

  return {
    version,
    suite,
    groupId,
    epoch,
    treeHash,
    confirmedTranscriptHash,
    contextExtensions,
    infoExtensions,
    confirmationTag,
    signer,
    signature,
    extensions,
    tree,
  };
}

export function extensionBytes(id: number, data: Uint8Array): Uint8Array {
  return new Writer().u16(id).vec(data).out();
}

export function ratchetTreeExtension(tree: Uint8Array): Uint8Array {
  return extensionBytes(EXT_RATCHET_TREE, tree);
}