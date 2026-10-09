import { sha256 } from "@noble/hashes/sha2.js";
import { Buf, Writer } from "./wire.ts";

export const VERSION = 1;
export const SUITE = 1;
export const APPLICATION = 1;
export const PROPOSAL = 2;
export const COMMIT = 3;
export const MEMBER = 1;
export const ADD = 1;
export const UPDATE = 2;
export const REMOVE = 3;
export const PSK = 5;
export const SRC_KEY_PACKAGE = 1;
export const SRC_UPDATE = 2;
export const SRC_COMMIT = 3;
export const WIRE_PUBLIC = 1;
export const WIRE_PRIVATE = 2;

export type Leaf = {
  enc: Uint8Array;
  sig: Uint8Array;
  cred: Uint8Array;
  source: number;
  parentHash: Uint8Array | null;
};

export type Par = {
  enc: Uint8Array;
  sig: Uint8Array;
  parentHash: Uint8Array;
};

export function writeLeafNode(v: Leaf): Uint8Array {
  const w = new Writer().vec(v.enc).vec(v.sig).vec(v.cred).u8(v.source);
  if (v.source === SRC_KEY_PACKAGE) w.u64(0).u64(0);
  else if (v.source === SRC_COMMIT) w.vec(v.parentHash ?? new Uint8Array(0));
  return w.out();
}

export function readLeafNode(b: Buf): Leaf {
  const enc = b.vec();
  const sig = b.vec();
  const cred = b.vec();
  const source = b.u8();
  let parentHash: Uint8Array | null = null;
  if (source === SRC_KEY_PACKAGE) {
    b.u64();
    b.u64();
  } else if (source === SRC_COMMIT) {
    parentHash = b.vec();
  }
  return { enc, sig, cred, source, parentHash };
}

export function writeParentNode(v: Par): Uint8Array {
  return new Writer().vec(v.enc).vec(v.sig).vec(v.parentHash).out();
}

export function readParentNode(b: Buf): Par {
  return { enc: b.vec(), sig: b.vec(), parentHash: b.vec() };
}

export type Proposal =
  | { t: 1; pkg: Uint8Array }
  | { t: 2; pkg: Uint8Array }
  | { t: 3; leaf: number }
  | { t: 5; psk: Uint8Array };

export function writeProposal(p: Proposal): Uint8Array {
  const w = new Writer().u8(p.t);
  if (p.t === 3) w.u32(p.leaf);
  else if (p.t === 5) w.vec(p.psk);
  else w.vec(p.pkg);
  return w.out();
}

export function readProposal(b: Buf): Proposal {
  const t = b.u8();
  if (t === 3) return { t, leaf: b.u32() };
  if (t === 5) return { t, psk: b.vec() };
  if (t === 1 || t === 2) return { t, pkg: b.vec() };
  throw new Error("bad proposal type");
}

export type PathNode = { enc: Uint8Array; kemOutput: Uint8Array };

export type UpdatePath = { leaf: Leaf; nodes: PathNode[] };

export function writePath(p: UpdatePath): Uint8Array {
  const nw = new Writer();
  for (const n of p.nodes) nw.vec(n.enc).vec(n.kemOutput);
  return new Writer().vec(writeLeafNode(p.leaf)).vec(nw.out()).out();
}

export function readPath(b: Buf): UpdatePath {
  const leaf = readLeafNode(new Buf(b.vec()));
  const blob = new Buf(b.vec());
  const nodes: PathNode[] = [];
  while (!blob.done) nodes.push({ enc: blob.vec(), kemOutput: blob.vec() });
  return { leaf, nodes };
}

export function writeCommit(path: UpdatePath | null, proposals: Proposal[]): Uint8Array {
  const w = new Writer().none(path !== null);
  if (path) w.vec(writePath(path));
  const pw = new Writer();
  for (const p of proposals) pw.vec(writeProposal(p));
  w.vec(pw.out());
  return w.out();
}

export function framed(groupId: Uint8Array, epoch: number, leaf: number, auth: Uint8Array, ctype: number, body: Uint8Array): Uint8Array {
  return new Writer().vec(groupId).u64(epoch).u8(MEMBER).u32(leaf).vec(auth).u8(ctype).vec(body).out();
}

export type Framed = {
  groupId: Uint8Array;
  epoch: number;
  sender: number;
  auth: Uint8Array;
  ctype: number;
  body: Uint8Array;
};

export function readFramed(b: Buf): Framed {
  const groupId = b.vec();
  const epoch = b.u64();
  const kind = b.u8();
  if (kind !== MEMBER) throw new Error("external sender");
  return {
    groupId,
    epoch,
    sender: b.u32(),
    auth: b.vec(),
    ctype: b.u8(),
    body: b.vec()
  };
}

export function groupContext(groupId: Uint8Array, epoch: number, suite: number, treeHash: Uint8Array, confirmed: Uint8Array): Uint8Array {
  return new Writer().u16(VERSION).u16(suite).vec(groupId).u64(epoch).vec(treeHash).vec(confirmed).out();
}

export function contentTbs(wire: number, content: Uint8Array, ctx: Uint8Array): Uint8Array {
  return contentTbsExt(wire, content, ctx, new Uint8Array(0));
}

export function contentTbsExt(wire: number, content: Uint8Array, ctx: Uint8Array, ext: Uint8Array): Uint8Array {
  return new Writer().u16(VERSION).u16(wire).vec(content).vec(ctx).vec(ext).out();
}

export function externalFramed(groupId: Uint8Array, epoch: number, senderIndex: number, auth: Uint8Array, ctype: number, body: Uint8Array): Uint8Array {
  return new Writer().vec(groupId).u64(epoch).u8(2).u32(senderIndex).vec(auth).u8(ctype).vec(body).out();
}

export function externalTbs(wire: number, content: Uint8Array): Uint8Array {
  return new Writer().u16(VERSION).u16(wire).vec(content).out();
}

export function confirmedInput(wire: number, content: Uint8Array, signature: Uint8Array): Uint8Array {
  return new Writer().u16(wire).vec(content).vec(signature).out();
}

export function nextConfirmed(prev: Uint8Array, wire: number, content: Uint8Array, signature: Uint8Array): Uint8Array {
  return sha256(new Writer().vec(prev).vec(confirmedInput(wire, content, signature)).out());
}

export function nextInterim(confirmed: Uint8Array, tag: Uint8Array): Uint8Array {
  return sha256(new Writer().vec(confirmed).vec(tag).out());
}

export function tbsLabel(label: string, body: Uint8Array): Uint8Array {
  const l = new TextEncoder().encode("MLS 1.0 " + label);
  return new Writer().vec(l).vec(body).out();
}

export function keyPackageTbs(sigPub: Uint8Array, initPub: Uint8Array, notBefore: number, notAfter: number): Uint8Array {
  return new Writer().u16(VERSION).vec(sigPub).vec(initPub).vec(sigPub).u64(notBefore).u64(notAfter).out();
}

export function keyPackage(
  sigPub: Uint8Array,
  initPub: Uint8Array,
  notBefore: number,
  notAfter: number,
  leafSig: Uint8Array,
  sign: (msg: Uint8Array) => Uint8Array,
): Uint8Array {
  const body = keyPackageTbs(sigPub, initPub, notBefore, notAfter);
  return new Writer().vec(body).vec(sign(tbsLabel("KeyPackageTBS", body))).vec(leafSig).out();
}

export function keyPackageRef(pkg: Uint8Array): Uint8Array {
  return sha256(pkg);
}

export function leafTbs(v: Leaf, groupId: Uint8Array | null, index: number, notBefore: number, notAfter: number): Uint8Array {
  const w = new Writer().u16(VERSION).vec(v.enc).vec(v.cred).u8(v.source);
  if (v.source === SRC_KEY_PACKAGE) w.u64(notBefore).u64(notAfter);
  else w.vec(v.parentHash ?? new Uint8Array(0)).vec(groupId ?? new Uint8Array(0)).u32(index);
  return w.out();
}

export function parentHashTbs(enc: Uint8Array, ph: Uint8Array, siblingHash: Uint8Array): Uint8Array {
  return new Writer().vec(enc).vec(ph).vec(siblingHash).out();
}

export function parentHashOf(enc: Uint8Array, ph: Uint8Array, siblingHash: Uint8Array): Uint8Array {
  return sha256(parentHashTbs(enc, ph, siblingHash));
}