import { ed25519 } from "@noble/curves/ed25519.js";
import * as K from "./hpke.ts";
import * as S from "./schedule.ts";
import * as F from "./frame.ts";
import { Buf, Writer } from "./wire.ts";
import { EMPTY } from "./zero.ts";

export const PSK_EXTERNAL = 1;
export const PSK_RESUMPTION = 2;
export const USAGE_REINIT = 1;
export const USAGE_BRANCH = 2;
export const USAGE_RESUME = 3;
export const EXT_REQUIRED_CAPABILITIES = 1;
export const EXT_EXTERNAL_SENDERS = 2;
export const EXT_RATCHET_TREE = 3;

export type PskId = {
  t: number;
  id?: Uint8Array;
  usage?: number;
  groupId?: Uint8Array;
  epoch?: number;
  nonce: Uint8Array;
};

export function writePskId(p: PskId): Uint8Array {
  const w = new Writer().u8(p.t);
  if (p.t === PSK_EXTERNAL) w.vec(p.id ?? EMPTY);
  else w.u8(p.usage ?? USAGE_RESUME).vec(p.groupId ?? EMPTY).u64(p.epoch ?? 0);
  return w.vec(p.nonce).out();
}

export function readPskId(b: Buf): PskId {
  const t = b.u8();
  if (t === PSK_EXTERNAL) return { t, id: b.vec(), nonce: b.vec() };
  const usage = b.u8();
  const groupId = b.vec();
  const epoch = b.u64();
  return { t, usage, groupId, epoch, nonce: b.vec() };
}

export function freshNonce(): Uint8Array {
  return K.fresh();
}

export type Resumption = {
  groupId: Uint8Array;
  epoch: number;
  treeHash: Uint8Array;
  confirmed: Uint8Array;
  psk: Uint8Array;
};

export function resumptionId(groupId: Uint8Array, epoch: number, usage: number): Uint8Array {
  return new Writer().vec(groupId).u64(epoch).u8(usage).out();
}

export function resumptionSecret(external: Uint8Array, groupId: Uint8Array, epoch: number, usage: number): Uint8Array {
  return S.makePskSecret(
    [S.deriveSecret(external, "external psk")],
    [resumptionId(groupId, epoch, usage)],
  );
}

export function externalSendersBody(signers: Uint8Array[]): Uint8Array {
  const w = new Writer();
  for (const pub of signers) w.vec(pub);
  return w.out();
}

export function readExternalSenders(b: Buf): Uint8Array[] {
  const out: Uint8Array[] = [];
  while (!b.done) out.push(b.vec());
  return out;
}

export function extension(id: number, data: Uint8Array): Uint8Array {
  return new Writer().u16(id).vec(data).out();
}

export function writeExtensions(list: Uint8Array[]): Uint8Array {
  const w = new Writer();
  for (const e of list) w.u16(e.length).vec(e);
  return w.out();
}

export function readExtensions(b: Buf): Uint8Array[] {
  const out: Uint8Array[] = [];
  while (!b.done) out.push(b.take(b.u16()));
  return out;
}

export function groupContextExt(id: Uint8Array, epoch: number, suite: number, th: Uint8Array, confirmed: Uint8Array, ext: Uint8Array): Uint8Array {
  return new Writer().u16(F.VERSION).u16(suite).vec(id).u64(epoch).vec(th).vec(confirmed).vec(ext).out();
}

export function externalKeyPair(secret: Uint8Array): K.Key {
  return K.derivePair(S.deriveSecret(secret, "external"));
}

export function externalSignatureKey(seed: Uint8Array): { priv: Uint8Array; pub: Uint8Array } {
  const priv = ed25519.utils.randomSecretKey(seed.slice(0, 32));
  return { priv, pub: ed25519.getPublicKey(priv) };
}

export function signedWithLabel(priv: Uint8Array, label: string, body: Uint8Array): Uint8Array {
  return ed25519.sign(F.tbsLabel(label, body), priv);
}

export function verifiedWithLabel(pub: Uint8Array, label: string, body: Uint8Array, sig: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, F.tbsLabel(label, body), pub);
  } catch {
    return false;
  }
}