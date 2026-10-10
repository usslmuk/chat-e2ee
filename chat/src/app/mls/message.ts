import { gcm } from "@noble/ciphers/aes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { NK, NN } from "./hpke.ts";
import { expandWithLabel } from "./schedule.ts";
import { Buf, Writer } from "./wire.ts";

export const WIRE_PUBLIC = 1;
export const WIRE_PRIVATE = 2;
export const APPLICATION = 1;
export const PROPOSAL = 2;
export const COMMIT = 3;

export type SenderData = {
  leaf: number;
  generation: number;
  guard: Uint8Array;
};

export function writeSenderData(s: SenderData): Uint8Array {
  return new Writer().u32(s.leaf).u32(s.generation).raw(s.guard).out();
}

export function readSenderData(b: Buf): SenderData {
  const leaf = b.u32();
  const generation = b.u32();
  return { leaf, generation, guard: b.take(4) };
}

function sample(ct: Uint8Array): Uint8Array {
  return ct.length <= 32 ? ct : ct.slice(0, 32);
}

export function openAead(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Uint8Array {
  return gcm(key, nonce, aad).decrypt(ct);
}

export function senderDataKeys(senderDataSecret: Uint8Array, ct: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const s = sample(ct);
  return {
    key: expandWithLabel(senderDataSecret, "key", s, NK),
    nonce: expandWithLabel(senderDataSecret, "nonce", s, NN),
  };
}

function guardNonce(ratchet: Uint8Array, guard: Uint8Array): Uint8Array {
  const out = Uint8Array.from(ratchet);
  for (let i = 0; i < 4 && i < NN; i++) out[i] ^= guard[i];
  return out;
}

function xorNonce(ratchet: Uint8Array, key: Uint8Array, guard: Uint8Array): Uint8Array {
  void key;
  return guardNonce(ratchet, guard);
}

export function privateContentAad(groupId: Uint8Array, epoch: number, ctype: number, auth: Uint8Array): Uint8Array {
  return new Writer().vec(groupId).u64(epoch).u8(ctype).vec(auth).out();
}

export function senderDataAad(groupId: Uint8Array, epoch: number, ctype: number): Uint8Array {
  return new Writer().vec(groupId).u64(epoch).u8(ctype).out();
}

export type Sealed = {
  encryptedSenderData: Uint8Array;
  ciphertext: Uint8Array;
  generation: number;
  leaf: number;
};

export function sealPrivate(
  groupId: Uint8Array,
  epoch: number,
  ctype: number,
  auth: Uint8Array,
  body: Uint8Array,
  senderDataSecret: Uint8Array,
  ratchetKey: Uint8Array,
  ratchetNonce: Uint8Array,
  leaf: number,
  generation: number,
): Sealed {
  const guard = randomBytes(4);
  const contentAad = privateContentAad(groupId, epoch, ctype, auth);
  const nonce = xorNonce(ratchetNonce, ratchetKey, guard);
  const ciphertext = gcm(ratchetKey, nonce, contentAad).encrypt(body);
  const k = senderDataKeys(senderDataSecret, ciphertext);
  const sd = writeSenderData({ leaf, generation, guard });
  const encryptedSenderData = gcm(k.key, k.nonce, senderDataAad(groupId, epoch, ctype)).encrypt(sd);
  k.key.fill(0);
  k.nonce.fill(0);
  nonce.fill(0);
  return { encryptedSenderData, ciphertext, generation, leaf };
}

export function openPrivate(
  groupId: Uint8Array,
  epoch: number,
  ctype: number,
  auth: Uint8Array,
  encryptedSenderData: Uint8Array,
  ciphertext: Uint8Array,
  senderDataSecret: Uint8Array,
  keysFor: (leaf: number, generation: number) => { key: Uint8Array; nonce: Uint8Array },
): { body: Uint8Array; leaf: number; generation: number } {
  const k = senderDataKeys(senderDataSecret, ciphertext);
  const sdBytes = gcm(k.key, k.nonce, senderDataAad(groupId, epoch, ctype)).decrypt(encryptedSenderData);
  k.key.fill(0);
  k.nonce.fill(0);
  const sd = readSenderData(new Buf(sdBytes));
  const rk = keysFor(sd.leaf, sd.generation);
  const nonce = xorNonce(rk.nonce, rk.key, sd.guard);
  const body = gcm(rk.key, nonce, privateContentAad(groupId, epoch, ctype, auth)).decrypt(ciphertext);
  nonce.fill(0);
  rk.key.fill(0);
  rk.nonce.fill(0);
  return { body, leaf: sd.leaf, generation: sd.generation };
}

export function membershipTag(membershipKey: Uint8Array, tbs: Uint8Array, auth: Uint8Array): Uint8Array {
  return hmac(sha256, membershipKey, new Writer().vec(tbs).vec(auth).out());
}

export function confirmationTag(confirmKey: Uint8Array, confirmed: Uint8Array): Uint8Array {
  return hmac(sha256, confirmKey, confirmed);
}

export function authData(signature: Uint8Array, confirmation: Uint8Array | null): Uint8Array {
  const w = new Writer().vec(signature);
  if (confirmation) w.vec(confirmation);
  return w.out();
}

export type Public = {
  version: number;
  ctype: number;
  framed: Uint8Array;
  body: Uint8Array;
  authSig: Uint8Array;
  confirmation: Uint8Array | null;
  signature: Uint8Array;
};

export function sealPublic(
  version: number,
  ctype: number,
  framed: Uint8Array,
  body: Uint8Array,
  authSig: Uint8Array,
  confirmation: Uint8Array | null,
  signature: Uint8Array,
): Uint8Array {
  const w = new Writer().u16(version).u16(WIRE_PUBLIC).u8(ctype);
  if (ctype === APPLICATION) w.vec(body);
  else w.raw(body);
  return w.raw(authData(authSig, confirmation)).vec(signature).out();
}

export function openPublic(b: Buf): Public {
  const version = b.u16();
  b.u16();
  const ctype = b.u8();
  const framedStart = b.pos;
  const body = ctype === APPLICATION ? b.vec() : b.rest();
  const framed = b.slice(framedStart, b.pos);
  const authSig = b.vec();
  const confirmation = ctype === COMMIT ? b.vec() : null;
  const signature = b.vec();
  return { version, ctype, framed, body, authSig, confirmation, signature };
}