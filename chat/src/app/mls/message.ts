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
  return new Writer().u32(s.leaf).u32(s.generation).vec(s.guard).out();
}

export function readSenderData(b: Buf): SenderData {
  return { leaf: b.u32(), generation: b.u32(), guard: b.vec() };
}

function sample(ct: Uint8Array): Uint8Array {
  return ct.length <= 32 ? ct : ct.slice(0, 32);
}

export function senderDataKeys(senderDataSecret: Uint8Array, ct: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const s = sample(ct);
  return {
    key: expandWithLabel(senderDataSecret, "key", s, NK),
    nonce: expandWithLabel(senderDataSecret, "nonce", s, NN),
  };
}

function guardNonce(key: Uint8Array, guard: Uint8Array): Uint8Array {
  const g = gcm(key, new Uint8Array(NN)).encrypt(guard);
  const out = new Uint8Array(NN);
  out.set(g.slice(0, NN));
  return out;
}

function xorNonce(ratchet: Uint8Array, key: Uint8Array, guard: Uint8Array): Uint8Array {
  const g = guardNonce(key, guard);
  const out = new Uint8Array(NN);
  for (let i = 0; i < NN; i++) out[i] = ratchet[i] ^ g[i];
  return out;
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