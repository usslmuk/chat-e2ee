import { x25519 } from "@noble/curves/ed25519.js";
import { gcm } from "@noble/ciphers/aes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "@noble/hashes/utils.js";

export const NH = 32;
export const NK = 16;
export const NN = 12;

const KEM_ID = 32;
const KDF_ID = 1;
const AEAD_ID = 1;
const MODE_BASE = 0;

const enc = new TextEncoder();

function cat(...p: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const x of p) n += x.length;
  const v = new Uint8Array(n);
  let o = 0;
  for (const x of p) {
    v.set(x, o);
    o += x.length;
  }
  return v;
}

function u16(v: number): Uint8Array {
  return new Uint8Array([(v >> 8) & 255, v & 255]);
}

function extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  const s = salt.length === 0 ? new Uint8Array(NH) : salt;
  return hmac(sha256, s, ikm);
}

function expand(prk: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  const out: number[] = [];
  let i = 1;
  while (out.length < len) {
    const t = hmac(sha256, prk, cat(info, new Uint8Array([i])));
    for (let j = 0; j < t.length; j++) out.push(t[j]);
    i++;
  }
  return new Uint8Array(out.slice(0, len));
}

const kemSuite = cat(enc.encode("HPKE-v1"), enc.encode("KEM"), u16(KEM_ID));
const kdfSuite = cat(enc.encode("HPKE-v1"), enc.encode("HPKE"), u16(KEM_ID), u16(KDF_ID), u16(AEAD_ID));

function kemExtract(salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return extract(salt, cat(kemSuite, enc.encode(label), ikm));
}

function kemExpand(prk: Uint8Array, label: string, info: Uint8Array, len: number): Uint8Array {
  return expand(prk, cat(u16(len), kemSuite, enc.encode(label), info), len);
}

function kdfExtract(salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return extract(salt, cat(kdfSuite, enc.encode(label), ikm));
}

function kdfExpand(prk: Uint8Array, label: string, info: Uint8Array, len: number): Uint8Array {
  return expand(prk, cat(u16(len), kdfSuite, enc.encode(label), info), len);
}

export type Key = { priv: Uint8Array; pub: Uint8Array };

export function keygen(): Key {
  const priv = x25519.utils.randomSecretKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

function dh(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  const s = x25519.getSharedSecret(priv, pub);
  if (s.length !== NH) throw new Error("bad dh result");
  return s;
}

function extractExpand(dhOut: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const prk = kemExtract(new Uint8Array(0), "eae_prk", dhOut);
  const out = kemExpand(prk, "shared_secret", kemContext, NH);
  prk.fill(0);
  return out;
}

export function encap(pk: Uint8Array): { shared: Uint8Array; kemOutput: Uint8Array } {
  const ek = keygen();
  const dhOut = dh(ek.priv, pk);
  const shared = extractExpand(dhOut, cat(ek.pub, pk));
  dhOut.fill(0);
  ek.priv.fill(0);
  return { shared, kemOutput: ek.pub };
}

export function decap(priv: Uint8Array, kemOutput: Uint8Array): Uint8Array {
  const dhOut = dh(priv, kemOutput);
  const shared = extractExpand(dhOut, cat(kemOutput, x25519.getPublicKey(priv)));
  dhOut.fill(0);
  return shared;
}

export function derivePair(ikm: Uint8Array): Key {
  const bit = new Uint8Array(sha256.length);
  bit[bit.length - 1] |= 0x80;
  const dkpPrk = kdfExtract(new Uint8Array(0), "dkp_prk", ikm);
  const bytes = kdfExpand(dkpPrk, "sk", bit, NH);
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  dkpPrk.fill(0);
  return { priv: bytes, pub: x25519.getPublicKey(bytes) };
}

export type Context = { key: Uint8Array; baseNonce: Uint8Array; exporter: Uint8Array; seq: number };

export function keySchedule(shared: Uint8Array, info: Uint8Array): Context {
  const pskIdHash = kdfExtract(new Uint8Array(0), "psk_id_hash", new Uint8Array(0));
  const infoHash = kdfExtract(new Uint8Array(0), "info_hash", info);
  const ctx = cat(new Uint8Array([MODE_BASE]), pskIdHash, infoHash);
  const secret = kdfExtract(shared, "secret", new Uint8Array(0));
  const key = kdfExpand(secret, "key", ctx, NK);
  const baseNonce = kdfExpand(secret, "base_nonce", ctx, NN);
  const exporter = kdfExpand(secret, "exp", ctx, NH);
  secret.fill(0);
  pskIdHash.fill(0);
  infoHash.fill(0);
  return { key, baseNonce, exporter, seq: 0 };
}

function nonceFor(c: Context): Uint8Array {
  const n = Uint8Array.from(c.baseNonce);
  let s = c.seq;
  for (let i = n.length - 1; i >= 0 && s > 0; i--) {
    n[i] ^= s & 255;
    s >>>= 8;
  }
  return n;
}

export function seal(c: Context, aad: Uint8Array, pt: Uint8Array): Uint8Array {
  const n = nonceFor(c);
  const out = gcm(c.key, n, aad).encrypt(pt);
  n.fill(0);
  c.seq++;
  return out;
}

export function openC(c: Context, aad: Uint8Array, ct: Uint8Array): Uint8Array {
  const n = nonceFor(c);
  const out = gcm(c.key, n, aad).decrypt(ct);
  n.fill(0);
  c.seq++;
  return out;
}

export function exporterKey(c: Context, ctx: Uint8Array, len: number): Uint8Array {
  return kdfExpand(c.exporter, "sec", ctx, len);
}

export function fresh(): Uint8Array {
  return randomBytes(NH);
}