import { gcm } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { cat, suiteOf, expandWith, type Suite, type CHash } from "./suite.ts";

export const NH = 32;
export const NK = 16;
export const NN = 12;

const enc = new TextEncoder();

function u16(v: number): Uint8Array {
  return new Uint8Array([(v >> 8) & 255, v & 255]);
}

type Sched = {
  suite: Suite;
  kemSuite: Uint8Array;
  kdfSuite: Uint8Array;
  extract: (salt: Uint8Array, ikm: Uint8Array) => Uint8Array;
  expand: (prk: Uint8Array, info: Uint8Array, len: number) => Uint8Array;
  kemExtract: (salt: Uint8Array, label: string, ikm: Uint8Array) => Uint8Array;
  kemExpand: (prk: Uint8Array, label: string, info: Uint8Array, len: number) => Uint8Array;
  kdfExtract: (salt: Uint8Array, label: string, ikm: Uint8Array) => Uint8Array;
  kdfExpand: (prk: Uint8Array, label: string, info: Uint8Array, len: number) => Uint8Array;
};

function makeSched(id: number): Sched {
  const suite = suiteOf(id);
  const nh = suite.nh;
  const hExpand = expandWith(suite.hash as CHash);
  const extract = (salt: Uint8Array, ikm: Uint8Array): Uint8Array => {
    const s = salt.length === 0 ? new Uint8Array(nh) : salt;
    return hmac(suite.hash as CHash, s, ikm);
  };
  const kemSuite = cat(enc.encode("HPKE-v1"), enc.encode("KEM"), u16(suite.kem.id));
  const kdfSuite = cat(enc.encode("HPKE-v1"), enc.encode("HPKE"), u16(suite.kem.id), u16(suite.kdf), u16(suite.aead.id));
  return {
    suite,
    kemSuite,
    kdfSuite,
    extract,
    expand: hExpand,
    kemExtract: (salt, label, ikm) => extract(salt, cat(kemSuite, enc.encode(label), ikm)),
    kemExpand: (prk, label, info, len) => hExpand(prk, cat(u16(len), kemSuite, enc.encode(label), info), len),
    kdfExtract: (salt, label, ikm) => extract(salt, cat(kdfSuite, enc.encode(label), ikm)),
    kdfExpand: (prk, label, info, len) => hExpand(prk, cat(u16(len), kdfSuite, enc.encode(label), info), len)
  };
}

const cache = new Map<number, Sched>();

function sched(id: number): Sched {
  let s = cache.get(id);
  if (!s) {
    s = makeSched(id);
    cache.set(id, s);
  }
  return s;
}

export type Key = { priv: Uint8Array; pub: Uint8Array };

export type Hpke = {
  suite: Suite;
  keygen: () => Key;
  pubOf: (priv: Uint8Array) => Uint8Array;
  encap: (pk: Uint8Array) => { shared: Uint8Array; kemOutput: Uint8Array };
  decap: (priv: Uint8Array, kemOutput: Uint8Array) => Uint8Array;
  derivePair: (ikm: Uint8Array) => Key;
  keySchedule: (shared: Uint8Array, info: Uint8Array) => Context;
};

export function makeHpke(suiteId: number): Hpke {
  const s = sched(suiteId);
  const suite = s.suite;

  const keygen = (): Key => suite.kem.keygen();

  const dh = (priv: Uint8Array, pub: Uint8Array): Uint8Array => {
    const out = suite.kem.shared(priv, pub);
    if (out.length !== suite.kem.dhLen) throw new Error("bad dh result");
    return out;
  };

  const extractExpand = (dhOut: Uint8Array, kemContext: Uint8Array): Uint8Array => {
    const prk = s.kemExtract(new Uint8Array(0), "eae_prk", dhOut);
    const out = s.kemExpand(prk, "shared_secret", kemContext, suite.nh);
    prk.fill(0);
    return out;
  };

  const encap = (pk: Uint8Array): { shared: Uint8Array; kemOutput: Uint8Array } => {
    const ek = keygen();
    const dhOut = dh(ek.priv, pk);
    const shared = extractExpand(dhOut, cat(ek.pub, pk));
    dhOut.fill(0);
    ek.priv.fill(0);
    return { shared, kemOutput: ek.pub };
  };

  const decap = (priv: Uint8Array, kemOutput: Uint8Array): Uint8Array => {
    const dhOut = dh(priv, kemOutput);
    const shared = extractExpand(dhOut, cat(kemOutput, suite.kem.pubOf(priv)));
    dhOut.fill(0);
    return shared;
  };

  const derivePair = (ikm: Uint8Array): Key => {
    const dkpPrk = s.kemExtract(new Uint8Array(0), "dkp_prk", ikm);
    const bytes = s.kemExpand(dkpPrk, "sk", new Uint8Array(0), suite.kem.skLen);
    dkpPrk.fill(0);
    return { priv: bytes, pub: suite.kem.pubOf(bytes) };
  };

  const keySchedule = (shared: Uint8Array, info: Uint8Array): Context => {
    const pskIdHash = s.kdfExtract(new Uint8Array(0), "psk_id_hash", new Uint8Array(0));
    const infoHash = s.kdfExtract(new Uint8Array(0), "info_hash", info);
    const ctx = cat(new Uint8Array([0]), pskIdHash, infoHash);
    const secret = s.kdfExtract(shared, "secret", new Uint8Array(0));
    const key = s.kdfExpand(secret, "key", ctx, suite.nk);
    const baseNonce = s.kdfExpand(secret, "base_nonce", ctx, suite.nn);
    const exporter = s.kdfExpand(secret, "exp", ctx, suite.nh);
    secret.fill(0);
    pskIdHash.fill(0);
    infoHash.fill(0);
    return { suite, key, baseNonce, exporter, seq: 0 };
  };

  return {
    suite,
    keygen,
    pubOf: (priv) => suite.kem.pubOf(priv),
    encap,
    decap,
    derivePair,
    keySchedule
  };
}

const suite1 = makeHpke(1);

export function keygen(): Key {
  return suite1.keygen();
}

export function encap(pk: Uint8Array): { shared: Uint8Array; kemOutput: Uint8Array } {
  return suite1.encap(pk);
}

export function decap(priv: Uint8Array, kemOutput: Uint8Array): Uint8Array {
  return suite1.decap(priv, kemOutput);
}

export function pubOf(priv: Uint8Array): Uint8Array {
  return suite1.pubOf(priv);
}

export function derivePair(ikm: Uint8Array): Key {
  return suite1.derivePair(ikm);
}

export function keySchedule(shared: Uint8Array, info: Uint8Array): Context {
  return suite1.keySchedule(shared, info);
}

export type Context = { suite: Suite; key: Uint8Array; baseNonce: Uint8Array; exporter: Uint8Array; seq: number };

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
  const out = c.suite.aead.seal(c.key, n, aad, pt);
  n.fill(0);
  c.seq++;
  return out;
}

export function openC(c: Context, aad: Uint8Array, ct: Uint8Array): Uint8Array {
  const n = nonceFor(c);
  const out = c.suite.aead.open(c.key, n, aad, ct);
  n.fill(0);
  c.seq++;
  return out;
}

export function exporterKey(c: Context, ctx: Uint8Array, len: number): Uint8Array {
  return sched(c.suite.id).kdfExpand(c.exporter, "sec", ctx, len);
}

export function fresh(): Uint8Array {
  return randomBytes(32);
}