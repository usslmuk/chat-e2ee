import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { x448, ed448 } from "@noble/curves/ed448.js";
import { gcm } from "@noble/ciphers/aes.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "@noble/hashes/utils.js";

export type Kem = {
  keygen: () => { priv: Uint8Array; pub: Uint8Array };
  shared: (priv: Uint8Array, pub: Uint8Array) => Uint8Array;
  pubOf: (priv: Uint8Array) => Uint8Array;
  id: number;
  dhLen: number;
  skLen: number;
};

export type Aead = {
  seal: (key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array) => Uint8Array;
  open: (key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array) => Uint8Array;
  id: number;
};

export type Sig = {
  keygen: () => { priv: Uint8Array; pub: Uint8Array };
  sign: (msg: Uint8Array, priv: Uint8Array) => Uint8Array;
  verify: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => boolean;
  keyLen: number;
  sigLen: number;
};

export type Hash = (data: Uint8Array) => Uint8Array;
export type CHash = typeof sha256 | typeof sha512;

export type Suite = {
  id: number;
  nh: number;
  nk: number;
  nn: number;
  kdf: number;
  hash: Hash;
  kem: Kem;
  aead: Aead;
  sig: Sig;
  label: string;
};

const x25519Kem: Kem = {
  id: 0x0020,
  dhLen: 32,
  skLen: 32,
  keygen: () => {
    const priv = x25519.utils.randomSecretKey();
    return { priv, pub: x25519.getPublicKey(priv) };
  },
  shared: (priv, pub) => x25519.getSharedSecret(priv, pub),
  pubOf: (priv) => x25519.getPublicKey(priv)
};

const x448Kem: Kem = {
  id: 0x0021,
  dhLen: 56,
  skLen: 56,
  keygen: () => {
    const k = x448.keygen();
    return { priv: k.secretKey, pub: k.publicKey };
  },
  shared: (priv, pub) => x448.getSharedSecret(priv, pub),
  pubOf: (priv) => x448.getPublicKey(priv)
};

const ed25519Sig: Sig = {
  keyLen: 32,
  sigLen: 64,
  keygen: () => {
    const priv = ed25519.utils.randomSecretKey();
    return { priv, pub: ed25519.getPublicKey(priv) };
  },
  sign: (msg, priv) => ed25519.sign(msg, priv),
  verify: (sig, msg, pub) => {
    try {
      return ed25519.verify(sig, msg, pub);
    } catch {
      return false;
    }
  }
};

const ed448Sig: Sig = {
  keyLen: 57,
  sigLen: 114,
  keygen: () => {
    const priv = ed448.utils.randomSecretKey();
    return { priv, pub: ed448.getPublicKey(priv) };
  },
  sign: (msg, priv) => ed448.sign(msg, priv),
  verify: (sig, msg, pub) => {
    try {
      return ed448.verify(sig, msg, pub);
    } catch {
      return false;
    }
  }
};

const aesGcm = (keyLen: number, id: number): Aead => ({
  id,
  seal: (key, nonce, aad, pt) => gcm(key, nonce, aad).encrypt(pt),
  open: (key, nonce, aad, ct) => gcm(key, nonce, aad).decrypt(ct)
});

function hmacExpand(hash: CHash) {
  return (prk: Uint8Array, info: Uint8Array, len: number): Uint8Array => {
    const out: number[] = [];
    let i = 1;
    while (out.length < len) {
      const t = hmac(hash, prk, cat(info, new Uint8Array([i])));
      for (const x of t) out.push(x);
      i++;
    }
    return new Uint8Array(out.slice(0, len));
  };
}

export function cat(...p: Uint8Array[]): Uint8Array {
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

export const SUITES: Record<number, Suite> = {
  1: {
    id: 1,
    nh: 32,
    nk: 16,
    nn: 12,
    kdf: 0x0001,
    hash: sha256 as CHash,
    kem: x25519Kem,
    aead: aesGcm(16, 0x0001),
    sig: ed25519Sig,
    label: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
  },
  2: {
    id: 2,
    nh: 64,
    nk: 32,
    nn: 12,
    kdf: 0x0003,
    hash: sha512 as CHash,
    kem: x448Kem,
    aead: aesGcm(32, 0x0002),
    sig: ed448Sig,
    label: "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448"
  }
};

export const KDF_ID = 0x0001;
export const MODE_BASE = 0;

export function suiteOf(id: number): Suite {
  const s = SUITES[id];
  if (!s) throw new Error("unknown cipher suite " + id);
  return s;
}

export function expandWith(hmacHash: CHash) {
  return hmacExpand(hmacHash);
}

export function fresh(n: number): Uint8Array {
  return randomBytes(n);
}