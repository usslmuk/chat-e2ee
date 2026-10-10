import { ed25519 } from "@noble/curves/ed25519.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "@noble/hashes/utils.js";

export type Keys = {
  edPriv: Uint8Array;
  edPub: Uint8Array;
  xPriv: Uint8Array;
  xPub: Uint8Array;
};

export type Bundle = {
  edPub: Uint8Array;
  xPub: Uint8Array;
  spk: Uint8Array;
  spkSig: Uint8Array;
};

const enc = new TextEncoder();

export function b64e(v: Uint8Array): string {
  let s = "";
  for (let i = 0; i < v.length; i += 8192) s += String.fromCharCode(...v.subarray(i, i + 8192));
  return btoa(s);
}

export function b64d(s: string): Uint8Array {
  const b = atob(s);
  const v = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) v[i] = b.charCodeAt(i);
  return v;
}

function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacSha256(salt.length === 0 ? new Uint8Array(32) : salt, ikm);
}

function hkdfExpand(prk: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  const out: number[] = [];
  let prev: Uint8Array = new Uint8Array(0);
  let i = 1;
  while (out.length < len) {
    const inp = new Uint8Array(prev.length + info.length + 1);
    inp.set(prev, 0);
    inp.set(info, prev.length);
    inp[prev.length + info.length] = i;
    const t: Uint8Array = hmacSha256(prk, inp);
    for (let j = 0; j < t.length; j++) out.push(t[j]);
    prev = t;
    i++;
  }
  return new Uint8Array(out.slice(0, len));
}

export function ctId(ct: string): string {
  const h = sha256(enc.encode(ct));
  let s = "";
  for (let i = 0; i < 15; i++) s += String.fromCharCode(h[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_");
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const v = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    v.set(p, o);
    o += p.length;
  }
  return v;
}

export function genKeys(): Keys {
  const edPriv = ed25519.utils.randomSecretKey();
  const xPriv = x25519.utils.randomSecretKey();
  return {
    edPriv,
    edPub: ed25519.getPublicKey(edPriv),
    xPriv,
    xPub: x25519.getPublicKey(xPriv),
  };
}

export function genKey32(): Uint8Array {
  return randomBytes(32);
}

export function derive(ikm: Uint8Array, info: string, len: number): Uint8Array {
  const prk = hkdfExtract(new Uint8Array(32), ikm);
  const out = hkdfExpand(prk, enc.encode(info), len);
  prk.fill(0);
  return out;
}

export function seal(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad: Uint8Array): Uint8Array {
  return gcm(key, nonce, aad).encrypt(pt);
}

export function open(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, aad: Uint8Array): Uint8Array {
  return gcm(key, nonce, aad).decrypt(ct);
}

export function chacha(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad: Uint8Array): Uint8Array {
  return chacha20poly1305(key, nonce, aad).encrypt(data);
}

export function decipher(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad: Uint8Array): Uint8Array {
  return chacha20poly1305(key, nonce, aad).decrypt(data);
}

export function gcmEnc(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad: Uint8Array): Uint8Array {
  return gcm(key, nonce, aad).encrypt(data);
}

export function gcmDec(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad: Uint8Array): Uint8Array {
  return gcm(key, nonce, aad).decrypt(data);
}

export function edSign(priv: Uint8Array, data: Uint8Array): Uint8Array {
  return ed25519.sign(data, priv);
}

export function edVerify(pub: Uint8Array, data: Uint8Array, sig: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, data, pub);
  } catch (e) {
    return false;
  }
}

const pairInfo = "p4Wk8Zn2Qv6T";
const msgTag = new Uint8Array([109, 115, 103]);

export function safety(edA: Uint8Array, edB: Uint8Array, idA: string, idB: string): string {
  const cmp = (a: Uint8Array, b: Uint8Array) => {
    for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
  };
  const f = cmp(edA, edB) <= 0 ? edA : edB;
  const s = cmp(edA, edB) <= 0 ? edB : edA;
  const ia = idA <= idB ? idA : idB;
  const ib = idA <= idB ? idB : idA;
  const d = sha512(concat(f, s, enc.encode(ia), enc.encode(ib)));
  const parts: string[] = [];
  for (let i = 0; i < 12; i++) parts.push(String((d[2 * i] + d[2 * i + 1] * 256) % 100000).padStart(5, "0"));
  return parts.join(" ");
}