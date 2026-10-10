import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { NH, NK, NN, makeHpke, type Hpke } from "./hpke.ts";
import { suiteOf, type CHash, type Suite } from "./suite.ts";

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

export function extract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  const s = salt.length === 0 ? new Uint8Array(NH) : salt;
  return hmac(sha256, s, ikm);
}

function expand(prk: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  const out: number[] = [];
  let i = 1;
  while (out.length < len) {
    const t = hmac(sha256, prk, cat(info, new Uint8Array([i])));
    for (const j of t) out.push(j);
    i++;
  }
  return new Uint8Array(out.slice(0, len));
}

function vlen(v: Uint8Array): Uint8Array {
  const n = v.length;
  if (n < 64) return new Uint8Array([n]);
  if (n < 16384) return new Uint8Array([0x40 | ((n >> 8) & 63), n & 255]);
  if (n < 1073741824) {
    return new Uint8Array([0x80 | ((n >>> 24) & 63), (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  }
  throw new Error("vector too long");
}

export function expandWithLabel(secret: Uint8Array, label: string, ctx: Uint8Array, len: number, sid = 1): Uint8Array {
  const full = new TextEncoder().encode("MLS 1.0 " + label);
  const info = cat(
    new Uint8Array([(len >> 8) & 255, len & 255]),
    vlen(full),
    full,
    vlen(ctx),
    ctx,
  );
  return expand(secret, info, len);
}

export function deriveSecret(secret: Uint8Array, label: string, sid = 1): Uint8Array {
  return expandWithLabel(secret, label, new Uint8Array(0), suiteOf(sid).nh, sid);
}

export function deriveTreeSecret(secret: Uint8Array, label: string, gen: number, len: number, sid = 1): Uint8Array {
  const g = new Uint8Array([(gen >>> 24) & 255, (gen >> 16) & 255, (gen >> 8) & 255, gen & 255]);
  return expandWithLabel(secret, label, g, len, sid);
}

export function nil(): Uint8Array {
  return new Uint8Array(NH);
}

export type EpochSecrets = {
  init: Uint8Array;
  welcome: Uint8Array;
  epoch: Uint8Array;
  sender: Uint8Array;
  encryption: Uint8Array;
  exporter: Uint8Array;
  external: Uint8Array;
  confirm: Uint8Array;
  membership: Uint8Array;
  resumption: Uint8Array;
  auth: Uint8Array;
};

export function epochFromJoiner(joiner: Uint8Array, ctx: Uint8Array): EpochSecrets {
  const mixed = joiner;
  const welcome = deriveSecret(mixed, "welcome");
  const epoch = expandWithLabel(mixed, "epoch", ctx, NH);
  const init = deriveSecret(epoch, "init");
  return {
    init,
    welcome,
    epoch,
    sender: deriveSecret(epoch, "sender data"),
    encryption: deriveSecret(epoch, "encryption"),
    exporter: deriveSecret(epoch, "exporter"),
    external: deriveSecret(epoch, "external"),
    confirm: deriveSecret(epoch, "confirm"),
    membership: deriveSecret(epoch, "membership"),
    resumption: deriveSecret(epoch, "resumption"),
    auth: deriveSecret(epoch, "authentication"),
  };
}

export function joinerOf(initPrev: Uint8Array, commitSecret: Uint8Array, ctx: Uint8Array): Uint8Array {
  return expandWithLabel(extract(initPrev, commitSecret), "joiner", ctx, NH);
}

export function joinerFromJoiner(joiner: Uint8Array, psk: Uint8Array): Uint8Array {
  return extract(joiner, psk.length === 0 ? new Uint8Array(NH) : psk);
}

export function epochFrom(initPrev: Uint8Array, commitSecret: Uint8Array, psk: Uint8Array, ctx: Uint8Array): EpochSecrets {
  return epochFromJoiner(joinerFromJoiner(joinerOf(initPrev, commitSecret, ctx), psk), ctx);
}

export function pskLabel(id: Uint8Array, index: number, count: number): Uint8Array {
  return cat(
    id,
    new Uint8Array([(index >> 8) & 255, index & 255, (count >> 8) & 255, count & 255]),
  );
}

export function makePskSecret(psks: Uint8Array[], labels: Uint8Array[]): Uint8Array {
  if (psks.length === 0) return new Uint8Array(0);
  if (psks.length !== labels.length) throw new Error("psk count mismatch");
  let secret: Uint8Array = new Uint8Array(NH);
  for (let i = 0; i < psks.length; i++) {
    const extracted = extract(nil(), psks[i]);
    const input = expandWithLabel(extracted, "derived psk", pskLabel(labels[i], i, psks.length), NH);
    secret = extract(input, secret);
  }
  return secret;
}

export function exportSecret(exporterSecret: Uint8Array, label: string, ctx: Uint8Array, length: number): Uint8Array {
  const intermediate = deriveSecret(exporterSecret, label);
  const hashed = sha256(ctx);
  const out = expandWithLabel(intermediate, "exported", hashed, length);
  intermediate.fill(0);
  return out;
}

export type Ratchet = { secret: Uint8Array; gen: number };

export function initLeaf(s: Uint8Array, kind: "handshake" | "application"): Ratchet {
  return { secret: expandWithLabel(s, kind, new Uint8Array(0), NH), gen: 0 };
}

export function step(r: Ratchet): { key: Uint8Array; nonce: Uint8Array } {
  const key = deriveTreeSecret(r.secret, "key", r.gen, NK);
  const nonce = deriveTreeSecret(r.secret, "nonce", r.gen, NN);
  r.secret = deriveTreeSecret(r.secret, "secret", r.gen, NH);
  r.gen++;
  return { key, nonce };
}

export function confirmationTag(confirmKey: Uint8Array, transcript: Uint8Array): Uint8Array {
  return hmac(sha256, confirmKey, transcript);
}

export function membershipTag(membershipKey: Uint8Array, tbs: Uint8Array): Uint8Array {
  return hmac(sha256, membershipKey, tbs);
}

export function nonceXor(ratchetNonce: Uint8Array, provisional: Uint8Array): Uint8Array {
  const out = new Uint8Array(NN);
  for (let i = 0; i < NN; i++) out[i] = ratchetNonce[i] ^ provisional[i];
  return out;
}

export { NK, NN, NH };