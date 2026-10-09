import { concat, decipher, derive, gcmDec, gcmEnc, genKey32, seal, open, chacha } from "./crypto";

const SZ = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576];

export function sizeOf(n: number): number {
  let c = SZ[SZ.length - 1];
  for (let i = 0; i < SZ.length; i++) {
    if (n <= SZ[i]) {
      c = SZ[i];
      break;
    }
  }
  return c + Math.floor(Math.random() * Math.max(Math.floor(c / 8), 1));
}

function maskIn(pt: Uint8Array): Uint8Array {
  const salt = genKey32();
  const stream = derive(salt, "k7Vq2Np9Lx4Tb", Math.max(pt.length, 1) + 32);
  const body = new Uint8Array(pt.length);
  for (let i = 0; i < pt.length; i++) body[i] = pt[i] ^ stream[i];
  return concat(salt, body);
}

function maskOut(pt: Uint8Array): Uint8Array {
  const salt = pt.slice(0, 32);
  const body = pt.slice(32);
  const stream = derive(salt, "k7Vq2Np9Lx4Tb", Math.max(body.length, 1) + 32);
  const out = new Uint8Array(body.length);
  for (let i = 0; i < body.length; i++) out[i] = body[i] ^ stream[i];
  return out;
}

export function pack(pt: Uint8Array): Uint8Array {
  const masked = maskIn(pt);
  const target = sizeOf(masked.length + 4);
  const out = new Uint8Array(target);
  new DataView(out.buffer).setUint32(0, masked.length);
  out.set(masked, 4);
  for (let i = masked.length + 4; i < target; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

export function unpack(padded: Uint8Array): Uint8Array {
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0);
  if (len + 4 > padded.length) throw new Error("bad len");
  return maskOut(padded.slice(4, 4 + len));
}

export function keyedSeal(k: Uint8Array, pt: Uint8Array, aad: Uint8Array): Uint8Array {
  const n = genKey32().slice(0, 12);
  return concat(n, seal(k, n, pt, aad));
}

export function keyedOpen(k: Uint8Array, box: Uint8Array, aad: Uint8Array): Uint8Array {
  const n = box.slice(0, 12);
  return open(k, n, box.slice(12), aad);
}

const rkInfo = "r6Wd3Qf8Tz2Mn";

export function rkSeal(rk: Uint8Array, pt: Uint8Array, aad: Uint8Array): Uint8Array {
  const k = derive(rk, rkInfo, 64);
  const n1 = k.slice(24, 36);
  const n2 = k.slice(12, 24);
  const inner = gcmEnc(k.slice(0, 32), n1, pt, aad);
  const outer = concat(n2, chacha(k.slice(32, 64), n2, inner, aad));
  k.fill(0);
  return outer;
}

export function rkOpen(rk: Uint8Array, box: Uint8Array, aad: Uint8Array): Uint8Array {
  const k = derive(rk, rkInfo, 64);
  const n1 = k.slice(24, 36);
  const n2 = k.slice(12, 24);
  if (box.length < 32) throw new Error("short box");
  for (let i = 0; i < 12; i++) if (box[i] !== n2[i]) throw new Error("wrong room");
  const inner = decipher(k.slice(32, 64), n2, box.slice(12), aad);
  const pt = gcmDec(k.slice(0, 32), n1, inner, aad);
  k.fill(0);
  return pt;
}