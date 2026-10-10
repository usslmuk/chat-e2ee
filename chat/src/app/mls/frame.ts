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
export const REINIT = 4;
export const EXTERNAL_INIT = 5;
export const GROUP_CONTEXT_EXTENSIONS = 6;
export const PSK = 7;
export const SRC_KEY_PACKAGE = 1;
export const SRC_UPDATE = 2;
export const SRC_COMMIT = 3;
export const WIRE_PUBLIC = 1;
export const WIRE_PRIVATE = 2;

export type Leaf = {
  enc: Uint8Array;
  sigKey: Uint8Array;
  cred: Uint8Array;
  source: number;
  parentHash: Uint8Array | null;
  tbs: Uint8Array;
  signature: Uint8Array;
};

export type Par = {
  enc: Uint8Array;
  parentHash: Uint8Array;
  unmerged: number[];
};

function writeUnmerged(list: number[]): Uint8Array {
  const w = new Writer();
  for (const l of list) w.u32(l);
  return w.out();
}

function readUnmerged(b: Buf): number[] {
  const blob = new Buf(b.vec());
  const out: number[] = [];
  while (!blob.done) out.push(blob.u32());
  return out;
}

export function defaultCaps(): Uint8Array {
  return new Writer()
    .vec(new Writer().u16(VERSION).out())
    .vec(new Writer().u16(SUITE).out())
    .vec(new Uint8Array(0))
    .vec(new Writer().u8(ADD).u8(UPDATE).u8(REMOVE).u8(PSK).out())
    .vec(new Writer().u16(1).out())
    .out();
}

export function leafTbsOf(
  v: { enc: Uint8Array; sigKey: Uint8Array; cred: Uint8Array; source: number; parentHash: Uint8Array | null },
  caps?: Uint8Array,
  exts?: Uint8Array,
): Uint8Array {
  const w = new Writer()
    .vec(v.enc)
    .vec(v.sigKey)
    .u16(1)
    .vec(v.cred)
    .raw(caps ?? defaultCaps())
    .u8(v.source);
  if (v.source === SRC_KEY_PACKAGE) w.u64(0).u64(0);
  else if (v.source === SRC_COMMIT) w.vec(v.parentHash ?? new Uint8Array(0));
  w.vec(exts ?? new Uint8Array(0));
  return w.out();
}

export function writeLeafNode(v: Leaf): Uint8Array {
  return new Writer().u8(1).raw(writeLeafNodeBody(v)).out();
}

export function writeLeafNodeBody(v: Leaf): Uint8Array {
  return new Writer().raw(v.tbs).vec(v.signature).out();
}

export function readLeafNode(b: Buf): Leaf {
  b.u8();
  return readLeafNodeBody(b);
}

export function writeParentNode(v: Par): Uint8Array {
  return new Writer().vec(v.enc).vec(v.parentHash).vec(writeUnmerged(v.unmerged)).out();
}

export function readParentNode(b: Buf): Par {
  const enc = b.vec();
  const parentHash = b.vec();
  const unmerged = readUnmerged(b);
  return { enc, parentHash, unmerged };
}

export function writeParentNodeFull(v: Par): Uint8Array {
  return new Writer().u8(2).vec(v.enc).vec(v.parentHash).vec(writeUnmerged(v.unmerged)).out();
}

export type RatchetTree =
  | { k: 0 }
  | { k: 1; v: Leaf }
  | { k: 2; v: Par };

export function writeRatchetTree(nodes: RatchetTree[]): Uint8Array {
  const body = new Writer();
  for (const nd of nodes) {
    if (nd.k === 0) body.none(false);
    else if (nd.k === 1) body.none(true).raw(writeLeafNode(nd.v));
    else body.none(true).raw(writeParentNodeFull(nd.v));
  }
  return new Writer().vec(body.out()).out();
}

export function readRatchetTree(b: Buf): RatchetTree[] {
  const body = new Buf(b.vec());
  const out: RatchetTree[] = [];
  while (!body.done) {
    if (body.u8() === 0) {
      out.push({ k: 0 });
      continue;
    }
    const kind = body.u8();
    if (kind === 1) out.push({ k: 1, v: readLeafNodeBody(body) });
    else if (kind === 2) out.push({ k: 2, v: readParentNode(body) });
    else throw new Error("bad node type");
  }
  return out;
}

export function readLeafNodeBody(b: Buf): Leaf {
  const start = b.pos;
  const enc = b.vec();
  const sigKey = b.vec();
  b.u16();
  const cred = b.vec();
  for (let i = 0; i < 5; i++) b.vec();
  const source = b.u8();
  let parentHash: Uint8Array | null = null;
  if (source === SRC_KEY_PACKAGE) {
    b.u64();
    b.u64();
  } else if (source === SRC_COMMIT) {
    parentHash = b.vec();
  }
  b.vec();
  const end = b.pos;
  const signature = b.vec();
  return { enc, sigKey, cred, source, parentHash, tbs: b.slice(start, end), signature };
}

export const UNKNOWN_PROPOSAL = 65535;
export const REFERENCE = 300;

export type Proposal =
  | { t: typeof ADD; pkg: Uint8Array }
  | { t: typeof UPDATE; leaf: Uint8Array }
  | { t: typeof REMOVE; leaf: number }
  | { t: typeof PSK; psk: Uint8Array }
  | { t: typeof REFERENCE; ref: Uint8Array }
  | { t: typeof GROUP_CONTEXT_EXTENSIONS; ext: Uint8Array }
  | { t: typeof UNKNOWN_PROPOSAL; raw: Uint8Array };

export function readKeyPackage(b: Buf): Uint8Array {
  const start = b.pos;
  const attempt = (flat: boolean): void => {
    b.reset(start);
    b.u16();
    b.u16();
    b.vec();
    if (flat) {
      b.vec();
      b.vec();
      b.vec();
      b.vec();
    } else {
      readLeafNode(b);
    }
    b.vec();
    b.u64();
    b.u64();
    b.vec();
    b.vec();
  };
  for (const flat of [false, true]) {
    try {
      attempt(flat);
      return b.since(start);
    } catch {}
  }
  b.reset(start);
  return b.rest();
}

export function readPskId(b: Buf): Uint8Array {
  const start = b.pos;
  const kind = b.u8();
  if (kind === 1) {
    b.vec();
    b.vec();
  } else if (kind === 2) {
    b.vec();
    b.u64();
  } else if (kind === 3) {
    b.vec();
    b.vec();
    b.u16();
  }
  return b.since(start);
}

export function pskIdParts(ser: Uint8Array): { id: Uint8Array; psk: Uint8Array } {
  try {
    const b = new Buf(ser);
    if (b.u8() === 1) return { id: b.vec(), psk: b.vec() };
    return { id: b.vec(), psk: new Uint8Array(0) };
  } catch {
    return { id: new Uint8Array(0), psk: new Uint8Array(0) };
  }
}

export function writeProposal(p: Proposal): Uint8Array {
  if (p.t === REFERENCE) return new Writer().u8(2).vec(p.ref).out();
  const w = new Writer().u8(1).u16(p.t);
  if (p.t === REMOVE) w.u32(p.leaf);
  else if (p.t === UPDATE) w.raw(p.leaf);
  else if (p.t === PSK) w.raw(p.psk);
  else if (p.t === ADD) w.raw(p.pkg);
  else if (p.t === GROUP_CONTEXT_EXTENSIONS) w.vec(p.ext);
  return w.out();
}

export function readProposal(b: Buf): Proposal {
  const kind = b.u8();
  if (kind === 2) return { t: REFERENCE, ref: b.vec() };
  if (kind !== 1) return { t: UNKNOWN_PROPOSAL, raw: b.rest() };
  const t = b.u16();
  if (t === REMOVE) return { t, leaf: b.u32() };
  if (t === UPDATE) return { t, leaf: b.rest() };
  if (t === ADD) return { t, pkg: readKeyPackage(b) };
  if (t === PSK || t === 4) return { t: PSK, psk: readPskId(b) };
  if (t === GROUP_CONTEXT_EXTENSIONS || t === 5) return { t: GROUP_CONTEXT_EXTENSIONS, ext: b.vec() };
  return { t: UNKNOWN_PROPOSAL, raw: new Writer().u16(t).raw(b.rest()).out() };
}

export type PathNode = { enc: Uint8Array; kemOutput: Uint8Array };

export type UpdatePath = { leaf: Leaf; nodes: PathNode[] };

export function writePath(p: UpdatePath): Uint8Array {
  const nw = new Writer();
  for (const n of p.nodes) nw.vec(n.enc).vec(n.kemOutput);
  return new Writer().raw(writeLeafNodeBody(p.leaf)).vec(nw.out()).out();
}

export function readPath(b: Buf): UpdatePath {
  const leaf = readLeafNodeBody(b);
  const blob = new Buf(b.vec());
  const nodes: PathNode[] = [];
  while (!blob.done) nodes.push({ enc: blob.vec(), kemOutput: blob.vec() });
  return { leaf, nodes };
}

export function writeCommit(path: UpdatePath | null, proposals: Proposal[]): Uint8Array {
  const pw = new Writer();
  for (const p of proposals) pw.raw(writeProposal(p));
  const w = new Writer().vec(pw.out()).none(path !== null);
  if (path) w.raw(writePath(path));
  return w.out();
}

export function framed(groupId: Uint8Array, epoch: number, leaf: number, auth: Uint8Array, ctype: number, body: Uint8Array): Uint8Array {
  const w = new Writer().vec(groupId).u64(epoch).u8(MEMBER).u32(leaf).vec(auth).u8(ctype);
  return (ctype === APPLICATION ? w.vec(body) : w.raw(body)).out();
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
  const sender = b.u32();
  const auth = b.vec();
  const ctype = b.u8();
  return {
    groupId,
    epoch,
    sender,
    auth,
    ctype,
    body: ctype === APPLICATION ? b.vec() : b.rest()
  };
}

export function groupContext(groupId: Uint8Array, epoch: number, suite: number, treeHash: Uint8Array, confirmed: Uint8Array, extensions = new Uint8Array(0)): Uint8Array {
  return new Writer().u16(VERSION).u16(suite).vec(groupId).u64(epoch).vec(treeHash).vec(confirmed).vec(extensions).out();
}

export function contentTbs(wire: number, content: Uint8Array, ctx: Uint8Array): Uint8Array {
  return contentTbsExt(wire, content, ctx, new Uint8Array(0));
}

export function contentTbsExt(wire: number, content: Uint8Array, ctx: Uint8Array, ext: Uint8Array): Uint8Array {
  return new Writer().u16(VERSION).u16(wire).raw(content).raw(ctx).raw(ext).out();
}

export function externalFramed(groupId: Uint8Array, epoch: number, senderIndex: number, auth: Uint8Array, ctype: number, body: Uint8Array): Uint8Array {
  return new Writer().vec(groupId).u64(epoch).u8(2).u32(senderIndex).vec(auth).u8(ctype).vec(body).out();
}

export function externalTbs(wire: number, content: Uint8Array): Uint8Array {
  return new Writer().u16(VERSION).u16(wire).raw(content).out();
}

export function confirmedInput(wire: number, content: Uint8Array, signature: Uint8Array): Uint8Array {
  return new Writer().u16(wire).raw(content).vec(signature).out();
}

export function nextConfirmed(prev: Uint8Array, wire: number, content: Uint8Array, signature: Uint8Array): Uint8Array {
  return sha256(new Writer().raw(prev).raw(confirmedInput(wire, content, signature)).out());
}

export function nextInterim(confirmed: Uint8Array, tag: Uint8Array): Uint8Array {
  return sha256(new Writer().raw(confirmed).vec(tag).out());
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

export function refHash(label: string, value: Uint8Array): Uint8Array {
  return sha256(new Writer().vec(new TextEncoder().encode("MLS 1.0 " + label)).vec(value).out());
}

export function keyPackageRef(pkg: Uint8Array): Uint8Array {
  return refHash("KeyPackage Reference", pkg);
}

export function proposalRef(prop: Uint8Array): Uint8Array {
  return refHash("Proposal Reference", prop);
}

export function leafTbs(v: Leaf, groupId: Uint8Array | null, index: number): Uint8Array {
  const w = new Writer().raw(v.tbs);
  if (v.source !== SRC_KEY_PACKAGE) w.vec(groupId ?? new Uint8Array(0)).u32(index);
  return w.out();
}

export function parentHashTbs(enc: Uint8Array, ph: Uint8Array, siblingHash: Uint8Array): Uint8Array {
  return new Writer().vec(enc).vec(ph).vec(siblingHash).out();
}

export function parentHashOf(enc: Uint8Array, ph: Uint8Array, siblingHash: Uint8Array): Uint8Array {
  return sha256(parentHashTbs(enc, ph, siblingHash));
}