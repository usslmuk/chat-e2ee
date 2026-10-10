import { sha256 } from "@noble/hashes/sha2.js";
import { Writer } from "./wire.ts";

export const LEAF = 1;
export const PARENT = 2;
export const BLANK = 0;

export type Leaf = {
  enc: Uint8Array;
  sigKey: Uint8Array;
  cred: Uint8Array;
  ph: Uint8Array | null;
  unmerged: number[];
  tbs: Uint8Array;
  signature: Uint8Array;
};

export type Par = {
  enc: Uint8Array;
  sig: Uint8Array;
  ph: Uint8Array;
  unmerged: number[];
};

export type TNode =
  | { k: 0 }
  | { k: 1; v: Leaf }
  | { k: 2; v: Par };

export function log2(x: number): number {
  if (x === 0) return 0;
  let r = 0;
  while (x > 0) {
    x = Math.floor(x / 2);
    r++;
  }
  return r - 1;
}

export function level(x: number): number {
  if ((x & 1) === 0) return 0;
  let k = 0;
  while (((x >> k) & 1) === 1) k++;
  return k;
}

export function width(n: number): number {
  return n === 0 ? 0 : 2 * (n - 1) + 1;
}

export function alloc(n: number): number {
  if (n <= 1) return 1;
  let k = 1;
  while ((1 << (k - 1)) < n) k++;
  return (1 << k) - 1;
}

export function emptySlots(n: number): TNode[] {
  const out: TNode[] = [];
  for (let i = 0; i < alloc(n); i++) out.push({ k: BLANK });
  return out;
}

export function root(n: number): number {
  return (1 << log2(width(n))) - 1;
}

export function left(x: number): number {
  const k = level(x);
  if (k === 0) throw new Error("leaf has no children");
  return x ^ (1 << (k - 1));
}

export function right(x: number): number {
  const k = level(x);
  if (k === 0) throw new Error("leaf has no children");
  return x ^ (3 << (k - 1));
}

export function parent(x: number, n: number): number {
  if (x === root(n)) throw new Error("root has no parent");
  const k = level(x);
  const b = (x >> (k + 1)) & 1;
  return (x | (1 << k)) ^ (b << (k + 1));
}

export function sibling(x: number, n: number): number {
  const p = parent(x, n);
  return x < p ? right(p) : left(p);
}

export function directPath(x: number, n: number): number[] {
  const r = root(n);
  if (x === r) return [];
  const d: number[] = [];
  let c = x;
  while (c !== r) {
    c = parent(c, n);
    d.push(c);
  }
  return d;
}

export function copath(x: number, n: number): number[] {
  if (x === root(n)) return [];
  const d = directPath(x, n);
  d.unshift(x);
  d.pop();
  return d.map((y) => sibling(y, n));
}

export function resolution(t: TNode[], x: number): number[] {
  const node = t[x];
  if (node.k === 0) {
    if (level(x) === 0) return [];
    return [...resolution(t, left(x)), ...resolution(t, right(x))];
  }
  const out = [x];
  if (node.k === 1) {
    const v = node.v;
    for (const l of v.unmerged) out.push(2 * l);
  }
  return out;
}

export function filteredDirectPath(t: TNode[], leaf: number, n: number): number[] {
  const dp = directPath(2 * leaf, n);
  const cp = copath(2 * leaf, n);
  const keep: number[] = [];
  for (let i = 0; i < dp.length; i++) {
    if (resolution(t, cp[i]).length > 0) keep.push(dp[i]);
  }
  return keep;
}

export function leafCount(t: TNode[]): number {
  let c = 0;
  for (let i = 0; i < t.length; i += 2) {
    if (i === 0) {
      if (t[0].k !== BLANK) c++;
    } else if (t[i].k !== BLANK) c++;
  }
  return c;
}

export type Tree = { n: number; t: TNode[]; priv: Map<number, Uint8Array> };

export function newTree(): Tree {
  return { n: 0, t: [{ k: BLANK }], priv: new Map() };
}

export function cloneTree(tr: Tree): Tree {
  return {
    n: tr.n,
    t: tr.t.map((x): TNode => {
      if (x.k === 0) return { k: 0 };
      if (x.k === 1) return { k: 1, v: { ...x.v, unmerged: [...x.v.unmerged] } };
      return { k: 2, v: { ...x.v, unmerged: [...x.v.unmerged] } };
    }),
    priv: new Map(tr.priv),
  };
}

export function extend(tr: Tree): void {
  tr.n = tr.n * 2;
  const want = alloc(tr.n);
  while (tr.t.length < want) tr.t.push({ k: BLANK });
}

export function truncate(tr: Tree): void {
  tr.n = tr.n / 2;
  const keep = alloc(tr.n);
  tr.t = tr.t.slice(0, keep);
  for (const key of [...tr.priv.keys()]) if (key >= keep) tr.priv.delete(key);
}

export function hash(v: Uint8Array): Uint8Array {
  return sha256(v);
}

export function parentHashInput(pub: Uint8Array, leftH: Uint8Array, rightH: Uint8Array): Uint8Array {
  return hash(new Writer().vec(pub).vec(leftH).vec(rightH).out());
}

export function parentHashOf(tr: Tree, x: number): Uint8Array {
  if (level(x) === 0) {
    const node = tr.t[x];
    if (node.k !== 1) return new Uint8Array(0);
    return node.v.ph ?? new Uint8Array(0);
  }
  const n = tr.n;
  const r = root(n);
  if (x === r) {
    const node = tr.t[x];
    if (node.k === BLANK) return new Uint8Array(0);
    return (node.v as Par).ph;
  }
  const lh = parentHashOf(tr, left(x));
  const rh = parentHashOf(tr, right(x));
  const node = tr.t[x];
  const pub = node.k === PARENT ? (node.v as Par).enc : new Uint8Array(0);
  return parentHashInput(pub, lh, rh);
}