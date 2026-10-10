import { sha256 } from "@noble/hashes/sha2.js";
import { Writer } from "./wire.ts";
import { TNode, hash, left, right, level, root } from "./tree.ts";

export function leafNodeInput(index: number, node: TNode): Uint8Array {
  if (node.k !== 1) {
    return new Writer().u8(1).u32(index).none(false).out();
  }
  const v = node.v;
  return new Writer()
    .u8(1)
    .u32(index)
    .none(true)
    .raw(v.tbs)
    .vec(v.signature)
    .out();
}

export function parentNodeInput(node: TNode, leftH: Uint8Array, rightH: Uint8Array): Uint8Array {
  if (node.k !== 2) {
    return new Writer().u8(2).none(false).vec(leftH).vec(rightH).out();
  }
  const v = node.v;
  const unmerged = new Writer();
  for (const l of v.unmerged) unmerged.u32(l);
  return new Writer()
    .u8(2)
    .none(true)
    .vec(v.enc)
    .vec(v.parentHash)
    .vec(unmerged.out())
    .vec(leftH)
    .vec(rightH)
    .out();
}

export function nodeHash(t: TNode[], x: number, n: number): Uint8Array {
  if (level(x) === 0) {
    return hash(leafNodeInput(x / 2, t[x]));
  }
  return hash(parentNodeInput(t[x], nodeHash(t, left(x), n), nodeHash(t, right(x), n)));
}

export function treeHash(t: TNode[], n: number): Uint8Array {
  if (n === 0) return sha256(new Uint8Array(0));
  return nodeHash(t, root(n), n);
}

export function treeSize(t: TNode[]): number {
  let last = 0;
  for (let i = t.length - 1; i >= 0; i--) {
    if (t[i].k !== 0) {
      last = i;
      break;
    }
  }
  return last;
}