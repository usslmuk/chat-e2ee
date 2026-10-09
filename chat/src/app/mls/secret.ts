import { NH } from "./hpke.ts";
import * as S from "./schedule.ts";
import * as T from "./tree.ts";

export type Held = { node: number; pathSecret: Uint8Array };

export function rootSecret(encryptionSecret: Uint8Array): Uint8Array {
  return S.expandWithLabel(encryptionSecret, "tree", new Uint8Array(0), NH);
}

export function nodeSecret(pathSecret: Uint8Array): Uint8Array {
  return S.deriveSecret(pathSecret, "node");
}

export function nextSecret(secret: Uint8Array, side: "left" | "right"): Uint8Array {
  return S.expandWithLabel(secret, "path", new TextEncoder().encode(side), NH);
}

export function pathChain(leafSecret: Uint8Array, count: number): Uint8Array[] {
  const out: Uint8Array[] = [leafSecret];
  for (let i = 1; i < count; i++) out.push(S.deriveSecret(out[i - 1], "path"));
  return out;
}

export function leafSecret(root: Uint8Array, own: Uint8Array | null, held: Held[], leaf: number, n: number): Uint8Array {
  const target = 2 * leaf;
  const have = new Map<number, Uint8Array>();
  for (const h of held) have.set(h.node, h.pathSecret);

  const chain: number[] = [];
  let cursor = target;
  let guard = 0;
  while (guard < 128) {
    chain.push(cursor);
    if (cursor === T.root(n)) break;
    cursor = T.parent(cursor, n);
    guard++;
  }
  chain.reverse();

  let cur: Uint8Array | null = null;
  for (let i = 0; i < chain.length; i++) {
    const node = chain[i];
    if (i === chain.length - 1) {
      if (own) return nodeSecret(own);
      if (!cur) return root;
      return nodeSecret(cur);
    }
    const got = have.get(node);
    if (got) {
      cur = got;
      continue;
    }
    if (!cur) {
      cur = have.get(chain[0]) || root;
    }
    if (node === T.root(n)) continue;
    const up = T.parent(node, n);
    cur = nextSecret(cur, node === T.right(up) ? "right" : "left");
  }
  if (!cur) throw new Error("no path secret");
  return nodeSecret(cur);
}

export function ratchets(leafSecretValue: Uint8Array): { hs: S.Ratchet; app: S.Ratchet } {
  return {
    hs: S.initLeaf(S.expandWithLabel(leafSecretValue, "handshake", new Uint8Array(0), NH), "handshake"),
    app: S.initLeaf(S.expandWithLabel(leafSecretValue, "application", new Uint8Array(0), NH), "application"),
  };
}

export function senderRatchetKey(r: S.Ratchet, gen: number): { key: Uint8Array; nonce: Uint8Array } {
  let walk = { secret: Uint8Array.from(r.secret), gen: 0 };
  for (let i = 0; i < gen; i++) S.step(walk);
  return S.step(walk);
}