import * as G from "./mls/commit";
import * as F from "./mls/frame";
import * as T from "./mls/tree";
import * as X from "./mls/secret";
import * as S from "./mls/schedule";
import * as M from "./mls/message";
import * as K from "./mls/hpke";
import * as P from "./mls/psk";
import { treeHash } from "./mls/hash";
import { Buf } from "./mls/wire";
import { b64d, b64e } from "./lib/crypto";

const enc = new TextEncoder();

export type NodeSave = { k: number; enc?: string; sig?: string; cred?: string; ph?: string };

export type Saved = {
  gid: string;
  epoch: number;
  n: number;
  me: number;
  signPriv: string;
  signPub: string;
  initPriv: string;
  initPub: string;
  prevConfirmed: string;
  confirmed: string;
  interim: string;
  confirmation: string;
  extensions: string;
  leafSecret: string;
  held: { node: number; pathSecret: string }[];
  fromCommit: { node: number; pathSecret: string }[];
  secrets: Record<string, string>;
  nodes: NodeSave[];
  seed: string;
  hsSecret: string;
  appSecret: string;
  hsGen: number;
  appGen: number;
};

function seedFor(g: G.Group): Uint8Array {
  return g.seed;
}

function restore(s: Saved): { hs: S.Ratchet; app: S.Ratchet } {
  void 0;
  return {
    hs: { secret: b64d(s.hsSecret), gen: s.hsGen },
    app: { secret: b64d(s.appSecret), gen: s.appGen },
  };
}

export function self(): G.Self {
  return G.makeSelf();
}

export function newGroup(roomId: string, signer: G.Self): { group: G.Group; pkg: Uint8Array } {
  const { pkg, init } = G.makeKeyPackage(signer);
  const raw = enc.encode(roomId);
  const gid = new Uint8Array(16);
  gid.set(raw.subarray(0, 16));
  const group = G.create(gid, signer, pkg, init);
  return { group, pkg };
}

export function myPackage(signer: G.Self): Uint8Array {
  return G.makeKeyPackage(signer).pkg;
}

export type Offer = { pkg: Uint8Array; init: K.Key; ref: Uint8Array };

export function offer(signer: G.Self): Offer {
  const kp = G.makeKeyPackage(signer);
  return { pkg: kp.pkg, init: kp.init, ref: F.keyPackageRef(kp.pkg) };
}

export function packNodes(g: G.Group): NodeSave[] {
  const out: NodeSave[] = [];
  for (const n of g.t) {
    if (n.k === 1) {
      const v = n.v as T.Leaf;
      out.push({ k: 1, enc: b64e(v.enc), sig: b64e(v.sig), cred: b64e(v.cred), ph: v.ph ? b64e(v.ph) : "" });
    } else if (n.k === 2) {
      const v = n.v as T.Par;
      out.push({ k: 2, enc: b64e(v.enc), sig: b64e(v.sig), ph: b64e(v.ph) });
    } else out.push({ k: 0 });
  }
  return out;
}

export function save(g: G.Group): Saved {
  const secrets: Record<string, string> = {};
  for (const k of Object.keys(g.secrets) as (keyof S.EpochSecrets)[]) secrets[k] = b64e(g.secrets[k]);
  return {
    gid: b64e(g.id),
    epoch: g.epoch,
    n: g.n,
    me: g.me,
    signPriv: b64e(g.self.sigPriv),
    signPub: b64e(g.self.sigPub),
    initPriv: b64e(g.initPriv),
    initPub: b64e(g.initPub),
    prevConfirmed: b64e(g.prevConfirmed),
    confirmed: b64e(g.confirmed),
    interim: b64e(g.interim),
    confirmation: b64e(g.confirmation),
    extensions: b64e(g.extensions),
    leafSecret: g.leafSecret ? b64e(g.leafSecret) : "",
    held: g.held.map((h) => ({ node: h.node, pathSecret: b64e(h.pathSecret) })),
    fromCommit: g.fromCommit.map((h) => ({ node: h.node, pathSecret: b64e(h.pathSecret) })),
    seed: b64e(g.seed),
    secrets,
    nodes: packNodes(g),
    hsSecret: b64e(g.hs.secret),
    appSecret: b64e(g.app.secret),
    hsGen: g.hs.gen,
    appGen: g.app.gen,
  };
}

export function load(s: Saved): G.Group {
  const signer: G.Self = { sigPriv: b64d(s.signPriv), sigPub: b64d(s.signPub) };
  const t: T.TNode[] = s.nodes.map((n) => {
    if (n.k === 1) return { k: 1, v: { enc: b64d(n.enc!), sig: b64d(n.sig!), cred: b64d(n.cred!), ph: n.ph ? b64d(n.ph) : null, unmerged: [] } };
    if (n.k === 2) return { k: 2, v: { enc: b64d(n.enc!), sig: b64d(n.sig!), ph: b64d(n.ph!), unmerged: [] } };
    return { k: 0 };
  });
  const initPriv = b64d(s.initPriv);
  const g: G.Group = {
    id: b64d(s.gid),
    epoch: s.epoch,
    n: s.n,
    t,
    priv: new Map([[2 * s.me, initPriv]]),
    me: s.me,
    self: signer,
    initPriv,
    initPub: b64d(s.initPub),
    secrets: {
      init: b64d(s.secrets.init),
      welcome: b64d(s.secrets.welcome),
      epoch: b64d(s.secrets.epoch),
      sender: b64d(s.secrets.sender),
      encryption: b64d(s.secrets.encryption),
      exporter: b64d(s.secrets.exporter),
      external: b64d(s.secrets.external),
      confirm: b64d(s.secrets.confirm),
      membership: b64d(s.secrets.membership),
      resumption: b64d(s.secrets.resumption),
      auth: b64d(s.secrets.auth),
    },
    prevConfirmed: b64d(s.prevConfirmed),
    confirmed: b64d(s.confirmed),
    interim: b64d(s.interim),
    confirmation: b64d(s.confirmation),
    leafSecret: s.leafSecret ? b64d(s.leafSecret) : null,
    held: s.held.map((h) => ({ node: h.node, pathSecret: b64d(h.pathSecret) })),
    fromCommit: (s.fromCommit || []).map((h) => ({ node: h.node, pathSecret: b64d(h.pathSecret) })),
    extensions: b64d(s.extensions),
    seed: b64d(s.seed),
    hs: { secret: new Uint8Array(32), gen: 0 },
    app: { secret: new Uint8Array(32), gen: 0 },
  };
  const r = restore(s);
  g.hs = r.hs;
  g.app = r.app;
  g.fromCommit = (s.fromCommit || []).map((h) => ({ node: h.node, pathSecret: b64d(h.pathSecret) }));
  g.held = s.held.map((h) => ({ node: h.node, pathSecret: b64d(h.pathSecret) }));
  return g;
}

export type WelcomeWire = {
  info: string;
  entries: { ref: string; kem: string; ct: string; path: { node: number; kem: string; ct: string }[] }[];
};

export function packWelcome(w: G.Welcome): WelcomeWire {
  return {
    info: b64e(G.writeGroupInfoFrom(w.info)),
    entries: w.entries.map((e) => ({
      ref: b64e(e.ref),
      kem: b64e(e.enc.kemOutput),
      ct: b64e(e.enc.ciphertext),
      path: e.path.map((s) => ({ node: s.node, kem: b64e(s.kemOutput), ct: b64e(s.ciphertext) })),
    })),
  };
}

export function unpackWelcome(w: WelcomeWire): G.Welcome {
  return {
    info: G.readGroupInfo(new Buf(b64d(w.info))),
    entries: w.entries.map((e) => ({
      ref: b64d(e.ref),
      enc: { kemOutput: b64d(e.kem), ciphertext: b64d(e.ct) },
      path: (e.path || []).map((s) => ({ node: s.node, kemOutput: b64d(s.kem), ciphertext: b64d(s.ct) })),
    })),
  };
}

export function acceptWelcome(signer: G.Self, init: K.Key, w: WelcomeWire, ref: Uint8Array): G.Group {
  return G.join(signer, init, unpackWelcome(w), ref).group;
}

export function accept(signer: G.Self): { pkg: Uint8Array; key: K.Key; ref: Uint8Array } {
  const o = offer(signer);
  return { pkg: o.pkg, key: o.init, ref: o.ref };
}

export function addMembers(g: G.Group, pkgs: Uint8Array[]): G.CommitOut {
  return G.commit(g, pkgs, []);
}

export function dropMembers(g: G.Group, leaves: number[]): G.CommitOut {
  return G.commit(g, [], leaves);
}

export function applyCommit(g: G.Group, out: G.CommitOut): G.Group {
  return G.applyCommit(g, out);
}

export type RemoteWire = {
  content: string;
  signature: string;
  joiner: string;
  shares: { l: number; n: number; k: string; c: string }[];
};

export function applyAny(g: G.Group, w: RemoteWire, shares: { l: number; n: number; k: string; c: string }[]): G.Group {
  const list = shares && shares.length ? shares : w.shares;
  const parsed: { node: number; kemOutput: Uint8Array; ciphertext: Uint8Array }[] = [];
  for (const s of list || []) {
    try {
      parsed.push({ node: Number(s.n), kemOutput: b64d(s.k), ciphertext: b64d(s.c) });
    } catch (e) {}
  }
  return G.applyRemote(g, {
    content: b64d(w.content),
    signature: b64d(w.signature),
    joiner: b64d(w.joiner),
    shares: parsed
  });
}

export function remote(out: G.CommitOut, pub: Uint8Array): RemoteWire {
  const leaf = G.leafIndexOf(out.group.t, pub);
  let hit: G.OutShare | null = null;
  if (leaf >= 0) {
    for (const s of out.pathShares) {
      if (s.forLeaf === leaf) {
        hit = s;
        break;
      }
    }
  }
  return {
    content: b64e(out.content),
    signature: b64e(out.signature),
    joiner: b64e(out.joiner),
    shares: out.pathShares.map((s) => ({ l: s.forLeaf, n: s.node, k: b64e(s.kemOutput), c: b64e(s.ciphertext) }))
  };
}

export function applyWire(g: G.Group, w: RemoteWire): G.Group {
  return applyAny(g, w, w.shares || []);
}

export function rotateLeaf(g: G.Group): G.CommitOut {
  return G.commit(g, [], [], { updates: [g.me] });
}

export function pskCommit(g: G.Group, psk: Uint8Array, id: Uint8Array): G.CommitOut {
  return G.commit(g, [], [], { psks: [{ secret: psk, id }] });
}

export function reseed(g: G.Group): G.Group {
  G.refresh(g, null, g.held);
  return g;
}

export function sealApp(g: G.Group, plaintext: Uint8Array): { ct: string; gen: number } {
  const gen = g.app.gen;
  const rk = S.step(g.app);
  const out = M.sealPrivate(g.id, g.epoch, M.APPLICATION, new Uint8Array(0), plaintext, g.secrets.sender, rk.key, rk.nonce, g.me, gen);
  rk.key.fill(0);
  rk.nonce.fill(0);
  const sdLen = out.encryptedSenderData.length;
  const v = new Uint8Array(3 + sdLen + out.ciphertext.length);
  v[0] = 1;
  v[1] = (sdLen >> 8) & 255;
  v[2] = sdLen & 255;
  v.set(out.encryptedSenderData, 3);
  v.set(out.ciphertext, 3 + sdLen);
  return { ct: b64e(v), gen: out.generation };
}

export function senderSeed(g: G.Group, leaf: number): Uint8Array {
  if (leaf === g.me) return g.seed;
  const root = X.rootSecret(g.secrets.encryption);
  const known = g.fromCommit.concat(g.held);
  return X.leafSecret(root, null, known, leaf, g.n);
}

export function openApp(g: G.Group, blob: Uint8Array): { body: Uint8Array; leaf: number; generation: number } | null {
  if (blob.length < 24 || blob[0] !== 1) return null;
  const sdLen = (blob[1] << 8) | blob[2];
  if (sdLen < 28 || 3 + sdLen + 16 > blob.length) return null;
  const enc = blob.subarray(3, 3 + sdLen);
  const ct = blob.subarray(3 + sdLen);
  try {
    return M.openPrivate(g.id, g.epoch, M.APPLICATION, new Uint8Array(0), enc, ct, g.secrets.sender, (leaf, gen) => {
      if (leaf < 0 || leaf >= g.n) throw new Error("bad leaf");
      return X.ratchetAt(b64e(g.id), leaf, senderSeed(g, leaf), gen);
    });
  } catch (e) {
    return null;
  }
}

export function exportKey(g: G.Group, label: string, ctx: Uint8Array, len: number): Uint8Array {
  return S.exportSecret(g.secrets.exporter, label, ctx, len);
}

export function externalPub(g: G.Group): Uint8Array {
  return P.externalKeyPair(g.secrets.external).pub;
}

export function resumption(g: G.Group): Uint8Array {
  return Uint8Array.from(g.secrets.resumption);
}

export function leafOf(g: G.Group, who: Uint8Array): number {
  return G.leafIndexOf(g.t, who);
}

export function members(g: G.Group): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < g.n; i++) {
    const n = g.t[2 * i];
    if (n.k === 1) out.push((n.v as T.Leaf).cred);
  }
  return out;
}

export function treeHashOf(g: G.Group): Uint8Array {
  return treeHash(g.t, g.n);
}

export function confirmTag(g: G.Group): Uint8Array {
  return Uint8Array.from(g.confirmation);
}

export function leafSecretAt(g: G.Group, leaf: number): Uint8Array {
  return X.leafSecret(X.rootSecret(g.secrets.encryption), null, g.fromCommit, leaf, g.n);
}

export function nodeSecretOf(v: Uint8Array): Uint8Array {
  return X.nodeSecret(v);
}

export function ratchetFrom(pathSecret: Uint8Array): Uint8Array {
  return X.nodeSecret(pathSecret);
}

export function forgetRatchets(room: string): void {
  X.forgetRatchets(room);
}
export function encode(v: Uint8Array): string {
  return b64e(v);
}

export function decode(v: string): Uint8Array {
  return b64d(v);
}
