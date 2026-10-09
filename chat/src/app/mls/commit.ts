import { ed25519 } from "@noble/curves/ed25519.js";
import * as K from "./hpke.ts";
import * as S from "./schedule.ts";
import * as T from "./tree.ts";
import * as X from "./secret.ts";
import * as F from "./frame.ts";
import { leafNodeInput, parentNodeInput, treeHash } from "./hash.ts";
import * as P from "./psk.ts";
import { Buf, Writer } from "./wire.ts";
const EMPTY = new Uint8Array(0);
const NIL = new Uint8Array(32);

const writeExtensions = P.writeExtensions;
const writePskId = P.writePskId;
const writeLeafNode = F.writeLeafNode;

export type Self = { sigPriv: Uint8Array; sigPub: Uint8Array };

export type Group = {
  id: Uint8Array;
  epoch: number;
  n: number;
  t: T.TNode[];
  priv: Map<number, Uint8Array>;
  me: number;
  self: Self;
  initPriv: Uint8Array;
  initPub: Uint8Array;
  secrets: S.EpochSecrets;
  prevConfirmed: Uint8Array;
  confirmed: Uint8Array;
  interim: Uint8Array;
  confirmation: Uint8Array;
  hs: S.Ratchet;
  app: S.Ratchet;
  leafSecret: Uint8Array | null;
  held: X.Held[];
  extensions: Uint8Array;
  seed: Uint8Array;
  fromCommit: X.Held[];
};

export function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function makeSelf(): Self {
  const sigPriv = ed25519.utils.randomSecretKey();
  return { sigPriv, sigPub: ed25519.getPublicKey(sigPriv) };
}

export function makeKeyPackage(self: Self): { pkg: Uint8Array; init: K.Key; leaf: F.Leaf } {
  const init = K.keygen();
  const base: F.Leaf = { enc: init.pub, sig: EMPTY, cred: self.sigPub, source: F.SRC_KEY_PACKAGE, parentHash: null };
  const leaf = signLeaf(self, base, null, 0);
  const now = Math.floor(Date.now() / 1000);
  const pkg = F.keyPackage(self.sigPub, init.pub, now, now + 86400, leaf.sig, (m) => ed25519.sign(m, self.sigPriv));
  return { pkg, init, leaf };
}

export function leafFromPackage(pkg: Uint8Array): F.Leaf {
  const b = new Buf(pkg);
  const body = b.vec();
  const sig = b.vec();
  const leafSig = b.vec();
  const inner = new Buf(body);
  inner.u16();
  const sigPub = inner.vec();
  const enc = inner.vec();
  inner.vec();
  inner.u64();
  inner.u64();
  if (!ed25519.verify(sig, F.tbsLabel("KeyPackageTBS", body), sigPub)) throw new Error("bad key package signature");
  const leaf: F.Leaf = { enc, sig: leafSig, cred: sigPub, source: F.SRC_KEY_PACKAGE, parentHash: null };
  if (!verifyLeaf(leaf, null, 0)) throw new Error("bad key package leaf signature");
  return leaf;
}

export function signLeaf(self: Self, v: F.Leaf, groupId: Uint8Array | null, index: number): F.Leaf {
  return { ...v, sig: ed25519.sign(F.tbsLabel("LeafNodeTBS", F.leafTbs(v, groupId, index, 0, 0)), self.sigPriv) };
}

export function verifyLeaf(v: F.Leaf, groupId: Uint8Array | null, index: number): boolean {
  try {
    return ed25519.verify(v.sig, F.tbsLabel("LeafNodeTBS", F.leafTbs(v, groupId, index, 0, 0)), v.cred);
  } catch {
    return false;
  }
}

export function leafIndexOf(t: T.TNode[], pub: Uint8Array): number {
  for (let i = 0; i * 2 < t.length; i++) {
    const node = t[2 * i];
    if (node.k !== 1) continue;
    if (eq((node.v as T.Leaf).cred, pub)) return i;
  }
  return -1;
}

function clone(t: T.TNode[]): T.TNode[] {
  return t.map((x): T.TNode => {
    if (x.k === 0) return { k: 0 };
    if (x.k === 1) return { k: 1, v: { ...x.v, unmerged: [...x.v.unmerged] } };
    return { k: 2, v: { ...x.v, unmerged: [...x.v.unmerged] } };
  });
}

function toLeafNode(v: T.Leaf): F.Leaf {
  return {
    enc: v.enc,
    sig: v.sig,
    cred: v.cred,
    source: v.ph === null ? F.SRC_KEY_PACKAGE : F.SRC_COMMIT,
    parentHash: v.ph,
  };
}

export type GroupInfo = {
  groupId: Uint8Array;
  epoch: number;
  treeHash: Uint8Array;
  prevConfirmed: Uint8Array;
  confirmed: Uint8Array;
  interim: Uint8Array;
  confirmation: Uint8Array;
  nodes: Uint8Array[];
};

export function groupInfoOf(g: Group): GroupInfo {
  const nodes: Uint8Array[] = [];
  for (let i = 0; i < T.alloc(g.n); i++) {
    const nd = g.t[i];
    if (nd.k === 1) nodes.push(F.writeLeafNode(toLeafNode(nd.v as T.Leaf)));
    else if (nd.k === 2) {
      const p = nd.v as T.Par;
      nodes.push(F.writeParentNode({ enc: p.enc, sig: p.sig, parentHash: p.ph }));
    } else nodes.push(EMPTY);
  }
  return {
    groupId: g.id,
    epoch: g.epoch,
    treeHash: treeHash(g.t, g.n),
    prevConfirmed: g.prevConfirmed,
    confirmed: g.confirmed,
    interim: g.interim,
    confirmation: g.confirmation,
    nodes,
  };
}

export function writeGroupInfo(g: Group): Uint8Array {
  const info = groupInfoOf(g);
  return writeGroupInfoFrom(info);
}

export function writeGroupInfoFrom(info: GroupInfo): Uint8Array {
  const w = new Writer();
  w.u16(F.VERSION)
    .u16(F.SUITE)
    .vec(info.groupId)
    .u64(info.epoch)
    .vec(info.treeHash)
    .vec(info.prevConfirmed)
    .vec(info.confirmed)
    .vec(info.interim)
    .vec(info.confirmation);
  for (const n of info.nodes) w.vec(n);
  return w.out();
}

export function readGroupInfo(b: Buf): GroupInfo {
  b.u16();
  b.u16();
  const groupId = b.vec();
  const epoch = b.u64();
  const th = b.vec();
  const prevConfirmed = b.vec();
  const confirmed = b.vec();
  const interim = b.vec();
  const confirmation = b.vec();
  const nodes: Uint8Array[] = [];
  while (!b.done) nodes.push(b.vec());
  return { groupId, epoch, treeHash: th, prevConfirmed, confirmed, interim, confirmation, nodes };
}

export function applyGroupInfo(
  info: GroupInfo,
  self: Self,
  initPriv: Uint8Array,
  initPub: Uint8Array,
  n: number,
  secret: Uint8Array | null,
  held: X.Held[],
): Group {
  const t = T.emptySlots(n);
  const priv = new Map<number, Uint8Array>();
  const leaves: Uint8Array[] = [];
  const parents = new Map<number, T.Par>();
  let leafSlot = 0;
  for (let i = 0; i < info.nodes.length; i++) {
    const raw = info.nodes[i];
    if (raw.length === 0) continue;
    const nb = new Buf(raw);
    if (T.level(i) === 0) {
      const l = F.readLeafNode(nb);
      if (!verifyLeaf(l, info.groupId, leafSlot)) throw new Error("bad leaf signature");
      t[i] = { k: 1, v: { enc: l.enc, sig: l.sig, cred: l.cred, ph: l.parentHash, unmerged: [] } };
      leaves.push(l.enc);
      leafSlot++;
    } else {
      const p = F.readParentNode(nb);
      t[i] = { k: 2, v: { enc: p.enc, sig: p.sig, ph: p.parentHash, unmerged: [] } };
      parents.set(i, { enc: p.enc, sig: p.sig, ph: p.parentHash, unmerged: [] });
    }
  }
  const me = leafIndexOf(t, self.sigPub);
  if (me < 0) throw new Error("not a member");
  priv.set(2 * me, initPriv);
  const g: Group = {
    id: info.groupId,
    epoch: info.epoch,
    n,
    t,
    priv,
    me,
    self,
    initPriv,
    initPub,
    secrets: S.epochFrom(NIL, K.fresh(), EMPTY, F.groupContext(info.groupId, info.epoch, F.SUITE, info.treeHash, info.prevConfirmed)),
    prevConfirmed: info.prevConfirmed,
    confirmed: info.confirmed,
    interim: info.interim,
    confirmation: info.confirmation,
    hs: S.initLeaf(NIL, "handshake"),
    app: S.initLeaf(NIL, "application"),
    leafSecret: null,
    held: [],
    extensions: EMPTY,
  seed: new Uint8Array(32),
    fromCommit: [],
  };
  void leaves;
  refresh(g, secret, held);
  return g;
}

function subtreeHash(t: T.TNode[], x: number): Uint8Array {
  if (T.level(x) === 0) return leafNodeHash(x / 2, t[x]);
  const l = subtreeHash(t, T.left(x));
  const r = subtreeHash(t, T.right(x));
  return parentNodeHash(t[x], l, r);
}

function leafNodeHash(index: number, node: T.TNode): Uint8Array {
  return T.hash(leafNodeInput(index, node));
}

function parentNodeHash(node: T.TNode, l: Uint8Array, r: Uint8Array): Uint8Array {
  return T.hash(parentNodeInput(node, l, r));
}

export function create(id: Uint8Array, self: Self, pkg: Uint8Array, init: K.Key): Group {
  const leaf = signLeaf(self, leafFromPackage(pkg), null, 0);
  const t: T.TNode[] = [{ k: 1, v: { enc: leaf.enc, sig: leaf.sig, cred: leaf.cred, ph: null, unmerged: [] } }];
  const g: Group = {
    id,
    epoch: 0,
    n: 1,
    t,
    priv: new Map([[0, init.priv]]),
    me: 0,
    self,
    initPriv: init.priv,
    initPub: init.pub,
    secrets: S.epochFrom(NIL, K.fresh(), EMPTY, F.groupContext(id, 0, F.SUITE, treeHash(t, 1), EMPTY)),
    prevConfirmed: EMPTY,
    confirmed: EMPTY,
    interim: EMPTY,
    confirmation: EMPTY,
    hs: S.initLeaf(NIL, "handshake"),
    app: S.initLeaf(NIL, "application"),
    leafSecret: null,
    held: [],
    extensions: EMPTY,
  seed: new Uint8Array(32),
    fromCommit: [],
  };
  refresh(g, null, []);
  return g;
}

export function refresh(g: Group, own: Uint8Array | null, held: X.Held[]): void {
  const root = X.rootSecret(g.secrets.encryption);
  const ls = X.leafSecret(root, own, held, g.me, g.n);
  const r = X.ratchets(ls);
  g.hs = r.hs;
  g.app = r.app;
  g.seed = ls;
  g.leafSecret = own;
  g.held = held;
}

function sharesFor(
  t: T.TNode[],
  n: number,
  committer: number,
  target: number,
  fdp: number[],
  path: F.UpdatePath,
  targetEnc: Uint8Array,
): PathShare[] {
  const cp = T.copath(2 * committer, n);
  const out: PathShare[] = [];
  for (let i = 0; i < fdp.length; i++) {
    const live = T.resolution(t, cp[i]);
    const node = t[2 * target];
    if (node.k === 0) continue;
    const targetPk = node.k === 1 ? (node.v as T.Leaf).enc : (node.v as T.Par).enc;
    if (!eq(targetPk, targetEnc)) continue;
    let slot = -1;
    for (let k = 0; k < live.length; k++) {
      const nd = t[live[k]];
      if (nd.k === 0) continue;
      const pk = nd.k === 1 ? (nd.v as T.Leaf).enc : (nd.v as T.Par).enc;
      if (eq(pk, targetEnc)) slot = live.indexOf(live[k]);
    }
    if (slot < 0) continue;
    const slice = blobsAt(path.nodes[i].kemOutput, slot);
    if (slice) out.push({ node: fdp[i], kemOutput: slice.kemOutput, ciphertext: slice.ciphertext });
  }
  return out;
}

function blobsAt(blob: Uint8Array, index: number): { kemOutput: Uint8Array; ciphertext: Uint8Array } | null {
  const b = new Buf(blob);
  let i = 0;
  while (!b.done && i <= index) {
    const item = b.vec();
    const ib = new Buf(item);
    const kemOutput = ib.vec();
    const ciphertext = ib.vec();
    if (i === index) return { kemOutput, ciphertext };
    i++;
  }
  return null;
}

export type GroupSecrets = { joiner: Uint8Array; pathSecret: Uint8Array | null };



export type EncGroupSecrets = { kemOutput: Uint8Array; ciphertext: Uint8Array };

export type PathShare = { node: number; kemOutput: Uint8Array; ciphertext: Uint8Array };

export type WelcomeEntry = { ref: Uint8Array; enc: EncGroupSecrets; path: PathShare[] };

export type Welcome = { info: GroupInfo; entries: WelcomeEntry[] };

export type CommitOpts = {
  psks?: { secret: Uint8Array; id: Uint8Array; nonce?: Uint8Array }[];
  updates?: number[];
  extensions?: Uint8Array[];
};

function pskSecretOf(psks: { secret: Uint8Array; id: Uint8Array; nonce: Uint8Array }[]): Uint8Array {
  if (psks.length === 0) return EMPTY;
  return S.makePskSecret(
    psks.map((p) => p.secret),
    psks.map((p) => writePskId({ t: P.PSK_EXTERNAL, id: p.id, nonce: p.nonce })),
  );
}

export function leafToPackage(v: T.Leaf): Uint8Array {
  return F.keyPackage(v.cred, v.enc, 0, 0, v.sig, () => v.sig);
}

export type OutShare = { forLeaf: number; node: number; kemOutput: Uint8Array; ciphertext: Uint8Array };

export type CommitOut = {
  content: Uint8Array;
  signature: Uint8Array;
  confirmationTag: Uint8Array;
  group: Group;
  welcome: Welcome | null;
  pathShares: OutShare[];
  joiner: Uint8Array;
  committer: number;
};

export type Remote = {
  content: Uint8Array;
  signature: Uint8Array;
  joiner: Uint8Array;
  shares: { node: number; kemOutput: Uint8Array; ciphertext: Uint8Array }[];
};

export function applyRemote(g: Group, wire: Remote): Group {
  const fr = F.readFramed(new Buf(wire.content));
  if (!eq(fr.groupId, g.id)) throw new Error("wrong group id");
  if (fr.epoch !== g.epoch) throw new Error("commit is for epoch " + fr.epoch + ", group is at " + g.epoch);
  if (fr.ctype !== F.COMMIT) throw new Error("not a commit");
  if (fr.sender < 0 || fr.sender >= g.n) throw new Error("committer not in tree");

  const senderLeaf = g.t[2 * fr.sender];
  if (senderLeaf.k !== 1) throw new Error("committer leaf is blank");
  const cred = (senderLeaf.v as T.Leaf).cred;

  const signCtx = P.groupContextExt(g.id, g.epoch, F.SUITE, treeHash(g.t, g.n), g.confirmed, new Uint8Array(0));
  const tbs = F.contentTbsExt(F.WIRE_PUBLIC, wire.content, signCtx, new Uint8Array(0));
  if (!ed25519.verify(wire.signature, tbs, cred)) throw new Error("commit signature did not verify");

  const bb = new Buf(fr.body);
  const hasPath = !bb.none();
  const path = hasPath ? F.readPath(new Buf(bb.vec())) : null;
  const pb = new Buf(bb.vec());
  const proposals: F.Proposal[] = [];
  while (!pb.done) proposals.push(F.readProposal(new Buf(pb.vec())));

  const ext = g.extensions;
  const t = clone(g.t);
  let n = g.n;
  const fresh: F.Leaf[] = [];
  let removed = 0;
  for (const pr of proposals) {
    if (pr.t === F.ADD) fresh.push(leafFromPackage(pr.pkg));
    else if (pr.t === F.REMOVE) {
      if (pr.leaf < 0 || pr.leaf >= n) throw new Error("remove out of range");
      t[2 * pr.leaf] = { k: 0 };
      removed++;
    }
  }

  let at = g.n;
  for (const l of fresh) {
    while (t.length < T.alloc(n + 1)) t.push({ k: 0 });
    t[2 * at] = { k: 1, v: { enc: l.enc, sig: l.sig, cred: l.cred, ph: null, unmerged: [] } };
    at++;
  }
  n += fresh.length;
  if (removed > 0) {
    const packed = T.emptySlots(n);
    let slot = 0;
    for (let i = 0; i < n; i++) {
      if (t[2 * i] && t[2 * i].k === 1) {
        packed[2 * slot] = t[2 * i];
        slot++;
      }
    }
    for (let i = 0; i < packed.length; i++) if (!packed[i]) packed[i] = { k: 0 };
    t.length = 0;
    for (const nd of packed) t.push(nd);
    n = slot;
  }

  const encs: Uint8Array[] = [];
  if (path) {
    const fdp = T.filteredDirectPath(t, fr.sender, n);
    for (let i = 0; i < fdp.length; i++) {
      const enc = path.nodes[i] ? path.nodes[i].enc : new Uint8Array(32);
      encs.push(enc);
      t[fdp[i]] = { k: 2, v: { enc, sig: EMPTY, ph: new Uint8Array(32), unmerged: [] } };
    }
    const phs = parentHashChain(t, fdp, encs, n);
    for (let i = 0; i < fdp.length; i++) {
      const nd = t[fdp[i]];
      if (nd.k === 2) nd.v.ph = phs[i];
    }
    t[2 * fr.sender] = { k: 1, v: { enc: path.leaf.enc, sig: path.leaf.sig, cred: path.leaf.cred, ph: phs[0] ?? EMPTY, unmerged: [] } };
  }

  const ctx = P.groupContextExt(g.id, g.epoch + 1, F.SUITE, treeHash(t, n), g.confirmed, ext);
  const confirmed = F.nextConfirmed(g.interim, F.WIRE_PUBLIC, wire.content, wire.signature);
  const secrets = S.epochFromJoiner(wire.joiner, ctx);
  const tag = S.confirmationTag(secrets.confirm, confirmed);

  const held: X.Held[] = [];
  const label = F.tbsLabel("UpdatePathNode", ctx);
  const priv = g.priv.get(2 * g.me);
  if (priv && wire.shares) {
    for (const sh of wire.shares) {
      try {
        const sk = K.decap(priv, sh.kemOutput);
        const c = K.keySchedule(sk, label);
        const secret = K.openC(c, label, sh.ciphertext);
        sk.fill(0);
        held.push({ node: sh.node, pathSecret: secret });
        break;
      } catch (e) {}
    }
  }

  const privNext = new Map(g.priv);
  const next: Group = {
    ...g,
    epoch: g.epoch + 1,
    n,
    t,
    priv: privNext,
    secrets,
    prevConfirmed: g.confirmed,
    confirmed,
    interim: F.nextInterim(confirmed, tag),
    confirmation: tag,
    fromCommit: held,
    held
  };
  refresh(next, null, held);
  return next;
}

export function commit(g: Group, adds: Uint8Array[], removes: number[], opts: CommitOpts = {}): CommitOut {
  const psks = (opts.psks ?? []).map((x) => ({ ...x, nonce: x.nonce ?? P.freshNonce() }));
  const resolved: CommitOpts = { ...opts, psks };
  const p = prepare(g, adds, removes, resolved);
  const ext = writeExtensions(opts.extensions ?? []);
  const signCtx = P.groupContextExt(g.id, g.epoch, F.SUITE, treeHash(g.t, g.n), g.confirmed, EMPTY);
  const provisionalCtx = P.groupContextExt(g.id, g.epoch + 1, F.SUITE, treeHash(p.t, p.n), g.confirmed, ext);
  const body = F.writeCommit(p.path, p.proposals);
  const content = F.framed(g.id, g.epoch, g.me, EMPTY, F.COMMIT, body);
  const tbs = F.contentTbsExt(F.WIRE_PUBLIC, content, signCtx, EMPTY);
  const signature = ed25519.sign(tbs, g.self.sigPriv);
  const commitSecret = K.fresh();
  const pskSecret = pskSecretOf(psks);
  const secrets = S.epochFrom(g.secrets.init, commitSecret, pskSecret, provisionalCtx);
  const confirmed = F.nextConfirmed(g.interim, F.WIRE_PUBLIC, content, signature);
  const tag = S.confirmationTag(secrets.confirm, confirmed);
  const interim = F.nextInterim(confirmed, tag);
  const joinerSecret = S.joinerFromJoiner(S.joinerOf(g.secrets.init, commitSecret, provisionalCtx), pskSecret);

  const nextPriv = new Map(g.priv);
  for (const [node, priv] of p.priv) nextPriv.set(node, priv);
  const next: Group = {
    ...g,
    epoch: g.epoch + 1,
    n: p.n,
    t: p.t,
    priv: nextPriv,
    extensions: ext,
    secrets,
    prevConfirmed: g.confirmed,
    confirmed,
    interim,
    confirmation: tag,
    leafSecret: p.leafSecret,
    held: p.held,
  };
  refresh(next, null, p.held);

  let welcome: Welcome | null = null;
  if (adds.length > 0) {
    const entries: WelcomeEntry[] = [];
    const newInfo: GroupInfo = groupInfoOf(next);
    const infoBytes = writeGroupInfo(next);
    for (let i = 0; i < adds.length; i++) {
      const pkgLeaf = leafFromPackage(adds[i]);
      const ref = F.keyPackageRef(adds[i]);
      const target = g.n + i;
      const ownPath = T.filteredDirectPath(p.t, target, p.n);
      const chain = X.pathChain(K.fresh(), ownPath.length);
      const e = K.encap(pkgLeaf.enc);
      const pw = new Writer().vec(joinerSecret);
      for (const sec of chain) pw.vec(sec);
      const payload = pw.out();
      const c = K.keySchedule(e.shared, F.tbsLabel("Welcome", infoBytes));
      const ciphertext = K.seal(c, F.tbsLabel("Welcome", infoBytes), payload);
      e.shared.fill(0);
      const path = sharesFor(p.t, p.n, g.me, target, p.fdp, p.path, pkgLeaf.enc);
      entries.push({ ref, enc: { kemOutput: e.kemOutput, ciphertext }, path });
    }
    welcome = { info: newInfo, entries };
  }

  return { content, signature, confirmationTag: tag, group: next, welcome, pathShares: p.out, joiner: joinerSecret, committer: g.me };
}

export type Joined = {
  group: Group;
  interim: Uint8Array;
};

export function applyCommit(g: Group, from: CommitOut): Group {
  const prev = from.group;
  const shared: X.Held[] = [];
  const ext = prev.extensions;
  const provisional = P.groupContextExt(g.id, g.epoch + 1, F.SUITE, treeHash(prev.t, prev.n), g.confirmed, ext);
  const secrets = prev.secrets;
  const label = F.tbsLabel("UpdatePathNode", provisional);
  for (const share of commitPathShares(from, g.me)) {
    try {
      const sk = K.decap(g.priv.get(2 * g.me) ?? g.initPriv, share.kemOutput);
      const c = K.keySchedule(sk, label);
      const secret = K.openC(c, label, share.ciphertext);
      sk.fill(0);
      shared.push({ node: share.node, pathSecret: secret });
    } catch (e) {}
  }
  const next: Group = {
    ...g,
    epoch: g.epoch + 1,
    n: prev.n,
    t: prev.t,
    priv: new Map(g.priv),
    secrets,
    prevConfirmed: g.confirmed,
    confirmed: prev.confirmed,
    interim: prev.interim,
    confirmation: prev.confirmation,
    extensions: ext,
    fromCommit: shared,
  };
  refresh(next, null, shared);
  return next;
}

function commitPathShares(from: CommitOut, me: number): PathShare[] {
  const out: PathShare[] = [];
  const nodes = from.pathShares || [];
  for (const s of nodes) {
    if (s.forLeaf === me) out.push({ node: s.node, kemOutput: s.kemOutput, ciphertext: s.ciphertext });
  }
  return out;
}

export function join(self: Self, init: K.Key, welcome: Welcome, ref: Uint8Array): Joined {
  const entry = welcome.entries.find((e) => eq(e.ref, ref));
  if (!entry) throw new Error("welcome has no entry for this key package");
  const shared = K.decap(init.priv, entry.enc.kemOutput);
  const infoBytes = writeGroupInfoFrom(welcome.info);
  const c = K.keySchedule(shared, F.tbsLabel("Welcome", infoBytes));
  const payload = c && K.openC(c, F.tbsLabel("Welcome", infoBytes), entry.enc.ciphertext);
  shared.fill(0);
  const pb = new Buf(payload);
  const joiner = pb.vec();
  const chain: Uint8Array[] = [];
  while (!pb.done) chain.push(pb.vec());
  const n = countLeaves(welcome.info.nodes);
  const ctx = P.groupContextExt(welcome.info.groupId, welcome.info.epoch, F.SUITE, welcome.info.treeHash, welcome.info.prevConfirmed, EMPTY);
  const g = applyGroupInfo(welcome.info, self, init.priv, init.pub, n, null, []);
  g.secrets = S.epochFromJoiner(joiner, ctx);
  g.interim = welcome.info.interim;
  const own = T.filteredDirectPath(g.t, g.me, n);
  const label = F.tbsLabel("UpdatePathNode", ctx);
  const fromCommit: X.Held[] = [];
  for (const share of entry.path) {
    try {
      const shared = K.decap(init.priv, share.kemOutput);
      const c = K.keySchedule(shared, label);
      const secret = K.openC(c, label, share.ciphertext);
      shared.fill(0);
      fromCommit.push({ node: share.node, pathSecret: secret });
    } catch (e) {}
  }
  g.fromCommit = fromCommit;
  const ownHeld: X.Held[] = own.map((node, i) => ({ node, pathSecret: chain[i] }));
  refresh(g, null, [...ownHeld, ...fromCommit]);
  return { group: g, interim: welcome.info.interim };
}

function countLeaves(nodes: Uint8Array[]): number {
  let c = 0;
  for (let i = 0; i < nodes.length; i += 2) if (nodes[i].length > 0) c++;
  return c;
}

export type Prepared = {
  path: F.UpdatePath;
  proposals: F.Proposal[];
  t: T.TNode[];
  n: number;
  ctx: Uint8Array;
  leafSecret: Uint8Array;
  held: X.Held[];
  priv: Map<number, Uint8Array>;
  fdp: number[];
  out: OutShare[];
};

export function prepare(g: Group, adds: Uint8Array[], removes: number[], opts: CommitOpts = {}): Prepared {
  const t = clone(g.t);
  const updatedPriv = new Map<number, Uint8Array>();
  const proposals: F.Proposal[] = [];
  for (const l of removes) {
    if (l < 0 || l >= g.n) throw new Error("leaf out of range");
    t[2 * l] = { k: 0 };
    proposals.push({ t: F.REMOVE, leaf: l });
  }
  for (const l of opts.updates ?? []) {
    if (l < 0 || l >= g.n) throw new Error("leaf out of range");
    const old = t[2 * l];
    if (old.k !== 1) throw new Error("update of a blank leaf");
    const fresh = K.keygen();
    updatedPriv.set(2 * l, fresh.priv);
    const node = signLeaf(g.self, { enc: fresh.pub, sig: EMPTY, cred: g.self.sigPub, source: F.SRC_UPDATE, parentHash: null }, g.id, l);
    t[2 * l] = { k: 1, v: { enc: node.enc, sig: node.sig, cred: node.cred, ph: null, unmerged: [] } };
    proposals.push({ t: F.UPDATE, pkg: writeLeafNode(node) });
  }
  const pskIds = (opts.psks ?? []).map((p) => writePskId({ t: P.PSK_EXTERNAL, id: p.id, nonce: p.nonce ?? P.freshNonce() }));
  for (const id of pskIds) proposals.push({ t: F.PSK, psk: id });
  const fresh: F.Leaf[] = [];
  for (const pkg of adds) {
    fresh.push(leafFromPackage(pkg));
    proposals.push({ t: F.ADD, pkg });
  }
  const n = g.n + fresh.length;
  while (t.length < T.alloc(n)) t.push({ k: 0 });
  let at = g.n;
  for (const l of fresh) {
    t[2 * at] = { k: 1, v: { enc: l.enc, sig: l.sig, cred: l.cred, ph: null, unmerged: [] } };
    at++;
  }
  const leafSecret = K.fresh();
  const fdp = T.filteredDirectPath(t, g.me, n);
  const chain = X.pathChain(leafSecret, fdp.length + 1);
  const cp = T.copath(2 * g.me, n);
  const encs: Uint8Array[] = [];
  const held: X.Held[] = [];
  const seals: Uint8Array[] = [];
  const ctx = P.groupContextExt(g.id, g.epoch + 1, F.SUITE, treeHash(t, n), g.confirmed, writeExtensions(opts.extensions ?? []));
  for (let i = 0; i < fdp.length; i++) {
    const ps = chain[i + 1];
    const pair = K.derivePair(X.nodeSecret(ps));
    encs.push(pair.pub);
    t[fdp[i]] = { k: 2, v: { enc: pair.pub, sig: EMPTY, ph: new Uint8Array(32), unmerged: [] } };
    held.push({ node: fdp[i], pathSecret: ps });
    seals.push(new Uint8Array(0));
  }
  const phs = parentHashChain(t, fdp, encs, n);
  const leafPair = K.derivePair(X.nodeSecret(chain[0]));
  const leaf = signLeaf(
    g.self,
    { enc: leafPair.pub, sig: EMPTY, cred: g.self.sigPub, source: F.SRC_COMMIT, parentHash: phs[0] ?? EMPTY },
    g.id,
    g.me,
  );
  for (let i = 0; i < fdp.length; i++) {
    t[fdp[i]] = { k: 2, v: { enc: encs[i], sig: EMPTY, ph: phs[i], unmerged: [] } };
  }
  t[2 * g.me] = { k: 1, v: { enc: leaf.enc, sig: leaf.sig, cred: leaf.cred, ph: phs[0] ?? EMPTY, unmerged: [] } };
  const provisional = P.groupContextExt(g.id, g.epoch + 1, F.SUITE, treeHash(t, n), g.confirmed, writeExtensions(opts.extensions ?? []));
  const label = F.tbsLabel("UpdatePathNode", provisional);
  const out: OutShare[] = [];
  for (let i = 0; i < fdp.length; i++) {
    const ps = chain[i + 1];
    const bw = new Writer();
    for (const r of T.resolution(t, cp[i])) {
      const nd = t[r];
      if (nd.k === 0) continue;
      const pk = nd.k === 1 ? (nd.v as T.Leaf).enc : (nd.v as T.Par).enc;
      const e = K.encap(pk);
      const c = K.keySchedule(e.shared, label);
      const ct = K.seal(c, label, ps);
      bw.vec(new Writer().vec(e.kemOutput).vec(ct).out());
      for (let who = 0; who < n; who++) {
        const wn = t[2 * who];
        if (wn.k === 0) continue;
        const wpk = wn.k === 1 ? (wn.v as T.Leaf).enc : (wn.v as T.Par).enc;
        if (eq(wpk, pk)) out.push({ forLeaf: who, node: fdp[i], kemOutput: e.kemOutput, ciphertext: ct });
      }
      e.shared.fill(0);
    }
    seals[i] = bw.out();
  }
  const nodes: F.PathNode[] = [];
  for (let i = 0; i < fdp.length; i++) nodes.push({ enc: encs[i], kemOutput: seals[i] });
  return { path: { leaf, nodes }, proposals, t, n, ctx: provisional, leafSecret, held, priv: updatedPriv, fdp, out };
}

function parentHashChain(t: T.TNode[], fdp: number[], encs: Uint8Array[], n: number): Uint8Array[] {
  const out: Uint8Array[] = new Array(fdp.length);
  for (let i = fdp.length - 1; i >= 0; i--) {
    const node = fdp[i];
    const above = i === fdp.length - 1 ? EMPTY : out[i + 1];
    const sibHash = node === T.root(n) ? EMPTY : subtreeHash(t, T.sibling(node, n));
    out[i] = F.parentHashOf(encs[i], above, sibHash);
  }
  return out;
}
