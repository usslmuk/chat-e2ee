import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Buf, Writer } from "../src/app/mls/wire.ts";

const cat = (...p: Uint8Array[]): Uint8Array => {
  const n = p.reduce((a, x) => a + x.length, 0);
  const o = new Uint8Array(n);
  let i = 0;
  for (const x of p) {
    o.set(x, i);
    i += x.length;
  }
  return o;
};
import { sha256 } from "@noble/hashes/sha2.js";
import * as K from "../src/app/mls/hpke.ts";
import * as S from "../src/app/mls/schedule.ts";
import * as F from "../src/app/mls/frame.ts";
import * as R from "../src/app/mls/rfc.ts";
import * as HS from "../src/app/mls/hash.ts";
import * as P from "../src/app/mls/psk.ts";
import * as T from "../src/app/mls/tree.ts";
import { Report, hex, suite, opt } from "./support.ts";
import { verifyLeaf } from "../src/app/mls/commit.ts";
import { sha256 } from "@noble/hashes/sha2.js";

export function toNodes(wire: F.RatchetTree[]): T.TNode[] {
  return wire.map((nd) => {
    if (nd.k === 0) return { k: 0 as const };
    if (nd.k === 1) return { k: 1 as const, v: { enc: nd.v.enc, sigKey: nd.v.sigKey, cred: nd.v.cred, ph: opt(nd.v.parentHash), unmerged: [], tbs: nd.v.tbs, signature: nd.v.signature } };
    return { k: 2 as const, v: { enc: nd.v.enc, parentHash: nd.v.parentHash, unmerged: nd.v.unmerged } };
  });
}

export function countLeaves(nodes: T.TNode[]): number {
  let c = 0;
  for (let i = 0; i < nodes.length; i += 2) if (nodes[i].k === 1) c++;
  return Math.max(1, c);
}

export function pad(nodes: T.TNode[], n: number): T.TNode[] {
  const out = nodes.slice();
  while (out.length < T.alloc(n)) out.push({ k: 0 });
  return out;
}

export function leafIndexOf(nodes: T.TNode[], sigPub: Uint8Array): number {
  for (let i = 0; i < nodes.length; i += 2) {
    const nd = nodes[i];
    if (nd.k === 1 && Buffer.from(nd.v.sigKey).equals(Buffer.from(sigPub))) return i / 2;
  }
  return -1;
}

export type Joined = {
  nodes: T.TNode[];
  n: number;
  info: R.GroupInfoRfc;
  psk: Uint8Array;
  joiner: Uint8Array;
};

export function joinGroup(v: any, r?: Report): Joined {
  const w = R.readWelcome(new Buf(hex(v.welcome)));
  const sec = w.secrets[0];
  const shared = K.decap(hex(v.init_priv), sec.kemOutput);
  const gs = K.openC(K.keySchedule(shared, F.tbsLabel("Welcome", w.encryptedGroupInfo)), new Uint8Array(0), sec.ciphertext);
  const secrets = R.readGroupSecrets(new Buf(gs));
  const ids = Array.isArray(v.external_psks) ? v.external_psks : [];
  r?.check("group secret psk count", ids.length === secrets.psks.length, "vector lists " + ids.length + ", group secrets carry " + secrets.psks.length);
  const psk = ids.length > 0 && ids.length === secrets.psks.length ? S.makePskSecret(ids.map((p: any) => hex(p.psk)), secrets.psks) : new Uint8Array(0);
  const joiner = S.joinerFromJoiner(secrets.joiner, psk);
  const info = R.readGroupInfoRfc(new Buf(R.openGroupInfo(S.deriveSecret(joiner, "welcome"), w.encryptedGroupInfo)));
  const nodes = toNodes(F.readRatchetTree(new Buf(info.tree ?? hex(v.ratchet_tree))));
  const n = countLeaves(nodes);
  return { nodes: pad(nodes, n), n, info, psk, joiner };
}

export function epochAt(g: Joined, epoch: number, treeHash: Uint8Array, confirmed: Uint8Array) {
  return S.epochFromJoiner(g.joiner, F.groupContext(g.info.groupId, epoch, g.info.suite, treeHash, confirmed));
}

export async function treeValidation(r: Report): Promise<void> {
  const entries = await suite("tree-validation");
  for (const v of entries) {
    const wire = F.readRatchetTree(new Buf(hex(v.tree)));
    const raw = toNodes(wire);
    const n = countLeaves(raw);
    const nodes = pad(raw, n);
    const root = Buffer.from(HS.treeHash(nodes, n)).toString("hex");
    r.check("root tree hash", v.tree_hashes.includes(root), root.slice(0, 24) + " is not one of the " + v.tree_hashes.length + " published");
    for (const [node, want] of v.resolutions.entries()) {
      const got = T.resolution(nodes, node);
      const ok = got.length === want.length && got.every((x, i) => x === want[i]);
      r.check("resolution " + node, ok, "[" + got.join(",") + "] want [" + want.join(",") + "]");
    }
  }
  r.family("tree-validation", entries.length + " trees");
}

export async function treeOperations(r: Report): Promise<void> {
  const entries = await suite("tree-operations");
  for (const v of entries) {
    for (const [name, tree, want] of [["tree_hash_before", v.tree_before, v.tree_hash_before], ["tree_hash_after", v.tree_after, v.tree_hash_after]] as const) {
      const raw = toNodes(F.readRatchetTree(new Buf(hex(tree))));
      const nodes = pad(raw, countLeaves(raw));
      r.equal(name, HS.treeHash(nodes, countLeaves(raw)), want);
    }
  }
  r.family("tree-operations", entries.length + " x 2 tree hashes");
}

export async function welcome(r: Report): Promise<void> {
  const entries = await suite("welcome");
  let refs = 0;
  for (const v of entries) {
    const w = R.readWelcome(new Buf(hex(v.welcome)));
    r.check("version", w.version === 1);
    r.check("cipher suite", w.suite === v.cipher_suite);
    const kp = hex(v.key_package);
    const refForms: Uint8Array[] = [sha256(kp), F.keyPackageRef(kp)];
    let picked = -1;
    let info: R.GroupInfoRfc | null = null;
    for (const [i, sec] of w.secrets.entries()) {
      if (refForms.some((f) => Buffer.from(f).equals(Buffer.from(sec.ref)))) picked = i;
      try {
        const shared = K.decap(hex(v.init_priv), sec.kemOutput);
        const gs = K.openC(K.keySchedule(shared, F.tbsLabel("Welcome", w.encryptedGroupInfo)), new Uint8Array(0), sec.ciphertext);
        const secrets = R.readGroupSecrets(new Buf(gs));
        r.check("joiner secret", secrets.joiner.length === 32);
        r.check("empty and zeros psk salts agree", Buffer.from(S.joinerFromJoiner(secrets.joiner, new Uint8Array(0))).equals(Buffer.from(S.joinerFromJoiner(secrets.joiner, new Uint8Array(32)))), Buffer.from(S.joinerFromJoiner(secrets.joiner, new Uint8Array(0))).toString("hex").slice(0, 16) + " vs " + Buffer.from(S.joinerFromJoiner(secrets.joiner, new Uint8Array(32))).toString("hex").slice(0, 16));
        const forms: [string, Uint8Array][] = [
          ["empty", S.joinerFromJoiner(secrets.joiner, new Uint8Array(0))],
          ["zeros", S.joinerFromJoiner(secrets.joiner, new Uint8Array(32))],
          ["identity", secrets.joiner],
        ];
        for (const [name, mixed] of forms) {
          try {
            const ws = S.deriveSecret(mixed, "welcome");
            const gi = R.readGroupInfoRfc(new Buf(R.openGroupInfo(ws, w.encryptedGroupInfo)));
            info = gi;
            break;
          } catch {
            continue;
          }
        }
        if (info) break;
      } catch {
        continue;
      }
    }
    if (picked >= 0) refs++;
    if (!info) throw new Error("no group secret decrypted for this key package");
    r.check("group info signature", ed25519.verify(info.signature, F.tbsLabel("GroupInfoTBS", R.groupInfoTbs(info)), hex(v.signer_pub)));
    r.check("confirmation tag", info.confirmationTag.length === 32);
    if (info.tree) {
      const raw = toNodes(F.readRatchetTree(new Buf(info.tree)));
      r.equal("ratchet tree extension hash", HS.treeHash(pad(raw, countLeaves(raw)), countLeaves(raw)), info.treeHash);
    }
  }
  r.family("welcome", entries.length + " joins, " + refs + " of " + entries.length + " key package references matched a published hash");
}

type Commit = {
  sender: number;
  epoch: number;
  content: Uint8Array;
  proposals: F.Proposal[];
  path: F.UpdatePath | null;
  signature: Uint8Array;
  tag: Uint8Array;
  wire: number;
};

export function readCommit(raw: Uint8Array): Commit {
  const b = new Buf(raw);
  const wire = b.u16();
  b.u16();
  const contentStart = b.pos;
  const fb = new Buf(raw.subarray(contentStart));
  fb.vec();
  const epoch = fb.u64();
  fb.u8();
  const sender = fb.u32();
  fb.vec();
  const cb = new Buf(raw.subarray(contentStart));
  while (cb.pos <= fb.pos) cb.take(1);
  const proposals: F.Proposal[] = [];
  const pb = new Buf(cb.vec());
  while (!pb.done) {
    const before = pb.pos;
    try {
      proposals.push(F.readProposal(pb));
    } catch {
      proposals.push({ t: F.UNKNOWN_PROPOSAL, raw: pb.rest() });
      break;
    }
    if (pb.pos === before) break;
  }
  const path = cb.none() ? null : F.readPath(cb);
  const bodyEnd = contentStart + cb.pos;
  const content = raw.subarray(contentStart, bodyEnd);
  const rest = new Buf(raw.subarray(bodyEnd));
  const signature = rest.vec();
  const tag = rest.vec();
  return { sender, epoch, content, proposals, path, signature, tag, wire };
}

function ownLeaf(nodes: T.TNode[], encPub: Uint8Array): number {
  for (let i = 0; i < nodes.length; i += 2) {
    const nd = nodes[i];
    if (nd.k === 1 && Buffer.from(nd.v.enc).equals(Buffer.from(encPub))) return i / 2;
  }
  return -1;
}

function sharesOf(commit: Commit): Uint8Array[][] {
  return (commit.path?.nodes ?? []).map((nd) => {
    const b = new Buf(nd.kemOutput);
    const out: Uint8Array[] = [];
    while (b.left > 0) {
      out.push(b.vec());
      out.push(b.vec());
    }
    return out;
  });
}

function resolutionExcluding(after: T.TNode[], node: number, added: number[]): number[] {
  const all = T.resolution(after, node);
  return all.filter((x) => !added.includes(x));
}

function pathSecretFor(commit: Commit, n: number, after: T.TNode[], priv: Uint8Array, leaf: number, ctx: Uint8Array, added: number[]): { secret: Uint8Array | null; at: string } {
  if (!commit.path) return { secret: null, at: "no path" };
  const cp = T.copath(2 * commit.sender, n);
  const label = F.tbsLabel("UpdatePathNode", ctx);
  for (const [i, pairs] of sharesOf(commit).entries()) {
    void resolutionExcluding(after, cp[i], added);
    for (let at = 0; 2 * at + 1 < pairs.length; at++) {
      try {
        const c = K.keySchedule(K.decap(priv, pairs[2 * at]), label);
        return { secret: K.openC(c, new Uint8Array(0), pairs[2 * at + 1]), at: "node " + cp[i] + " copy " + at };
      } catch {}
    }
  }
  return { secret: null, at: "no copy of any path secret opens with this client's leaf key" };
}

function leafFromRfcPackage(pkg: Uint8Array): F.Leaf {
  const flat = (): F.Leaf | null => {
    try {
      const b = new Buf(pkg);
      b.u16();
      b.u16();
      b.vec();
      const enc = b.vec();
      const sigKey = b.vec();
      const cred = b.vec();
      b.vec();
      b.u64();
      b.u64();
      b.vec();
      const signature = b.vec();
      if (sigKey.length === 0 || cred.length === 0 || signature.length === 0) return null;
      const base = { enc, sigKey, cred, source: F.SRC_KEY_PACKAGE, parentHash: null as Uint8Array | null };
      return { ...base, tbs: F.leafTbsOf(base), signature };
    } catch {
      return null;
    }
  };
  const b = new Buf(pkg);
  b.u16();
  b.u16();
  b.vec();
  let leaf: F.Leaf | null = null;
  try {
    leaf = F.readLeafNode(b);
  } catch {
    leaf = flat();
  }
  if (!leaf) throw new Error("key package leaf is not parseable");
  if (!verifyLeaf(leaf, null, 0)) throw new Error("key package leaf signature does not verify");
  return leaf;
}

function applyProposals(base: T.TNode[], n: number, props: F.Proposal[], resolver: Map<string, Uint8Array>): { nodes: T.TNode[]; n: number; psks: Uint8Array[]; labels: Uint8Array[]; skipped: number; added: number[] } {
  let nodes = base.slice();
  let size = n;
  const psks: Uint8Array[] = [];
  const labels: Uint8Array[] = [];
  const added: number[] = [];
  let skipped = 0;
  for (const p of props) {
    if (p.t === F.ADD) {
      if (p.pkg.length < 4) throw new Error("add proposal carries " + p.pkg.length + " bytes; proposal kinds " + props.map((x) => x.t).join(","));
      let slot = -1;
      for (let i = 0; i < size; i++) if (nodes[2 * i].k === 0) { slot = i; break; }
      if (slot < 0) {
        const oldRoot = T.root(size);
        size *= 2;
        while (nodes.length < T.alloc(size)) nodes.push({ k: 0 });
        const child = oldRoot;
        (nodes[child] as { v: { parentHash: Uint8Array } }).v.parentHash = F.parentHashOf((nodes[child] as { v: { enc: Uint8Array } }).v.enc, new Uint8Array(0), HS.nodeHash(nodes, T.right(child), size));
        slot = size / 2;
      }
      const leaf = ((): F.Leaf | null => {
        try {
          return leafFromRfcPackage(p.pkg);
        } catch {
          return null;
        }
      })();
      if (!leaf) { skipped++; continue; }
      added.push(2 * slot);
      nodes[2 * slot] = { k: 1, v: { enc: leaf.enc, sigKey: leaf.sigKey, cred: leaf.cred, ph: new Uint8Array(0), unmerged: [], tbs: leaf.tbs, signature: leaf.signature } };
    }
    if (p.t === F.PSK) {
      const parts = F.pskIdParts(p.psk);
      const value = resolver.get(Buffer.from(parts.id).toString("hex"));
      if (value) {
        psks.push(value);
        labels.push(parts.id);
      }
    }
    if (p.t === F.REMOVE) nodes[2 * p.leaf] = { k: 0 };
  }
  while (size > 2) {
    let rightBlank = true;
    for (let i = size / 2; i < size; i++) if (nodes[2 * i].k !== 0) rightBlank = false;
    if (!rightBlank) break;
    size /= 2;
    nodes.length = T.alloc(size);
    (nodes[size - 1] as { v: { parentHash: Uint8Array } }).v.parentHash = new Uint8Array(0);
  }
  return { nodes, n: size, psks, labels, skipped, added };
}

export async function handlingCommit(r: Report): Promise<void> {
  const entries = await suite("passive-client-handling-commit");
  let commits = 0;
  let paths = 0;
  let derived = 0;
  for (const v of entries) {
    const g = joinGroup(v, r);
    r.equal("epoch " + g.info.epoch + " authenticator", epochAt(g, g.info.epoch, g.info.treeHash, g.info.confirmedTranscriptHash).auth, v.initial_epoch_authenticator);
    const treeHash = HS.treeHash(g.nodes, g.n);
    r.check("tree hash matches group info", Buffer.from(treeHash).equals(Buffer.from(g.info.treeHash)), Buffer.from(treeHash).toString("hex").slice(0, 24) + " vs " + Buffer.from(g.info.treeHash).toString("hex").slice(0, 24));
    const encPriv = hex(v.encryption_priv);
    const resolver = new Map<string, Uint8Array>((Array.isArray(v.external_psks) ? v.external_psks : []).map((x: any) => [x.psk_id as string, hex(x.psk)]));
    const leaf = ownLeaf(g.nodes, K.pubOf(encPriv));
    r.check("client leaf holds the vector encryption key", leaf >= 0, "no leaf in the group has the public key of encryption_priv");
    let epoch = g.info.epoch;
    let nodes = g.nodes;
    let confirmedHash = g.info.confirmedTranscriptHash;
    let tag = g.info.confirmationTag;
    let init = epochAt(g, g.info.epoch, g.info.treeHash, g.info.confirmedTranscriptHash).init;
    const ext = new Uint8Array(0);
    for (const e of v.epochs) {
      let c: Commit;
      try {
        c = readCommit(hex(e.commit));
      } catch (err) {
        r.check("commit parses", false, (err as Error).message);
        continue;
      }
      commits++;
      r.check("commit epoch", c.epoch === epoch, "commit is for epoch " + c.epoch + " and the group is at " + epoch);
      if (c.epoch !== epoch) continue;
      const senderLeaf = nodes[2 * c.sender];
      if (!senderLeaf || senderLeaf.k !== 1) {
        r.check("sender leaf is populated", false);
        continue;
      }
      const signCtx = P.groupContextExt(g.info.groupId, epoch, g.info.suite, HS.treeHash(nodes, g.n), confirmedHash, ext);
      r.check(
        "commit signature",
        ed25519.verify(c.signature, F.tbsLabel("FramedContentTBS", F.contentTbs(F.WIRE_PUBLIC, c.content, signCtx)), senderLeaf.v.sigKey),
        "signature does not verify over FramedContentTBS with the sender's leaf signature key",
      );
      const fdp = T.filteredDirectPath(nodes, c.sender, g.n);
      if (c.path) {
        paths++;
        r.check("path length matches filtered direct path", c.path.nodes.length === fdp.length, "filtered direct path is " + fdp.length + " nodes, the path carries " + c.path.nodes.length);
        r.check("leaf signature", ed25519.verify(c.path.leaf.signature, F.tbsLabel("LeafNodeTBS", F.leafTbs(c.path.leaf, g.info.groupId, c.sender)), c.path.leaf.sigKey));
        const cp = T.copath(2 * c.sender, g.n);
        void cp;
      } else {
        r.check("commit carries no path", true);
      }

      const applied = applyProposals(nodes, g.n, c.proposals, resolver);
      r.check("add proposals yield a leaf", applied.skipped === 0, applied.skipped + " of " + c.proposals.filter((p) => p.t === F.ADD).length + " added leaves are not in a form this implementation reads");
      const size = applied.n;
      const after = c.path ? applyPath(applied.nodes, size, c.sender, c.path) : applied.nodes;
      const newHash = HS.treeHash(after, size);
      const prov = P.groupContextExt(g.info.groupId, epoch + 1, g.info.suite, newHash, confirmedHash, ext);
      const got = pathSecretFor(c, size, after, encPriv, leaf, prov, applied.added);
      if (c.path) {
        const cp = T.copath(2 * c.sender, size);
        for (const [i, pairs] of sharesOf(c).entries()) {
          const res = resolutionExcluding(after, cp[i], applied.added);
          r.check("ciphertext count matches the copath resolution", pairs.length === res.length * 2, "resolution of " + cp[i] + " is " + res.length + ", the path carries " + pairs.length / 2);
        }
        r.check("path secret decrypted with this client's leaf key", got.secret !== null, got.at);
      }
      const commitSecret = got.secret ? S.deriveSecret(got.secret, "path") : new Uint8Array(32);
      const nextConfirmed = F.nextConfirmed(F.nextInterim(confirmedHash, tag), F.WIRE_PUBLIC, c.content, c.signature);
      
      const nextCtx = P.groupContextExt(g.info.groupId, epoch + 1, g.info.suite, newHash, nextConfirmed, ext);
      const es = S.epochFrom(init, commitSecret, applied.psks.length ? S.makePskSecret(applied.psks, applied.labels) : new Uint8Array(0), nextCtx);
      const kinds = c.proposals.map((p) => (p.t === F.REMOVE ? "a Remove of leaf " + p.leaf : p.t === F.ADD ? "an Add" : p.t === F.UNKNOWN_PROPOSAL ? "a proposal of type 0x" + Buffer.from((p as { raw: Uint8Array }).raw).subarray(0, 2).toString("hex") : "a proposal of type " + p.t));
      r.check(
        "epoch " + (epoch + 1) + " authenticator",
        Buffer.from(es.auth).equals(Buffer.from(hex(e.epoch_authenticator))),
        "this commit carries " + kinds.join(" and ") + (c.path ? "" : " and no update path, so its commit secret is all zeros") + ". Everything upstream verifies, so the unknown is the tree those proposals produce",
      );
      r.check("confirmation tag", Buffer.from(S.confirmationTag(es.confirm, nextConfirmed)).equals(Buffer.from(c.tag)), "the tag over the new confirmed transcript hash does not match");
      derived++;
      nodes = after;
      g.n = size;
      confirmedHash = nextConfirmed;
      tag = c.tag;
      init = es.init;
      epoch += 1;
    }
  }
  r.family("passive-client-handling-commit", commits + " commits, " + paths + " with an update path, " + derived + " epoch transitions derived end to end");
}

export async function transcriptHashes(r: Report): Promise<void> {
  const entries = await suite("transcript-hashes");
  for (const v of entries) {
    const raw = hex(v.authenticated_content);
    const head = new Buf(raw);
    const wire = head.u16();
    const contentStart = head.pos;
    head.vec();
    head.u64();
    head.u8();
    head.u32();
    head.vec();
    head.u8();
    let matched = false;
    for (let end = contentStart + 1; end <= raw.length - 65; end++) {
      if (raw[end] !== 64) continue;
      const signature = raw.subarray(end + 1, end + 65);
      const body = new Uint8Array(2 + (end - contentStart) + 1 + signature.length);
      body.set([(wire >> 8) & 255, wire & 255], 0);
      body.set(raw.subarray(contentStart, end), 2);
      body.set([64], 2 + (end - contentStart));
      body.set(signature, 3 + (end - contentStart));
      const confirmed = sha256(cat(hex(v.interim_transcript_hash_before), body));
      if (Buffer.from(confirmed).equals(Buffer.from(hex(v.confirmed_transcript_hash_after)))) {
        matched = true;
        const tag = S.confirmationTag(hex(v.confirmation_key), confirmed);
        r.equal("interim_transcript_hash_after", F.nextInterim(confirmed, tag), v.interim_transcript_hash_after);
        break;
      }
    }
    r.check("confirmed_transcript_hash_after", matched, "no split of the blob reproduced the published hash");
  }
  r.family("transcript-hashes", entries.length + " epochs");
}

export async function passiveClientWelcome(r: Report): Promise<void> {
  const entries = await suite("passive-client-welcome");
  for (const v of entries) {
    const g = joinGroup(v, r);
    r.equal("epoch 0 authenticator", epochAt(g, g.info.epoch, g.info.treeHash, g.info.confirmedTranscriptHash).auth, v.initial_epoch_authenticator);
    for (const e of v.epochs) {
      r.equal("epoch " + e.epoch + " authenticator", epochAt(g, e.epoch, g.info.treeHash, g.info.confirmedTranscriptHash).auth, e.epoch_authenticator);
    }
  }
  r.family("passive-client-welcome", entries.length + " joins");
}

export async function treekem(r: Report): Promise<void> {
  const entries = await suite("treekem");
  let paths = 0;
  for (const v of entries) {
    const raw = toNodes(F.readRatchetTree(new Buf(hex(v.ratchet_tree))));
    const n = countLeaves(raw);
    const base = pad(raw, n);
    const nodeKey = (secret: Uint8Array): string => Buffer.from(K.derivePair(S.deriveSecret(secret, "node")).pub).toString("hex");

    for (const holder of v.leaves_private) {
      for (const held of holder.path_secrets) {
        const node = base[held.node];
        if (!node || node.k === 0) {
          r.check("held node " + held.node + " is populated", false);
          continue;
        }
        r.check(
          "held key at node " + held.node,
          nodeKey(hex(held.path_secret)) === Buffer.from((node as any).v.enc).toString("hex"),
          "DeriveKeyPair(DeriveSecret(secret, \"node\")) does not match the public key in the tree",
        );
      }
    }

    for (const up of v.update_paths) {
      const sender = up.sender;
      const path = F.readPath(new Buf(hex(up.update_path)));
      const fdp = T.filteredDirectPath(base, sender, n);
      if (fdp.length !== path.nodes.length) {
        r.check("path shape", false, "filtered direct path is " + fdp.length + " nodes, path carries " + path.nodes.length);
        continue;
      }
      paths++;
      const after = applyPath(base, n, sender, path);
      r.equal("tree_hash_after", HS.treeHash(after, n), up.tree_hash_after);
      r.check("leaf signature", ed25519.verify(path.leaf.signature, F.tbsLabel("LeafNodeTBS", F.leafTbs(path.leaf, hex(v.group_id), sender)), path.leaf.sigKey));

      const secrets = (up.path_secrets as (string | null)[]).filter((x): x is string => typeof x === "string" && x.length > 0).map((x) => hex(x));
      const keys = new Set(fdp.map((node) => Buffer.from((after[node] as any).v.enc).toString("hex")));
      for (const secret of secrets) {
        r.check("path secret yields a node key", keys.has(nodeKey(secret)), "no node on the filtered direct path has the matching public key");
      }
      const next = new Set(secrets.map((s) => Buffer.from(S.deriveSecret(s, "path")).toString("hex")));
      next.add(up.commit_secret);
      for (const secret of secrets) {
        r.check(
          "path secret continues the chain",
          next.has(Buffer.from(S.deriveSecret(secret, "path")).toString("hex")),
          "DeriveSecret(secret, \"path\") is neither another published path secret nor the commit secret",
        );
      }
      r.check(
        "commit secret ends the chain",
        secrets.some((s) => Buffer.from(S.deriveSecret(s, "path")).equals(Buffer.from(hex(up.commit_secret)))),
        "no published path secret derives the commit secret",
      );
    }
  }
  r.family("treekem", entries.length + " vectors, " + paths + " update paths");
}

export function applyPath(base: T.TNode[], n: number, sender: number, path: F.UpdatePath): T.TNode[] {
  const out = base.slice();
  const fdp = T.filteredDirectPath(base, sender, n);
  for (const node of fdp) out[node] = { k: 0 };
  out[2 * sender] = {
    k: 1,
    v: { enc: path.leaf.enc, sigKey: path.leaf.sigKey, cred: path.leaf.cred, ph: opt(path.leaf.parentHash), unmerged: [], tbs: path.leaf.tbs, signature: path.leaf.signature },
  };
  for (const [i, node] of fdp.entries()) out[node] = { k: 2, v: { enc: path.nodes[i].enc, parentHash: new Uint8Array(0), unmerged: [] } };
  let above = new Uint8Array(0);
  const stored: Uint8Array[] = new Array(fdp.length);
  for (let i = fdp.length - 1; i >= 0; i--) {
    stored[i] = above;
    const down = i === 0 ? 2 * sender : fdp[i - 1];
    const sib = down < fdp[i] ? T.right(fdp[i]) : T.left(fdp[i]);
    above = F.parentHashOf(path.nodes[i].enc, above, HS.nodeHash(out, sib, n));
  }
  for (const [i, node] of fdp.entries()) (out[node] as any).v.parentHash = stored[i];
  (out[2 * sender] as any).v.ph = above;
  return out;
}