import * as X from "./mlsx";
import * as G from "./mls/commit";

import * as P2P from "./p2p";
import { b64d, b64e } from "./lib/crypto";
import * as vault from "./lib/vault";

export type Group = X.Saved & { signer: string; initPub: string; ref: string; pkg: string };
type SelfSave = { priv: string; pub: string };

const KEY = "groups";
const SELF = "self";
const OFFER = "offer";
const STAMP = "build";

export function version(): string {
  return process.env.APP_VERSION || "0.0.0";
}

export async function ready(): Promise<void> {
  await vault.ready();
  stamp();
}

export function stamp(): void {
  if (vault.get<string>(STAMP) === version()) return;
  vault.del(KEY);
  vault.del(SELF);
  vault.del(OFFER);
  vault.set(STAMP, version());
}

function read<T>(k: string): T | null {
  return vault.get<T>(k);
}

function write(k: string, v: unknown): void {
  vault.set(k, v);
}

export function selfKey(): { priv: string; pub: string } | null {
  return read<SelfSave>(SELF);
}

export function setSelfKey(): { priv: string; pub: string } {
  const cur = selfKey();
  if (cur && cur.priv && cur.pub) return cur;
  const s = X.self();
  const v = { priv: b64e(s.sigPriv), pub: b64e(s.sigPub) };
  write(SELF, v);
  return v;
}

export function signer(): G.Self {
  const saved = selfKey() || setSelfKey();
  return { sigPriv: b64d(saved.priv), sigPub: b64d(saved.pub) };
}

type OfferSave = { pkg: string; priv: string; pub: string; ref: string };

export function offerOnce(): OfferSave {
  const cur = read<OfferSave>(OFFER);
  if (cur && cur.priv && cur.pkg) return cur;
  const o = X.accept(signer());
  const v: OfferSave = {
    pkg: b64e(o.pkg),
    priv: b64e(o.key.priv),
    pub: b64e(o.key.pub),
    ref: b64e(o.ref)
  };
  write(OFFER, v);
  return v;
}

export function packageB64(): string {
  return offerOnce().pkg;
}

export function acceptReady(): { initPriv: string; initPub: string; ref: string } {
  const o = offerOnce();
  return { initPriv: o.priv, initPub: o.pub, ref: o.ref };
}

let lastCommit: G.CommitOut | null = null;

export function setLastCommit(out: G.CommitOut): void {
  lastCommit = out;
}

export function addMembers(room: string, kp: Uint8Array): G.CommitOut {
  const g = load(room);
  if (!g) throw new Error("no group");
  const out = X.addMembers(g, [kp]);
  lastCommit = out;
  return out;
}

export type CommitWire = { ep: number; ct: string; sg: string; js: string; sh: string };

export function publishCommit(room: string): CommitWire | null {
  const out = lastCommit;
  if (!out) return null;
  lastCommit = null;
  return {
    ep: out.group.epoch,
    ct: b64e(out.content),
    sg: b64e(out.signature),
    js: b64e(out.joiner),
    sh: JSON.stringify(out.pathShares.map((s) => ({ l: s.forLeaf, n: s.node, k: b64e(s.kemOutput), c: b64e(s.ciphertext) })))
  };
}

export function applyCommits(room: string, list: CommitWire[]): number {
  let g = load(room);
  if (!g) return 0;
  let done = 0;
  for (const c of list) {
    if (c.ep <= g.epoch) continue;
    let shares: any[] = [];
    try {
      shares = JSON.parse(c.sh);
    } catch (e) {
      shares = [];
    }
    const list2 = Array.isArray(shares) ? shares : [];
    const g2 = g;
    const next = X.applyAny(g2, { content: c.ct, signature: c.sg, joiner: c.js, shares: [] }, list2.map((s) => ({ l: Number(s.l), n: Number(s.n), k: String(s.k), c: String(s.c) })));
    g = next;
    done++;
  }
  if (done > 0) {
    X.forgetRatchets(room);
    saveGroup(room, g);
  }
  return done;
}

export function rotationDue(room: string, everyDays: number): boolean {
  const g = load(room);
  return g ? X.rotationDue(g, everyDays) : false;
}

export function saveGroup(room: string, g: G.Group): void {
  const saved = get(room);
  if (saved) put(room, g, { signer: saved.signer, initPub: saved.initPub, ref: saved.ref, pkg: saved.pkg });
}

export function forgetRatchets(room: string): void {
  X.forgetRatchets(room);
}

export function all(): Record<string, Group> {
  return read<Record<string, Group>>(KEY) || {};
}

export function put(room: string, g: G.Group, extra: { signer: string; initPub: string; ref: string; pkg: string }): void {
  const cur = all();
  cur[room] = { ...X.save(g), ...extra };
  write(KEY, cur);
}

export function get(room: string): Group | null {
  return all()[room] || null;
}

export function load(room: string): G.Group | null {
  const saved = get(room);
  return saved ? X.load(saved) : null;
}

export function drop(room: string): void {
  const cur = all();
  delete cur[room];
  write(KEY, cur);
}

export function joinRoom(room: string, welcome: X.WelcomeWire, initPriv: string, initPub: string, ref: string, pkg: string): G.Group {
  const init = { priv: b64d(initPriv), pub: b64d(initPub) };
  const g = X.acceptWelcome(signer(), init, welcome, b64d(ref));
  put(room, g, { signer: b64e(g.self.sigPub), initPub, ref, pkg });
  return g;
}

export function createRoom(room: string): G.Group {
  const s = signer();
  const { group } = X.newGroup(room, s);
  put(room, group, { signer: b64e(s.sigPub), initPub: b64e(group.initPub), ref: "", pkg: "" });
  return group;
}

export function newGroup(room: string, signerKey: G.Self): G.Group {
  return X.newGroup(room, signerKey).group;
}

export function groupInfo(g: G.Group): string {
  return b64e(G.writeGroupInfo(g));
}

export function groupInfoOf(room: string): string {
  const g = load(room);
  return g ? b64e(G.writeGroupInfo(g)) : "";
}

export function epochOf(room: string): number {
  const saved = get(room);
  return saved ? saved.epoch : 0;
}

export function memberCount(room: string): number {
  const saved = get(room);
  return saved ? saved.n : 0;
}

export function seal(room: string, plaintext: Uint8Array): string | null {
  const g = load(room);
  if (!g) return null;
  const out = X.sealApp(g, plaintext);
  const saved = get(room);
  if (saved) put(room, g, { signer: saved.signer, initPub: saved.initPub, ref: saved.ref, pkg: saved.pkg });
  return out.ct;
}

export function open(room: string, ct: string): { text: string; who: string; raw: Uint8Array } | null {
  const g = load(room);
  if (!g) return null;
  let raw: Uint8Array;
  try {
    raw = b64d(ct);
  } catch (e) {
    return null;
  }
  const opened = X.openApp(g, raw);
  if (!opened) return null;
  const saved = get(room);
  if (saved) put(room, g, { signer: saved.signer, initPub: saved.initPub, ref: saved.ref, pkg: saved.pkg });
  const creds = X.members(g);
  const cred = creds[opened.leaf];
  return {
    text: new TextDecoder().decode(opened.body),
    who: opened.leaf === g.me ? saved?.signer || "" : cred ? b64e(cred).slice(0, 16) : "",
    raw: opened.body,
  };
}
