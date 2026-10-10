"use client";
import { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { Check, Copy, Download, FileText, Plus, Smile, Trash2, X as CloseIcon } from "lucide-react";
import { bundle, delLink, delMsg, dropReact, dropWelcome, freshInvite, getBlob, getLink, getMsgs, getReacts, getWelcome, ice, ids, joinLink, newLink, online, postBlob, postMsg, postReact, publish, pullCommits, pushCommit, putGroupInfo, putWelcome, resolveInvite, signal, stream } from "./lib/net";
import { unpack } from "./lib/blob";
import { stamp } from "./lib/time";
import { b64d, b64e, ctId, edSign, edVerify, genKeys, safety } from "./lib/crypto";
import * as W from "./wire";
import * as X from "./mlsx";
import * as P2P from "./p2p";

const EmoPicker = dynamic(() => import("./emo"), { ssr: false });

type Att = { id: string; name: string; mime: string; size: number };
type Msg = { id: string; who: string; room: string; text: string; mine: boolean; at: number; att?: Att };
type Mark = { id: string; mid: string; who: string; emo: string; mine: boolean };
type Chan = { sid: string; link: string; members: string[]; unread: number };
type Sess = {
  who: string;
  token: string;
  keys: any;
  pbs: Record<string, { ed: Uint8Array; x: Uint8Array; sig: Uint8Array; kp: Uint8Array }>;
  codes: Record<string, string>;


  asked: Record<string, string>;
  chans: Chan[];
  msgs: Msg[];
};

const enc = new TextEncoder();
const dec = new TextDecoder();
const MAXM = 200;

function short(id: string) {
  return id.slice(0, 8);
}

function fmtSize(n: number) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

function rid(n: number) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

const blobUrls = new Map<string, string>();
const CACHE_MAX = 60;

function keepBlob(id: string, url: string) {
  blobUrls.set(id, url);
  while (blobUrls.size > CACHE_MAX) {
    const oldest = blobUrls.keys().next().value;
    if (oldest === undefined || oldest === id) break;
    const gone = blobUrls.get(oldest);
    blobUrls.delete(oldest);
    if (gone) URL.revokeObjectURL(gone);
  }
}

function dropBlob(id: string) {
  const u = blobUrls.get(id);
  if (u) {
    URL.revokeObjectURL(u);
    blobUrls.delete(id);
  }
}

function dropRoom(g: string, msgs: Msg[]) {
  for (const m of msgs) {
    if (m.room === g && m.att) dropBlob(m.att.id);
  }
}

function FileView({ id, conv, token, name, mime, size, big, out, onBig, onShut }: { id: string; conv: string; token: string; name: string; mime: string; size: number; big: boolean; out: boolean; onBig: () => void; onShut: () => void }) {
  const [url, setUrl] = useState("");
  const [ok, setOk] = useState(false);
  const isImg = mime.startsWith("image/");
  useEffect(() => {
    const hit = blobUrls.get(id);
    if (hit) {
      setUrl(hit);
      return;
    }
    let dead = false;
    getBlob(token, id).then((b) => {
      const opened = W.open(conv, String(b.data));
      if (!opened) return;
      const fresh = URL.createObjectURL(new Blob([opened.raw as BlobPart], { type: mime }));
      keepBlob(id, fresh);
      if (!dead) setUrl(fresh);
    }).catch(() => {});
    return () => {
      dead = true;
    };
  }, [id, conv]);
  useEffect(() => {
    if (!big) return;
    const h = (e: KeyboardEvent) => {
      if (e.key === "Escape") onShut();
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [big]);
  async function copy() {
    try {
      const r = await fetch(url);
      const b = await r.blob();
      await navigator.clipboard.write([new ClipboardItem({ [mime]: b })]);
      setOk(true);
      window.setTimeout(() => setOk(false), 1200);
    } catch (e) {}
  }
  if (!url) return <div className="iPh7P">loading</div>;
  if (!isImg) {
    return (
      <div className="aT8fD">
        <div className="wQ8rT">
          <FileText size={28} />
          <div>
            <div className="fN2pQ">{name}</div>
            <div className="sZ4zA">{fmtSize(size)}</div>
          </div>
          <a href={url} download={name} className="ZwE4b td7Kx qWz9k"><Download size={16} /></a>
        </div>
      </div>
    );
  }
  if (!big) return <img src={url} onClick={onBig} className="iTt5T" alt={name} />;
  return (
    <div className={out ? "vX3oL qZ4oU" : "vX3oL"} onClick={onShut}>
      <div className="bA7rB" onClick={(e) => e.stopPropagation()}>
        <a href={url} download={name} className="ZwE4b td7Kx qWz9k"><Download size={18} /></a>
        <button className="ZwE4b td7Kx qWz9k" onClick={copy}>{ok ? <Check size={18} /> : <Copy size={18} />}</button>
        <button className="ZwE4b td7Kx qWz9k" onClick={onShut}><CloseIcon size={18} /></button>
      </div>
      <img src={url} className="oI9mG" alt={name} onClick={(e) => e.stopPropagation()} />
    </div>
  );
}

export default function Shell() {
  const [view, setView] = useState("boot");
  const [sess, setSess] = useState<Sess | null>(null);
  const [link, setLink] = useState("");
  const [room, setRoom] = useState("");
  const [codeIn, setCodeIn] = useState("");
  const [paste, setPaste] = useState("");
  const [text, setText] = useState("");
  const [err, setErr] = useState("");
  const [typers, setTypers] = useState<Record<string, number>>({});
  const [liveNow, setLiveNow] = useState<string[]>([]);
  const typersRef = useRef<Record<string, number>>({});
  const bootDone = useRef(false);
  const liveRef = useRef<string[]>([]);
  const [copied, setCopied] = useState(0);
  const [isFunder, setIsFunder] = useState(false);
  const [q, setQ] = useState("");
  const [marks, setMarks] = useState<Mark[]>([]);

  const [emoOpen, setEmoOpen] = useState<string | null>(null);
  const [composeEmo, setComposeEmo] = useState(false);
  const [emoOut, setEmoOut] = useState(false);
  const [cmpOut, setCmpOut] = useState(false);
  const [big, setBig] = useState<string | null>(null);
  const [bigOut, setBigOut] = useState(false);
  const [pending, setPending] = useState<{ f: File; url: string; name: string } | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [sel, setSel] = useState("");

  const booted = useRef(false);
  const seen = useRef<Set<string>>(new Set());
  const seenQ = useRef<string[]>([]);

  function remember(id: string) {
    seen.current.add(id);
    seenQ.current.push(id);
    if (seenQ.current.length > 5000) {
      const drop = seenQ.current.splice(0, 1000);
      for (const d of drop) seen.current.delete(d);
    }
  }
  const viewRef = useRef("boot");
  useEffect(() => {
    viewRef.current = view;
  }, [view]);

  function shutEmo() {
    setEmoOut(true);
    window.setTimeout(() => {
      setEmoOpen(null);
      setEmoOut(false);
    }, 150);
  }

  function shutCmp() {
    setCmpOut(true);
    window.setTimeout(() => {
      setComposeEmo(false);
      setCmpOut(false);
    }, 150);
  }

  function shutBig() {
    setBigOut(true);
    window.setTimeout(() => {
      setBig(null);
      setBigOut(false);
    }, 150);
  }

  const fileRef = useRef<HTMLInputElement | null>(null);
  const live = useRef<number | null>(null);
  const sock = useRef<(() => void) | null>(null);
  const retry = useRef<number | null>(null);
  const box = useRef<HTMLTextAreaElement | null>(null);
  const lastPing = useRef(0);
  const wasTyping = useRef(false);
  
  const busy = useRef(false);
  const gate = useRef<Promise<void>>(Promise.resolve());
  const selRef = useRef("");
  const ref = useRef({ sess: null as Sess | null, link: "", room: "" });
  ref.current = { sess, link, room };

  function activeCh(s: Sess | null): Chan | undefined {
    if (!s) return undefined;
    return s.chans.find((x) => x.sid === sel) || s.chans[0];
  }

  function select(sid: string) {
    const s = ref.current.sess;
    if (!s) return;
    const ch = s.chans.find((x) => x.sid === sid);
    if (!ch) return;
    selRef.current = sid;
    setSel(sid);
    if (ch.link) setLink(ch.link);
    setRoom(ch.sid);
    setErr("");
    setTypers({});
    typersRef.current = {};
    s.chans = s.chans.map((x) => (x.sid === sid ? { ...x, unread: 0 } : x));
    setSess({ ...s });
    window.history.replaceState(null, "", "?l=" + ch.sid);
    tick();
    loadMarks(sid);
  }

  useEffect(() => {
    boot();
    const guard = window.setTimeout(() => {
      if (!bootDone.current) {
        setErr("still trying to reach the server, is it up?");
        setView("home");
      }
    }, 12000);
    const onFocus = () => {
      pull().catch(() => {});
    };
    window.addEventListener("focus", onFocus);
    window.addEventListener("online", onFocus);
    const onKeys = (e: KeyboardEvent) => {
      if (!ref.current.link) return;
      const t = e.target as HTMLElement | null;
      const tag = t ? t.tagName : "";
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key.length === 1 && box.current) box.current.focus();
    };
    window.addEventListener("keydown", onKeys);
    return () => {
      clearTimeout(guard);
      if (live.current) clearInterval(live.current);
      if (retry.current) clearTimeout(retry.current);
      if (sock.current) {
        sock.current();
        sock.current = null;
      }
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("online", onFocus);
      window.removeEventListener("keydown", onKeys);
      for (const id of blobUrls.keys()) dropBlob(id);
    };
  }, []);

  function dberr(e: unknown) {
    return e instanceof Error && (e as Error & { db?: boolean }).db === true;
  }

  function gone(e: unknown) {
    return e instanceof Error && (e as Error & { status?: number }).status === 404;
  }

  function seq<T>(f: () => Promise<T>): Promise<T> {
    const r = gate.current.then(f);
    gate.current = r.then(() => undefined, () => undefined);
    return r;
  }

  async function boot() {
    if (booted.current) return;
    booted.current = true;
    try {
      const r = await ids();
      const k = genKeys();
      const s: Sess = {
        who: String(r.who),
        token: String(r.tok),
        keys: { edPriv: b64e(k.edPriv), edPub: b64e(k.edPub), xPriv: b64e(k.xPriv), xPub: b64e(k.xPub) },
        pbs: {},
        codes: {},


        asked: {},
        chans: [],
        msgs: []
      };
      W.stamp();
      W.setSelfKey();
      setSess(s);
      announce(s);
      const l = new URLSearchParams(window.location.search).get("l") || "";
      if (l) {
        await openLink(s, l);
      } else {
        setView("home");
      }
    } catch (e) {
      setErr(dberr(e) ? "database unreachable" : "boot failed, is the server up");
      setView("home");
    } finally {
      bootDone.current = true;
    }
  }

  function connect() {
    const s = ref.current.sess;
    if (!s) return;
    if (sock.current) {
      sock.current();
      sock.current = null;
    }
    const stop = stream(
      s.token,
      (m) => {
        if (m.type === "sig") {
          const g = String(m.link || "");
          const from = String(m.from || "");
          const kind = String(m.kind || "");
          if (kind === "typing") {
            if (g === ref.current.room) {
              noteTyping(from, m.on === true);
            }
            return;
          }
          if (kind === "bye") {
            const meshFor = meshes.get(g);
            if (meshFor) P2P.hangUp(meshFor, from);
            return;
          }
          const found = wirePeers(g);
          if (!found) return;
          const body = (m.body || null) as any;
          if (!body || typeof body.kind !== "string") return;
          if (body.kind === "offer") P2P.accept(found, from, body.sdp).catch(() => {});
          else if (body.kind === "answer") P2P.settle(found, from, body.sdp).catch(() => {});
          else if (body.kind === "ice") P2P.chill(found, from, body.cand).catch(() => {});
          return;
        }
        if (m.type === "wake") {
          tick().catch(() => {});
          return;
        }
        if (m.type === "presence") {
          const ss = ref.current.sess;
          if (ss) refreshPresence(ss);
        }
      },
      () => {
        if (sock.current !== stop) return;
        sock.current = null;
        setLiveNow([]);
        liveRef.current = [];
        if (retry.current) clearTimeout(retry.current);
        retry.current = window.setTimeout(() => {
          if (ref.current.room) connect();
        }, 3000);
      }
    );
    sock.current = stop;
    refreshPresence(s);
  }

  function goLive() {
    if (live.current) clearInterval(live.current);
    connect();
    const step = () => {
      const s = ref.current.sess;
      const ready = s ? fresh(s) : Promise.resolve();
      return ready.then(() => tick());
    };
    const loop = () => {
      live.current = window.setTimeout(() => {
        step().then(loop, loop);
      }, eager() ? 1200 + Math.random() * 800 : 20000 + Math.random() * 10000);
    };
    loop();
  }

  function eager(): boolean {
    const s = ref.current.sess;
    const r = ref.current.room;
    if (!s || !r) return false;
    const n = W.memberCount(r);
    if (n === 0) return true;
    const ch = s.chans.find((x) => x.sid === r);
    if (!ch) return false;
    const want = ch.members.filter((x) => x !== s.who).length;
    if (n < want) return true;
    for (const who of ch.members) {
      if (who === s.who) continue;
      const pb = s.pbs[who];
      if (!pb || pb.kp.length === 0) return true;
    }
    return false;
  }

  const mesh = new Map<string, P2P.Mesh>();
  const meshes = mesh;

  function wirePeers(g: string) {
    if (mesh.has(g)) return mesh.get(g)!;
    const s = ref.current.sess;
    if (!s) return null;
    const m = P2P.mesh(
      g,
      s.who,
      (to, body) => {
        const ss = ref.current.sess;
        if (!ss) return;
        const kind = String((body as any).kind || "");
        if (kind !== "offer" && kind !== "answer" && kind !== "ice") return;
        signal(ss.token, g, kind, body).catch(() => {});
      },
      () => {},
      (from, payload) => {
        const ct = b64e(payload);
        const id = ctId(ct);
        const ss = ref.current.sess;
        if (!ss) return;
        if (seen.current.has(id)) return;
        const opened = W.open(g, ct);
        if (!opened || opened.who === s.who) return;
        const o = JSON.parse(opened.text);
        remember(id);
        addMsg(ss, {
          id,
          who: String(o.w || opened.who),
          room: g,
          text: String(o.t || ""),
          mine: false,
          at: Number(o.d) || Date.now()
        });
      },
      () => {}
    );
    mesh.set(g, m);
    return m;
  }

  async function dialPeers(g: string) {
    const m = wirePeers(g);
    const s = ref.current.sess;
    if (!m || !s) return;
    for (const who of m.online) {
      try {
        await P2P.dial(m, who);
      } catch (e) {}
    }
  }

  function noteTyping(who: string, on: boolean) {
    const next: Record<string, number> = { ...typersRef.current };
    if (on) next[who] = Date.now();
    else delete next[who];
    typersRef.current = next;
    setTypers(next);
  }

  function sweepTypers() {
    const now = Date.now();
    const cur = typersRef.current;
    let changed = false;
    const next: Record<string, number> = {};
    for (const k of Object.keys(cur)) {
      if (now - cur[k] < 6000) next[k] = cur[k];
      else changed = true;
    }
    if (changed) {
      typersRef.current = next;
      setTypers(next);
    }
  }

  async function loadIce(s: Sess) {
  try {
    const r = await ice(s.token);
    if (Array.isArray(r.ice) && r.ice.length > 0) P2P.setIce(r.ice);
    turnOn = r.turn === true;
    iceAt = Date.now();
  } catch (e) {}
}

const ICE_LIFE = 45 * 60 * 1000;
let iceAt = 0;
let turnOn = false;

function fresh(s: Sess): Promise<void> {
  if (iceAt === 0) return loadIce(s);
  if (!turnOn) return Promise.resolve();
  if (Date.now() - iceAt < ICE_LIFE) return Promise.resolve();
  return loadIce(s);
}

async function refreshPresence(s: Sess) {
    const rooms = s.chans.map((c) => c.sid).filter((x) => x.length > 0);
    if (rooms.length === 0) return;
    try {
      const r = await online(s.token, rooms);
      liveRef.current = Array.isArray(r.on) ? r.on : [];
      setLiveNow(liveRef.current);
    } catch (e) {}
  }

  function wsSend(o: any) {
    const s = ref.current.sess;
    if (!s) return;
    const g = String(o.link || ref.current.room || "");
    if (!g) return;
    if (o.type === "typing") signal(s.token, g, "typing", null, o.on === true).catch(() => {});
    else if (o.type === "bye") signal(s.token, g, "bye", null).catch(() => {});
  }

  async function ping(on: boolean) {
    const s = ref.current.sess;
    const l = ref.current.room;
    if (!s || !l) return;
    const now = Date.now();
    if (on && wasTyping.current && now - lastPing.current < 4000) return;
    if (!on && !wasTyping.current) return;
    wasTyping.current = on;
    lastPing.current = now;
    wsSend({ type: "typing", link: l, on });
  }

  function onType(v: string) {
    setText(v);
    ping(v.length > 0);
  }

  async function peerOf(s: Sess, who: string) {
    const hit = s.pbs[who];
    if (hit && hit.kp.length > 0) return hit;
    const b = await bundle(s.token, who);
    const bb = { ed: b64d(String(b.ed)), x: b64d(String(b.ex)), sig: b64d(String(b.sig)), kp: b64d(String(b.kp || "")) };
    if (bb.kp.length === 0) delete s.pbs[who];
    else {
      s.pbs[who] = bb;
      s.codes[who] = safety(b64d(s.keys.edPub), bb.ed, s.who, who);
    }
    return bb;
  }

  async function announce(s: Sess) {
    const sk = W.signer();
    await publish(s.token, {
      ed: b64e(b64d(s.keys.edPub)),
      ex: b64e(b64d(s.keys.xPub)),
      sig: b64e(sk.sigPub),
      kp: W.packageB64()
    }).catch(() => {});
  }

  async function roomTick(s: Sess, g: string) {
    const st = await getLink(s.token, g);
    if (!st.inRoom) throw new Error("not a member");
    const ch = s.chans.find((x) => x.sid === g);
    if (ch) {
      ch.members = st.mm;
      setSess({ ...s });
    }
    if (g === ref.current.room) setIsFunder(st.mm[0] === s.who);
    if (W.memberCount(g) === 0 && st.mm.length > 0 && st.mm[0] === s.who) {
      W.createRoom(g);
      setSess({ ...s });
    }
    wirePeers(g);
    announce(s);
    for (const who of st.mm) {
      if (who === s.who) continue;
      try {
        await peerOf(s, who);
      } catch (e) {}
    }
    try {
      await growGroup(s, g, st.mm);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (g === ref.current.room) setErr("group: " + msg);
    }
  }

  async function catchUp(s: Sess, g: string) {
    const local = W.epochOf(g);
    const r = await pullCommits(s.token, g, local);
    const list = r.commits || [];
    if (list.length === 0) return;
    const n = W.applyCommits(g, list);
    if (n > 0) setSess({ ...s });
  }

  async function growGroup(s: Sess, g: string, mm: string[]) {
    if (mm[0] === s.who) {
      if (W.memberCount(g) === 0) return;
      if (!W.load(g)) throw new Error("founder has no group");
      let cur = W.load(g);
      if (!cur) return;
      let moved = false;
      for (const who of mm) {
        if (who === s.who) continue;
        const pb = s.pbs[who];
        if (!pb || pb.kp.length === 0) continue;
        if (X.leafOf(cur, pb.sig) >= 0) continue;
        const out = W.addMembers(g, pb.kp);
        W.saveGroup(g, out.group);
        W.forgetRatchets(g);
        cur = out.group;
        moved = true;
        if (out.welcome) await putWelcome(s.token, g, who, JSON.stringify(X.packWelcome(out.welcome)));
      }
      if (moved) {
        await putGroupInfo(s.token, g, W.groupInfoOf(g));
        const pub = W.publishCommit(g);
        if (pub) await pushCommit(s.token, g, pub.ep, pub.ct, pub.sg, pub.js, pub.sh).catch(() => {});
      }
      await catchUp(s, g);
      return;
    }
    if (W.memberCount(g) > 0) {
      await dropWelcome(s.token, g).catch(() => {});
      return;
    }
    const w = await getWelcome(s.token, g);
    const blob = String(w.wc || "");
    if (!blob) return;
    const acc = W.acceptReady();
    let wire: any = null;
    try {
      wire = JSON.parse(blob);
    } catch (e) {
      throw new Error("welcome was not json");
    }
    W.joinRoom(g, wire, acc.initPriv, acc.initPub, acc.ref, W.packageB64());
    if (W.memberCount(g) < 2) throw new Error("welcome did not add me, n=" + W.memberCount(g));
    await dropWelcome(s.token, g).catch(() => {});
    await catchUp(s, g);
    setSess({ ...s });
  }

  async function tick() {
    const s = ref.current.sess;
    if (!s || busy.current) return;
    busy.current = true;
    const cur = ref.current.room;
    const rooms = s.chans.map((c) => c.sid).filter((x) => x.length > 0);
    if (cur && !rooms.includes(cur)) rooms.push(cur);
    try {
      const states = await Promise.allSettled(rooms.map((g) => getLink(s.token, g)));
      let dead = "";
      for (let i = 0; i < rooms.length; i++) {
        const r = states[i];
        if (r.status === "rejected") {
          if (gone(r.reason)) dead = rooms[i];
          else if (dberr(r.reason)) setErr("database unreachable");
          continue;
        }
        try {
          await roomTick(s, rooms[i]);
        } catch (e) {
          if (gone(e)) dead = rooms[i];
        }
      }
      if (dead && dead === cur) {
        dropRoom(dead, s.msgs);
        s.msgs = s.msgs.filter((m) => m.room !== dead);
        s.chans = s.chans.filter((c) => c.sid !== dead);
        selRef.current = "";
        setSel("");
        setRoom("");
        setLink("");
        setErr("link is gone");
        setView("home");
        window.history.replaceState(null, "", "/");
      }
      sweepTypers();
      await pull();
      await refreshPresence(s);
      if (cur) loadMarks(cur);
    } finally {
      busy.current = false;
    }
  }

  function withAtt(id: string, who: string, room: string, o: any, mine: boolean): Msg {
    const at = Number(o.d) || Date.now();
    if (o.a && o.a.id) {
      return { id, who, room, text: String(o.t || ""), mine, at, att: { id: String(o.a.id), name: String(o.a.n), mime: String(o.a.m), size: Number(o.a.s) } };
    }
    return { id, who, room, text: String(o.t || ""), mine, at };
  }

  function addMsg(s: Sess, m: Msg) {
    if (s.msgs.find((x) => x.id === m.id)) return;
    s.msgs.push(m);
    const ex = s.chans.find((x) => x.sid === m.room);
    if (!ex) {
      s.chans.push({ sid: m.room, link: "", members: [m.who], unread: m.mine || m.room === selRef.current ? 0 : 1 });
    } else if (!m.mine && ex.sid !== selRef.current) {
      ex.unread++;
    }
    setSess({ ...s });
  }

  async function pull(pre?: any[]) {
    return seq(async () => {
      const s = ref.current.sess;
      if (!s) return;
      const rooms = s.chans.map((c) => c.sid).filter((x) => x.length > 0);
      let rows: any[];
      if (pre) {
        rows = pre;
      } else {
        rows = [];
        let cursor: string | null = null;
        for (let page = 0; page < 25; page++) {
          const r = await getMsgs(s.token, rooms, cursor);
          const batch = r.msgs || [];
          rows.push(...batch);
          if (!r.more || !r.cursor || batch.length === 0) break;
          cursor = r.cursor;
        }
      }
      let changed = false;
      for (const row of rows) {
        const g = String(row.g);
        if (s.msgs.find((x) => x.id === String(row.id))) continue;
        if (Number(row.bo) !== 0) continue;
        if (W.memberCount(g) === 0) continue;
        const o = await openBody(s, g, row);
        if (!o) continue;
        addMsg(s, withAtt(String(row.id), o.who, g, { t: o.text, d: o.at, a: o.att }, o.who === s.who));
        remember(String(row.id));
        changed = true;
      }
      if (changed) setSess({ ...s });
    });
  }

  async function loadMarks(g: string) {
    const s = ref.current.sess;
    if (!s || W.memberCount(g) === 0) return;
    try {
      const r = await getReacts(s.token, g);
      const out: Mark[] = [];
      for (const x of r.reacts || []) {
        try {
          const id = String(x.id);
          const opened = W.open(g, String(x.ct || ""));
          if (!opened) continue;
          const o = JSON.parse(opened.text);
          const who = String(o.w || opened.who);
          const b = await peerOf(s, who);
          if (!edVerify(b.ed, enc.encode(g + "|r|" + id + "|" + who), b64d(String(x.sg)))) continue;
          out.push({ id, mid: String(o.m), who, emo: String(o.e), mine: who === s.who });
        } catch (e) {}
      }
      setMarks(out);
    } catch (e) {}
  }

  async function toggleMark(mid: string, emo: string) {
    const s = ref.current.sess;
    const ch = activeCh(s);
    if (!s || !ch) return;
    setErr("");
    try {
      const hit = marks.find((x) => x.mid === mid && x.emo === emo && x.mine);
      if (hit) {
        await dropReact(s.token, hit.id, ch.sid);
        setMarks((prev) => prev.filter((x) => x.id !== hit.id));
      } else {
        const id = rid(16);
        const aad = enc.encode(ch.sid + "|r|" + id);
        const ct = W.seal(ch.sid, enc.encode(JSON.stringify({ m: mid, w: s.who, e: emo })));
        if (!ct) throw new Error("waiting for peer");
        const sg = b64e(edSign(b64d(s.keys.edPriv), enc.encode(ch.sid + "|r|" + id + "|" + s.who)));
        await postReact(s.token, { id, g: ch.sid, ct, sg });
        setMarks((prev) => [...prev, { id, mid, who: s.who, emo, mine: true }]);
      }
    } catch (e) {
      setErr(dberr(e) ? "database unreachable" : "react failed");
    }
  }

  async function makeLink() {
    const s = ref.current.sess;
    if (!s) return;
    setErr("");
    setView("boot");
    try {
      const gi = W.groupInfo(W.newGroup(s.who, W.signer()));
      const r = await newLink(s.token, gi);
      const g = String(r.g);
      W.createRoom(g);
      await putGroupInfo(s.token, g, W.groupInfoOf(g));
      const code = String((await freshInvite(s.token, g)).code);
      setRoom(g);
      setLink(code);
      if (!s.chans.find((x) => x.sid === g)) s.chans.push({ sid: g, link: code, members: [s.who], unread: 0 });
      selRef.current = g;
      setSel(g);
      setIsFunder(true);
      setView("chan");
      setSess({ ...s });
      goLive();
      window.history.replaceState(null, "", "?l=" + g);
    } catch (e) {
      setErr(dberr(e) ? "database unreachable" : "link failed");
      setView("home");
    }
  }

  async function openLink(s: Sess, g: string, knownCode?: string) {
    setErr("");
    try {
      const st = await getLink(s.token, g);
      setRoom(g);
      const ch = s.chans.find((x) => x.sid === g);
      if (ch) {
        ch.members = st.mm;
        setSess({ ...s });
      }
      if (!st.inRoom) {
        if (knownCode) {
          await enterWithCode(s, g, knownCode);
          return;
        }
        setView("code");
        window.history.replaceState(null, "", "?l=" + g);
        return;
      }
      const code = String((await freshInvite(s.token, g)).code);
      setLink(code);
      announce(s);
      if (!ch) {
        s.chans.push({ sid: g, link: code, members: st.mm, unread: 0 });
        setSess({ ...s });
      }
      setIsFunder(st.mm[0] === s.who);
      selRef.current = g;
      setSel(g);
      setView("chan");
      goLive();
    } catch (e) {
      setErr(dberr(e) ? "database unreachable" : "bad link");
      setView("code");
    }
  }

  async function enterWithCode(s: Sess, g: string, code: string) {
    const got = String((await resolveInvite(s.token, code)).g);
    if (got !== g) throw new Error("wrong code");
    const j = await joinLink(s.token, g, code);
    const others = j.mm.filter((x: string) => x !== s.who);
    if (others.length === 0) throw new Error("wrong code");
    const ex = s.chans.find((x) => x.sid === g);
    if (!ex) {
      s.chans.push({ sid: g, link: code, members: j.mm, unread: 0 });
    } else {
      ex.members = j.mm;
      if (!ex.link) ex.link = code;
    }
    setSess({ ...s });
    selRef.current = g;
    setSel(g);
    setRoom(g);
    setLink(code);
    setIsFunder(j.mm[0] === s.who);
    setView("chan");
    goLive();
  }

  async function openBody(s: Sess, g: string, row: any): Promise<{ who: string; text: string; at: number; att?: Att } | null> {
    const ct = String(row.ct || "");
    if (!ct) return null;
    const opened = W.open(g, ct);
    if (!opened) return null;
    let o: any = null;
    try {
      o = JSON.parse(opened.text);
    } catch (e) {
      return null;
    }
    return {
      who: String(o.w || opened.who),
      text: String(o.t || ""),
      at: Number(o.d) || Date.now(),
      att: o.a ? { id: String(o.a.id), name: String(o.a.n), mime: String(o.a.m), size: Number(o.a.s) } : undefined
    };
  }

  function relay(g: string, payload: Uint8Array) {
    const m = meshes.get(g);
    if (!m) return;
    P2P.spread(m, payload);
  }


  async function joinWithCode() {
    const s = ref.current.sess;
    const g = ref.current.room;
    if (!s || !g || !codeIn) return;
    setErr("");
    setView("boot");
    try {
      await enterWithCode(s, g, codeIn.trim());
      setCodeIn("");
    } catch (e) {
      if (dberr(e)) {
        setErr("database unreachable");
        setView("code");
        return;
      }
      setErr(e instanceof Error && (e as Error & { status?: number }).status === 409 ? "this chat already has two people, links are for one other person" : "wrong code");
      setView("code");
    }
  }

  async function openPaste() {
    const s = ref.current.sess;
    if (!s || !paste) return;
    const raw = paste.trim();
    setPaste("");
    if (raw.includes("?l=")) {
      await openLink(s, (raw.split("?l=").pop() || raw).trim());
      return;
    }
    setView("boot");
    try {
      const g = String((await resolveInvite(s.token, raw)).g);
      window.history.replaceState(null, "", "?l=" + g);
      await openLink(s, g, raw);
    } catch (e) {
      setErr(dberr(e) ? "database unreachable" : "bad link");
      setView("home");
    }
  }

  async function send() {
    if (pending) {
      const f = pending.f;
      const caption = text;
      dropPending();
      await sendFile(f, caption);
      return;
    }
    return seq(async () => {
      const s = ref.current.sess;
      const ch = activeCh(s);
      if (!s || !ch || !text) return;
      if (text.length > MAXM) {
        setErr("too long");
        return;
      }
      setErr("");
      try {
        const at = Date.now();
        const body = text;
        const id = await post(s, ch, { w: s.who, t: body, d: at });
        s.msgs.push({ id, who: s.who, room: ch.sid, text: body, mine: true, at });
        remember(id);
        setSess({ ...s });
        setText("");
        ping(false);
      } catch (e) {
        setErr(dberr(e) ? "database unreachable" : e instanceof Error ? e.message : "send failed");
      }
    }).then(() => {
      pull().catch(() => {});
    });
  }

  async function post(s: Sess, ch: Chan, o: { w: string; t: string; d: number; a?: Att }): Promise<string> {
    const ct = W.seal(ch.sid, enc.encode(JSON.stringify({ w: o.w, t: o.t, d: o.d, a: o.a ? { id: o.a.id, n: o.a.name, m: o.a.mime, s: o.a.size } : null })));
    if (!ct) throw new Error("waiting for peer");
    const id = ctId(ct);
    const aad = enc.encode(ch.sid + "|" + id);
    const sg = b64e(edSign(b64d(s.keys.edPriv), enc.encode(ch.sid + "|" + id + "|" + o.w + "m")));
    relay(ch.sid, b64d(ct));
    await postMsg(s.token, { id, g: ch.sid, ct, sg, bo: 0, exp: null });
    return id;
  }

  async function sendFile(f: File, caption: string) {
    return seq(async () => {
      const s = ref.current.sess;
      const ch = activeCh(s);
      if (!s || !ch) return;
      setErr("");
      try {
        if (!f.size || f.size > 10485760) throw new Error("bad file");
        if (caption.length > MAXM) throw new Error("too long");
        if (W.memberCount(ch.sid) === 0) throw new Error("waiting for peer");
        const buf = new Uint8Array(await f.arrayBuffer());
        const blobId = rid(16);
        const eb = W.seal(ch.sid, buf) || "";
        await postBlob(s.token, { id: blobId, data: eb, g: ch.sid });
        keepBlob(blobId, URL.createObjectURL(new Blob([buf as BlobPart], { type: f.type || "bin" })));
        const at = Date.now();
        const id = await post(s, ch, {
          w: s.who,
          t: caption,
          d: at,
          a: { id: blobId, name: f.name.slice(0, 100), mime: f.type || "bin", size: f.size }
        });
        s.msgs.push({ id, who: s.who, room: ch.sid, text: caption, mine: true, at, att: { id: blobId, name: f.name.slice(0, 100), mime: f.type || "bin", size: f.size } });
        setSess({ ...s });
        setText("");
        setPending(null);
        ping(false);
      } catch (e) {
        setErr(dberr(e) ? "database unreachable" : e instanceof Error ? e.message : "send failed");
      }
    }).then(() => {
      pull().catch(() => {});
    });
  }

  function keys(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  }

  async function remove() {
    const s = ref.current.sess;
    const ch = activeCh(s);
    if (!s || !ch) return;
    setErr("");
    try {
      dropRoom(ch.sid, s.msgs);
      await delLink(s.token, ch.sid);
      s.chans = s.chans.filter((c) => c.sid !== ch.sid);
      s.msgs = s.msgs.filter((m) => m.room !== ch.sid);
      const nx = s.chans[0];
      selRef.current = nx ? nx.sid : "";
      setSel(selRef.current);
      setRoom(selRef.current);
      setLink(nx ? nx.link : "");
      setSess({ ...s });
      if (!nx) {
        if (live.current) clearInterval(live.current);
        if (sock.current) sock.current();
        setView("home");
        window.history.replaceState(null, "", "/");
      } else {
        tick();
      }
    } catch (e) {
      setErr(dberr(e) ? "database unreachable" : "delete failed");
    }
  }

  async function newCode() {
    const s = ref.current.sess;
    const ch = activeCh(s);
    if (!s || !ch) return;
    setErr("");
    try {
      const code = String((await freshInvite(s.token, ch.sid)).code);
      ch.link = code;
      setLink(code);
      setSess({ ...s });
      window.history.replaceState(null, "", "?l=" + ch.sid);
    } catch (e) {
      setErr(dberr(e) ? "database unreachable" : "code failed");
    }
  }

  async function pickFile() {
    const s = ref.current.sess;
    const ch = activeCh(s);
    if (!s || !ch) return;
    if (W.memberCount(ch.sid) === 0) {
      setErr("waiting for peer");
      return;
    }
    fileRef.current?.click();
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files ? e.target.files[0] : null;
    e.target.value = "";
    if (!f) return;
    if (!f.size || f.size > 10485760) {
      setErr("bad file");
      return;
    }
    if (pending) URL.revokeObjectURL(pending.url);
    setPending({ f, url: URL.createObjectURL(f), name: f.name.slice(0, 100) });
    box.current?.focus();
  }

  function dropPending() {
    if (pending) URL.revokeObjectURL(pending.url);
    setPending(null);
  }

  async function wipeMsg(id: string, g: string) {
    const s = ref.current.sess;
    if (!s) return;
    setErr("");
    try {
      const sig = b64e(edSign(b64d(s.keys.edPriv), enc.encode(g + "|" + id + "|" + s.who + "m")));
      await delMsg(s.token, id, g, sig);
      const hit = s.msgs.find((m) => m.id === id);
      if (hit && hit.att) dropBlob(hit.att.id);
      s.msgs = s.msgs.filter((m) => m.id !== id);
      setMarks((prev) => prev.filter((x) => x.mid !== id));
      setSess({ ...s });
    } catch (e) {
      setErr(dberr(e) ? "database unreachable" : e instanceof Error && (e as Error & { status?: number }).status === 403 ? "you can only delete your own" : "delete failed");
    }
  }

  function markGroups(mid: string) {
    const out: { emo: string; n: number; mine: boolean }[] = [];
    for (const m of marks.filter((x) => x.mid === mid)) {
      const g = out.find((x) => x.emo === m.emo);
      if (g) {
        g.n++;
        if (m.mine) g.mine = true;
      } else {
        out.push({ emo: m.emo, n: 1, mine: m.mine });
      }
    }
    return out;
  }

  function doCopy(which: number) {
    navigator.clipboard.writeText(link);
    setCopied(which);
    window.setTimeout(() => setCopied(0), 1200);
  }

  if (view === "boot") {
    return (
      <div className="uKTAN">
        <div className="nBzan SWxs9">chat<span>.</span></div>
      </div>
    );
  }

  if (view === "home") {
    return (
      <div className="uKTAN">
        <div className="qh46j RHOGd" />
        <div className="qh46j QLy7z" />
        <div className="Ieofc">
          <div className="nBzan">chat<span>.</span></div>
          <div className="wIE7B">share a link, talk in private</div>
          <button className="ZwE4b lTlgd" onClick={makeLink}>new link</button>
          <div className="CDnzW"><span>or join one</span></div>
          <input className="LjfKp nAfL3" value={paste} onChange={(e) => setPaste(e.target.value)} placeholder="paste link" />
          <button className="ZwE4b td7Kx lTlgd" onClick={openPaste}>open</button>
          {err ? <div className="Kxztl">{err}</div> : null}
        </div>
      </div>
    );
  }

  if (view === "code") {
    return (
      <div className="uKTAN">
        <div className="qh46j RHOGd" />
        <div className="qh46j QLy7z" />
        <div className="Ieofc">
          <div className="nBzan">chat<span>.</span></div>
          <div className="wIE7B">this room needs its code, the link alone is not enough</div>
          <input className="LjfKp nAfL3" value={codeIn} onChange={(e) => setCodeIn(e.target.value)} placeholder="code" />
          <button className="ZwE4b lTlgd" onClick={joinWithCode}>join</button>
          {err ? <div className="Kxztl">{err}</div> : null}
        </div>
      </div>
    );
  }

  const ch0 = sess?.chans.find((x) => x.sid === sel);
  const shown = (sess?.msgs || [])
    .filter((m) => (ch0 ? m.room === ch0.sid : false))
    .sort((a, b) => (a.at - b.at) || (a.id < b.id ? -1 : 1));
  const ch = ch0;
  const who = sess ? sess.who : "";
  const others = ch ? ch.members.filter((x) => x !== who) : [];
  const ready = !!ch && W.memberCount(ch.sid) >= others.length && W.memberCount(ch.sid) > 0;
  const full = !!ch && ch.members.length >= 2;
  const iAmLive = liveNow.indexOf(who) >= 0;
  const whoLabel = (id: string) => (id === who ? "you" : short(id));

  const isOn = (id: string) => (id === who ? iAmLive : liveNow.indexOf(id) >= 0);
  const rows = others.slice().sort((a, b) => {
    const d = Number(isOn(b)) - Number(isOn(a));
    return d !== 0 ? d : a < b ? -1 : 1;
  });
  const onTotal = rows.filter(isOn).length + (iAmLive ? 1 : 0);

  const nowMs = Date.now();
  const typingNames = Object.keys(typers)
    .filter((k) => nowMs - typers[k] < 6000)
    .map(whoLabel)
    .slice(0, 3);
  const typingText =
    typingNames.length === 0
      ? ""
      : typingNames.length === 1
        ? typingNames[0] + " is typing"
        : typingNames.length === 2
          ? typingNames[0] + " and " + typingNames[1] + " are typing"
          : typingNames.slice(0, 2).join(", ") + " and " + (typingNames.length - 2) + " more are typing";

  const head = ch ? "# " + (others.length === 1 ? short(others[0]) : short(ch.sid)) : "private chat";

  return (
    <div className="H0Lil">
      <div className="VCY08">
        <button className="ILaXD" onClick={() => { setView("home"); window.history.replaceState(null, "", "/"); }}>+</button>
        {(sess?.chans || []).map((c) => (
          <button key={c.sid} className={c.sid === sel ? "ILaXD nNBWY" : "ILaXD"} onClick={() => select(c.sid)}>
            {short(c.sid).slice(0, 2)}
            {c.unread > 0 ? <b>{c.unread > 9 ? "9+" : c.unread}</b> : null}
          </button>
        ))}
      </div>
      <div className="Uz7eh">
        <input className="u0N0r" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find or start a conversation" />
        <div className="el0jq">
          <span>Direct Messages</span>
          <span>{(sess?.chans || []).length}</span>
        </div>
        {(sess?.chans || []).filter((c) => c.sid.includes(q) || others.some((o) => o.includes(q)) || q === "").map((c) => (
          <div key={c.sid} className={c.sid === sel ? "xguGG nNBWY" : "xguGG"} onClick={() => select(c.sid)}>
            {short(c.sid)}{c.unread > 0 ? " (" + c.unread + ")" : ""}
          </div>
        ))}
        <div className="HtWIW">
          <div className="n2UDd">Y</div>
          <div>
            <div className="oK6fY">you</div>
            <div className="gMhjx">{sess ? short(sess.who) : ""}</div>
          </div>
        </div>
      </div>
      <div className="kbuXM">
        <div className="S1uUm">
          <span>{head}</span>
          {typingNames.length > 0 ? <span className="ilzlL">{typingNames}</span> : null}
        </div>
        {!ready ? (
          <div className="UdRtl">
            <div className="Ieofc" style={{ margin: "40px auto" }}>
              <div className="nBzan">{others.length ? "finishing the handshake" : "waiting for peer"}</div>
              <div className="wIE7B">{others.length ? "exchanging keys, one moment" : "share this code with one other person"}</div>
              {others.length ? null : (
                <>
                  <div className="Kxztl">{link}</div>
                  <div className="TYj89">
                    <button className="ZwE4b td7Kx" onClick={() => doCopy(1)}>{copied === 1 ? "copied" : "copy code"}</button>
                  </div>
                </>
              )}
              {err ? <div className="vSx8V">{err}</div> : null}
            </div>
          </div>
        ) : null}
        <div className="UdRtl">
          {shown.map((m, i) => {
            const first = i === 0 || shown[i - 1].who !== m.who || shown[i - 1].mine !== m.mine;
            const groups = markGroups(m.id);
            return (
              <div key={m.id} onMouseEnter={() => setHover(m.id)} onMouseLeave={() => setHover(null)} className={first ? (m.mine ? "j0aiJ dmbYY" : "j0aiJ") : (m.mine ? "j0aiJ FfZQF dmbYY" : "j0aiJ FfZQF")}>
                {first ? <div className="fGTYh">{m.mine ? "Y" : short(m.who).slice(0, 1)}</div> : <div className="brlVj" />}
                <div className="GOfVa">
                  {first ? (
                    <div className="sCdur">
                      {m.mine ? "you" : short(m.who)}
                      <span>{stamp(new Date(m.at).toISOString())}</span>
                    </div>
                  ) : null}
                  {m.att && sess ? (
                    <div className="aT8fD">
                      <FileView id={m.att.id} conv={m.room} token={sess.token} name={m.att.name} mime={m.att.mime} size={m.att.size} big={big === m.id} out={bigOut} onBig={() => setBig(m.id)} onShut={shutBig} />
                    </div>
                  ) : null}
                  {m.text ? <div className="hejGP">{m.text}</div> : null}
                  {groups.length > 0 ? (
                    <div className="cHp1R" key={groups.map((g) => g.emo + g.n).join("|")}>
                      {groups.map((g) => (
                        <span key={g.emo} onClick={() => toggleMark(m.id, g.emo)} className={g.mine ? "cHp2C nNBWY" : "cHp2C"}>{g.emo} <b>{g.n}</b></span>
                      ))}
                    </div>
                  ) : null}
                  {hover === m.id ? (
                    <div className="rBr3A">
                      <span onClick={() => toggleMark(m.id, "❤️")}>❤️</span>
                      <span onClick={() => { if (emoOpen === m.id) shutEmo(); else { setEmoOut(false); setEmoOpen(m.id); } }} className="rIc7S"><Plus size={16} /></span>
                      {m.mine ? (
                        <span onClick={() => wipeMsg(m.id, m.room)} className="rIc7S rmX7T" title="delete message"><Trash2 size={16} /></span>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
        {typingText ? (
          <div className="f8LAq"><span /><span /><span /><b>{typingText}</b></div>
        ) : null}
        {emoOpen ? (
          <>
            <div className="xV2pQ" onClick={shutEmo} />
            <div className={emoOut ? "eMw4E qZ4oU" : "eMw4E"}>
              <EmoPicker onPick={(n) => { toggleMark(emoOpen, n); shutEmo(); }} />
            </div>
          </>
        ) : null}
        {composeEmo ? (
          <>
            <div className="xV2pQ" onClick={shutCmp} />
            <div className={cmpOut ? "eMw4E qZ4oU" : "eMw4E"}>
              <EmoPicker onPick={(n) => { setText((t) => (t + n).slice(0, MAXM)); shutCmp(); box.current?.focus(); }} />
            </div>
          </>
        ) : null}
        {pending ? (
          <div className="aT8fD pD9vV">
            <img src={pending.url} className="iTt5T" alt="" />
            <div className="fN2pQ">{pending.name}</div>
            <button className="ZwE4b td7Kx qWz9k" onClick={dropPending}><CloseIcon size={16} /></button>
          </div>
        ) : null}
        <div className="XcZPL">
          <button className="ZwE4b td7Kx qWz9k" onClick={pickFile}><Plus size={20} /></button>
          <input ref={fileRef} type="file" style={{ display: "none" }} onChange={onFile} />
          <textarea ref={box} value={text} maxLength={MAXM} rows={1} onChange={(e) => onType(e.target.value)} onKeyDown={keys} placeholder={ready ? "Message" : "Waiting for someone to join"} />
          <span className="mCprG">{text.length}/{MAXM}</span>
          <button className="ZwE4b td7Kx qWz9k" onClick={() => { if (composeEmo) shutCmp(); else { setCmpOut(false); setComposeEmo(true); } }}><Smile size={20} /></button>
          <button className="ZwE4b" onClick={send}>send</button>
        </div>
      </div>
      <div className="WisiF">
        <div className="el0jq">
          <span>Session</span>
        </div>
        <div style={{ padding: 8 }}>
          <div className="Cqclo">invite code</div>
          <div className="Kxztl">{link}</div>
          <div className="TYj89">
            <button className="ZwE4b td7Kx" onClick={() => doCopy(2)}>{copied === 2 ? "copied" : "copy code"}</button>
          </div>
          <div className="TYj89">
            <button className="ZwE4b td7Kx" onClick={() => { if (full) makeLink(); else newCode(); }}>{full ? "new chat" : "new code"}</button>
          </div>
          {err ? <div className="vSx8V">{err}</div> : null}
          {isFunder ? (
            <div className="TYj89">
              <button className="ZwE4b td7Kx" onClick={remove}>delete chat</button>
            </div>
          ) : null}
        </div>
        <div className="el0jq">
          <span>In this link</span>
          <span>{onTotal} of {ch ? ch.members.length : 0} online</span>
        </div>
        <div className="iTwdo">
          <div className="n2UDd JjUHb">Y</div>
          <div>
            <div className="NytBQ">you</div>
            <div className="xc0wO">{iAmLive ? "online" : "reconnecting"}</div>
          </div>
          <div className={"kVw8L" + (iAmLive ? " Qm7dRt" : "")} />
        </div>
        {rows.map((p) => {
          const up = isOn(p);
          const keyOk = !!sess?.codes[p];
          return (
            <div key={p} className="iTwdo">
              <div className={"n2UDd" + (up ? " JjUHb" : " Rp4vXq")}>{short(p).slice(0, 1)}</div>
              <div>
                <div className="NytBQ">{short(p)}</div>
                <div className="xc0wO">{up ? (keyOk ? "online, key known" : "online") : "offline"}</div>
              </div>
              <div className={"kVw8L" + (up ? " Qm7dRt" : "")} />
            </div>
          );
        })}
      </div>
    </div>
  );
}
