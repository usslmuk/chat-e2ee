import { MongoClient, Db } from "mongodb";
import { config } from "./env";
import { createHmac } from "crypto";
import path from "path";
import C from "../../../../fields.json";

const g = globalThis as Record<string, unknown>;
if (!g.__envOnce) {
  config({ quiet: true, path: [path.join(process.cwd(), ".env"), path.join(process.cwd(), "..", ".env")] });
  g.__envOnce = true;
}

function must(k: string): string {
  const v = process.env[k];
  if (!v) throw new Error("missing " + k);
  return v;
}

function peppers(): { pepper: string; codePepper: string } {
  const p = must("PEPPER");
  const c = must("CODE_PEPPER");
  if (p.length < 32) throw new Error("PEPPER must be at least 32 bytes");
  if (c.length < 32) throw new Error("CODE_PEPPER must be at least 32 bytes");
  if (p === c) throw new Error("PEPPER and CODE_PEPPER must differ");
  return { pepper: p, codePepper: c };
}

const secret = peppers();

function num(k: string, min: number, max: number): number {
  const raw = must(k);
  const v = Number(raw);
  if (!Number.isFinite(v) || v < min || v > max) throw new Error("bad " + k);
  return Math.floor(v);
}

const prod = process.env.CHAT_DEV !== "1";

function optional(k: string): string {
  const v = process.env[k];
  return v ? v.trim() : "";
}

function turn(): { url: string; urls: string[]; secret: string } {
  const url = optional("TURN_URL");
  const s = optional("TURN_SECRET");
  if (!url && !s) return { url: "", urls: [], secret: "" };
  if (!url) throw new Error("TURN_SECRET is set but TURN_URL is missing");
  if (!s) throw new Error("TURN_URL is set but TURN_SECRET is missing");
  if (s.length < 16) throw new Error("TURN_SECRET must be at least 16 bytes");
  const urls = url.split(",").map((x) => x.trim()).filter(Boolean);
  if (urls.length === 0) throw new Error("TURN_URL has no usable urls");
  for (const u of urls) {
    if (!/^turns?:[a-z0-9.-]+(:\d+)?$/i.test(u)) {
      throw new Error("TURN_URL entries must look like turn:host:port or turns:host:port");
    }
  }
  return { url, urls, secret: s };
}

const turnCfg = turn();

export const env = {
  mongo: must("MONGO"),
  pepper: secret.pepper,
  codePepper: secret.codePepper,
  turnUrls: turnCfg.urls,
  turnSecret: turnCfg.secret,
  maxMsg: num("MAX_MSG_BYTES", 1024, 10485760),
  winMs: num("RATE_WINDOW_MS", 1000, 3600000),
  maxRate: num("RATE_MAX", 1, 100000),
  tokenTtlH: num("TOKEN_TTL_HOURS", 1, 87600),
  linkTtlH: num("LINK_TTL_HOURS", 1, 87600),
  blobTtlH: num("BLOB_TTL_HOURS", 1, 87600),
  idleTtlH: num("IDLE_TTL_HOURS", 1, 87600)
};

export function turnEnabled(): boolean {
  return env.turnUrls.length > 0;
}

export function turnCredential(ttlSeconds: number): { username: string; credential: string } {
  const username = String(Math.floor(Date.now() / 1000) + ttlSeconds);
  const mac = createHmac("sha1", env.turnSecret).update(username).digest();
  return { username, credential: mac.toString("base64") };
}

export function tokenExpiry() {
  return new Date(Date.now() + env.tokenTtlH * 3600 * 1000);
}

export class DbDown extends Error {}

let p: Promise<Db> | null = null;

async function setup(d: Db) {
  await Promise.all([
    d.collection("nodes").createIndex({ [C.nodes.who]: 1 }, { unique: true }),
    d.collection("grps").createIndex({ [C.grps.g]: 1 }, { unique: true }),
    d.collection("grps").createIndex({ [C.grps.exp]: 1 }, { expireAfterSeconds: 0 }),
    d.collection("grps").createIndex({ [C.grps.mm]: 1 }),
    d.collection("grps").createIndex({ [C.grps.ac]: 1 }),
    d.collection("wel").createIndex({ [C.wel.r]: 1, [C.wel.w]: 1 }, { unique: true }),
    d.collection("wel").createIndex({ [C.wel.exp]: 1 }, { expireAfterSeconds: 0 }),
    d.collection("inv").createIndex({ [C.inv.h]: 1 }, { unique: true }),
    d.collection("inv").createIndex({ [C.inv.exp]: 1 }, { expireAfterSeconds: 0 }),
    d.collection("msgs").createIndex(
      { [C.msgs.g]: 1, [C.msgs.id]: 1 },
      { unique: true, partialFilterExpression: { [C.msgs.g]: { $type: "string" } } }
    ),
    d.collection("msgs").createIndex({ [C.msgs.g]: 1, _id: -1 }),
    d.collection("msgs").createIndex({ [C.msgs.exp]: 1 }, { expireAfterSeconds: 0 }),
    d.collection("reac").createIndex({ [C.reac.g]: 1 }),
    d.collection("reac").createIndex({ [C.reac.exp]: 1 }, { expireAfterSeconds: 0 }),
    d.collection("blobs").createIndex({ [C.blobs.id]: 1 }, { unique: true }),
    d.collection("blobs").createIndex({ [C.blobs.exp]: 1 }, { expireAfterSeconds: 0 }),
    d.collection("tok").createIndex({ [C.tok.h]: 1 }, { unique: true }),
    d.collection("tok").createIndex({ [C.tok.exp]: 1 }, { expireAfterSeconds: 0 })
  ]);
  return d;
}

export function getDb(): Promise<Db> {
  if (!p) {
    p = (async () => {
      const c = new MongoClient(env.mongo, {
        serverSelectionTimeoutMS: prod ? 8000 : 5000,
        connectTimeoutMS: 8000,
        socketTimeoutMS: 45000,
        maxPoolSize: prod ? 40 : 20,
        minPoolSize: 2,
        retryWrites: true,
        retryReads: true,
        compressors: ["zstd"],
        appName: "chat"
      });
      await c.connect();
      const d = c.db("e2ee");
      await d.command({ ping: 1 });
      return setup(d);
    })().catch((e: unknown) => {
      p = null;
      if (process.env.NODE_ENV !== "production") {
        console.error("[db] connect failed", e);
      }
      throw new DbDown("database unreachable: " + (e instanceof Error ? e.message : String(e)));
    });
  }
  return p;
}

let warm = false;

export function prewarm(): void {
  if (warm) return;
  warm = true;
  getDb().catch(() => {
    warm = false;
  });
}

let sweepTimer: NodeJS.Timeout | null = null;

async function sweep(): Promise<void> {
  try {
    const d = await getDb();
    const cutoff = new Date(Date.now() - env.idleTtlH * 3600 * 1000);
    const stale = await d
      .collection("grps")
      .find({ [C.grps.ac]: { $lt: cutoff } }, { projection: { [C.grps.g]: 1 } })
      .limit(200)
      .toArray();
    for (const row of stale) {
      const g = String(row[C.grps.g]);
      await Promise.all([
        d.collection("msgs").deleteMany({ [C.msgs.g]: g }),
        d.collection("reac").deleteMany({ [C.reac.g]: g }),
        d.collection("blobs").deleteMany({ [C.blobs.g]: g }),
        d.collection("inv").deleteMany({ [C.inv.g]: g }),
        d.collection("wel").deleteMany({ [C.wel.r]: g }),
        d.collection("grps").deleteOne({ [C.grps.g]: g })
      ]);
    }
  } catch (e) {}
}

export function startSweeper(): void {
  if (sweepTimer) return;
  sweepTimer = setInterval(() => {
    sweep().catch(() => {});
  }, 10 * 60 * 1000);
  sweepTimer.unref();
}