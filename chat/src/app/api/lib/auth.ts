import { randomBytes, createHash, timingSafeEqual } from "crypto";
import { getDb, env } from "./db";
import { limited, ipOf } from "./limit";
import C from "../../../../fields.json";

export function hex(n: number) {
  return randomBytes(n).toString("hex");
}

export function hashToken(token: string) {
  return createHash("sha256").update(token + env.pepper).digest("hex");
}

export function hashCode(code: string) {
  return createHash("sha256").update(code + env.pepper).digest("hex");
}

export function same(a: string, b: string) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

export function need(v: unknown, max: number) {
  return typeof v === "string" && v.length > 0 && v.length <= max;
}

const bursts = new Map<string, { n: number; reset: number }>();

export function guard(who: string) {
  const now = Date.now();
  let h = bursts.get(who);
  if (!h || now > h.reset) {
    if (bursts.size > 20000) bursts.clear();
    h = { n: 0, reset: now + 10000 };
    bursts.set(who, h);
  }
  h.n++;
  if (h.n > 60) return Response.json({ error: "slow down" }, { status: 429 });
  return null;
}

const whoByTok = new Map<string, string>();

export async function authed(req: Request) {
  const h = req.headers.get("authorization") || "";
  const parts = h.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return null;
  const db = await getDb();
  const hh = hashToken(parts[1]);
  const hit = await db.collection("tok").findOne({ [C.tok.h]: hh });
  if (!hit) return null;
  if (hit[C.tok.exp] && new Date(hit[C.tok.exp]).getTime() < Date.now()) return null;
  const who = String(hit[C.tok.who]);
  if (whoByTok.size > 20000) whoByTok.clear();
  whoByTok.set(hh, who);
  return { who };
}

export async function member(who: string, g: string) {
  const row = await (await getDb()).collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return null;
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(who) < 0) return null;
  return { row, mm };
}

export function deny() {
  return Response.json({ error: "bad auth" }, { status: 401 });
}

export function throttled(req: Request) {
  const h = req.headers.get("authorization") || "";
  const parts = h.split(" ");
  let who = parts.length === 2 && parts[0] === "Bearer" ? whoByTok.get(hashToken(parts[1])) || "" : "";
  if (who) {
    const stopped = guard(who);
    if (stopped) return stopped;
  }
  if (limited(ipOf(req))) return Response.json({ error: "slow down" }, { status: 429 });
  return null;
}