import { getDb, env } from "../../lib/db";
import { authed, deny, need, throttled } from "../../lib/auth";
import { tell } from "../../lib/push";
import { ObjectId } from "mongodb";
import C from "../../../../../fields.json";

const PAGE = 300;
const PER_ROOM = 60;
const MAX_CT = 200000;

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json();
  if (!need(b.id, 64) || !need(b.g, 64) || !need(b.ct, MAX_CT) || !need(b.sg, 256)) {
    return Response.json({ error: "bad msg" }, { status: 400 });
  }
  const g = String(b.g);
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "bad msg" }, { status: 400 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map(String) : [];
  if (!mm.includes(me.who)) return Response.json({ error: "bad msg" }, { status: 400 });
  if (b.exp !== undefined && b.exp !== null) return Response.json({ error: "bad msg" }, { status: 400 });
  const exp = new Date(Date.now() + env.blobTtlH * 3600 * 1000);
  try {
    await db.collection("msgs").insertOne({
      [C.msgs.id]: String(b.id),
      [C.msgs.g]: g,
      [C.msgs.ct]: String(b.ct),
      [C.msgs.sg]: String(b.sg),
      [C.msgs.bo]: b.bo === 1 ? 1 : 0,
      [C.msgs.exp]: exp
    });
  } catch (e) {
    if (e && typeof e === "object" && (e as { code?: number }).code === 11000) {
      return Response.json({ ok: true });
    }
    throw e;
  }
  await db.collection("grps").updateOne({ [C.grps.g]: g }, { $set: { [C.grps.ac]: new Date() } });
  tell(mm, me.who, { type: "wake", link: g });
  return Response.json({ ok: true });
}

function roomList(req: Request): string[] {
  const q = new URL(req.url).searchParams;
  return (q.get("g") || "").split(",").filter((x) => need(x, 64)).slice(0, 200);
}

function memberList(row: { [key: string]: unknown }): string[] {
  const v = row[C.grps.mm];
  return Array.isArray(v) ? v.map(String) : [];
}

async function allowedRooms(db: Awaited<ReturnType<typeof getDb>>, rooms: string[], who: string): Promise<string[]> {
  const out: string[] = [];
  for (const g of rooms) {
    const row = await db.collection("grps").findOne({ [C.grps.g]: g });
    if (!row) continue;
    if (memberList(row as { [key: string]: unknown }).includes(who)) out.push(g);
  }
  return out;
}

function capPage(page: { [key: string]: unknown }[]): { kept: { [key: string]: unknown }[]; capped: Set<string> } {
  const perRoom: Record<string, number> = {};
  const capped = new Set<string>();
  const kept = page.filter((r) => {
    const g = String(r[C.msgs.g]);
    const n = (perRoom[g] || 0) + 1;
    if (n > PER_ROOM) {
      capped.add(g);
      return false;
    }
    perRoom[g] = n;
    return true;
  });
  return { kept, capped };
}

function cursorOf(kept: { [key: string]: unknown }[], more: boolean): string | null {
  if (!more || kept.length === 0) return null;
  const id = kept[kept.length - 1]._id;
  if (id instanceof ObjectId) return id.toHexString();
  if (typeof id === "string") return id;
  return null;
}

function msgView(r: { [key: string]: unknown }): { id: string; g: string; ct: string; sg: string; bo: number } {
  return {
    id: String(r[C.msgs.id]),
    g: String(r[C.msgs.g]),
    ct: String(r[C.msgs.ct]),
    sg: String(r[C.msgs.sg]),
    bo: Number(r[C.msgs.bo] || 0),
  };
}

export async function GET(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const db = await getDb();
  const rooms = roomList(req);
  if (rooms.length === 0) return Response.json({ msgs: [], more: false });
  const allowed = await allowedRooms(db, rooms, me.who);
  if (allowed.length === 0) return Response.json({ msgs: [], more: false });

  const q = new URL(req.url).searchParams;
  const before = q.get("before");
  const cursor = before && ObjectId.isValid(before) ? new ObjectId(before) : null;
  const rows = await db
    .collection("msgs")
    .find(cursor ? { [C.msgs.g]: { $in: allowed }, _id: { $lt: cursor } } : { [C.msgs.g]: { $in: allowed } })
    .sort({ _id: -1 })
    .limit(PAGE + 1)
    .toArray();
  const more = rows.length > PAGE;
  const page = rows.slice(0, PAGE);

  const { kept, capped } = capPage(page as { [key: string]: unknown }[]);

  const cursorOut = cursorOf(kept, more);
  return Response.json({
    more,
    cursor: cursorOut,
    full: capped.size === 0,
    trimmed: capped.size > 0,
    trimmedRooms: [...capped].slice(0, 50),
    msgs: kept.slice().reverse().map(msgView),
  });
}