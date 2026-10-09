import { getDb, env } from "../../lib/db";
import { authed, deny, need, throttled } from "../../lib/auth";
import { tell } from "../../lib/push";
import C from "../../../../../fields.json";

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json();
  if (!need(b.id, 64) || !need(b.g, 64) || !need(b.ct, 1400000) || !need(b.sg, 256)) {
    return Response.json({ error: "bad msg" }, { status: 400 });
  }
  const g = String(b.g);
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "bad msg" }, { status: 400 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) < 0) return Response.json({ error: "bad msg" }, { status: 400 });
  if (b.exp !== undefined && b.exp !== null) return Response.json({ error: "bad msg" }, { status: 400 });
  const exp = new Date(Date.now() + env.blobTtlH * 3600 * 1000);
  await db.collection("msgs").insertOne({
    [C.msgs.id]: String(b.id),
    [C.msgs.g]: g,
    [C.msgs.ct]: String(b.ct),
    [C.msgs.sg]: String(b.sg),
    [C.msgs.bo]: b.bo === 1 ? 1 : 0,
    [C.msgs.sq]: Number(row[C.grps.sq] || 0),
    [C.msgs.exp]: exp
  });
  await db.collection("grps").updateOne({ [C.grps.g]: g }, { $set: { [C.grps.ac]: new Date() } });
  tell(mm, me.who, { type: "wake", link: g });
  return Response.json({ ok: true, sq: Number(row[C.grps.sq] || 0) });
}

export async function GET(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const db = await getDb();
  const rooms = (new URL(req.url).searchParams.get("g") || "").split(",").filter((x) => need(x, 64)).slice(0, 200);
  if (rooms.length === 0) return Response.json({ msgs: [] });
  const allowed: string[] = [];
  for (const g of rooms) {
    const row = await db.collection("grps").findOne({ [C.grps.g]: g });
    if (!row) continue;
    const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
    if (mm.indexOf(me.who) >= 0) allowed.push(g);
  }
  if (allowed.length === 0) return Response.json({ msgs: [] });
  const rows = await db.collection("msgs").find({ [C.msgs.g]: { $in: allowed } }).sort({ [C.msgs.sq]: 1, [C.msgs.id]: 1 }).limit(300).toArray();
  return Response.json({
    msgs: rows.map((r) => ({
      id: String(r[C.msgs.id]),
      g: String(r[C.msgs.g]),
      ct: String(r[C.msgs.ct]),
      sg: String(r[C.msgs.sg]),
      bo: Number(r[C.msgs.bo] || 0),
      sq: Number(r[C.msgs.sq] || 0)
    }))
  });
}