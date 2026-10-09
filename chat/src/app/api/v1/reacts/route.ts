import { getDb } from "../../lib/db";
import { authed, deny, need, throttled } from "../../lib/auth";
import C from "../../../../../fields.json";

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json();
  if (!need(b.id, 64) || !need(b.g, 64) || !need(b.ct, 8192)) {
    return Response.json({ error: "bad react" }, { status: 400 });
  }
  const g = String(b.g);
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "bad react" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) < 0) return Response.json({ error: "bad react" }, { status: 404 });
  await db.collection("reac").insertOne({
    [C.reac.id]: String(b.id),
    [C.reac.g]: g,
    [C.reac.ct]: String(b.ct),
    [C.reac.sg]: String(b.sg),
    [C.reac.exp]: null
  });
  return Response.json({ ok: true });
}

export async function GET(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const g = new URL(req.url).searchParams.get("g") || "";
  if (!need(g, 64)) return Response.json({ error: "bad react" }, { status: 400 });
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "bad react" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) < 0) return Response.json({ error: "bad react" }, { status: 404 });
  const rows = await db.collection("reac").find({ [C.reac.g]: g }).sort({ [C.reac.id]: 1 }).limit(500).toArray();
  return Response.json({
    reacts: rows.map((r) => ({ id: String(r[C.reac.id]), ct: String(r[C.reac.ct]), sg: String(r[C.reac.sg]) }))
  });
}

export async function DELETE(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const id = new URL(req.url).searchParams.get("id") || "";
  const g = new URL(req.url).searchParams.get("g") || "";
  if (!need(id, 64) || !need(g, 64)) return Response.json({ error: "bad react" }, { status: 400 });
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "bad react" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) < 0) return Response.json({ error: "bad react" }, { status: 404 });
  const hit = await db.collection("reac").findOne({ [C.reac.id]: id, [C.reac.g]: g });
  if (!hit) return Response.json({ ok: true });
  await db.collection("reac").deleteOne({ [C.reac.id]: id, [C.reac.g]: g });
  return Response.json({ ok: true });
}