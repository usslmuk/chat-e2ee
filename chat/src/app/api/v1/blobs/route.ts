import { getDb, env } from "../../lib/db";
import { authed, deny, need, throttled } from "../../lib/auth";
import C from "../../../../../fields.json";

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json();
  if (!need(b.id, 64) || !need(b.data, 14000000) || !need(b.g, 64)) {
    return Response.json({ error: "bad blob" }, { status: 400 });
  }
  const g = String(b.g);
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "bad blob" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) < 0) return Response.json({ error: "bad blob" }, { status: 404 });
  await db.collection("blobs").insertOne({
    [C.blobs.id]: String(b.id),
    [C.blobs.data]: String(b.data),
    [C.blobs.g]: g,
    [C.blobs.exp]: new Date(Date.now() + env.blobTtlH * 3600 * 1000)
  });
  return Response.json({ ok: true });
}