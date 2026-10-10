import { getDb, env } from "../../lib/db";
import { authed, deny, need, throttled } from "../../lib/auth";
import C from "../../../../../fields.json";

const MAX_BLOB = 1500000;
const MAX_ROOM_BYTES = 64 * 1024 * 1024;

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json();
  if (!need(b.id, 64) || !need(b.data, MAX_BLOB) || !need(b.g, 64)) {
    return Response.json({ error: "bad blob" }, { status: 400 });
  }
  const g = String(b.g);
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "bad blob" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) < 0) return Response.json({ error: "bad blob" }, { status: 404 });

  const size = Buffer.byteLength(String(b.data), "utf8");
  const res = await db
    .collection("grps")
    .updateOne(
      { [C.grps.g]: g, $or: [{ [C.grps.by]: { $exists: false } }, { [C.grps.by]: { $lte: MAX_ROOM_BYTES - size } }] },
      { $inc: { [C.grps.by]: size } }
    );
  if (res.modifiedCount === 0) return Response.json({ error: "room storage full" }, { status: 413 });

  await db.collection("blobs").insertOne({
    [C.blobs.id]: String(b.id),
    [C.blobs.data]: String(b.data),
    [C.blobs.g]: g,
    [C.blobs.exp]: new Date(Date.now() + env.blobTtlH * 3600 * 1000)
  });
  return Response.json({ ok: true });
}