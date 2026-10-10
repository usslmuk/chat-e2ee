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
  const used = await roomBytes(db, g);
  if (used + size > MAX_ROOM_BYTES) return Response.json({ error: "room storage full" }, { status: 413 });

  try {
    await db.collection("blobs").insertOne({
      [C.blobs.id]: String(b.id),
      [C.blobs.data]: String(b.data),
      [C.blobs.g]: g,
      [C.blobs.sz]: size,
      [C.blobs.exp]: new Date(Date.now() + env.blobTtlH * 3600 * 1000)
    });
  } catch (err) {
    return Response.json({ error: "bad blob" }, { status: 409 });
  }
  await db.collection("grps").updateOne({ [C.grps.g]: g }, { $set: { [C.grps.by]: used + size } });
  return Response.json({ ok: true });
}

async function roomBytes(db: any, g: string): Promise<number> {
  const rows = await db
    .collection("blobs")
    .aggregate([
      { $match: { [C.blobs.g]: g } },
      {
        $group: {
          _id: null,
          n: {
            $sum: {
              $cond: [
                { $gt: [{ $ifNull: [`$${C.blobs.sz}`, 0] }, 0] },
                `$${C.blobs.sz}`,
                { $strLenBytes: `$${C.blobs.data}` },
              ],
            },
          },
        },
      },
    ])
    .toArray();
  return rows.length ? Number(rows[0].n) : 0;
}