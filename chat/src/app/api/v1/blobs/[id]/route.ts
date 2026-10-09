import { getDb } from "../../../lib/db";
import { authed, deny, need, throttled } from "../../../lib/auth";
import C from "../../../../../../fields.json";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { id } = await ctx.params;
  if (!need(id, 64)) return Response.json({ error: "no blob" }, { status: 400 });
  const db = await getDb();
  const row = await db.collection("blobs").findOne({ [C.blobs.id]: id });
  if (!row) return Response.json({ error: "no blob" }, { status: 404 });
  const room = await db.collection("grps").findOne({ [C.grps.g]: String(row[C.blobs.g] || "") });
  if (!room) return Response.json({ error: "no blob" }, { status: 404 });
  const mm: string[] = Array.isArray(room[C.grps.mm]) ? room[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) < 0) return Response.json({ error: "no blob" }, { status: 404 });
  return Response.json({ id: String(row[C.blobs.id]), data: String(row[C.blobs.data]) });
}