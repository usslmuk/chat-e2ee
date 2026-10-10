import { getDb } from "../../../lib/db";
import { authed, deny, need, throttled } from "../../../lib/auth";
import C from "../../../../../../fields.json";

export async function GET(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  if (!need(g, 64)) return Response.json({ error: "no link" }, { status: 400 });
  const row = await (await getDb()).collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "no link" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  const gi = typeof row[C.grps.gi] === "string" ? row[C.grps.gi] : "";
  const inside = mm.indexOf(me.who) >= 0;
  if (!inside) {
    return Response.json({ g, mm: [], sq: 0, ep: 0, inRoom: false, gi: "" });
  }
  return Response.json({
    g,
    mm,
    ep: Number(row[C.grps.ep] || 0),
    inRoom: true,
    gi
  });
}

export async function DELETE(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  const mm: string[] = row && Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (!row || mm[0] !== me.who) return Response.json({ error: "no link" }, { status: 404 });
  await db.collection("grps").deleteOne({ [C.grps.g]: g });
  await db.collection("msgs").deleteMany({ [C.msgs.g]: g });
  await db.collection("reac").deleteMany({ [C.reac.g]: g });
  await db.collection("blobs").deleteMany({ [C.blobs.g]: g });
  await db.collection("inv").deleteMany({ [C.inv.g]: g });
  return Response.json({ ok: true });
}