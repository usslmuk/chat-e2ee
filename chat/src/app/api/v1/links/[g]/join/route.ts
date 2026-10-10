import { getDb } from "../../../../lib/db";
import { authed, deny, hashCode, need, throttled } from "../../../../lib/auth";
import { tell } from "../../../../lib/push";
import C from "../../../../../../../fields.json";

export const ROOM_CAP = 2;

export async function PUT(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  if (!need(g, 64)) return Response.json({ error: "no link" }, { status: 400 });
  const b = await req.json().catch(() => ({}));
  const code = String(b.code || "");
  if (!need(code, 64)) return Response.json({ error: "no link" }, { status: 404 });
  const db = await getDb();
  const inv = await db.collection("inv").findOne({ [C.inv.h]: hashCode(code) });
  if (!inv || String(inv[C.inv.g]) !== g) return Response.json({ error: "no link" }, { status: 404 });
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "no link" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) >= 0) return Response.json({ ok: true, mm });
  if (mm.length >= ROOM_CAP) return Response.json({ error: "full", cap: ROOM_CAP }, { status: 409 });
  const filter: Record<string, unknown> = { [C.grps.g]: g, [C.grps.mm]: { $ne: me.who } };
  const update: Record<string, unknown> = {};
  update["$push"] = { [C.grps.mm]: me.who };
  update["$inc"] = { [C.grps.ep]: 1 };
  const res = await db.collection("grps").findOneAndUpdate(filter, update, { returnDocument: "after" });
  const now: string[] = res && Array.isArray(res[C.grps.mm]) ? res[C.grps.mm].map((x: unknown) => String(x)) : mm.concat([me.who]);
  tell(now, me.who, { type: "wake", link: g });
  return Response.json({
    ok: true,
    mm: now,
    ep: res && res[C.grps.ep] !== undefined ? Number(res[C.grps.ep]) : Number(row[C.grps.ep] || 0) + 1
  });
}