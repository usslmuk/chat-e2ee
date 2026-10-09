import { getDb } from "../../../../lib/db";
import { authed, deny, member, need, throttled } from "../../../../lib/auth";
import C from "../../../../../../../fields.json";

export async function PUT(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  const b = await req.json();
  if (!need(g, 64) || !need(b.gi, 40000)) return Response.json({ error: "bad key" }, { status: 400 });
  const found = await member(me.who, g);
  if (!found) return Response.json({ error: "bad key" }, { status: 404 });
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  const mm: string[] = row && Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm[0] !== me.who) return Response.json({ error: "bad key" }, { status: 403 });
  await db.collection("grps").updateOne({ [C.grps.g]: g }, { $set: { [C.grps.gi]: String(b.gi) } });
  return Response.json({ ok: true });
}