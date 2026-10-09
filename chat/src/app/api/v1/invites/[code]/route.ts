import { getDb } from "../../../lib/db";
import { authed, deny, hashCode, need, throttled } from "../../../lib/auth";
import C from "../../../../../../fields.json";

export async function GET(req: Request, ctx: { params: Promise<{ code: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { code } = await ctx.params;
  if (!need(code, 64)) return Response.json({ error: "no link" }, { status: 400 });
  const inv = await (await getDb()).collection("inv").findOne({ [C.inv.h]: hashCode(code) });
  if (!inv) return Response.json({ error: "no link" }, { status: 404 });
  return Response.json({ g: String(inv[C.inv.g]) });
}