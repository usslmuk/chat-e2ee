import { getDb } from "../../../lib/db";
import { authed, deny, need, throttled } from "../../../lib/auth";
import C from "../../../../../../fields.json";

export async function GET(req: Request, ctx: { params: Promise<{ who: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { who } = await ctx.params;
  if (!need(who, 64)) return Response.json({ error: "no keys" }, { status: 400 });
  const db = await getDb();
  const dev = await db.collection("nodes").findOne({ [C.nodes.who]: who });
  if (!dev || !dev[C.nodes.ed]) return Response.json({ error: "no keys" }, { status: 404 });
  return Response.json({
    ed: dev[C.nodes.ed],
    ex: dev[C.nodes.ex],
    sig: dev[C.nodes.sig],
    kp: typeof dev[C.nodes.kp] === "string" ? dev[C.nodes.kp] : ""
  });
}