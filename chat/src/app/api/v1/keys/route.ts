import { getDb } from "../../lib/db";
import { authed, deny, need, throttled } from "../../lib/auth";
import C from "../../../../../fields.json";

export async function PUT(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json();
  if (!need(b.ed, 128) || !need(b.ex, 64) || !need(b.sig, 128)) {
    return Response.json({ error: "bad keys" }, { status: 400 });
  }
  if (b.opks) return Response.json({ error: "bad keys" }, { status: 400 });
  if (b.kp !== undefined && b.kp !== null && !need(b.kp, 40000)) {
    return Response.json({ error: "bad keys" }, { status: 400 });
  }
  const db = await getDb();
  const set: Record<string, unknown> = {
    [C.nodes.ed]: b.ed,
    [C.nodes.ex]: b.ex,
    [C.nodes.sig]: b.sig,
    [C.nodes.at]: new Date()
  };
  if (typeof b.kp === "string" && b.kp.length > 0) set[C.nodes.kp] = b.kp;
  await db.collection("nodes").updateOne({ [C.nodes.who]: me.who }, { $set: set }, { upsert: true });
  return Response.json({ ok: true });
}