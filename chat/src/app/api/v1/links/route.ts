import { getDb, env } from "../../lib/db";
import { hex, authed, deny, need, throttled } from "../../lib/auth";
import C from "../../../../../fields.json";

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json().catch(() => null);
  if (!b || !need(b.gi, 40000)) return Response.json({ error: "bad key" }, { status: 400 });
  const g = hex(16);
  const db = await getDb();
  const exp = new Date(Date.now() + env.linkTtlH * 3600 * 1000);
  await db.collection("grps").insertOne({
    [C.grps.g]: g,
    [C.grps.mm]: [me.who],
    [C.grps.gi]: String(b.gi),
    [C.grps.sq]: 0,
    [C.grps.ep]: 0,
    [C.grps.ac]: new Date(),
    [C.grps.exp]: exp
  });
  return Response.json({ g });
}