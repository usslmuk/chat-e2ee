import { getDb, env } from "../../lib/db";
import { hex, hashCode, authed, deny, need, throttled } from "../../lib/auth";
import C from "../../../../../fields.json";

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json();
  const g = String(b.g || "");
  if (!need(g, 64)) return Response.json({ error: "no link" }, { status: 400 });
  const found = await (async () => {
    const db = await getDb();
    const row = await db.collection("grps").findOne({ [C.grps.g]: g });
    if (!row) return null;
    const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
    return mm.indexOf(me.who) >= 0;
  })();
  if (!found) return Response.json({ error: "no link" }, { status: 404 });
  const code = hex(8);
  await (await getDb()).collection("inv").insertOne({
    [C.inv.h]: hashCode(code),
    [C.inv.g]: g,
    [C.inv.exp]: new Date(Date.now() + env.idleTtlH * 3600 * 1000)
  });
  return Response.json({ code });
}