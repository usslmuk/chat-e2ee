import { online } from "../../lib/push";
import { authed, deny, need, throttled } from "../../lib/auth";
import { getDb } from "../../lib/db";
import C from "../../../../../fields.json";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();

  const rooms = (new URL(req.url).searchParams.get("g") || "").split(",").filter((x) => need(x, 64)).slice(0, 200);
  if (rooms.length === 0) return Response.json({ on: [] });

  const db = await getDb();
  const live = new Set(online());
  const out: string[] = [];
  for (const g of rooms) {
    const row = await db.collection("grps").findOne({ [C.grps.g]: g });
    if (!row) continue;
    const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
    for (const who of mm) {
      if (live.has(who) && out.indexOf(who) < 0) out.push(who);
    }
  }
  return Response.json({ on: out });
}