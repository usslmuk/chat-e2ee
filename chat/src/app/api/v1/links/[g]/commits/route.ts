import { getDb, env } from "../../../../lib/db";
import { authed, deny, member, need, throttled } from "../../../../lib/auth";
import { sendTo, tell } from "../../../../lib/push";
import C from "../../../../../../../fields.json";

export const dynamic = "force-dynamic";

export async function PUT(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  const b = await req.json().catch(() => null);
  if (!b || typeof b !== "object") return Response.json({ error: "bad commit" }, { status: 400 });
  if (!need(g, 64)) return Response.json({ error: "bad commit" }, { status: 400 });
  const ep = Number(b.ep);
  if (!Number.isInteger(ep) || ep < 1 || ep > 1000000) return Response.json({ error: "bad commit" }, { status: 400 });
  if (!need(b.ct, 400000) || !need(b.sg, 256) || !need(b.js, 128) || !need(b.sh, 400000)) {
    return Response.json({ error: "bad commit" }, { status: 400 });
  }
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  if (!row) return Response.json({ error: "bad commit" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm.indexOf(me.who) < 0) return Response.json({ error: "bad commit" }, { status: 403 });
  const exp = new Date(Date.now() + env.linkTtlH * 3600 * 1000);
  await db.collection("cms").updateOne(
    { [C.cms.g]: g, [C.cms.e]: ep },
    {
      $set: {
        [C.cms.g]: g,
        [C.cms.e]: ep,
        [C.cms.p]: JSON.stringify({ ct: String(b.ct), sg: String(b.sg), js: String(b.js), sh: String(b.sh) }),
        [C.cms.exp]: exp
      }
    },
    { upsert: true }
  );
  tell(mm, me.who, { type: "wake", link: g });
  return Response.json({ ok: true });
}

export async function GET(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  const from = Number(new URL(req.url).searchParams.get("e") || "0");
  if (!need(g, 64) || !Number.isInteger(from) || from < 0) {
    return Response.json({ error: "bad commit" }, { status: 400 });
  }
  const found = await member(me.who, g);
  if (!found) return Response.json({ error: "bad commit" }, { status: 404 });
  const db = await getDb();
  const rows = await db
    .collection("cms")
    .find({ [C.cms.g]: g, [C.cms.e]: { $gt: from } })
    .sort({ [C.cms.e]: 1 })
    .limit(200)
    .toArray();
  const out: { ep: number; ct: string; sg: string; js: string; sh: string }[] = [];
  for (const r of rows) {
    let p: any = null;
    try {
      p = JSON.parse(String(r[C.cms.p]));
    } catch (e) {
      continue;
    }
    if (!p) continue;
    out.push({ ep: Number(r[C.cms.e]), ct: String(p.ct), sg: String(p.sg), js: String(p.js), sh: String(p.sh) });
  }
  return Response.json({ commits: out });
}