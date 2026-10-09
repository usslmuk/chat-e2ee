import { getDb, env } from "../../../../lib/db";
import { authed, deny, member, need, throttled } from "../../../../lib/auth";
import { sendTo } from "../../../../lib/push";
import C from "../../../../../../../fields.json";

export async function PUT(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  const b = await req.json().catch(() => ({}));
  const forWho = String(b.w || "");
  if (!need(g, 64) || !need(forWho, 64) || !need(b.wc, 400000)) {
    return Response.json({ error: "bad welcome" }, { status: 400 });
  }
  const found = await member(me.who, g);
  if (!found) return Response.json({ error: "bad welcome" }, { status: 404 });
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: g });
  const mm: string[] = row && Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (mm[0] !== me.who) return Response.json({ error: "bad welcome" }, { status: 403 });
  const exp = new Date(Date.now() + env.linkTtlH * 3600 * 1000);
  await db.collection("wel").updateOne(
    { [C.wel.r]: g, [C.wel.w]: forWho },
    {
      $set: {
        [C.wel.b]: String(b.wc),
        [C.wel.r]: g,
        [C.wel.w]: forWho,
        [C.wel.ep]: Number(row && row[C.grps.ep] ? row[C.grps.ep] : 0),
        [C.wel.exp]: exp
      }
    },
    { upsert: true }
  );
  sendTo(forWho, "data: " + JSON.stringify({ type: "wake", link: g }) + "\n\n");
  return Response.json({ ok: true });
}

export async function GET(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  if (!need(g, 64)) return Response.json({ error: "bad welcome" }, { status: 400 });
  const found = await member(me.who, g);
  if (!found) return Response.json({ error: "bad welcome" }, { status: 404 });
  const db = await getDb();
  const row = await db.collection("wel").findOne({ [C.wel.r]: g, [C.wel.w]: me.who });
  if (!row || !row[C.wel.b]) return Response.json({ wc: "" });
  return Response.json({ wc: String(row[C.wel.b]) });
}

export async function DELETE(req: Request, ctx: { params: Promise<{ g: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { g } = await ctx.params;
  if (!need(g, 64)) return Response.json({ error: "bad welcome" }, { status: 400 });
  const found = await member(me.who, g);
  if (!found) return Response.json({ error: "bad welcome" }, { status: 404 });
  const db = await getDb();
  await db.collection("wel").deleteOne({ [C.wel.r]: g, [C.wel.w]: me.who });
  return Response.json({ ok: true });
}