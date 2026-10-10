import { createHash } from "crypto";
import { getDb } from "../../../lib/db";
import { authed, deny, member, need, throttled } from "../../../lib/auth";
import { tell } from "../../../lib/push";
import C from "../../../../../../fields.json";

const LABEL = Buffer.from("chat. delete commitment v1|");

function commitOf(tokB64url: string): string {
  const raw = Buffer.from(tokB64url.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  return createHash("sha256").update(LABEL).update(raw).digest("base64url");
}

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { id } = await ctx.params;
  const url = new URL(req.url);
  const g = url.searchParams.get("g") || "";
  const tok = url.searchParams.get("tok") || "";
  if (!need(id, 64) || !need(g, 64) || !need(tok, 256)) return Response.json({ error: "bad msg" }, { status: 400 });
  const found = await member(me.who, g);
  if (!found) return Response.json({ error: "bad msg" }, { status: 404 });
  const db = await getDb();
  const row = await db.collection("msgs").findOne({ [C.msgs.id]: id, [C.msgs.g]: g });
  if (!row) return Response.json({ ok: true });
  if (commitOf(tok) !== String(row[C.msgs.sg])) return Response.json({ error: "not yours" }, { status: 403 });
  await db.collection("msgs").deleteOne({ [C.msgs.id]: id, [C.msgs.g]: g });
  tell(found.mm, me.who, { type: "wake", link: g });
  return Response.json({ ok: true });
}