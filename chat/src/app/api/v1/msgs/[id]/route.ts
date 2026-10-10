import { createPublicKey, verify } from "crypto";
import { getDb } from "../../../lib/db";
import { authed, deny, member, need, throttled } from "../../../lib/auth";
import { tell } from "../../../lib/push";
import C from "../../../../../../fields.json";

function edKey(edB64: string) {
  return createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(edB64, "base64")]),
    format: "der",
    type: "spki"
  });
}

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();
  const { id } = await ctx.params;
  const url = new URL(req.url);
  const g = url.searchParams.get("g") || "";
  const sig = url.searchParams.get("sig") || "";
  if (!need(id, 64) || !need(g, 64) || !need(sig, 256)) return Response.json({ error: "bad msg" }, { status: 400 });
  const found = await member(me.who, g);
  if (!found) return Response.json({ error: "bad msg" }, { status: 404 });
  const db = await getDb();
  const row = await db.collection("msgs").findOne({ [C.msgs.id]: id, [C.msgs.g]: g });
  if (!row) return Response.json({ ok: true });
  const b64u = Buffer.from(String(row[C.msgs.sg]), "base64").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (b64u !== sig) return Response.json({ error: "not yours" }, { status: 403 });
  const data = Buffer.from(g + "|" + id + "|" + me.who + "m");
  const raw = Buffer.from(sig.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  let mine = false;
  for (const who of found.mm) {
    const n = await db.collection("nodes").findOne({ [C.nodes.who]: who });
    if (!n || !n[C.nodes.ed]) continue;
    if (!verify(null, data, edKey(String(n[C.nodes.ed])), raw)) continue;
    mine = who === me.who;
    break;
  }
  if (!mine) return Response.json({ error: "not yours" }, { status: 403 });
  await db.collection("msgs").deleteOne({ [C.msgs.id]: id, [C.msgs.g]: g });
  tell(found.mm, me.who, { type: "wake", link: g });
  return Response.json({ ok: true });
}