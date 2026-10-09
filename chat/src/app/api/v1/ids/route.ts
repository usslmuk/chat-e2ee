import { getDb, tokenExpiry } from "../../lib/db";
import { hex, hashToken, throttled } from "../../lib/auth";
import C from "../../../../../fields.json";

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const who = hex(16);
  const token = hex(32);
  const db = await getDb();
  await db.collection("tok").insertOne({
    [C.tok.h]: hashToken(token),
    [C.tok.who]: who,
    [C.tok.exp]: tokenExpiry()
  });
  return Response.json({ who, tok: token });
}