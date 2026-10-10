import { authed, deny, throttled } from "../../lib/auth";
import { env, turnCredential, turnEnabled } from "../../lib/db";

export const dynamic = "force-dynamic";

const STUN = ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"];
const TTL = 3600;

export async function GET(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const me = await authed(req);
  if (!me) return deny();

  const ice: RTCIceServer[] = [{ urls: STUN }];
  if (turnEnabled()) {
    const { username, credential } = turnCredential(TTL);
    ice.push({ urls: env.turnUrls, username, credential });
  }
  return Response.json({ ice, turn: turnEnabled() });
}