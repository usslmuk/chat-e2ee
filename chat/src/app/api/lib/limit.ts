import { env } from "./db";

const hits = new Map<string, { n: number; reset: number }>();

export function limited(ip: string) {
  const now = Date.now();
  const h = hits.get(ip);
  if (!h || now > h.reset) {
    if (hits.size > 5000) hits.clear();
    hits.set(ip, { n: 1, reset: now + env.winMs });
    return false;
  }
  h.n++;
  return h.n > env.maxRate;
}

export function ipOf(req: Request) {
  const h = req.headers.get("x-forwarded-for") || "";
  if (h.length === 0) return "local";
  return h.split(",")[0].trim();
}

export function rateKey(req: Request, who: string) {
  return ipOf(req) + "|" + who;
}
