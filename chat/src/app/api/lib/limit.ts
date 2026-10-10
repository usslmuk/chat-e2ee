import { env } from "./db";

type Bucket = { tokens: number; last: number };

const buckets = new Map<string, Bucket>();

export function limited(ip: string) {
  const now = Date.now();
  let b = buckets.get(ip);
  if (!b) {
    if (buckets.size > 20000) evict(now);
    buckets.set(ip, { tokens: env.maxRate, last: now });
    return false;
  }
  const refill = ((now - b.last) / env.winMs) * env.maxRate;
  b.tokens = Math.min(env.maxRate, b.tokens + refill);
  b.last = now;
  if (b.tokens < 1) return true;
  b.tokens -= 1;
  return false;
}

function evict(now: number) {
  const stale = now - env.winMs * 2;
  for (const [k, v] of buckets) {
    if (v.last < stale) buckets.delete(k);
  }
  if (buckets.size > 20000) buckets.clear();
}

export function ipOf(req: Request) {
  const h = req.headers.get("x-forwarded-for") || "";
  if (h.length === 0) return "local";
  return h.split(",")[0].trim();
}

export function rateKey(req: Request, who: string) {
  return ipOf(req) + "|" + who;
}