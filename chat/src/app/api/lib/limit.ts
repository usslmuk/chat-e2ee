import { env } from "./db";

type Bucket = { tokens: number; last: number };

const buckets = new Map<string, Bucket>();
const MAX_BUCKETS = 20000;

export function limited(ip: string) {
  const now = Date.now();
  let b = buckets.get(ip);
  if (!b) {
    if (buckets.size >= MAX_BUCKETS) evict(now);
    if (buckets.size >= MAX_BUCKETS) return true;
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
}

export function ipOf(req: Request) {
  const direct = req.headers.get("x-real-ip");
  if (direct) return direct.trim();
  const fwd = req.headers.get("x-forwarded-for") || "";
  if (!fwd) return "local";
  const parts = fwd.split(",").map((x) => x.trim()).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : "local";
}

export function rateKey(req: Request, who: string) {
  return ipOf(req) + "|" + who;
}