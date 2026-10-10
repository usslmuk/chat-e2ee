import { addSub, sendTo, tell } from "../../lib/push";
import { authed, deny, throttled } from "../../lib/auth";
import { getDb } from "../../lib/db";
import C from "../../../../../fields.json";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const KINDS = new Set(["offer", "answer", "ice", "typing", "bye"]);

type Ctx = { who: string; body: Record<string, unknown>; link: string; mm: string[] };

async function ctx(req: Request): Promise<Ctx | Response> {
  const me = await authed(req);
  if (!me) return deny();
  const b = await req.json().catch(() => null);
  if (!b || typeof b !== "object") return Response.json({ error: "bad" }, { status: 400 });
  const link = String(b.link || "");
  if (!/^[0-9a-f]{16,64}$/.test(link)) return Response.json({ error: "bad" }, { status: 400 });
  const db = await getDb();
  const row = await db.collection("grps").findOne({ [C.grps.g]: link });
  if (!row) return Response.json({ error: "bad" }, { status: 404 });
  const mm: string[] = Array.isArray(row[C.grps.mm]) ? row[C.grps.mm].map((x: unknown) => String(x)) : [];
  if (!mm.includes(me.who)) return Response.json({ error: "bad" }, { status: 403 });
  return { who: me.who, body: b, link, mm };
}

function bad(): Response {
  return Response.json({ error: "bad" }, { status: 400 });
}

export async function GET(req: Request) {
  const me = await authed(req);
  if (!me) return deny();

  const who = me.who;
  const enc = new TextEncoder();
  let drop: (() => void) | null = null;
  let beat: ReturnType<typeof setInterval> | null = null;

  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      const push = (line: string) => {
        try {
          c.enqueue(enc.encode(line));
        } catch (e) {}
      };
      drop = addSub(who, push);
      push("data: " + JSON.stringify({ type: "ready" }) + "\n\n");
      beat = setInterval(() => push(": beat\n\n"), 20000);
    },
    cancel() {
      if (beat) clearInterval(beat);
      if (drop) drop();
      drop = null;
      beat = null;
    }
  });

  req.signal.addEventListener("abort", () => {
    if (beat) clearInterval(beat);
    if (drop) drop();
    drop = null;
    beat = null;
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no"
    }
  });
}

export async function POST(req: Request) {
  const slow = throttled(req);
  if (slow) return slow;
  const c = await ctx(req);
  if (c instanceof Response) return c;
  const b = c.body;
  const from = c.who;
  const kind = String(b.kind || "");
  if (!KINDS.has(kind)) return bad();
  if (kind === "typing" && typeof b.on !== "boolean") return bad();
  const body = b.body ?? null;
  const raw = body === null ? "" : JSON.stringify(body);
  if (kind !== "typing" && raw.length > 32768) return bad();
  const line =
    "data: " +
    JSON.stringify({ type: "sig", from, link: c.link, kind, body, on: b.on === true }) +
    "\n\n";
  for (const other of c.mm) {
    if (other === from) continue;
    sendTo(other, line);
  }
  return Response.json({ ok: true });
}

export async function PUT(req: Request) {
  const c = await ctx(req);
  if (c instanceof Response) return c;
  tell(c.mm, c.who, { type: "wake", link: c.link });
  return Response.json({ ok: true });
}