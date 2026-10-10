import C from "../../../fields.json";

export { C };

async function call(path: string, token: string, method: string, body?: unknown) {
  let r: Response;
  try {
    r = await fetch(path, {
      method,
      headers: { "content-type": "application/json", authorization: "Bearer " + token },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000)
    });
  } catch (e) {
    throw new Error("server unreachable") as Error & { status: number; db: boolean };
  }
  let j: any = null;
  try {
    j = await r.json();
  } catch (e) {
    j = null;
  }
  if (!r.ok) {
    const db = r.status >= 500;
    const e = new Error(db ? "database unreachable" : String((j && j.error) || "net fail " + r.status)) as Error & { status: number; db: boolean };
    e.status = r.status;
    e.db = db;
    throw e;
  }
  return j === null ? {} : j;
}

export function stream(token: string, onEvent: (e: Record<string, unknown>) => void, onDown: () => void): () => void {
  const ac = new AbortController();
  fetch("/api/v1/events", { headers: { authorization: "Bearer " + token }, signal: ac.signal })
    .then(async (r) => {
      if (!r.ok || !r.body) {
        onDown();
        return;
      }
      const rd = r.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const chunk = await rd.read();
        if (chunk.done) break;
        buf += dec.decode(chunk.value, { stream: true });
        let cut = buf.indexOf("\n\n");
        while (cut !== -1) {
          const frame = buf.slice(0, cut);
          buf = buf.slice(cut + 2);
          if (frame.startsWith("data: ")) {
            try {
              onEvent(JSON.parse(frame.slice(6)) as Record<string, unknown>);
            } catch (e) {}
          }
          cut = buf.indexOf("\n\n");
        }
      }
      onDown();
    })
    .catch(() => {
      if (!ac.signal.aborted) onDown();
    });
  return () => ac.abort();
}

export function ids() {
  return call("/api/v1/ids", "", "POST", {}) as Promise<{ who: string; tok: string }>;
}

export function publish(token: string, body: object) {
  return call("/api/v1/keys", token, "PUT", body);
}

export function bundle(token: string, who: string) {
  return call("/api/v1/keys/" + who, token, "GET") as Promise<Record<string, string | null>>;
}

export function postMsg(token: string, body: object) {
  return call("/api/v1/msgs", token, "POST", body) as Promise<{ ok: boolean }>;
}

export function getMsgs(token: string, rooms: string[], before?: string | null) {
  const q = "/api/v1/msgs?g=" + rooms.join(",") + (before ? "&before=" + before : "");
  return call(q, token, "GET") as Promise<{ msgs: any[]; more: boolean; cursor: string | null; full?: boolean }>;
}

export function newLink(token: string, gi: string) {
  return call("/api/v1/links", token, "POST", { gi }) as Promise<{ g: string }>;
}

export function postBlob(token: string, body: object) {
  return call("/api/v1/blobs", token, "POST", body);
}

export function getBlob(token: string, id: string) {
  return call("/api/v1/blobs/" + id, token, "GET") as Promise<{ id: string; data: string }>;
}

export function postReact(token: string, body: object) {
  return call("/api/v1/reacts", token, "POST", body);
}

export function dropReact(token: string, id: string, g: string) {
  return call("/api/v1/reacts?id=" + id + "&g=" + g, token, "DELETE");
}

export function getReacts(token: string, g: string) {
  return call("/api/v1/reacts?g=" + g, token, "GET") as Promise<{ reacts: any[] }>;
}

export function resolveInvite(token: string, code: string) {
  return call("/api/v1/invites/" + code, token, "GET") as Promise<{ g: string }>;
}

export function freshInvite(token: string, g: string) {
  return call("/api/v1/invites", token, "POST", { g }) as Promise<{ code: string }>;
}

export function getLink(token: string, g: string) {
  return call("/api/v1/links/" + g, token, "GET") as Promise<{ g: string; mm: string[]; sq: number; ep: number; inRoom: boolean; rk: string | null }>;
}

export function joinLink(token: string, g: string, code: string) {
  return call("/api/v1/links/" + g + "/join", token, "PUT", { code }) as Promise<{ ok: boolean; mm: string[]; sq: number; ep: number }>;
}

export function putGroupInfo(token: string, g: string, gi: string) {
  return call("/api/v1/links/" + g + "/key", token, "PUT", { gi });
}

export function putWelcome(token: string, g: string, w: string, wc: string) {
  return call("/api/v1/links/" + g + "/welcome", token, "PUT", { w, wc });
}

export function getWelcome(token: string, g: string) {
  return call("/api/v1/links/" + g + "/welcome", token, "GET") as Promise<{ wc: string }>;
}

export function dropWelcome(token: string, g: string) {
  return call("/api/v1/links/" + g + "/welcome", token, "DELETE");
}

export function pushCommit(token: string, g: string, ep: number, ct: string, sg: string, js: string, sh: string) {
  return call("/api/v1/links/" + g + "/commits", token, "PUT", { ep, ct, sg, js, sh });
}

export function pullCommits(token: string, g: string, from: number) {
  return call("/api/v1/links/" + g + "/commits?e=" + from, token, "GET") as Promise<{
    commits: { ep: number; ct: string; sg: string; js: string; sh: string }[];
  }>;
}

export function signal(token: string, link: string, kind: string, body: unknown, on = false) {
  return call("/api/v1/events", token, "POST", { link, kind, body, on });
}

export function online(token: string, rooms: string[]) {
  const q = rooms.join(",");
  return call("/api/v1/online?g=" + q, token, "GET") as Promise<{ on: string[] }>;
}

export function ice(token: string) {
  return call("/api/v1/ice", token, "GET") as Promise<{ ice: unknown; turn: boolean }>;
}

export function delLink(token: string, g: string) {
  return call("/api/v1/links/" + g, token, "DELETE", {}) as Promise<{ ok: boolean }>;
}

export function delMsg(token: string, id: string, g: string, sig: string) {
  const u = sig.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return call("/api/v1/msgs/" + id + "?g=" + g + "&sig=" + u, token, "DELETE") as Promise<{ ok: boolean }>;
}