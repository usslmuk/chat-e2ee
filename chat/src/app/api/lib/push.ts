type Sub = (payload: string) => void;

const g = globalThis as Record<string, unknown>;

type Hub = { subs: Map<string, Set<Sub>> };

function hub(): Hub {
  if (!g.__chatHub) g.__chatHub = { subs: new Map<string, Set<Sub>>() } as Hub;
  return g.__chatHub as Hub;
}

export function addSub(who: string, fn: Sub): () => void {
  const h = hub();
  const cur = h.subs.get(who) || new Set<Sub>();
  const was = cur.size > 0;
  cur.add(fn);
  h.subs.set(who, cur);
  if (!was) shout({ type: "presence" });
  return () => {
    const set = h.subs.get(who);
    if (!set) return;
    set.delete(fn);
    if (set.size === 0) {
      h.subs.delete(who);
      shout({ type: "presence" });
    }
  };
}

function shout(payload: object): void {
  const line = "data: " + JSON.stringify(payload) + "\n\n";
  for (const set of hub().subs.values()) {
    for (const fn of set) {
      try {
        fn(line);
      } catch (e) {}
    }
  }
}

export function online(): string[] {
  return Array.from(hub().subs.keys());
}

export function sendTo(who: string, payload: string): boolean {
  const set = hub().subs.get(who);
  if (!set) return false;
  let ok = false;
  for (const fn of set) {
    try {
      fn(payload);
      ok = true;
    } catch (e) {}
  }
  return ok;
}

export function tell(members: string[], from: string, payload: object): void {
  const line = "data: " + JSON.stringify(payload) + "\n\n";
  for (const who of members) {
    if (who === from) continue;
    sendTo(who, line);
  }
}