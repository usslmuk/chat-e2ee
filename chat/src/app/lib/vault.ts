const DB = "chat.vault";
const STORE = "kv";
const VERSION = 1;

const mem = new Map<string, unknown>();
let db: IDBDatabase | null = null;
let opening: Promise<IDBDatabase | null> | null = null;
let loaded = false;

function open(): Promise<IDBDatabase | null> {
  if (db) return Promise.resolve(db);
  if (opening) return opening;
  opening = new Promise<IDBDatabase | null>((resolve) => {
    let req: IDBOpenDBRequest;
    try {
      req = indexedDB.open(DB, VERSION);
    } catch {
      resolve(null);
      return;
    }
    req.onupgradeneeded = () => {
      const d = req.result;
      if (!d.objectStoreNames.contains(STORE)) d.createObjectStore(STORE);
    };
    req.onsuccess = () => {
      db = req.result;
      resolve(db);
    };
    req.onerror = () => resolve(null);
    req.onblocked = () => resolve(null);
  });
  return opening;
}

export async function ready(): Promise<void> {
  if (loaded) return;
  const d = await open();
  if (!d) {
    loaded = true;
    return;
  }
  await new Promise<void>((resolve) => {
    let req: IDBRequest;
    try {
      req = d.transaction(STORE, "readonly").objectStore(STORE).getAllKeys();
    } catch {
      resolve();
      return;
    }
    req.onsuccess = () => {
      const keys = (req.result || []) as IDBValidKey[];
      if (keys.length === 0) {
        resolve();
        return;
      }
      let tx: IDBTransaction;
      try {
        tx = d.transaction(STORE, "readonly");
      } catch {
        resolve();
        return;
      }
      const store = tx.objectStore(STORE);
      for (const k of keys) {
        const g = store.get(k as string);
        g.onsuccess = () => {
          if (g.result !== undefined) mem.set(String(k), g.result);
        };
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
      tx.onabort = () => resolve();
    };
    req.onerror = () => resolve();
  });
  loaded = true;
}

function put(k: string, v: unknown): void {
  const d = db;
  if (!d) return;
  try {
    d.transaction(STORE, "readwrite").objectStore(STORE).put(v, k);
  } catch {
    return;
  }
}

export function get<T>(k: string): T | null {
  const v = mem.get(k);
  return v === undefined ? null : (v as T);
}

export function set(k: string, v: unknown): void {
  mem.set(k, v);
  put(k, v);
}

export function del(k: string): void {
  mem.delete(k);
  const d = db;
  if (!d) return;
  try {
    d.transaction(STORE, "readwrite").objectStore(STORE).delete(k);
  } catch {
    return;
  }
}

export function keys(): string[] {
  return [...mem.keys()];
}

export async function wipe(): Promise<void> {
  for (const k of [...mem.keys()]) del(k);
  const d = await open();
  if (!d) return;
  await new Promise<void>((resolve) => {
    let req: IDBRequest;
    try {
      req = d.transaction(STORE, "readwrite").objectStore(STORE).clear();
    } catch {
      resolve();
      return;
    }
    req.onsuccess = () => resolve();
    req.onerror = () => resolve();
  });
}