import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { URL, fileURLToPath } from "node:url";

export type EnvMap = Record<string, string | undefined>;

export type ParseOptions = {
  fast?: boolean;
};

export type ConfigOptions = {
  path?: string | string[] | URL;
  encoding?: string;
  quiet?: boolean;
  debug?: boolean;
  override?: boolean;
  fast?: boolean;
  processEnv?: EnvMap;
};

export type PopulateOptions = {
  debug?: boolean;
  override?: boolean;
};

export function parseBoolean(value: unknown): boolean {
  if (typeof value === "string") {
    return !["false", "0", "no", "off", ""].includes(value.toLowerCase());
  }
  return Boolean(value);
}

export function optionsFromEnv(env: EnvMap = process.env): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (const name of ["ENCODING", "PATH", "QUIET", "DEBUG", "OVERRIDE", "FAST"]) {
    const v = env["DOTENV_" + name] != null ? env["DOTENV_" + name] : env["DOTENV_CONFIG_" + name];
    if (v != null) {
      out[name.toLowerCase()] = name === "ENCODING" || name === "PATH" ? v as string : parseBoolean(v);
    }
  }
  return out;
}

const KEY_CHAR = new Uint8Array(256);
for (let i = 48; i <= 57; i++) KEY_CHAR[i] = 1;
for (let i = 65; i <= 90; i++) KEY_CHAR[i] = 1;
for (let i = 97; i <= 122; i++) KEY_CHAR[i] = 1;
KEY_CHAR[45] = 1;
KEY_CHAR[46] = 1;
KEY_CHAR[95] = 1;

function takeBlanks(s: string, i: number): number {
  while (i < s.length && (s[i] === " " || s[i] === "\t")) i++;
  return i;
}

function matchExport(s: string, i: number): number {
  if (s.startsWith("export", i)) {
    const j = takeBlanks(s, i + 6);
    if (j > i + 6 && j < s.length) return j;
  }
  return i;
}

function codeAt(s: string, i: number): number {
  return s.codePointAt(i) ?? 0;
}

function matchKey(s: string, i: number): number {
  const start = i;
  while (i < s.length && codeAt(s, i) < 256 && KEY_CHAR[codeAt(s, i)] === 1) i++;
  return i === start ? -1 : i;
}

function splitLine(line: string): { key: string; raw: string } | null {
  let i = takeBlanks(line, 0);
  if (i >= line.length || line[i] === "#") return null;
  i = matchExport(line, i);
  const keyEnd = matchKey(line, i);
  if (keyEnd === -1) return null;
  const key = line.slice(i, keyEnd);
  i = takeBlanks(line, keyEnd);
  if (i < line.length && line[i] === "=") {
    i = takeBlanks(line, i + 1);
    return { key, raw: line.slice(i) };
  }
  if (i < line.length && line[i] === ":") {
    if (i + 1 >= line.length || (line[i + 1] !== " " && line[i + 1] !== "\t")) return null;
    i = takeBlanks(line, i + 1);
    return { key, raw: line.slice(i) };
  }
  if (i >= line.length) return null;
  if (line[i] === "#") return { key, raw: "" };
  return null;
}

function unquote(raw: string): string {
  const first = raw[0];
  let close = -1;
  for (let i = 1; i < raw.length; i++) {
    if (raw[i] === "\\") {
      i++;
      continue;
    }
    if (raw[i] === first) {
      close = i;
      break;
    }
  }
  return close === -1 ? raw : raw.slice(1, close);
}

function stripComment(raw: string): string {
  const hash = raw.indexOf("#");
  return hash === -1 ? raw.trim() : raw.slice(0, hash).trim();
}

function decodeValue(raw: string): string {
  const text = raw.trim();
  const first = text[0];
  if (first === "'" || first === '"' || first === "`") {
    const inner = unquote(text);
    return first === '"' ? inner.replace(/\\n/g, "\n").replace(/\\r/g, "\r") : inner;
  }
  return stripComment(text);
}

function parseRegex(src: string | Buffer): Record<string, string> {
  const obj: Record<string, string> = {};
  const text = src.toString().replace(/\r\n?/mg, "\n");
  const lines = text.split("\n");
  for (const line of lines) {
    const parts = splitLine(line);
    if (!parts) continue;
    obj[parts.key] = decodeValue(parts.raw);
  }
  return obj;
}

function blank(c: number): boolean {
  if (c <= 32) return c === 32 || (c >= 9 && c <= 13);
  return c >= 160 && (c === 160 || c === 5760 || (c >= 8192 && c <= 8202) || c === 8232 || c === 8233 || c === 8239 || c === 8287 || c === 12288 || c === 65279);
}

function eol(c: number): boolean {
  return c === 10 || c === 8232 || c === 8233;
}

function skipBlanks(str: string, i: number): number {
  const len = str.length;
  while (i < len && blank(codeAt(str, i))) i++;
  return i;
}

function skipLine(str: string, i: number): number {
  const len = str.length;
  while (i < len && !eol(codeAt(str, i))) i++;
  return i;
}

function matchExportWord(str: string, i: number): number {
  const len = str.length;
  if (i + 6 >= len) return -1;
  if (codeAt(str, i) !== 101 || codeAt(str, i + 1) !== 120) return -1;
  if (codeAt(str, i + 2) !== 112 || codeAt(str, i + 3) !== 111) return -1;
  if (codeAt(str, i + 4) !== 114 || codeAt(str, i + 5) !== 116) return -1;
  if (!blank(codeAt(str, i + 6))) return -1;
  const next = skipBlanks(str, i + 7);
  if (!KEY_CHAR[codeAt(str, next)]) return -1;
  return next;
}

function readKey(str: string, i: number): number {
  const len = str.length;
  while (i < len && KEY_CHAR[codeAt(str, i)]) i++;
  return i;
}

function readQuoted(str: string, quoteStart: number): { value: string; i: number } | null {
  const len = str.length;
  const qc = str[quoteStart];
  let j = str.indexOf(qc, quoteStart + 1);
  let closeAt = -1;
  let closeEnd = -1;
  while (j !== -1) {
    const escaped = codeAt(str, j - 1) === 92;
    let end = j + 1;
    while (end < len && !eol(codeAt(str, end)) && blank(codeAt(str, end))) end++;
    if (end === len || eol(codeAt(str, end)) || codeAt(str, end) === 35) {
      closeAt = j;
      closeEnd = end;
    }
    if (!escaped) break;
    j = str.indexOf(qc, j + 1);
  }
  if (closeAt === -1) return null;
  let i = closeEnd;
  if (codeAt(str, i) === 35) i = skipLine(str, i);
  return { value: str.slice(quoteStart + 1, closeAt), i };
}

function hashAt(str: string, rawStart: number, nl: number): number {
  if (str.length < 4096) {
    const hash = str.indexOf("#", rawStart);
    if (hash === -1 || hash > nl) return nl;
    return hash;
  }
  let hash = rawStart;
  while (hash < nl && codeAt(str, hash) !== 35) hash++;
  return hash;
}

function trimSpan(str: string, rawStart: number, hash: number): { start: number; end: number } {
  let start = rawStart;
  let end = hash;
  while (start < end && blank(codeAt(str, start))) start++;
  while (end > start && blank(codeAt(str, end - 1))) end--;
  return { start, end };
}

function readUnquoted(str: string, rawStart: number): { value: string; i: number } {
  const len = str.length;
  let nl = str.indexOf("\n", rawStart);
  if (nl === -1) nl = len;
  const hash = hashAt(str, rawStart, nl);
  const span = trimSpan(str, rawStart, hash);
  const first = codeAt(str, span.start);
  const quotedEdge = span.end - span.start >= 2 && (first === 39 || first === 34 || first === 96) && codeAt(str, span.end - 1) === first;
  const value = quotedEdge ? str.slice(span.start + 1, span.end - 1) : str.slice(span.start, span.end);
  const i = hash < nl ? skipLine(str, hash) : hash;
  return { value, i };
}

type Keyed = { key: string; i: number; exportEnd: number };

function readKeyLine(str: string, from: number): Keyed | null {
  const len = str.length;
  let i = skipBlanks(str, from);
  if (i >= len) return null;
  if (codeAt(str, i) === 35) return { key: "", i: skipLine(str, i), exportEnd: -1 };
  const afterExport = matchExportWord(str, i);
  const exportEnd = afterExport === -1 ? -1 : i + 6;
  if (afterExport !== -1) i = afterExport;
  const keyStart = i;
  const keyEnd = readKey(str, i);
  if (keyEnd === keyStart) return { key: "", i: skipLine(str, i), exportEnd: -1 };
  const key = str.slice(keyStart, keyEnd);
  i = skipBlanks(str, keyEnd);
  const stop = i < len ? codeAt(str, i) : 0;
  if (stop === 61) return { key, i: i + 1, exportEnd };
  if (stop === 58 && i === keyEnd && i + 1 < len && blank(codeAt(str, i + 1))) return { key, i: i + 2, exportEnd };
  return { key: "", i: skipLine(str, exportEnd === -1 ? keyEnd : exportEnd), exportEnd: -1 };
}

function readValueAt(str: string, rawStart: number): { value: string; i: number } {
  const quoteStart = skipBlanks(str, rawStart);
  const quote = codeAt(str, quoteStart);
  if (quote === 39 || quote === 34 || quote === 96) {
    const q = readQuoted(str, quoteStart);
    if (q !== null) return { value: q.value, i: q.i };
  }
  return readUnquoted(str, rawStart);
}

function parseFast(src: string | Buffer): Record<string, string> {
  const obj: Record<string, string> = {};
  let str = typeof src === "string" ? src : src.toString();
  if (str.includes("\r")) str = str.replace(/\r\n?/g, "\n");
  const len = str.length;
  let i = 0;
  while (i < len) {
    const line = readKeyLine(str, i);
    if (line === null) break;
    i = line.i;
    if (line.key === "") continue;
    const read = readValueAt(str, i);
    i = read.i;
    const quoteStart = skipBlanks(str, line.i);
    if (codeAt(str, quoteStart) === 34 && read.value.includes("\\")) {
      obj[line.key] = read.value.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
    } else {
      obj[line.key] = read.value;
    }
  }
  return obj;
}

export function parse(src: string | Buffer, options?: ParseOptions): Record<string, string> {
  if (options && parseBoolean(options.fast)) return parseFast(src);
  return parseRegex(src);
}

function logDebug(message: string) {
  console.log("┆ " + message);
}

function logInfo(message: string) {
  console.error("◇ " + message);
}

function home(p: string) {
  return p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
}

function resolvePaths(o: ConfigOptions, fallback: string): (string | URL)[] {
  if (!o || !o.path) return [fallback];
  if (!Array.isArray(o.path)) return [typeof o.path === "string" ? home(o.path) : o.path];
  const out: (string | URL)[] = [];
  for (const f of o.path) out.push(typeof f === "string" ? home(f) : f);
  return out;
}

function displayName(f: string | URL): { name: string; error?: Error } {
  try {
    return { name: path.relative(process.cwd(), f instanceof URL ? fileURLToPath(f) : f) };
  } catch (e) {
    return { name: String(f), error: e as Error };
  }
}

export function configDotenv(options?: ConfigOptions): { parsed?: Record<string, string>; error?: Error } {
  const o: ConfigOptions = { ...optionsFromEnv(), ...options };
  const fallback = path.resolve(process.cwd(), ".env");
  let encoding = "utf8";
  let target: EnvMap = process.env;
  if (o && o.processEnv != null) target = o.processEnv;
  const debug = parseBoolean(o && o.debug);
  if (o && o.encoding) {
    encoding = o.encoding;
  } else if (debug) {
    logDebug("no encoding is specified (UTF-8 is used by default)");
  }
  const paths = resolvePaths(o, fallback);
  let lastError: Error | undefined;
  const parsedAll: Record<string, string> = {};
  const parseOptions = { fast: o.fast };
  for (const p of paths) {
    try {
      const loaded = parse(fs.readFileSync(p as string, { encoding: encoding as BufferEncoding }), parseOptions);
      populate(parsedAll, loaded, o);
    } catch (e) {
      if (debug) logDebug("failed to load " + String(p) + " " + (e as Error).message);
      lastError = e as Error;
    }
  }
  const done = populate(target, parsedAll, o);
  const quiet = parseBoolean(Object.prototype.hasOwnProperty.call(o, "quiet") ? o.quiet : optionsFromEnv(target).quiet);
  if (debug || !quiet) {
    const keysCount = Object.keys(done).length;
    const names: string[] = [];
    for (const f of paths) {
      const d = displayName(f);
      names.push(d.name);
      if (d.error) {
        if (debug) logDebug("failed to load " + String(f) + " " + d.error.message);
        lastError = d.error;
      }
    }
    logInfo("injected env (" + keysCount + ") from " + names.join(","));
  }
  if (lastError) return { parsed: parsedAll, error: lastError };
  return { parsed: parsedAll };
}

export function config(options?: ConfigOptions) {
  return configDotenv(options);
}

export function populate(target: EnvMap, source: EnvMap, options: PopulateOptions = {}): Record<string, string> {
  const debug = parseBoolean(options && options.debug);
  const override = parseBoolean(options && options.override);
  const out: Record<string, string> = {};
  if (target === null || typeof target !== "object" || source === null || typeof source !== "object") {
    const err = new Error("OBJECT_REQUIRED: Please check the processEnv argument being passed to populate") as Error & { code: string };
    err.code = "OBJECT_REQUIRED";
    throw err;
  }
  for (const key of Object.keys(source)) {
    if (Object.prototype.hasOwnProperty.call(target, key)) {
      if (override === true) {
        target[key] = source[key];
        out[key] = source[key] as string;
      }
      if (debug) {
        if (override === true) logDebug('"' + key + '" is already defined and WAS overwritten');
        else logDebug('"' + key + '" is already defined and was NOT overwritten');
      }
    } else {
      target[key] = source[key];
      out[key] = source[key] as string;
    }
  }
  return out;
}
