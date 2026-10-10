import fs from "fs";
import path from "path";
import os from "os";
import { URL, fileURLToPath } from "url";

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

const LINE = /^[ \t]*(?:export[ \t]+)?([\w.-]+)(?:[ \t]*=[ \t]*|:[ \t]+)?((?:'(?:[^'\\]|\\[\s\S])*'|"(?:[^"\\]|\\[\s\S])*"|`(?:[^`\\]|\\[\s\S])*`|[^#\r\n]*)?)[ \t]*(?:#.*)?$/gm;

const KEY_CHAR = new Uint8Array(256);
for (let i = 48; i <= 57; i++) KEY_CHAR[i] = 1;
for (let i = 65; i <= 90; i++) KEY_CHAR[i] = 1;
for (let i = 97; i <= 122; i++) KEY_CHAR[i] = 1;
KEY_CHAR[45] = 1;
KEY_CHAR[46] = 1;
KEY_CHAR[95] = 1;

function parseRegex(src: string | Buffer): Record<string, string> {
  const obj: Record<string, string> = {};
  let text = src.toString();
  text = text.replace(/\r\n?/mg, "\n");
  let m: RegExpExecArray | null;
  while ((m = LINE.exec(text)) != null) {
    const key = m[1];
    let value = m[2] || "";
    value = value.trim();
    const q = value[0];
    value = value.replace(/^(['"`])([\s\S]*)\1$/mg, "$2");
    if (q === '"') {
      value = value.replace(/\\n/g, "\n");
      value = value.replace(/\\r/g, "\r");
    }
    obj[key] = value;
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

function parseFast(src: string | Buffer): Record<string, string> {
  const obj: Record<string, string> = {};
  let str = typeof src === "string" ? src : src.toString();
  if (str.indexOf("\r") !== -1) str = str.replace(/\r\n?/g, "\n");
  const len = str.length;
  let i = 0;
  while (i < len) {
    let c = str.charCodeAt(i);
    while (i < len && blank(c)) {
      i++;
      c = str.charCodeAt(i);
    }
    if (i >= len) break;
    if (c === 35) {
      while (i < len && !eol(str.charCodeAt(i))) i++;
      continue;
    }
    let exportEnd = -1;
    if (c === 101 && i + 6 < len &&
      str.charCodeAt(i + 1) === 120 &&
      str.charCodeAt(i + 2) === 112 &&
      str.charCodeAt(i + 3) === 111 &&
      str.charCodeAt(i + 4) === 114 &&
      str.charCodeAt(i + 5) === 116) {
      const nc = str.charCodeAt(i + 6);
      if (blank(nc)) {
        let next = i + 7;
        while (next < len && blank(str.charCodeAt(next))) next++;
        if (KEY_CHAR[str.charCodeAt(next)]) {
          exportEnd = i + 6;
          i = next;
        }
      } else {
        c = str.charCodeAt(i);
      }
    }
    const keyStart = i;
    let stop = 0;
    while (i < len) {
      stop = str.charCodeAt(i);
      if (KEY_CHAR[stop]) i++;
      else break;
    }
    if (i === keyStart) {
      while (i < len && !eol(str.charCodeAt(i))) i++;
      continue;
    }
    const key = str.slice(keyStart, i);
    const keyEnd = i;
    if (i >= len) stop = 0;
    if (blank(stop)) {
      do {
        i++;
        stop = i < len ? str.charCodeAt(i) : 0;
      } while (blank(stop));
    }
    if (stop === 61) {
      i++;
    } else if (stop === 58 && i === keyEnd && i + 1 < len && blank(str.charCodeAt(i + 1))) {
      i += 2;
    } else {
      i = exportEnd === -1 ? keyEnd : exportEnd;
      while (i < len && !eol(str.charCodeAt(i))) i++;
      continue;
    }
    const rawStart = i;
    let quoteStart = i;
    while (quoteStart < len && blank(str.charCodeAt(quoteStart))) quoteStart++;
    const quote = str.charCodeAt(quoteStart);
    let value = "";
    let quoted = false;
    if (quote === 39 || quote === 34 || quote === 96) {
      const qc = str[quoteStart];
      let j = str.indexOf(qc, quoteStart + 1);
      let closeAt = -1;
      let closeEnd = -1;
      while (j !== -1) {
        const escaped = str.charCodeAt(j - 1) === 92;
        let end = j + 1;
        while (end < len && !eol(str.charCodeAt(end)) && blank(str.charCodeAt(end))) end++;
        if (end === len || eol(str.charCodeAt(end)) || str.charCodeAt(end) === 35) {
          closeAt = j;
          closeEnd = end;
        }
        if (!escaped) break;
        j = str.indexOf(qc, j + 1);
      }
      if (closeAt !== -1) {
        value = str.slice(quoteStart + 1, closeAt);
        i = closeEnd;
        if (str.charCodeAt(i) === 35) {
          while (i < len && !eol(str.charCodeAt(i))) i++;
        }
        quoted = true;
      }
    }
    if (!quoted) {
      let nl = str.indexOf("\n", rawStart);
      if (nl === -1) nl = len;
      let hash: number;
      if (len < 4096) {
        hash = str.indexOf("#", rawStart);
        if (hash === -1 || hash > nl) hash = nl;
      } else {
        hash = rawStart;
        while (hash < nl && str.charCodeAt(hash) !== 35) hash++;
      }
      let start = rawStart;
      let end = hash;
      while (start < end && blank(str.charCodeAt(start))) start++;
      while (end > start && blank(str.charCodeAt(end - 1))) end--;
      const first = str.charCodeAt(start);
      if (end - start >= 2 && (first === 39 || first === 34 || first === 96) && str.charCodeAt(end - 1) === first) {
        value = str.slice(start + 1, end - 1);
      } else {
        value = str.slice(start, end);
      }
      i = hash;
      if (hash < nl) {
        while (i < len && !eol(str.charCodeAt(i))) i++;
      }
    }
    if (quote === 34 && (quoted || quoteStart < i) && value.indexOf("\\") !== -1) {
      value = value.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
    }
    obj[key] = value;
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
  return p[0] === "~" ? path.join(os.homedir(), p.slice(1)) : p;
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
  let paths: (string | URL)[] = [fallback];
  if (o && o.path) {
    if (!Array.isArray(o.path)) {
      paths = [typeof o.path === "string" ? home(o.path) : o.path];
    } else {
      paths = [];
      for (const f of o.path) paths.push(typeof f === "string" ? home(f) : f);
    }
  }
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
      try {
        names.push(path.relative(process.cwd(), f instanceof URL ? fileURLToPath(f) : f));
      } catch (e) {
        if (debug) logDebug("failed to load " + String(f) + " " + (e as Error).message);
        lastError = e as Error;
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
