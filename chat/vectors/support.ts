import { mkdirSync, readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";

const SOURCE = "https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors";
const CACHE = join(process.cwd(), ".vectors");

export async function load(name: string): Promise<any[]> {
  mkdirSync(CACHE, { recursive: true });
  const file = join(CACHE, name + ".json");
  if (!existsSync(file)) {
    process.stdout.write("  fetching " + name + "\n");
    const res = await fetch(SOURCE + "/" + name + ".json");
    if (!res.ok) throw new Error("cannot fetch " + name + ": " + res.status);
    writeFileSync(file, Buffer.from(await res.arrayBuffer()));
  }
  return JSON.parse(readFileSync(file, "utf8"));
}

export function suite(name: string, id = 1): any[] {
  return load(name).then((all) => all.filter((x) => x.cipher_suite === undefined || x.cipher_suite === id));
}

export const hex = (s: string): Uint8Array => {
  if (typeof s !== "string" || s.length % 2 !== 0 || /[^0-9a-f]/.test(s)) throw new Error("bad hex");
  return Uint8Array.from(Buffer.from(s, "hex"));
};

export const show = (b: Uint8Array): string => Buffer.from(b).toString("hex");

export const same = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

export const opt = (v: Uint8Array | null): Uint8Array => v ?? new Uint8Array(0);

export class Report {
  private pass = 0;
  private fail = 0;
  private lines: string[] = [];
  private tally = new Map<string, number>();

  check(what: string, ok: boolean, note = ""): boolean {
    if (ok) this.pass++;
    else {
      this.fail++;
      this.tally.set(what, (this.tally.get(what) ?? 0) + 1);
      if (this.lines.length < 6) this.lines.push("    FAIL " + what + (note ? "  " + note : ""));
    }
    return ok;
  }

  equal(what: string, got: Uint8Array, want: string): boolean {
    const w = hex(want);
    return this.check(what, same(got, w), got.length !== w.length ? "length " + got.length + " want " + w.length : show(got).slice(0, 32) + " want " + want.slice(0, 32));
  }

  family(name: string, note = ""): void {
    const status = this.fail === 0 ? "pass" : this.fail + " failed";
    process.stdout.write("  " + name.padEnd(30) + String(this.pass).padStart(6) + " passed  " + status.padEnd(10) + note + "\n");
    for (const l of this.lines) process.stdout.write(l + "\n");
    if (this.lines.length > 6) process.stdout.write("    ... " + (this.fail - 6) + " more\n");
    for (const [what, count] of [...this.tally.entries()].sort((a, b) => b[1] - a[1])) {
      process.stdout.write("      " + String(count).padStart(4) + "  " + what + "\n");
    }
    this.pass = 0;
    this.fail = 0;
    this.lines = [];
    this.tally.clear();
  }
}