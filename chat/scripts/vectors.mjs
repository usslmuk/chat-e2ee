import { build } from "esbuild";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const out = join(process.cwd(), ".vectors", "run.mjs");
rmSync(out, { force: true });

await build({
  entryPoints: ["vectors/run.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  outfile: out,
  logLevel: "error",
});

const args = process.argv.slice(2);
const done = spawnSync(process.execPath, [out, ...args], { stdio: "inherit" });
rmSync(out, { force: true });
process.exit(done.status ?? 1);