import { Report } from "./support.ts";
import { treeMath, cryptoBasics, keySchedule, secretTree, deserialization, pskSecret } from "./primitives.ts";
import { treeValidation, treeOperations, welcome, passiveClientWelcome, handlingCommit, treekem, transcriptHashes, cipherSuites } from "./groups.ts";

const only = new Set(process.argv.slice(2));
const r = new Report();

const families: [string, () => Promise<void>][] = [
  ["cipher-suites", () => cipherSuites(r)],
  ["tree-math", () => treeMath(r)],
  ["crypto-basics", () => cryptoBasics(r)],
  ["key-schedule", () => keySchedule(r)],
  ["secret-tree", () => secretTree(r)],
  ["deserialization", () => deserialization(r)],
  ["psk_secret", () => pskSecret(r)],
  ["tree-validation", () => treeValidation(r)],
  ["tree-operations", () => treeOperations(r)],
  ["welcome", () => welcome(r)],
  ["passive-client-welcome", () => passiveClientWelcome(r)],
  ["transcript-hashes", () => transcriptHashes(r)],
  ["treekem", () => treekem(r)],
  ["passive-client-handling-commit", () => handlingCommit(r)],
];

process.stdout.write("\nchat. MLS test vectors\n\n");

let failed = 0;

for (const [name, run] of families) {
  if (only.size > 0 && !only.has(name)) continue;
  try {
    await run();
  } catch (e) {
    failed++;
    process.stdout.write("  " + name.padEnd(30) + "  threw: " + (e as Error).stack + "\n");
  }
}

process.stdout.write("\n");
process.exit(failed === 0 ? 0 : 1);