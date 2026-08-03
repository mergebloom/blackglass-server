import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const privateName = ["bea", "ini"].join("");
const privateDomain = ["mkna", "ca"].join(".");
const patterns = [
  new RegExp(privateName, "iu"),
  new RegExp(`(?:[a-z0-9-]+\\.)*${privateDomain.replace(".", "\\.")}`, "iu"),
  /\/Users\/m\/Software\//u,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  /\bgh[oprsu]_[A-Za-z0-9]{30,}\b/u,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/u,
];
const artifactPath = /(?:^|\/)\S+\.(?:asar|dmg|pkg)(?:$|\/)|(?:^|\/)\S+\.app(?:$|\/)/iu;
const failures: string[] = [];
const files = git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
  .split("\0").filter(Boolean).sort();
for (const path of files) {
  if (artifactPath.test(path)) failures.push(`${path}: proprietary client artifact path`);
  const bytes = await readFile(resolve(root, path));
  if (!bytes.includes(0)) inspect(path, bytes.toString("utf8"));
}
inspect("reachable Git history", git(["log", "--all", "--format=fuller", "-p", "--text"]));
if (failures.length !== 0) throw new Error(`Distribution boundary violations:\n${failures.join("\n")}`);
console.log("distribution boundary verified");

function inspect(label: string, text: string): void {
  for (const pattern of patterns) {
    if (pattern.test(text)) failures.push(`${label}: private identifier or secret pattern`);
  }
}

function git(args: string[]): string {
  const result = Bun.spawnSync(["git", "-C", root, ...args], { stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) throw new Error(result.stderr.toString().trim());
  return result.stdout.toString();
}
