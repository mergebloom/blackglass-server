import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const verifier = join(root, "ops/verify-native-release-binary.sh");
const version = "1.2.3";
const sourceRevision = "a".repeat(40);

describe("native release binary attestation", () => {
  test("returns the hash only after exact version and build-info validation", async () => {
    const fixture = await createFixture();
    try {
      const result = verify(fixture.binary);
      expect(result.exitCode, result.stderr.toString()).toBe(0);
      expect(result.stdout.toString().trim()).toBe(
        createHash("sha256").update(await readFile(fixture.binary)).digest("hex"),
      );
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  });

  test("rejects every self-attestation mismatch", async () => {
    const cases: Array<[string, FixtureOptions, string]> = [
      ["CLI version", { cliVersion: "9.9.9" }, "version does not match"],
      ["build-info version", { buildVersion: "9.9.9" }, "build-info does not match"],
      ["source revision", { buildRevision: "b".repeat(40) }, "build-info does not match"],
      ["extra key", { extraBuildKey: true }, "build-info does not match"],
      ["duplicate key", { duplicateVersionKey: true }, "duplicate JSON paths"],
    ];
    for (const [label, options, message] of cases) {
      const fixture = await createFixture(options);
      try {
        const result = verify(fixture.binary);
        expect(result.exitCode, label).toBe(1);
        expect(result.stderr.toString(), label).toContain(message);
      } finally {
        await rm(fixture.directory, { recursive: true, force: true });
      }
    }
  });
});

interface FixtureOptions {
  buildRevision?: string;
  buildVersion?: string;
  cliVersion?: string;
  duplicateVersionKey?: boolean;
  extraBuildKey?: boolean;
}

async function createFixture(options: FixtureOptions = {}) {
  const directory = await mkdtemp(join(tmpdir(), "blackglass-native-binary-"));
  const binary = join(directory, "blackglass-server");
  const buildVersion = options.buildVersion ?? version;
  const buildRevision = options.buildRevision ?? sourceRevision;
  let buildInfo = JSON.stringify({
    name: "blackglass-server",
    sourceRevision: buildRevision,
    version: buildVersion,
    ...(options.extraBuildKey ? { extra: true } : {}),
  });
  if (options.duplicateVersionKey) {
    buildInfo = buildInfo.replace(
      `"version":"${buildVersion}"`,
      `"version":"9.9.9","version":"${buildVersion}"`,
    );
  }
  await writeFile(
    binary,
    `#!/bin/sh\ncase "\${1:-}" in\n  --version) printf '%s\\n' 'blackglass-server ${options.cliVersion ?? version}' ;;\n  build-info) printf '%s\\n' '${buildInfo}' ;;\n  *) exit 2 ;;\nesac\n`,
  );
  await chmod(binary, 0o755);
  return { binary, directory };
}

function verify(binary: string) {
  return Bun.spawnSync([verifier, binary, version, sourceRevision], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
}
