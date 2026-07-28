import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const validator = join(root, "ops/release-version.sh");

const validVersions = [
  "0.0.0",
  "1.2.3",
  "10.20.30-alpha",
  "1.2.3-alpha.1",
  "1.2.3-0",
  "1.2.3-1",
  "1.2.3-000a",
  "1.2.3-ALPHA.beta",
  "1.2.3-rc.10-x",
];

const invalidVersions = [
  "01.2.3",
  "1.02.3",
  "1.2.03",
  "1.2.3-alpha..1",
  "1.2.3-alpha.",
  "1.2.3-.alpha",
  "1.2.3-01",
  "1.2.3-alpha.01",
  "1.2.3+build.1",
  "1.2.3-alpha+build.1",
  "1.2.3\n2.3.4",
  "1.2.3 ",
  "v1.2.3",
];

describe("supported release versions", () => {
  for (const version of validVersions) {
    test(`accepts ${version}`, () => {
      expect(validate(version)).toBe(0);
    });
  }

  for (const version of invalidVersions) {
    test(`rejects ${version}`, () => {
      expect(validate(version)).not.toBe(0);
    });
  }

  test("all publishing entrypoints reject malformed versions before external access", () => {
    const cases: Array<[string, string[]]> = [
      ["publish-release.sh", ["v1.2.3-alpha..1", "title", "missing-asset"]],
      ["publish-oci-version.sh", ["1.2.3-alpha..1", "ghcr.io/example/repo", "0".repeat(40), "missing-assets"]],
      ["promote-oci-latest.sh", ["1.2.3-alpha..1", "ghcr.io/example/repo", `sha256:${"0".repeat(64)}`]],
    ];
    for (const [script, args] of cases) {
      const result = Bun.spawnSync([join(root, "ops", script), ...args], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(result.exitCode, `${script}: ${result.stderr.toString()}`).toBe(1);
      expect(result.stderr.toString()).toMatch(/semantic version|invalid image version/);
    }
  });

  test("accepts only v-prefixed supported release tags", () => {
    expect(validateTag("v1.2.3")).toBe(0);
    expect(validateTag("v1.2.3-alpha.1")).toBe(0);
    expect(validateTag("1.2.3")).not.toBe(0);
    expect(validateTag("vv1.2.3")).not.toBe(0);
    expect(validateTag("v01.2.3")).not.toBe(0);
    expect(validateTag("v1.2.3+build.1")).not.toBe(0);
  });

  test("the archive verifier rejects a malformed embedded version", async () => {
    const directory = await mkdtemp(join(tmpdir(), "blackglass-semver-"));
    try {
      const archive = join(directory, "blackglass-server-v01.2.3-linux-amd64.tar.gz");
      await writeFile(archive, "not an archive");
      await writeFile(`${archive}.sha256`, `unused  ${basename(archive)}\n`);
      const result = Bun.spawnSync([
        join(root, "ops/verify-linux-release.sh"),
        "linux-amd64",
        archive,
      ], { cwd: root, stdout: "pipe", stderr: "pipe" });
      expect(result.exitCode, result.stderr.toString()).toBe(1);
      expect(result.stderr.toString()).toContain("unsupported release version");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

function validate(version: string): number {
  return Bun.spawnSync([
    "/bin/sh",
    "-c",
    '. "$1"; blackglass_is_supported_release_version "$2"',
    "blackglass-release-version-test",
    validator,
    version,
  ], { cwd: root, stdout: "pipe", stderr: "pipe" }).exitCode;
}

function validateTag(tag: string): number {
  return Bun.spawnSync([
    "/bin/sh",
    "-c",
    '. "$1"; blackglass_is_supported_release_tag "$2"',
    "blackglass-release-tag-test",
    validator,
    tag,
  ], { cwd: root, stdout: "pipe", stderr: "pipe" }).exitCode;
}
