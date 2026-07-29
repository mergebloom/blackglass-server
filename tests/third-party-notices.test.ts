import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");

describe("third-party notices", () => {
  test("are bound to the complete locked Rust dependency graph", async () => {
    const notices = await readFile(join(root, "THIRD_PARTY_NOTICES.md"), "utf8");
    const manifest = JSON.parse(
      await readFile(join(root, "third-party-notices.lock.json"), "utf8"),
    ) as Record<string, unknown>;
    const result = Bun.spawnSync(["bun", "run", "tools/third-party-notices.ts"], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    expect(result.stdout.toString()).toMatch(
      /^third-party notices verified: \d+ packages, \d+ license texts\n$/u,
    );
    expect(notices).toStartWith("# Blackglass Server third-party notices\n");
    expect(notices).not.toMatch(/^- blackglass-server /mu);
    expect(notices).not.toMatch(/&(?:amp|apos|gt|lt|quot);/u);
    expect(notices).not.toContain("\r");
    expect(notices).not.toMatch(/[ \t]+$/mu);
    expect(notices).toContain("# Native and language runtime notices\n");
    expect(notices).toContain("## Rust 1.92.0 standard library and runtime\n");
    expect(notices).toContain("## musl libc 1.2.5\n");
    expect(notices).toContain("## SQLite amalgamation\n");
    expect(Object.keys(manifest).sort()).toEqual([
      "cargoAboutVersion",
      "cargoLockSha256",
      "cargoManifestSha256",
      "configSha256",
      "generatorSha256",
      "licenseTexts",
      "nativeRuntimeNoticesSha256",
      "noticedPackages",
      "noticesSha256",
      "releaseDockerfileSha256",
      "rustToolchainSha256",
      "schemaVersion",
      "templateSha256",
    ].sort());
    expect(manifest.schemaVersion).toBe(2);
    expect((notices.match(/^----- BEGIN LICENSE TEXT -----$/gmu) ?? []).length)
      .toBeGreaterThan(0);
    expect((notices.match(/^----- BEGIN LICENSE TEXT -----$/gmu) ?? []).length)
      .toBe((notices.match(/^----- END LICENSE TEXT -----$/gmu) ?? []).length);
  });
});
