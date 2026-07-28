import { describe, expect, test } from "bun:test";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const verifier = join(root, "ops/verify-release-metadata.sh");
const currentVersion = JSON.parse(
  await readFile(join(root, "package.json"), "utf8"),
).version as string;
const mismatchedVersion = currentVersion === "999.999.999" ? "999.999.998" : "999.999.999";
const metadataFiles = [
  "package.json",
  "package-lock.json",
  "apps/server-rust/Cargo.toml",
  "apps/server-rust/Cargo.lock",
];

describe("release metadata consistency", () => {
  test("the checked-in package and lockfile versions match", () => {
    const result = verify(root);
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    expect(result.stdout.toString()).toContain(
      `release metadata verified: blackglass-server ${currentVersion}`,
    );
  });

  for (const mismatch of [
    "package.json",
    "package-lock.json",
    "apps/server-rust/Cargo.toml",
    "apps/server-rust/Cargo.lock",
  ]) {
    test(`rejects a version mismatch in ${mismatch}`, async () => {
      const fixture = await copyMetadataFixture();
      try {
        const path = join(fixture, mismatch);
        if (mismatch.endsWith(".json")) {
          const value = JSON.parse(await readFile(path, "utf8"));
          value.version = mismatchedVersion;
          if (mismatch === "package-lock.json") {
            value.packages[""].version = mismatchedVersion;
          }
          await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
        } else if (mismatch.endsWith("Cargo.toml")) {
          const value = await readFile(path, "utf8");
          await writeFile(
            path,
            value.replace(
              `version = "${currentVersion}"`,
              `version = "${mismatchedVersion}"`,
            ),
          );
        } else {
          const value = await readFile(path, "utf8");
          await writeFile(
            path,
            value.replace(
              `name = "blackglass-server"\nversion = "${currentVersion}"`,
              `name = "blackglass-server"\nversion = "${mismatchedVersion}"`,
            ),
          );
        }

        const result = verify(fixture);
        expect(result.exitCode).toBe(1);
        expect(result.stderr.toString()).toContain("release versions do not match");
      } finally {
        await rm(fixture, { recursive: true, force: true });
      }
    });
  }

  test("rejects disagreement inside package-lock.json", async () => {
    const fixture = await copyMetadataFixture();
    try {
      const path = join(fixture, "package-lock.json");
      const value = JSON.parse(await readFile(path, "utf8"));
      value.packages[""].version = mismatchedVersion;
      await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);

      const result = verify(fixture);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain(
        "invalid root package-lock.json release metadata",
      );
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });
});

function verify(projectRoot: string) {
  return Bun.spawnSync([verifier, projectRoot], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
}

async function copyMetadataFixture(): Promise<string> {
  const fixture = await mkdtemp(join(tmpdir(), "blackglass-release-metadata-"));
  for (const relativePath of metadataFiles) {
    const destination = join(fixture, relativePath);
    await mkdir(dirname(destination), { recursive: true });
    await cp(join(root, relativePath), destination, { recursive: false });
  }
  return fixture;
}
