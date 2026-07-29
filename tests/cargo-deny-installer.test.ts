import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");

describe("cargo-deny installer", () => {
  test("pins and verifies the exact upstream binary before installation", async () => {
    const scriptPath = join(root, "ops/install-cargo-deny.sh");
    const script = await readFile(scriptPath, "utf8");
    const syntax = Bun.spawnSync(["sh", "-n", scriptPath], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(syntax.exitCode, syntax.stderr.toString()).toBe(0);
    expect(script).toContain("version=0.20.2");
    expect(script).toContain(
      "expected_sha256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f",
    );
    expect(script).toContain("--proto '=https'");
    expect(script).toContain("--max-filesize 6000000");
    expect(script).toContain("sha256sum -c -");
    expect(script).toContain("tar -tzf");
    expect(script).not.toMatch(/curl[^\n]*\|[^\n]*tar/u);
    expect(script).toContain('"$("$candidate" --version)" != "cargo-deny $version"');
  });
});
