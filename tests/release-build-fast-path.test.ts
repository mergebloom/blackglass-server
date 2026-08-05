import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");

describe("release build fast paths", () => {
  test("checks release publication state before starting Docker", async () => {
    const script = await readFile(
      resolve(root, "ops/build-linux-release.sh"),
      "utf8",
    );
    const existingCheck = script.indexOf('existing=0');
    const dockerBuild = script.indexOf('docker buildx build');
    expect(existingCheck).toBeGreaterThan(0);
    expect(dockerBuild).toBeGreaterThan(existingCheck);
    expect(script).toContain("refusing a partial existing release artifact set");
    expect(script).toContain("release already ready:");
  });

  test("caches compiled Cargo outputs without publishing from the cache mount", async () => {
    const dockerfile = await readFile(
      resolve(root, "ops/Dockerfile.release"),
      "utf8",
    );
    expect(dockerfile).toContain(
      "id=blackglass-cargo-target-$TARGETARCH,target=/cargo-target,sharing=locked",
    );
    expect(dockerfile).toContain(
      "cp /cargo-target/release/blackglass-server /target/release/blackglass-server",
    );
    expect(dockerfile).toContain("CARGO_INCREMENTAL=0");
    expect(dockerfile).toContain('if test "$RUN_TESTS" = 1');
  });

  test("includes every compile-time UI asset in the release build context", async () => {
    const [dockerfile, dockerignore] = await Promise.all([
      readFile(resolve(root, "ops/Dockerfile.release"), "utf8"),
      readFile(resolve(root, ".dockerignore"), "utf8"),
    ]);

    for (const path of [
      "apps/server-rust/admin",
      "apps/server-rust/account",
      "assets/blackglass-prism.png",
    ]) {
      expect(dockerfile).toContain(`COPY ${path}`);
      expect(dockerignore).toContain(`!${path}`);
    }
  });

  test("reuses an already attested native binary unless forced", async () => {
    const script = await readFile(resolve(root, "ops/build-release.sh"), "utf8");
    expect(script).toContain('BLACKGLASS_FORCE_REBUILD:-0');
    expect(script).toContain("rebuilding stale native release binary:");
    expect(script).toContain("BLACKGLASS_FORCE_REBUILD must be 0 or 1");
    expect(script).toContain('build_target_directory="$target_directory/native-release-cache"');
    expect(script).toContain('test ! -L "$build_target_directory"');
    expect(script.indexOf("native release already ready:")).toBeLessThan(
      script.indexOf('cargo test --locked'),
    );
  });

  test("skips duplicate unit tests only for an exact tested source revision", async () => {
    for (const name of ["ops/build-release.sh", "ops/build-linux-release.sh"]) {
      const script = await readFile(resolve(root, name), "utf8");
      expect(script).toContain("BLACKGLASS_TESTED_SOURCE_REVISION");
      expect(script).toContain("does not match the release source");
    }
  });
});
