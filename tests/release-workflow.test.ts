import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const workflow = readFileSync(
  resolve(import.meta.dir, "../.github/workflows/release.yml"),
  "utf8",
);

describe("release workflow source binding", () => {
  test("can recover an existing immutable tag without rebuilding another revision", () => {
    expect(workflow).toContain("release_tag:");
    expect(workflow.match(/ref: \$\{\{ env\.CHECKOUT_REF \}\}/gu)?.length).toBe(3);
    expect(workflow.match(/Bind exact immutable release source/gu)?.length).toBe(3);
    expect(workflow).toContain('test "$(git rev-parse --verify "${release_tag}^{commit}")" = "$source_revision"');
    expect(workflow).toContain("BLACKGLASS_TESTED_SOURCE_REVISION=\"$SOURCE_REVISION\"");
    expect(workflow).toContain("BLACKGLASS_EXPECTED_SOURCE_REVISION=\"$SOURCE_REVISION\"");
    expect(workflow).toContain('--arg revision "$SOURCE_REVISION"');
    expect(workflow).toContain('GITHUB_SHA="$SOURCE_REVISION" bash ops/publish-release.sh');
    expect(workflow).not.toContain('BLACKGLASS_TESTED_SOURCE_REVISION="$GITHUB_SHA"');
    expect(workflow).not.toContain('BLACKGLASS_EXPECTED_SOURCE_REVISION="$GITHUB_SHA"');
  });

  test("uses an explicit portable ShellCheck severity gate", () => {
    expect(workflow).toContain("shellcheck --severity=warning ops/*.sh");
  });
});
