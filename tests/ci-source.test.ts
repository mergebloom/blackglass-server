import { afterEach, describe, expect, test } from "bun:test";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dir, "..");
const prepareScript = join(root, "ops/prepare-ci-source.sh");
const scannerPath = join(root, "tools/distribution-boundary.ts");
const directories: string[] = [];
const ciEmail = "blackglass-ci@users.noreply.github.com";
type Environment = Record<string, string>;
type Fixture = { directory: string; repository: string; initial: string };

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) =>
    rm(directory, { recursive: true, force: true })));
});

describe("CI source preparation", () => {
  test("merges divergent PR and base trees without changing original commits or refs", async () => {
    const fixture = await createFixture();
    const { head, base } = await diverge(fixture);
    const originalHead = git(fixture.repository, ["cat-file", "commit", head]);
    const originalBase = git(fixture.repository, ["cat-file", "commit", base]);
    const originalRefs = git(fixture.repository, ["show-ref"]);
    git(fixture.repository, ["config", "user.email", "ambient@example.test"]);
    const result = prepare(fixture.repository, head, base, {
      GIT_AUTHOR_EMAIL: await privateFixtureEmail(),
      GIT_COMMITTER_EMAIL: await privateFixtureEmail(),
    });
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    const merged = git(fixture.repository, ["rev-parse", "HEAD"]);
    expect(merged).not.toBe(head);
    expect(git(fixture.repository, ["show", "-s", "--format=%P", merged])).toBe(`${head} ${base}`);
    expect(await readFile(join(fixture.repository, "head.txt"), "utf8")).toBe("PR content\n");
    expect(await readFile(join(fixture.repository, "base.txt"), "utf8")).toBe("base content\n");
    expect(git(fixture.repository, ["cat-file", "commit", head]) === originalHead).toBe(true);
    expect(git(fixture.repository, ["cat-file", "commit", base]) === originalBase).toBe(true);
    expect(git(fixture.repository, ["show-ref"])).toBe(originalRefs);
    expect(git(fixture.repository, ["show", "-s", "--format=%ae%n%ce", merged])).toBe(`${ciEmail}\n${ciEmail}`);
    expect(git(fixture.repository, ["show", "-s", "--format=%an%n%cn", merged])).toBe("Blackglass CI\nBlackglass CI");
    expect(git(fixture.repository, ["config", "user.email"])).toBe("ambient@example.test");
    expect(git(fixture.repository, ["status", "--porcelain"])).toBe("");
    expect(scan(fixture.repository).exitCode).toBe(0);
  });

  test("keeps HEAD unchanged when the base is already an ancestor", async () => {
    const fixture = await createFixture();
    const head = await commitFile(fixture.repository, "head.txt", "PR content\n");
    const before = git(fixture.repository, ["rev-list", "--all"]);
    expect(prepare(fixture.repository, head, fixture.initial).exitCode).toBe(0);
    expect(git(fixture.repository, ["rev-parse", "HEAD"])).toBe(head);
    expect(git(fixture.repository, ["rev-list", "--all"])).toBe(before);
  });

  test("retains the exact PR head as first parent when base could fast-forward it", async () => {
    const fixture = await createFixture();
    const base = await commitFile(fixture.repository, "base.txt", "base content\n");
    git(fixture.repository, ["checkout", "--detach", fixture.initial]);
    expect(prepare(fixture.repository, fixture.initial, base).exitCode).toBe(0);
    expect(git(fixture.repository, ["show", "-s", "--format=%P", "HEAD"])).toBe(`${fixture.initial} ${base}`);
  });

  test("push validates the checkout but does not create a merge or fetch", async () => {
    const fixture = await createFixture();
    const { head, base } = await diverge(fixture);
    const before = git(fixture.repository, ["rev-list", "--all"]);
    expect(prepare(fixture.repository, head, base, { CI_EVENT_NAME: "push" }).exitCode).toBe(0);
    expect(git(fixture.repository, ["rev-parse", "HEAD"])).toBe(head);
    expect(git(fixture.repository, ["rev-list", "--all"])).toBe(before);
    expect(prepare(fixture.repository, head, "", { CI_EVENT_NAME: "push" }).exitCode).toBe(0);
  });

  for (const variable of ["CI_HEAD_SHA", "CI_BASE_SHA"]) {
    for (const [label, value] of [
      ["missing", ""],
      ["short", "abc123"],
      ["uppercase", "A".repeat(40)],
      ["non-hex", "z".repeat(40)],
      ["ref expression", "HEAD^{commit}"],
      ["shell syntax", "$(touch injected)"],
      ["trailing newline", `${"a".repeat(40)}\n`],
    ]) {
      test(`rejects ${label} ${variable} before changing the checkout`, async () => {
        const fixture = await createFixture();
        const { head, base } = await diverge(fixture);
        const result = prepare(fixture.repository, head, base, { [variable]: value! });
        expect(result.exitCode).not.toBe(0);
        expect(result.stderr.toString()).toContain(`${variable} must be a full lowercase Git commit`);
        expect(git(fixture.repository, ["rev-parse", "HEAD"])).toBe(head);
        expect(git(fixture.repository, ["status", "--porcelain"])).toBe("");
      });
    }
  }

  test("rejects unsupported or missing event types", async () => {
    const fixture = await createFixture();
    for (const event of ["", "pull_request_target", "workflow_dispatch"]) {
      const result = prepare(fixture.repository, fixture.initial, fixture.initial, { CI_EVENT_NAME: event });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain("CI_EVENT_NAME must be push or pull_request");
    }
  });

  test("rejects a checkout that is not the exact expected head", async () => {
    const fixture = await createFixture();
    const { head, base } = await diverge(fixture);
    const result = prepare(fixture.repository, fixture.initial, base);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("checkout HEAD does not match CI_HEAD_SHA");
    expect(git(fixture.repository, ["rev-parse", "HEAD"])).toBe(head);
  });

  test("rejects an unavailable base instead of silently testing only the PR", async () => {
    const fixture = await createFixture();
    const result = prepare(fixture.repository, fixture.initial, "0".repeat(40));
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("could not fetch exact CI_BASE_SHA");
    expect(git(fixture.repository, ["rev-parse", "HEAD"])).toBe(fixture.initial);
  });

  test("rejects a non-commit base object", async () => {
    const fixture = await createFixture();
    const tree = git(fixture.repository, ["rev-parse", "HEAD^{tree}"]);
    const result = prepare(fixture.repository, fixture.initial, tree);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("CI_BASE_SHA must identify a commit object");
  });

  test("fails on conflicts and restores the exact clean PR checkout", async () => {
    const fixture = await createFixture();
    const base = await commitFile(fixture.repository, "shared.txt", "base conflict\n");
    git(fixture.repository, ["update-ref", "refs/heads/base", base]);
    git(fixture.repository, ["checkout", "--detach", fixture.initial]);
    const head = await commitFile(fixture.repository, "shared.txt", "PR conflict\n");
    const result = prepare(fixture.repository, head, base);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("CI integration merge failed");
    expect(git(fixture.repository, ["rev-parse", "HEAD"])).toBe(head);
    expect(git(fixture.repository, ["status", "--porcelain"])).toBe("");
    expect(await readFile(join(fixture.repository, "shared.txt"), "utf8")).toBe("PR conflict\n");
  });

  test("rejects dirty source before merging", async () => {
    const fixture = await createFixture();
    const { head, base } = await diverge(fixture);
    await writeFile(join(fixture.repository, "shared.txt"), "uncommitted content\n");
    const result = prepare(fixture.repository, head, base);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("clean checkout is required");
    expect(git(fixture.repository, ["rev-parse", "HEAD"])).toBe(head);
    expect(await readFile(join(fixture.repository, "shared.txt"), "utf8")).toBe("uncommitted content\n");
  });

  test("fetches a missing immutable base with its history, never the synthetic merge ref", async () => {
    const fixture = await createFixture();
    const head = await commitFile(fixture.repository, "head.txt", "PR content\n");
    git(fixture.repository, ["branch", "pr", head]);
    const checkout = join(fixture.directory, "checkout");
    git(fixture.directory, ["clone", "--quiet", "--single-branch", "--branch", "pr", pathToFileURL(fixture.repository).href, checkout]);
    git(checkout, ["checkout", "--detach", head]);
    git(fixture.repository, ["checkout", "--detach", fixture.initial]);
    const intermediate = await commitFile(fixture.repository, "base-earlier.txt", "earlier base content\n");
    const base = await commitFile(fixture.repository, "base.txt", "base content\n");
    // The server-side synthetic merge has intentionally forbidden, synthetic metadata.
    git(fixture.repository, ["merge", "--no-ff", "--no-edit", "--no-gpg-sign", "-m", "Synthetic platform merge", head], {
      GIT_AUTHOR_EMAIL: await privateFixtureEmail(),
      GIT_COMMITTER_EMAIL: await privateFixtureEmail(),
    });
    const synthetic = git(fixture.repository, ["rev-parse", "HEAD"]);
    git(fixture.repository, ["update-ref", "refs/pull/123/merge", synthetic]);
    expect(scan(fixture.repository).stderr.toString()).toContain("reachable Git history: private identifier or secret pattern");
    const trace = join(fixture.directory, "fetch-trace");
    const result = prepare(checkout, head, base, { GIT_TRACE: trace });
    expect(result.exitCode, result.stderr.toString()).toBe(0);
    expect(git(checkout, ["show", "-s", "--format=%P", "HEAD"])).toBe(`${head} ${base}`);
    expect(git(checkout, ["rev-list", "HEAD"])).toContain(intermediate);
    expect(git(checkout, ["rev-parse", "--is-shallow-repository"])).toBe("false");
    const fetchTrace = await readFile(trace, "utf8");
    expect(fetchTrace).toContain(`fetch --no-tags origin ${base}`);
    expect(fetchTrace).not.toContain("refs/pull/");
    expect(command(checkout, ["git", "cat-file", "-e", synthetic]).exitCode).not.toBe(0);
    expect(scan(checkout).exitCode).toBe(0);
  });

  test("rejects shallow history rather than scanning a truncated graph", async () => {
    const fixture = await createFixture();
    const head = await commitFile(fixture.repository, "head.txt", "PR content\n");
    const checkout = join(fixture.directory, "shallow");
    git(fixture.directory, ["clone", "--quiet", "--depth=1", pathToFileURL(fixture.repository).href, checkout]);
    const result = prepare(checkout, head, fixture.initial);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("full Git history is required");
    expect(git(checkout, ["rev-parse", "HEAD"])).toBe(head);
  });

  for (const side of ["head", "base", "unrelated"] as const) {
    for (const violation of ["private metadata", "historical secret content"] as const) {
      test(`existing scanner still rejects ${violation} in ${side} history after preparation`, async () => {
        const fixture = await createFixture();
        const contaminated = violation === "private metadata"
          ? await commitFile(fixture.repository, "history.txt", "safe content\n", {
            GIT_AUTHOR_EMAIL: await privateFixtureEmail(),
            GIT_COMMITTER_EMAIL: await privateFixtureEmail(),
          })
          : await commitFile(fixture.repository, "history.txt", ["gh", "p_", "0".repeat(32)].join(""));
        const original = git(fixture.repository, ["cat-file", "commit", contaminated]);
        const cleaned = await commitFile(fixture.repository, "history.txt", "cleaned content\n");
        git(fixture.repository, ["update-ref", `refs/heads/${side}-history`, cleaned]);
        git(fixture.repository, ["checkout", "--detach", side === "base" ? cleaned : fixture.initial]);
        const base = await commitFile(fixture.repository, "base.txt", "base content\n");
        git(fixture.repository, ["update-ref", "refs/heads/base", base]);
        git(fixture.repository, ["checkout", "--detach", side === "head" ? cleaned : fixture.initial]);
        const head = await commitFile(fixture.repository, "head.txt", "PR content\n");
        expect(prepare(fixture.repository, head, base).exitCode).toBe(0);
        expect(git(fixture.repository, ["cat-file", "commit", contaminated]) === original).toBe(true);
        expect(git(fixture.repository, ["rev-list", "--all"])).toContain(contaminated);
        const result = scan(fixture.repository);
        expect(result.exitCode).not.toBe(0);
        expect(result.stderr.toString()).toContain("reachable Git history: private identifier or secret pattern");
      });
    }
  }

  test("existing scanner still rejects secret-bearing current source", async () => {
    const fixture = await createFixture();
    const head = await commitFile(fixture.repository, "source.txt", ["gh", "p_", "0".repeat(32)].join(""));
    expect(prepare(fixture.repository, head, fixture.initial).exitCode).toBe(0);
    const result = scan(fixture.repository);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("source.txt: private identifier or secret pattern");
  });
});

describe("CI workflow source binding", () => {
  test("checks out complete immutable real history and prepares integration before checks", async () => {
    const workflow = await readFile(join(root, ".github/workflows/ci.yml"), "utf8");
    expect(workflow).toContain("ref: ${{ github.event.pull_request.head.sha || github.sha }}");
    expect(workflow).toContain("fetch-depth: 0");
    expect(workflow).toContain("CI_EVENT_NAME: ${{ github.event_name }}");
    expect(workflow).toContain("CI_HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}");
    expect(workflow).toContain("CI_BASE_SHA: ${{ github.event.pull_request.base.sha }}");
    expect(workflow.indexOf("run: ./ops/prepare-ci-source.sh")).toBeGreaterThan(0);
    expect(workflow.indexOf("run: ./ops/prepare-ci-source.sh")).toBeLessThan(workflow.indexOf("run: npm ci"));
    expect(workflow).not.toContain("refs/pull/");
    expect(workflow).toContain('BLACKGLASS_TESTED_SOURCE_REVISION="$(git rev-parse --verify HEAD)" ./ops/build-release.sh');
    expect(workflow).not.toContain('BLACKGLASS_TESTED_SOURCE_REVISION="$GITHUB_SHA"');
  });
});

function command(repository: string, args: string[], overrides: Environment = {}) {
  return Bun.spawnSync(args, {
    cwd: repository,
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: repository,
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
      GIT_ALLOW_PROTOCOL: "file",
      GIT_AUTHOR_NAME: "Fixture Author",
      GIT_AUTHOR_EMAIL: "fixture@example.test",
      GIT_COMMITTER_NAME: "Fixture Committer",
      GIT_COMMITTER_EMAIL: "fixture@example.test",
      GIT_AUTHOR_DATE: "2025-01-01T00:00:00Z",
      GIT_COMMITTER_DATE: "2025-01-01T00:00:00Z",
      ...overrides,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
}

function git(repository: string, args: string[], overrides: Environment = {}): string {
  const result = command(repository, ["git", ...args], overrides);
  if (result.exitCode !== 0) throw new Error(`Fixture Git operation failed: ${args[0]}`);
  return result.stdout.toString().trim();
}

function prepare(repository: string, head: string, base: string, overrides: Environment = {}) {
  return command(repository, ["sh", prepareScript], {
    CI_EVENT_NAME: "pull_request",
    CI_HEAD_SHA: head,
    CI_BASE_SHA: base,
    ...overrides,
  });
}

function scan(repository: string) {
  return command(repository, [process.execPath, "run", "tools/distribution-boundary.ts"]);
}

async function createFixture(): Promise<Fixture> {
  const directory = await mkdtemp(join(tmpdir(), "blackglass-ci-source-"));
  directories.push(directory);
  const repository = join(directory, "repository");
  await mkdir(join(repository, "tools"), { recursive: true });
  await cp(scannerPath, join(repository, "tools/distribution-boundary.ts"));
  git(repository, ["init", "--quiet", "--initial-branch=fixture", "--object-format=sha1"]);
  git(repository, ["config", "core.hooksPath", "/dev/null"]);
  const initial = await commitFile(repository, "shared.txt", "initial content\n");
  git(repository, ["checkout", "--detach", initial]);
  return { directory, repository, initial };
}

async function commitFile(repository: string, path: string, content: string, overrides: Environment = {}): Promise<string> {
  await writeFile(join(repository, path), content);
  git(repository, ["add", "."]);
  git(repository, ["commit", "--quiet", "--no-gpg-sign", "-m", "Fixture change"], overrides);
  return git(repository, ["rev-parse", "HEAD"]);
}

async function diverge(fixture: Fixture): Promise<{ head: string; base: string }> {
  const base = await commitFile(fixture.repository, "base.txt", "base content\n");
  git(fixture.repository, ["update-ref", "refs/heads/base", base]);
  git(fixture.repository, ["checkout", "--detach", fixture.initial]);
  const head = await commitFile(fixture.repository, "head.txt", "PR content\n");
  return { head, base };
}

async function privateFixtureEmail(): Promise<string> {
  // Reuse the scanner's deny marker, but never store a real private address or
  // print the generated value. Only the repository's unchanged scanner is run.
  const scanner = await readFile(scannerPath, "utf8");
  const parts = scanner.match(/const privateName = (\[[^\n]+\])\.join\(""\);/u)?.[1];
  if (!parts) throw new Error("Scanner private-name fixture marker not found");
  return `fixture@${(JSON.parse(parts) as string[]).join("")}.invalid`;
}
