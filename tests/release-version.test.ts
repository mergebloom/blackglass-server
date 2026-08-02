import { describe, expect, test } from "bun:test";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

  test("OCI publishing verifies repository releases and registry digests without owner-wide package listing", async () => {
    const release = await readFile(join(root, "ops/publish-release.sh"), "utf8");
    const publish = await readFile(join(root, "ops/publish-oci-version.sh"), "utf8");
    const promote = await readFile(join(root, "ops/promote-oci-latest.sh"), "utf8");

    for (const source of [publish, promote]) {
      expect(source).not.toContain("packages?package_type=container");
      expect(source).toContain("docker buildx imagetools inspect");
    }
    expect(promote).toContain(
      'repos/${GITHUB_REPOSITORY}/releases?per_page=100',
    );
    expect(release).toContain(
      'repos/${GITHUB_REPOSITORY}/releases?per_page=100',
    );
    expect(release).not.toContain(
      'repos/${GITHUB_REPOSITORY}/releases/tags/${tag}',
    );
  });

  test("release publishing resumes an exact-tag draft that is absent from the tag endpoint", async () => {
    const toolDirectory = await mkdtemp(join(tmpdir(), "blackglass-release-tools-"));
    try {
      const asset = join(toolDirectory, "test-release.bin");
      const uploaded = join(toolDirectory, "uploaded");
      const published = join(toolDirectory, "published");
      const revision = "a".repeat(40);
      const digest = "b".repeat(64);
      await writeFile(asset, "payload");
      await writeFile(join(toolDirectory, "git"), `#!/bin/sh
test "\${1:-}" = rev-parse || exit 91
printf '%s\\n' "$BLACKGLASS_TEST_REVISION"
`);
      await writeFile(join(toolDirectory, "sha256sum"), `#!/bin/sh
printf '%s  %s\\n' "$BLACKGLASS_TEST_DIGEST" "\${1:-}"
`);
      await writeFile(join(toolDirectory, "stat"), `#!/bin/sh
printf '%s\\n' 7
`);
      await writeFile(join(toolDirectory, "gh"), `#!/bin/sh
set -eu
case "\${1:-}:\${2:-}" in
  api:--paginate)
    case "\${3:-}" in
      */releases?per_page=100)
        draft=true
        test ! -f "$BLACKGLASS_TEST_PUBLISHED" || draft=false
        printf '[[{"id":7,"tag_name":"v1.2.3","name":"Test release","prerelease":false,"draft":%s}]]\\n' "$draft"
        ;;
      */releases/7/assets?per_page=100)
        if test -f "$BLACKGLASS_TEST_UPLOADED"; then
          printf '[[{"id":8,"name":"test-release.bin","state":"uploaded","digest":"sha256:%s","size":7}]]\\n' "$BLACKGLASS_TEST_DIGEST"
        else
          printf '[[]]\\n'
        fi
        ;;
      *) exit 92 ;;
    esac
    ;;
  release:upload)
    : > "$BLACKGLASS_TEST_UPLOADED"
    ;;
  release:edit)
    : > "$BLACKGLASS_TEST_PUBLISHED"
    ;;
  *) exit 93 ;;
esac
`);
      for (const command of ["git", "sha256sum", "stat", "gh"]) {
        await chmod(join(toolDirectory, command), 0o755);
      }

      const result = Bun.spawnSync([
        join(root, "ops/publish-release.sh"),
        "v1.2.3",
        "Test release",
        asset,
      ], {
        cwd: root,
        env: {
          ...process.env,
          PATH: `${toolDirectory}:${process.env.PATH ?? ""}`,
          GITHUB_REPOSITORY: "example/repository",
          GITHUB_SHA: revision,
          GH_TOKEN: "test-token",
          BLACKGLASS_TEST_REVISION: revision,
          BLACKGLASS_TEST_DIGEST: digest,
          BLACKGLASS_TEST_UPLOADED: uploaded,
          BLACKGLASS_TEST_PUBLISHED: published,
        },
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(result.exitCode, result.stderr.toString()).toBe(0);
      expect(await readFile(uploaded, "utf8")).toBe("");
      expect(await readFile(published, "utf8")).toBe("");
    } finally {
      await rm(toolDirectory, { recursive: true, force: true });
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

  test("accepts only full lowercase source revisions", () => {
    expect(validateSourceRevision("0".repeat(40))).toBe(0);
    expect(validateSourceRevision("0123456789abcdef".repeat(2) + "01234567")).toBe(0);
    expect(validateSourceRevision("0".repeat(39))).not.toBe(0);
    expect(validateSourceRevision("0".repeat(41))).not.toBe(0);
    expect(validateSourceRevision("A".repeat(40))).not.toBe(0);
    expect(validateSourceRevision("g".repeat(40))).not.toBe(0);
    expect(validateSourceRevision(`${"0".repeat(40)}\n`)).not.toBe(0);
  });

  test("the Linux build rejects an invalid explicit source revision before Docker access", () => {
    for (const [entrypoint, args] of releaseBuildEntrypoints) {
      for (const revision of ["release-candidate", "A".repeat(40), "0".repeat(39)]) {
        const result = Bun.spawnSync([
          join(root, "ops", entrypoint),
          ...args,
        ], {
          cwd: root,
          env: { ...process.env, SOURCE_REVISION: revision },
          stdout: "pipe",
          stderr: "pipe",
        });
        expect(result.exitCode).toBe(1);
        expect(result.stderr.toString()).toContain(
          "SOURCE_REVISION must be a full lowercase Git commit",
        );
        expect(result.stderr.toString()).not.toContain("Docker with Buildx");
      }
    }
  });

  test("both release builders fail closed on Git identity and status errors", async () => {
    const toolDirectory = await mkdtemp(join(tmpdir(), "blackglass-fake-git-"));
    try {
      const fakeGit = join(toolDirectory, "git");
      await writeFile(fakeGit, `#!/bin/sh
case "\${3:-}" in
  rev-parse)
    test "\${BLACKGLASS_FAKE_GIT_MODE:-}" != no-repository || exit 2
    printf '%s\\n' '${"a".repeat(40)}'
    ;;
  status)
    case "\${BLACKGLASS_FAKE_GIT_MODE:-}" in
      status-error) exit 7 ;;
      dirty) printf '%s\\n' ' M tracked-file' ;;
    esac
    ;;
  archive)
    test "\${6:-}" = '${"a".repeat(40)}' || exit 97
    exit 99
    ;;
  *) exit 98 ;;
esac
`);
      await chmod(fakeGit, 0o755);

      const cases = [
        ["no-repository", "a".repeat(40), "a clean Git checkout is required"],
        ["status-error", "a".repeat(40), "could not verify that the release checkout is clean"],
        ["dirty", "a".repeat(40), "dirty worktree"],
        ["clean", "b".repeat(40), "SOURCE_REVISION does not match the clean checkout HEAD"],
        ["archive-error", "a".repeat(40), "could not export the immutable release source commit"],
      ] as const;
      for (const [entrypoint, args] of releaseBuildEntrypoints) {
        for (const [mode, revision, message] of cases) {
          const result = Bun.spawnSync([join(root, "ops", entrypoint), ...args], {
            cwd: root,
            env: {
              ...process.env,
              BLACKGLASS_FAKE_GIT_MODE: mode,
              PATH: `${toolDirectory}:${process.env.PATH ?? ""}`,
              SOURCE_REVISION: revision,
            },
            stdout: "pipe",
            stderr: "pipe",
          });
          expect(result.exitCode, `${entrypoint}: ${mode}`).toBe(1);
          expect(result.stderr.toString(), `${entrypoint}: ${mode}`).toContain(message);
          expect(result.stderr.toString()).not.toContain("Docker with Buildx");
        }
      }
    } finally {
      await rm(toolDirectory, { recursive: true, force: true });
    }
  });

  test("both release builders require Git to be available", async () => {
    const toolDirectory = await mkdtemp(join(tmpdir(), "blackglass-no-git-"));
    try {
      const dirnameProxy = join(toolDirectory, "dirname");
      await writeFile(dirnameProxy, '#!/bin/sh\nexec /usr/bin/dirname "$@"\n');
      await chmod(dirnameProxy, 0o755);
      for (const [entrypoint, args] of releaseBuildEntrypoints) {
        const result = Bun.spawnSync([join(root, "ops", entrypoint), ...args], {
          cwd: root,
          env: {
            ...process.env,
            PATH: toolDirectory,
            SOURCE_REVISION: "a".repeat(40),
          },
          stdout: "pipe",
          stderr: "pipe",
        });
        expect(result.exitCode, entrypoint).toBe(1);
        expect(result.stderr.toString(), entrypoint).toContain(
          "a clean Git checkout is required",
        );
      }
    } finally {
      await rm(toolDirectory, { recursive: true, force: true });
    }
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

const releaseBuildEntrypoints: Array<[string, string[]]> = [
  ["build-linux-release.sh", ["linux-amd64"]],
  ["build-release.sh", []],
];

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

function validateSourceRevision(revision: string): number {
  return Bun.spawnSync([
    "/bin/sh",
    "-c",
    '. "$1"; blackglass_is_full_source_revision "$2"',
    "blackglass-source-revision-test",
    validator,
    revision,
  ], { cwd: root, stdout: "pipe", stderr: "pipe" }).exitCode;
}
