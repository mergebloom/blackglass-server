import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const verifier = join(root, "ops/verify-linux-release.sh");
const version = "1.2.3";
const target = "linux-amd64";
const sourceRevision = "a".repeat(40);
const dockerfile = await readFile(join(root, "ops/Dockerfile.release"), "utf8");
const toolchain = await readFile(join(root, "rust-toolchain.toml"), "utf8");
const builderImage = dockerfile.match(/^ARG RUST_BUILDER="([^"]+)"$/m)?.[1];
const rustVersion = toolchain.match(/^channel = "([^"]+)"$/m)?.[1];

if (!builderImage || !rustVersion) {
  throw new Error("release test could not resolve pinned builder metadata");
}

describe("Linux release verifier", () => {
  test("accepts an exact manifest and matching executable self-attestation", async () => {
    const fixture = await createReleaseFixture();
    try {
      const result = await verify(fixture);
      expect(result.exitCode, result.stderr.toString()).toBe(0);
      expect(result.stdout.toString()).toContain(
        `verified: blackglass-server-v${version}-${target}.tar.gz`,
      );
      expect(result.stdout.toString()).toContain(sourceRevision);
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  });

  test("rejects malformed, incomplete, or inconsistent manifest structures", async () => {
    const mutations: Array<[string, (manifest: Record<string, unknown>) => void]> = [
      ["filename version", (manifest) => { manifest.version = "9.9.9"; }],
      ["target", (manifest) => { manifest.target = "linux-arm64"; }],
      ["operating system", (manifest) => { manifest.os = "darwin"; }],
      ["architecture", (manifest) => { manifest.architecture = "arm64"; }],
      ["binary name", (manifest) => { manifest.binary = "other-server"; }],
      ["binary size type", (manifest) => { manifest.binarySize = String(manifest.binarySize); }],
      ["Rust version", (manifest) => { manifest.rustVersion = "1.91.0"; }],
      ["builder image", (manifest) => { manifest.builderImage = "rust:latest"; }],
      ["source revision", (manifest) => { manifest.sourceRevision = "A".repeat(40); }],
      ["newline-terminated source revision", (manifest) => { manifest.sourceRevision = `${"a".repeat(40)}\n`; }],
      ["extra key", (manifest) => { manifest.unreviewed = true; }],
      ["missing key", (manifest) => { delete manifest.libc; }],
    ];

    for (const [label, mutateManifest] of mutations) {
      const fixture = await createReleaseFixture({ mutateManifest });
      try {
        const result = await verify(fixture);
        expect(result.exitCode, label).toBe(1);
        expect(result.stderr.toString(), label).toContain(
          "release manifest does not match the archive, target, or pinned build metadata",
        );
      } finally {
        await rm(fixture.directory, { recursive: true, force: true });
      }
    }
  }, 20_000);

  test("binds the manifest to the caller's expected source revision", async () => {
    const fixture = await createReleaseFixture();
    try {
      const result = await verify(fixture, "b".repeat(40));
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "release manifest does not match the archive, target, or pinned build metadata",
      );
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  });

  test("rejects duplicate JSON keys before last-key-wins parsing", async () => {
    const replacements = [
      `  "version": "9.9.9",\n  "version": "${version}",`,
      `  "version": {"ignored": "9.9.9"},\n  "version": "${version}",`,
    ];
    for (const replacement of replacements) {
      const fixture = await createReleaseFixture({
        transformManifestText: (text) => text.replace(
          `  "version": "${version}",`,
          replacement,
        ),
      });
      try {
        const result = await verify(fixture, null, false);
        expect(result.exitCode).toBe(1);
        expect(result.stderr.toString()).toContain(
          "release manifest contains duplicate JSON paths",
        );
      } finally {
        await rm(fixture.directory, { recursive: true, force: true });
      }
    }
  });

  test("rejects a newline-terminated source revision without a caller expectation", async () => {
    const fixture = await createReleaseFixture({
      mutateManifest: (manifest) => {
        manifest.sourceRevision = `${sourceRevision}\n`;
      },
    });
    try {
      const result = await verify(fixture, null, false);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "release manifest does not match the archive, target, or pinned build metadata",
      );
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  });

  test("rejects executable build-info that disagrees with the manifest", async () => {
    const fixture = await createReleaseFixture({
      executableSourceRevision: "b".repeat(40),
    });
    try {
      const result = await verify(fixture);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "release binary build-info does not match its manifest",
      );
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  });

  test("does not execute an untrusted download in the default verification mode", async () => {
    const fixture = await createReleaseFixture({
      executableSourceRevision: "b".repeat(40),
      recordExecution: true,
    });
    try {
      const result = await verify(fixture, sourceRevision, false);
      expect(result.exitCode, result.stderr.toString()).toBe(0);
      expect(await Bun.file(fixture.executionMarker).exists()).toBe(false);
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  });

  test("rejects a checksum record that is not bound to the archive filename", async () => {
    const fixture = await createReleaseFixture();
    try {
      const checksum = (await readFile(`${fixture.archive}.sha256`, "utf8")).split(/\s+/)[0];
      await writeFile(`${fixture.archive}.sha256`, `${checksum}  unrelated.tar.gz\n`);
      const result = await verify(fixture);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(
        "archive checksum record does not match",
      );
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  });
});

interface FixtureOptions {
  executableSourceRevision?: string;
  mutateManifest?: (manifest: Record<string, unknown>) => void;
  recordExecution?: boolean;
  transformManifestText?: (text: string) => string;
}

interface ReleaseFixture {
  archive: string;
  directory: string;
  executionMarker: string;
  rawBinary: string;
  toolDirectory: string;
}

async function createReleaseFixture(
  options: FixtureOptions = {},
): Promise<ReleaseFixture> {
  const directory = await mkdtemp(join(tmpdir(), "blackglass-release-verifier-"));
  const staging = join(directory, "staging");
  const bundle = `blackglass-server-v${version}-${target}`;
  const bundleDirectory = join(staging, bundle);
  const binary = join(bundleDirectory, "blackglass-server");
  const executionMarker = join(directory, "binary-executed");
  const executableSourceRevision =
    options.executableSourceRevision ?? sourceRevision;

  await mkdir(bundleDirectory, { recursive: true });
  for (const filename of [
    "INSTALL.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "blackglass-server.env.example",
    "blackglass-server.service",
    "blackglass-server.sysusers.conf",
  ]) {
    await writeFile(join(bundleDirectory, filename), `${filename}\n`);
  }
  await writeFile(
    binary,
    `#!/bin/sh\n${options.recordExecution ? `printf '%s\\n' executed >> '${executionMarker}'\n` : ""}case "\${1:-}" in\n  --version) printf '%s\\n' 'blackglass-server ${version}' ;;\n  build-info) printf '%s\\n' '${JSON.stringify({ name: "blackglass-server", sourceRevision: executableSourceRevision, version })}' ;;\n  *) exit 2 ;;\nesac\n`,
  );
  await chmod(binary, 0o755);

  const binaryBytes = await readFile(binary);
  const manifest: Record<string, unknown> = {
    schemaVersion: 1,
    name: "blackglass-server",
    version,
    target,
    os: "linux",
    architecture: "amd64",
    libc: "musl",
    binary: "blackglass-server",
    binarySha256: sha256(binaryBytes),
    binarySize: binaryBytes.byteLength,
    rustVersion,
    builderImage,
    sourceRevision,
  };
  options.mutateManifest?.(manifest);
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  await writeFile(
    join(bundleDirectory, "manifest.json"),
    options.transformManifestText?.(manifestText) ?? manifestText,
  );
  await copyFile(
    join(root, "ops/release/release-contract.json"),
    join(bundleDirectory, "release-contract.json"),
  );

  const archive = join(directory, `${bundle}.tar.gz`);
  const entries = [
    `${bundle}/`,
    `${bundle}/INSTALL.md`,
    `${bundle}/LICENSE`,
    `${bundle}/THIRD_PARTY_NOTICES.md`,
    `${bundle}/blackglass-server`,
    `${bundle}/blackglass-server.env.example`,
    `${bundle}/blackglass-server.service`,
    `${bundle}/blackglass-server.sysusers.conf`,
    `${bundle}/manifest.json`,
    `${bundle}/release-contract.json`,
  ];
  const tar = Bun.spawnSync([
    "tar",
    "-czf",
    archive,
    "--no-recursion",
    "-C",
    staging,
    ...entries,
  ], { stdout: "pipe", stderr: "pipe" });
  expect(tar.exitCode, tar.stderr.toString()).toBe(0);
  await writeChecksum(archive);

  const rawBinary = join(directory, bundle);
  await copyFile(binary, rawBinary);
  await chmod(rawBinary, 0o755);
  await writeChecksum(rawBinary);

  const toolDirectory = join(directory, "tools");
  await mkdir(toolDirectory);
  const fileStub = join(toolDirectory, "file");
  await writeFile(
    fileStub,
    "#!/bin/sh\nprintf '%s: ELF 64-bit LSB pie executable, x86-64, static-pie linked\\n' \"$1\"\n",
  );
  await chmod(fileStub, 0o755);
  const unameStub = join(toolDirectory, "uname");
  await writeFile(
    unameStub,
    "#!/bin/sh\ncase \"$1\" in\n  -s) echo Linux ;;\n  -m) echo x86_64 ;;\n  *) exit 2 ;;\nesac\n",
  );
  await chmod(unameStub, 0o755);

  return { archive, directory, executionMarker, rawBinary, toolDirectory };
}

async function verify(
  fixture: ReleaseFixture,
  expectedRevision: string | null = sourceRevision,
  executeTrustedBinary = true,
) {
  const args = [
    verifier,
    target,
    fixture.archive,
    fixture.rawBinary,
  ];
  if (expectedRevision !== null) {
    args.push(expectedRevision);
  }
  if (executeTrustedBinary) {
    args.push("--execute-trusted-binary");
  }
  return Bun.spawnSync(args, {
    cwd: root,
    env: {
      ...process.env,
      PATH: `${fixture.toolDirectory}:${process.env.PATH ?? ""}`,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
}

async function writeChecksum(path: string): Promise<void> {
  const bytes = await readFile(path);
  await writeFile(`${path}.sha256`, `${sha256(bytes)}  ${path.split("/").at(-1)}\n`);
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
