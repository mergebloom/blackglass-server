import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const write = Bun.argv.slice(2).includes("--write");
if (Bun.argv.slice(2).some((argument) => argument !== "--write")) {
  throw new Error("Usage: bun run tools/third-party-notices.ts [--write]");
}

const cargoAboutVersion = "0.9.1";
const paths = {
  lock: join(root, "apps/server-rust/Cargo.lock"),
  cargoManifest: join(root, "apps/server-rust/Cargo.toml"),
  config: join(root, "about.toml"),
  generator: join(root, "tools/third-party-notices.ts"),
  template: join(root, "about.hbs"),
  nativeRuntimeNotices: join(root, "native-runtime-notices.md"),
  releaseDockerfile: join(root, "ops/Dockerfile.release"),
  rustToolchain: join(root, "rust-toolchain.toml"),
  notices: join(root, "THIRD_PARTY_NOTICES.md"),
  manifest: join(root, "third-party-notices.lock.json"),
};

await assertNativeRuntimeInputs();
if (write) await generate();
await verify();

async function assertNativeRuntimeInputs(): Promise<void> {
  const [lock, cargoManifest, releaseDockerfile, rustToolchain, nativeNotices] =
    await Promise.all([
      readFile(paths.lock, "utf8"),
      readFile(paths.cargoManifest, "utf8"),
      readFile(paths.releaseDockerfile, "utf8"),
      readFile(paths.rustToolchain, "utf8"),
      readFile(paths.nativeRuntimeNotices, "utf8"),
    ]);
  const rustVersion = /^channel = "([0-9]+\.[0-9]+\.[0-9]+)"$/mu.exec(
    rustToolchain,
  )?.[1];
  const builderRustVersion =
    /^ARG RUST_BUILDER="rust:([0-9]+\.[0-9]+\.[0-9]+)-alpine[^" ]+"$/mu.exec(
      releaseDockerfile,
    )?.[1];
  const muslPackage = /^\s+musl=([^\s\\]+)\s+\\$/mu.exec(releaseDockerfile)?.[1];
  const muslDevPackage = /^\s+musl-dev=([^\s\\]+)\s+\\$/mu.exec(
    releaseDockerfile,
  )?.[1];
  const sqliteSysVersion =
    /\[\[package\]\]\nname = "libsqlite3-sys"\nversion = "([^"]+)"/u.exec(lock)?.[1];
  const muslUpstreamVersion = muslPackage?.replace(/-r\d+$/u, "");
  if (
    !rustVersion ||
    builderRustVersion !== rustVersion ||
    !muslPackage ||
    muslDevPackage !== muslPackage ||
    !sqliteSysVersion ||
    !/rusqlite\s*=\s*\{[^\n]*features\s*=\s*\[[^\]]*"bundled"/u.test(cargoManifest) ||
    !nativeNotices.includes(`## Rust ${rustVersion} standard library and runtime\n`) ||
    !nativeNotices.includes(`## musl libc ${muslUpstreamVersion}\n`) ||
    !nativeNotices.includes(`\`musl=${muslPackage}\``) ||
    !nativeNotices.includes(`\`musl-dev=${muslDevPackage}\``) ||
    !nativeNotices.includes(`\`libsqlite3-sys\` ${sqliteSysVersion}`)
  ) {
    throw new Error(
      "Native/runtime notice inventory does not match the pinned Rust, musl, and bundled SQLite inputs",
    );
  }
}

async function generate(): Promise<void> {
  const version = Bun.spawnSync(["cargo", "about", "--version"], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (
    version.exitCode !== 0 ||
    version.stdout.toString().trim() !== `cargo-about ${cargoAboutVersion}`
  ) {
    throw new Error(
      `Generating notices requires cargo-about ${cargoAboutVersion} with the cli feature`,
    );
  }

  const temporary = await mkdtemp(join(tmpdir(), "blackglass-notices-"));
  try {
    const generated = join(temporary, "THIRD_PARTY_NOTICES.md");
    const result = Bun.spawnSync([
      "cargo",
      "about",
      "generate",
      "--locked",
      "--offline",
      "--fail",
      "--manifest-path",
      paths.lock.replace(/Cargo\.lock$/u, "Cargo.toml"),
      "--config",
      paths.config,
      "--output-file",
      generated,
      paths.template,
    ], { cwd: root, stdout: "pipe", stderr: "pipe" });
    if (result.exitCode !== 0) {
      throw new Error(`cargo-about failed: ${result.stderr.toString().trim()}`);
    }
    const cargoNotice = await readFile(generated, "utf8");
    const nativeRuntimeNotice = await readFile(paths.nativeRuntimeNotices, "utf8");
    const noticeText = canonicalNoticeText(`${cargoNotice}\n${nativeRuntimeNotice}`);
    const noticeBytes = Buffer.from(noticeText, "utf8");
    const inventory = noticeInventory(noticeText);
    const manifest = {
      schemaVersion: 2,
      cargoAboutVersion,
      cargoLockSha256: await fileSha256(paths.lock),
      cargoManifestSha256: await fileSha256(paths.cargoManifest),
      configSha256: await fileSha256(paths.config),
      generatorSha256: await fileSha256(paths.generator),
      nativeRuntimeNoticesSha256: await fileSha256(paths.nativeRuntimeNotices),
      releaseDockerfileSha256: await fileSha256(paths.releaseDockerfile),
      rustToolchainSha256: await fileSha256(paths.rustToolchain),
      templateSha256: await fileSha256(paths.template),
      noticesSha256: sha256(noticeBytes),
      noticedPackages: inventory.packages,
      licenseTexts: inventory.licenseTexts,
    } as const;
    const replacementId = randomUUID();
    const nextNotices = join(root, `.THIRD_PARTY_NOTICES.${replacementId}.tmp`);
    const nextManifest = join(root, `.third-party-notices-lock.${replacementId}.tmp`);
    try {
      await Promise.all([
        writeFile(nextNotices, noticeBytes, { flag: "wx", mode: 0o644 }),
        writeFile(nextManifest, `${JSON.stringify(manifest, null, 2)}\n`, {
          flag: "wx",
          mode: 0o644,
        }),
      ]);
      await rename(nextNotices, paths.notices);
      await rename(nextManifest, paths.manifest);
    } finally {
      await Promise.all([
        rm(nextNotices, { force: true }),
        rm(nextManifest, { force: true }),
      ]);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function verify(): Promise<void> {
  const raw = JSON.parse(await readFile(paths.manifest, "utf8")) as unknown;
  if (!isRecord(raw)) throw new Error("Third-party notice manifest is malformed");
  const keys = Object.keys(raw).sort(compareCodePoints);
  const expectedKeys = [
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
    "schemaVersion",
    "rustToolchainSha256",
    "templateSha256",
  ].sort(compareCodePoints);
  const notices = await readFile(paths.notices);
  const inventory = noticeInventory(notices.toString("utf8"));
  if (
    JSON.stringify(keys) !== JSON.stringify(expectedKeys) ||
    raw.schemaVersion !== 2 ||
    raw.cargoAboutVersion !== cargoAboutVersion ||
    raw.cargoLockSha256 !== await fileSha256(paths.lock) ||
    raw.cargoManifestSha256 !== await fileSha256(paths.cargoManifest) ||
    raw.configSha256 !== await fileSha256(paths.config) ||
    raw.generatorSha256 !== await fileSha256(paths.generator) ||
    raw.nativeRuntimeNoticesSha256 !== await fileSha256(paths.nativeRuntimeNotices) ||
    raw.releaseDockerfileSha256 !== await fileSha256(paths.releaseDockerfile) ||
    raw.rustToolchainSha256 !== await fileSha256(paths.rustToolchain) ||
    raw.templateSha256 !== await fileSha256(paths.template) ||
    raw.noticesSha256 !== sha256(notices) ||
    raw.noticedPackages !== inventory.packages ||
    raw.licenseTexts !== inventory.licenseTexts
  ) {
    throw new Error(
      "Third-party notices do not match the locked dependency graph; " +
        "install pinned cargo-about and run `bun run licenses:generate`",
    );
  }
  console.log(
    `third-party notices verified: ${inventory.packages} packages, ` +
      `${inventory.licenseTexts} license texts`,
  );
}

function noticeInventory(notices: string): { packages: number; licenseTexts: number } {
  if (
    !notices.startsWith("# Blackglass Server third-party notices\n") ||
    /&(?:amp|apos|gt|lt|quot);/u.test(notices) ||
    /^- blackglass-server /mu.test(notices) ||
    !notices.includes("# Native and language runtime notices\n") ||
    !notices.includes("## musl libc 1.2.5\n") ||
    !notices.includes("## Rust 1.92.0 standard library and runtime\n") ||
    !notices.includes("## SQLite amalgamation\n") ||
    !notices.includes("## Apache License 2.0\n") ||
    !notices.includes("## MIT License\n") ||
    !notices.includes("## Unicode License v3\n") ||
    notices.includes("\r") ||
    /[ \t]+$/mu.test(notices)
  ) {
    throw new Error("Generated third-party notices have an unexpected structure");
  }
  const packages = new Set(
    [...notices.matchAll(/^- ([A-Za-z0-9_-]+) ([^\s]+)(?: — .+)?$/gmu)]
      .map((match) => `${match[1]} ${match[2]}`),
  ).size;
  const begins = (notices.match(/^----- BEGIN LICENSE TEXT -----$/gmu) ?? []).length;
  const ends = (notices.match(/^----- END LICENSE TEXT -----$/gmu) ?? []).length;
  if (packages === 0 || begins === 0 || begins !== ends) {
    throw new Error("Generated third-party notices are incomplete");
  }
  return { packages, licenseTexts: begins };
}

function canonicalNoticeText(value: string): string {
  const lines = value.replace(/\r\n?/gu, "\n").split("\n");
  return `${lines.map((line) => line.replace(/[ \t]+$/u, "")).join("\n").trimEnd()}\n`;
}

async function fileSha256(path: string): Promise<string> {
  return sha256(await readFile(path));
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function compareCodePoints(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
