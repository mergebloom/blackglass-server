import { chmod, mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "bun:test";

const root = resolve(import.meta.dir, "..");
const script = resolve(root, "ops/compose-ops.sh");

test("publishes a verified backup and requires its checksum for verification", async () => {
  const fixture = await fixtureDirectory();
  const backup = join(fixture.root, "backup.sqlite");
  const result = run(fixture.bin, ["backup", backup]);
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  expect(await readFile(backup, "utf8")).toBe("sqlite-backup-bytes");
  expect(await readFile(`${backup}.sha256`, "utf8")).toMatch(/^[a-f0-9]{64}  backup\.sqlite\n$/u);
  expect(run(fixture.bin, ["verify-backup", backup]).exitCode).toBe(0);

  await Bun.file(`${backup}.sha256`).delete();
  const missing = run(fixture.bin, ["verify-backup", backup]);
  expect(missing.exitCode).not.toBe(0);
  expect(missing.stderr.toString()).toContain("backup checksum is required");
});

test("runs the permission bootstrap before first-account initialization", async () => {
  const fixture = await fixtureDirectory();
  const log = join(fixture.root, "docker.log");
  await executable(join(fixture.bin, "docker"), `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
case "$*" in
  *permissions*) read ignored || true; exit 0 ;;
  *'user create'*) read password; [ "$password" = safe-test-password ] ;;
  *) exit 0 ;;
esac
`);
  const result = Bun.spawnSync(["/bin/sh", script, "init", "owner@example.test", "Owner"], {
    cwd: root,
    env: {
      ...process.env,
      PATH: `${fixture.bin}:/usr/local/bin:/usr/bin:/bin`,
      BLACKGLASS_ENV_FILE: ".env.example",
      FAKE_DOCKER_LOG: log,
    },
    stdin: Buffer.from("safe-test-password\n"), stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  const invocations = (await readFile(log, "utf8")).trim().split("\n");
  expect(invocations[0]).toContain("run --rm -T permissions");
  expect(invocations[1]).toContain("run --rm --no-deps -T server user create");
});

test("runs the health probe through the server executable", async () => {
  const fixture = await fixtureDirectory();
  await executable(join(fixture.bin, "docker"), `#!/bin/sh
[ "$*" = "compose --env-file .env.example -f compose.yaml exec -T server /usr/local/bin/blackglass-server healthcheck" ]
`);
  const result = run(fixture.bin, ["health"]);
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});

test("rejects checksum mismatch before invoking the restore container", async () => {
  const fixture = await fixtureDirectory();
  const backup = join(fixture.root, "backup.sqlite");
  expect(run(fixture.bin, ["backup", backup]).exitCode).toBe(0);
  await writeFile(backup, "tampered");
  const result = run(fixture.bin, ["restore-drill", backup]);
  expect(result.exitCode).not.toBe(0);
});

test("leaves no published or partial files when checksum generation fails", async () => {
  const fixture = await fixtureDirectory();
  await executable(join(fixture.bin, "sha256sum"), "#!/bin/sh\nexit 9\n");
  const backup = join(fixture.root, "backup.sqlite");
  const result = run(fixture.bin, ["backup", backup]);
  expect(result.exitCode).not.toBe(0);
  expect(await releaseFiles(fixture.root)).toEqual([]);
});

test("rolls back the checksum when final database publication fails", async () => {
  const fixture = await fixtureDirectory();
  const count = join(fixture.root, "mv-count");
  await executable(join(fixture.bin, "mv"), `#!/bin/sh
count=$(sed -n '1p' "$FAKE_MV_COUNT" 2>/dev/null || true)
count=\${count:-0}
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_MV_COUNT"
[ "$count" -ne 2 ] || exit 8
exec /bin/mv "$@"
`);
  const backup = join(fixture.root, "backup.sqlite");
  const result = run(fixture.bin, ["backup", backup], { FAKE_MV_COUNT: count });
  expect(result.exitCode).not.toBe(0);
  expect(result.stderr.toString()).toContain("checksum was rolled back");
  expect(await releaseFiles(fixture.root)).toEqual(["mv-count"]);
});

async function fixtureDirectory(): Promise<{ root: string; bin: string }> {
  const directory = await mkdtemp(join(tmpdir(), "blackglass-compose-ops-"));
  const bin = join(directory, "bin");
  await mkdir(bin);
  await executable(join(bin, "docker"), `#!/bin/sh
case "$*" in
  *'/usr/local/bin/blackglass-server backup-stdout'*) printf %s sqlite-backup-bytes ;;
  *backup-stdout*) exit 11 ;;
  *) exit 0 ;;
esac
`);
  return { root: directory, bin };
}

async function executable(path: string, contents: string): Promise<void> {
  await writeFile(path, contents, { mode: 0o700 });
  await chmod(path, 0o700);
}

function run(bin: string, arguments_: string[], extraEnvironment: Record<string, string> = {}) {
  return Bun.spawnSync(["/bin/sh", script, ...arguments_], {
    cwd: root,
    env: {
      ...process.env,
      ...extraEnvironment,
      PATH: `${bin}:/usr/local/bin:/usr/bin:/bin`,
      BLACKGLASS_ENV_FILE: ".env.example",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
}

async function releaseFiles(directory: string): Promise<string[]> {
  return (await readdir(directory)).filter((name) => name !== "bin").sort();
}
