import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const manifest = join(root, "apps/server-rust/Cargo.toml");
let directory = "";
let controlPort = 0;
let dataPort = 0;
let processHandle: ReturnType<typeof Bun.spawn>;
let token = "";
let vault: Record<string, any>;
const sockets: WebSocket[] = [];

describe("production Rust server", () => {
  beforeAll(async () => {
    const build = Bun.spawnSync(["cargo", "build", "--manifest-path", manifest], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    });
    if (build.exitCode !== 0) throw new Error(build.stderr.toString());
    const binary = join(root, "apps/server-rust/target/debug/blackglass-server");
    const version = Bun.spawnSync([binary, "--version"], { stdout: "pipe", stderr: "pipe" });
    expect(version.exitCode, version.stderr.toString()).toBe(0);
    expect(version.stdout.toString().trim()).toBe("blackglass-server 0.2.1");
    const help = Bun.spawnSync([binary, "--help"], { stdout: "pipe", stderr: "pipe" });
    expect(help.exitCode, help.stderr.toString()).toBe(0);
    expect(help.stdout.toString()).toContain("backup <database> <output>");
    directory = await mkdtemp(join(tmpdir(), "obsidian-rust-sync-"));
    [controlPort, dataPort] = await Promise.all([freePort(), freePort()]);
    processHandle = Bun.spawn([
      join(root, "apps/server-rust/target/debug/blackglass-server"),
      "serve",
    ], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        SELFHOST_BIND_HOST: "127.0.0.1",
        SELFHOST_CONTROL_PORT: String(controlPort),
        SELFHOST_DATA_PORT: String(dataPort),
        SELFHOST_DATA_HOST: `127.0.0.1:${dataPort}`,
        SELFHOST_DATABASE: join(directory, "server.sqlite"),
        SELFHOST_STAGING_DIR: join(directory, "uploads"),
        SELFHOST_EMAIL: "owner@example.test",
        SELFHOST_PASSWORD: "test-password",
        SELFHOST_ALLOW_PLAINTEXT_PASSWORD: "1",
        SELFHOST_NAME: "Rust test owner",
        SELFHOST_PER_FILE_MAX: String(8 * 1024 * 1024),
        SELFHOST_ALLOWED_ORIGINS: "app://obsidian.md,http://localhost",
        SELFHOST_LOG_FORMAT: "pretty",
      },
    });
    await waitForHealth();
    const signin = await post("/user/signin", {
      email: "owner@example.test",
      password: "test-password",
    });
    expect(signin).toMatchObject({
      email: "owner@example.test",
      license: "selfhosted-sync",
    });
    expect(signin.token).toHaveLength(64);
    token = signin.token;
    vault = await post("/vault/create", {
      token,
      name: "Rust conformance vault",
      keyhash: "opaque-key-hash",
      salt: "opaque-salt",
      region: "selfhost",
      encryption_version: 3,
    });
  }, 60_000);

  afterAll(async () => {
    for (const socket of sockets) socket.close();
    processHandle?.kill("SIGTERM");
    if (processHandle) await processHandle.exited;
  });

  test("uses expiring sessions, E2EE-only vaults, and exact origins", async () => {
    expect(vault).toMatchObject({
      host: `127.0.0.1:${dataPort}`,
      keyhash: "opaque-key-hash",
      salt: "opaque-salt",
      encryption_version: 3,
      size: 0,
    });
    const listed = await post("/vault/list", { token });
    expect(listed.vaults).toHaveLength(1);
    expect(await post("/vault/create", {
      token,
      name: "Managed encryption must fail",
      keyhash: null,
      salt: null,
      region: "selfhost",
      encryption_version: 3,
    })).toEqual({ error: "End-to-end encryption is required" });
    const rejected = await fetch(`http://127.0.0.1:${controlPort}/user/info`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil.example" },
      body: JSON.stringify({ token }),
    });
    expect(rejected.status).toBe(403);
    for (const origin of ["app://obsidian.md", "http://localhost"]) {
      const preflight = await fetch(`http://127.0.0.1:${controlPort}/user/info`, {
        method: "OPTIONS",
        headers: { origin },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get("access-control-allow-origin")).toBe(origin);

      const info = await fetch(`http://127.0.0.1:${controlPort}/user/info`, {
        method: "POST",
        headers: { "content-type": "application/json", origin },
        body: JSON.stringify({ token }),
      });
      expect(info.status).toBe(200);
      expect(info.headers.get("access-control-allow-origin")).toBe(origin);
      expect(await info.json()).toMatchObject({ email: "owner@example.test" });
    }
    const nearMiss = await fetch(`http://127.0.0.1:${controlPort}/user/info`, {
      method: "OPTIONS",
      headers: { origin: "http://localhost.evil.example" },
    });
    expect(nearMiss.status).toBe(403);

    const mobileSocket = await Probe.connect(`ws://127.0.0.1:${dataPort}`, "http://localhost");
    mobileSocket.socket.close();
    await expect(
      Probe.connect(`ws://127.0.0.1:${dataPort}`, "http://localhost.evil.example"),
    ).rejects.toThrow("websocket failed");
  });

  test("round-trips multi-piece opaque ciphertext with bounded staging", async () => {
    const payload = new Uint8Array(randomBytes(3 * 1024 * 1024 + 17));
    const writer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(writer, "Writer", 0, true);
    writer.json(push("encrypted-large-path", "large-hash", payload.byteLength, 2));
    expect(await writer.nextJson()).toEqual({ res: "next" });
    writer.socket.send(payload.slice(0, 2 * 1024 * 1024));
    expect(await writer.nextJson()).toEqual({ res: "next" });
    const staged = await readdir(join(directory, "uploads"));
    expect(staged).toHaveLength(1);
    expect((await stat(join(directory, "uploads", staged[0]!))).size).toBe(2 * 1024 * 1024);
    writer.socket.send(payload.slice(2 * 1024 * 1024));
    const notice = await writer.nextJson();
    expect(notice).toMatchObject({ op: "push", path: "encrypted-large-path", size: payload.byteLength });
    expect(await writer.nextJson()).toEqual({ res: "ok" });
    expect(await readdir(join(directory, "uploads"))).toEqual([]);

    const reader = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(reader, "Reader", notice.uid, false);
    reader.json({ op: "pull", uid: notice.uid });
    expect(await reader.nextJson()).toEqual({ res: "ok", size: payload.byteLength, pieces: 2, deleted: false, hash: "large-hash" });
    const first = new Uint8Array(await reader.nextBinary());
    const second = new Uint8Array(await reader.nextBinary());
    const restored = new Uint8Array(first.length + second.length);
    restored.set(first); restored.set(second, first.length);
    expect(restored).toEqual(payload);

    reader.json({ op: "restore", uid: notice.uid });
    const restoredNotice = await reader.nextJson();
    expect(restoredNotice).toMatchObject({ op: "push", path: "encrypted-large-path", size: payload.byteLength });
    expect(await reader.nextJson()).toEqual({ res: "ok" });
    reader.json({ op: "pull", uid: restoredNotice.uid });
    expect(await reader.nextJson()).toMatchObject({ res: "ok", size: payload.byteLength, pieces: 2 });
    const restoredFirst = new Uint8Array(await reader.nextBinary());
    const restoredSecond = new Uint8Array(await reader.nextBinary());
    const restoredAgain = new Uint8Array(restoredFirst.length + restoredSecond.length);
    restoredAgain.set(restoredFirst); restoredAgain.set(restoredSecond, restoredFirst.length);
    expect(restoredAgain).toEqual(payload);
  }, 20_000);

  test("broadcasts revisions and preserves snapshot/resume semantics", async () => {
    const writer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    const reader = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(writer, "Broadcast writer", 0, false);
    const baseVersion = (await currentReady(reader, "Broadcast reader")).version;
    writer.json(push("live-head", "hash-v1", 0, 0));
    const v1 = await writer.nextJson(); expect(await writer.nextJson()).toEqual({ res: "ok" });
    expect(await reader.nextJson()).toMatchObject({ uid: v1.uid, path: "live-head" });
    writer.json(push("live-head", "hash-v2", 0, 0));
    const v2 = await writer.nextJson(); expect(await writer.nextJson()).toEqual({ res: "ok" });
    expect((await reader.nextJson()).uid).toBe(v2.uid);
    writer.json(push("gone-head", "", 0, 0, { deleted: true }));
    const gone = await writer.nextJson(); expect(await writer.nextJson()).toEqual({ res: "ok" });
    expect((await reader.nextJson()).uid).toBe(gone.uid);

    const fresh = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    fresh.json(init("Fresh", 0, true));
    expect(await fresh.nextJson()).toMatchObject({ res: "ok" });
    const snapshot: any[] = [];
    while (true) { const m = await fresh.nextJson(); if (m.op === "ready") { expect(m.version).toBe(gone.uid); break; } snapshot.push(m); }
    expect(snapshot.find((x) => x.path === "live-head")?.uid).toBe(v2.uid);
    expect(snapshot.some((x) => x.path === "gone-head")).toBe(false);

    const resumed = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    resumed.json(init("Resumed", baseVersion, false));
    expect(await resumed.nextJson()).toMatchObject({ res: "ok" });
    expect((await resumed.nextJson()).uid).toBe(v1.uid);
    expect((await resumed.nextJson()).uid).toBe(v2.uid);
    expect((await resumed.nextJson()).uid).toBe(gone.uid);
  }, 20_000);

  test("supports history, deletion, restore, purge, and cleans interrupted uploads", async () => {
    const probe = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(probe, "History device", 0, false);
    const a = await metadata(probe, "history-path", "history-v1");
    const b = await metadata(probe, "history-path", "history-v2");
    const tombstone = await metadata(probe, "history-path", "", { deleted: true });
    probe.json({ op: "deleted", suppressrenames: false });
    expect((await probe.nextJson()).items.some((x: any) => x.uid === tombstone.uid)).toBe(true);
    probe.json({ op: "history", path: "history-path", last: null });
    expect((await probe.nextJson()).items.slice(0, 3).map((x: any) => x.uid)).toEqual([tombstone.uid, b.uid, a.uid]);
    probe.json({ op: "restore", uid: tombstone.uid });
    const restored = await probe.nextJson();
    expect(restored).toMatchObject({ op: "push", hash: "history-v2", deleted: false });
    expect(await probe.nextJson()).toEqual({ res: "ok" });
    probe.json({ op: "purge" }); expect(await probe.nextJson()).toEqual({ res: "ok" });
    probe.json({ op: "history", path: "history-path", last: null });
    expect((await probe.nextJson()).items.map((x: any) => x.uid)).toEqual([restored.uid]);

    const interrupted = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(interrupted, "Interrupted", 0, false);
    interrupted.json(push("partial-path", "partial", 3 * 1024 * 1024, 2));
    expect(await interrupted.nextJson()).toEqual({ res: "next" });
    interrupted.socket.send(new Uint8Array(2 * 1024 * 1024));
    expect(await interrupted.nextJson()).toEqual({ res: "next" });
    interrupted.socket.close();
    await Bun.sleep(150);
    expect(await readdir(join(directory, "uploads"))).toEqual([]);
  });

  test("exposes safe health/metrics and produces verified live backups", async () => {
    expect(await (await fetch(`http://127.0.0.1:${controlPort}/health`)).json()).toMatchObject({
      implementation: "rust",
      service: "blackglass-server",
      version: "0.2.1",
    });
    expect((await fetch(`http://127.0.0.1:${controlPort}/ready`)).status).toBe(200);
    const errorsBeforeClose = metricValue(
      await (await fetch(`http://127.0.0.1:${controlPort}/metrics`)).text(),
      "blackglass_errors_total",
    );
    const normalClose = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(normalClose, "Normal close", 0, false);
    normalClose.socket.close();
    await Bun.sleep(100);
    const metrics = await (await fetch(`http://127.0.0.1:${controlPort}/metrics`)).text();
    expect(metrics).toContain("blackglass_upload_bytes_total");
    expect(metrics).toContain("obsidian_sync_upload_bytes_total");
    expect(metricValue(metrics, "blackglass_errors_total")).toBe(errorsBeforeClose);
    const backup = join(directory, "backup.sqlite");
    const command = Bun.spawnSync([join(root, "apps/server-rust/target/debug/blackglass-server"), "backup", join(directory, "server.sqlite"), backup], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(command.exitCode, command.stderr.toString()).toBe(0);
    expect((await stat(backup)).size).toBeGreaterThan(0);
    const verify = Bun.spawnSync([join(root, "apps/server-rust/target/debug/blackglass-server"), "verify", backup], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(verify.exitCode, verify.stderr.toString()).toBe(0);
  });

  test("rejects malformed and oversized protocol input without committing it", async () => {
    const probe = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(probe, "Input validator", 0, false);
    probe.socket.send("{");
    expect(await probe.nextJson()).toEqual({ res: "err", msg: "Invalid JSON" });
    probe.json(push("oversized-path", "oversized", 9 * 1024 * 1024, 5));
    expect(await probe.nextJson()).toEqual({ err: "Invalid push metadata" });
    probe.json({ op: "history", path: "" });
    expect(await probe.nextJson()).toEqual({ err: "Invalid history path" });
  });

  test("revokes a session on signout", async () => {
    const signin = await post("/user/signin", { email: "owner@example.test", password: "test-password" });
    expect(await post("/user/signout", { token: signin.token })).toEqual({});
    expect(await post("/user/info", { token: signin.token })).toEqual({ error: "Not logged in" });
    for (let attempt = 0; attempt < 8; attempt++) {
      expect(await post("/user/signin", { email: "owner@example.test", password: "wrong" })).toEqual({ error: "Invalid email or password" });
    }
    expect(await post("/user/signin", { email: "owner@example.test", password: "wrong" })).toEqual({ error: "Try again later" });
  }, 20_000);
});

function push(path: string, hash: string, size: number, pieces: number, extra: Record<string, unknown> = {}) { return { op: "push", path, relatedpath: null, extension: "md", hash, ctime: 1_700_000_000_000, mtime: 1_700_000_000_100, folder: false, deleted: false, size, pieces, ...extra }; }
function init(device: string, version: number, initial: boolean) { return { op: "init", token, id: vault.id, keyhash: vault.keyhash, version, initial, device, encryption_version: vault.encryption_version }; }
async function initialize(probe: Probe, device: string, version: number, initial: boolean) { probe.json(init(device, version, initial)); expect(await probe.nextJson()).toMatchObject({ res: "ok", userId: 1 }); while (true) { const message = await probe.nextJson(); if (message.op === "ready") return; } }
async function currentReady(probe: Probe, device: string) { probe.json(init(device, 0, false)); expect(await probe.nextJson()).toMatchObject({ res: "ok" }); while (true) { const m = await probe.nextJson(); if (m.op === "ready") return m; } }
async function metadata(probe: Probe, path: string, hash: string, extra: Record<string, unknown> = {}) { probe.json(push(path, hash, 0, 0, extra)); const n = await probe.nextJson(); expect(n).toMatchObject({ op: "push", path }); expect(await probe.nextJson()).toEqual({ res: "ok" }); return n; }
async function post(path: string, body: Record<string, unknown>) { const response = await fetch(`http://127.0.0.1:${controlPort}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: "app://obsidian.md" }, body: JSON.stringify(body) }); return response.json(); }
function metricValue(metrics: string, name: string): number { const line = metrics.split("\n").find((entry) => entry.startsWith(`${name} `)); if (!line) throw new Error(`missing metric: ${name}`); return Number(line.slice(name.length + 1)); }
async function waitForHealth() { const deadline = Date.now() + 30_000; while (Date.now() < deadline) { if (processHandle.exitCode !== null) throw new Error(`server exited early: ${await new Response(processHandle.stderr as ReadableStream<Uint8Array>).text()}`); try { if ((await fetch(`http://127.0.0.1:${controlPort}/health`)).ok) return; } catch {} await Bun.sleep(50); } throw new Error("Rust server did not become healthy"); }
async function freePort(): Promise<number> { return new Promise((resolve, reject) => { const server = createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const address = server.address(); if (!address || typeof address === "string") return reject(new Error("no port")); server.close(() => resolve(address.port)); }); }); }

class Probe {
  private queue: unknown[] = []; private waiters: Array<(v: unknown) => void> = [];
  private constructor(readonly socket: WebSocket) { socket.binaryType = "arraybuffer"; socket.addEventListener("message", (e) => { const v = typeof e.data === "string" ? JSON.parse(e.data) : e.data; const waiter = this.waiters.shift(); waiter ? waiter(v) : this.queue.push(v); }); }
  static connect(url: string, origin?: string): Promise<Probe> { return new Promise((resolve, reject) => { const ws = origin ? new WebSocket(url, { headers: { Origin: origin } } as any) : new WebSocket(url); sockets.push(ws); const probe = new Probe(ws); ws.addEventListener("open", () => resolve(probe), { once: true }); ws.addEventListener("error", () => reject(new Error("websocket failed")), { once: true }); }); }
  json(v: Record<string, unknown>) { this.socket.send(JSON.stringify(v)); }
  async nextJson(): Promise<any> { const value = await this.next(); if (value instanceof ArrayBuffer) throw new Error("expected JSON"); return value; }
  async nextBinary(): Promise<ArrayBuffer> { const value = await this.next(); if (!(value instanceof ArrayBuffer)) throw new Error(`expected binary: ${JSON.stringify(value)}`); return value; }
  private next(): Promise<unknown> { if (this.queue.length) return Promise.resolve(this.queue.shift()); return new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error("websocket timeout")), 5_000); this.waiters.push((v) => { clearTimeout(timer); resolve(v); }); }); }
}
