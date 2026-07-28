import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createServer } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Database } from "bun:sqlite";

const root = resolve(import.meta.dir, "..");
const manifest = join(root, "apps/server-rust/Cargo.toml");
const binary = join(root, "apps/server-rust/target/debug/blackglass-server");
const perFileMax = 8 * 1024 * 1024;
const aesGcmWireOverhead = 12 + 16;
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
    const version = Bun.spawnSync([binary, "--version"], { stdout: "pipe", stderr: "pipe" });
    expect(version.exitCode, version.stderr.toString()).toBe(0);
    expect(version.stdout.toString().trim()).toBe("blackglass-server 0.2.1");
    const help = Bun.spawnSync([binary, "--help"], { stdout: "pipe", stderr: "pipe" });
    expect(help.exitCode, help.stderr.toString()).toBe(0);
    expect(help.stdout.toString()).toContain("backup <database> <output>");
    expect(help.stdout.toString()).toContain("migrate-legacy <legacy-database> <new-database>");
    directory = await mkdtemp(join(tmpdir(), "obsidian-rust-sync-"));
    [controlPort, dataPort] = await Promise.all([freePort(), freePort()]);
    processHandle = spawnRustServer(directory, controlPort, dataPort, {
      SELFHOST_ALLOWED_ORIGIN: "",
      SELFHOST_ALLOWED_ORIGINS: "app://obsidian.md,http://localhost",
    });
    await waitForHealthAt(controlPort, processHandle);
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

  test("uses expiring sessions, client-managed E2EE vaults, and exact origins", async () => {
    expect(vault).toMatchObject({
      host: `127.0.0.1:${dataPort}`,
      keyhash: "opaque-key-hash",
      salt: "opaque-salt",
      encryption_version: 3,
      size: 0,
    });
    expect(vault.password).toBeUndefined();
    const listed = await post("/vault/list", { token });
    expect(listed.vaults).toHaveLength(1);
    const rejected = await fetch(`http://127.0.0.1:${controlPort}/user/info`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil.example" },
      body: JSON.stringify({ token }),
    });
    expect(rejected.status).toBe(403);
    const missing = await fetch(`http://127.0.0.1:${controlPort}/user/info`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    expect(missing.status).toBe(403);
    await expectWebSocketRejected(`ws://127.0.0.1:${dataPort}`, null);
    await expectWebSocketRejected(`ws://127.0.0.1:${dataPort}`, "https://evil.example");

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

  test("persists managed-encryption credentials and first-device binding across restart", async () => {
    const managedDirectory = await mkdtemp(join(tmpdir(), "blackglass-managed-restart-"));
    const [managedControlPort, managedDataPort] = await Promise.all([freePort(), freePort()]);
    let child = spawnRustServer(managedDirectory, managedControlPort, managedDataPort);
    try {
      await waitForHealthAt(managedControlPort, child);
      const signin = await postAt(managedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const created = await postAt(managedControlPort, "/vault/create", {
        token: signin.token,
        name: "Managed vault",
        keyhash: null,
        salt: null,
        region: "selfhost",
        encryption_version: 3,
      });
      expect(created).toMatchObject({
        keyhash: null,
        host: `127.0.0.1:${managedDataPort}`,
        encryption_version: 3,
      });
      expect(created.password).toMatch(/^[0-9a-f]{64}$/);
      expect(created.salt).toMatch(/^[0-9a-f]{32}$/);

      const derivedKeyhash = "client-derived-managed-keyhash";
      expect(await postAt(managedControlPort, "/vault/access", {
        token: signin.token,
        vault_uid: created.id,
        keyhash: derivedKeyhash,
        host: created.host,
        encryption_version: created.encryption_version,
      })).toEqual({});
      expect(await postAt(managedControlPort, "/vault/access", {
        token: signin.token,
        vault_uid: created.id,
        keyhash: "conflicting-keyhash",
        host: created.host,
        encryption_version: created.encryption_version,
      })).toEqual({ error: "Unable to access vault" });

      const beforeRestart = await postAt(managedControlPort, "/vault/list", {
        token: signin.token,
      });
      expect(beforeRestart.vaults[0]).toMatchObject({
        id: created.id,
        keyhash: derivedKeyhash,
        password: created.password,
        salt: created.salt,
      });

      child.kill("SIGTERM");
      await child.exited;
      child = spawnRustServer(managedDirectory, managedControlPort, managedDataPort);
      await waitForHealthAt(managedControlPort, child);

      const secondSignin = await postAt(managedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const afterRestart = await postAt(managedControlPort, "/vault/list", {
        token: secondSignin.token,
      });
      expect(afterRestart.vaults[0]).toMatchObject({
        id: created.id,
        keyhash: derivedKeyhash,
        password: created.password,
        salt: created.salt,
      });
      expect(await postAt(managedControlPort, "/vault/access", {
        token: secondSignin.token,
        vault_uid: created.id,
        keyhash: derivedKeyhash,
        host: created.host,
        encryption_version: created.encryption_version,
      })).toEqual({});

      const secondDevice = await Probe.connect(`ws://127.0.0.1:${managedDataPort}`);
      secondDevice.json({
        op: "init",
        token: secondSignin.token,
        id: created.id,
        keyhash: derivedKeyhash,
        version: 0,
        initial: true,
        device: "Managed second device",
        encryption_version: created.encryption_version,
      });
      expect(await secondDevice.nextJson()).toMatchObject({
        res: "ok",
        userId: 1,
        perFileMax,
      });
      expect(await secondDevice.nextJson()).toEqual({ op: "ready", version: 0 });
      secondDevice.socket.close();
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 30_000);

  test("bounds unauthenticated WebSockets and requires prompt initialization", async () => {
    const unauthenticatedPing = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    unauthenticatedPing.json({ op: "ping" });
    expect((await waitForClose(unauthenticatedPing, 2_000)).code).toBe(1008);

    const idle = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    const idleClose = await waitForClose(idle, 7_000);
    expect(idleClose.code).toBe(1008);
    expect(idleClose.reason).toContain("Authentication deadline");

    const cappedDirectory = await mkdtemp(join(tmpdir(), "blackglass-ws-cap-"));
    const [cappedControlPort, cappedDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(cappedDirectory, cappedControlPort, cappedDataPort, {
      SELFHOST_MAX_WS_CONNECTIONS: "2",
    });
    try {
      await waitForHealthAt(cappedControlPort, child);
      const first = await Probe.connect(`ws://127.0.0.1:${cappedDataPort}`);
      const second = await Probe.connect(`ws://127.0.0.1:${cappedDataPort}`);
      await expectWebSocketRejected(`ws://127.0.0.1:${cappedDataPort}`, "app://obsidian.md");
      first.socket.close();
      await waitForClose(first, 2_000);
      const replacement = await Probe.connect(`ws://127.0.0.1:${cappedDataPort}`);
      second.socket.close();
      replacement.socket.close();
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 20_000);

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

  test("advertises plaintext perFileMax and accepts the 28-byte AES-GCM wire overhead", async () => {
    const belowBoundary = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    belowBoundary.json(init("Boundary below max", 0, false));
    expect(await belowBoundary.nextJson()).toMatchObject({ res: "ok", perFileMax });
    while ((await belowBoundary.nextJson()).op !== "ready") {}
    const maxMinusOneWireSize = perFileMax - 1 + aesGcmWireOverhead;
    belowBoundary.json(push(
      "ciphertext-max-minus-one",
      "boundary-max-minus-one",
      maxMinusOneWireSize,
      piecesFor(maxMinusOneWireSize),
    ));
    expect(await belowBoundary.nextJson()).toEqual({ res: "next" });
    belowBoundary.socket.close();

    const atBoundary = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(atBoundary, "Boundary at max", 0, false);
    const maxWireSize = perFileMax + aesGcmWireOverhead;
    const accepted = await uploadOpaqueCiphertext(
      atBoundary,
      "ciphertext-max",
      "boundary-max",
      maxWireSize,
    );
    expect(accepted).toMatchObject({
      op: "push",
      path: "ciphertext-max",
      size: maxWireSize,
    });

    const overBoundary = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(overBoundary, "Boundary over max", accepted.uid, false);
    const maxPlusOneWireSize = perFileMax + 1 + aesGcmWireOverhead;
    overBoundary.json(push(
      "ciphertext-max-plus-one",
      "boundary-max-plus-one",
      maxPlusOneWireSize,
      piecesFor(maxPlusOneWireSize),
    ));
    expect(await overBoundary.nextJson()).toEqual({ err: "Invalid push metadata" });

    atBoundary.socket.close();
    overBoundary.socket.close();
  }, 30_000);

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

  test("publishes concurrent commits in UID order while origins apply backpressure", async () => {
    const writerA = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    const writerB = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    const observer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(writerA, "Ordered writer A", 0, false);
    await initialize(writerB, "Ordered writer B", 0, false);
    const baseVersion = (await currentReady(observer, "Ordered observer")).version;
    const revisionsPerWriter = 128;

    // Pipeline both writers without consuming either origin's replies. The
    // independent observer must still receive one strictly ordered stream.
    for (let index = 0; index < revisionsPerWriter; index++) {
      writerA.json(push(`ordered-a-${index}`, `hash-a-${index}`, 0, 0));
      writerB.json(push(`ordered-b-${index}`, `hash-b-${index}`, 0, 0));
    }

    const observed: any[] = [];
    for (let index = 0; index < revisionsPerWriter * 2; index++) {
      const notice = await observer.nextJson();
      expect(notice.op).toBe("push");
      expect(notice.path.startsWith("ordered-")).toBe(true);
      observed.push(notice);
    }
    const observedUids = observed.map((notice) => notice.uid as number);
    expect(new Set(observedUids).size).toBe(observedUids.length);
    expect(observedUids.every((uid, index) => index === 0 || uid > observedUids[index - 1]!)).toBe(true);

    const [writerAUids, writerBUids] = await Promise.all([
      drainCommitResponses(writerA, revisionsPerWriter, observedUids.at(-1)!),
      drainCommitResponses(writerB, revisionsPerWriter, observedUids.at(-1)!),
    ]);
    expect(writerAUids).toEqual(observedUids);
    expect(writerBUids).toEqual(observedUids);

    const resumed = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    resumed.json(init("Ordered resume verifier", baseVersion, false));
    expect(await resumed.nextJson()).toMatchObject({ res: "ok" });
    const replayed: any[] = [];
    while (true) {
      const message = await resumed.nextJson();
      if (message.op === "ready") {
        expect(message.version).toBe(observedUids.at(-1));
        break;
      }
      replayed.push(message);
    }
    expect(replayed.map((notice) => notice.uid)).toEqual(observedUids);
    expect(new Set(replayed.map((notice) => notice.path))).toEqual(
      new Set(observed.map((notice) => notice.path)),
    );

    const fresh = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    fresh.json(init("Ordered snapshot verifier", 0, true));
    expect(await fresh.nextJson()).toMatchObject({ res: "ok" });
    const snapshot: any[] = [];
    while (true) {
      const message = await fresh.nextJson();
      if (message.op === "ready") {
        expect(message.version).toBe(observedUids.at(-1));
        break;
      }
      snapshot.push(message);
    }
    expect(snapshot.filter((notice) => notice.path.startsWith("ordered-")).map((notice) => notice.uid)).toEqual(observedUids);

    writerA.socket.close();
    writerB.socket.close();
    observer.socket.close();
    resumed.socket.close();
    fresh.socket.close();
  }, 30_000);

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

  test("revalidates active WebSockets after signout, expiration, and events", async () => {
    const head = databaseVersion(join(directory, "server.sqlite"), vault.id);

    const idleSignin = await post("/user/signin", { email: "owner@example.test", password: "test-password" });
    const idle = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initializeFor(idle, idleSignin.token, vault, "Idle revoked session", head, false);
    expect(await post("/user/signout", { token: idleSignin.token })).toEqual({});
    expect((await waitForClose(idle, 7_000)).code).toBe(1008);

    const expiringSignin = await post("/user/signin", { email: "owner@example.test", password: "test-password" });
    const expiring = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initializeFor(expiring, expiringSignin.token, vault, "Expired session", head, false);
    expireSession(join(directory, "server.sqlite"), expiringSignin.token);
    expiring.json({ op: "ping" });
    expect((await waitForClose(expiring, 2_000)).code).toBe(1008);

    const observerSignin = await post("/user/signin", { email: "owner@example.test", password: "test-password" });
    const observer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    const writer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initializeFor(observer, observerSignin.token, vault, "Event-revoked observer", head, false);
    await initialize(writer, "Event writer", head, false);
    expect(await post("/user/signout", { token: observerSignin.token })).toEqual({});
    writer.json(push("session-revalidation-event", "session-revalidation", 0, 0));
    expect(await writer.nextJson()).toMatchObject({ op: "push", path: "session-revalidation-event" });
    expect(await writer.nextJson()).toEqual({ res: "ok" });
    expect((await waitForClose(observer, 2_000)).code).toBe(1008);
    writer.socket.close();
  }, 20_000);

  test("keeps a single-worker runtime responsive, honors admin revocation, and shuts down gracefully", async () => {
    const isolatedDirectory = await mkdtemp(join(tmpdir(), "blackglass-reactor-"));
    const [isolatedControlPort, isolatedDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(isolatedDirectory, isolatedControlPort, isolatedDataPort, {
      TOKIO_WORKER_THREADS: "1",
    });
    try {
      await waitForHealthAt(isolatedControlPort, child);
      const signin = await postAt(isolatedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const isolatedVault = await postAt(isolatedControlPort, "/vault/create", {
        token: signin.token,
        name: "Reactor vault",
        keyhash: "reactor-keyhash",
        salt: "reactor-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      const probe = await Probe.connect(`ws://127.0.0.1:${isolatedDataPort}`);
      await initializeFor(probe, signin.token, isolatedVault, "Reactor probe", 0, true);

      const lock = new Database(join(isolatedDirectory, "server.sqlite"));
      lock.exec("BEGIN IMMEDIATE");
      try {
        probe.json(push("blocked-database-write", "blocked-write", 0, 0));
        await Bun.sleep(100);
        const started = performance.now();
        const response = await promiseWithTimeout(
          fetch(`http://127.0.0.1:${isolatedControlPort}/health`),
          750,
          "health endpoint stalled behind SQLite",
        );
        expect(response.status).toBe(200);
        expect(performance.now() - started).toBeLessThan(750);
      } finally {
        lock.exec("ROLLBACK");
        lock.close();
      }
      expect(await probe.nextJson()).toMatchObject({ op: "push", path: "blocked-database-write" });
      expect(await probe.nextJson()).toEqual({ res: "ok" });

      const revoke = Bun.spawnSync([binary, "revoke-all-sessions", join(isolatedDirectory, "server.sqlite")], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(revoke.exitCode, revoke.stderr.toString()).toBe(0);
      expect(revoke.stdout.toString()).toContain("revoked sessions: 1");
      probe.json({ op: "ping" });
      expect((await waitForClose(probe, 2_000)).code).toBe(1008);

      const shutdownSignin = await postAt(isolatedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const head = databaseVersion(join(isolatedDirectory, "server.sqlite"), isolatedVault.id);
      const committing = await Probe.connect(`ws://127.0.0.1:${isolatedDataPort}`);
      const idle = await Probe.connect(`ws://127.0.0.1:${isolatedDataPort}`);
      await initializeFor(committing, shutdownSignin.token, isolatedVault, "Shutdown writer", head, false);
      await initializeFor(idle, shutdownSignin.token, isolatedVault, "Shutdown idle", head, false);

      const shutdownLock = new Database(join(isolatedDirectory, "server.sqlite"));
      shutdownLock.exec("BEGIN IMMEDIATE");
      try {
        committing.json(push("shutdown-committed-write", "shutdown-committed", 0, 0));
        await Bun.sleep(100);
        child.kill("SIGTERM");
        committing.json(push("shutdown-queued-write", "shutdown-queued", 0, 0));
        const idleClose = await waitForClose(idle, 2_000);
        // Bun 1.3 reports a peer's Going Away (1001) close as Normal (1000),
        // while retaining the server reason. Accept that client-runtime quirk.
        expect([1000, 1001]).toContain(idleClose.code);
        expect(idleClose.reason).toBe("Server shutting down");
        expect(child.exitCode).toBeNull();
      } finally {
        shutdownLock.exec("ROLLBACK");
        shutdownLock.close();
      }
      expect(await promiseWithTimeout(child.exited, 5_000, "server did not finish graceful shutdown")).toBe(0);
      await waitForClose(committing, 2_000);
      const persisted = new Database(join(isolatedDirectory, "server.sqlite"));
      try {
        expect((persisted.query("SELECT COUNT(*) AS count FROM revisions WHERE path='shutdown-committed-write'").get() as { count: number }).count).toBe(1);
        expect((persisted.query("SELECT COUNT(*) AS count FROM revisions WHERE path='shutdown-queued-write'").get() as { count: number }).count).toBe(0);
      } finally {
        persisted.close();
      }
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 20_000);

  test("failed signins do not create a globally exhaustible lockout", async () => {
    const signin = await post("/user/signin", { email: "owner@example.test", password: "test-password" });
    expect(await post("/user/signout", { token: signin.token })).toEqual({});
    expect(await post("/user/info", { token: signin.token })).toEqual({ error: "Not logged in" });
    for (let attempt = 0; attempt < 12; attempt++) {
      expect(await post("/user/signin", { email: "owner@example.test", password: "wrong" })).toEqual({ error: "Invalid email or password" });
    }
    expect(await post("/user/signin", { email: "owner@example.test", password: "test-password" })).toMatchObject({
      email: "owner@example.test",
      license: "selfhosted-sync",
    });
  }, 20_000);
});

function push(path: string, hash: string, size: number, pieces: number, extra: Record<string, unknown> = {}) { return { op: "push", path, relatedpath: null, extension: "md", hash, ctime: 1_700_000_000_000, mtime: 1_700_000_000_100, folder: false, deleted: false, size, pieces, ...extra }; }
function init(device: string, version: number, initial: boolean) { return initFor(token, vault, device, version, initial); }
function initFor(sessionToken: string, targetVault: Record<string, any>, device: string, version: number, initial: boolean) { return { op: "init", token: sessionToken, id: targetVault.id, keyhash: targetVault.keyhash, version, initial, device, encryption_version: targetVault.encryption_version }; }
async function initialize(probe: Probe, device: string, version: number, initial: boolean) { probe.json(init(device, version, initial)); expect(await probe.nextJson()).toMatchObject({ res: "ok", userId: 1 }); while (true) { const message = await probe.nextJson(); if (message.op === "ready") return; } }
async function initializeFor(probe: Probe, sessionToken: string, targetVault: Record<string, any>, device: string, version: number, initial: boolean) { probe.json(initFor(sessionToken, targetVault, device, version, initial)); expect(await probe.nextJson()).toMatchObject({ res: "ok", userId: 1 }); while (true) { const message = await probe.nextJson(); if (message.op === "ready") return; } }
async function currentReady(probe: Probe, device: string) { probe.json(init(device, 0, false)); expect(await probe.nextJson()).toMatchObject({ res: "ok" }); while (true) { const m = await probe.nextJson(); if (m.op === "ready") return m; } }
async function metadata(probe: Probe, path: string, hash: string, extra: Record<string, unknown> = {}) { probe.json(push(path, hash, 0, 0, extra)); const n = await probe.nextJson(); expect(n).toMatchObject({ op: "push", path }); expect(await probe.nextJson()).toEqual({ res: "ok" }); return n; }
async function drainCommitResponses(probe: Probe, expected: number, finalUid: number) {
  let committed = 0;
  const uids: number[] = [];
  while (committed < expected || uids.at(-1) !== finalUid) {
    const message = await probe.nextJson();
    if (message.res === "ok") committed++;
    if (message.op === "push") uids.push(message.uid);
  }
  return uids;
}
function piecesFor(size: number) { return Math.ceil(size / (2 * 1024 * 1024)); }
async function uploadOpaqueCiphertext(probe: Probe, path: string, hash: string, size: number) {
  probe.json(push(path, hash, size, piecesFor(size)));
  expect(await probe.nextJson()).toEqual({ res: "next" });
  let offset = 0;
  while (offset < size) {
    const length = Math.min(2 * 1024 * 1024, size - offset);
    probe.socket.send(new Uint8Array(length));
    offset += length;
    if (offset < size) expect(await probe.nextJson()).toEqual({ res: "next" });
  }
  const notice = await probe.nextJson();
  expect(await probe.nextJson()).toEqual({ res: "ok" });
  return notice;
}
function spawnRustServer(serviceDirectory: string, serviceControlPort: number, serviceDataPort: number, overrides: Record<string, string> = {}) {
  return Bun.spawn([binary, "serve"], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...process.env,
      SELFHOST_BIND_HOST: "127.0.0.1",
      SELFHOST_CONTROL_PORT: String(serviceControlPort),
      SELFHOST_DATA_PORT: String(serviceDataPort),
      SELFHOST_DATA_HOST: `127.0.0.1:${serviceDataPort}`,
      SELFHOST_DATABASE: join(serviceDirectory, "server.sqlite"),
      SELFHOST_STAGING_DIR: join(serviceDirectory, "uploads"),
      SELFHOST_EMAIL: "owner@example.test",
      SELFHOST_PASSWORD: "test-password",
      SELFHOST_ALLOW_PLAINTEXT_PASSWORD: "1",
      SELFHOST_NAME: "Rust test owner",
      SELFHOST_PER_FILE_MAX: String(perFileMax),
      SELFHOST_ALLOWED_ORIGIN: "app://obsidian.md",
      SELFHOST_LOG_FORMAT: "pretty",
      ...overrides,
    },
  });
}
async function post(path: string, body: Record<string, unknown>) { return postAt(controlPort, path, body); }
async function postAt(port: number, path: string, body: Record<string, unknown>) { const response = await fetch(`http://127.0.0.1:${port}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: "app://obsidian.md" }, body: JSON.stringify(body) }); return response.json(); }
function metricValue(metrics: string, name: string): number { const line = metrics.split("\n").find((entry) => entry.startsWith(`${name} `)); if (!line) throw new Error(`missing metric: ${name}`); return Number(line.slice(name.length + 1)); }
async function waitForHealthAt(port: number, child: ReturnType<typeof Bun.spawn>) { const deadline = Date.now() + 30_000; while (Date.now() < deadline) { if (child.exitCode !== null) throw new Error(`server exited early: ${await new Response(child.stderr as ReadableStream<Uint8Array>).text()}`); try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) return; } catch {} await Bun.sleep(50); } throw new Error("Rust server did not become healthy"); }
async function freePort(): Promise<number> { return new Promise((resolve, reject) => { const server = createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const address = server.address(); if (!address || typeof address === "string") return reject(new Error("no port")); server.close(() => resolve(address.port)); }); }); }

function databaseVersion(path: string, vaultId: string): number { const database = new Database(path, { readonly: true }); try { return (database.query("SELECT version FROM vaults WHERE id=?").get(vaultId) as { version: number }).version; } finally { database.close(); } }
function expireSession(path: string, sessionToken: string) { const database = new Database(path); try { const hash = createHash("sha256").update(sessionToken).digest("hex"); expect(database.query("UPDATE sessions SET expires_at=0 WHERE token_hash=?").run(hash).changes).toBe(1); } finally { database.close(); } }
async function promiseWithTimeout<T>(promise: Promise<T>, milliseconds: number, message: string): Promise<T> { return Promise.race([promise, new Promise<T>((_, reject) => setTimeout(() => reject(new Error(message)), milliseconds))]); }
async function waitForClose(probe: Probe, milliseconds: number) { return promiseWithTimeout(probe.closed, milliseconds, "websocket did not close"); }
function webSocketWithOrigin(url: string, origin: string) { return new WebSocket(url, { headers: { Origin: origin } } as unknown as string[]); }
async function expectWebSocketRejected(url: string, origin: string | null) { await new Promise<void>((resolveRejected, reject) => { const socket = origin === null ? new WebSocket(url) : webSocketWithOrigin(url, origin); const timer = setTimeout(() => { socket.close(); reject(new Error("websocket rejection timed out")); }, 2_000); let opened = false; socket.addEventListener("open", () => { opened = true; clearTimeout(timer); socket.close(); reject(new Error("websocket unexpectedly opened")); }, { once: true }); socket.addEventListener("error", () => { if (!opened) { clearTimeout(timer); resolveRejected(); } }, { once: true }); socket.addEventListener("close", () => { if (!opened) { clearTimeout(timer); resolveRejected(); } }, { once: true }); }); }

class Probe {
  private queue: unknown[] = []; private waiters: Array<(v: unknown) => void> = [];
  readonly closed: Promise<{ code: number; reason: string }>;
  private constructor(readonly socket: WebSocket) { this.closed = new Promise((resolveClosed) => socket.addEventListener("close", (event) => resolveClosed({ code: event.code, reason: event.reason }), { once: true })); socket.binaryType = "arraybuffer"; socket.addEventListener("message", (e) => { const v = typeof e.data === "string" ? JSON.parse(e.data) : e.data; const waiter = this.waiters.shift(); waiter ? waiter(v) : this.queue.push(v); }); }
  static connect(url: string, origin = "app://obsidian.md"): Promise<Probe> { return new Promise((resolve, reject) => { const ws = webSocketWithOrigin(url, origin); sockets.push(ws); const probe = new Probe(ws); ws.addEventListener("open", () => resolve(probe), { once: true }); ws.addEventListener("error", () => reject(new Error("websocket failed")), { once: true }); }); }
  json(v: Record<string, unknown>) { this.socket.send(JSON.stringify(v)); }
  async nextJson(): Promise<any> { const value = await this.next(); if (value instanceof ArrayBuffer) throw new Error("expected JSON"); return value; }
  async nextBinary(): Promise<ArrayBuffer> { const value = await this.next(); if (!(value instanceof ArrayBuffer)) throw new Error(`expected binary: ${JSON.stringify(value)}`); return value; }
  private next(): Promise<unknown> { if (this.queue.length) return Promise.resolve(this.queue.shift()); return new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error("websocket timeout")), 5_000); this.waiters.push((v) => { clearTimeout(timer); resolve(v); }); }); }
}
