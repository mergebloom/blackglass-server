import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createConnection, createServer } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Database } from "bun:sqlite";

const root = resolve(import.meta.dir, "..");
const manifest = join(root, "apps/server-rust/Cargo.toml");
const packageVersion = readFileSync(manifest, "utf8").match(/\[package\][\s\S]*?^version = "([^"]+)"/m)?.[1];
if (!packageVersion) throw new Error("unable to read Rust package version");
const configuredBinary = process.env.BLACKGLASS_RUST_BINARY;
const binary = configuredBinary ?? join(root, "apps/server-rust/target/debug/blackglass-server");
const perFileMax = 8 * 1024 * 1024;
const aesGcmWireOverhead = 12 + 16;
const maximumWorkPasswordHash =
  "$argon2id$v=19$m=65536,t=5,p=4$YmxhY2tnbGFzcy1yZXNvdXJjZS1lbnZlbG9wZS12MQ$qF1GQ0hLTNgx8hhl7Qo3R7r1pSYB+eYXdX4KtmWP5VI";
let directory = "";
let controlPort = 0;
let dataPort = 0;
let processHandle: ReturnType<typeof Bun.spawn>;
let token = "";
let vault: Record<string, any>;
const sockets: WebSocket[] = [];

describe("production Rust server", () => {
  beforeAll(async () => {
    if (!configuredBinary) {
      const build = Bun.spawnSync(["cargo", "build", "--manifest-path", manifest], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
      });
      if (build.exitCode !== 0) throw new Error(build.stderr.toString());
    }
    const version = Bun.spawnSync([binary, "--version"], { stdout: "pipe", stderr: "pipe" });
    expect(version.exitCode, version.stderr.toString()).toBe(0);
    expect(version.stdout.toString().trim()).toBe(`blackglass-server ${packageVersion}`);
    const buildInfo = Bun.spawnSync([binary, "build-info"], { stdout: "pipe", stderr: "pipe" });
    expect(buildInfo.exitCode, buildInfo.stderr.toString()).toBe(0);
    expect(JSON.parse(buildInfo.stdout.toString())).toMatchObject({
      name: "blackglass-server",
      version: packageVersion,
      sourceRevision: process.env.BLACKGLASS_EXPECTED_SOURCE_REVISION ?? "unknown",
    });
    const help = Bun.spawnSync([binary, "--help"], { stdout: "pipe", stderr: "pipe" });
    expect(help.exitCode, help.stderr.toString()).toBe(0);
    expect(help.stdout.toString()).toContain("backup <database> <output>");
    expect(help.stdout.toString()).toContain("migrate <versioned-database> <new-database>");
    expect(help.stdout.toString()).toContain("migrate-legacy <legacy-database> <new-database>");
    expect(help.stdout.toString()).toContain("rebind-data-host <database> <new-host> <backup>");
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
      license: null,
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
    expect(await post("/user/info", { token })).toMatchObject({
      email: "owner@example.test",
      license: null,
    });
    expect(await post("/subscription/list", { token })).toEqual({ sync: true, publish: false });
    for (const path of [
      "/user/pow-challenge",
      "/user/signup",
      "/user/forgetpass",
      "/user/resendconfirmation",
    ]) {
      expect(await post(path, {})).toEqual({
        error: "Accounts are managed by the Blackglass Server administrator",
      });
    }
    const signup = await fetch(`http://127.0.0.1:${controlPort}/user/signup`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost" },
      body: "{}",
    });
    expect(signup.headers.get("access-control-allow-origin")).toBe("http://localhost");
    expect(await signup.json()).toEqual({
      error: "Accounts are managed by the Blackglass Server administrator",
    });
    expect(await post("/subscription/business", { token })).toEqual({
      error: "Business subscriptions are unavailable on a self-hosted server",
    });
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

  test("returns explicit CORS JSON errors for recognized unsupported client routes", async () => {
    const routes = [
      ["/publish/create", "Publish is unavailable on a self-hosted server"],
      ["/publish/delete", "Publish is unavailable on a self-hosted server"],
      ["/publish/list", "Publish is unavailable on a self-hosted server"],
      ["/publish/share/accept", "Publish is unavailable on a self-hosted server"],
      ["/publish/share/invite", "Publish is unavailable on a self-hosted server"],
      ["/publish/share/list", "Publish is unavailable on a self-hosted server"],
      ["/publish/share/remove", "Publish is unavailable on a self-hosted server"],
      [
        "/subscription/sync/signup-mobile",
        "Mobile Sync signup is unavailable on a self-hosted server",
      ],
      ["/user/pow-challenge", "Accounts are managed by the Blackglass Server administrator"],
      ["/user/authtoken", "Accounts are managed by the Blackglass Server administrator"],
    ] as const;

    for (const [path, error] of routes) {
      const response = await fetch(`http://127.0.0.1:${controlPort}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://localhost" },
        body: JSON.stringify({ token }),
      });
      expect(response.status).toBe(200);
      expect(response.headers.get("access-control-allow-origin")).toBe("http://localhost");
      expect(response.headers.get("vary")).toBe("Origin");
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("content-type")).toContain("application/json");
      expect(await response.json()).toEqual({ error });

      const preflight = await fetch(`http://127.0.0.1:${controlPort}${path}`, {
        method: "OPTIONS",
        headers: { origin: "http://localhost" },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get("access-control-allow-origin")).toBe("http://localhost");
      expect(preflight.headers.get("access-control-allow-methods")).toBe("POST, GET, OPTIONS");
      expect(preflight.headers.get("access-control-allow-headers")).toBe("content-type");
    }

    for (const method of ["POST", "OPTIONS"]) {
      const unknown = await fetch(`http://127.0.0.1:${controlPort}/publish/unknown`, {
        method,
        headers: { "content-type": "application/json", origin: "http://localhost" },
        ...(method === "POST" ? { body: JSON.stringify({ token }) } : {}),
      });
      expect(unknown.status).toBe(404);
    }
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

  test("migrates legacy encryption atomically, invalidates old sockets, and supports v3 recovery", async () => {
    const migrationDirectory = await mkdtemp(join(tmpdir(), "blackglass-vault-migrate-"));
    const [migrationControlPort, migrationDataPort] = await Promise.all([freePort(), freePort()]);
    let child = spawnRustServer(migrationDirectory, migrationControlPort, migrationDataPort);
    try {
      await waitForHealthAt(migrationControlPort, child);
      let signin = await postAt(migrationControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const legacy = await postAt(migrationControlPort, "/vault/create", {
        token: signin.token,
        name: "Legacy custom vault",
        keyhash: "legacy-key",
        salt: "legacy-salt",
        region: "selfhost",
        encryption_version: 2,
      });
      const oldSocket = await Probe.connect(`ws://127.0.0.1:${migrationDataPort}`);
      await initializeFor(oldSocket, signin.token, legacy, "Legacy device", 0, true);
      oldSocket.json(push("old-history", "old-history-hash", 0, 0));
      expect(await oldSocket.nextJson()).toMatchObject({ op: "push", path: "old-history" });
      expect(await oldSocket.nextJson()).toEqual({ res: "ok" });

      expect(await postAt(migrationControlPort, "/vault/migrate", {
        token: signin.token,
        vault_uid: legacy.id,
        keyhash: "incomplete-new-key",
        salt: null,
        region: "selfhost",
        encryption_version: 3,
      })).toEqual({ error: "Invalid encryption credentials" });
      oldSocket.json({ op: "ping" });
      expect(await oldSocket.nextJson()).toEqual({ op: "pong" });

      const unfinished = new TextEncoder().encode("unfinished ciphertext");
      oldSocket.json(push("pending-during-migration", "pending-hash", unfinished.length, 1));
      expect(await oldSocket.nextJson()).toEqual({ res: "next" });
      expect(await stagedParts(join(migrationDirectory, "uploads"))).toHaveLength(1);
      const replacement = await postAt(migrationControlPort, "/vault/migrate", {
        token: signin.token,
        vault_uid: legacy.id,
        keyhash: "v3-key",
        salt: "v3-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      expect(replacement).toMatchObject({
        name: "Legacy custom vault",
        keyhash: "v3-key",
        salt: "v3-salt",
        host: `127.0.0.1:${migrationDataPort}`,
        encryption_version: 3,
        size: 0,
      });
      expect(replacement.id).not.toBe(legacy.id);
      expect(replacement.password).toBeUndefined();
      expect((await waitForClose(oldSocket, 2_000)).code).toBe(1008);
      await waitForDirectoryEmpty(join(migrationDirectory, "uploads"), 2_000);
      expect(await postAt(migrationControlPort, "/vault/access", {
        token: signin.token,
        vault_uid: legacy.id,
        keyhash: "legacy-key",
        host: legacy.host,
        encryption_version: 2,
      })).toEqual({ error: "Unable to access vault" });

      const recovery = await Probe.connect(`ws://127.0.0.1:${migrationDataPort}`);
      await initializeFor(recovery, signin.token, replacement, "Recovery device", 0, true);
      recovery.json(push("reuploaded", "reuploaded-hash", 0, 0));
      expect(await recovery.nextJson()).toMatchObject({ op: "push", path: "reuploaded" });
      expect(await recovery.nextJson()).toEqual({ res: "ok" });
      expect(await postAt(migrationControlPort, "/vault/migrate", {
        token: signin.token,
        vault_uid: replacement.id,
        keyhash: "should-not-replace-v3",
        salt: "should-not-replace-v3",
        region: "selfhost",
        encryption_version: 3,
      })).toEqual({ error: "Vault already uses encryption version 3" });
      recovery.json({ op: "history", path: "reuploaded", last: null });
      expect(await recovery.nextJson()).toMatchObject({
        items: [{ path: "reuploaded", hash: "reuploaded-hash" }],
      });
      recovery.socket.close();

      const managedLegacy = await postAt(migrationControlPort, "/vault/create", {
        token: signin.token,
        name: "Legacy managed vault",
        keyhash: null,
        salt: null,
        region: "selfhost",
        encryption_version: 1,
      });
      const managedReplacement = await postAt(migrationControlPort, "/vault/migrate", {
        token: signin.token,
        vault_uid: managedLegacy.id,
        keyhash: null,
        region: "selfhost",
        encryption_version: 3,
      });
      expect(managedReplacement).toMatchObject({
        name: "Legacy managed vault",
        keyhash: null,
        host: `127.0.0.1:${migrationDataPort}`,
        encryption_version: 3,
        size: 0,
      });
      expect(managedReplacement.password).toMatch(/^[0-9a-f]{64}$/);
      expect(managedReplacement.salt).toMatch(/^[0-9a-f]{32}$/);
      expect(await postAt(migrationControlPort, "/vault/access", {
        token: signin.token,
        vault_uid: managedReplacement.id,
        keyhash: "managed-v3-keyhash",
        host: managedReplacement.host,
        encryption_version: 3,
      })).toEqual({});

      child.kill("SIGTERM");
      expect(await child.exited).toBe(0);
      child = spawnRustServer(migrationDirectory, migrationControlPort, migrationDataPort);
      await waitForHealthAt(migrationControlPort, child);
      signin = await postAt(migrationControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      expect(await postAt(migrationControlPort, "/vault/access", {
        token: signin.token,
        vault_uid: managedReplacement.id,
        keyhash: "managed-v3-keyhash",
        host: managedReplacement.host,
        encryption_version: 3,
      })).toEqual({});
      const listed = await postAt(migrationControlPort, "/vault/list", { token: signin.token });
      expect(listed.vaults.map((item: any) => item.id).sort()).toEqual(
        [replacement.id, managedReplacement.id].sort(),
      );
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 45_000);

  test("serializes rename with destructive encryption migration", async () => {
    const raceDirectory = await mkdtemp(join(tmpdir(), "blackglass-vault-race-"));
    const [raceControlPort, raceDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(raceDirectory, raceControlPort, raceDataPort);
    try {
      await waitForHealthAt(raceControlPort, child);
      const signin = await postAt(raceControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      for (let iteration = 0; iteration < 3; iteration++) {
        const sourceName = `Migration race ${iteration}`;
        const renamedName = `Migration race renamed ${iteration}`;
        const source = await postAt(raceControlPort, "/vault/create", {
          token: signin.token,
          name: sourceName,
          keyhash: `race-key-${iteration}`,
          salt: `race-salt-${iteration}`,
          region: "selfhost",
          encryption_version: 2,
        });
        const [rename, migration] = await Promise.all([
          postAt(raceControlPort, "/vault/rename", {
            token: signin.token,
            vault_uid: source.id,
            name: renamedName,
          }),
          postAt(raceControlPort, "/vault/migrate", {
            token: signin.token,
            vault_uid: source.id,
            keyhash: `race-v3-key-${iteration}`,
            salt: `race-v3-salt-${iteration}`,
            region: "selfhost",
            encryption_version: 3,
          }),
        ]);
        expect(migration.error).toBeUndefined();
        if (rename.error === undefined) {
          expect(migration.name).toBe(renamedName);
        } else {
          expect(rename).toEqual({ error: "Unable to rename vault" });
          expect(migration.name).toBe(sourceName);
        }
      }
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 20_000);

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
      first.socket.send(new Uint8Array(2 * 1024 * 1024));
      second.socket.send(new Uint8Array(2 * 1024 * 1024));
      expect((await waitForClose(first, 2_000)).code).toBe(1008);
      expect((await waitForClose(second, 2_000)).code).toBe(1008);
      const replacement = await Probe.connect(`ws://127.0.0.1:${cappedDataPort}`);
      replacement.socket.close();
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }

    const overCapDirectory = await mkdtemp(join(tmpdir(), "blackglass-ws-over-cap-"));
    const [overCapControlPort, overCapDataPort] = await Promise.all([freePort(), freePort()]);
    const overCap = spawnRustServer(overCapDirectory, overCapControlPort, overCapDataPort, {
      SELFHOST_MAX_WS_CONNECTIONS: "33",
    });
    expect(await promiseWithTimeout(overCap.exited, 3_000, "over-cap server did not fail")).not.toBe(0);
    expect(await new Response(overCap.stderr as ReadableStream<Uint8Array>).text()).toContain(
      "SELFHOST_MAX_WS_CONNECTIONS must be between 1 and 16",
    );
  }, 20_000);

  test("requires an explicit acknowledgement for container-reachable binds", async () => {
    const deniedDirectory = await mkdtemp(join(tmpdir(), "blackglass-external-bind-denied-"));
    const [deniedControlPort, deniedDataPort] = await Promise.all([freePort(), freePort()]);
    const denied = spawnRustServer(deniedDirectory, deniedControlPort, deniedDataPort, {
      SELFHOST_BIND_HOST: "0.0.0.0",
      SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND: "",
    });
    expect(await promiseWithTimeout(denied.exited, 3_000, "unacknowledged bind did not fail")).not.toBe(0);
    expect(await new Response(denied.stderr as ReadableStream<Uint8Array>).text()).toContain(
      "SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND=1",
    );

    const plaintextDirectory = await mkdtemp(join(tmpdir(), "blackglass-external-plaintext-"));
    const [plaintextControlPort, plaintextDataPort] = await Promise.all([freePort(), freePort()]);
    const plaintext = spawnRustServer(plaintextDirectory, plaintextControlPort, plaintextDataPort, {
      SELFHOST_BIND_HOST: "0.0.0.0",
      SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND: "1",
      SELFHOST_DATA_HOST: "sync-data.example.test",
    });
    expect(
      await promiseWithTimeout(plaintext.exited, 3_000, "external plaintext password did not fail"),
    ).not.toBe(0);
    expect(await new Response(plaintext.stderr as ReadableStream<Uint8Array>).text()).toContain(
      "permitted only with a loopback SELFHOST_BIND_HOST",
    );

    const allowedDirectory = await mkdtemp(join(tmpdir(), "blackglass-external-bind-allowed-"));
    const [allowedControlPort, allowedDataPort] = await Promise.all([freePort(), freePort()]);
    const allowed = spawnRustServer(allowedDirectory, allowedControlPort, allowedDataPort, {
      SELFHOST_BIND_HOST: "0.0.0.0",
      SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND: "1",
      SELFHOST_DATA_HOST: "sync-data.example.test",
      SELFHOST_PASSWORD: "",
      SELFHOST_ALLOW_PLAINTEXT_PASSWORD: "",
      SELFHOST_PASSWORD_HASH: maximumWorkPasswordHash,
    });
    try {
      await waitForHealthAt(allowedControlPort, allowed);
      expect((await fetch(`http://127.0.0.1:${allowedControlPort}/health`)).status).toBe(200);
    } finally {
      if (allowed.exitCode === null) allowed.kill("SIGTERM");
      await allowed.exited;
    }

    for (const bind of ["0.0.0.0", "::1", "::"]) {
      const missingDirectory = await mkdtemp(join(tmpdir(), "blackglass-data-host-missing-"));
      const [missingControlPort, missingDataPort] = await Promise.all([freePort(), freePort()]);
      const missing = spawnRustServer(missingDirectory, missingControlPort, missingDataPort, {
        SELFHOST_BIND_HOST: bind,
        SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND: bind === "::1" ? "" : "1",
        SELFHOST_DATA_HOST: "",
        SELFHOST_PASSWORD: "",
        SELFHOST_ALLOW_PLAINTEXT_PASSWORD: "",
        SELFHOST_PASSWORD_HASH: maximumWorkPasswordHash,
      });
      expect(await promiseWithTimeout(missing.exited, 3_000, `missing data host passed for ${bind}`)).not.toBe(0);
      expect(await new Response(missing.stderr as ReadableStream<Uint8Array>).text()).toContain(
        "SELFHOST_DATA_HOST is required",
      );
    }

    for (const host of [
      "localhost",
      "127.0.0.1",
      "127.0.0.1:1",
      "0.0.0.0:3003",
      "224.0.0.1:3003",
      "255.255.255.255:3003",
      "[::]",
      "[ff02::1]:3003",
    ]) {
      const invalidDirectory = await mkdtemp(join(tmpdir(), "blackglass-data-host-invalid-"));
      const [invalidControlPort, invalidDataPort] = await Promise.all([freePort(), freePort()]);
      const invalid = spawnRustServer(invalidDirectory, invalidControlPort, invalidDataPort, {
        SELFHOST_DATA_HOST: host,
      });
      expect(await promiseWithTimeout(invalid.exited, 3_000, `invalid data host passed: ${host}`)).not.toBe(0);
    }
  }, 30_000);

  test("fails closed on persisted data-host drift and supports backup-first domain and port rebinding", async () => {
    const rebindDirectory = await mkdtemp(join(tmpdir(), "blackglass-host-rebind-"));
    const [rebindControlPort, rebindDataPort] = await Promise.all([freePort(), freePort()]);
    const databasePath = join(rebindDirectory, "server.sqlite");
    let child = spawnRustServer(rebindDirectory, rebindControlPort, rebindDataPort);
    try {
      await waitForHealthAt(rebindControlPort, child);
      const signin = await postAt(rebindControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const original = await postAt(rebindControlPort, "/vault/create", {
        token: signin.token,
        name: "Rebound vault",
        keyhash: "rebind-keyhash",
        salt: "rebind-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      child.kill("SIGTERM");
      expect(await child.exited).toBe(0);

      child = spawnRustServer(rebindDirectory, rebindControlPort, rebindDataPort, {
        SELFHOST_DATA_HOST: "sync-data.example.test",
      });
      expect(await promiseWithTimeout(child.exited, 3_000, "mismatched host did not fail")).not.toBe(0);
      expect(await new Response(child.stderr as ReadableStream<Uint8Array>).text()).toContain(
        "rebind-data-host",
      );

      const firstBackup = join(rebindDirectory, "before-domain-rebind.sqlite");
      const domainRebind = Bun.spawnSync([
        binary,
        "rebind-data-host",
        databasePath,
        "sync-data.example.test",
        firstBackup,
      ], { cwd: root, stdout: "pipe", stderr: "pipe" });
      expect(domainRebind.exitCode, domainRebind.stderr.toString()).toBe(0);
      expect(domainRebind.stdout.toString()).toContain("rebound 1 vault(s)");

      child = spawnRustServer(rebindDirectory, rebindControlPort, rebindDataPort);
      expect(await promiseWithTimeout(child.exited, 3_000, "stale configured host did not fail")).not.toBe(0);
      child = spawnRustServer(rebindDirectory, rebindControlPort, rebindDataPort, {
        SELFHOST_DATA_HOST: "sync-data.example.test",
      });
      await waitForHealthAt(rebindControlPort, child);
      let currentSignin = await postAt(rebindControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      let listed = await postAt(rebindControlPort, "/vault/list", { token: currentSignin.token });
      expect(listed.vaults[0]).toMatchObject({ id: original.id, host: "sync-data.example.test" });
      expect(await postAt(rebindControlPort, "/vault/access", {
        token: currentSignin.token,
        vault_uid: original.id,
        keyhash: original.keyhash,
        host: original.host,
        encryption_version: 3,
      })).toEqual({ error: "Unable to access vault" });
      expect(await postAt(rebindControlPort, "/vault/access", {
        token: currentSignin.token,
        vault_uid: original.id,
        keyhash: original.keyhash,
        host: "sync-data.example.test",
        encryption_version: 3,
      })).toEqual({});
      child.kill("SIGTERM");
      expect(await child.exited).toBe(0);

      const secondBackup = join(rebindDirectory, "before-port-rebind.sqlite");
      const portRebind = Bun.spawnSync([
        binary,
        "rebind-data-host",
        databasePath,
        "sync-data.example.test:8443",
        secondBackup,
      ], { cwd: root, stdout: "pipe", stderr: "pipe" });
      expect(portRebind.exitCode, portRebind.stderr.toString()).toBe(0);
      child = spawnRustServer(rebindDirectory, rebindControlPort, rebindDataPort, {
        SELFHOST_DATA_HOST: "sync-data.example.test:8443",
      });
      await waitForHealthAt(rebindControlPort, child);
      currentSignin = await postAt(rebindControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      listed = await postAt(rebindControlPort, "/vault/list", { token: currentSignin.token });
      expect(listed.vaults[0].host).toBe("sync-data.example.test:8443");
      expect((await stat(firstBackup)).size).toBeGreaterThan(0);
      expect((await stat(secondBackup)).size).toBeGreaterThan(0);
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 35_000);

  test("round-trips multi-piece opaque ciphertext with bounded staging", async () => {
    const payload = new Uint8Array(randomBytes(3 * 1024 * 1024 + 17));
    const writer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(writer, "Writer", 0, true);
    writer.json(push("encrypted-large-path", "large-hash", payload.byteLength, 2));
    expect(await writer.nextJson()).toEqual({ res: "next" });
    writer.socket.send(payload.slice(0, 2 * 1024 * 1024));
    expect(await writer.nextJson()).toEqual({ res: "next" });
    const staged = await stagedParts(join(directory, "uploads"));
    expect(staged).toHaveLength(1);
    expect((await stat(join(directory, "uploads", staged[0]!))).size).toBe(2 * 1024 * 1024);
    writer.socket.send(payload.slice(2 * 1024 * 1024));
    const notice = await writer.nextJson();
    expect(notice).toMatchObject({ op: "push", path: "encrypted-large-path", size: payload.byteLength });
    expect(await writer.nextJson()).toEqual({ res: "ok" });
    expect(await stagedParts(join(directory, "uploads"))).toEqual([]);

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

  test("enforces the stored-ciphertext quota across uploads and restores", async () => {
    const quotaDirectory = await mkdtemp(join(tmpdir(), "blackglass-storage-quota-"));
    const [quotaControlPort, quotaDataPort] = await Promise.all([freePort(), freePort()]);
    const storageQuota = 64;
    const child = spawnRustServer(quotaDirectory, quotaControlPort, quotaDataPort, {
      SELFHOST_PER_FILE_MAX: String(storageQuota - aesGcmWireOverhead),
      SELFHOST_STORAGE_QUOTA_BYTES: String(storageQuota),
    });
    try {
      await waitForHealthAt(quotaControlPort, child);
      const signin = await postAt(quotaControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const quotaVault = await postAt(quotaControlPort, "/vault/create", {
        token: signin.token,
        name: "Storage quota vault",
        keyhash: "storage-quota-keyhash",
        salt: "storage-quota-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      const probe = await Probe.connect(`ws://127.0.0.1:${quotaDataPort}`);
      await initializeFor(probe, signin.token, quotaVault, "Quota writer", 0, true);

      probe.json({ op: "size" });
      expect(await probe.nextJson()).toEqual({
        res: "ok",
        size: 0,
        limit: storageQuota,
        vault_size: 0,
      });
      const payload = new Uint8Array(32).fill(0x5a);
      const emptySource = await metadata(probe, "quota-empty", "quota-empty");

      const fullPending = await Probe.connect(`ws://127.0.0.1:${quotaDataPort}`);
      await initializeFor(
        fullPending,
        signin.token,
        quotaVault,
        "Full quota reservation",
        0,
        true,
      );
      fullPending.json(push("quota-full-pending", "quota-full-pending", storageQuota, 1));
      expect(await fullPending.nextJson()).toEqual({ res: "next" });
      probe.json(push("quota-concurrent", "quota-concurrent", 1, 1));
      expect(await probe.nextJson()).toEqual({ err: "Storage limit reached" });
      probe.json({ op: "restore", uid: emptySource.uid });
      expect(await probe.nextJson()).toMatchObject({
        op: "push",
        path: "quota-empty",
        size: 0,
      });
      expect(await probe.nextJson()).toEqual({ res: "ok" });
      fullPending.socket.close();
      await waitForClose(fullPending, 2_000);
      await waitForDirectoryEmpty(join(quotaDirectory, "uploads"), 2_000);

      const source = await uploadOpaqueCiphertext(
        probe,
        "quota-path",
        "quota-source",
        payload.byteLength,
      );

      const pending = await Probe.connect(`ws://127.0.0.1:${quotaDataPort}`);
      await initializeFor(pending, signin.token, quotaVault, "Quota reservation", 0, true);
      pending.json(push("quota-pending", "quota-pending", payload.byteLength, 1));
      expect(await pending.nextJson()).toEqual({ res: "next" });
      probe.json({ op: "restore", uid: source.uid });
      expect(await probe.nextJson()).toEqual({ err: "Storage limit reached" });
      pending.socket.close();
      await waitForClose(pending, 2_000);
      await waitForDirectoryEmpty(join(quotaDirectory, "uploads"), 2_000);

      probe.json({ op: "restore", uid: source.uid });
      const restored = await probe.nextJson();
      expect(restored).toMatchObject({ op: "push", path: "quota-path", size: 32 });
      expect(await probe.nextJson()).toEqual({ res: "ok" });

      probe.json({ op: "size" });
      expect(await probe.nextJson()).toEqual({
        res: "ok",
        size: storageQuota,
        limit: storageQuota,
        vault_size: payload.byteLength,
      });
      probe.json({ op: "restore", uid: source.uid });
      expect(await probe.nextJson()).toEqual({ err: "Storage limit reached" });

      probe.json(push("quota-overflow", "quota-overflow", payload.byteLength, 1));
      expect(await probe.nextJson()).toEqual({ err: "Storage limit reached" });
      await waitForDirectoryEmpty(join(quotaDirectory, "uploads"), 2_000);

      const database = new Database(join(quotaDirectory, "server.sqlite"), { readonly: true });
      try {
        expect(
          database.query("SELECT COALESCE(SUM(size),0) AS size FROM revisions").get(),
        ).toEqual({ size: storageQuota });
      } finally {
        database.close();
      }

      await metadata(probe, "quota-path", "", { deleted: true });
      probe.json({ op: "purge" });
      expect(await probe.nextJson()).toEqual({ res: "ok" });
      await uploadOpaqueCiphertext(probe, "quota-after-purge", "quota-recovered", 32);
      const metrics = await (
        await fetch(`http://127.0.0.1:${quotaControlPort}/metrics`)
      ).text();
      expect(metricValue(metrics, "blackglass_storage_quota_bytes")).toBe(storageQuota);
      expect(metricValue(metrics, "blackglass_storage_quota_rejections_total")).toBe(4);
      probe.socket.close();
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
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
    await waitForClose(interrupted, 2_000);
    await waitForDirectoryEmpty(join(directory, "uploads"), 2_000);
  });

  test("expires stalled uploads, removes staging, and restores upload capacity", async () => {
    const timeoutDirectory = await mkdtemp(join(tmpdir(), "blackglass-upload-timeout-"));
    const [timeoutControlPort, timeoutDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(timeoutDirectory, timeoutControlPort, timeoutDataPort, {
      SELFHOST_MAX_CONCURRENT_UPLOADS: "1",
      SELFHOST_UPLOAD_IDLE_TIMEOUT_SECONDS: "5",
    });
    try {
      await waitForHealthAt(timeoutControlPort, child);
      const signin = await postAt(timeoutControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const timeoutVault = await postAt(timeoutControlPort, "/vault/create", {
        token: signin.token,
        name: "Upload timeout vault",
        keyhash: "upload-timeout-keyhash",
        salt: "upload-timeout-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      const stalled = await Probe.connect(`ws://127.0.0.1:${timeoutDataPort}`);
      const retrying = await Probe.connect(`ws://127.0.0.1:${timeoutDataPort}`);
      await initializeFor(stalled, signin.token, timeoutVault, "Stalled upload", 0, true);
      await initializeFor(retrying, signin.token, timeoutVault, "Capacity retry", 0, true);

      stalled.json(push("stalled-upload", "stalled-upload-hash", 32, 1));
      expect(await stalled.nextJson()).toEqual({ res: "next" });
      expect(await stagedParts(join(timeoutDirectory, "uploads"))).toHaveLength(1);

      retrying.json(push("recovered-upload", "recovered-upload-hash", 32, 1));
      expect(await retrying.nextJson()).toEqual({
        err: "Server upload capacity reached; retry shortly",
      });

      const stalledClose = await waitForClose(stalled, 8_000);
      expect(stalledClose.code).toBe(1008);
      expect(stalledClose.reason).toBe("Upload idle timeout exceeded");
      await waitForDirectoryEmpty(join(timeoutDirectory, "uploads"), 2_000);

      const payload = new Uint8Array(32).fill(7);
      retrying.json(push("recovered-upload", "recovered-upload-hash", payload.byteLength, 1));
      expect(await retrying.nextJson()).toEqual({ res: "next" });
      retrying.socket.send(payload);
      expect(await retrying.nextJson()).toMatchObject({
        op: "push",
        path: "recovered-upload",
        hash: "recovered-upload-hash",
      });
      expect(await retrying.nextJson()).toEqual({ res: "ok" });
      expect(await stagedParts(join(timeoutDirectory, "uploads"))).toEqual([]);

      const metrics = await (await fetch(
        `http://127.0.0.1:${timeoutControlPort}/metrics`,
      )).text();
      expect(metricValue(metrics, "blackglass_upload_timeouts_total")).toBe(1);
      retrying.socket.close();
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 25_000);

  test("purge retains a compact tombstone for offline-client convergence", async () => {
    const writer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    const start = databaseVersion(join(directory, "server.sqlite"), vault.id);
    await initialize(writer, "Purge convergence writer", start, false);
    const live = await metadata(writer, "purged-offline-path", "purged-live-hash");
    const deleted = await metadata(writer, "purged-offline-path", "", { deleted: true });
    writer.json({ op: "purge" });
    expect(await writer.nextJson()).toEqual({ res: "ok" });

    writer.json({ op: "deleted", suppressrenames: false });
    expect((await writer.nextJson()).items.some(
      (item: any) => item.path === "purged-offline-path",
    )).toBe(false);
    writer.json({ op: "restore", uid: deleted.uid });
    expect(await writer.nextJson()).toEqual({ err: "Revision not found" });
    writer.socket.close();

    const resumed = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    resumed.json(init("Offline client after purge", live.uid, false));
    expect(await resumed.nextJson()).toMatchObject({ res: "ok" });
    expect(await resumed.nextJson()).toMatchObject({
      op: "push",
      uid: deleted.uid,
      path: "purged-offline-path",
      deleted: true,
    });
    expect(await resumed.nextJson()).toEqual({ op: "ready", version: deleted.uid });
    resumed.socket.close();
  });

  test("removes a staged upload when its database commit fails", async () => {
    const failedDirectory = await mkdtemp(join(tmpdir(), "blackglass-failed-upload-"));
    const [failedControlPort, failedDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(failedDirectory, failedControlPort, failedDataPort);
    try {
      await waitForHealthAt(failedControlPort, child);
      const signin = await postAt(failedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const failedVault = await postAt(failedControlPort, "/vault/create", {
        token: signin.token,
        name: "Failed upload vault",
        keyhash: "failed-upload-keyhash",
        salt: "failed-upload-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      const probe = await Probe.connect(`ws://127.0.0.1:${failedDataPort}`);
      await initializeFor(probe, signin.token, failedVault, "Failed upload", 0, true);
      const payload = new TextEncoder().encode("opaque upload that must not remain staged");
      probe.json(push("failed-upload", "failed-upload-hash", payload.byteLength, 1));
      expect(await probe.nextJson()).toEqual({ res: "next" });
      expect(await stagedParts(join(failedDirectory, "uploads"))).toHaveLength(1);
      const database = new Database(join(failedDirectory, "server.sqlite"));
      try {
        database.exec("DROP TABLE revision_content");
      } finally {
        database.close();
      }
      probe.socket.send(payload);
      await waitForClose(probe, 5_000);
      await waitForDirectoryEmpty(join(failedDirectory, "uploads"), 2_000);
      expect((await fetch(`http://127.0.0.1:${failedControlPort}/health`)).status).toBe(200);
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 20_000);

  test("rejects duplicate database or staging owners before touching active uploads", async () => {
    const lockedDirectory = await mkdtemp(join(tmpdir(), "blackglass-state-lock-"));
    const [lockedControlPort, lockedDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(lockedDirectory, lockedControlPort, lockedDataPort);
    try {
      await waitForHealthAt(lockedControlPort, child);
      const signin = await postAt(lockedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const lockedVault = await postAt(lockedControlPort, "/vault/create", {
        token: signin.token,
        name: "Locked vault",
        keyhash: "locked-keyhash",
        salt: "locked-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      const writer = await Probe.connect(`ws://127.0.0.1:${lockedDataPort}`);
      await initializeFor(writer, signin.token, lockedVault, "Locked writer", 0, true);
      const payload = new TextEncoder().encode("active staged ciphertext");
      writer.json(push("active-lock-upload", "active-lock-hash", payload.length, 1));
      expect(await writer.nextJson()).toEqual({ res: "next" });
      expect(await stagedParts(join(lockedDirectory, "uploads"))).toHaveLength(1);

      const [duplicateControlPort, duplicateDataPort] = await Promise.all([freePort(), freePort()]);
      const duplicate = spawnRustServer(
        join(lockedDirectory, ".", "alias", ".."),
        duplicateControlPort,
        duplicateDataPort,
        { SELFHOST_DATA_HOST: `127.0.0.1:${duplicateDataPort}` },
      );
      expect(await promiseWithTimeout(duplicate.exited, 3_000, "duplicate database owner did not fail")).not.toBe(0);
      expect(await new Response(duplicate.stderr as ReadableStream<Uint8Array>).text()).toContain(
        "database state is already locked",
      );
      expect(await stagedParts(join(lockedDirectory, "uploads"))).toHaveLength(1);

      const blockedMigrationDestination = join(lockedDirectory, "must-not-migrate.sqlite");
      const blockedMigration = Bun.spawnSync(
        [binary, "migrate", join(lockedDirectory, "server.sqlite"), blockedMigrationDestination],
        { cwd: root, stdout: "pipe", stderr: "pipe" },
      );
      expect(blockedMigration.exitCode).not.toBe(0);
      expect(blockedMigration.stderr.toString()).toContain("database state is already locked");
      expect(await Bun.file(blockedMigrationDestination).exists()).toBe(false);

      const separateDirectory = await mkdtemp(join(tmpdir(), "blackglass-shared-staging-"));
      const [sharedControlPort, sharedDataPort] = await Promise.all([freePort(), freePort()]);
      const shared = spawnRustServer(separateDirectory, sharedControlPort, sharedDataPort, {
        SELFHOST_STAGING_DIR: join(lockedDirectory, "uploads", "."),
      });
      expect(await promiseWithTimeout(shared.exited, 3_000, "duplicate staging owner did not fail")).not.toBe(0);
      expect(await new Response(shared.stderr as ReadableStream<Uint8Array>).text()).toContain(
        "staging state is already locked",
      );
      expect(await stagedParts(join(lockedDirectory, "uploads"))).toHaveLength(1);

      writer.socket.send(payload);
      expect(await writer.nextJson()).toMatchObject({ op: "push", path: "active-lock-upload" });
      expect(await writer.nextJson()).toEqual({ res: "ok" });
      expect(await stagedParts(join(lockedDirectory, "uploads"))).toEqual([]);
      writer.socket.close();
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 20_000);

  test("vault deletion immediately revokes idle and in-flight sockets", async () => {
    const deletionDirectory = await mkdtemp(join(tmpdir(), "blackglass-vault-delete-"));
    const [deletionControlPort, deletionDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(deletionDirectory, deletionControlPort, deletionDataPort);
    try {
      await waitForHealthAt(deletionControlPort, child);
      const signin = await postAt(deletionControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const deletedVault = await postAt(deletionControlPort, "/vault/create", {
        token: signin.token,
        name: "Deleted vault",
        keyhash: "deleted-keyhash",
        salt: "deleted-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      const idle = await Probe.connect(`ws://127.0.0.1:${deletionDataPort}`);
      const uploading = await Probe.connect(`ws://127.0.0.1:${deletionDataPort}`);
      await initializeFor(idle, signin.token, deletedVault, "Idle delete", 0, true);
      await initializeFor(uploading, signin.token, deletedVault, "Upload delete", 0, true);
      uploading.json(push("pending-delete", "pending-delete-hash", 32, 1));
      expect(await uploading.nextJson()).toEqual({ res: "next" });
      expect(await stagedParts(join(deletionDirectory, "uploads"))).toHaveLength(1);

      expect(await postAt(deletionControlPort, "/vault/delete", {
        token: signin.token,
        vault_uid: deletedVault.id,
      })).toEqual({});
      expect((await waitForClose(idle, 2_000)).code).toBe(1008);
      expect((await waitForClose(uploading, 2_000)).code).toBe(1008);
      await waitForDirectoryEmpty(join(deletionDirectory, "uploads"), 2_000);
      const stale = await Probe.connect(`ws://127.0.0.1:${deletionDataPort}`);
      stale.json(initFor(signin.token, deletedVault, "Stale deleted vault", 0, false));
      expect(await stale.nextJson()).toEqual({ res: "err", msg: "Vault not found" });
      const staleClose = await waitForClose(stale, 2_000);
      expect(staleClose.code).toBe(1008);
      expect(staleClose.reason).toBe("Vault not found");
      expect(await postAt(deletionControlPort, "/vault/list", { token: signin.token })).toMatchObject({
        vaults: [],
      });
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 20_000);

  test("restore rotates vault identity and gives stale clients an exact recovery signal", async () => {
    const sourceDirectory = await mkdtemp(join(tmpdir(), "blackglass-restore-source-"));
    const recoveredDirectory = await mkdtemp(join(tmpdir(), "blackglass-restore-recovered-"));
    const backup = join(sourceDirectory, "server.backup.sqlite");
    const recoveredDatabase = join(recoveredDirectory, "server.sqlite");
    const [sourceControlPort, sourceDataPort] = await Promise.all([freePort(), freePort()]);
    let child = spawnRustServer(sourceDirectory, sourceControlPort, sourceDataPort);
    try {
      await waitForHealthAt(sourceControlPort, child);
      const originalSignin = await postAt(sourceControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const originalVault = await postAt(sourceControlPort, "/vault/create", {
        token: originalSignin.token,
        name: "Restore vault",
        keyhash: "restore-keyhash",
        salt: "restore-salt",
        region: "selfhost",
        encryption_version: 3,
      });
      const writer = await Probe.connect(`ws://127.0.0.1:${sourceDataPort}`);
      await initializeFor(writer, originalSignin.token, originalVault, "Restore writer", 0, true);
      await metadata(writer, "restore-proof", "restore-proof-hash");
      writer.socket.close();

      const backupCommand = Bun.spawnSync(
        [binary, "backup", join(sourceDirectory, "server.sqlite"), backup],
        { cwd: root, stdout: "pipe", stderr: "pipe" },
      );
      expect(backupCommand.exitCode, backupCommand.stderr.toString()).toBe(0);
      const postBackupSignin = await postAt(sourceControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      expect(postBackupSignin.token).toMatch(/^[0-9a-f]{64}$/);

      child.kill("SIGTERM");
      expect(await child.exited).toBe(0);
      const restoreCommand = Bun.spawnSync([binary, "restore", backup, recoveredDatabase], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(restoreCommand.exitCode, restoreCommand.stderr.toString()).toBe(0);

      const recoveredControlPort = sourceControlPort;
      const recoveredDataPort = sourceDataPort;
      child = spawnRustServer(recoveredDirectory, recoveredControlPort, recoveredDataPort);
      await waitForHealthAt(recoveredControlPort, child);

      const stale = await Probe.connect(`ws://127.0.0.1:${recoveredDataPort}`);
      // This token was issued after the backup and is therefore not a valid
      // session in the restored database. Merely having token shape must not
      // disclose a tenant's retired-vault marker.
      stale.json(initFor(postBackupSignin.token, originalVault, "Post-backup stale client", 1, false));
      expect(await stale.nextJson()).toEqual({ res: "err", msg: "Unable to authenticate" });
      stale.socket.close();

      const malformedToken = await Probe.connect(`ws://127.0.0.1:${recoveredDataPort}`);
      malformedToken.json(
        initFor("not-a-session-token", originalVault, "Malformed stale client", 1, false),
      );
      expect(await malformedToken.nextJson()).toEqual({
        res: "err",
        msg: "Unable to authenticate",
      });
      malformedToken.socket.close();

      const arbitrary = await Probe.connect(`ws://127.0.0.1:${recoveredDataPort}`);
      arbitrary.json(initFor(postBackupSignin.token, {
        ...originalVault,
        id: "00000000-0000-4000-8000-000000000000",
      }, "Arbitrary missing vault", 0, true));
      expect(await arbitrary.nextJson()).toEqual({ res: "err", msg: "Unable to authenticate" });
      arbitrary.socket.close();

      const freshSignin = await postAt(recoveredControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      const listed = await postAt(recoveredControlPort, "/vault/list", {
        token: freshSignin.token,
      });
      expect(listed.vaults).toHaveLength(1);
      expect(listed.vaults[0].id).not.toBe(originalVault.id);
      const reader = await Probe.connect(`ws://127.0.0.1:${recoveredDataPort}`);
      await initializeFor(reader, freshSignin.token, listed.vaults[0], "Fresh restore reader", 0, true);
      reader.socket.close();
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
  }, 30_000);

  test("exposes safe health/metrics and produces verified live backups", async () => {
    expect(await (await fetch(`http://127.0.0.1:${controlPort}/health`)).json()).toMatchObject({
      implementation: "rust",
      service: "blackglass-server",
      version: packageVersion,
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
    const command = Bun.spawnSync([binary, "backup", join(directory, "server.sqlite"), backup], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(command.exitCode, command.stderr.toString()).toBe(0);
    expect((await stat(backup)).size).toBeGreaterThan(0);
    const verify = Bun.spawnSync([binary, "verify", backup], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(verify.exitCode, verify.stderr.toString()).toBe(0);
  });

  test("rejects malformed and oversized protocol input without committing it", async () => {
    const versionBefore = databaseVersion(join(directory, "server.sqlite"), vault.id);
    const probe = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    await initialize(probe, "Input validator", 0, false);
    probe.socket.send("{");
    expect(await probe.nextJson()).toEqual({ res: "err", msg: "Invalid JSON" });
    probe.json(push("oversized-path", "oversized", 9 * 1024 * 1024, 5));
    expect(await probe.nextJson()).toEqual({ err: "Invalid push metadata" });
    probe.json({ op: "history", path: "" });
    expect(await probe.nextJson()).toEqual({ err: "Invalid history path" });
    probe.json(push("bounded-path", "oversized-related", 0, 0, {
      relatedpath: "r".repeat(16_385),
    }));
    expect(await probe.nextJson()).toEqual({ err: "Invalid push metadata" });
    probe.json(push("unsafe-time", "unsafe-time", 0, 0, {
      ctime: Number.MAX_SAFE_INTEGER + 1,
    }));
    expect(await probe.nextJson()).toEqual({ err: "Invalid push metadata" });
    expect(databaseVersion(join(directory, "server.sqlite"), vault.id)).toBe(versionBefore);
    probe.socket.close();

    const unsafeVersion = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    unsafeVersion.json(init("Unsafe version", Number.MAX_SAFE_INTEGER + 1, false));
    expect(await unsafeVersion.nextJson()).toEqual({ res: "err", msg: "Invalid Sync version" });
    expect((await waitForClose(unsafeVersion, 2_000)).code).toBe(1008);
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

  test("fails closed when an existing client is ahead of restored server history", async () => {
    const ahead = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    const serverVersion = databaseVersion(join(directory, "server.sqlite"), vault.id);
    ahead.json(initFor(token, vault, "Ahead restore client", serverVersion + 100, false));
    expect(await ahead.nextJson()).toEqual({
      res: "err",
      msg: "Client Sync version is ahead of the server; reconnect this vault as a fresh client after restore",
    });
    const closed = await waitForClose(ahead, 2_000);
    expect(closed.code).toBe(1008);
    expect(closed.reason).toContain("ahead of the server");
  });

  test("queues bounded database work without invalidating healthy WebSocket bursts", async () => {
    const burstSignin = await post("/user/signin", {
      email: "owner@example.test",
      password: "test-password",
    });
    const head = databaseVersion(join(directory, "server.sqlite"), vault.id);
    const observers: Probe[] = [];
    let writer: Probe | undefined;
    try {
      for (let index = 0; index < 6; index++) {
        const observer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
        observers.push(observer);
        await initializeFor(
          observer,
          burstSignin.token,
          vault,
          `Burst observer ${index}`,
          head,
          false,
        );
      }
      writer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
      await initializeFor(writer, burstSignin.token, vault, "Burst writer", head, false);
      writer.json(push("bounded-db-broadcast", "bounded-db-broadcast-hash", 0, 0));
      expect(await writer.nextJson()).toMatchObject({ op: "push", path: "bounded-db-broadcast" });
      expect(await writer.nextJson()).toEqual({ res: "ok" });
      const notices = await promiseWithTimeout(
        Promise.all(observers.map((observer) => observer.nextJson())),
        3_000,
        "healthy observers stalled behind bounded database workers",
      );
      for (const notice of notices) expect(notice).toMatchObject({ op: "push", path: "bounded-db-broadcast" });

      for (const observer of observers) observer.json({ op: "ping" });
      const pongs = await promiseWithTimeout(
        Promise.all(observers.map((observer) => observer.nextJson())),
        3_000,
        "healthy sessions were closed under bounded database concurrency",
      );
      expect(pongs).toEqual(observers.map(() => ({ op: "pong" })));
    } finally {
      writer?.socket.close();
      for (const observer of observers) observer.socket.close();
    }
  }, 15_000);

  test("keeps bounded control/database work responsive, honors admin revocation, and drains on shutdown", async () => {
    const isolatedDirectory = await mkdtemp(join(tmpdir(), "blackglass-reactor-"));
    const [isolatedControlPort, isolatedDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(isolatedDirectory, isolatedControlPort, isolatedDataPort);
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

      const rejectedSlow = await openWrongOriginSlowControlRequest(isolatedControlPort);
      try {
        expect(await promiseWithTimeout(
          rejectedSlow.response,
          750,
          "wrong-origin request was not rejected before its body arrived",
        )).toContain(" 403 ");
      } finally {
        rejectedSlow.socket.destroy();
      }

      const slowRequests = await Promise.all(
        Array.from({ length: 16 }, () => openSlowControlRequest(isolatedControlPort)),
      );
      try {
        await Bun.sleep(100);
        const ownerResponse = await promiseWithTimeout(
          fetch(`http://127.0.0.1:${isolatedControlPort}/user/signin`, {
            method: "POST",
            headers: { "content-type": "application/json", origin: "app://obsidian.md" },
            body: JSON.stringify({ email: "owner@example.test", password: "test-password" }),
          }),
          2_000,
          "slow bodies exhausted admitted control work",
        );
        expect(ownerResponse.status).toBe(200);
        const ownerSignin = await ownerResponse.json();
        expect(ownerSignin.token).toHaveLength(64);
        expect(await postAt(isolatedControlPort, "/user/signout", {
          token: ownerSignin.token,
        })).toEqual({});
        expect((await fetch(`http://127.0.0.1:${isolatedControlPort}/health`)).status).toBe(200);
        expect(await promiseWithTimeout(
          slowRequests[0]!.response,
          7_000,
          "slow control body was not timed out",
        )).toContain(" 408 ");
      } finally {
        for (const request of slowRequests) request.socket.destroy();
      }

      const lock = new Database(join(isolatedDirectory, "server.sqlite"));
      lock.exec("BEGIN IMMEDIATE");
      let flood: Promise<Response[]> | undefined;
      try {
        probe.json(push("blocked-database-write", "blocked-write", 0, 0));
        flood = Promise.all(Array.from({ length: 64 }, () => fetch(
          `http://127.0.0.1:${isolatedControlPort}/user/info`,
          {
            method: "POST",
            headers: { "content-type": "application/json", origin: "app://obsidian.md" },
            body: JSON.stringify({ token: "0".repeat(64) }),
          },
        )));
        await Bun.sleep(100);
        const started = performance.now();
        const response = await promiseWithTimeout(
          fetch(`http://127.0.0.1:${isolatedControlPort}/health`),
          750,
          "health endpoint stalled behind SQLite",
        );
        expect(response.status).toBe(200);
        expect(performance.now() - started).toBeLessThan(750);
        const readiness = await promiseWithTimeout(
          fetch(`http://127.0.0.1:${isolatedControlPort}/ready`),
          750,
          "readiness did not fail fast behind SQLite",
        );
        expect(readiness.status).toBe(503);
      } finally {
        lock.exec("ROLLBACK");
        lock.close();
      }
      const floodResponses = await promiseWithTimeout(
        flood!,
        7_000,
        "bounded control flood did not drain",
      );
      expect(floodResponses.some((response) => response.status === 503)).toBe(true);
      for (const response of floodResponses) {
        expect([200, 503]).toContain(response.status);
        if (response.status === 503) expect(await response.json()).toEqual({ error: "Server busy" });
      }
      const recoveredSignin = await postAt(isolatedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      });
      expect(recoveredSignin.token).toHaveLength(64);
      expect(await postAt(isolatedControlPort, "/user/signout", {
        token: recoveredSignin.token,
      })).toEqual({});
      const boundedMetrics = await (await fetch(
        `http://127.0.0.1:${isolatedControlPort}/metrics`,
      )).text();
      expect(metricValue(boundedMetrics, "blackglass_control_rejections_total")).toBeGreaterThan(0);
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
      const pendingUpload = await Probe.connect(`ws://127.0.0.1:${isolatedDataPort}`);
      await initializeFor(committing, shutdownSignin.token, isolatedVault, "Shutdown writer", head, false);
      await initializeFor(idle, shutdownSignin.token, isolatedVault, "Shutdown idle", head, false);
      await initializeFor(pendingUpload, shutdownSignin.token, isolatedVault, "Shutdown upload", head, false);
      pendingUpload.json(push("shutdown-pending-upload", "shutdown-pending-hash", 32, 1));
      expect(await pendingUpload.nextJson()).toEqual({ res: "next" });
      expect(await stagedParts(join(isolatedDirectory, "uploads"))).toHaveLength(1);

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
      await waitForClose(pendingUpload, 2_000);
      expect(await stagedParts(join(isolatedDirectory, "uploads"))).toEqual([]);
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
  }, 35_000);

  test("bounds password-check concurrency without a globally exhaustible owner lockout", async () => {
    const limitedDirectory = await mkdtemp(join(tmpdir(), "blackglass-login-rate-"));
    const [limitedControlPort, limitedDataPort] = await Promise.all([freePort(), freePort()]);
    const child = spawnRustServer(limitedDirectory, limitedControlPort, limitedDataPort, {
      SELFHOST_TRUSTED_PROXY: "127.0.0.1",
    });
    try {
      await waitForHealthAt(limitedControlPort, child);
      const burst = await Promise.all(Array.from({ length: 8 }, () =>
        postAt(limitedControlPort, "/user/signin", {
          email: "owner@example.test",
          password: "wrong",
        }, { "x-forwarded-for": "198.51.100.10" })));
      expect(burst.some((result) => result.error === "Too many sign-in attempts; try again later")).toBe(true);
      expect(burst.every((result) =>
        result.error === "Too many sign-in attempts; try again later" ||
        result.error === "Try again later" ||
        result.error === "Invalid email or password",
      )).toBe(true);
      expect(await postAt(limitedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      }, { "x-forwarded-for": "198.51.100.11" })).toMatchObject({
        email: "owner@example.test",
        license: null,
      });
      expect(await postAt(limitedControlPort, "/user/signin", {
        email: "owner@example.test",
        password: "test-password",
      }, { "x-forwarded-for": "198.51.100.11" })).toMatchObject({
        email: "owner@example.test",
      });

      const unauthenticated: Probe[] = [];
      try {
        for (let index = 0; index < 4; index++) {
          unauthenticated.push(await Probe.connect(
            `ws://127.0.0.1:${limitedDataPort}`,
            "app://obsidian.md",
            { "X-Forwarded-For": "198.51.100.20" },
          ));
        }
        await expectWebSocketRejected(
          `ws://127.0.0.1:${limitedDataPort}`,
          "app://obsidian.md",
          { "X-Forwarded-For": "198.51.100.20" },
        );
        const otherSource = await Probe.connect(
          `ws://127.0.0.1:${limitedDataPort}`,
          "app://obsidian.md",
          { "X-Forwarded-For": "198.51.100.21" },
        );
        otherSource.socket.close();
      } finally {
        for (const probe of unauthenticated) probe.socket.close();
      }
    } finally {
      if (child.exitCode === null) child.kill("SIGTERM");
      await child.exited;
    }
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
async function postAt(port: number, path: string, body: Record<string, unknown>, extraHeaders: Record<string, string> = {}) { const response = await fetch(`http://127.0.0.1:${port}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: "app://obsidian.md", ...extraHeaders }, body: JSON.stringify(body) }); return response.json(); }
function metricValue(metrics: string, name: string): number { const line = metrics.split("\n").find((entry) => entry.startsWith(`${name} `)); if (!line) throw new Error(`missing metric: ${name}`); return Number(line.slice(name.length + 1)); }
async function waitForHealthAt(port: number, child: ReturnType<typeof Bun.spawn>) { const deadline = Date.now() + 30_000; while (Date.now() < deadline) { if (child.exitCode !== null) throw new Error(`server exited early: ${await new Response(child.stderr as ReadableStream<Uint8Array>).text()}`); try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) return; } catch {} await Bun.sleep(50); } throw new Error("Rust server did not become healthy"); }
async function stagedParts(path: string) { return (await readdir(path)).filter((name) => name.endsWith(".part")); }
async function waitForDirectoryEmpty(path: string, milliseconds: number) { const deadline = Date.now() + milliseconds; while (Date.now() < deadline) { if ((await stagedParts(path)).length === 0) return; await Bun.sleep(25); } throw new Error(`staging directory still contains partial uploads: ${path}`); }
async function freePort(): Promise<number> { return new Promise((resolve, reject) => { const server = createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const address = server.address(); if (!address || typeof address === "string") return reject(new Error("no port")); server.close(() => resolve(address.port)); }); }); }

async function openSlowControlRequest(port: number) {
  const socket = createConnection({ host: "127.0.0.1", port });
  let received = "";
  let resolveResponse!: (value: string) => void;
  let rejectResponse!: (error: Error) => void;
  const response = new Promise<string>((resolve, reject) => { resolveResponse = resolve; rejectResponse = reject; });
  socket.on("data", (chunk) => {
    received += chunk.toString();
    if (received.includes(" 408 ")) resolveResponse(received);
  });
  socket.on("error", (error) => {
    if (!received.includes(" 408 ")) rejectResponse(error);
  });
  await new Promise<void>((resolveConnected, rejectConnected) => {
    socket.once("connect", resolveConnected);
    socket.once("error", rejectConnected);
  });
  socket.write(
    "POST /user/info HTTP/1.1\r\n" +
    `Host: 127.0.0.1:${port}\r\n` +
    "Content-Type: application/json\r\n" +
    "Origin: app://obsidian.md\r\n" +
    "Content-Length: 65536\r\n" +
    "Connection: keep-alive\r\n\r\n{",
  );
  return { socket, response };
}

async function openWrongOriginSlowControlRequest(port: number) {
  const socket = createConnection({ host: "127.0.0.1", port });
  let received = "";
  let resolveResponse!: (value: string) => void;
  let rejectResponse!: (error: Error) => void;
  const response = new Promise<string>((resolve, reject) => {
    resolveResponse = resolve;
    rejectResponse = reject;
  });
  socket.on("data", (chunk) => {
    received += chunk.toString();
    if (received.includes("\r\n\r\n")) resolveResponse(received);
  });
  socket.on("error", rejectResponse);
  await new Promise<void>((resolveConnected, rejectConnected) => {
    socket.once("connect", resolveConnected);
    socket.once("error", rejectConnected);
  });
  socket.write(
    "POST /user/info HTTP/1.1\r\n" +
      `Host: 127.0.0.1:${port}\r\n` +
      "Content-Type: application/json\r\n" +
      "Origin: https://evil.example\r\n" +
      "Content-Length: 65536\r\n" +
      "Connection: keep-alive\r\n\r\n{",
  );
  return { socket, response };
}

function databaseVersion(path: string, vaultId: string): number { const database = new Database(path, { readonly: true }); try { return (database.query("SELECT version FROM vaults WHERE id=?").get(vaultId) as { version: number }).version; } finally { database.close(); } }
function expireSession(path: string, sessionToken: string) { const database = new Database(path); try { const hash = createHash("sha256").update(sessionToken).digest("hex"); expect(database.query("UPDATE sessions SET expires_at=0 WHERE token_hash=?").run(hash).changes).toBe(1); } finally { database.close(); } }
async function promiseWithTimeout<T>(promise: Promise<T>, milliseconds: number, message: string): Promise<T> { return Promise.race([promise, new Promise<T>((_, reject) => setTimeout(() => reject(new Error(message)), milliseconds))]); }
async function waitForClose(probe: Probe, milliseconds: number) { return promiseWithTimeout(probe.closed, milliseconds, "websocket did not close"); }
function webSocketWithOrigin(url: string, origin: string, extraHeaders: Record<string, string> = {}) { return new WebSocket(url, { headers: { Origin: origin, ...extraHeaders } } as unknown as string[]); }
async function expectWebSocketRejected(url: string, origin: string | null, extraHeaders: Record<string, string> = {}) { await new Promise<void>((resolveRejected, reject) => { const socket = origin === null ? new WebSocket(url, { headers: extraHeaders } as unknown as string[]) : webSocketWithOrigin(url, origin, extraHeaders); const timer = setTimeout(() => { socket.close(); reject(new Error("websocket rejection timed out")); }, 2_000); let opened = false; socket.addEventListener("open", () => { opened = true; clearTimeout(timer); socket.close(); reject(new Error("websocket unexpectedly opened")); }, { once: true }); socket.addEventListener("error", () => { if (!opened) { clearTimeout(timer); resolveRejected(); } }, { once: true }); socket.addEventListener("close", () => { if (!opened) { clearTimeout(timer); resolveRejected(); } }, { once: true }); }); }

class Probe {
  private queue: unknown[] = []; private waiters: Array<(v: unknown) => void> = [];
  readonly closed: Promise<{ code: number; reason: string }>;
  private constructor(readonly socket: WebSocket) { this.closed = new Promise((resolveClosed) => socket.addEventListener("close", (event) => resolveClosed({ code: event.code, reason: event.reason }), { once: true })); socket.binaryType = "arraybuffer"; socket.addEventListener("message", (e) => { const v = typeof e.data === "string" ? JSON.parse(e.data) : e.data; const waiter = this.waiters.shift(); waiter ? waiter(v) : this.queue.push(v); }); }
  static connect(url: string, origin = "app://obsidian.md", extraHeaders: Record<string, string> = {}): Promise<Probe> { return new Promise((resolve, reject) => { const ws = webSocketWithOrigin(url, origin, extraHeaders); sockets.push(ws); const probe = new Probe(ws); ws.addEventListener("open", () => resolve(probe), { once: true }); ws.addEventListener("error", () => reject(new Error("websocket failed")), { once: true }); }); }
  json(v: Record<string, unknown>) { this.socket.send(JSON.stringify(v)); }
  async nextJson(): Promise<any> { const value = await this.next(); if (value instanceof ArrayBuffer) throw new Error("expected JSON"); return value; }
  async nextBinary(): Promise<ArrayBuffer> { const value = await this.next(); if (!(value instanceof ArrayBuffer)) throw new Error(`expected binary: ${JSON.stringify(value)}`); return value; }
  private next(): Promise<unknown> { if (this.queue.length) return Promise.resolve(this.queue.shift()); return new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error("websocket timeout")), 5_000); this.waiters.push((v) => { clearTimeout(timer); resolve(v); }); }); }
}
