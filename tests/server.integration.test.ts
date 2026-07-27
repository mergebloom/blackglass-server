import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ServerConfig } from "../apps/server/src/config";
import {
  startService,
  type RunningService,
} from "../apps/server/src/service";

const running: RunningService[] = [];
const temporaryDirectories: string[] = [];
const sockets: WebSocket[] = [];

afterEach(async () => {
  for (const socket of sockets.splice(0)) {
    socket.close();
  }
  await Promise.all(running.splice(0).map((service) => service.stop()));
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("single-user compatibility service", () => {
  test("supports CORS and the managed-encryption control-plane lifecycle", async () => {
    const { service, config } = await createTestService();
    const preflight = await fetch(`${service.controlOrigin}/vault/list`, {
      method: "OPTIONS",
      headers: { origin: "app://obsidian.md" },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe("*");

    const created = await post(service.controlOrigin, "/vault/create", {
      token: config.token,
      name: "Managed vault",
      keyhash: null,
      region: "selfhost",
      encryption_version: 3,
    });
    expect(created.keyhash).toBeNull();
    expect(created.salt).toMatch(/^[0-9a-f]{32}$/);
    expect(created.password).toMatch(/^[0-9a-f]{64}$/);

    expect(
      await post(service.controlOrigin, "/vault/access", {
        token: config.token,
        vault_uid: created.id,
        keyhash: "client-derived-managed-keyhash",
        host: created.host,
        encryption_version: created.encryption_version,
      }),
    ).toEqual({});
    const listed = await post(service.controlOrigin, "/vault/list", {
      token: config.token,
    });
    expect(listed.vaults[0].keyhash).toBe("client-derived-managed-keyhash");

    expect(
      await post(service.controlOrigin, "/vault/rename", {
        token: config.token,
        vault_uid: created.id,
        name: "Renamed managed vault",
      }),
    ).toEqual({});
    expect(
      await post(service.controlOrigin, "/vault/share/list", {
        token: config.token,
        vault_uid: created.id,
      }),
    ).toEqual({ shares: [] });
    expect(
      await post(service.controlOrigin, "/vault/share/invite", {
        token: config.token,
        vault_uid: created.id,
      }),
    ).toEqual({ error: "Sharing is unavailable in single-user mode" });
    expect(
      await post(service.controlOrigin, "/vault/delete", {
        token: config.token,
        vault_uid: created.id,
      }),
    ).toEqual({});
    const afterDelete = await post(service.controlOrigin, "/vault/list", {
      token: config.token,
    });
    expect(afterDelete.vaults).toEqual([]);
  });

  test("signs in and creates, lists, and authorizes a vault", async () => {
    const { service, config } = await createTestService();
    const signin = await post(service.controlOrigin, "/user/signin", {
      email: config.email,
      password: config.password,
    });

    expect(signin).toMatchObject({
      email: config.email,
      token: config.token,
      license: "selfhosted-sync",
    });

    const regions = await post(service.controlOrigin, "/vault/regions", {
      token: config.token,
    });
    expect(regions).toEqual({
      regions: [{ value: "selfhost", name: "Blackglass Server" }],
    });

    const created = await post(service.controlOrigin, "/vault/create", {
      token: config.token,
      name: "Research vault",
      keyhash: "opaque-key-hash",
      salt: "opaque-salt",
      region: "selfhost",
      encryption_version: 3,
    });
    expect(created).toMatchObject({
      name: "Research vault",
      host: service.dataHost,
      keyhash: "opaque-key-hash",
      encryption_version: 3,
      size: 0,
    });

    const listed = await post(service.controlOrigin, "/vault/list", {
      token: config.token,
      supported_encryption_version: 3,
    });
    expect(listed.vaults).toHaveLength(1);
    expect(listed.vaults[0].id).toBe(created.id);
    expect(listed.shared).toEqual([]);

    const access = await post(service.controlOrigin, "/vault/access", {
      token: config.token,
      vault_uid: created.id,
      keyhash: created.keyhash,
      host: created.host,
      encryption_version: created.encryption_version,
    });
    expect(access).toEqual({});
  });

  test("authenticates the reference init envelope over WebSocket", async () => {
    const { service, config } = await createTestService();
    const created = await post(service.controlOrigin, "/vault/create", {
      token: config.token,
      name: "Socket vault",
      keyhash: "key-hash",
      salt: "salt",
      region: "selfhost",
      encryption_version: 3,
    });

    const messages = await connectAndCollect(`ws://${service.dataHost}`, {
      op: "init",
      token: config.token,
      id: created.id,
      keyhash: created.keyhash,
      version: 0,
      initial: true,
      device: "integration-test",
      encryption_version: 3,
    });

    expect(messages[0]).toEqual({
      res: "ok",
      userId: 1,
      perFileMax: config.perFileMax,
    });
    expect(messages[1]).toEqual({ op: "ready", version: 0 });
  });

  test("stores opaque encrypted bytes and serves them to a fresh client", async () => {
    const { service, config } = await createTestService();
    const created = await post(service.controlOrigin, "/vault/create", {
      token: config.token,
      name: "Data vault",
      keyhash: "key-hash",
      salt: "salt",
      region: "selfhost",
      encryption_version: 3,
    });
    const encryptedPayload = new TextEncoder().encode(
      "opaque ciphertext, not vault plaintext",
    );

    const writer = await SocketProbe.connect(`ws://${service.dataHost}`);
    await initializeProbe(writer, config, created, "Writer", 0);
    writer.sendJson({
      op: "push",
      path: "encrypted-path",
      relatedpath: null,
      extension: "md",
      hash: "encrypted-hash",
      ctime: 1_700_000_000_000,
      mtime: 1_700_000_000_100,
      folder: false,
      deleted: false,
      size: encryptedPayload.byteLength,
      pieces: 1,
    });
    expect(await writer.nextJson()).toEqual({ res: "next" });
    writer.socket.send(encryptedPayload);
    const writerNotification = await writer.nextJson();
    expect(writerNotification).toMatchObject({
      op: "push",
      path: "encrypted-path",
      hash: "encrypted-hash",
      device: "Writer",
      deleted: false,
    });
    expect(await writer.nextJson()).toEqual({ res: "ok" });

    const reader = await SocketProbe.connect(`ws://${service.dataHost}`);
    reader.sendJson(initEnvelope(config, created, "Reader", 0));
    expect(await reader.nextJson()).toMatchObject({ res: "ok", userId: 1 });
    const replayed = await reader.nextJson();
    expect(replayed).toMatchObject({
      op: "push",
      path: "encrypted-path",
      uid: writerNotification.uid,
    });
    expect(await reader.nextJson()).toEqual({
      op: "ready",
      version: writerNotification.uid,
    });

    reader.sendJson({ op: "pull", uid: replayed.uid });
    expect(await reader.nextJson()).toEqual({
      res: "ok",
      size: encryptedPayload.byteLength,
      pieces: 1,
      deleted: false,
      hash: "encrypted-hash",
    });
    expect(new Uint8Array(await reader.nextBinary())).toEqual(encryptedPayload);
  });

  test("uses live heads for initial sync and the full log for resume", async () => {
    const { service, config } = await createTestService();
    const vault = await createVault(service, config, "Replay vault");
    const writer = await SocketProbe.connect(`ws://${service.dataHost}`);
    await initializeProbe(writer, config, vault, "Writer", 0);

    const first = await pushMetadata(writer, "live-path", "hash-v1");
    const second = await pushMetadata(writer, "live-path", "hash-v2");
    const tombstone = await pushMetadata(writer, "gone-path", "gone", {
      deleted: true,
    });

    const fresh = await SocketProbe.connect(`ws://${service.dataHost}`);
    fresh.sendJson(initEnvelope(config, vault, "Fresh", 0));
    expect(await fresh.nextJson()).toMatchObject({ res: "ok" });
    expect(await fresh.nextJson()).toMatchObject({
      op: "push",
      uid: second.uid,
      path: "live-path",
    });
    expect(await fresh.nextJson()).toEqual({
      op: "ready",
      version: tombstone.uid,
    });

    const resumed = await SocketProbe.connect(`ws://${service.dataHost}`);
    resumed.sendJson({
      ...initEnvelope(config, vault, "Resumed", 0),
      initial: false,
    });
    expect(await resumed.nextJson()).toMatchObject({ res: "ok" });
    expect((await resumed.nextJson()).uid).toBe(first.uid);
    expect((await resumed.nextJson()).uid).toBe(second.uid);
    expect((await resumed.nextJson()).uid).toBe(tombstone.uid);
    expect(await resumed.nextJson()).toEqual({
      op: "ready",
      version: tombstone.uid,
    });
  });

  test("lists deleted/history entries, restores revisions, and purges safely", async () => {
    const { service, config } = await createTestService();
    const vault = await createVault(service, config, "History vault");
    const probe = await SocketProbe.connect(`ws://${service.dataHost}`);
    await initializeProbe(probe, config, vault, "History tester", 0);

    const v1 = await pushMetadata(probe, "document-path", "hash-v1");
    const v2 = await pushMetadata(probe, "document-path", "hash-v2");
    const deleted = await pushMetadata(probe, "document-path", "", {
      deleted: true,
    });
    expect(deleted.ts).toBeGreaterThanOrEqual(v1.ts);

    probe.sendJson({ op: "deleted", suppressrenames: true });
    const deletedResponse = await probe.nextJson();
    expect(deletedResponse.items).toHaveLength(1);
    expect(deletedResponse.items[0]).toMatchObject({
      uid: deleted.uid,
      deleted: true,
      device: "History tester",
    });

    probe.sendJson({ op: "history", path: "document-path", last: null });
    const history = await probe.nextJson();
    expect(history.more).toBe(false);
    expect(history.items.map((item: any) => item.uid)).toEqual([
      deleted.uid,
      v2.uid,
      v1.uid,
    ]);
    expect(history.items.every((item: any) => Number.isInteger(item.ts))).toBe(true);

    probe.sendJson({ op: "restore", uid: deleted.uid });
    const restored = await probe.nextJson();
    expect(restored).toMatchObject({
      op: "push",
      path: "document-path",
      hash: "hash-v2",
      deleted: false,
      relatedpath: null,
    });
    expect(await probe.nextJson()).toEqual({ res: "ok" });

    await pushMetadata(probe, "old-path", "old-live");
    await pushMetadata(probe, "old-path", "", { deleted: true });
    await pushMetadata(probe, "new-path", "new-live", {
      relatedpath: "old-path",
    });
    probe.sendJson({ op: "deleted", suppressrenames: true });
    expect((await probe.nextJson()).items).toEqual([]);
    probe.sendJson({ op: "deleted", suppressrenames: false });
    expect((await probe.nextJson()).items).toHaveLength(1);

    probe.sendJson({ op: "purge" });
    expect(await probe.nextJson()).toEqual({ res: "ok" });
    probe.sendJson({ op: "history", path: "document-path", last: null });
    const afterPurge = await probe.nextJson();
    expect(afterPurge.items).toHaveLength(1);
    expect(afterPurge.items[0].uid).toBe(restored.uid);
    probe.sendJson({ op: "history", path: "old-path", last: null });
    expect((await probe.nextJson()).items).toEqual([]);
  });

  test("rejects bad credentials and mismatched vault access", async () => {
    const { service, config } = await createTestService();
    expect(
      await post(service.controlOrigin, "/user/signin", {
        email: config.email,
        password: "incorrect",
      }),
    ).toEqual({ error: "Invalid email or password" });

    expect(
      await post(service.controlOrigin, "/vault/access", {
        token: config.token,
        vault_uid: "missing",
        keyhash: null,
        host: service.dataHost,
        encryption_version: 3,
      }),
    ).toEqual({ error: "Unable to access vault" });
  });
});

async function createVault(
  service: RunningService,
  config: ServerConfig,
  name: string,
): Promise<Record<string, any>> {
  return post(service.controlOrigin, "/vault/create", {
    token: config.token,
    name,
    keyhash: "key-hash",
    salt: "salt",
    region: "selfhost",
    encryption_version: 3,
  });
}

async function pushMetadata(
  probe: SocketProbe,
  path: string,
  hash: string,
  overrides: Partial<Record<string, unknown>> = {},
): Promise<Record<string, any>> {
  probe.sendJson({
    op: "push",
    path,
    relatedpath: null,
    extension: "md",
    hash,
    ctime: 1_700_000_000_000,
    mtime: 1_700_000_000_100,
    folder: false,
    deleted: false,
    size: 0,
    pieces: 0,
    ...overrides,
  });
  const notification = await probe.nextJson();
  expect(notification).toMatchObject({ op: "push", path });
  expect(await probe.nextJson()).toEqual({ res: "ok" });
  return notification;
}

async function createTestService(): Promise<{
  service: RunningService;
  config: ServerConfig;
}> {
  const directory = await mkdtemp(join(tmpdir(), "blackglass-server-"));
  temporaryDirectories.push(directory);
  const config: ServerConfig = {
    bindHost: "127.0.0.1",
    controlPort: 0,
    dataPort: 0,
    publicDataHost: "",
    databasePath: join(directory, "test.sqlite"),
    email: "admin@example.test",
    password: "test-password",
    token: "test-token-with-at-least-24-characters",
    displayName: "Integration test user",
    perFileMax: 1024 * 1024,
  };
  const provisional = startService(config);
  config.publicDataHost = provisional.dataHost;
  running.push(provisional);
  return { service: provisional, config };
}

async function post(
  origin: string,
  path: string,
  body: Record<string, unknown>,
): Promise<any> {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
  });
  return response.json();
}

function connectAndCollect(
  url: string,
  init: Record<string, unknown>,
): Promise<Record<string, unknown>[]> {
  return new Promise((resolve, reject) => {
    const messages: Record<string, unknown>[] = [];
    const socket = new WebSocket(url);
    sockets.push(socket);
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error("Timed out waiting for WebSocket messages"));
    }, 2_000);

    socket.addEventListener("open", () => {
      socket.send(JSON.stringify(init));
    });
    socket.addEventListener("message", (event) => {
      messages.push(JSON.parse(String(event.data)));
      if (messages.length === 2) {
        clearTimeout(timeout);
        socket.close();
        resolve(messages);
      }
    });
    socket.addEventListener("error", () => {
      clearTimeout(timeout);
      reject(new Error("WebSocket connection failed"));
    });
  });
}

async function initializeProbe(
  probe: SocketProbe,
  config: ServerConfig,
  vault: Record<string, any>,
  device: string,
  version: number,
): Promise<void> {
  probe.sendJson(initEnvelope(config, vault, device, version));
  expect(await probe.nextJson()).toMatchObject({ res: "ok", userId: 1 });
  expect(await probe.nextJson()).toEqual({ op: "ready", version });
}

function initEnvelope(
  config: ServerConfig,
  vault: Record<string, any>,
  device: string,
  version: number,
): Record<string, unknown> {
  return {
    op: "init",
    token: config.token,
    id: vault.id,
    keyhash: vault.keyhash,
    version,
    initial: version === 0,
    device,
    encryption_version: vault.encryption_version,
  };
}

class SocketProbe {
  private buffered: unknown[] = [];
  private waiters: Array<(value: unknown) => void> = [];

  private constructor(readonly socket: WebSocket) {
    socket.binaryType = "arraybuffer";
    socket.addEventListener("message", (event) => {
      const value =
        typeof event.data === "string" ? JSON.parse(event.data) : event.data;
      const waiter = this.waiters.shift();
      if (waiter) {
        waiter(value);
      } else {
        this.buffered.push(value);
      }
    });
  }

  static connect(url: string): Promise<SocketProbe> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(url);
      sockets.push(socket);
      const probe = new SocketProbe(socket);
      socket.addEventListener("open", () => resolve(probe), { once: true });
      socket.addEventListener(
        "error",
        () => reject(new Error("WebSocket connection failed")),
        { once: true },
      );
    });
  }

  sendJson(value: Record<string, unknown>): void {
    this.socket.send(JSON.stringify(value));
  }

  async nextJson(): Promise<Record<string, any>> {
    const value = await this.next();
    if (
      value === null ||
      typeof value !== "object" ||
      value instanceof ArrayBuffer
    ) {
      throw new Error("Expected a JSON WebSocket message");
    }
    return value as Record<string, any>;
  }

  async nextBinary(): Promise<ArrayBuffer> {
    const value = await this.next();
    if (!(value instanceof ArrayBuffer)) {
      throw new Error("Expected a binary WebSocket message");
    }
    return value;
  }

  private next(): Promise<unknown> {
    const buffered = this.buffered.shift();
    if (buffered !== undefined) {
      return Promise.resolve(buffered);
    }
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error("Timed out waiting for WebSocket message")),
        2_000,
      );
      this.waiters.push((value) => {
        clearTimeout(timeout);
        resolve(value);
      });
    });
  }
}
