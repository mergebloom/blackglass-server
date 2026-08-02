import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createServer } from "node:net";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const manifest = join(root, "apps/server-rust/Cargo.toml");
const binary =
  process.env.BLACKGLASS_RUST_BINARY ??
  join(root, "apps/server-rust/target/debug/blackglass-server");
const sockets: WebSocket[] = [];

let directory = "";
let controlPort = 0;
let dataPort = 0;
let server: ReturnType<typeof Bun.spawn>;
let ownerToken = "";
let memberToken = "";
let outsiderToken = "";
let vault: Record<string, any>;

describe("Phase 4 shared-vault collaboration", () => {
  beforeAll(async () => {
    if (!process.env.BLACKGLASS_RUST_BINARY) {
      const build = Bun.spawnSync(["cargo", "build", "--manifest-path", manifest], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
      });
      if (build.exitCode !== 0) throw new Error(build.stderr.toString());
    }
    directory = await mkdtemp(join(tmpdir(), "blackglass-collaboration-"));
    [controlPort, dataPort] = await Promise.all([freePort(), freePort()]);
    createUser("owner@example.test", "Owner", "owner-password");
    createUser("member@example.test", "Member", "member-password");
    createUser("outsider@example.test", "Outsider", "outsider-password");
    createUser("disabled@example.test", "Disabled", "disabled-password");
    userCommand("set-status", "4", "disabled");
    server = spawnServer();
    await waitForHealth();
    ownerToken = (await signin("owner@example.test", "owner-password")).token;
    memberToken = (await signin("member@example.test", "member-password")).token;
    outsiderToken = (await signin("outsider@example.test", "outsider-password")).token;
    vault = await createVault(ownerToken, "Shared custom E2EE", "custom-key", "custom-salt");
  }, 60_000);

  afterAll(async () => {
    for (const socket of sockets) {
      if (socket.readyState < WebSocket.CLOSING) socket.close();
    }
    server?.kill("SIGTERM");
    if (server) await server.exited;
  });

  test("P4-SHARE and P4-INVENTORY enforce owner/member/outsider boundaries", async () => {
    for (const email of [
      "owner@example.test",
      "unknown@example.test",
      "disabled@example.test",
    ]) {
      expect(
        await post("/vault/share/invite", {
          token: ownerToken,
          vault_uid: vault.id,
          email,
        }),
      ).toEqual({ error: "User unavailable for sharing" });
    }

    const invited = await inviteMember(vault.id);
    expect(invited).toMatchObject({
      email: "member@example.test",
      name: "Member",
      accepted: true,
    });
    expect(Number.isSafeInteger(invited.uid)).toBe(true);
    expect((await inviteMember(vault.id)).uid).toBe(invited.uid);
    expect(await post("/vault/share/list", { token: ownerToken, vault_uid: vault.id })).toEqual({
      shares: [invited],
    });

    const inventory = await post("/vault/list", {
      token: memberToken,
      supported_encryption_version: 3,
    });
    expect(inventory.vaults).toEqual([]);
    expect(inventory.limit).toBe(100);
    expect(inventory.shared).toEqual([
      expect.objectContaining({ id: vault.id, share_uid: invited.uid, keyhash: "custom-key" }),
    ]);
    expect(
      await post("/vault/access", accessEnvelope(outsiderToken, vault)),
    ).toEqual({ error: "Unable to access vault" });
    expect(await post("/vault/access", accessEnvelope(memberToken, vault))).toEqual({});
    expect(
      await post("/vault/share/list", { token: memberToken, vault_uid: vault.id }),
    ).toEqual({ error: "Unable to list collaborators" });
    expect(
      await post("/vault/share/remove", {
        token: outsiderToken,
        vault_uid: vault.id,
        share_uid: invited.uid,
      }),
    ).toEqual({ error: "Unable to remove collaborator" });
  });

  test("P4-DATA, P4-ATTRIBUTION, and P4-REVOKE synchronize and revoke immediately", async () => {
    const shares = await post("/vault/share/list", { token: ownerToken, vault_uid: vault.id });
    const shareUid = shares.shares[0].uid as number;
    const owner = await Probe.connect();
    owner.json(init(ownerToken, vault, "Owner device"));
    expect(await owner.nextJson()).toMatchObject({ res: "ok", userId: 1 });
    expect(await owner.nextJson()).toMatchObject({ op: "ready" });
    const member = await Probe.connect();
    member.json(init(memberToken, vault, "Member device"));
    expect(await member.nextJson()).toMatchObject({ res: "ok", userId: 2 });
    expect(await member.nextJson()).toMatchObject({ op: "ready" });

    owner.json(push("owner-note", "owner-hash"));
    const ownerNotice = await owner.nextJson();
    expect(ownerNotice).toMatchObject({ op: "push", path: "owner-note", user: 1 });
    expect(await owner.nextJson()).toEqual({ res: "ok" });
    expect(await member.nextJson()).toMatchObject({
      op: "push",
      path: "owner-note",
      user: 1,
    });

    member.json(push("member-note", "member-hash"));
    const memberNotice = await member.nextJson();
    expect(memberNotice).toMatchObject({ op: "push", path: "member-note", user: 2 });
    expect(await member.nextJson()).toEqual({ res: "ok" });
    expect(await owner.nextJson()).toMatchObject({
      op: "push",
      path: "member-note",
      user: 2,
    });
    owner.json({ op: "usernames" });
    expect(await owner.nextJson()).toEqual({ "1": "Owner", "2": "Member" });

    member.json({ ...push("revoked-upload", "revoked-upload-hash"), size: 1, pieces: 1 });
    expect(await member.nextJson()).toEqual({ res: "next" });

    expect(
      await post("/vault/share/remove", {
        token: ownerToken,
        vault_uid: vault.id,
        share_uid: shareUid,
      }),
    ).toEqual({});
    expect((await withTimeout(member.closed, 2_000)).code).toBe(1008);
    await waitForNoStagedParts();
    expect((await post("/vault/list", { token: memberToken })).shared).toEqual([]);
    expect(await post("/vault/access", accessEnvelope(memberToken, vault))).toEqual({
      error: "Unable to access vault",
    });

    const reinvited = await inviteMember(vault.id);
    expect(reinvited.uid).toBeGreaterThan(shareUid);
    expect(
      await post("/vault/share/remove", {
        token: memberToken,
        vault_uid: vault.id,
        share_uid: shareUid,
      }),
    ).toEqual({ error: "Unable to remove collaborator" });
    expect(
      await post("/vault/share/remove", {
        token: memberToken,
        vault_uid: vault.id,
        share_uid: reinvited.uid,
      }),
    ).toEqual({});
    expect((await post("/vault/list", { token: memberToken })).shared).toEqual([]);
    owner.socket.close();
    await owner.closed;
  });

  test("P4-MIGRATE preserves active share IDs and P4-DATA supports managed encryption", async () => {
    const active = await inviteMember(vault.id);
    const member = await Probe.connect();
    member.json(init(memberToken, vault, "Migration member"));
    expect(await member.nextJson()).toMatchObject({ res: "ok" });
    await expectReady(member);
    const replacement = await post("/vault/migrate", {
      token: ownerToken,
      vault_uid: vault.id,
      keyhash: "replacement-key",
      salt: "replacement-salt",
      region: "selfhost",
      encryption_version: 3,
    });
    // This synthetic source already uses v3, so exercise membership-preserving
    // migration on a separate legacy-encryption vault below.
    expect(replacement).toEqual({ error: "Vault already uses encryption version 3" });
    member.socket.close();
    await member.closed;

    const managed = await createVault(ownerToken, "Managed shared", null, null);
    expect(managed.password).toMatch(/^[0-9a-f]{64}$/);
    expect(
      await post("/vault/access", {
        ...accessEnvelope(ownerToken, managed),
        keyhash: "managed-derived-key",
      }),
    ).toEqual({});
    managed.keyhash = "managed-derived-key";
    const managedShare = await inviteMember(managed.id);
    const memberInventory = await post("/vault/list", { token: memberToken });
    expect(memberInventory.shared).toContainEqual(
      expect.objectContaining({
        id: managed.id,
        share_uid: managedShare.uid,
        keyhash: "managed-derived-key",
        password: managed.password,
      }),
    );
    expect(await post("/vault/access", accessEnvelope(memberToken, managed))).toEqual({});

    const legacy = await post("/vault/create", {
      token: ownerToken,
      name: "Legacy shared",
      keyhash: "legacy-key",
      salt: "legacy-salt",
      region: "selfhost",
      encryption_version: 2,
    });
    const legacyShare = await inviteMember(legacy.id);
    const legacyMember = await Probe.connect();
    legacyMember.json(init(memberToken, legacy, "Legacy migration member"));
    expect(await legacyMember.nextJson()).toMatchObject({ res: "ok" });
    expect(await legacyMember.nextJson()).toMatchObject({ op: "ready" });
    const migrated = await post("/vault/migrate", {
      token: ownerToken,
      vault_uid: legacy.id,
      keyhash: "migrated-key",
      salt: "migrated-salt",
      region: "selfhost",
      encryption_version: 3,
    });
    expect(migrated).toMatchObject({ encryption_version: 3, keyhash: "migrated-key" });
    expect(migrated.id).not.toBe(legacy.id);
    expect((await withTimeout(legacyMember.closed, 2_000)).code).toBe(1008);
    const refreshed = await post("/vault/list", { token: memberToken });
    expect(refreshed.shared).toContainEqual(
      expect.objectContaining({ id: migrated.id, share_uid: legacyShare.uid }),
    );
    expect(refreshed.shared.some((item: any) => item.id === legacy.id)).toBe(false);
    expect(active.uid).toBeGreaterThan(0);
  });

  test("P4-RACES bounds rotating unknown targets before account lookup", async () => {
    for (let index = 0; index < 16; index++) {
      expect(
        await post("/vault/share/invite", {
          token: ownerToken,
          vault_uid: vault.id,
          email: `rotating-${index}@example.test`,
        }),
      ).toEqual({ error: "User unavailable for sharing" });
    }
    expect(
      await post("/vault/share/invite", {
        token: ownerToken,
        vault_uid: vault.id,
        email: "rotating-rate-limited@example.test",
      }),
    ).toEqual({ error: "Share invitation rate limit reached" });
    const metrics = await (
      await fetch(`http://127.0.0.1:${controlPort}/metrics`)
    ).text();
    expect(metrics).toContain(
      'blackglass_share_invites_total{outcome="rate_limited"} 1',
    );
    expect(metrics).not.toContain("rotating-rate-limited@example.test");
  });
});

function spawnServer() {
  return Bun.spawn([binary, "serve"], {
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
      SELFHOST_PER_FILE_MAX: String(8 * 1024 * 1024),
      SELFHOST_STORAGE_QUOTA_BYTES: String(64 * 1024 * 1024),
      SELFHOST_STORAGE_QUOTA_BYTES_PER_OWNER: String(32 * 1024 * 1024),
      SELFHOST_ALLOWED_ORIGIN: "app://obsidian.md",
      SELFHOST_SHARING_ENABLED: "true",
      SELFHOST_LOG_FORMAT: "pretty",
    },
  });
}

function createUser(email: string, name: string, password: string) {
  const created = Bun.spawnSync(
    [binary, "user", "create", join(directory, "server.sqlite"), email, name],
    { cwd: root, stdin: Buffer.from(`${password}\n`), stdout: "pipe", stderr: "pipe" },
  );
  expect(created.exitCode, created.stderr.toString()).toBe(0);
}

function userCommand(command: string, ...args: string[]) {
  const result = Bun.spawnSync(
    [binary, "user", command, join(directory, "server.sqlite"), ...args],
    { cwd: root, stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, result.stderr.toString()).toBe(0);
}

async function signin(email: string, password: string) {
  const result = await post("/user/signin", { email, password });
  expect(result.token).toHaveLength(64);
  return result;
}

async function createVault(
  token: string,
  name: string,
  keyhash: string | null,
  salt: string | null,
) {
  return post("/vault/create", {
    token,
    name,
    keyhash,
    salt,
    region: "selfhost",
    encryption_version: 3,
  });
}

function inviteMember(vaultUid: string) {
  return post("/vault/share/invite", {
    token: ownerToken,
    vault_uid: vaultUid,
    email: "MEMBER@EXAMPLE.TEST",
  });
}

function accessEnvelope(token: string, remote: Record<string, any>) {
  return {
    token,
    vault_uid: remote.id,
    keyhash: remote.keyhash,
    host: remote.host,
    encryption_version: remote.encryption_version,
  };
}

function init(token: string, remote: Record<string, any>, device: string) {
  return {
    op: "init",
    token,
    id: remote.id,
    keyhash: remote.keyhash,
    version: 0,
    initial: true,
    device,
    encryption_version: remote.encryption_version,
  };
}

function push(path: string, hash: string) {
  return {
    op: "push",
    path,
    relatedpath: null,
    extension: "md",
    hash,
    ctime: 1,
    mtime: 2,
    folder: false,
    deleted: false,
    size: 0,
    pieces: 0,
  };
}

async function post(path: string, body: Record<string, unknown>) {
  const response = await fetch(`http://127.0.0.1:${controlPort}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "app://obsidian.md" },
    body: JSON.stringify(body),
  });
  return response.json();
}

async function waitForHealth() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) {
      throw new Error(
        `server exited early: ${await new Response(server.stderr as ReadableStream<Uint8Array>).text()}`,
      );
    }
    try {
      if ((await fetch(`http://127.0.0.1:${controlPort}/health`)).ok) return;
    } catch {}
    await Bun.sleep(50);
  }
  throw new Error("server did not become healthy");
}

async function waitForNoStagedParts() {
  const staging = join(directory, "uploads");
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    if (!(await readdir(staging)).some((name) => name.endsWith(".part"))) return;
    await Bun.sleep(20);
  }
  throw new Error("revoked upload was not discarded");
}

function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const listener = createServer();
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const address = listener.address();
      if (!address || typeof address === "string") return reject(new Error("no port"));
      listener.close(() => resolvePort(address.port));
    });
  });
}

function withTimeout<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error("operation timed out")), milliseconds),
    ),
  ]);
}

async function expectReady(probe: Probe) {
  for (;;) {
    const message = await probe.nextJson();
    if (message.op === "ready") return;
    expect(message.op).toBe("push");
  }
}

class Probe {
  private queue: unknown[] = [];
  private waiters: Array<(value: unknown) => void> = [];
  readonly closed: Promise<{ code: number; reason: string }>;

  private constructor(readonly socket: WebSocket) {
    this.closed = new Promise((resolveClosed) =>
      socket.addEventListener(
        "close",
        (event) => resolveClosed({ code: event.code, reason: event.reason }),
        { once: true },
      ),
    );
    socket.addEventListener("message", (event) => {
      const value = typeof event.data === "string" ? JSON.parse(event.data) : event.data;
      const waiter = this.waiters.shift();
      waiter ? waiter(value) : this.queue.push(value);
    });
  }

  static connect(): Promise<Probe> {
    return new Promise((resolveProbe, reject) => {
      const socket = new WebSocket(`ws://127.0.0.1:${dataPort}`, {
        headers: { Origin: "app://obsidian.md" },
      } as unknown as string[]);
      sockets.push(socket);
      const probe = new Probe(socket);
      socket.addEventListener("open", () => resolveProbe(probe), { once: true });
      socket.addEventListener("error", () => reject(new Error("websocket failed")), {
        once: true,
      });
    });
  }

  json(value: Record<string, unknown>) {
    this.socket.send(JSON.stringify(value));
  }

  nextJson(): Promise<any> {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    return new Promise((resolveValue, reject) => {
      const timer = setTimeout(() => reject(new Error("websocket timeout")), 5_000);
      this.waiters.push((value) => {
        clearTimeout(timer);
        resolveValue(value);
      });
    });
  }
}
