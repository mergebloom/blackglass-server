import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createServer } from "node:net";
import { mkdtemp } from "node:fs/promises";
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
let ownerVault: Record<string, any>;
let memberVault: Record<string, any>;

describe("Phase 3 tenant isolation", () => {
  beforeAll(async () => {
    if (!process.env.BLACKGLASS_RUST_BINARY) {
      const build = Bun.spawnSync(["cargo", "build", "--manifest-path", manifest], {
        cwd: root,
        stdout: "pipe",
        stderr: "pipe",
      });
      if (build.exitCode !== 0) throw new Error(build.stderr.toString());
    }

    directory = await mkdtemp(join(tmpdir(), "blackglass-tenants-"));
    [controlPort, dataPort] = await Promise.all([freePort(), freePort()]);

    createUser("owner@example.test", "Rust test owner", "test-password");
    createUser("member@example.test", "Member", "member-password");
    createUser("outsider@example.test", "Outsider", "outsider-password");
    const listed = Bun.spawnSync([binary, "user", "list", join(directory, "server.sqlite")], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(listed.exitCode, listed.stderr.toString()).toBe(0);
    expect(JSON.parse(listed.stdout.toString())).toMatchObject([
      { id: 1, email: "owner@example.test", status: "active" },
      { id: 2, email: "member@example.test", status: "active" },
      { id: 3, email: "outsider@example.test", status: "active" },
    ]);

    server = spawnServer();
    await waitForHealth(server);
    ownerToken = (await signin("OWNER@EXAMPLE.TEST", "test-password")).token;
    memberToken = (await signin("member@example.test", "member-password")).token;
    outsiderToken = (await signin("outsider@example.test", "outsider-password")).token;
    ownerVault = await createVault(ownerToken, "Owner vault");
    memberVault = await createVault(memberToken, "Member vault");
  }, 60_000);

  afterAll(async () => {
    for (const socket of sockets) socket.close();
    if (server) await stopServer();
  });

  test("P3-AUTH and P3-CONTROL scope sessions and vault inventory", async () => {
    expect(await post("/vault/list", { token: ownerToken })).toMatchObject({
      vaults: [{ id: ownerVault.id }],
      shared: [],
      limit: 100,
    });
    expect(await post("/vault/list", { token: memberToken })).toMatchObject({
      vaults: [{ id: memberVault.id }],
      shared: [],
      limit: 100,
    });
    expect(await post("/vault/list", { token: outsiderToken })).toMatchObject({
      vaults: [],
      shared: [],
      limit: 100,
    });

    const crossAccess = await post("/vault/access", {
      token: memberToken,
      vault_uid: ownerVault.id,
      keyhash: ownerVault.keyhash,
      host: ownerVault.host,
      encryption_version: ownerVault.encryption_version,
    });
    expect(crossAccess).toEqual({ error: "Unable to access vault" });
    expect(
      await post("/vault/rename", {
        token: memberToken,
        vault_uid: ownerVault.id,
        name: "Cross-tenant rename",
      }),
    ).toEqual({ error: "Unable to rename vault" });
    expect(
      await post("/vault/delete", { token: outsiderToken, vault_uid: ownerVault.id }),
    ).toEqual({ error: "Unable to delete vault" });
    expect((await post("/vault/list", { token: ownerToken })).vaults[0].name).toBe(
      "Owner vault",
    );
  });

  test("P3-DATA binds each socket to its session user and owned vault", async () => {
    const owner = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    owner.json(init(ownerToken, ownerVault, "Owner device"));
    expect(await owner.nextJson()).toMatchObject({ res: "ok", userId: 1 });
    expect(await owner.nextJson()).toMatchObject({ op: "ready" });

    const member = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    member.json(init(memberToken, memberVault, "Member device"));
    expect(await member.nextJson()).toMatchObject({ res: "ok", userId: 2 });
    expect(await member.nextJson()).toMatchObject({ op: "ready" });

    owner.json({ op: "usernames" });
    expect(await owner.nextJson()).toEqual({ "1": "Rust test owner" });
    member.json({ op: "usernames" });
    expect(await member.nextJson()).toEqual({ "2": "Member" });

    owner.json({ op: "size" });
    expect(await owner.nextJson()).toMatchObject({
      res: "ok",
      size: 0,
      limit: 16 * 1024 * 1024,
      vault_size: 0,
    });

    const ownerSecond = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    ownerSecond.json(init(ownerToken, ownerVault, "Owner second device"));
    expect(await ownerSecond.nextJson()).toMatchObject({ res: "ok", userId: 1 });
    expect(await ownerSecond.nextJson()).toMatchObject({ op: "ready" });

    owner.json({
      op: "push",
      path: "held-upload",
      relatedpath: null,
      extension: "bin",
      hash: "held-hash",
      ctime: 1,
      mtime: 2,
      folder: false,
      deleted: false,
      size: 1,
      pieces: 1,
    });
    expect(await owner.nextJson()).toEqual({ res: "next" });
    ownerSecond.json({
      op: "push",
      path: "denied-upload",
      relatedpath: null,
      extension: "bin",
      hash: "denied-hash",
      ctime: 1,
      mtime: 2,
      folder: false,
      deleted: false,
      size: 1,
      pieces: 1,
    });
    expect(await ownerSecond.nextJson()).toEqual({
      err: "Account upload capacity reached; retry shortly",
    });

    const ownerOverLimit = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    ownerOverLimit.json(init(ownerToken, ownerVault, "Owner over limit"));
    expect(await ownerOverLimit.nextJson()).toEqual({
      res: "err",
      msg: "Account connection capacity reached; retry shortly",
    });
    expect((await ownerOverLimit.closed).code).toBe(1013);

    const cross = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    cross.json(init(memberToken, ownerVault, "Cross-tenant device"));
    expect(await cross.nextJson()).toEqual({ res: "err", msg: "Vault not found" });
    expect((await cross.closed).code).toBe(1008);
    owner.socket.close();
    ownerSecond.socket.close();
    member.socket.close();
    await Promise.all([owner.closed, ownerSecond.closed, member.closed]);
  });

  test("P3-REVOKE signout immediately closes only the matching session sockets", async () => {
    const owner = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    owner.json(init(ownerToken, ownerVault, "Owner revocation device"));
    expect(await owner.nextJson()).toMatchObject({ res: "ok", userId: 1 });
    expect(await owner.nextJson()).toMatchObject({ op: "ready" });

    const member = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    member.json(init(memberToken, memberVault, "Member surviving device"));
    expect(await member.nextJson()).toMatchObject({ res: "ok", userId: 2 });
    expect(await member.nextJson()).toMatchObject({ op: "ready" });

    expect(await post("/user/signout", { token: ownerToken })).toEqual({});
    expect((await withTimeout(owner.closed, 2_000)).code).toBe(1008);
    member.json({ op: "ping" });
    expect(await member.nextJson()).toEqual({ op: "pong" });
  });

  test("P3-CLI-LOCK refuses online lifecycle work and password replacement revokes sessions", async () => {
    const database = join(directory, "server.sqlite");
    const commands: Array<{ args: string[]; input?: string }> = [
      { args: ["user", "list", database] },
      {
        args: ["user", "create", database, "blocked@example.test", "Blocked"],
        input: "blocked-password\n",
      },
      { args: ["user", "set-password", database, "2"], input: "replacement\n" },
      { args: ["user", "set-email", database, "2", "changed@example.test"] },
      { args: ["user", "set-name", database, "2", "Changed"] },
      { args: ["user", "set-status", database, "2", "disabled"] },
      { args: ["user", "revoke-sessions", database, "2"] },
    ];
    for (const command of commands) {
      const blocked = Bun.spawnSync([binary, ...command.args], {
        cwd: root,
        stdin: command.input ? Buffer.from(command.input) : undefined,
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(blocked.exitCode).not.toBe(0);
      expect(blocked.stderr.toString()).toContain(
        "database state is already locked by another Blackglass Server process",
      );
    }

    await stopServer();
    const replacement = Bun.spawnSync(
      [binary, "user", "set-password", database, "2"],
      {
        cwd: root,
        stdin: Buffer.from("replacement-password\n"),
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    expect(replacement.exitCode, replacement.stderr.toString()).toBe(0);

    server = spawnServer();
    await waitForHealth(server);
    expect(await post("/user/info", { token: memberToken })).toEqual({
      error: "Not logged in",
    });
    expect(await post("/user/signin", {
      email: "member@example.test",
      password: "member-password",
    })).toEqual({ error: "Invalid email or password" });
    const replacementSignin = await signin(
      "member@example.test",
      "replacement-password",
    );
    expect(replacementSignin.name).toBe("Member");
    memberToken = replacementSignin.token;
  }, 60_000);
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
      SELFHOST_STORAGE_QUOTA_BYTES: String(32 * 1024 * 1024),
      SELFHOST_STORAGE_QUOTA_BYTES_PER_OWNER: String(16 * 1024 * 1024),
      SELFHOST_MAX_WS_CONNECTIONS_PER_USER: "2",
      SELFHOST_MAX_CONCURRENT_UPLOADS_PER_USER: "1",
      SELFHOST_ALLOWED_ORIGIN: "app://obsidian.md",
      SELFHOST_LOG_FORMAT: "pretty",
    },
  });
}

function createUser(email: string, name: string, password: string) {
  const created = Bun.spawnSync(
    [binary, "user", "create", join(directory, "server.sqlite"), email, name],
    {
      cwd: root,
      stdin: Buffer.from(`${password}\n`),
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  expect(created.exitCode, created.stderr.toString()).toBe(0);
}

async function signin(email: string, password: string) {
  const result = await post("/user/signin", { email, password });
  expect(result.token).toHaveLength(64);
  return result;
}

async function createVault(token: string, name: string) {
  return post("/vault/create", {
    token,
    name,
    keyhash: `${name}-keyhash`,
    salt: `${name}-salt`,
    region: "selfhost",
    encryption_version: 3,
  });
}

async function post(path: string, body: Record<string, unknown>) {
  const response = await fetch(`http://127.0.0.1:${controlPort}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "app://obsidian.md" },
    body: JSON.stringify(body),
  });
  return response.json();
}

function init(token: string, vault: Record<string, any>, device: string) {
  return {
    op: "init",
    token,
    id: vault.id,
    keyhash: vault.keyhash,
    version: 0,
    initial: true,
    device,
    encryption_version: vault.encryption_version,
  };
}

async function stopServer() {
  server.kill("SIGTERM");
  await server.exited;
}

async function waitForHealth(child: ReturnType<typeof Bun.spawn>) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `server exited early: ${await new Response(child.stderr as ReadableStream<Uint8Array>).text()}`,
      );
    }
    try {
      if ((await fetch(`http://127.0.0.1:${controlPort}/health`)).ok) return;
    } catch {}
    await Bun.sleep(50);
  }
  throw new Error("server did not become healthy");
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

  static connect(url: string): Promise<Probe> {
    return new Promise((resolveProbe, reject) => {
      const socket = new WebSocket(url, {
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
