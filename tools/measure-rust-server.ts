import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { mkdir, mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const pieceBytes = 2 * 1024 * 1024;
const uploadBytes = 64 * 1024 * 1024;
const pieces = uploadBytes / pieceBytes;
const websocketConnections = 16;
const concurrentUploads = 4;
const concurrentPulls = 8;
const concurrentArgonRequests = 10;
const historyRevisions = 100;
const maxPeakRssMiB = 224;
const maxDeltaRssMiB = 128;
const resourcePassword = "resource-password";
// A deterministic, non-secret test fixture at every accepted Argon2 work
// maximum. Starting the server with it makes the measured password queue cover
// the production configuration envelope rather than only the generated
// default. Changing the accepted policy without updating this gate fails fast.
const maximumWorkPasswordHash =
  "$argon2id$v=19$m=65536,t=5,p=4$YmxhY2tnbGFzcy1yZXNvdXJjZS1lbnZlbG9wZS12MQ$qF1GQ0hLTNgx8hhl7Qo3R7r1pSYB+eYXdX4KtmWP5VI";

class Probe {
  private queue: unknown[] = [];
  private waiters: Array<(value: unknown) => void> = [];

  private constructor(readonly socket: WebSocket) {
    socket.binaryType = "arraybuffer";
    socket.addEventListener("message", (event) => {
      const value = typeof event.data === "string" ? JSON.parse(event.data) : event.data;
      const waiter = this.waiters.shift();
      if (waiter) waiter(value);
      else this.queue.push(value);
    });
  }

  static connect(url: string): Promise<Probe> {
    return new Promise((resolveProbe, reject) => {
      const socket = new WebSocket(url, {
        headers: { Origin: "app://obsidian.md" },
      } as unknown as string[]);
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

  next(): Promise<any> {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    return new Promise((resolveValue, reject) => {
      const timer = setTimeout(() => reject(new Error("websocket timeout")), 60_000);
      this.waiters.push((value) => {
        clearTimeout(timer);
        resolveValue(value);
      });
    });
  }
}

const output = resolve(Bun.argv[2] ?? ".data/validation/rust-resource-report.json");
const root = resolve(import.meta.dir, "..");
const binary = resolve(
  process.env.BLACKGLASS_RUST_BINARY ??
    join(root, "apps/server-rust/target/release/blackglass-server"),
);
if (!(await Bun.file(binary).exists())) {
  throw new Error(`release server binary does not exist: ${binary}`);
}
const buildInfoResult = Bun.spawnSync([binary, "build-info"], {
  stdout: "pipe",
  stderr: "pipe",
});
if (buildInfoResult.exitCode !== 0) throw new Error(buildInfoResult.stderr.toString());
const buildInfo = JSON.parse(buildInfoResult.stdout.toString());
const directory = await mkdtemp(join(tmpdir(), "blackglass-rust-resource-"));
const [controlPort, dataPort] = await freePorts(2);
const child = Bun.spawn([binary, "serve"], {
  cwd: root,
  stdout: "ignore",
  stderr: "ignore",
  env: {
    ...process.env,
    SELFHOST_BIND_HOST: "127.0.0.1",
    SELFHOST_CONTROL_PORT: String(controlPort),
    SELFHOST_DATA_PORT: String(dataPort),
    SELFHOST_DATA_HOST: `127.0.0.1:${dataPort}`,
    SELFHOST_DATABASE: join(directory, "server.sqlite"),
    SELFHOST_STAGING_DIR: join(directory, "uploads"),
    SELFHOST_EMAIL: "resource@example.test",
    SELFHOST_PASSWORD_HASH: maximumWorkPasswordHash,
    SELFHOST_NAME: "Resource test",
    SELFHOST_PER_FILE_MAX: String(128 * 1024 * 1024),
    SELFHOST_MAX_CONCURRENT_UPLOADS: String(concurrentUploads),
    SELFHOST_ALLOWED_ORIGINS: "app://obsidian.md",
    SELFHOST_TRUSTED_PROXY: "127.0.0.1",
    SELFHOST_LOG_FORMAT: "pretty",
  },
});
const probes: Probe[] = [];

try {
  await waitHealth();
  const signin = await post("/user/signin", {
    email: "resource@example.test",
    password: resourcePassword,
  });
  if (typeof signin.token !== "string") throw new Error("resource sign-in failed");
  const vault = await post("/vault/create", {
    token: signin.token,
    name: "Resource vault",
    keyhash: "opaque-key",
    salt: "opaque-salt",
    region: "selfhost",
    encryption_version: 3,
  });
  if (typeof vault.id !== "string") throw new Error("resource vault creation failed");

  const sourceProbes: Probe[] = [];
  const writer = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
  sourceProbes.push(writer);
  probes.push(writer);
  await initialize(writer, signin.token, vault, "Resource writer");
  const uploaded = await upload(writer, "seed-large-opaque-path", "seed-large-opaque-hash");

  const historyPath = `history-${"x".repeat(16_000)}`;
  for (let index = 0; index < historyRevisions; index++) {
    writer.json(metadataPush(historyPath, `history-${index}`));
    const notice = await writer.next();
    const committed = await writer.next();
    if (notice.op !== "push" || committed.res !== "ok") {
      throw new Error("history setup did not commit");
    }
  }

  for (let index = 1; index < websocketConnections - concurrentUploads; index++) {
    const probe = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    sourceProbes.push(probe);
    probes.push(probe);
    await initialize(probe, signin.token, vault, `Resource reader ${index}`);
  }

  const uploadProbes: Probe[] = [];
  for (let index = 0; index < concurrentUploads; index++) {
    const uploadVault = await post("/vault/create", {
      token: signin.token,
      name: `Concurrent upload vault ${index}`,
      keyhash: `opaque-upload-key-${index}`,
      salt: `opaque-upload-salt-${index}`,
      region: "selfhost",
      encryption_version: 3,
    });
    if (typeof uploadVault.id !== "string") {
      throw new Error("concurrent upload vault creation failed");
    }
    const probe = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
    uploadProbes.push(probe);
    probes.push(probe);
    await initialize(probe, signin.token, uploadVault, `Resource uploader ${index}`);
  }
  await Bun.sleep(100);

  const baselineRssKiB = await rss();
  let peakRssKiB = baselineRssKiB;
  const rssSamplesKiB: number[] = [];
  const sharedUploadPiece = new Uint8Array(randomBytes(pieceBytes));
  const uploadWork = uploadProbes.map((probe, index) =>
    upload(
      probe,
      `concurrent-large-opaque-path-${index}`,
      `concurrent-large-opaque-hash-${index}`,
      sharedUploadPiece,
    ),
  );
  const pullWork = sourceProbes
    .slice(1, concurrentPulls + 1)
    .map((probe) => download(probe, uploaded.uid));
  const historyWork = requestHistory(writer, historyPath);
  const argonWork = Array.from({ length: concurrentArgonRequests }, (_, index) =>
    post(
      "/user/signin",
      { email: "resource@example.test", password: `wrong-${index}` },
      { "x-forwarded-for": `198.51.100.${index + 1}` },
    ),
  );
  let workSettled = false;
  const work = Promise.all([
    Promise.all(uploadWork),
    Promise.all(pullWork),
    historyWork,
    Promise.all(argonWork),
  ]).finally(() => {
    workSettled = true;
  });
  while (!workSettled) {
    const sample = await rss();
    rssSamplesKiB.push(sample);
    peakRssKiB = Math.max(peakRssKiB, sample);
    await Bun.sleep(25);
  }
  const [uploadResults, downloadSizes, historyResponse, signinResponses] = await work;
  peakRssKiB = Math.max(peakRssKiB, await rss());

  if (uploadResults.length !== concurrentUploads) {
    throw new Error("not every concurrent upload committed");
  }
  if (downloadSizes.some((size) => size !== uploadBytes)) {
    throw new Error("a concurrent pull returned incomplete content");
  }
  if (!Array.isArray(historyResponse.items) || historyResponse.items.length !== historyRevisions) {
    throw new Error("large history response was incomplete");
  }
  if (
    signinResponses.some(
      (response) =>
        response.error !== "Invalid email or password" && response.error !== "Try again later",
    )
  ) {
    throw new Error("bounded Argon2 workload returned an unexpected response");
  }

  const databaseBytes = (await stat(join(directory, "server.sqlite"))).size;
  const stagingEntries = await readdir(join(directory, "uploads"));
  const unexpectedStagingEntries = stagingEntries.filter(
    (entry) => entry !== ".blackglass-staging-v1",
  );
  const binarySha256 = createHash("sha256")
    .update(Buffer.from(await Bun.file(binary).arrayBuffer()))
    .digest("hex");
  const deltaRssKiB = peakRssKiB - baselineRssKiB;
  const peakRssMiB = peakRssKiB / 1024;
  const deltaRssMiB = deltaRssKiB / 1024;
  const largeResponseBytes = Buffer.byteLength(JSON.stringify(historyResponse));
  const workloadPassed =
    probes.length === websocketConnections &&
    sourceProbes.length === websocketConnections - concurrentUploads &&
    uploadProbes.length === concurrentUploads &&
    uploadResults.length === concurrentUploads &&
    downloadSizes.length === concurrentPulls &&
    unexpectedStagingEntries.length === 0;
  const report = {
    schemaVersion: 3,
    passed:
      workloadPassed && peakRssMiB < maxPeakRssMiB && deltaRssMiB < maxDeltaRssMiB,
    implementation: "rust-release",
    target: process.env.BLACKGLASS_RELEASE_TARGET ?? `${process.platform}-${process.arch}`,
    binaryName: basename(binary),
    binarySha256,
    sourceRevision: buildInfo.sourceRevision,
    workload: {
      seedUploadBytes: uploadBytes,
      uploadBytesEach: uploadBytes,
      concurrentUploads,
      measuredUploadBytes: uploadBytes * concurrentUploads,
      pieceBytes,
      pieces,
      websocketConnections,
      concurrentPulls,
      concurrentArgonRequests,
      argon2PolicyMaximum: {
        algorithm: "argon2id",
        version: 19,
        memoryKiB: 65_536,
        timeCost: 5,
        parallelism: 4,
        concurrentChecks: 1,
      },
      historyRevisions,
      largeResponseBytes,
    },
    baselineRssKiB,
    rssSamplesKiB,
    peakRssKiB,
    deltaRssKiB,
    peakRssMiB,
    deltaRssMiB,
    databaseBytes,
    stagingEntries,
    unexpectedStagingEntries,
    limits: { maxPeakRssMiB, maxDeltaRssMiB },
  };
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  console.log(JSON.stringify(report, null, 2));
  if (!report.passed) process.exitCode = 1;
} finally {
  for (const probe of probes) probe.socket.close();
  child.kill("SIGTERM");
  await child.exited;
  await rm(directory, { recursive: true, force: true });
}

async function initialize(
  probe: Probe,
  token: string,
  vault: Record<string, any>,
  device: string,
) {
  probe.json({
    op: "init",
    token,
    id: vault.id,
    keyhash: vault.keyhash,
    version: 0,
    initial: true,
    device,
    encryption_version: 3,
  });
  const accepted = await probe.next();
  if (accepted.res !== "ok") throw new Error("websocket init failed");
  while (true) {
    const message = await probe.next();
    if (message.op === "ready") return;
  }
}

async function upload(
  probe: Probe,
  path: string,
  hash: string,
  payload = new Uint8Array(randomBytes(pieceBytes)),
): Promise<{ uid: number }> {
  probe.json({
    ...metadataPush(path, hash),
    extension: "bin",
    size: uploadBytes,
    pieces,
  });
  expectNext(await probe.next());
  for (let index = 0; index < pieces; index++) {
    probe.socket.send(payload);
    if (index < pieces - 1) expectNext(await probe.next());
  }
  const notice = await probe.next();
  const committed = await probe.next();
  if (notice.op !== "push" || committed.res !== "ok" || typeof notice.uid !== "number") {
    throw new Error("upload did not commit");
  }
  return { uid: notice.uid };
}

async function download(probe: Probe, uid: number): Promise<number> {
  probe.json({ op: "pull", uid });
  const info = await probe.next();
  if (info.res !== "ok" || info.size !== uploadBytes || info.pieces !== pieces) {
    throw new Error("pull metadata was invalid");
  }
  let received = 0;
  for (let index = 0; index < pieces; index++) {
    const chunk = await probe.next();
    if (!(chunk instanceof ArrayBuffer)) throw new Error("pull piece was not binary");
    received += chunk.byteLength;
  }
  return received;
}

async function requestHistory(probe: Probe, path: string) {
  probe.json({ op: "history", path, last: null });
  return probe.next();
}

function metadataPush(path: string, hash: string) {
  return {
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
  };
}

async function rss(): Promise<number> {
  const result = Bun.spawnSync(["ps", "-o", "rss=", "-p", String(child.pid)], {
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) throw new Error(result.stderr.toString());
  return Number(result.stdout.toString().trim());
}

async function post(
  path: string,
  body: Record<string, unknown>,
  extraHeaders: Record<string, string> = {},
) {
  const response = await fetch(`http://127.0.0.1:${controlPort}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "app://obsidian.md",
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
  return response.json();
}

async function waitHealth() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("server exited early");
    try {
      if ((await fetch(`http://127.0.0.1:${controlPort}/ready`)).ok) return;
    } catch {}
    await Bun.sleep(50);
  }
  throw new Error("health timeout");
}

async function freePorts(count: number): Promise<number[]> {
  const servers = Array.from({ length: count }, () => createServer());
  try {
    const ports = await Promise.all(
      servers.map(
        (server) =>
          new Promise<number>((resolvePort, reject) => {
            server.once("error", reject);
            server.listen(0, "127.0.0.1", () => {
              const address = server.address();
              if (!address || typeof address === "string") {
                reject(new Error("unable to reserve a loopback port"));
                return;
              }
              resolvePort(address.port);
            });
          }),
      ),
    );
    return ports;
  } finally {
    await Promise.all(
      servers.map(
        (server) =>
          new Promise<void>((resolveClose) => {
            if (!server.listening) {
              resolveClose();
              return;
            }
            server.close(() => resolveClose());
          }),
      ),
    );
  }
}

function expectNext(value: any) {
  if (value.res !== "next") throw new Error(`expected next: ${JSON.stringify(value)}`);
}
