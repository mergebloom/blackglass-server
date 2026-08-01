import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:net";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import {
  type CgroupEvents,
  cgroupResourceLimits,
  evaluateCgroupResourceGate,
  evaluateResourceGate,
  parseCgroupEvents,
  parseCgroupPidList,
  parseCgroupScalar,
  parseLinuxProcessMemoryKiB,
  parseLinuxRssKiBDuringExit,
  parseUnifiedCgroupPath,
  qualifyNativeLinuxTarget,
  resourceLimits,
  resourceReportSchemaVersion,
  subtractCgroupEvents,
} from "./resource-gate.ts";
import {
  collectFailureDiagnostics,
  observeWorkWithSamples,
  readExitKernelValue,
  rethrowWithDiagnostics,
  withMeasurementPhase,
} from "./resource-harness.ts";

const pieceBytes = 2 * 1024 * 1024;
const uploadBytes = 64 * 1024 * 1024;
const pieces = uploadBytes / pieceBytes;
const websocketConnections = 16;
const concurrentUploads = 4;
const concurrentPulls = 8;
const concurrentArgonRequests = 10;
const pullFrameConcurrencyLimit = 2;
const bulkMemoryAdmission = Object.freeze({
  totalPermits: 4,
  argon2Permits: 3,
  reservedSyncPermits: 1,
});
const historyRevisions = 128;
const historyResponseItems = 100;
const replayStormConnections = websocketConnections - concurrentUploads - 1;
const replayPageSize = 16;
const resourcePassword = "resource-password";
const resourceMode = process.env.BLACKGLASS_RESOURCE_MODE ?? "process-rss";
if (resourceMode !== "process-rss" && resourceMode !== "cgroup-v2") {
  throw new Error("BLACKGLASS_RESOURCE_MODE must be process-rss or cgroup-v2");
}
const cgroupMode = resourceMode === "cgroup-v2";
// A deterministic, non-secret test fixture at every accepted Argon2 work
// maximum. Starting the server with it makes the measured password queue cover
// the production configuration envelope rather than only the generated
// default. Changing the accepted policy without updating this gate fails fast.
const maximumWorkPasswordHash =
  "$argon2id$v=19$m=65536,t=5,p=4$YmxhY2tnbGFzcy1yZXNvdXJjZS1lbnZlbG9wZS12MQ$qF1GQ0hLTNgx8hhl7Qo3R7r1pSYB+eYXdX4KtmWP5VI";

type CgroupContext = {
  container: string;
  image: string;
  imageId: string;
  volume: string;
  stopped: boolean;
  hostPid: number;
  path: string;
  eventsPath: string;
  eventsBefore: CgroupEvents;
  artifactBinarySha256: string;
  stagedBinarySha256: string;
  inImageBinarySha256: string;
  nativeTarget: string;
  hostPlatform: string;
  hostArchitecture: string;
  elfDescription: string;
};

type ProcessMemorySnapshot = {
  rssKiB: number;
  linuxPeakRssKiB: number | null;
};

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

  static connect(url: string, extraHeaders: Record<string, string> = {}): Promise<Probe> {
    return new Promise((resolveProbe, reject) => {
      const socket = new WebSocket(url, {
        headers: { Origin: "app://obsidian.md", ...extraHeaders },
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
const expectedSourceRevision = process.env.BLACKGLASS_EXPECTED_SOURCE_REVISION;
if (
  expectedSourceRevision !== undefined &&
  (!/^[0-9a-f]{40}$/.test(expectedSourceRevision) ||
    buildInfo.sourceRevision !== expectedSourceRevision)
) {
  throw new Error("release binary source revision does not match the expected full commit");
}
if (cgroupMode && expectedSourceRevision === undefined) {
  throw new Error("cgroup-v2 qualification requires BLACKGLASS_EXPECTED_SOURCE_REVISION");
}
const directory = await mkdtemp(join(tmpdir(), "blackglass-rust-resource-"));
const [controlPort, dataPort] = await freePorts(2);
let child: ReturnType<typeof Bun.spawn> | undefined;
let cgroup: CgroupContext | undefined;
if (cgroupMode) {
  try {
    cgroup = await startCgroupContainer();
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
} else {
  child = Bun.spawn([binary, "serve"], {
    cwd: root,
    stdout: process.env.BLACKGLASS_RESOURCE_DEBUG === "1" ? "inherit" : "ignore",
    stderr: process.env.BLACKGLASS_RESOURCE_DEBUG === "1" ? "inherit" : "ignore",
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
}
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

  const replayWork: Promise<void>[] = [];
  for (let offset = 0; offset < replayStormConnections; offset++) {
    const index = offset + 1;
    const probe = await Probe.connect(`ws://127.0.0.1:${dataPort}`, {
      "x-forwarded-for": `198.51.100.${50 + index}`,
    });
    sourceProbes.push(probe);
    probes.push(probe);
    let accepted!: () => void;
    const authenticated = new Promise<void>((resolveAuthenticated) => {
      accepted = resolveAuthenticated;
    });
    const initialization = initialize(
      probe,
      signin.token,
      vault,
      `Resource reader ${index}`,
      false,
      accepted,
    );
    replayWork.push(initialization);
    await Promise.race([authenticated, initialization]);
  }
  await Promise.all(replayWork);

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

  const baselineMemory = await readActiveProcessMemorySnapshot("baseline");
  const baselineRssKiB = baselineMemory.rssKiB;
  const workloadStartedAt = performance.now();
  let linuxPeakRssKiB = baselineMemory.linuxPeakRssKiB;
  let peakRssKiB = Math.max(
    baselineRssKiB,
    baselineMemory.linuxPeakRssKiB ?? baselineRssKiB,
  );
  const rssSamplesKiB: number[] = [];
  const sampleActiveRss = async (phase: string): Promise<number> => {
    const sample = await readActiveProcessMemorySnapshot(phase);
    peakRssKiB = Math.max(
      peakRssKiB,
      sample.rssKiB,
      sample.linuxPeakRssKiB ?? sample.rssKiB,
    );
    if (sample.linuxPeakRssKiB !== null) {
      linuxPeakRssKiB = Math.max(linuxPeakRssKiB ?? 0, sample.linuxPeakRssKiB);
    }
    return sample.rssKiB;
  };
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
  const work = Promise.all([
    Promise.all(uploadWork),
    Promise.all(pullWork),
    historyWork,
    Promise.all(argonWork),
  ]);
  const [uploadResults, downloadSizes, historyResponse, signinResponses] =
    await observeWorkWithSamples(
      work,
      () => sampleActiveRss("concurrent workload"),
      (sample) => {
        rssSamplesKiB.push(sample);
      },
      () => Bun.sleep(25),
    );

  if (uploadResults.length !== concurrentUploads) {
    throw new Error("not every concurrent upload committed");
  }
  if (downloadSizes.some((size) => size !== uploadBytes)) {
    throw new Error("a concurrent pull returned incomplete content");
  }
  if (
    !Array.isArray(historyResponse.items) ||
    historyResponse.items.length !== historyResponseItems ||
    historyResponse.more !== true
  ) {
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

  // Prove that the measured binary completes maximum-policy password work
  // while the permit deliberately reserved for authenticated Sync is active.
  // Admission rejections in the larger overlap are valid, but cannot make a
  // release pass without this deterministic 1+1 phase.
  const standaloneArgonWork = post(
    "/user/signin",
    { email: "resource@example.test", password: "standalone-wrong-password" },
    { "x-forwarded-for": "198.51.100.250" },
  );
  const reservedSyncPullWork = download(sourceProbes[1]!, uploaded.uid);
  const [standaloneArgonResponse, reservedSyncPullBytes] = await observeWorkWithSamples(
    Promise.all([standaloneArgonWork, reservedSyncPullWork]),
    () => sampleActiveRss("reserved Sync and Argon2 workload"),
    (sample) => {
      rssSamplesKiB.push(sample);
    },
    () => Bun.sleep(25),
  );
  const standaloneArgon2CompletedCheck =
    standaloneArgonResponse.error === "Invalid email or password";
  const reservedSyncPullCompleted = reservedSyncPullBytes === uploadBytes;
  const argon2WithReservedSyncCompleted =
    standaloneArgon2CompletedCheck && reservedSyncPullCompleted;
  if (!argon2WithReservedSyncCompleted) {
    throw new Error("maximum-policy Argon2 and its reserved Sync lane did not complete");
  }
  const concurrentArgon2CompletedChecks = signinResponses.filter(
    (response) => response.error === "Invalid email or password",
  ).length;
  const concurrentArgon2RejectedRequests =
    signinResponses.length - concurrentArgon2CompletedChecks;
  const argon2CompletedChecks = concurrentArgon2CompletedChecks + 1;
  const durationMs = Math.round(performance.now() - workloadStartedAt);

  await sampleActiveRss("post-work");

  const binarySha256 = await sha256Path(binary);
  const largeResponseBytes = Buffer.byteLength(JSON.stringify(historyResponse));
  const protocolWorkloadPassed =
    probes.length === websocketConnections &&
    sourceProbes.length === websocketConnections - concurrentUploads &&
    uploadProbes.length === concurrentUploads &&
    uploadResults.length === concurrentUploads &&
    downloadSizes.length === concurrentPulls &&
    argon2WithReservedSyncCompleted &&
    concurrentArgon2CompletedChecks >= 1 &&
    argon2CompletedChecks >= 1;
  const reportIdentity = {
    implementation: "rust-release",
    target: process.env.BLACKGLASS_RELEASE_TARGET ?? `${process.platform}-${process.arch}`,
    binaryName: basename(binary),
    binarySha256,
    sourceRevision: buildInfo.sourceRevision,
  };
  const workload = {
    seedUploadBytes: uploadBytes,
    uploadBytesEach: uploadBytes,
    concurrentUploads,
    measuredUploadBytes: uploadBytes * concurrentUploads,
    pieceBytes,
    pieces,
    websocketConnections,
    concurrentPulls,
    pullFrameConcurrencyLimit,
    replayStormConnections,
    replayPageSize,
    replayRevisions: historyRevisions,
    concurrentArgonRequests,
    bulkMemoryAdmission,
    concurrentArgon2CompletedChecks,
    concurrentArgon2RejectedRequests,
    standaloneArgon2CompletedCheck,
    reservedSyncPullBytes,
    reservedSyncPullCompleted,
    argon2WithReservedSyncCompleted,
    argon2CompletedChecks,
    argon2PolicyMaximum: {
      algorithm: "argon2id",
      version: 19,
      memoryKiB: 65_536,
      timeCost: 5,
      parallelism: 4,
      concurrentChecks: 1,
    },
    historyRevisions,
    historyResponseItems,
    largeResponseBytes,
    durationMs,
  };
  if (cgroupMode) {
    const context = cgroup!;
    const cgroupDirectory = resolve("/sys/fs/cgroup", `.${context.path}`);
    let memoryPeakBytes = parseCgroupScalar(
      await readFile(join(cgroupDirectory, "memory.peak"), "utf8"),
      "memory.peak",
    );
    const configuredMemoryBytes = parseCgroupScalar(
      await readFile(join(cgroupDirectory, "memory.max"), "utf8"),
      "memory.max",
    );
    const configuredMemorySwapBytes = parseCgroupScalar(
      await readFile(join(cgroupDirectory, "memory.swap.max"), "utf8"),
      "memory.swap.max",
    );
    let memoryEvents = parseCgroupEvents(await readFile(context.eventsPath, "utf8"));
    const finalCgroupPids = parseCgroupPidList(
      await readFile(join(cgroupDirectory, "cgroup.procs"), "utf8"),
    );
    const finalCopiedBinary = join(directory, "in-image-binary-final");
    runDocker([
      "cp",
      `${context.container}:/usr/local/bin/blackglass-server`,
      finalCopiedBinary,
    ]);
    const finalInImageBinarySha256 = await sha256Path(finalCopiedBinary);
    for (const probe of probes) probe.socket.close();
    await Bun.sleep(100);

    const retainCgroupSnapshot = (snapshot: {
      memoryPeakBytes: number;
      memoryEvents: CgroupEvents;
    }) => {
      memoryPeakBytes = Math.max(memoryPeakBytes, snapshot.memoryPeakBytes);
      memoryEvents = snapshot.memoryEvents;
    };
    const retainProcessMemory = (snapshot: ProcessMemorySnapshot) => {
      peakRssKiB = Math.max(
        peakRssKiB,
        snapshot.rssKiB,
        snapshot.linuxPeakRssKiB ?? snapshot.rssKiB,
      );
      if (snapshot.linuxPeakRssKiB !== null) {
        linuxPeakRssKiB = Math.max(linuxPeakRssKiB ?? 0, snapshot.linuxPeakRssKiB);
      }
    };

    // The active pre-stop snapshot is strict. A missing procfs/cgroup field or
    // changed container identity before we request shutdown is a qualification
    // failure, never an exit transition.
    const preStopCgroupSnapshot = await withMeasurementPhase(
      "active cgroup memory snapshot (pre-stop)",
      async () => {
        const snapshot = await readCgroupSnapshot(cgroupDirectory, context.eventsPath);
        if (snapshot === null) throw new Error("cgroup disappeared before stop");
        return snapshot;
      },
    );
    retainCgroupSnapshot(preStopCgroupSnapshot);
    retainProcessMemory(
      await readActiveProcessMemorySnapshotForPid(context.hostPid, "pre-stop"),
    );
    const preStopInspection = dockerInspect(context.container);
    const preStopCgroupPids = await withMeasurementPhase(
      "active cgroup identity snapshot (pre-stop)",
      async () =>
        parseCgroupPidList(await readFile(join(cgroupDirectory, "cgroup.procs"), "utf8")),
    );
    if (
      preStopInspection.State.Running !== true ||
      Number(preStopInspection.State.Pid) !== context.hostPid ||
      preStopCgroupPids.length !== 1 ||
      preStopCgroupPids[0] !== context.hostPid
    ) {
      throw new Error("server process identity changed before requested stop");
    }

    const stopProcess = Bun.spawn(["docker", "stop", "--time", "30", context.container], {
      stdout: "pipe",
      stderr: "pipe",
    });
    // Docker removes the process and its cgroup after a successful stop. Keep
    // the last valid kernel snapshots while the graceful drain runs so the
    // release report includes shutdown allocations and non-killing OOM events,
    // not only the steady-state workload. Terminal tolerance is reachable only
    // after the stop command has been spawned.
    const captureShutdownMeasurements = async () => {
      const cgroupSnapshot = await withMeasurementPhase(
        "terminal cgroup memory snapshot",
        () => readCgroupSnapshot(cgroupDirectory, context.eventsPath),
      );
      if (cgroupSnapshot === null) return;
      retainCgroupSnapshot(cgroupSnapshot);
      const shutdownPeakRssKiB = await readLinuxPeakRssDuringExit(context.hostPid);
      if (shutdownPeakRssKiB !== null) {
        peakRssKiB = Math.max(peakRssKiB, shutdownPeakRssKiB);
        linuxPeakRssKiB = Math.max(linuxPeakRssKiB ?? 0, shutdownPeakRssKiB);
      }
    };
    let stopSettled = false;
    const stopCompletion = stopProcess.exited.finally(() => {
      stopSettled = true;
    });
    while (!stopSettled) {
      await captureShutdownMeasurements();
      await Bun.sleep(10);
    }
    const stopExitCode = await stopCompletion;
    await captureShutdownMeasurements();
    if (stopExitCode !== 0) {
      throw new Error(
        `docker stop failed: ${await new Response(stopProcess.stderr).text()}`,
      );
    }
    context.stopped = true;
    const memoryEventDelta = subtractCgroupEvents(memoryEvents, context.eventsBefore);
    const inspection = dockerInspect(context.container);
    const exitCode = Number(inspection.State.ExitCode);
    const oomKilled = inspection.State.OOMKilled === true;
    const stateError = String(inspection.State.Error ?? "");
    const dockerMemoryLimitBytes = Number(inspection.HostConfig.Memory);
    const dockerMemorySwapTotalBytes = Number(inspection.HostConfig.MemorySwap);
    const capturedState = join(directory, "captured-state");
    await mkdir(capturedState);
    runDocker([
      "cp",
      `${context.container}:/var/lib/blackglass-server/.`,
      capturedState,
    ]);
    const databaseBytes = (await stat(join(capturedState, "server.sqlite"))).size;
    const stagingEntries = await readdir(join(capturedState, "uploads"));
    const unexpectedStagingEntries = stagingEntries.filter(
      (entry) => entry !== ".blackglass-staging-v1",
    );
    const workloadPassed = protocolWorkloadPassed && unexpectedStagingEntries.length === 0;
    const deltaRssKiB = peakRssKiB - baselineRssKiB;
    const processEvaluation = evaluateResourceGate(
      workloadPassed,
      baselineRssKiB,
      peakRssKiB,
    );
    const { peakRssMiB, deltaRssMiB, processRssMarginMiB } = processEvaluation;
    const identityHashesMatch =
      binarySha256 === context.artifactBinarySha256 &&
      binarySha256 === context.stagedBinarySha256 &&
      binarySha256 === context.inImageBinarySha256 &&
      binarySha256 === finalInImageBinarySha256;
    const serverOnlyCgroup =
      finalCgroupPids.length === 1 && finalCgroupPids[0] === context.hostPid;
    const containerIsolationPassed =
      inspection.Config.User === "65532:65532" &&
      JSON.stringify(inspection.Config.Entrypoint) ===
        JSON.stringify(["/usr/local/bin/blackglass-server"]) &&
      JSON.stringify(inspection.Config.Cmd) === JSON.stringify(["serve"]) &&
      inspection.Path === "/usr/local/bin/blackglass-server" &&
      JSON.stringify(inspection.Args) === JSON.stringify(["serve"]) &&
      inspection.HostConfig.ReadonlyRootfs === true &&
      inspection.HostConfig.NetworkMode === "host" &&
      Number(inspection.HostConfig.PidsLimit) === 64 &&
      inspection.HostConfig.CapDrop?.includes("ALL") === true &&
      inspection.HostConfig.SecurityOpt?.includes("no-new-privileges") === true &&
      inspection.Mounts?.some((mount: any) =>
        mountCoversPath(String(mount.Destination), "/usr/local/bin/blackglass-server"),
      ) !== true;
    const evaluation = evaluateCgroupResourceGate(
      workloadPassed,
      memoryPeakBytes,
      configuredMemoryBytes,
      configuredMemorySwapBytes,
      memoryEvents.oom,
      memoryEvents.oomKill,
      memoryEvents.oomGroupKill,
      oomKilled,
      exitCode,
    );
    const report = {
      schemaVersion: resourceReportSchemaVersion,
      passed:
        processEvaluation.passed &&
        evaluation.passed &&
        context.eventsBefore.oom === 0 &&
        context.eventsBefore.oomKill === 0 &&
        context.eventsBefore.oomGroupKill === 0 &&
        memoryEvents.oom === 0 &&
        memoryEvents.oomKill === 0 &&
        memoryEvents.oomGroupKill === 0 &&
        memoryEventDelta.oomGroupKill === 0 &&
        dockerMemoryLimitBytes === cgroupResourceLimits.memoryMaxBytes &&
        dockerMemorySwapTotalBytes === cgroupResourceLimits.dockerMemorySwapTotalBytes &&
        identityHashesMatch &&
        serverOnlyCgroup &&
        containerIsolationPassed &&
        inspection.Image === context.imageId &&
        stateError === "",
      ...reportIdentity,
      workload,
      measurement: "cgroup-v2",
      baselineRssKiB,
      rssSamplesKiB,
      peakRssMeasurement: "linux-vmhwm",
      peakRssKiB,
      deltaRssKiB,
      peakRssMiB,
      deltaRssMiB,
      processRssMarginMiB,
      execution: {
        nativeTarget: context.nativeTarget,
        hostPlatform: context.hostPlatform,
        hostArchitecture: context.hostArchitecture,
        elfDescription: context.elfDescription,
        nativeRunnerMatch: true,
        imageId: context.imageId,
        containerUser: inspection.Config.User,
        artifactBinarySha256: context.artifactBinarySha256,
        stagedBinarySha256: context.stagedBinarySha256,
        inImageBinarySha256: context.inImageBinarySha256,
        finalInImageBinarySha256,
        identityHashesMatch,
        serverOnlyCgroup,
        cgroupProcessCount: finalCgroupPids.length,
        harnessCgroupSeparated: true,
        containerIsolationPassed,
        entrypoint: inspection.Config.Entrypoint,
        command: inspection.Config.Cmd,
        readOnlyRootFilesystem: inspection.HostConfig.ReadonlyRootfs,
        networkMode: inspection.HostConfig.NetworkMode,
        pidsLimit: Number(inspection.HostConfig.PidsLimit),
        capDrop: inspection.HostConfig.CapDrop,
        securityOptions: inspection.HostConfig.SecurityOpt,
      },
      cgroup: {
        version: 2,
        eventsSource: basename(context.eventsPath),
        memoryPeakBytes,
        memoryMaxBytes: configuredMemoryBytes,
        memorySwapMaxBytes: configuredMemorySwapBytes,
        memoryEventsBefore: context.eventsBefore,
        memoryEvents,
        memoryEventDelta,
      },
      container: {
        dockerMemoryLimitBytes,
        dockerMemorySwapTotalBytes,
        gracefulExit: exitCode === 0 && !oomKilled && stateError === "",
        exitCode,
        oomKilled,
        stateError,
      },
      databaseBytes,
      stagingEntries,
      unexpectedStagingEntries,
      limits: { ...resourceLimits, ...cgroupResourceLimits },
    };
    await emitReport(report);
  } else {
    const databaseBytes = (await stat(join(directory, "server.sqlite"))).size;
    const stagingEntries = await readdir(join(directory, "uploads"));
    const unexpectedStagingEntries = stagingEntries.filter(
      (entry) => entry !== ".blackglass-staging-v1",
    );
    const workloadPassed = protocolWorkloadPassed && unexpectedStagingEntries.length === 0;
    const deltaRssKiB = peakRssKiB - baselineRssKiB;
    const resourceEvaluation = evaluateResourceGate(
      workloadPassed,
      baselineRssKiB,
      peakRssKiB,
    );
    const { peakRssMiB, deltaRssMiB, processRssMarginMiB } = resourceEvaluation;
    const report = {
      schemaVersion: resourceReportSchemaVersion,
      passed: resourceEvaluation.passed,
      ...reportIdentity,
      workload,
      measurement: "process-rss",
      baselineRssKiB,
      rssSamplesKiB,
      peakRssMeasurement: linuxPeakRssKiB === null ? "sampled-rss" : "linux-vmhwm",
      peakRssKiB,
      deltaRssKiB,
      peakRssMiB,
      deltaRssMiB,
      processRssMarginMiB,
      databaseBytes,
      stagingEntries,
      unexpectedStagingEntries,
      limits: resourceLimits,
    };
    await emitReport(report);
  }
} catch (error) {
  if (cgroup) {
    await rethrowWithDiagnostics(
      error,
      () => captureCgroupFailureDiagnostics(cgroup!),
      (diagnostics) => {
        console.error(
          JSON.stringify(
            { event: "blackglass_resource_workload_failed", ...diagnostics },
            null,
            2,
          ),
        );
      },
    );
  }
  throw error;
} finally {
  for (const probe of probes) probe.socket.close();
  if (child) {
    child.kill("SIGTERM");
    await child.exited;
  }
  if (cgroup) {
    if (!cgroup.stopped) {
      Bun.spawnSync(["docker", "stop", "--time", "30", cgroup.container]);
    }
    Bun.spawnSync(["docker", "rm", "--force", "--volumes", cgroup.container]);
    Bun.spawnSync(["docker", "volume", "rm", "--force", cgroup.volume]);
    Bun.spawnSync(["docker", "image", "rm", "--force", cgroup.image]);
  }
  await rm(directory, { recursive: true, force: true });
}

async function startCgroupContainer(): Promise<CgroupContext> {
  const target = process.env.BLACKGLASS_RELEASE_TARGET;
  const fileResult = Bun.spawnSync(["file", "--brief", binary]);
  const fileDescription = fileResult.stdout.toString();
  if (fileResult.exitCode !== 0) throw new Error(fileResult.stderr.toString());
  const targetShape = qualifyNativeLinuxTarget(
    target,
    process.platform,
    process.arch,
    fileDescription,
  );
  const container = `blackglass-resource-${process.pid}-${Date.now()}`;
  const image = `${container}:image`;
  const volume = `${container}-state`;
  const context = join(directory, "image-context");
  await mkdir(join(context, "state"), { recursive: true });
  await writeFile(join(context, "state/.blackglass-state"), "");
  const stagedBinary = join(context, "blackglass-server");
  await Promise.all([
    copyFile(binary, stagedBinary),
    copyFile(join(root, "LICENSE"), join(context, "LICENSE")),
    copyFile(
      join(root, "THIRD_PARTY_NOTICES.md"),
      join(context, "THIRD_PARTY_NOTICES.md"),
    ),
  ]);
  await chmod(stagedBinary, 0o555);
  const artifactBinarySha256 = await sha256Path(binary);
  const stagedBinarySha256 = await sha256Path(stagedBinary);
  try {
    runDocker([
      "buildx",
      "build",
      "--load",
      "--platform",
      `linux/${targetShape.dockerArchitecture}`,
      "--file",
      join(root, "ops/Dockerfile.prebuilt"),
      "--tag",
      image,
      "--build-arg",
      `SOURCE_REVISION=${buildInfo.sourceRevision}`,
      "--build-arg",
      `SOURCE_URL=https://github.com/${process.env.GITHUB_REPOSITORY ?? "mergebloom/blackglass-server"}`,
      "--build-arg",
      `TARGETARCH=${targetShape.dockerArchitecture}`,
      "--build-arg",
      `VERSION=${buildInfo.version}`,
      context,
    ]);
    const imageId = runDocker(["image", "inspect", "--format", "{{.Id}}", image]).trim();
    runDocker(["volume", "create", volume]);
    runDocker([
      "create",
      "--name",
      container,
      "--network",
      "host",
      "--stop-timeout",
      "30",
      "--memory",
      "256m",
      "--memory-swap",
      "256m",
      "--pids-limit",
      "64",
      "--ulimit",
      "nofile=4096:4096",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
      "--mount",
      `type=volume,src=${volume},dst=/var/lib/blackglass-server`,
      "--env",
      "SELFHOST_BIND_HOST=127.0.0.1",
      "--env",
      `SELFHOST_CONTROL_PORT=${controlPort}`,
      "--env",
      `SELFHOST_DATA_PORT=${dataPort}`,
      "--env",
      `SELFHOST_DATA_HOST=127.0.0.1:${dataPort}`,
      "--env",
      "SELFHOST_EMAIL=resource@example.test",
      "--env",
      `SELFHOST_PASSWORD_HASH=${maximumWorkPasswordHash}`,
      "--env",
      "SELFHOST_NAME=Resource test",
      "--env",
      `SELFHOST_PER_FILE_MAX=${128 * 1024 * 1024}`,
      "--env",
      `SELFHOST_MAX_CONCURRENT_UPLOADS=${concurrentUploads}`,
      "--env",
      "SELFHOST_ALLOWED_ORIGINS=app://obsidian.md",
      "--env",
      "SELFHOST_TRUSTED_PROXY=127.0.0.1",
      "--env",
      "SELFHOST_LOG_FORMAT=pretty",
      imageId,
      "serve",
    ]);
    const createdInspection = dockerInspect(container);
    if (
      createdInspection.Image !== imageId ||
      JSON.stringify(createdInspection.Config.Entrypoint) !==
        JSON.stringify(["/usr/local/bin/blackglass-server"]) ||
      JSON.stringify(createdInspection.Config.Cmd) !== JSON.stringify(["serve"]) ||
      createdInspection.Path !== "/usr/local/bin/blackglass-server" ||
      JSON.stringify(createdInspection.Args) !== JSON.stringify(["serve"]) ||
      createdInspection.Config.User !== "65532:65532" ||
      createdInspection.HostConfig.ReadonlyRootfs !== true ||
      createdInspection.HostConfig.NetworkMode !== "host" ||
      Number(createdInspection.HostConfig.PidsLimit) !== 64 ||
      !createdInspection.HostConfig.CapDrop?.includes("ALL") ||
      !createdInspection.HostConfig.SecurityOpt?.includes("no-new-privileges") ||
      createdInspection.Mounts?.some((mount: any) =>
        mountCoversPath(String(mount.Destination), "/usr/local/bin/blackglass-server"),
      )
    ) {
      throw new Error("cgroup server container isolation or exact entrypoint drifted");
    }
    const copiedBinary = join(directory, "in-image-binary-start");
    runDocker(["cp", `${container}:/usr/local/bin/blackglass-server`, copiedBinary]);
    const inImageBinarySha256 = await sha256Path(copiedBinary);
    runDocker(["start", container]);
    const inspection = dockerInspect(container);
    const hostPid = Number(inspection.State.Pid);
    if (
      !Number.isSafeInteger(hostPid) ||
      hostPid <= 0 ||
      inspection.State.Running !== true ||
      inspection.Image !== imageId
    ) {
      throw new Error("cgroup server did not start as one native container process");
    }
    const path = await readUnifiedCgroupPath(`/proc/${hostPid}/cgroup`);
    const harnessPath = await readUnifiedCgroupPath("/proc/self/cgroup");
    if (path === harnessPath) throw new Error("server and workload harness share a cgroup");
    const cgroupDirectory = resolve("/sys/fs/cgroup", `.${path}`);
    if (!cgroupDirectory.startsWith("/sys/fs/cgroup/")) {
      throw new Error("Docker returned an unsafe cgroup path");
    }
    const cgroupPids = parseCgroupPidList(
      await readFile(join(cgroupDirectory, "cgroup.procs"), "utf8"),
    );
    if (cgroupPids.length !== 1 || cgroupPids[0] !== hostPid) {
      throw new Error("resource cgroup contains a process other than the exact server");
    }
    const eventsLocal = join(cgroupDirectory, "memory.events.local");
    const eventsPath = (await Bun.file(eventsLocal).exists())
      ? eventsLocal
      : join(cgroupDirectory, "memory.events");
    const eventsBefore = parseCgroupEvents(await readFile(eventsPath, "utf8"));
    return {
      container,
      image,
      imageId,
      volume,
      stopped: false,
      hostPid,
      path,
      eventsPath,
      eventsBefore,
      artifactBinarySha256,
      stagedBinarySha256,
      inImageBinarySha256,
      nativeTarget: target!,
      hostPlatform: process.platform,
      hostArchitecture: process.arch,
      elfDescription: fileDescription.trim(),
    };
  } catch (error) {
    Bun.spawnSync(["docker", "rm", "--force", "--volumes", container]);
    Bun.spawnSync(["docker", "volume", "rm", "--force", volume]);
    Bun.spawnSync(["docker", "image", "rm", "--force", image]);
    throw error;
  }
}

function runDocker(args: string[]): string {
  const result = Bun.spawnSync(["docker", ...args]);
  if (result.exitCode !== 0) {
    throw new Error(`docker ${args[0]} failed: ${result.stderr.toString()}`);
  }
  return result.stdout.toString();
}

function mountCoversPath(destination: string, path: string): boolean {
  const normalized = destination === "/" ? "/" : destination.replace(/\/+$/, "");
  return normalized === "/" || path === normalized || path.startsWith(`${normalized}/`);
}

function dockerInspect(container: string): any {
  const result = Bun.spawnSync(["docker", "inspect", container]);
  if (result.exitCode !== 0) {
    throw new Error(`could not inspect cgroup container: ${result.stderr.toString()}`);
  }
  return parseDockerInspection(result.stdout.toString());
}

function parseDockerInspection(output: string): any {
  const inspections = JSON.parse(output);
  if (!Array.isArray(inspections) || inspections.length !== 1) {
    throw new Error("Docker returned an invalid cgroup container inspection");
  }
  return inspections[0];
}

async function dockerInspectForDiagnostics(container: string, signal: AbortSignal): Promise<any> {
  const result = await runDiagnosticDocker(["inspect", container], signal);
  if (result.exitCode !== 0) {
    throw new Error(`could not inspect cgroup container: ${result.stderr}`);
  }
  return parseDockerInspection(result.stdout);
}

async function captureCgroupFailureDiagnostics(
  context: CgroupContext,
): Promise<Record<string, unknown>> {
  const cgroupDirectory = resolve("/sys/fs/cgroup", `.${context.path}`);
  return collectFailureDiagnostics([
    {
      name: "cgroupIdentity",
      read: () => ({
        container: context.container,
        imageId: context.imageId,
        nativeTarget: context.nativeTarget,
        hostArchitecture: context.hostArchitecture,
        path: context.path,
        eventsSource: basename(context.eventsPath),
        eventsBefore: context.eventsBefore,
        expectedPid: context.hostPid,
      }),
    },
    {
      name: "cgroupMemory",
      read: async () => {
        const [current, peak, maximum, swapCurrent, swapMaximum] = await Promise.all([
          readFile(join(cgroupDirectory, "memory.current"), "utf8"),
          readFile(join(cgroupDirectory, "memory.peak"), "utf8"),
          readFile(join(cgroupDirectory, "memory.max"), "utf8"),
          readFile(join(cgroupDirectory, "memory.swap.current"), "utf8"),
          readFile(join(cgroupDirectory, "memory.swap.max"), "utf8"),
        ]);
        return {
          currentBytes: parseCgroupScalar(current, "memory.current"),
          peakBytes: parseCgroupScalar(peak, "memory.peak"),
          maxBytes: parseCgroupScalar(maximum, "memory.max"),
          swapCurrentBytes: parseCgroupScalar(swapCurrent, "memory.swap.current"),
          swapMaxBytes: parseCgroupScalar(swapMaximum, "memory.swap.max"),
        };
      },
    },
    {
      name: "cgroupEvents",
      read: async () => {
        const events = parseCgroupEvents(await readFile(context.eventsPath, "utf8"));
        return {
          events,
          delta: subtractCgroupEvents(events, context.eventsBefore),
        };
      },
    },
    {
      name: "cgroupProcesses",
      read: async () => {
        const raw = await readFile(join(cgroupDirectory, "cgroup.procs"), "utf8");
        return raw.trim() === "" ? [] : parseCgroupPidList(raw);
      },
    },
    {
      name: "processStatus",
      read: async () => summarizeProcessStatus(
        await readFile(`/proc/${context.hostPid}/status`, "utf8"),
      ),
    },
    {
      name: "containerState",
      read: async (signal) => summarizeContainerInspection(
        await dockerInspectForDiagnostics(context.container, signal),
      ),
    },
    {
      name: "containerStateAfter100ms",
      read: async (signal) => {
        await Bun.sleep(100);
        if (signal.aborted) throw new Error("container state diagnostic was aborted");
        return summarizeContainerInspection(
          await dockerInspectForDiagnostics(context.container, signal),
        );
      },
    },
    {
      name: "containerLogs",
      read: (signal) => readContainerLogs(context.container, signal),
    },
  ]);
}

function summarizeProcessStatus(status: string): Record<string, string> {
  const selected: Record<string, string> = {};
  for (const line of status.split("\n")) {
    const match = /^(Name|State|Pid|PPid|Threads|VmRSS|VmHWM):\s*(.*)$/.exec(line);
    if (match?.[1] && match[2] !== undefined) selected[match[1]] = match[2];
  }
  return selected;
}

function summarizeContainerInspection(inspection: any) {
  return {
    image: String(inspection.Image ?? ""),
    restartCount: Number(inspection.RestartCount ?? 0),
    state: {
      status: String(inspection.State?.Status ?? ""),
      running: inspection.State?.Running === true,
      paused: inspection.State?.Paused === true,
      restarting: inspection.State?.Restarting === true,
      oomKilled: inspection.State?.OOMKilled === true,
      dead: inspection.State?.Dead === true,
      pid: Number(inspection.State?.Pid ?? 0),
      exitCode: Number(inspection.State?.ExitCode ?? 0),
      error: String(inspection.State?.Error ?? ""),
      startedAt: String(inspection.State?.StartedAt ?? ""),
      finishedAt: String(inspection.State?.FinishedAt ?? ""),
    },
  };
}

async function readContainerLogs(container: string, signal: AbortSignal) {
  const result = await runDiagnosticDocker(["logs", "--tail", "200", container], signal);
  if (result.exitCode !== 0) {
    throw new Error(`docker logs failed: ${result.stderr}`);
  }
  const limit = 32 * 1024;
  return {
    stdout: result.stdout.slice(-limit),
    stderr: result.stderr.slice(-limit),
  };
}

async function runDiagnosticDocker(
  args: string[],
  signal: AbortSignal,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const process = Bun.spawn(["docker", ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const terminate = () => {
    try {
      process.kill("SIGKILL");
    } catch {
      // The command may have exited between the abort signal and this callback.
    }
  };
  if (signal.aborted) terminate();
  else signal.addEventListener("abort", terminate, { once: true });
  try {
    const [exitCode, stdout, stderr] = await Promise.all([
      process.exited,
      new Response(process.stdout).text(),
      new Response(process.stderr).text(),
    ]);
    return { exitCode, stdout, stderr };
  } finally {
    signal.removeEventListener("abort", terminate);
  }
}

async function readCgroupSnapshot(
  cgroupDirectory: string,
  eventsPath: string,
): Promise<{ memoryPeakBytes: number; memoryEvents: CgroupEvents } | null> {
  try {
    const [memoryPeak, memoryEvents] = await Promise.all([
      readFile(join(cgroupDirectory, "memory.peak"), "utf8"),
      readFile(eventsPath, "utf8"),
    ]);
    return {
      memoryPeakBytes: parseCgroupScalar(memoryPeak, "memory.peak"),
      memoryEvents: parseCgroupEvents(memoryEvents),
    };
  } catch (error) {
    if (isDisappearedKernelPath(error)) return null;
    throw error;
  }
}

async function readLinuxPeakRssDuringExit(pid: number): Promise<number | null> {
  try {
    return await readExitKernelValue({
      read: () => readFile(`/proc/${pid}/status`, "utf8"),
      parse: (status) => parseLinuxRssKiBDuringExit(status, "VmHWM"),
      isDisappeared: isDisappearedKernelPath,
      waitBeforeRetry: () => Bun.sleep(1),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`terminal process memory snapshot failed: ${message}`, {
      cause: error,
    });
  }
}

function isDisappearedKernelPath(error: unknown): boolean {
  const code =
    typeof error === "object" && error !== null && "code" in error
      ? String(error.code)
      : "";
  return code === "ENOENT" || code === "ESRCH";
}

async function readUnifiedCgroupPath(path: string): Promise<string> {
  return parseUnifiedCgroupPath(await readFile(path, "utf8"));
}

async function sha256Path(path: string): Promise<string> {
  return createHash("sha256")
    .update(Buffer.from(await Bun.file(path).arrayBuffer()))
    .digest("hex");
}

async function emitReport(report: Record<string, unknown> & { passed: boolean }) {
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  console.log(JSON.stringify(report, null, 2));
  if (!report.passed) process.exitCode = 1;
}

async function initialize(
  probe: Probe,
  token: string,
  vault: Record<string, any>,
  device: string,
  initial = true,
  onAccepted?: () => void,
) {
  probe.json({
    op: "init",
    token,
    id: vault.id,
    keyhash: vault.keyhash,
    version: 0,
    initial,
    device,
    encryption_version: 3,
  });
  const accepted = await probe.next();
  if (accepted.res !== "ok") throw new Error("websocket init failed");
  onAccepted?.();
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

async function readActiveProcessMemorySnapshot(
  phase: string,
): Promise<ProcessMemorySnapshot> {
  const pid = child?.pid ?? cgroup?.hostPid;
  return withMeasurementPhase(`active process memory snapshot (${phase})`, async () => {
    if (pid === undefined) throw new Error("server process is unavailable");
    return readProcessMemorySnapshotForPid(pid);
  });
}

async function readActiveProcessMemorySnapshotForPid(
  pid: number,
  phase: string,
): Promise<ProcessMemorySnapshot> {
  return withMeasurementPhase(`active process memory snapshot (${phase})`, () =>
    readProcessMemorySnapshotForPid(pid),
  );
}

async function readProcessMemorySnapshotForPid(pid: number): Promise<ProcessMemorySnapshot> {
  if (process.platform === "linux") {
    const parsed = parseLinuxProcessMemoryKiB(
      await readFile(`/proc/${pid}/status`, "utf8"),
    );
    return { rssKiB: parsed.rssKiB, linuxPeakRssKiB: parsed.peakRssKiB };
  }
  const result = Bun.spawnSync(["ps", "-o", "rss=", "-p", String(pid)], {
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) throw new Error(result.stderr.toString());
  const rssKiB = Number(result.stdout.toString().trim());
  if (!Number.isFinite(rssKiB) || rssKiB < 0) {
    throw new Error("ps returned an invalid RSS value");
  }
  return { rssKiB, linuxPeakRssKiB: null };
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
    if (child?.exitCode !== null && child?.exitCode !== undefined) {
      throw new Error("server exited early");
    }
    if (cgroup && dockerInspect(cgroup.container).State.Running !== true) {
      throw new Error("cgroup server exited early");
    }
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
