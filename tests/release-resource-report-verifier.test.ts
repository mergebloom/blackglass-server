import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const sha = "a".repeat(64);
const revision = "b".repeat(40);
const filter = resolve(import.meta.dir, "../tools/verify-release-resource-report.jq");
let directory: string;
let reportPath: string;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "blackglass-report-verifier-"));
  reportPath = join(directory, "report.json");
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

function validReport(): any {
  const eventsBefore = { low: 0, high: 0, max: 0, oom: 0, oomKill: 0, oomGroupKill: 0 };
  const memoryEvents = { ...eventsBefore, max: 2 };
  const memoryEventDelta = { ...eventsBefore, max: 2 };
  return {
    schemaVersion: 5,
    passed: true,
    implementation: "rust-release",
    measurement: "cgroup-v2",
    binarySha256: sha,
    sourceRevision: revision,
    target: "linux-amd64",
    workload: {
      concurrentUploads: 4,
      uploadBytesEach: 67_108_864,
      measuredUploadBytes: 268_435_456,
      concurrentPulls: 8,
      pullFrameConcurrencyLimit: 2,
      replayStormConnections: 11,
      replayPageSize: 16,
      replayRevisions: 128,
      concurrentArgonRequests: 10,
      bulkMemoryAdmission: { totalPermits: 4, argon2Permits: 3, reservedSyncPermits: 1 },
      concurrentArgon2CompletedChecks: 1,
      argon2CompletedChecks: 2,
      standaloneArgon2CompletedCheck: true,
      reservedSyncPullBytes: 67_108_864,
      reservedSyncPullCompleted: true,
      argon2WithReservedSyncCompleted: true,
      durationMs: 1,
      websocketConnections: 16,
      historyRevisions: 128,
      historyResponseItems: 100,
      argon2PolicyMaximum: {
        algorithm: "argon2id",
        version: 19,
        memoryKiB: 65_536,
        timeCost: 5,
        parallelism: 4,
        concurrentChecks: 1,
      },
    },
    peakRssMeasurement: "linux-vmhwm",
    baselineRssKiB: 10_240,
    peakRssKiB: 102_400,
    deltaRssKiB: 92_160,
    peakRssMiB: 100,
    deltaRssMiB: 90,
    processRssMarginMiB: 156,
    execution: {
      nativeTarget: "linux-amd64",
      hostPlatform: "linux",
      hostArchitecture: "x64",
      elfDescription: "ELF 64-bit LSB pie executable, x86-64, static-pie linked",
      nativeRunnerMatch: true,
      imageId: `sha256:${"c".repeat(64)}`,
      containerUser: "65532:65532",
      artifactBinarySha256: sha,
      stagedBinarySha256: sha,
      inImageBinarySha256: sha,
      finalInImageBinarySha256: sha,
      identityHashesMatch: true,
      serverOnlyCgroup: true,
      cgroupProcessCount: 1,
      harnessCgroupSeparated: true,
      containerIsolationPassed: true,
      entrypoint: ["/usr/local/bin/blackglass-server"],
      command: ["serve"],
      readOnlyRootFilesystem: true,
      networkMode: "host",
      pidsLimit: 64,
      capDrop: ["ALL"],
      securityOptions: ["no-new-privileges"],
    },
    cgroup: {
      version: 2,
      eventsSource: "memory.events.local",
      // Linux may temporarily report a peak above memory.max while direct
      // reclaim succeeds; the zero OOM counters remain the failure boundary.
      memoryPeakBytes: 270_000_000,
      memoryMaxBytes: 268_435_456,
      memorySwapMaxBytes: 0,
      memoryEventsBefore: eventsBefore,
      memoryEvents,
      memoryEventDelta,
    },
    container: {
      dockerMemoryLimitBytes: 268_435_456,
      dockerMemorySwapTotalBytes: 268_435_456,
      gracefulExit: true,
      exitCode: 0,
      oomKilled: false,
      stateError: "",
    },
    databaseBytes: 340_000_000,
    stagingEntries: [".blackglass-staging-v1"],
    unexpectedStagingEntries: [],
    limits: {
      serviceMemoryMaxMiB: 256,
      minimumProcessRssMarginMiB: 32,
      maxPeakProcessRssMiB: 224,
      maxDeltaProcessRssMiB: 128,
      memoryMaxBytes: 268_435_456,
      memorySwapMaxBytes: 0,
      dockerMemorySwapTotalBytes: 268_435_456,
    },
  };
}

async function verify(report: any): Promise<boolean> {
  await writeFile(reportPath, `${JSON.stringify(report)}\n`);
  return (
    Bun.spawnSync([
      "jq",
      "-e",
      "--arg",
      "sha",
      sha,
      "--arg",
      "revision",
      revision,
      "--arg",
      "target",
      "linux-amd64",
      "-f",
      filter,
      reportPath,
    ]).exitCode === 0
  );
}

describe("release resource report verifier", () => {
  test("accepts the bound schema and rejects trust-boundary mutations", async () => {
    expect(await verify(validReport())).toBe(true);
    const mutations: Array<(report: any) => void> = [
      (report) => (report.binarySha256 = "0".repeat(64)),
      (report) => (report.sourceRevision = "0".repeat(40)),
      (report) => (report.target = "linux-arm64"),
      (report) => report.deltaRssKiB++,
      (report) => (report.peakRssKiB = 229_376),
      (report) => (report.cgroup.memoryPeakBytes = 0),
      (report) => (report.cgroup.memoryMaxBytes = 1),
      (report) => (report.cgroup.memorySwapMaxBytes = 1),
      (report) => (report.cgroup.memoryEventsBefore.oom = 1),
      (report) => (report.container.exitCode = 1),
      (report) => (report.container.oomKilled = true),
      (report) => (report.execution.identityHashesMatch = false),
      (report) => (report.execution.containerIsolationPassed = false),
    ];
    for (const mutate of mutations) {
      const report = validReport();
      mutate(report);
      expect(await verify(report)).toBe(false);
    }
  });
});
