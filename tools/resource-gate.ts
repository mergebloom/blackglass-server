export const resourceReportSchemaVersion = 5;
export const resourceLimits = Object.freeze({
  serviceMemoryMaxMiB: 384,
  minimumProcessRssMarginMiB: 160,
  maxPeakProcessRssMiB: 224,
  maxDeltaProcessRssMiB: 128,
});
export const cgroupResourceLimits = Object.freeze({
  memoryMaxBytes: 384 * 1024 * 1024,
  memorySwapMaxBytes: 0,
  dockerMemorySwapTotalBytes: 384 * 1024 * 1024,
});

export type CgroupEvents = {
  low: number;
  high: number;
  max: number;
  oom: number;
  oomKill: number;
  oomGroupKill: number;
};

export type LinuxProcessMemoryKiB = {
  rssKiB: number;
  peakRssKiB: number;
};

export function evaluateResourceGate(
  workloadPassed: boolean,
  baselineRssKiB: number,
  peakRssKiB: number,
) {
  if (
    !Number.isFinite(baselineRssKiB) ||
    baselineRssKiB < 0 ||
    !Number.isFinite(peakRssKiB) ||
    peakRssKiB < baselineRssKiB
  ) {
    throw new Error("RSS values must be finite, non-negative, and ordered");
  }
  const peakRssMiB = peakRssKiB / 1024;
  const deltaRssMiB = (peakRssKiB - baselineRssKiB) / 1024;
  return {
    passed:
      workloadPassed &&
      peakRssMiB < resourceLimits.maxPeakProcessRssMiB &&
      deltaRssMiB < resourceLimits.maxDeltaProcessRssMiB,
    peakRssMiB,
    deltaRssMiB,
    processRssMarginMiB: resourceLimits.serviceMemoryMaxMiB - peakRssMiB,
  };
}

export function evaluateCgroupResourceGate(
  workloadPassed: boolean,
  memoryPeakBytes: number,
  configuredMemoryBytes: number,
  configuredMemorySwapBytes: number,
  oomEvents: number,
  oomKillEvents: number,
  oomGroupKillEvents: number,
  oomKilled: boolean,
  exitCode: number,
) {
  const values = [
    memoryPeakBytes,
    configuredMemoryBytes,
    configuredMemorySwapBytes,
    oomEvents,
    oomKillEvents,
    oomGroupKillEvents,
    exitCode,
  ];
  if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new Error("cgroup measurements must be non-negative safe integers");
  }
  return {
    passed:
      workloadPassed &&
      configuredMemoryBytes === cgroupResourceLimits.memoryMaxBytes &&
      configuredMemorySwapBytes === cgroupResourceLimits.memorySwapMaxBytes &&
      memoryPeakBytes > 0 &&
      oomEvents === 0 &&
      oomKillEvents === 0 &&
      oomGroupKillEvents === 0 &&
      !oomKilled &&
      exitCode === 0,
  };
}

export function parseLinuxRssKiB(status: string, field: "VmRSS" | "VmHWM"): number {
  const match = status.match(new RegExp(`^${field}:\\s+(\\d+)\\s+kB$`, "m"));
  if (!match?.[1]) throw new Error(`Linux process status has no valid ${field} value`);
  return Number(match[1]);
}

// Parse both active-process fields from the same procfs snapshot. Reading the
// fields through separate opens introduces a race where VmRSS can come from a
// live process and VmHWM from the process's subsequent terminal status.
export function parseLinuxProcessMemoryKiB(status: string): LinuxProcessMemoryKiB {
  return {
    rssKiB: parseLinuxRssKiB(status, "VmRSS"),
    peakRssKiB: parseLinuxRssKiB(status, "VmHWM"),
  };
}

// Linux omits the memory fields from /proc/<pid>/status after a process has
// entered a terminal zombie/dead state. Callers may use this parser only after
// initiating a confirmed process exit, when retaining an earlier valid
// high-water sample is correct. A present but malformed field remains a hard
// failure.
export function parseLinuxRssKiBDuringExit(
  status: string,
  field: "VmRSS" | "VmHWM",
): number | null {
  if (!new RegExp(`^${field}(?=[:\\s])`, "m").test(status)) {
    if (/^State:\s+(?:Z|X)(?:\s|$)/m.test(status)) return null;
    return parseLinuxRssKiB(status, field);
  }
  return parseLinuxRssKiB(status, field);
}

export function parseCgroupScalar(raw: string, field: string): number {
  const value = raw.trim();
  if (!/^\d+$/.test(value)) throw new Error(`${field} is not a finite cgroup byte value`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${field} exceeds safe integer precision`);
  return parsed;
}

export function parseCgroupEvents(raw: string): CgroupEvents {
  const values = new Map<string, number>();
  for (const line of raw.trim().split("\n")) {
    const match = /^(\S+) (\d+)$/.exec(line);
    if (!match?.[1] || !match[2] || values.has(match[1])) {
      throw new Error("memory.events is malformed or duplicated");
    }
    values.set(match[1], Number(match[2]));
  }
  const required = (name: string) => {
    const value = values.get(name);
    if (!Number.isSafeInteger(value)) throw new Error(`memory.events has no valid ${name}`);
    return value!;
  };
  return {
    low: required("low"),
    high: required("high"),
    max: required("max"),
    oom: required("oom"),
    oomKill: required("oom_kill"),
    oomGroupKill: required("oom_group_kill"),
  };
}

export function subtractCgroupEvents(
  after: CgroupEvents,
  before: CgroupEvents,
): CgroupEvents {
  const delta = {
    low: after.low - before.low,
    high: after.high - before.high,
    max: after.max - before.max,
    oom: after.oom - before.oom,
    oomKill: after.oomKill - before.oomKill,
    oomGroupKill: after.oomGroupKill - before.oomGroupKill,
  };
  if (Object.values(delta).some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new Error("cgroup memory event counters moved backwards");
  }
  return delta;
}

export function parseUnifiedCgroupPath(raw: string): string {
  const lines = raw.trim().split("\n");
  if (lines.length !== 1 || !lines[0]?.startsWith("0::")) {
    throw new Error("process is not in one unified cgroup-v2 hierarchy");
  }
  const value = lines[0].slice(3);
  const segments = value.split("/").slice(1);
  if (
    !value.startsWith("/") ||
    value.includes("//") ||
    value.includes("\\") ||
    segments.some((segment) => segment === "." || segment === ".." || segment.includes("\0"))
  ) {
    throw new Error("process has an unsafe cgroup-v2 path");
  }
  return value;
}

export function parseCgroupPidList(raw: string): number[] {
  const lines = raw.trim().split("\n").filter(Boolean);
  const pids = lines.map(Number);
  if (
    pids.length === 0 ||
    pids.some((pid) => !Number.isSafeInteger(pid) || pid <= 0) ||
    new Set(pids).size !== pids.length
  ) {
    throw new Error("cgroup.procs contains an invalid process id");
  }
  return pids;
}

export function qualifyNativeLinuxTarget(
  target: string | undefined,
  platform: string,
  architecture: string,
  fileDescription: string,
) {
  const shape =
    target === "linux-amd64"
      ? { nodeArchitecture: "x64", dockerArchitecture: "amd64", fileMarker: "x86-64" }
      : target === "linux-arm64"
        ? { nodeArchitecture: "arm64", dockerArchitecture: "arm64", fileMarker: "ARM aarch64" }
        : undefined;
  if (
    platform !== "linux" ||
    !shape ||
    architecture !== shape.nodeArchitecture ||
    !fileDescription.includes("ELF 64-bit") ||
    !fileDescription.includes(shape.fileMarker) ||
    !/(static-pie linked|statically linked)/.test(fileDescription)
  ) {
    throw new Error("release artifact and native Linux runner target do not match");
  }
  return shape;
}
