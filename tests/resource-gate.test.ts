import { describe, expect, test } from "bun:test";
import {
  cgroupResourceLimits,
  evaluateCgroupResourceGate,
  evaluateResourceGate,
  parseCgroupEvents,
  parseCgroupPidList,
  parseCgroupScalar,
  parseLinuxRssKiB,
  parseUnifiedCgroupPath,
  qualifyNativeLinuxTarget,
  resourceLimits,
  resourceReportSchemaVersion,
  subtractCgroupEvents,
} from "../tools/resource-gate.ts";

describe("release resource gate", () => {
  test("binds the absolute process RSS peak to the service memory maximum", () => {
    expect(resourceReportSchemaVersion).toBe(5);
    expect(resourceLimits).toEqual({
      serviceMemoryMaxMiB: 256,
      minimumProcessRssMarginMiB: 32,
      maxPeakProcessRssMiB: 224,
      maxDeltaProcessRssMiB: 128,
    });
    expect(
      resourceLimits.serviceMemoryMaxMiB - resourceLimits.maxPeakProcessRssMiB,
    ).toBe(resourceLimits.minimumProcessRssMarginMiB);
  });

  test("rejects the prior Linux overlap that exceeded the retained delta gate", () => {
    const result = evaluateResourceGate(true, 13_932, 189_068);
    expect(result.passed).toBe(false);
    expect(result.peakRssMiB).toBeCloseTo(184.64, 2);
    expect(result.processRssMarginMiB).toBeGreaterThan(71);
    expect(result.deltaRssMiB).toBeGreaterThan(171);
  });

  test("fails an incomplete workload and the absolute peak boundary", () => {
    expect(evaluateResourceGate(false, 0, 1).passed).toBe(false);
    expect(evaluateResourceGate(true, 96 * 1024, 224 * 1024 - 1).passed).toBe(true);
    expect(evaluateResourceGate(true, 96 * 1024, 224 * 1024).passed).toBe(false);
    expect(evaluateResourceGate(true, 1, 128 * 1024 + 1).passed).toBe(false);
  });

  test("parses Linux kernel high-water RSS and rejects ambiguous status", () => {
    const status = "Name:\tserver\nVmRSS:\t42 kB\nVmHWM:\t189068 kB\n";
    expect(parseLinuxRssKiB(status, "VmRSS")).toBe(42);
    expect(parseLinuxRssKiB(status, "VmHWM")).toBe(189_068);
    expect(() => parseLinuxRssKiB("VmRSS:\t42 kB\n", "VmHWM")).toThrow("VmHWM");
    expect(() => parseLinuxRssKiB("VmHWM:\tunknown kB\n", "VmHWM")).toThrow("VmHWM");
  });

  test("rejects invalid peak inputs", () => {
    for (const value of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => evaluateResourceGate(true, 0, value)).toThrow("RSS values");
    }
    expect(() => evaluateResourceGate(true, 2, 1)).toThrow("RSS values");
  });

  test("fails cgroup survival on a wrong limit, OOM signal, or unclean exit", () => {
    expect(cgroupResourceLimits).toEqual({
      memoryMaxBytes: 256 * 1024 * 1024,
      memorySwapMaxBytes: 0,
      dockerMemorySwapTotalBytes: 256 * 1024 * 1024,
    });
    const evaluate = (
      peak: number = cgroupResourceLimits.memoryMaxBytes,
      memory: number = cgroupResourceLimits.memoryMaxBytes,
      swap: number = cgroupResourceLimits.memorySwapMaxBytes,
      oom: number = 0,
      oomKill: number = 0,
      oomGroupKill: number = 0,
      killed: boolean = false,
      exitCode: number = 0,
    ) =>
      evaluateCgroupResourceGate(
        true,
        peak,
        memory,
        swap,
        oom,
        oomKill,
        oomGroupKill,
        killed,
        exitCode,
      );
    expect(evaluate().passed).toBe(true);
    // memory.max is a hard enforcement boundary, but the kernel documents that
    // memory usage (and therefore memory.peak) can exceed it temporarily while
    // reclaim succeeds. Zero OOM signals and a clean exit prove survival.
    expect(evaluate(cgroupResourceLimits.memoryMaxBytes + 4 * 1024 * 1024).passed).toBe(
      true,
    );
    expect(evaluate(0).passed).toBe(false);
    expect(evaluate(1, 1).passed).toBe(false);
    expect(evaluate(1, undefined, 1).passed).toBe(false);
    expect(evaluate(1, undefined, undefined, 1).passed).toBe(false);
    expect(evaluate(1, undefined, undefined, 0, 1).passed).toBe(false);
    expect(evaluate(1, undefined, undefined, 0, 0, 1).passed).toBe(false);
    expect(evaluate(1, undefined, undefined, 0, 0, 0, true).passed).toBe(false);
    expect(evaluate(1, undefined, undefined, 0, 0, 0, false, 1).passed).toBe(false);
    expect(() => evaluateCgroupResourceGate(true, -1, 1, 1, 0, 0, 0, false, 0)).toThrow(
      "cgroup measurements",
    );
  });

  test("parses cgroup-v2 counters strictly and rejects backwards snapshots", () => {
    const raw = "low 0\nhigh 1\nmax 2\noom 0\noom_kill 0\noom_group_kill 0\n";
    const before = parseCgroupEvents(raw);
    const after = parseCgroupEvents(raw.replace("max 2", "max 5"));
    expect(subtractCgroupEvents(after, before).max).toBe(3);
    expect(() => subtractCgroupEvents(before, after)).toThrow("moved backwards");
    expect(() => parseCgroupEvents(raw.replace("oom 0\n", ""))).toThrow("oom");
    expect(() => parseCgroupEvents(`${raw}oom 0\n`)).toThrow("duplicated");
    expect(() => parseCgroupEvents(raw.replace("max 2", "max -1"))).toThrow("malformed");
    expect(parseCgroupScalar("268435456\n", "memory.max")).toBe(268_435_456);
    for (const value of ["max", "-1", "1.5", `${Number.MAX_SAFE_INTEGER}0`]) {
      expect(() => parseCgroupScalar(value, "memory.max")).toThrow("memory.max");
    }
  });

  test("accepts only safe unified cgroup paths and exact PID memberships", () => {
    expect(parseUnifiedCgroupPath("0::/system.slice/docker.scope\n")).toBe(
      "/system.slice/docker.scope",
    );
    for (const value of [
      "2:memory:/docker/id",
      "0::/safe\n2:memory:/legacy",
      "0::/safe/../escape",
      "0::/safe//child",
      "0::relative",
    ]) {
      expect(() => parseUnifiedCgroupPath(value)).toThrow("cgroup");
    }
    expect(parseCgroupPidList("42\n")).toEqual([42]);
    for (const value of ["", "0\n", "1\n1\n", "not-a-pid\n", "1.5\n"]) {
      expect(() => parseCgroupPidList(value)).toThrow("cgroup.procs");
    }
  });

  test("qualifies only a native static ELF matching the declared target", () => {
    const amd64 = "ELF 64-bit LSB pie executable, x86-64, static-pie linked";
    expect(qualifyNativeLinuxTarget("linux-amd64", "linux", "x64", amd64)).toEqual({
      nodeArchitecture: "x64",
      dockerArchitecture: "amd64",
      fileMarker: "x86-64",
    });
    const arm64 = "ELF 64-bit LSB pie executable, ARM aarch64, statically linked";
    expect(qualifyNativeLinuxTarget("linux-arm64", "linux", "arm64", arm64)).toEqual({
      nodeArchitecture: "arm64",
      dockerArchitecture: "arm64",
      fileMarker: "ARM aarch64",
    });
    for (const args of [
      ["linux-amd64", "darwin", "x64", amd64],
      ["linux-amd64", "linux", "arm64", amd64],
      ["linux-arm64", "linux", "arm64", amd64],
      ["linux-amd64", "linux", "x64", "Mach-O 64-bit executable"],
    ] as Array<[string, string, string, string]>) {
      expect(() => qualifyNativeLinuxTarget(args[0], args[1], args[2], args[3])).toThrow(
        "native Linux runner",
      );
    }
  });
});
