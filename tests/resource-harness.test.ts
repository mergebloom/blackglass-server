import { describe, expect, test } from "bun:test";
import {
  collectFailureDiagnostics,
  observeWorkWithSamples,
  rethrowWithDiagnostics,
  withMeasurementPhase,
} from "../tools/resource-harness.ts";

describe("release resource harness failure handling", () => {
  test("adds the exact measurement phase while preserving the sampling cause", async () => {
    const cause = new Error("Linux process status has no valid VmHWM value");
    try {
      await withMeasurementPhase("active process memory snapshot (post-work)", () => {
        throw cause;
      });
      throw new Error("expected measurement failure");
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe(
        "active process memory snapshot (post-work) failed: " + cause.message,
      );
      expect((error as Error).cause).toBe(cause);
    }
  });

  test("returns successful phase measurements unchanged", async () => {
    await expect(withMeasurementPhase("baseline", () => 42)).resolves.toBe(42);
  });

  test("preserves a workload rejection when the concurrent RSS sample also fails", async () => {
    const workloadError = Object.assign(new Error("socket closed"), { code: "ECONNRESET" });
    const samplingError = new Error("Linux process status has no valid VmRSS value");
    const work = Promise.reject(workloadError);

    try {
      await observeWorkWithSamples(
        work,
        async () => {
          await Promise.resolve();
          throw samplingError;
        },
        () => {},
        async () => {},
      );
      throw new Error("expected workload rejection");
    } catch (error) {
      expect(error).toBe(workloadError);
    }
  });

  test("allows a short grace for a concurrent workload rejection", async () => {
    const workloadError = new Error("server exited");
    const samplingError = new Error("process status disappeared");
    const work = new Promise<never>((_, reject) => {
      setTimeout(() => reject(workloadError), 5);
    });

    await expect(
      observeWorkWithSamples(
        work,
        async () => {
          throw samplingError;
        },
        () => {},
        async () => {},
        { workFailureGraceMs: 50 },
      ),
    ).rejects.toBe(workloadError);
  });

  test("does not wait forever for pending work after sampling fails", async () => {
    const samplingError = new Error("process status disappeared");

    await expect(
      observeWorkWithSamples(
        new Promise<never>(() => {}),
        async () => {
          throw samplingError;
        },
        () => {},
        async () => {},
        { workFailureGraceMs: 5 },
      ),
    ).rejects.toBe(samplingError);
  });

  test("does not wait forever for pending work after the sampling interval fails", async () => {
    const waitError = new Error("sampling timer failed");

    await expect(
      observeWorkWithSamples(
        new Promise<never>(() => {}),
        async () => 10,
        () => {},
        async () => {
          throw waitError;
        },
        { workFailureGraceMs: 5 },
      ),
    ).rejects.toBe(waitError);
  });

  test("keeps strict sampling failures when the workload itself succeeds", async () => {
    const samplingError = new Error("malformed VmRSS");
    await expect(
      observeWorkWithSamples(
        Promise.resolve("complete"),
        async () => {
          throw samplingError;
        },
        () => {},
        async () => {},
      ),
    ).rejects.toBe(samplingError);
  });

  test("records samples and returns the successful workload value", async () => {
    const samples: number[] = [];
    let resolveWork!: (value: string) => void;
    const work = new Promise<string>((resolve) => {
      resolveWork = resolve;
    });
    let sample = 10;
    const result = await observeWorkWithSamples(
      work,
      async () => sample++,
      (value) => samples.push(value),
      async () => {
        resolveWork("done");
      },
    );
    expect(result).toBe("done");
    expect(samples).toEqual([10]);
  });

  test("collects independent diagnostic sources without losing partial evidence", async () => {
    const diagnostics = await collectFailureDiagnostics([
      { name: "container", read: () => ({ oomKilled: true, exitCode: 137 }) },
      {
        name: "cgroup",
        read: async () => {
          throw Object.assign(new Error("cgroup disappeared"), { code: "ENOENT" });
        },
      },
    ]);
    expect(diagnostics.container).toEqual({
      status: "captured",
      value: { oomKilled: true, exitCode: 137 },
    });
    expect(diagnostics.cgroup).toEqual({
      status: "unavailable",
      error: { name: "Error", message: "cgroup disappeared", code: "ENOENT" },
    });
  });

  test("bounds a never-settling diagnostic source and aborts its work", async () => {
    let aborted = false;
    const diagnostics = await collectFailureDiagnostics(
      [
        { name: "available", read: () => ({ running: false }) },
        {
          name: "stuck",
          read: (signal) =>
            new Promise<void>(() => {
              signal.addEventListener(
                "abort",
                () => {
                  aborted = true;
                },
                { once: true },
              );
            }),
        },
      ],
      { perSourceTimeoutMs: 5 },
    );

    expect(diagnostics.available).toEqual({
      status: "captured",
      value: { running: false },
    });
    expect(diagnostics.stuck).toEqual({
      status: "unavailable",
      error: {
        name: "Error",
        message: "diagnostic source stuck timed out after 5 ms",
        code: "ETIMEDOUT",
      },
    });
    expect(aborted).toBe(true);
  });

  test("captures and reports diagnostics before cleanup while preserving the primary", async () => {
    const order: string[] = [];
    const primary = Object.assign(new Error("socket closed"), { code: "ECONNRESET" });
    let reported: unknown;

    try {
      try {
        await rethrowWithDiagnostics(
          primary,
          async () => {
            order.push("capture");
            return { container: { oomKilled: false, exitCode: 1 } };
          },
          (diagnostics) => {
            order.push("report");
            reported = diagnostics;
          },
        );
      } finally {
        order.push("cleanup");
      }
    } catch (error) {
      expect(error).toBe(primary);
    }

    expect(order).toEqual(["capture", "report", "cleanup"]);
    expect(reported).toEqual({
      primaryError: { name: "Error", message: "socket closed", code: "ECONNRESET" },
      captured: { container: { oomKilled: false, exitCode: 1 } },
    });
  });

  test("diagnostic capture and reporting failures never mask the primary", async () => {
    const primary = Object.assign(new Error("socket closed"), { code: "ECONNRESET" });
    try {
      await rethrowWithDiagnostics(
        primary,
        async () => {
          throw new Error("diagnostic capture failed");
        },
        () => {
          throw new Error("diagnostic reporter failed");
        },
      );
      throw new Error("expected primary failure");
    } catch (error) {
      expect(error).toBe(primary);
    }
  });
});
