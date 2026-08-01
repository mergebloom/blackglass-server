export type ErrorDetails = {
  name: string;
  message: string;
  code?: string;
  errno?: string | number;
  syscall?: string;
  path?: string;
};

export type DiagnosticSource = {
  name: string;
  read: (signal: AbortSignal) => unknown | Promise<unknown>;
  timeoutMs?: number;
};

export type WorkObservationOptions = {
  workFailureGraceMs?: number;
};

export type DiagnosticCollectionOptions = {
  perSourceTimeoutMs?: number;
};

export type ExitKernelReadOptions<T> = {
  read: () => string | Promise<string>;
  parse: (value: string) => T;
  isDisappeared: (error: unknown) => boolean;
  waitBeforeRetry: () => void | Promise<void>;
  retries?: number;
};

export const defaultWorkFailureGraceMs = 100;
export const defaultDiagnosticSourceTimeoutMs = 2_000;

export type DiagnosticResult =
  | { status: "captured"; value: unknown }
  | { status: "unavailable"; error: ErrorDetails };

type WorkOutcome<T> =
  | { status: "fulfilled"; value: T }
  | { status: "rejected"; error: unknown };

export async function withMeasurementPhase<T>(
  phase: string,
  read: () => T | Promise<T>,
): Promise<T> {
  try {
    return await read();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${phase} failed: ${message}`, { cause: error });
  }
}

// procfs files can remain open for a brief exit transition while their memory
// fields are already gone. Retry a bounded number of times so a subsequent
// valid snapshot is retained or a subsequent ENOENT/ESRCH is treated exactly
// like the disappeared path. A persistently malformed live snapshot remains a
// hard qualification failure.
export async function readExitKernelValue<T>(
  options: ExitKernelReadOptions<T>,
): Promise<T | null> {
  const retries = options.retries ?? 2;
  if (!Number.isSafeInteger(retries) || retries < 0) {
    throw new Error("exit kernel read retries must be a non-negative safe integer");
  }
  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return options.parse(await options.read());
    } catch (error) {
      if (options.isDisappeared(error)) return null;
      lastError = error;
      if (attempt < retries) await options.waitBeforeRetry();
    }
  }
  throw lastError;
}

export async function observeWorkWithSamples<T>(
  work: Promise<T>,
  sample: () => Promise<number>,
  record: (sample: number) => void,
  waitBetweenSamples: () => Promise<void>,
  options: WorkObservationOptions = {},
): Promise<T> {
  let outcome: WorkOutcome<T> | undefined;
  // Attach both handlers before sampling. This prevents a fast workload
  // rejection from becoming unhandled while a concurrent /proc read is in
  // flight.
  const observed = work.then(
    (value) => {
      outcome = { status: "fulfilled", value };
    },
    (error: unknown) => {
      outcome = { status: "rejected", error };
    },
  );
  const workFailureGraceMs = checkedDuration(
    options.workFailureGraceMs ?? defaultWorkFailureGraceMs,
    "work failure grace",
  );

  const preferWorkFailure = async (samplingError: unknown): Promise<never> => {
    if (outcome === undefined) {
      await settleWithin(observed, workFailureGraceMs);
    }
    const completed = outcome as WorkOutcome<T> | undefined;
    if (completed?.status === "rejected") throw completed.error;
    throw samplingError;
  };

  while (outcome === undefined) {
    try {
      record(await sample());
    } catch (error) {
      return preferWorkFailure(error);
    }
    if (outcome === undefined) {
      try {
        await waitBetweenSamples();
      } catch (error) {
        return preferWorkFailure(error);
      }
    }
  }

  await observed;
  const completed = outcome as WorkOutcome<T> | undefined;
  if (completed?.status === "fulfilled") return completed.value;
  if (completed?.status === "rejected") throw completed.error;
  throw new Error("observed workload completed without an outcome");
}

export async function collectFailureDiagnostics(
  sources: readonly DiagnosticSource[],
  options: DiagnosticCollectionOptions = {},
): Promise<Record<string, DiagnosticResult>> {
  const defaultTimeoutMs = checkedDuration(
    options.perSourceTimeoutMs ?? defaultDiagnosticSourceTimeoutMs,
    "diagnostic source timeout",
  );
  const entries = await Promise.all(
    sources.map(async (source): Promise<[string, DiagnosticResult]> => {
      const timeoutMs = checkedDuration(
        source.timeoutMs ?? defaultTimeoutMs,
        `diagnostic source ${source.name} timeout`,
      );
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const timeout = new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(
              Object.assign(
                new Error(`diagnostic source ${source.name} timed out after ${timeoutMs} ms`),
                { code: "ETIMEDOUT" },
              ),
            );
          }, timeoutMs);
        });
        const value = await Promise.race([
          Promise.resolve().then(() => source.read(controller.signal)),
          timeout,
        ]);
        return [source.name, { status: "captured", value }];
      } catch (error) {
        return [source.name, { status: "unavailable", error: errorDetails(error) }];
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    }),
  );
  return Object.fromEntries(entries);
}

export async function rethrowWithDiagnostics(
  primaryError: unknown,
  capture: () => Promise<unknown>,
  report: (diagnostics: {
    primaryError: ErrorDetails;
    captured: unknown;
  }) => void | Promise<void>,
): Promise<never> {
  let captured: unknown;
  try {
    captured = await capture();
  } catch (error) {
    captured = {
      diagnosticsCapture: { status: "unavailable", error: errorDetails(error) },
    };
  }
  try {
    await report({ primaryError: errorDetails(primaryError), captured });
  } catch {
    // Diagnostic reporting is best effort. The workload or server failure is
    // always the authoritative error returned to the caller.
  }
  throw primaryError;
}

export function errorDetails(error: unknown): ErrorDetails {
  const details: ErrorDetails =
    error instanceof Error
      ? { name: error.name, message: error.message }
      : { name: "Error", message: String(error) };
  if (typeof error !== "object" || error === null) return details;
  const record = error as Record<PropertyKey, unknown>;
  for (const key of ["code", "errno", "syscall", "path"] as const) {
    if (!(key in record)) continue;
    const value = record[key];
    if (typeof value === "string" || (key === "errno" && typeof value === "number")) {
      Object.assign(details, { [key]: value });
    }
  }
  return details;
}

function checkedDuration(value: number, description: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${description} must be a non-negative safe integer`);
  }
  return value;
}

async function settleWithin(promise: Promise<unknown>, milliseconds: number): Promise<void> {
  if (milliseconds === 0) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      promise,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, milliseconds);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
