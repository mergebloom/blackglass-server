import { isIP } from "node:net";

export interface ServerConfig {
  bindHost: string;
  controlPort: number;
  dataPort: number;
  publicDataHost: string;
  databasePath: string;
  email: string;
  password: string;
  token: string;
  displayName: string;
  perFileMax: number;
}

export function configFromEnvironment(
  environment: Record<string, string | undefined> = process.env,
): ServerConfig {
  const bindHost = environment.SELFHOST_BIND_HOST ?? "127.0.0.1";
  const controlPort = parsePort(environment.SELFHOST_CONTROL_PORT, 3000);
  const dataPort = parsePort(environment.SELFHOST_DATA_PORT, 3003);
  const email = requireValue(environment, "SELFHOST_EMAIL");
  const password = requireValue(environment, "SELFHOST_PASSWORD");
  const token = requireValue(environment, "SELFHOST_TOKEN");

  if (token.length < 24) {
    throw new Error("SELFHOST_TOKEN must contain at least 24 characters");
  }
  if (!isLoopback(bindHost)) {
    throw new Error(
      "The first-pass server only permits loopback binding. TLS termination is not implemented yet.",
    );
  }

  return {
    bindHost,
    controlPort,
    dataPort,
    publicDataHost:
      environment.SELFHOST_DATA_HOST ?? `127.0.0.1:${dataPort}`,
    databasePath: environment.SELFHOST_DATABASE ?? "selfhost-sync.sqlite",
    email,
    password,
    token,
    displayName: environment.SELFHOST_NAME ?? "Blackglass user",
    perFileMax: parsePositiveInteger(
      environment.SELFHOST_PER_FILE_MAX,
      200 * 1024 * 1024,
      "SELFHOST_PER_FILE_MAX",
    ),
  };
}

function requireValue(
  environment: Record<string, string | undefined>,
  name: string,
): string {
  const value = environment[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function parsePort(value: string | undefined, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error(`Invalid port: ${value}`);
  }
  return port;
}

function parsePositiveInteger(
  value: string | undefined,
  fallback: number,
  name: string,
): number {
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function isLoopback(host: string): boolean {
  if (host === "localhost") {
    return true;
  }
  const family = isIP(host);
  return family === 4
    ? host.startsWith("127.")
    : family === 6 && (host === "::1" || host === "0:0:0:0:0:0:0:1");
}
