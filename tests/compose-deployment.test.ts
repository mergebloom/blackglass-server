import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const composePath = resolve(root, "compose.yaml");
const compose = readFileSync(composePath, "utf8");
const operations = readFileSync(resolve(root, "ops/compose-ops.sh"), "utf8");
const caddy = readFileSync(resolve(root, "ops/Caddyfile.compose"), "utf8");

describe("one-command production deployment", () => {
  test("keeps the Server non-root, read-only, bounded, and health-checked", () => {
    expect(compose).toContain('user: "65532:65532"');
    expect(compose.match(/user: "65532:65532"/gu)?.length).toBe(2);
    expect(compose).toContain("read_only: true");
    expect(compose).toContain("no-new-privileges:true");
    expect(compose).toContain("pids_limit: 64");
    expect(compose).toContain("mem_limit: 384m");
    expect(compose).toContain("stop_grace_period: 30s");
    expect(compose).toContain('["CMD", "/usr/local/bin/blackglass-server", "healthcheck"]');
    expect(compose).toContain("SELFHOST_ALLOWED_ORIGINS: app://obsidian.md");
    expect(compose).toContain("SELFHOST_TRUSTED_PROXY: 127.0.0.1");
    expect(compose).not.toMatch(/^\s+ports:/mu);
    expect(compose).toContain("service_completed_successfully");
    expect(compose).toContain("exec chown -R 65532:65532 /var/lib/blackglass-server /data /config");
    expect(compose).not.toMatch(/^\s+command:/mu);
    expect(compose).toContain("network_mode: none");
    expect(compose).toContain("pids_limit: 16");
    expect(compose).toContain("mem_limit: 32m");
  });

  test("keeps operational endpoints private and overwrites forwarded identity", () => {
    expect(caddy).toContain("@operations path /health /ready /metrics");
    expect(caddy).toContain("respond @operations 404");
    expect(caddy.match(/header_up X-Forwarded-For \{remote_host\}/gu)).toHaveLength(2);
  });

  test("provides password-safe init plus verified backup and restore commands", () => {
    expect(operations).toContain("pipe the new account password on standard input");
    expect(operations).not.toContain("--password");
    expect(operations).toContain("compose run --rm -T permissions");
    expect(operations).toContain("backup-stdout");
    expect(operations).toContain("refusing to overwrite backup output");
    expect(operations).toContain("backup checksum is required and must be a regular file");
    expect(operations).toContain("its checksum was rolled back");
    expect(operations).toContain("restore /backup.sqlite /tmp/restored.sqlite");
    const syntax = Bun.spawnSync(["sh", "-n", resolve(root, "ops/compose-ops.sh")]);
    expect(syntax.exitCode, syntax.stderr.toString()).toBe(0);
  });

  test("keeps private deployment configuration out of Git", () => {
    const ignored = Bun.spawnSync(["git", "check-ignore", "-q", ".env"], { cwd: root });
    expect(ignored.exitCode).toBe(0);
    const example = Bun.spawnSync(["git", "check-ignore", "-q", ".env.example"], { cwd: root });
    expect(example.exitCode).not.toBe(0);
  });

  test("renders a complete Compose model when Docker Compose is available", () => {
    const available = Bun.spawnSync(["docker", "compose", "version"], {
      stdout: "ignore",
      stderr: "ignore",
    });
    if (available.exitCode !== 0) return;
    const rendered = Bun.spawnSync([
      "docker", "compose", "--env-file", ".env.example", "-f", "compose.yaml", "config",
    ], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(rendered.exitCode, rendered.stderr.toString()).toBe(0);
    expect(rendered.stdout.toString()).toContain("ghcr.io/mergebloom/blackglass-server:VERSION");
  });
});
