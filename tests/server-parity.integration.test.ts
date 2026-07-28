import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createServer } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const children: Array<ReturnType<typeof Bun.spawn>> = [];
const sockets: WebSocket[] = [];
let oracle: Endpoint;
let rust: Endpoint;

interface Endpoint { control: string; data: string; token: string; vault: Record<string, any> }

describe("Bun oracle and Rust protocol parity", () => {
  beforeAll(async () => {
    const directory = await mkdtemp(join(tmpdir(), "obsidian-parity-"));
    const ports = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
    const staticToken = "oracle-token-with-more-than-24-characters";
    const bun = Bun.spawn(["bun", "run", "apps/server/src/index.ts"], {
      cwd: root, stdout: "pipe", stderr: "pipe",
      env: { ...process.env, SELFHOST_BIND_HOST: "127.0.0.1", SELFHOST_CONTROL_PORT: String(ports[0]), SELFHOST_DATA_PORT: String(ports[1]), SELFHOST_DATA_HOST: `127.0.0.1:${ports[1]}`, SELFHOST_DATABASE: join(directory, "oracle.sqlite"), SELFHOST_EMAIL: "owner@example.test", SELFHOST_PASSWORD: "test-password", SELFHOST_TOKEN: staticToken, SELFHOST_NAME: "Parity owner", SELFHOST_PER_FILE_MAX: String(8 * 1024 * 1024) },
    });
    const rustBuild = Bun.spawnSync(["cargo", "build", "--manifest-path", join(root, "apps/server-rust/Cargo.toml")], { cwd: root, stdout: "pipe", stderr: "pipe" });
    if (rustBuild.exitCode !== 0) throw new Error(rustBuild.stderr.toString());
    const rustChild = Bun.spawn([join(root, "apps/server-rust/target/debug/blackglass-server"), "serve"], {
      cwd: root, stdout: "pipe", stderr: "pipe",
      env: { ...process.env, SELFHOST_BIND_HOST: "127.0.0.1", SELFHOST_CONTROL_PORT: String(ports[2]), SELFHOST_DATA_PORT: String(ports[3]), SELFHOST_DATA_HOST: `127.0.0.1:${ports[3]}`, SELFHOST_DATABASE: join(directory, "rust.sqlite"), SELFHOST_STAGING_DIR: join(directory, "uploads"), SELFHOST_EMAIL: "owner@example.test", SELFHOST_PASSWORD: "test-password", SELFHOST_ALLOW_PLAINTEXT_PASSWORD: "1", SELFHOST_NAME: "Parity owner", SELFHOST_PER_FILE_MAX: String(8 * 1024 * 1024), SELFHOST_ALLOWED_ORIGIN: "app://obsidian.md", SELFHOST_LOG_FORMAT: "pretty" },
    });
    children.push(bun, rustChild);
    await Promise.all([waitHealth(ports[0], bun), waitHealth(ports[2], rustChild)]);
    oracle = await prepare(`http://127.0.0.1:${ports[0]}`, `127.0.0.1:${ports[1]}`);
    rust = await prepare(`http://127.0.0.1:${ports[2]}`, `127.0.0.1:${ports[3]}`);
  }, 60_000);

  afterAll(async () => {
    for (const socket of sockets) socket.close();
    for (const child of children) child.kill("SIGTERM");
    await Promise.all(children.map((child) => child.exited));
  });

  test("produces the same normalized control and data transcript", async () => {
    const [bunTranscript, rustTranscript] = await Promise.all([transcript(oracle), transcript(rust)]);
    expect(rustTranscript).toEqual(bunTranscript);
  }, 20_000);
});

async function prepare(control: string, data: string): Promise<Endpoint> {
  const signin = await post(control, "/user/signin", { email: "owner@example.test", password: "test-password" });
  const token = signin.token;
  const vault = await post(control, "/vault/create", { token, name: "Parity vault", keyhash: "opaque-key", salt: "opaque-salt", region: "selfhost", encryption_version: 3 });
  return { control, data, token, vault };
}

async function transcript(endpoint: Endpoint): Promise<unknown[]> {
  const output: unknown[] = [];
  output.push(normalize(await post(endpoint.control, "/user/info", { token: endpoint.token }), endpoint));
  output.push(normalize(await post(endpoint.control, "/subscription/list", { token: endpoint.token }), endpoint));
  output.push(normalize(await post(endpoint.control, "/vault/regions", { token: endpoint.token }), endpoint));
  output.push(normalize(await post(endpoint.control, "/vault/list", { token: endpoint.token }), endpoint));
  output.push(normalize(await post(endpoint.control, "/vault/access", { token: endpoint.token, vault_uid: endpoint.vault.id, keyhash: endpoint.vault.keyhash, host: endpoint.vault.host, encryption_version: 3 }), endpoint));

  const ws = await Probe.connect(`ws://${endpoint.data}`);
  ws.json({ op: "init", token: endpoint.token, id: endpoint.vault.id, keyhash: endpoint.vault.keyhash, version: 0, initial: true, device: "Parity device", encryption_version: 3 });
  output.push(normalize(await ws.nextJson(), endpoint));
  output.push(normalize(await ws.nextJson(), endpoint));
  const bytes = new TextEncoder().encode("opaque parity ciphertext");
  ws.json({ op: "push", path: "encrypted-path", relatedpath: null, extension: "md", hash: "encrypted-hash", ctime: 1700000000000, mtime: 1700000000100, folder: false, deleted: false, size: bytes.length, pieces: 1 });
  output.push(await ws.nextJson());
  ws.socket.send(bytes);
  const live = await ws.nextJson(); output.push(normalize(live, endpoint)); output.push(await ws.nextJson());
  ws.json({ op: "pull", uid: live.uid }); output.push(await ws.nextJson()); output.push(Array.from(new Uint8Array(await ws.nextBinary())));
  ws.json({ op: "push", path: "encrypted-path", relatedpath: null, extension: "md", hash: "", ctime: 1700000000000, mtime: 1700000000100, folder: false, deleted: true, size: 0, pieces: 0 });
  const deleted = await ws.nextJson(); output.push(normalize(deleted, endpoint)); output.push(await ws.nextJson());
  ws.json({ op: "deleted", suppressrenames: false }); output.push(normalize(await ws.nextJson(), endpoint));
  ws.json({ op: "history", path: "encrypted-path", last: null }); output.push(normalize(await ws.nextJson(), endpoint));
  ws.json({ op: "size" }); output.push(await ws.nextJson());
  ws.json({ op: "usernames" }); output.push(await ws.nextJson());
  ws.json({ op: "ping" }); output.push(await ws.nextJson());
  return output;
}

function normalize(value: any, endpoint: Endpoint): any {
  if (Array.isArray(value)) return value.map((item) => normalize(item, endpoint));
  if (!value || typeof value !== "object") return value;
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === "password") continue;
    if (key === "version" && "encryption_version" in value) continue;
    if (key === "ts" || key === "created") { result[key] = "<time>"; continue; }
    if (key === "id" && item === endpoint.vault.id) { result[key] = "<vault>"; continue; }
    if (key === "host" && item === endpoint.vault.host) { result[key] = "<host>"; continue; }
    if (key === "token") { result[key] = "<token>"; continue; }
    result[key] = normalize(item, endpoint);
  }
  return result;
}

async function post(origin: string, path: string, body: Record<string, unknown>) { const response = await fetch(`${origin}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: "app://obsidian.md" }, body: JSON.stringify(body) }); return response.json(); }
async function waitHealth(port: number, child: ReturnType<typeof Bun.spawn>) { const deadline = Date.now() + 30_000; while (Date.now() < deadline) { if (child.exitCode !== null) throw new Error(await new Response(child.stderr as ReadableStream<Uint8Array>).text()); try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) return; } catch {} await Bun.sleep(50); } throw new Error("server health timeout"); }
async function freePort(): Promise<number> { return new Promise((resolve, reject) => { const server = createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const address = server.address(); if (!address || typeof address === "string") return reject(new Error("no port")); server.close(() => resolve(address.port)); }); }); }

class Probe {
  private queue: unknown[]=[];private waiters:Array<(v:unknown)=>void>=[];
  private constructor(readonly socket:WebSocket){socket.binaryType="arraybuffer";socket.addEventListener("message",e=>{const v=typeof e.data==="string"?JSON.parse(e.data):e.data;const waiter=this.waiters.shift();waiter?waiter(v):this.queue.push(v);});}
  static connect(url:string):Promise<Probe>{return new Promise((resolve,reject)=>{const ws=new WebSocket(url,{headers:{Origin:"app://obsidian.md"}} as unknown as string[]);sockets.push(ws);const probe=new Probe(ws);ws.addEventListener("open",()=>resolve(probe),{once:true});ws.addEventListener("error",()=>reject(new Error("websocket failed")),{once:true});});}
  json(v:Record<string,unknown>){this.socket.send(JSON.stringify(v));}
  async nextJson():Promise<any>{const value=await this.next();if(value instanceof ArrayBuffer)throw new Error("expected JSON");return value;}
  async nextBinary():Promise<ArrayBuffer>{const value=await this.next();if(!(value instanceof ArrayBuffer))throw new Error("expected binary");return value;}
  private next():Promise<unknown>{if(this.queue.length)return Promise.resolve(this.queue.shift());return new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error("websocket timeout")),5000);this.waiters.push(v=>{clearTimeout(timer);resolve(v);});});}
}
