import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { mkdir, mkdtemp, readdir, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

class Probe { private queue:unknown[]=[];private waiters:Array<(v:unknown)=>void>=[];private constructor(readonly socket:WebSocket){socket.binaryType="arraybuffer";socket.addEventListener("message",e=>{const v=typeof e.data==="string"?JSON.parse(e.data):e.data;const waiter=this.waiters.shift();waiter?waiter(v):this.queue.push(v);});}static connect(url:string):Promise<Probe>{return new Promise((resolveProbe,reject)=>{const ws=new WebSocket(url,{headers:{Origin:"app://obsidian.md"}} as unknown as string[]);const probe=new Probe(ws);ws.addEventListener("open",()=>resolveProbe(probe),{once:true});ws.addEventListener("error",()=>reject(new Error("websocket failed")),{once:true});});}json(v:Record<string,unknown>){this.socket.send(JSON.stringify(v));}nextJson():Promise<any>{if(this.queue.length)return Promise.resolve(this.queue.shift());return new Promise((resolveValue,reject)=>{const timer=setTimeout(()=>reject(new Error("websocket timeout")),10_000);this.waiters.push(v=>{clearTimeout(timer);resolveValue(v);});});}}

const output = resolve(Bun.argv[2] ?? ".data/validation/rust-resource-report.json");
const root = resolve(import.meta.dir, "..");
const binary = join(root, "apps/server-rust/target/release/blackglass-server");
if (!(await Bun.file(binary).exists())) throw new Error("Build the release server first");
const directory = await mkdtemp(join(tmpdir(), "obsidian-rust-resource-"));
const [controlPort, dataPort] = await Promise.all([freePort(), freePort()]);
const child = Bun.spawn([binary, "serve"], {
  cwd: root, stdout: "pipe", stderr: "pipe",
  env: { ...process.env, SELFHOST_BIND_HOST: "127.0.0.1", SELFHOST_CONTROL_PORT: String(controlPort), SELFHOST_DATA_PORT: String(dataPort), SELFHOST_DATA_HOST: `127.0.0.1:${dataPort}`, SELFHOST_DATABASE: join(directory, "server.sqlite"), SELFHOST_STAGING_DIR: join(directory, "uploads"), SELFHOST_EMAIL: "resource@example.test", SELFHOST_PASSWORD: "resource-password", SELFHOST_ALLOW_PLAINTEXT_PASSWORD: "1", SELFHOST_NAME: "Resource test", SELFHOST_PER_FILE_MAX: String(128 * 1024 * 1024), SELFHOST_ALLOWED_ORIGIN: "app://obsidian.md", SELFHOST_LOG_FORMAT: "pretty" },
});

try {
  await waitHealth();
  const signin = await post("/user/signin", { email: "resource@example.test", password: "resource-password" });
  const vault = await post("/vault/create", { token: signin.token, name: "Resource vault", keyhash: "opaque-key", salt: "opaque-salt", region: "selfhost", encryption_version: 3 });
  const probe = await Probe.connect(`ws://127.0.0.1:${dataPort}`);
  probe.json({ op: "init", token: signin.token, id: vault.id, keyhash: vault.keyhash, version: 0, initial: true, device: "Resource probe", encryption_version: 3 });
  await probe.nextJson(); await probe.nextJson();
  await Bun.sleep(100);
  const baselineRssKiB = await rss();
  let peakRssKiB = baselineRssKiB;
  const rssAfterPiecesKiB: number[] = [];
  const size = 64 * 1024 * 1024;
  const piece = new Uint8Array(randomBytes(2 * 1024 * 1024));
  probe.json({ op: "push", path: "large-opaque-path", relatedpath: null, extension: "bin", hash: "large-opaque-hash", ctime: 1700000000000, mtime: 1700000000100, folder: false, deleted: false, size, pieces: 32 });
  expectNext(await probe.nextJson());
  for (let index = 0; index < 32; index++) {
    probe.socket.send(piece);
    if (index < 31) expectNext(await probe.nextJson());
    const sample = await rss();
    rssAfterPiecesKiB.push(sample);
    peakRssKiB = Math.max(peakRssKiB, sample);
  }
  const final = Promise.all([probe.nextJson(), probe.nextJson()]);
  while (await pending(final, 10)) peakRssKiB = Math.max(peakRssKiB, await rss());
  const [notice, ok] = await final;
  if (notice.op !== "push" || ok.res !== "ok") throw new Error("upload did not commit");
  peakRssKiB = Math.max(peakRssKiB, await rss());
  const databaseBytes = (await stat(join(directory, "server.sqlite"))).size;
  const stagingEntries = await readdir(join(directory, "uploads"));
  const deltaMiB = (peakRssKiB - baselineRssKiB) / 1024;
  const binarySha256 = createHash("sha256").update(Buffer.from(await Bun.file(binary).arrayBuffer())).digest("hex");
  const report = { schemaVersion: 1, passed: deltaMiB < 48 && stagingEntries.length === 0, implementation: "rust-release", binarySha256, uploadBytes: size, pieceBytes: piece.byteLength, pieces: 32, baselineRssKiB, rssAfterPiecesKiB, peakRssKiB, deltaRssKiB: peakRssKiB - baselineRssKiB, deltaMiB, databaseBytes, stagingEntries, thresholdMiB: 48 };
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  console.log(JSON.stringify(report, null, 2));
  if (!report.passed) process.exitCode = 1;
  probe.socket.close();
} finally {
  child.kill("SIGTERM");
  await child.exited;
}

async function rss(): Promise<number> { const result = Bun.spawnSync(["ps", "-o", "rss=", "-p", String(child.pid)], { stdout: "pipe", stderr: "pipe" }); if (result.exitCode !== 0) throw new Error(result.stderr.toString()); return Number(result.stdout.toString().trim()); }
async function post(path: string, body: Record<string, unknown>) { return (await fetch(`http://127.0.0.1:${controlPort}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: "app://obsidian.md" }, body: JSON.stringify(body) })).json(); }
async function waitHealth() { const deadline=Date.now()+15_000;while(Date.now()<deadline){if(child.exitCode!==null)throw new Error("server exited early");try{if((await fetch(`http://127.0.0.1:${controlPort}/ready`)).ok)return;}catch{}await Bun.sleep(50);}throw new Error("health timeout"); }
async function freePort():Promise<number>{return new Promise((resolvePort,reject)=>{const server=createServer();server.once("error",reject);server.listen(0,"127.0.0.1",()=>{const address=server.address();if(!address||typeof address==="string")return reject(new Error("no port"));server.close(()=>resolvePort(address.port));});});}
function expectNext(value:any){if(value.res!=="next")throw new Error(`expected next: ${JSON.stringify(value)}`);}
async function pending<T>(promise:Promise<T>,milliseconds:number):Promise<boolean>{return Promise.race([promise.then(()=>false),Bun.sleep(milliseconds).then(()=>true)]);}
