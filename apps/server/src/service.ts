import { randomBytes, timingSafeEqual } from "node:crypto";
import type {
  ApiError,
  RemoteVault,
  SigninRequest,
  TokenRequest,
  VaultAccessRequest,
  VaultCreateRequest,
  VaultDeleteRequest,
  VaultRenameRequest,
} from "../../../packages/protocol/src/control";
import { CONTROL_ROUTES } from "../../../packages/protocol/src/control";
import type {
  ClientTextMessage,
  DeletedMessage,
  HistoryMessage,
  InitMessage,
  PullMessage,
  PurgeMessage,
  PushMessage,
  PushNotification,
  RestoreMessage,
  RevisionItem,
  ServerTextMessage,
} from "../../../packages/protocol/src/sync";
import type { ServerConfig } from "./config";
import {
  SyncDatabase,
  type NewRevision,
  type Revision,
} from "./database";

interface SocketState {
  authenticated: boolean;
  vaultId?: string;
  device?: string;
  pendingUpload?: {
    revision: Omit<NewRevision, "content">;
    chunks: Uint8Array[];
    receivedBytes: number;
  };
}

type SyncSocket = Bun.ServerWebSocket<SocketState>;

export interface RunningService {
  controlOrigin: string;
  dataHost: string;
  stop(): Promise<void>;
}

export function startService(config: ServerConfig): RunningService {
  const database = new SyncDatabase(config.databasePath);

  const controlServer = Bun.serve({
    hostname: config.bindHost,
    port: config.controlPort,
    fetch: (request) => handleControlRequest(request, config, database),
  });

  const dataServer = Bun.serve<SocketState>({
    hostname: config.bindHost,
    port: config.dataPort,
    fetch(request, server) {
      if (new URL(request.url).pathname !== "/") {
        return new Response("Not found", { status: 404 });
      }
      if (
        !server.upgrade(request, {
          data: { authenticated: false },
        })
      ) {
        return new Response("WebSocket upgrade required", { status: 426 });
      }
      return undefined;
    },
    websocket: {
      message(socket, message) {
        handleSyncMessage(socket, message, config, database);
      },
    },
  });

  return {
    controlOrigin: `http://${config.bindHost}:${controlServer.port}`,
    dataHost: `${config.bindHost}:${dataServer.port}`,
    async stop() {
      controlServer.stop(true);
      dataServer.stop(true);
      database.close();
    },
  };
}

async function handleControlRequest(
  request: Request,
  config: ServerConfig,
  database: SyncDatabase,
): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(),
    });
  }
  if (request.method === "GET" && url.pathname === "/health") {
    return json({ ok: true, service: "blackglass-server" });
  }
  if (request.method !== "POST") {
    return json({ error: "Not found" } satisfies ApiError, 404);
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "Invalid JSON" } satisfies ApiError, 400);
  }

  switch (url.pathname) {
    case CONTROL_ROUTES.signin:
      return signin(body as unknown as SigninRequest, config);
    case CONTROL_ROUTES.signout:
      return requireToken(body as unknown as TokenRequest, config, () =>
        json({}),
      );
    case CONTROL_ROUTES.userInfo:
      return requireToken(body as unknown as TokenRequest, config, () =>
        json(account(config)),
      );
    case CONTROL_ROUTES.subscriptionList:
      return requireToken(body as unknown as TokenRequest, config, () =>
        json({ sync: true, publish: false }),
      );
    case CONTROL_ROUTES.vaultRegions:
      return requireToken(body as unknown as TokenRequest, config, () =>
        json({
          regions: [{ value: "selfhost", name: "Blackglass Server" }],
        }),
      );
    case CONTROL_ROUTES.vaultList:
      return requireToken(body as unknown as TokenRequest, config, () =>
        json({
          vaults: database.listVaults(),
          shared: [],
          limit: 100,
        }),
      );
    case CONTROL_ROUTES.vaultCreate:
      return requireToken(
        body as unknown as VaultCreateRequest,
        config,
        () => createVault(body as unknown as VaultCreateRequest, config, database),
      );
    case CONTROL_ROUTES.vaultAccess:
      return requireToken(
        body as unknown as VaultAccessRequest,
        config,
        () => accessVault(body as unknown as VaultAccessRequest, database),
      );
    case CONTROL_ROUTES.vaultRename:
      return requireToken(
        body as unknown as VaultRenameRequest,
        config,
        () => renameVault(body as unknown as VaultRenameRequest, database),
      );
    case CONTROL_ROUTES.vaultDelete:
      return requireToken(
        body as unknown as VaultDeleteRequest,
        config,
        () => deleteVault(body as unknown as VaultDeleteRequest, database),
      );
    case CONTROL_ROUTES.vaultShareList:
      return requireToken(body as unknown as TokenRequest, config, () =>
        json({ shares: [] }),
      );
    case CONTROL_ROUTES.vaultShareInvite:
    case CONTROL_ROUTES.vaultShareRemove:
      return requireToken(body as unknown as TokenRequest, config, () =>
        json({ error: "Sharing is unavailable in single-user mode" } satisfies ApiError),
      );
    default:
      return json({ error: "Not found" } satisfies ApiError, 404);
  }
}

function signin(request: SigninRequest, config: ServerConfig): Response {
  const validEmail =
    typeof request.email === "string" &&
    request.email.toLocaleLowerCase() === config.email.toLocaleLowerCase();
  const validPassword =
    typeof request.password === "string" &&
    constantTimeEqual(request.password, config.password);
  if (!validEmail || !validPassword) {
    return json({ error: "Invalid email or password" } satisfies ApiError);
  }
  return json({ ...account(config), token: config.token });
}

function account(config: ServerConfig) {
  return {
    email: config.email,
    name: config.displayName,
    license: "selfhosted-sync",
  };
}

function createVault(
  request: VaultCreateRequest,
  config: ServerConfig,
  database: SyncDatabase,
): Response {
  if (typeof request.name !== "string" || request.name.trim() === "") {
    return json({ error: "Vault name is required" } satisfies ApiError);
  }
  if (
    !Number.isInteger(request.encryption_version) ||
    request.encryption_version < 0 ||
    request.encryption_version > 3
  ) {
    return json({ error: "Unsupported encryption version" } satisfies ApiError);
  }
  if (request.keyhash !== null && typeof request.keyhash !== "string") {
    return json({ error: "Invalid key hash" } satisfies ApiError);
  }
  if (
    request.salt !== null &&
    request.salt !== undefined &&
    typeof request.salt !== "string"
  ) {
    return json({ error: "Invalid salt" } satisfies ApiError);
  }

  const managed = request.keyhash === null && request.salt == null;
  const vault: RemoteVault = {
    id: crypto.randomUUID(),
    name: request.name.trim(),
    keyhash: request.keyhash,
    salt: managed ? randomBytes(16).toString("hex") : request.salt ?? null,
    host: config.publicDataHost,
    region: "Blackglass Server",
    encryption_version: request.encryption_version,
    size: 0,
    created: Date.now(),
    ...(managed ? { password: randomBytes(32).toString("hex") } : {}),
  };

  return json(database.createVault(vault));
}

function accessVault(
  request: VaultAccessRequest,
  database: SyncDatabase,
): Response {
  const vault = database.findVault(request.vault_uid);
  if (
    !vault ||
    request.host !== vault.host ||
    request.encryption_version !== vault.encryption_version
  ) {
    return json({ error: "Unable to access vault" } satisfies ApiError);
  }
  if (
    vault.password &&
    vault.keyhash === null &&
    typeof request.keyhash === "string" &&
    request.keyhash !== ""
  ) {
    database.bindManagedKeyhash(vault.id, request.keyhash);
    vault.keyhash = request.keyhash;
  }
  if (
    request.keyhash !== vault.keyhash
  ) {
    return json({ error: "Unable to access vault" } satisfies ApiError);
  }
  return json({});
}

function renameVault(request: VaultRenameRequest, database: SyncDatabase): Response {
  if (
    typeof request.vault_uid !== "string" ||
    typeof request.name !== "string" ||
    request.name.trim() === "" ||
    !database.renameVault(request.vault_uid, request.name.trim())
  ) {
    return json({ error: "Unable to rename vault" } satisfies ApiError);
  }
  return json({});
}

function deleteVault(request: VaultDeleteRequest, database: SyncDatabase): Response {
  if (
    typeof request.vault_uid !== "string" ||
    !database.deleteVault(request.vault_uid)
  ) {
    return json({ error: "Unable to delete vault" } satisfies ApiError);
  }
  return json({});
}

function requireToken(
  request: TokenRequest,
  config: ServerConfig,
  action: () => Response,
): Response {
  if (
    typeof request.token !== "string" ||
    !constantTimeEqual(request.token, config.token)
  ) {
    return json({ error: "Not logged in" } satisfies ApiError);
  }
  return action();
}

function handleSyncMessage(
  socket: SyncSocket,
  rawMessage: string | BufferSource,
  config: ServerConfig,
  database: SyncDatabase,
): void {
  if (typeof rawMessage !== "string") {
    handleUploadChunk(socket, rawMessage, database);
    return;
  }

  let message: ClientTextMessage;
  try {
    message = JSON.parse(rawMessage) as ClientTextMessage;
  } catch {
    send(socket, { res: "err", msg: "Invalid JSON" });
    return;
  }

  if (message.op === "ping") {
    send(socket, { op: "pong" });
    return;
  }

  if (!socket.data.authenticated) {
    authenticateSocket(socket, message, config, database);
    return;
  }

  switch (message.op) {
    case "size":
      send(socket, {
        res: "ok",
        size: database.totalSize(),
        limit: 1024 * 1024 * 1024 * 1024,
        vault_size: database.vaultSize(requireVaultId(socket)),
      });
      break;
    case "usernames":
      send(socket, { "1": config.displayName });
      break;
    case "push":
      beginPush(socket, message as PushMessage, config, database);
      break;
    case "pull":
      pullRevision(socket, message as PullMessage, database);
      break;
    case "deleted":
      listDeleted(socket, message as DeletedMessage, database);
      break;
    case "history":
      listHistory(socket, message as HistoryMessage, database);
      break;
    case "restore":
      restoreRevision(socket, message as RestoreMessage, database);
      break;
    case "purge":
      purgeHistory(socket, message as PurgeMessage, database);
      break;
    default:
      send(socket, {
        err: `Unsupported operation: ${message.op}`,
      });
  }
}

function authenticateSocket(
  socket: SyncSocket,
  message: ClientTextMessage,
  config: ServerConfig,
  database: SyncDatabase,
): void {
  if (message.op !== "init") {
    send(socket, { res: "err", msg: "Authentication required" });
    return;
  }

  const init = message as InitMessage;
  const vault = database.findVault(init.id);
  if (
    !vault ||
    typeof init.token !== "string" ||
    !constantTimeEqual(init.token, config.token) ||
    init.keyhash !== vault.keyhash ||
    init.encryption_version !== vault.encryption_version
  ) {
    send(socket, { res: "err", msg: "Unable to authenticate" });
    return;
  }

  socket.data.authenticated = true;
  socket.data.vaultId = vault.id;
  socket.data.device =
    typeof init.device === "string" && init.device !== ""
      ? init.device
      : "Unknown device";
  socket.subscribe(vaultTopic(vault.id));
  send(socket, { res: "ok", userId: 1, perFileMax: config.perFileMax });
  queueMicrotask(() => {
    const revisions = init.initial
      ? database.listInitialSnapshot(vault.id)
      : database.listChangesAfter(vault.id, init.version);
    for (const revision of revisions) {
      send(socket, revisionNotification(revision));
    }
    send(socket, {
      op: "ready",
      version: database.currentVersion(vault.id),
    });
  });
}

function beginPush(
  socket: SyncSocket,
  message: PushMessage,
  config: ServerConfig,
  database: SyncDatabase,
): void {
  const vaultId = requireVaultId(socket);
  if (!isValidPush(message, config.perFileMax)) {
    send(socket, { err: "Invalid push metadata" });
    return;
  }
  if (socket.data.pendingUpload) {
    send(socket, { err: "An upload is already in progress" });
    return;
  }

  const revision: Omit<NewRevision, "content"> = {
    vaultId,
    path: message.path,
    relatedpath: message.relatedpath ?? null,
    extension: message.extension,
    hash: message.hash,
    ctime: message.ctime,
    mtime: message.mtime,
    folder: message.folder,
    deleted: message.deleted,
    size: message.size ?? 0,
    pieces: message.pieces ?? 0,
    device: socket.data.device ?? "Unknown device",
    userId: 1,
  };

  if (revision.folder || revision.deleted || revision.pieces === 0) {
    const stored = database.addRevision({ ...revision, content: null });
    broadcastRevision(socket, stored);
    send(socket, { res: "ok" });
    return;
  }

  socket.data.pendingUpload = {
    revision,
    chunks: [],
    receivedBytes: 0,
  };
  send(socket, { res: "next" });
}

function handleUploadChunk(
  socket: SyncSocket,
  rawMessage: BufferSource,
  database: SyncDatabase,
): void {
  const pending = socket.data.pendingUpload;
  if (!socket.data.authenticated || !pending) {
    socket.close(1008, "Unexpected binary message");
    return;
  }

  const bytes = copyBytes(rawMessage);
  pending.chunks.push(bytes);
  pending.receivedBytes += bytes.byteLength;

  if (
    pending.chunks.length > pending.revision.pieces ||
    pending.receivedBytes > pending.revision.size
  ) {
    delete socket.data.pendingUpload;
    socket.close(1009, "Upload exceeds declared size");
    return;
  }

  if (pending.chunks.length < pending.revision.pieces) {
    send(socket, { res: "next" });
    return;
  }
  if (pending.receivedBytes !== pending.revision.size) {
    delete socket.data.pendingUpload;
    socket.close(1008, "Upload size does not match metadata");
    return;
  }

  const content = Buffer.concat(pending.chunks.map((chunk) => Buffer.from(chunk)));
  const stored = database.addRevision({
    ...pending.revision,
    content,
  });
  delete socket.data.pendingUpload;
  broadcastRevision(socket, stored);
  send(socket, { res: "ok" });
}

function pullRevision(
  socket: SyncSocket,
  message: PullMessage,
  database: SyncDatabase,
): void {
  if (!Number.isInteger(message.uid)) {
    send(socket, { err: "Revision not found" });
    return;
  }
  const revision = database.getRevision(message.uid);
  if (
    !revision ||
    revision.vault_id !== requireVaultId(socket)
  ) {
    send(socket, { err: "Revision not found" });
    return;
  }

  if (revision.deleted || revision.folder || !revision.content) {
    send(socket, {
      res: "ok",
      size: 0,
      pieces: 0,
      deleted: revision.deleted === 1,
      hash: revision.hash,
    });
    return;
  }

  send(socket, {
    res: "ok",
    size: revision.size,
    pieces: revision.pieces,
    deleted: false,
    hash: revision.hash,
  });
  const content = new Uint8Array(revision.content);
  const pieceSize = 2 * 1024 * 1024;
  for (let offset = 0; offset < content.byteLength; offset += pieceSize) {
    socket.send(content.slice(offset, Math.min(offset + pieceSize, content.byteLength)));
  }
}

function listDeleted(
  socket: SyncSocket,
  message: DeletedMessage,
  database: SyncDatabase,
): void {
  const items = database
    .listDeleted(requireVaultId(socket), message.suppressrenames === true)
    .map(revisionItem);
  send(socket, { items });
}

function listHistory(
  socket: SyncSocket,
  message: HistoryMessage,
  database: SyncDatabase,
): void {
  if (typeof message.path !== "string" || message.path === "") {
    send(socket, { err: "Invalid history path" });
    return;
  }
  const last = Number.isInteger(message.last) ? Number(message.last) : null;
  const pageSize = 100;
  const revisions = database.listHistory(
    requireVaultId(socket),
    message.path,
    last,
    pageSize + 1,
  );
  send(socket, {
    items: revisions.slice(0, pageSize).map(revisionItem),
    more: revisions.length > pageSize,
  });
}

function restoreRevision(
  socket: SyncSocket,
  message: RestoreMessage,
  database: SyncDatabase,
): void {
  if (!Number.isInteger(message.uid)) {
    send(socket, { err: "Revision not found" });
    return;
  }
  const restored = database.restoreRevision(
    requireVaultId(socket),
    message.uid,
    socket.data.device ?? "Unknown device",
    1,
  );
  if (!restored) {
    send(socket, { err: "Revision not found" });
    return;
  }
  broadcastRevision(socket, restored);
  send(socket, { res: "ok" });
}

function purgeHistory(
  socket: SyncSocket,
  _message: PurgeMessage,
  database: SyncDatabase,
): void {
  database.purgeHistory(requireVaultId(socket));
  send(socket, { res: "ok" });
}

function broadcastRevision(socket: SyncSocket, revision: Revision): void {
  const notification = JSON.stringify(revisionNotification(revision));
  socket.send(notification);
  socket.publish(vaultTopic(revision.vault_id), notification);
}

function revisionNotification(revision: Revision): PushNotification {
  return {
    op: "push",
    path: revision.path,
    relatedpath: revision.relatedpath,
    extension: revision.extension,
    hash: revision.hash,
    ctime: revision.ctime,
    mtime: revision.mtime,
    folder: revision.folder === 1,
    deleted: revision.deleted === 1,
    size: revision.size,
    uid: revision.uid,
    device: revision.device,
    user: revision.user_id,
    ts: revision.ts,
  };
}

function revisionItem(revision: Revision): RevisionItem {
  const { op: _op, ...item } = revisionNotification(revision);
  return item;
}

function isValidPush(message: PushMessage, perFileMax: number): boolean {
  const size = message.size ?? 0;
  const pieces = message.pieces ?? 0;
  return (
    typeof message.path === "string" &&
    message.path !== "" &&
    (message.relatedpath === null ||
      message.relatedpath === undefined ||
      typeof message.relatedpath === "string") &&
    typeof message.extension === "string" &&
    typeof message.hash === "string" &&
    Number.isFinite(message.ctime) &&
    Number.isFinite(message.mtime) &&
    typeof message.folder === "boolean" &&
    typeof message.deleted === "boolean" &&
    Number.isInteger(size) &&
    size >= 0 &&
    size <= perFileMax &&
    Number.isInteger(pieces) &&
    pieces >= 0 &&
    pieces === Math.ceil(size / (2 * 1024 * 1024))
  );
}

function requireVaultId(socket: SyncSocket): string {
  if (!socket.data.vaultId) {
    throw new Error("Authenticated socket has no vault");
  }
  return socket.data.vaultId;
}

function vaultTopic(vaultId: string): string {
  return `vault:${vaultId}`;
}

function copyBytes(source: BufferSource): Uint8Array {
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(
      source.buffer.slice(
        source.byteOffset,
        source.byteOffset + source.byteLength,
      ),
    );
  }
  return new Uint8Array(source.slice(0));
}

function send(socket: SyncSocket, message: ServerTextMessage): void {
  socket.send(JSON.stringify(message));
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  if (leftBytes.length !== rightBytes.length) {
    return false;
  }
  return timingSafeEqual(leftBytes, rightBytes);
}

function json(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: {
      "cache-control": "no-store",
      ...corsHeaders(),
    },
  });
}

function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "POST, GET, OPTIONS",
    "access-control-allow-headers": "content-type",
  };
}
