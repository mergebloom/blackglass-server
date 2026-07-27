import { Database } from "bun:sqlite";
import type { RemoteVault } from "../../../packages/protocol/src/control";

interface VaultRow {
  id: string;
  name: string;
  keyhash: string | null;
  salt: string | null;
  host: string;
  region: string;
  encryption_version: number;
  size: number;
  created: number;
  password?: string;
  version: number;
}

export interface Revision {
  uid: number;
  vault_id: string;
  path: string;
  relatedpath: string | null;
  extension: string;
  hash: string;
  ctime: number;
  mtime: number;
  folder: number;
  deleted: number;
  size: number;
  pieces: number;
  content: Uint8Array | null;
  device: string;
  user_id: number;
  ts: number;
}

export interface NewRevision {
  vaultId: string;
  path: string;
  relatedpath: string | null;
  extension: string;
  hash: string;
  ctime: number;
  mtime: number;
  folder: boolean;
  deleted: boolean;
  size: number;
  pieces: number;
  content: Uint8Array | null;
  device: string;
  userId: number;
}

export class SyncDatabase {
  readonly sqlite: Database;

  constructor(path: string) {
    this.sqlite = new Database(path, { create: true, strict: true });
    this.sqlite.exec("PRAGMA foreign_keys = ON");
    this.sqlite.exec("PRAGMA journal_mode = WAL");
    this.sqlite.exec(`
      CREATE TABLE IF NOT EXISTS vaults (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        keyhash TEXT,
        salt TEXT,
        host TEXT NOT NULL,
        region TEXT NOT NULL,
        encryption_version INTEGER NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        created INTEGER NOT NULL,
        password TEXT,
        version INTEGER NOT NULL DEFAULT 0
      )
    `);
    this.sqlite.exec(`
      CREATE TABLE IF NOT EXISTS revisions (
        uid INTEGER PRIMARY KEY AUTOINCREMENT,
        vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        relatedpath TEXT,
        extension TEXT NOT NULL,
        hash TEXT NOT NULL,
        ctime INTEGER NOT NULL,
        mtime INTEGER NOT NULL,
        folder INTEGER NOT NULL,
        deleted INTEGER NOT NULL,
        size INTEGER NOT NULL,
        pieces INTEGER NOT NULL,
        content BLOB,
        device TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        ts INTEGER NOT NULL DEFAULT 0
      )
    `);
    this.addColumnIfMissing("vaults", "password", "TEXT");
    this.addColumnIfMissing("vaults", "version", "INTEGER NOT NULL DEFAULT 0");
    this.addColumnIfMissing("revisions", "ts", "INTEGER NOT NULL DEFAULT 0");
    this.sqlite
      .query("UPDATE revisions SET ts = CASE WHEN mtime > 0 THEN mtime ELSE ? END WHERE ts = 0")
      .run(Date.now());
    this.sqlite.exec(`
      UPDATE vaults
         SET version = COALESCE(
           (SELECT MAX(uid) FROM revisions WHERE vault_id = vaults.id),
           version,
           0
         )
       WHERE version = 0
    `);
    this.sqlite.exec(`
      CREATE INDEX IF NOT EXISTS revisions_vault_uid
      ON revisions(vault_id, uid)
    `);
    this.sqlite.exec(`
      CREATE INDEX IF NOT EXISTS revisions_vault_path
      ON revisions(vault_id, path, uid)
    `);
  }

  createVault(vault: RemoteVault): RemoteVault {
    this.sqlite
      .query(
        `INSERT INTO vaults
          (id, name, keyhash, salt, host, region, encryption_version, size,
           created, password, version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      )
      .run(
        vault.id,
        vault.name,
        vault.keyhash,
        vault.salt,
        vault.host,
        vault.region,
        vault.encryption_version,
        vault.size,
        vault.created,
        vault.password ?? null,
      );
    return vault;
  }

  listVaults(): RemoteVault[] {
    return this.sqlite
      .query<VaultRow, []>(
        `SELECT id, name, keyhash, salt, host, region,
                encryption_version, size, created, password, version
           FROM vaults
          ORDER BY created ASC`,
      )
      .all();
  }

  findVault(id: string): RemoteVault | null {
    return (
      this.sqlite
        .query<VaultRow, [string]>(
          `SELECT id, name, keyhash, salt, host, region,
                  encryption_version, size, created, password, version
             FROM vaults
            WHERE id = ?`,
        )
        .get(id) ?? null
    );
  }

  renameVault(id: string, name: string): boolean {
    return this.sqlite.query("UPDATE vaults SET name = ? WHERE id = ?").run(name, id).changes === 1;
  }

  deleteVault(id: string): boolean {
    return this.sqlite.query("DELETE FROM vaults WHERE id = ?").run(id).changes === 1;
  }

  bindManagedKeyhash(id: string, keyhash: string): boolean {
    return this.sqlite
      .query("UPDATE vaults SET keyhash = ? WHERE id = ? AND password IS NOT NULL AND keyhash IS NULL")
      .run(keyhash, id).changes === 1;
  }

  addRevision(revision: NewRevision): Revision {
    const result = this.sqlite
      .query(
        `INSERT INTO revisions
          (vault_id, path, relatedpath, extension, hash, ctime, mtime,
           folder, deleted, size, pieces, content, device, user_id, ts)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        revision.vaultId,
        revision.path,
        revision.relatedpath,
        revision.extension,
        revision.hash,
        revision.ctime,
        revision.mtime,
        Number(revision.folder),
        Number(revision.deleted),
        revision.size,
        revision.pieces,
        revision.content,
        revision.device,
        revision.userId,
        Date.now(),
      );
    const inserted = this.getRevision(Number(result.lastInsertRowid));
    if (!inserted) {
      throw new Error("Failed to read inserted revision");
    }
    this.refreshVaultSize(revision.vaultId);
    this.sqlite.query("UPDATE vaults SET version = ? WHERE id = ?").run(inserted.uid, revision.vaultId);
    return inserted;
  }

  getRevision(uid: number): Revision | null {
    return (
      this.sqlite
        .query<Revision, [number]>(
          `SELECT uid, vault_id, path, relatedpath, extension, hash,
                  ctime, mtime, folder, deleted, size, pieces, content,
                  device, user_id, ts
             FROM revisions
            WHERE uid = ?`,
        )
        .get(uid) ?? null
    );
  }

  getCurrentRevision(vaultId: string, path: string): Revision | null {
    return (
      this.sqlite
        .query<Revision, [string, string]>(
          `SELECT uid, vault_id, path, relatedpath, extension, hash,
                  ctime, mtime, folder, deleted, size, pieces, content,
                  device, user_id, ts
             FROM revisions
            WHERE vault_id = ? AND path = ?
            ORDER BY uid DESC
            LIMIT 1`,
        )
        .get(vaultId, path) ?? null
    );
  }

  listChangesAfter(vaultId: string, uid: number): Revision[] {
    return this.sqlite
      .query<Revision, [string, number]>(
        `SELECT uid, vault_id, path, relatedpath, extension, hash,
                ctime, mtime, folder, deleted, size, pieces, content,
                device, user_id, ts
           FROM revisions
          WHERE vault_id = ? AND uid > ?
          ORDER BY uid ASC`,
      )
      .all(vaultId, uid);
  }

  listInitialSnapshot(vaultId: string): Revision[] {
    return this.sqlite
      .query<Revision, [string]>(
        `SELECT r.uid, r.vault_id, r.path, r.relatedpath, r.extension, r.hash,
                r.ctime, r.mtime, r.folder, r.deleted, r.size, r.pieces,
                r.content, r.device, r.user_id, r.ts
           FROM revisions r
           JOIN (
             SELECT path, MAX(uid) AS uid
               FROM revisions
              WHERE vault_id = ?
              GROUP BY path
           ) heads ON heads.uid = r.uid
          WHERE r.deleted = 0
          ORDER BY r.uid ASC`,
      )
      .all(vaultId);
  }

  listDeleted(vaultId: string, suppressRenames: boolean): Revision[] {
    return this.sqlite
      .query<Revision, [string, number]>(
        `SELECT r.uid, r.vault_id, r.path, r.relatedpath, r.extension, r.hash,
                r.ctime, r.mtime, r.folder, r.deleted, r.size, r.pieces,
                r.content, r.device, r.user_id, r.ts
           FROM revisions r
           JOIN (
             SELECT path, MAX(uid) AS uid
               FROM revisions
              WHERE vault_id = ?
              GROUP BY path
           ) heads ON heads.uid = r.uid
          WHERE r.deleted = 1
            AND (
              ? = 0 OR NOT EXISTS (
                SELECT 1
                  FROM revisions live
                  JOIN (
                    SELECT path, MAX(uid) AS uid
                      FROM revisions
                     WHERE vault_id = r.vault_id
                     GROUP BY path
                  ) live_heads ON live_heads.uid = live.uid
                 WHERE live.deleted = 0 AND live.relatedpath = r.path
              )
            )
          ORDER BY r.uid ASC`,
      )
      .all(vaultId, Number(suppressRenames));
  }

  listHistory(vaultId: string, path: string, last: number | null, limit = 100): Revision[] {
    return this.sqlite
      .query<Revision, [string, string, number | null, number | null, number]>(
        `SELECT uid, vault_id, path, relatedpath, extension, hash,
                ctime, mtime, folder, deleted, size, pieces, content,
                device, user_id, ts
           FROM revisions
          WHERE vault_id = ? AND path = ?
            AND (? IS NULL OR uid < ?)
          ORDER BY uid DESC
          LIMIT ?`,
      )
      .all(vaultId, path, last, last, limit);
  }

  restoreRevision(vaultId: string, uid: number, device: string, userId: number): Revision | null {
    const target = this.getRevision(uid);
    if (!target || target.vault_id !== vaultId) {
      return null;
    }
    const source = target.deleted
      ? this.sqlite
          .query<Revision, [string, string, number]>(
            `SELECT uid, vault_id, path, relatedpath, extension, hash,
                    ctime, mtime, folder, deleted, size, pieces, content,
                    device, user_id, ts
               FROM revisions
              WHERE vault_id = ? AND path = ? AND uid < ? AND deleted = 0
              ORDER BY uid DESC LIMIT 1`,
          )
          .get(vaultId, target.path, target.uid)
      : target;
    if (!source) {
      return null;
    }
    return this.addRevision({
      vaultId,
      path: target.path,
      relatedpath: null,
      extension: source.extension,
      hash: source.hash,
      ctime: source.ctime,
      mtime: source.mtime,
      folder: source.folder === 1,
      deleted: false,
      size: source.size,
      pieces: source.pieces,
      content: source.content,
      device,
      userId,
    });
  }

  purgeHistory(vaultId: string): void {
    this.sqlite.transaction(() => {
      this.sqlite
        .query(
          `DELETE FROM revisions
            WHERE vault_id = ?
              AND uid NOT IN (
                SELECT r.uid
                  FROM revisions r
                  JOIN (
                    SELECT path, MAX(uid) AS uid
                      FROM revisions
                     WHERE vault_id = ?
                     GROUP BY path
                  ) heads ON heads.uid = r.uid
                 WHERE r.deleted = 0
              )`,
        )
        .run(vaultId, vaultId);
      this.refreshVaultSize(vaultId);
    })();
  }

  currentVersion(vaultId: string): number {
    const row = this.sqlite
      .query<{ version: number }, [string]>(
        "SELECT version FROM vaults WHERE id = ?",
      )
      .get(vaultId);
    return row?.version ?? 0;
  }

  vaultSize(vaultId: string): number {
    const row = this.sqlite
      .query<{ size: number }, [string]>(
        `SELECT COALESCE(SUM(size), 0) AS size
           FROM revisions
          WHERE uid IN (
            SELECT MAX(uid)
              FROM revisions
             WHERE vault_id = ?
             GROUP BY path
          )
            AND deleted = 0
            AND folder = 0`,
      )
      .get(vaultId);
    return row?.size ?? 0;
  }

  totalSize(): number {
    const row = this.sqlite
      .query<{ size: number }, []>("SELECT COALESCE(SUM(size), 0) AS size FROM vaults")
      .get();
    return row?.size ?? 0;
  }

  private refreshVaultSize(vaultId: string): void {
    this.sqlite
      .query("UPDATE vaults SET size = ? WHERE id = ?")
      .run(this.vaultSize(vaultId), vaultId);
  }

  private addColumnIfMissing(table: string, column: string, definition: string): void {
    const columns = this.sqlite.query<{ name: string }, []>(`PRAGMA table_info(${table})`).all();
    if (!columns.some((entry) => entry.name === column)) {
      this.sqlite.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
  }

  close(): void {
    this.sqlite.close();
  }
}
