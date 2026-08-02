import { describe, expect, test } from "bun:test";
import type {
  SharedRemoteVault,
  VaultListRequest,
  VaultListResponse,
  VaultShareInviteRequest,
  VaultShareItem,
  VaultShareListRequest,
  VaultShareListResponse,
  VaultShareRemoveRequest,
} from "../packages/protocol/src/control";
import type {
  InitMessage,
  PushNotification,
  RevisionItem,
} from "../packages/protocol/src/sync";

const sharedVault = {
  id: "vault-shared",
  name: "Shared vault",
  keyhash: "opaque-keyhash",
  salt: "opaque-salt",
  host: "data.example.test",
  region: "Blackglass Server",
  encryption_version: 3,
  size: 128,
  created: 1_722_000_000_000,
  share_uid: 41,
} satisfies SharedRemoteVault;

describe("stock client Phase 3/4 protocol fixtures", () => {
  test("CLIENT-1127-SHARE-SHAPE and CLIENT-1134-SHARE-SHAPE", () => {
    const listRequest = {
      token: "session-token",
      supported_encryption_version: 3,
    } satisfies VaultListRequest;
    const listResponse = {
      vaults: [],
      shared: [sharedVault],
      limit: 100,
    } satisfies VaultListResponse;
    const shareListRequest = {
      token: "session-token",
      vault_uid: "vault-owned",
    } satisfies VaultShareListRequest;
    const share = {
      uid: 41,
      email: "collaborator@example.test",
      name: "Collaborator",
      accepted: true,
    } satisfies VaultShareItem;
    const shareListResponse = { shares: [share] } satisfies VaultShareListResponse;
    const inviteRequest = {
      ...shareListRequest,
      email: share.email,
    } satisfies VaultShareInviteRequest;
    const removeRequest = {
      ...shareListRequest,
      share_uid: share.uid,
    } satisfies VaultShareRemoveRequest;

    expect(Object.keys(listRequest).sort()).toEqual([
      "supported_encryption_version",
      "token",
    ]);
    expect(Object.keys(listResponse).sort()).toEqual(["limit", "shared", "vaults"]);
    expect(Object.keys(sharedVault)).toContain("share_uid");
    expect(Object.keys(shareListRequest).sort()).toEqual(["token", "vault_uid"]);
    expect(Object.keys(shareListResponse.shares[0]!).sort()).toEqual([
      "accepted",
      "email",
      "name",
      "uid",
    ]);
    expect(Object.keys(inviteRequest).sort()).toEqual(["email", "token", "vault_uid"]);
    expect(Object.keys(removeRequest).sort()).toEqual([
      "share_uid",
      "token",
      "vault_uid",
    ]);
  });

  test("CLIENT-1127-IDENTITY and CLIENT-1134-IDENTITY", () => {
    const init = {
      op: "init",
      token: "session-token",
      id: sharedVault.id,
      keyhash: sharedVault.keyhash,
      version: 0,
      initial: true,
      device: "fixture-device",
      encryption_version: sharedVault.encryption_version,
    } satisfies InitMessage;
    const push = {
      op: "push",
      path: "note.md",
      relatedpath: null,
      extension: "md",
      hash: "opaque-content-hash",
      ctime: 1,
      mtime: 2,
      folder: false,
      deleted: false,
      size: 12,
      uid: 51,
      device: init.device,
      user: 7,
      ts: 3,
    } satisfies PushNotification;
    const revision = { ...push } satisfies RevisionItem;
    const initResponse = { res: "ok" as const, userId: 7, perFileMax: 8 * 1024 * 1024 };
    const usernames = { "7": "Owner", "8": "Collaborator" };

    expect(initResponse.userId).toBe(push.user);
    expect(revision.user).toBe(push.user);
    expect(usernames["7"]).toBe("Owner");
    expect(usernames["8"]).toBe("Collaborator");
    expect(usernames["7"]).not.toBe(usernames["8"]);
  });

  test("CLIENT-1127-NO-ROLE and CLIENT-1134-NO-ROLE", () => {
    expect("role" in sharedVault).toBe(false);
  });
});
