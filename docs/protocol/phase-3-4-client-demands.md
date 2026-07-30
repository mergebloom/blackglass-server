# Obsidian 1.12.7 client demands for Blackglass Phase 3 and Phase 4

Status: static contract validated on 2026-07-30; multi-user and collaboration runtime qualification remains an implementation gate.

## Scope and evidence

This document records what the stock Obsidian 1.12.7 renderer actually asks of the server. It is a compatibility contract, not an attempt to reproduce or publish proprietary client source.

Evidence:

- Official release asset: `obsidian-1.12.7.asar.gz`
- Published compressed SHA-256: `75dd34f14c9db558fbad19e80f0b201bc9805b51b7388370277e0f91a38bd850`
- Verified decompressed ASAR SHA-256: `2b2483b2e1246772e0d25367ec055cbc5047ea2f0091b667c35656678f86d712`
- Package version read from the archive: `1.12.7`
- Blackglass Bridge analyzer result: all six exact patch anchors matched once and the release was patch-ready.
- Machine-readable scrubbed evidence: [`../validation/obsidian-1.12.7-phase-3-4-client-demand.json`](../validation/obsidian-1.12.7-phase-3-4-client-demand.json)
- Existing Blackglass protocol notes and deterministic integration tests.
- [Obsidian's public collaboration documentation](https://obsidian.md/help/sync/collaborate) and [Sync security documentation](https://obsidian.md/help/sync/security), used only to explain user-visible semantics. The client artifact remains the protocol authority.

The verified ASAR and extracted renderer were kept outside either repository in a temporary mode-`0700` directory with mode-`0600` files. They must not be committed or redistributed.

## Phase definitions

- Phase 3: multiple server accounts, user-bound sessions, per-user vault ownership, and complete tenant isolation. Vault sharing is still disabled.
- Phase 4: owner-managed shared-vault membership and stock-client collaboration on top of the Phase 3 authorization boundary.

Phase 4 must not be implemented by merely adding a `user_id` column. Every control-plane query, data-plane operation, transfer, event, quota, migration, and administrative projection must use an authenticated user and an explicit vault authorization decision.

## Confirmed control-plane contract

All calls are JSON `POST` requests. The stock client sends the session token in the JSON body rather than an HTTP Authorization header.

### Account and session behavior

The client requires at least:

- `/user/signin`: request fields `email`, `password`, and optional `mfa`; a successful response supplies `token`, `email`, `name`, and `license`.
- `/user/info`: request field `token`; the client refreshes its stored `email`, `name`, and `license` from the response.
- `/user/signout`: request field `token`; `Not logged in` is tolerated during local logout cleanup.
- `/subscription/list`: request field `token`; `sync: true` enables the client to connect to a remote vault.

The stock renderer also contains signup, password-reset, confirmation, auth-token, mobile-subscription, business-subscription, Publish, and regions routes. Blackglass may continue returning explicit unsupported responses for flows outside the self-hosted product contract. Phase 3 must not accidentally expose public self-signup or password reset merely because the route strings exist.

### Vault inventory

`/vault/list` request:

- `token`
- `supported_encryption_version: 3`

The response must contain:

- `vaults`: remote vaults owned by the authenticated user.
- `shared`: remote vaults shared with the authenticated user.
- `limit`: the authenticated user's owned-vault limit. Shared vaults are displayed separately and do not consume the owned-vault list in the client.

Each shared-vault item is a normal vault descriptor plus `share_uid`. The client uses `share_uid` when the collaborator chooses **Leave shared vault**.

The stock UI exposes create, delete, rename, and sharing management for entries in `vaults`. Entries in `shared` expose connect/disconnect and leave, but not owner-management actions. The server must enforce that boundary even if a caller invokes owner-only routes directly.

### Sharing calls

`/vault/share/list`:

- Request: `token`, `vault_uid`
- Response: `shares`
- Each visible share item uses `uid`, `email`, optional `name`, and `accepted`.

`/vault/share/invite`:

- Request: `token`, `vault_uid`, `email`
- The stock client only performs basic non-empty/`@` validation; canonicalization and authorization belong to the server.

`/vault/share/remove`:

- Request: `token`, `vault_uid`, `share_uid`
- The same route serves two cases: the owner removes a collaborator, or a collaborator leaves using their own `share_uid`.

There is no `/vault/share/accept` call in the 1.12.7 renderer. The client can display `accepted: false`, but acceptance is not performed through a renderer API call. For Blackglass's first collaboration release, inviting an already-provisioned local account and returning `accepted: true` is the smallest complete behavior. Inviting an unknown address should fail clearly until an email-backed invitation/acceptance system exists; a permanently pending row is not a functional invitation.

The client does not send a vault role or fine-grained permission in any sharing request. Phase 4 should therefore implement the observed owner/collaborator model, not invent a UI-invisible role system:

- Owner: owns the remote vault and manages its membership and lifecycle.
- Collaborator: can connect, leave, and perform normal Sync data operations.

## Confirmed data-plane contract

The stock client uses the existing Blackglass WebSocket protocol operations:

- `init`
- `ping`
- `pull`
- `push`
- `history`
- `deleted`
- `restore`
- `purge`
- `size`
- `usernames`

Phase 3 and Phase 4 must preserve the established ready/version handshake, request/response ordering, binary upload/download framing, revision cursor behavior, deduplication, and server-pushed `push` notifications.

### Identity fields are functional, not decorative

The client actively uses identity metadata:

- `init` response `userId` becomes the connected user's numeric identity.
- Revisions and pushed changes may contain numeric `user`.
- `usernames` returns a map keyed by numeric user ID.
- The recent-changes view uses `user` plus `userId` to hide the current user's own changes.
- The changes UI uses `usernames` to attribute revisions.

Phase 3 must therefore replace the current constant user identity with the authenticated session's durable numeric user ID. Phase 4 must return only the identities needed to render history for the authorized vault, including retained attribution for revisions written by a former collaborator.

### Shared-vault data permissions

There is no role or permission field in the WebSocket handshake or operations. Once authorized to a shared vault, the stock client can issue the same normal Sync operations as an owner client, including write, history, deleted-item, restore, purge, and size operations. Blackglass must either support those semantics for collaborators or deliberately reject and qualify each incompatible operation; silently relying on the UI is not authorization.

For the first compatible Phase 4 release, collaborators should have normal content synchronization permissions. Owner-only restrictions should apply to control-plane ownership, membership, migration, rename, and delete actions.

## Encryption behavior the server must preserve

The server remains an opaque-data service. It must never receive or log a custom end-to-end encryption password or plaintext vault content.

For an end-to-end encrypted shared vault, collaborators must separately know the same encryption password. Obsidian's public collaboration documentation tells owners to share that password out of band. The membership API does not transport it.

For server-managed encryption, the shared vault descriptor must provide the same managed-encryption metadata that an authorized client needs to connect. This behavior must be verified with a synthetic shared vault before Phase 4 is accepted.

Revocation is an authorization event, not retroactive erasure. Removing a collaborator can stop future server access and disconnect active sessions, but cannot erase data already synchronized to that person's device or revoke an encryption password they already know. Restoring confidentiality after a compromise requires a new key and complete re-encryption into a new remote vault; the 1.12.7 sharing contract has no member-specific key wrapping or transparent key rotation.

## Confirmed client-visible owner/collaborator behavior

The 1.12.7 renderer distinguishes the two categories returned by `/vault/list`:

- Owned vault: may be deleted, renamed, connected, and have sharing managed.
- Shared vault: may be connected/disconnected and left with its `share_uid`.

The manage-sharing screen:

- loads `shares` from `/vault/share/list`;
- renders name and email;
- labels an unaccepted share as pending;
- invites by email;
- removes by share UID.

Obsidian's public documentation additionally states that only the owner can invite or remove participants, collaborators need their own Sync subscription, shared vaults do not count against the collaborator's remote-vault limit, and the documented maximum is 20 collaborators. Blackglass can satisfy the subscription check with its self-hosted entitlement response, but should enforce the observed ownership boundary and a bounded membership limit.

## What is not demanded by this client

The following are not present in the 1.12.7 Sync sharing contract and must not be presented as client requirements:

- fine-grained read/write/admin roles;
- group or organization membership;
- per-file ACLs;
- member-specific encryption keys;
- an in-client invitation-accept endpoint;
- transparent key rotation on revocation;
- multiple simultaneously signed-in accounts in one Obsidian profile;
- a general feature-negotiation endpoint for server sharing capabilities.

These could be future Blackglass product features, but adding them must not weaken the stock-client boundary or imply client enforcement that does not exist.

## Runtime validation still required

Static inspection establishes request fields and response fields the renderer consumes. It does not replace exact-client end-to-end qualification. The staged releases have staged gates:

- Phase 3 must pass scenarios 1-3, the tenant-isolation portions of 11, and the user/session/restart/migration portions of 12 before its schema or authorization change is deployed.
- Phase 4 must pass the complete 1-12 suite before its membership schema or sharing authorization change is deployed.

Use an isolated test environment with the exact qualified client artifact to prove:

1. Two separately provisioned users can sign in from separate copied Obsidian profiles.
2. Each Phase 3 user sees and accesses only their own vaults.
3. A guessed vault ID, share UID, revision UID, or session token never crosses the authorization boundary.
4. An owner invitation for an existing account appears under the recipient's `shared` list with a usable `share_uid`.
5. The recipient connects with the correct E2EE password and cannot connect with the wrong password.
6. Owner and collaborator synchronize both directions and receive each other's live pushes.
7. Revision attribution and the **hide my changes** behavior use distinct user IDs and names correctly.
8. Collaborator history, deleted-item, restore, purge, file upload, file download, interrupted transfer, and reconnect paths behave as the client expects.
9. Owner removal and collaborator self-leave terminate active access, abort staged transfers, and reject subsequent control and data operations.
10. Rename, migration, and delete preserve owner-only lifecycle rules and leave clients in an understandable state.
11. A third, unrelated user cannot infer vault or membership existence through statuses, error payloads, timing, counters, events, or admin projections.
12. Restart, migration, session expiry, password reset, user disablement, and membership changes preserve the same boundaries.

Phase-scoped production deployment is allowed only after the applicable gate above passes against a disposable database and temporary vaults.