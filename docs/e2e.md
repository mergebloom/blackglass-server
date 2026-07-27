# macOS two-client E2E validation

## Qualification status

The client records below are historical protocol baselines produced before the
production executable and service identity became `blackglass-server`. They do
not qualify the current binary hash. Blackglass Bridge owns current packaged-
client qualification and records the exact server version, size, architecture,
and SHA-256 in every schema-2 report.

Status: **passed** against the Bun protocol oracle on 2026-07-25. A repeat
against the Rust production implementation is recorded below.

## Test boundary

- Official `/Applications/Obsidian.app` wrapper, installer version 1.9.12
- Obsidian renderer 1.12.7
- macOS Apple Silicon-capable application binary
- two simultaneous, isolated `--user-data-dir` profiles
- two isolated test vaults
- generated two-incision compatibility ASAR
- loopback control (`127.0.0.1:3000`) and data (`127.0.0.1:3003`) services
- installed application and normal Obsidian profile untouched

## Results

The built-in UI completed login, remote-vault creation, E2EE password setup,
connect/unlock, and Start syncing. Client B discovered the same Blackglass Server
remote vault and performed a fresh initial download.

| Direction | Bytes | SHA-256 | Result |
| --- | ---: | --- | --- |
| A -> B | 215 | `ddd170d7fe3661e2f87437cc65ce0bc07cd35db343f634c4fb1d5e23a470764b` | byte-identical |
| B -> A | 181 | `fbfe9cd22f8c16ce0a7e4f0f804b83caf9ab2943c55099ab2296123c47876548` | byte-identical |

Compatibility ASAR SHA-256:
`0a890c3cbd857f33269d8d957a32c72ea65fb8cc0d5435b67506c9817e89dc5a`.
The official upstream ASAR used to generate it had SHA-256
`2b2483b2e1246772e0d25367ec055cbc5047ea2f0091b667c35656678f86d712`.

The final database contained five revisions and 1,236 encrypted payload bytes.
The verifier found neither complete proof note as plaintext in any stored
payload. This check demonstrates the observed E2EE path; it is not a formal
cryptographic audit.

The native Sync screen reported “Obsidian Sync is currently running,” showed
both note names, and displayed the connected `E2E Vault`. The native Deleted
files screen also loaded successfully and reported zero files.

Machine-readable evidence is in the ignored local run directory at
`.data/e2e/run-20260725-2/report.json`; screenshots are listed in that report.
Re-run the deterministic checks with:

```sh
bun run e2e:verify -- .data/e2e/run-20260725-2
```

Protocol/unit validation finished with 13 passing tests and 90 assertions.

## Pre-Blackglass Rust implementation E2E (2026-07-26)

Status: **historical baseline passed** against the pre-brand Rust binary. The built-in 1.12.7
UI completed local-server login, creation of a `Blackglass Server` E2EE remote vault,
connect/unlock, background upload, clean-client recovery, and automatic
reconnect after a graceful server restart. The release binary is arm64,
3,813,088 bytes, and has SHA-256
`98d692f272b112f10742e70429bb254ceb95bbc6c6be450b24388a8f65f76970`.

Disposable client A uploaded a mixed vault plus a note authored through the
visible editor after Sync first reported `Fully synced`. Its local profile was
then stopped and moved out of the run into a recoverable sibling quarantine.
Only after that source removal, a new empty profile logged in, selected the
server-held vault, unlocked it, and recovered all content. Obsidian's own
attachment switches explicitly require a restart; the run enabled them,
restarted each isolated client, and verified PNG, SVG, PDF, Canvas, CSV, JSON,
JavaScript, and Markdown recovery.

The final manifest contained 17 files. The verifier reported 17 restored,
zero missing, zero unexpected, and zero changed files, with client A absent
from the run. SQLite contained 41 revisions and 13,954 ciphertext bytes in the
external content table, zero legacy inline payloads, and zero matches for the
five plaintext proof markers. Migrations 1 and 2 were present, the database
mode was `0600`, and the upload directory mode was `0700`.

After rebuilding and gracefully restarting the exact release binary, the
connected client returned from `Connecting to server` to `Fully synced`
without intervention. A new post-restart note then produced one upload on one
client and one download on the other. Final metrics reported two WebSocket
connections, one upload, one download, and zero errors. `/health` identified
the Rust implementation and `/ready` returned success.

The content-bearing SQLite backup was a single `0600` file with no WAL/SHM
sidecars; it was verified and restored into a disposable database successfully.
The 64 MiB release resource gate passed with a 6.64 MiB RSS increase and an
empty staging directory after commit.

Machine-readable evidence is in the ignored run directory at
`.data/e2e/run-rust-production-20260726-1/official-client-report.json`, with the
manifest, recovery report, backup, and eight native screenshots beside it. The
final automated suite contains 22 passing tests and 182 assertions.

## Exact release-image verification

The supplied GitHub DMG was downloaded separately. Its SHA-256
`3b85c13b4ce55512e86e170a7cd2a494e2db695ac888c0601e153cb85b77881b`
matched GitHub's published asset digest, and `hdiutil` verified the image CRC.
Its application executable is universal with an arm64 slice. Its embedded
`obsidian.asar` hash is exactly the upstream renderer hash above.

The copied-app packager replaced that embedded ASAR, preserved version 1.12.7,
ad-hoc signed the copy, and passed strict deep `codesign` verification. A normal
Obsidian process was already active on this host, so the newer wrapper did not
create a second isolated renderer; that user process was intentionally not
terminated. Therefore the bidirectional UI E2E result above is specifically
the installed universal wrapper loading the byte-identical official 1.12.7
renderer, while the clean-DMG packaging path is hash/signature verified rather
than separately UI-tested in this run.

## Repeat the full run

1. Generate the adapter with `patch:client` and the loopback endpoints.
2. Create a new ignored run directory with `e2e:prepare`.
3. Start its server with `e2e:server`.
4. Launch the official app twice with the two generated `user-data` directories
   and distinct debugging ports.
5. In the built-in UI, client A logs in, creates an E2EE remote vault, connects,
   unlocks, and starts Sync. Client B logs in, chooses the vault, unlocks, and
   starts Sync.
6. Create one unique proof note in each local vault and require the counterpart
   to become byte-identical.
7. Capture native Sync/Deleted files screens and run `e2e:verify`.

## Destructive recovery drill

The ignored run directory `.data/e2e/run-recovery-20260725-1` records a
full source-loss recovery test. Disposable client A uploaded a 14-file vault
containing seven Markdown notes, PNG and SVG images, PDF, Canvas, CSV, JSON,
and JavaScript files. One note was authored in the visible Obsidian editor
after Sync had already reached `Fully synced`; the server advanced without a
manual upload or retry action.

After the server reached 28 revisions and 12,739 encrypted payload bytes,
client A's isolated profile and vault directory were permanently removed.
A separately identified, empty client B profile then connected to the same
self-hosted remote vault and restored all 14 files. The recovery verifier found
no missing, unexpected, or changed files, and every restored SHA-256 digest and
byte size matched the source manifest.

The reusable fixture and verifier commands are:

```sh
bun run recovery:drill -- create <source-vault>
bun run recovery:drill -- capture <run-root> <source-vault>
bun run recovery:drill -- verify <run-root> <restored-vault>
```

Machine-readable evidence is in `recovery-manifest.json` and
`recovery-report.json` under the run directory. The client A editor proof and
client B restored Home/Gallery screenshots are stored alongside them.
