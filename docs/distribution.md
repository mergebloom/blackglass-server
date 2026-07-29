# Server builds and distribution

## Supported release matrix

Blackglass Server publishes two Linux binary targets and one multi-architecture
OCI image:

| Target | CPU | Linkage | Use it for |
| --- | --- | --- | --- |
| `linux-amd64` | x86-64 | static musl | Intel/AMD cloud VMs, servers, and NAS hosts |
| `linux-arm64` | AArch64 | static musl | Graviton, Ampere, ARM cloud VMs, and 64-bit ARM hosts |
| OCI image | amd64 + arm64 | scratch | Linux Docker with host networking and host Caddy |

The static binaries have no glibc, OpenSSL, or external SQLite dependency.
They are therefore the preferred distribution for Ubuntu, Debian, Fedora,
RHEL-family, Amazon Linux, Alpine, and other mainstream 64-bit Linux systems.
The host still needs a supported Linux kernel, local persistent storage, a TLS
reverse proxy, and an operator-managed backup destination.

Windows, FreeBSD, 32-bit Linux, and non-Linux container hosts are not qualified
production targets. The source continues to build natively on Apple Silicon
macOS for development and protocol testing, but the production operations and
hardening profile target Linux.

## Build locally

Requirements are Docker with Buildx, `jq`, standard Unix archive/file tools,
and enough disk for the pinned official Rust builder image. The host does not
need a Rust compiler. Build one architecture or both:

```sh
./ops/build-linux-release.sh linux-amd64
./ops/build-linux-release.sh linux-arm64
./ops/build-all-linux-releases.sh
```

Buildx executes each target architecture. During the image build, the exact
release binary runs its Rust tests, verifies its version, creates a disposable
SQLite database, starts both listeners, and passes `/health` and `/ready`.
After export, the verifier checks the archive checksum, exact allow-listed file
set, ELF architecture, static linkage, and every field and key in the embedded
manifest. For locally built, already-trusted artifacts on a matching Linux
architecture, the release pipeline explicitly compares the executable's
`--version` and `build-info` output with the manifest. The public verifier does
not execute an untrusted download. The separately emitted raw executable is
checksum-verified and must be byte-identical to the archive's executable. The
archive also carries the project license and generated third-party notices;
the same files are standalone GitHub release assets for raw-binary users. The
final scratch image is then
executed read-only, without Linux capabilities and with `no-new-privileges`, to
verify its CLI entry point. A second smoke starts it as its non-root runtime
identity with Linux host networking, loopback binding, the exact loopback
trusted proxy, read-only rootfs, 256 MiB memory and 64-PID limits, and proves
the control health endpoint and data listener are reachable.

The package job then subjects the exact raw binary to the full protocol and
recovery workload in a server-only, no-swap 256 MiB cgroup. Publication requires
zero OOM events, a bounded process high-water measurement, an observed cgroup
high-water measurement, matching artifact and in-image hashes, and a graceful
exit.

The builder image is pinned by multi-platform manifest digest in
`ops/Dockerfile.release`; its added Alpine package closure, the Dockerfile
frontend, Buildx version, BuildKit driver image, and GitHub Actions are pinned
as well. Cargo uses the locked dependency graph. CI rejects known RustSec
advisories, unreviewed dependency licenses, and unknown dependency sources.
The audit binary itself is version- and checksum-pinned. The committed notice
is hash-bound to the Cargo graph and feature manifest plus the pinned Rust,
musl, SQLite, and release-builder inventory. Release
archives have sorted entries, normalized ownership and timestamps, and
timestamp-free gzip output. `sourceRevision` is always the full lowercase
40-character Git commit for the clean source checkout. Both native and Docker
release builders compile an immutable `git archive` of that commit rather than
the mutable worktree. The root package and lockfile versions and the Rust
package and lockfile versions must all match.

## Verify a downloaded binary or archive

Download an archive and its adjacent `.sha256`, then run:

```sh
shasum -a 256 -c blackglass-server-vVERSION-linux-ARCH.tar.gz.sha256
./ops/verify-linux-release.sh \
  linux-ARCH \
  blackglass-server-vVERSION-linux-ARCH.tar.gz
```

Use `verify-linux-release.sh` from the matching `vVERSION` source tag. The
verifier intentionally binds the archive to that release's pinned Rust
toolchain and builder image, so a verifier from a later tag may reject an older
valid artifact after those pins are advanced.

The raw `blackglass-server-vVERSION-linux-ARCH` asset has its own adjacent
checksum and is the same executable contained by the archive:

```sh
shasum -a 256 -c blackglass-server-vVERSION-linux-ARCH.sha256
chmod 0755 blackglass-server-vVERSION-linux-ARCH
```

For a tagged GitHub release, verify its build provenance with GitHub CLI:

```sh
gh attestation verify \
  blackglass-server-vVERSION-linux-ARCH \
  --repo OWNER/REPOSITORY
```

Do not use an archive whose filename, checksum, embedded `version`, target,
binary hash, or provenance does not match the intended release.
`verify-linux-release.sh` performs static checks by default; never opt into its
trusted-binary execution mode before provenance and source are independently
authenticated.

## Safe container deployment

The OCI image is intentionally a scratch image: it contains the server binary,
`/licenses/LICENSE`, `/licenses/THIRD_PARTY_NOTICES.md`, and an owned state
directory, runs as numeric uid/gid 65532, and has no shell or package manager.
Its writable state belongs at
`/var/lib/blackglass-server`.

The native binary and OCI image retain the safe loopback default. The qualified
Linux Docker topology uses host networking so a host Caddy process reaches the
same loopback listeners and is the server's one exact trusted proxy. There are
no published plaintext ports:

```sh
docker volume create blackglass-server-state
docker run -d \
  --name blackglass-server \
  --restart unless-stopped \
  --network host \
  --stop-timeout 30 \
  --read-only \
  --memory 256m \
  --pids-limit 64 \
  --ulimit nofile=4096:4096 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env-file /etc/blackglass-server/server.env \
  --env SELFHOST_BIND_HOST=127.0.0.1 \
  --env SELFHOST_TRUSTED_PROXY=127.0.0.1 \
  --mount type=volume,src=blackglass-server-state,dst=/var/lib/blackglass-server \
  ghcr.io/OWNER/REPOSITORY:VERSION
```

This mode is for a native Linux Docker host; Docker Desktop host networking is
not a qualified production target. Use the Caddy configuration and two
hostnames documented in [production operations](production.md). Caddy must
overwrite `X-Forwarded-For`; never append an untrusted incoming value.

Kubernetes is not release-qualified by this topology. An orchestrated
deployment must leave `SELFHOST_TRUSTED_PROXY` unset unless the ingress has one
stable, exclusive peer IP; an ingress fleet cannot be represented by this
exact-IP option. Apply ingress per-source sign-in limits and a NetworkPolicy,
and use `runAsUser`/`runAsGroup`/`fsGroup` 65532,
`fsGroupChangePolicy: OnRootMismatch`, `readOnlyRootFilesystem: true`, a 32 MiB
memory-backed `/tmp`, `terminationGracePeriodSeconds` of at least 30, a 256 MiB
memory limit, a 64-PID limit where supported, and a locally backed PVC with
verified ownership. Never expose the server through a public NodePort,
LoadBalancer, or direct host-wide bind. Qualify that exact ingress topology
before production use.

Pin production deployments to a version tag or, preferably, the published OCI
digest. `latest` is a convenience tag, not an upgrade policy. Back up and verify
SQLite before changing the digest, and retain the old image until the recovery
test passes.

## CI release behavior

The release workflow runs natively on GitHub-hosted Ubuntu amd64 and arm64
runners. A manual dispatch produces retained workflow artifacts. A tag that
exactly equals `v` plus the Cargo package version additionally:

1. creates a verified GitHub release with both archives, both raw binaries,
   their adjacent checksums, per-architecture resource reports, license
   notices, and `SHA256SUMS`;
2. publishes a multi-architecture image to GitHub Container Registry;
3. attaches signed build-provenance attestations to archives, raw binaries,
   resource reports, and the OCI digest.

All third-party workflow actions are pinned to reviewed commit hashes. The
workflow grants package/release write permissions only to the tag publishing
job.
