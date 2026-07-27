# Server builds and distribution

## Supported release matrix

Blackglass Server publishes two Linux binary targets and one multi-architecture
OCI image:

| Target | CPU | Linkage | Use it for |
| --- | --- | --- | --- |
| `linux-amd64` | x86-64 | static musl | Intel/AMD cloud VMs, servers, and NAS hosts |
| `linux-arm64` | AArch64 | static musl | Graviton, Ampere, ARM cloud VMs, and 64-bit ARM hosts |
| OCI image | amd64 + arm64 | scratch | Container-managed Linux hosts using host networking |

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

Requirements are Docker with Buildx, standard Unix archive/file tools, and
enough disk for the pinned official Rust builder image. The host does not need
a Rust compiler. Build one architecture or both:

```sh
./ops/build-linux-release.sh linux-amd64
./ops/build-linux-release.sh linux-arm64
./ops/build-all-linux-releases.sh
```

Buildx executes each target architecture. During the image build, the exact
release binary runs its Rust tests, verifies its version, creates a disposable
SQLite database, starts both listeners, and passes `/health` and `/ready`.
After export, the verifier checks the archive checksum, exact allow-listed file
set, ELF architecture, static linkage, and the binary hash/size in the embedded
manifest. The final scratch image is then executed read-only, without Linux
capabilities and with `no-new-privileges`, to verify its CLI entry point. A
second smoke starts it as its non-root runtime identity with no external
network, confirms it can initialize the owned persistent volume, and observes
both listeners reaching the `server_started` state.

The builder image is pinned by multi-platform manifest digest in
`ops/Dockerfile.release`. Cargo uses the locked dependency graph. Release
archives have sorted entries, normalized ownership and timestamps, and
timestamp-free gzip output. `sourceRevision` is the current Git commit when one
is available or the explicitly supplied `SOURCE_REVISION` value.

## Verify a downloaded archive

Download an archive and its adjacent `.sha256`, then run:

```sh
shasum -a 256 -c blackglass-server-vVERSION-linux-ARCH.tar.gz.sha256
./ops/verify-linux-release.sh \
  linux-ARCH \
  blackglass-server-vVERSION-linux-ARCH.tar.gz
```

For a tagged GitHub release, verify its build provenance with GitHub CLI:

```sh
gh attestation verify \
  blackglass-server-vVERSION-linux-ARCH.tar.gz \
  --repo OWNER/REPOSITORY
```

Do not use an archive whose filename, checksum, embedded `version`, target,
binary hash, or provenance does not match the intended release.

## Safe container deployment

The OCI image is intentionally a scratch image: it contains the server binary
and an owned state directory, runs as numeric uid/gid 65532, and has no shell
or package manager. Its writable state belongs at
`/var/lib/blackglass-server`.

The server continues to reject non-loopback binds. On a Linux container host,
run it with host networking so the host TLS proxy can reach its loopback ports;
do not publish container ports:

```sh
docker volume create blackglass-server-state
docker run -d \
  --name blackglass-server \
  --restart unless-stopped \
  --network host \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env-file /etc/blackglass-server/server.env \
  --mount type=volume,src=blackglass-server-state,dst=/var/lib/blackglass-server \
  ghcr.io/OWNER/REPOSITORY:VERSION
```

Use the same Caddy configuration and two hostnames documented in
[production operations](production.md). Linux host networking is required by
this security model. Docker Desktop port publishing is not a supported
production substitute because it would require a non-loopback application
bind.

Pin production deployments to a version tag or, preferably, the published OCI
digest. `latest` is a convenience tag, not an upgrade policy. Back up and verify
SQLite before changing the digest, and retain the old image until the recovery
test passes.

## CI release behavior

The release workflow runs natively on GitHub-hosted Ubuntu amd64 and arm64
runners. A manual dispatch produces retained workflow artifacts. A tag that
exactly equals `v` plus the Cargo package version additionally:

1. creates or updates a GitHub release with both archives and `SHA256SUMS`;
2. publishes a multi-architecture image to GitHub Container Registry;
3. attaches signed build-provenance attestations to archives and the OCI
   digest.

All third-party workflow actions are pinned to reviewed commit hashes. The
workflow grants package/release write permissions only to the tag publishing
job.
