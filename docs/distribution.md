# Server builds and distribution

## Supported release matrix

Blackglass Server publishes two Linux binary targets and one multi-architecture
OCI image:

| Target | CPU | Linkage | Use it for |
| --- | --- | --- | --- |
| `linux-amd64` | x86-64 | static musl | Intel/AMD cloud VMs, servers, and NAS hosts |
| `linux-arm64` | AArch64 | static musl | Graviton, Ampere, ARM cloud VMs, and 64-bit ARM hosts |
| OCI image | amd64 + arm64 | scratch | Private Docker bridge or Kubernetes Pod networks |

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
manifest. The separately emitted raw executable is checksum-verified and must
be byte-identical to the archive's executable. The final scratch image is then
executed read-only, without Linux capabilities and with `no-new-privileges`, to
verify its CLI entry point. A second smoke starts it as its non-root runtime
identity on a standard bridge, publishes both ports to host loopback, and
proves the control health endpoint and data listener are reachable.

The builder image is pinned by multi-platform manifest digest in
`ops/Dockerfile.release`. Cargo uses the locked dependency graph. Release
archives have sorted entries, normalized ownership and timestamps, and
timestamp-free gzip output. `sourceRevision` is the current Git commit when one
is available or the explicitly supplied `SOURCE_REVISION` value.

## Verify a downloaded binary or archive

Download an archive and its adjacent `.sha256`, then run:

```sh
shasum -a 256 -c blackglass-server-vVERSION-linux-ARCH.tar.gz.sha256
./ops/verify-linux-release.sh \
  linux-ARCH \
  blackglass-server-vVERSION-linux-ARCH.tar.gz
```

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

## Safe container deployment

The OCI image is intentionally a scratch image: it contains the server binary
and an owned state directory, runs as numeric uid/gid 65532, and has no shell
or package manager. Its writable state belongs at
`/var/lib/blackglass-server`.

Native installs retain the safe loopback default. The OCI image alone sets
`SELFHOST_BIND_HOST=0.0.0.0` together with the required
`SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND=1`, because bridge and Pod networking must
reach the process. Both plaintext ports must remain private; only the TLS proxy
or ingress may face clients. A Docker deployment can publish them to host
loopback for a host TLS proxy:

```sh
docker volume create blackglass-server-state
docker run -d \
  --name blackglass-server \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env-file /etc/blackglass-server/server.env \
  --env SELFHOST_BIND_HOST=0.0.0.0 \
  --env SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND=1 \
  --publish 127.0.0.1:3000:3000 \
  --publish 127.0.0.1:3003:3003 \
  --mount type=volume,src=blackglass-server-state,dst=/var/lib/blackglass-server \
  ghcr.io/OWNER/REPOSITORY:VERSION
```

The explicit environment overrides are needed when the host-oriented env file
contains `SELFHOST_BIND_HOST=127.0.0.1`. Use the same Caddy configuration and
two hostnames documented in [production operations](production.md). In
Kubernetes, use a ClusterIP Service, WebSocket-capable TLS Ingress, and a
NetworkPolicy that permits these ports only from the ingress controller. Do
not expose either port through a public NodePort, LoadBalancer, or direct
host-wide bind.

Pin production deployments to a version tag or, preferably, the published OCI
digest. `latest` is a convenience tag, not an upgrade policy. Back up and verify
SQLite before changing the digest, and retain the old image until the recovery
test passes.

## CI release behavior

The release workflow runs natively on GitHub-hosted Ubuntu amd64 and arm64
runners. A manual dispatch produces retained workflow artifacts. A tag that
exactly equals `v` plus the Cargo package version additionally:

1. creates an immutable GitHub release with both archives, both raw binaries,
   their adjacent checksums, and `SHA256SUMS`;
2. publishes a multi-architecture image to GitHub Container Registry;
3. attaches signed build-provenance attestations to archives, raw binaries,
   and the OCI digest.

All third-party workflow actions are pinned to reviewed commit hashes. The
workflow grants package/release write permissions only to the tag publishing
job.
