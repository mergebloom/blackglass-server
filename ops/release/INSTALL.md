# Blackglass Server binary release

This archive contains a statically linked Linux binary. It does not require
glibc, SQLite, OpenSSL, or another shared userspace library.

Verify the adjacent archive checksum before extracting it, then inspect the
embedded `manifest.json`. Install the binary as root while keeping the service
process unprivileged:

```sh
sha256sum --check blackglass-server-vVERSION-linux-ARCH.tar.gz.sha256
tar -xzf blackglass-server-vVERSION-linux-ARCH.tar.gz
sudo install -d -m 0755 /opt/blackglass-server
sudo install -m 0755 \
  blackglass-server-vVERSION-linux-ARCH/blackglass-server \
  /opt/blackglass-server/blackglass-server
```

Use `blackglass-server --version` to identify the installed build. Complete
configuration, systemd hardening, TLS proxy, backup, restore, upgrade, and
rollback instructions are maintained in `docs/production.md` in the source
repository.

The service deliberately binds only to loopback. Do not publish its plaintext
control or data listeners; place the documented TLS reverse proxy in front.
