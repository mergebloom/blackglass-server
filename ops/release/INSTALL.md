# Blackglass Server binary release

This archive contains a statically linked Linux binary. It does not require
glibc, SQLite, OpenSSL, or another shared userspace library.

Choose either the archive or the separately published raw binary. Verify its
adjacent checksum. Archives also carry `INSTALL.md`, `LICENSE`, and an embedded
manifest; both forms contain byte-identical executables. Install as root while
keeping the service process unprivileged:

```sh
sha256sum --check blackglass-server-vVERSION-linux-ARCH.tar.gz.sha256
tar -xzf blackglass-server-vVERSION-linux-ARCH.tar.gz
sudo install -d -m 0755 /opt/blackglass-server
sudo install -m 0755 \
  blackglass-server-vVERSION-linux-ARCH/blackglass-server \
  /opt/blackglass-server/blackglass-server
sudo install -m 0644 \
  blackglass-server-vVERSION-linux-ARCH/blackglass-server.sysusers.conf \
  /usr/lib/sysusers.d/blackglass-server.conf
sudo systemd-sysusers /usr/lib/sysusers.d/blackglass-server.conf
sudo install -d -o blackglass-server -g blackglass-server -m 0700 \
  /var/lib/blackglass-server
sudo install -m 0644 \
  blackglass-server-vVERSION-linux-ARCH/blackglass-server.service \
  /etc/systemd/system/blackglass-server.service
sudo install -d -m 0755 /etc/blackglass-server
sudo install -m 0600 \
  blackglass-server-vVERSION-linux-ARCH/blackglass-server.env.example \
  /etc/blackglass-server/server.env

# Or, for the raw release asset:
sha256sum --check blackglass-server-vVERSION-linux-ARCH.sha256
sudo install -m 0755 blackglass-server-vVERSION-linux-ARCH \
  /opt/blackglass-server/blackglass-server
```

The raw binary is intentionally separate from the service support files; use
the archive once to install the static service account, unit, and environment
template. Run offline restore and migration commands as `blackglass-server`,
not as root, so their mode-0600 output remains readable by the service.

Use `blackglass-server --version` to identify the installed build. Complete
configuration, systemd hardening, TLS proxy, backup, restore, upgrade, and
rollback instructions are maintained in `docs/production.md` in the source
repository.

Native service configuration and OCI images default to loopback. The supported
Linux Docker deployment uses host networking so host Caddy reaches loopback
without published plaintext ports. Never expose the control or data listeners
directly; follow the exact topology in `docs/distribution.md`.
