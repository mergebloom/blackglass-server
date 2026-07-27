# Security policy

Do not disclose credentials, bearer tokens, vault metadata, ciphertext, or a
working exploit in a public issue. Use the hosting provider's private
security-advisory channel when this repository is published.

Reports should include the affected version and binary SHA-256, deployment
shape, reproduction using disposable data, and impact. Remove production host
names, account identifiers, database contents, and logs containing user data.

The supported boundary and incident procedure are in
[`docs/security.md`](docs/security.md). Internet-exposed deployments without a
TLS reverse proxy, non-loopback application binds, and the Bun protocol oracle
are outside the supported production boundary.
