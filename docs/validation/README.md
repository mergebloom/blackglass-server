# Validation records

This directory contains sanitized release-gate results. Reports must identify
the exact production binary SHA-256 and must not contain credentials, absolute
user paths, databases, ciphertext, vault metadata, or proprietary client
artifacts.

Raw resource and recovery runs stay in ignored `.data/` storage. Rebuilding the
binary invalidates artifact-level qualification until the gates run again.

The Linux distribution matrix has a separate sanitized qualification record:
[`blackglass-server-0.2.0-linux-matrix.json`](blackglass-server-0.2.0-linux-matrix.json).
