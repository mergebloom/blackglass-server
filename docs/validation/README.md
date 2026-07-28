# Validation records

Artifact qualification is generated for each tagged release rather than copied
into the source tree. Each Linux architecture publishes a resource report bound
to the exact binary SHA-256, target, and source revision. GitHub attestations
cover that report, the raw binary, archive, and OCI digest; `SHA256SUMS` covers
all downloadable release assets.

Before index publication, the release gate pulls each architecture digest,
verifies its runtime metadata without starting it, and byte-compares its
embedded server binary with the qualified raw release asset.

Rebuilding any binary invalidates its artifact-level qualification. Verify the
checksums, report binding, and provenance from the same release before deploy.
Reports must not contain credentials, absolute user paths, databases,
ciphertext, vault metadata, or proprietary client artifacts.
