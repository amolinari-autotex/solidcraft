# Bounded managed binary transfers

New native-console archives enable a persisted, versioned storage policy. The
creation form defaults to 512 MiB per incoming file and 20 GiB of unique blob
storage; both values are configurable before creation. Hard parser/storage guards
are 8 GiB per file and 16 TiB per archive. These are validation ceilings, not
benchmarked capacity claims. Existing installations are never upgraded in place.
The explicit backend initializer accepts only an empty transactional filesystem
archive, and preserves an incomplete-operation fence on failure.

The separate authenticated `POST /pdm/v2/capabilities` route negotiates
`solidcraft-pdm-capabilities/2`. `Client::transfer_capabilities()` returns `None`
for a legacy 404 without losing the authenticated identity. Strict v1 capability
and existing RPC schemas remain unchanged. Inline content stays limited to 1 MiB;
a large inline download returns `transfer_required` rather than a large JSON array.

`TransferInput` binds server identity, recovery epoch, request ID, declared total
and full SHA256, pinned dependencies and comment. `TransferTarget::NewOnly`
contains a portable logical path; `CheckIn` contains the stable document ID,
workspace/machine, checkout capability and expected parent. Request Debug output
does not expose credentials. Server retry fingerprints exclude the checkout
capability. The durable record stores only its verifier.

The direct verified-HTTPS SDK provides `begin_transfer`, `transfer_status`,
`upload_chunk`, `commit_transfer`, `cancel_transfer` and `download_stream`.
Uploads send raw chunks of at most 1 MiB to
`PUT /pdm/v1/transfers/{id}/chunks/{offset}`. Control JSON is bounded to 64 KiB.
Every operation uses a bearer header, pinned server ID and recovery epoch;
neither transfer IDs nor URLs grant authority. The listener bounds connections,
TLS/header/body deadlines and parser sizes. Before body polling or `100 Continue`,
admission authenticates the current account and checks the operation's role,
epoch and document/lease where known. At most two transfer bodies globally and
one per principal are admitted. The serialized writer rechecks authorization
and document fences before accepting each chunk or publishing a version.

Content paths use server-generated opaque IDs in a private staging root. The
durable staging ledger alternates two bounded, checksummed, fsynced slots under
an exclusive process lock. Acknowledged offsets follow content fsync; startup
truncates only an unacknowledged tail. Exact last-chunk retries retain the offset;
other offset/digest substitutions fail. Seal verifies the complete length/hash
with a 64 KiB buffer. Durable publication and cancellation intents cover crashes
before and after hard-link publication. Bounded reconciliation with authoritative
redb records reclaims undisclosed allocations and completes known handoffs.
Uncertain sealed bytes remain charged until a durable commit or cancel decision.

NewOnly creates no visible document until verified content and one redb
transaction publish its ID, version, head, receipt and audit. Concurrent case-folded
paths yield one winner. CheckIn consumes only the current owner's exact lease and
parent. Retry returns one existing version; an uncertain client must retain its
request/journal and query the same transfer, never fall back to an unguarded create.
Blob quotas count unique committed content, published orphans and pending files;
staging reserves full declared incoming bytes separately. Inline writers respect
those outstanding reservations. Version-byte metadata is a separate counter.

Downloads obtain immutable version metadata and bounded raw ranges. The SDK
checks each range's offset, length and digest and incrementally checks the full
file SHA256. It writes to caller-owned NEW private staging; only full success
authorizes atomic working-copy publication. The fixed hard read ceiling is
separate from the current incoming-file policy, preserving retained versions
under a later lower write policy. Native workspace journaling/integration is
owned by the client application; this backend commit alone does not update its UI.

Backup/2 streams hashes/copies and includes the exact storage policy and portable
committed metadata snapshot. It excludes active staging bytes. Restore verifies
all files into a NEW destination, rebuilds redb and rotates the recovery epoch;
old transfer sessions are invalidated. Preserve uncertain client journals across
restore and reconcile against catalog/history before any new write. Legacy
backup/1 remains readable and retains its existing bounds.

Focused synthetic tests cover real pinned HTTPS beyond 1 MiB, restart/resume,
chunk and commit retry, digest/offset rejection, principal/role/credential changes,
lease cancellation, case-folded winner conflicts, exact policy limit and limit+1,
pre-body admission, untrusted CA/hostname/server pin, cancellation/ledger abort,
publication and deletion crash boundaries, backup/restore and retained read
compatibility. A generated 64 MiB source verifies fixed-buffer reads without a
file-sized allocation. No measured process-RSS ceiling, power-loss certification,
remote deployment, public listener, tunnel or cloud service is claimed. TLS trust
remains explicitly provisioned; there is no invalid-certificate or plaintext
fallback. Existing configured bearer revocation is enforced; short-lived token
issuance/expiry is a separate enrollment feature.
