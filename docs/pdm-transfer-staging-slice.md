# Bounded transfer staging: first internal slice

`transfer_staging` stages raw bytes in a NEW private directory. It does not change
legacy file/frame limits or advertise a network capability. `Limits` validates
separate per-file, committed-plus-reserved archive and temporary quotas, writes
the chosen policy once and bounds active sessions. Callers supply trusted current
archive usage, identity, clock and an authorization callback on every operation.
The API itself does not authenticate remote callers.

`begin` reserves declared bytes. `chunk` requires a consecutive u64 offset, length
at most 1 MiB and lowercase SHA256. It uses a 64 KiB buffer, validates binding,
authorization, expiry and limits before reading, and restores the old length on
checksum/read/write failure. A failed rollback poisons the session. The last exact
offset/length/digest retry returns its previous next offset without rewriting.
A nonblocking per-stager mutex admits at most one body reader; HTTP process-wide
admission, deadlines and connection limits remain adapter requirements.

`seal` reauthorizes, streams the full length/hash and creates a new-only hard link
under the private sealed namespace. It is NOT a document/catalog publication.
If unlinking the redundant staging link fails, success explicitly reports
`staging_link_retained`; bytes remain charged and cannot be released by abort.
Sealed reservations are intentionally retained until a future transactional
handoff. `abort` removes only the owner's active staging file and reservation.

Sessions and their quota accounting are in memory. Existing roots are refused;
durable restart/resume, automatic expiry cleanup, policy loading/migration,
transactional blob/catalog handoff and receipt retry, bounded download/backup,
real HTTP/TLS authorization and advertised capabilities are NOT implemented.
The client streaming-source helper is separately frozen at `6bb3a77`; its u64
offset, 1 MiB chunk digest and full-file hash semantics agree with this API, but it
has not been linked to a network transfer pipeline.

Four focused tests cover a synthetic file larger than 1 MiB, exact chunk retry,
bad checksum rollback/retry, pre-body cross-principal/revocation/size/expiry
rejection, separate quotas, existing-root preservation and injected seal-unlink
failure. No user trial, industrial file or remote deployment was used. These
checks do not establish end-to-end remote security or measured process peak RAM.
