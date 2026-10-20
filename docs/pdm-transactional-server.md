# Transactional metadata server evaluation

This is an explicit single-node prototype built on the optional managed PDM
workflow. It does not enable PDM during normal application startup, expose a LAN
listener, configure a provider, install a system service or migrate an existing
archive automatically.

## Import a disposable archive

Stop the owner of a disposable source store, then create a verified backup and
restore it into a new destination:

```text
solidcraft-pdm backup SOURCE NEW_BACKUP
solidcraft-pdm restore-redb NEW_BACKUP NEW_DATABASE_STORE
solidcraft-pdm rehearse-https ABSOLUTE_DEPLOYMENT_CONFIG
```

The source and backup remain unchanged. Existing destinations are refused. The
new store uses `managed/metadata.redb`; ordinary `Store::open` detects this format
on subsequent starts. Generation 4097 is a downgrade fence: older JSON-only
servers fail instead of reading the retained seed generations. Do not remove the
fence, database or an interrupted-conversion marker to attempt recovery. Restore
the verified backup into another new path instead.

The deployment configuration retains its existing fields: absolute store,
loopback bind, certificate chain DER paths and private key DER path. Readiness
contains the server identity and bound address. Send `shutdown` on the owned
stdin or close stdin to stop only this service. HTTPS authentication requires
configured principals, never an environment-owner fallback.

## Transactions and authority

redb 4.4.0 is pinned to the native service package. Its MIT OR Apache-2.0 licensing
and Rust 1.90 minimum are compatible with the repository's Rust 1.95 requirement.
The optional runtime dependencies are disabled by default; the Windows build adds
only redb itself to the lockfile. On supported Unix targets redb uses libc for OS
interfaces; the database engine is Rust, without a C database runtime. See the
[redb manifest](https://github.com/cberner/redb/blob/v4.4.0/Cargo.toml) and
[transaction API](https://docs.rs/redb/4.4.0/redb/).

The first adapter deliberately stores a bounded serialized aggregate in one redb
record. A write transaction atomically replaces heads, immutable versions, pinned
references, checkout capabilities, retry receipts, imported credential hashes and
an audit event. Immediate durability is requested. State is validated before the
transaction and memory changes only after commit. The previous generation is
checked inside the write transaction. Blob bytes are verified and stored
separately before metadata publication; a failed transaction can leave an
unreferenced blob but cannot publish a partial head or release the checkout.

The existing `solidcraft-pdm/2` RPC API and `/pdm/v2/rpc` path are unchanged.
Import preserves server identity, exact version references and checkout grants.
Credentials are imported into the database and become its authority; editing the
retained `managed-principals.json` does not change database accounts or roles.
There is no user/role mutation API in this increment. Such an API needs explicit
capability negotiation and coordinated client work. Audit covers successful
post-import create/checkout/cancel/check-in operations; it does not reconstruct
historical activity, log denied requests or claim tamper-proof storage.

## Backup and restore

The existing backup command exports a committed logical
`managed/metadata-snapshot.json`, together with verified content-addressed blob
files and any legacy immutable version files. It never copies an open database
file. The exclusive store lock and immutable borrow cover the complete snapshot.
Database snapshots include credential hashes and checkout capabilities and must
be kept private. Existing private-directory and host-account assumptions apply;
this increment adds no Windows ACL hardening.

`verify-backup` checks the file manifest and hashes. `restore` reconstructs the
database from its validated logical image in a new directory, then validates the
domain and referenced blobs. Audit and imported roles survive the roundtrip.
Older binaries reject these extended backups. JSON-only backups and stores retain
their existing behavior unless `restore-redb` is explicitly selected.

## Boundaries

The aggregate retains the prototype's 256-version, 64 MiB content and 4096
generation limits, plus 4 MiB state and 8 MiB logical-image bounds. It rewrites the
bounded aggregate and audit; no secondary-index scaling or physical database-size
benchmark is claimed. redb provides transaction recovery, but actual power-loss,
host-disk failure, adversarial host-account tampering and filesystem certification
remain untested. Legacy non-managed documents still use their existing immutable
directory storage; their check-ins do not enter the managed transaction/audit.

The `redb_demo` example and standalone launcher use public test credentials and
test TLS keys on an ephemeral loopback port. They create a text payload, not a CAD
design, and must never be used for private documents. Future local/LAN, outbound
relay and hosted modes need their own operational validation; no public account,
provisioning, installer, relay or provider expansion is included here.
