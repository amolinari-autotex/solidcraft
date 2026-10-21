# Managed rename and logical deletion

Namespace operations require transactional metadata and an authenticated
contributor or administrator. They preserve document IDs, immutable versions,
bytes and pinned references. No operation deletes blobs or changes a host path.

`Client::namespace_capabilities()` probes the separate authenticated
`/pdm/v1/namespace-capabilities` route using `solidcraft-pdm-namespace/1` and the
pinned server identity. Legacy route 404 returns `None`; a JSON-generation peer
reports unsupported. Authentication/transport failures remain errors. Existing
capabilities v1 responses retain their strict schema. Check `supported`,
`can_mutate` and `stable_materialization_paths` before enabling controls.

`namespace_catalog()` returns active `NamespaceMetadata` entries; `managed_metadata`
queries one stable ID, including a tombstone. Metadata contains `entry` (display
logical path), `materialization_path`, `revision` and `tombstoned`.

`managed_namespace(NamespaceMutation)` supplies document, unique request ID,
expected head and expected namespace revision. Its action is `Rename { logical_path }`
or `Tombstone`. Any active checkout, including the caller's, must first be resolved.
Stale head/revision, occupied/case-folded/ancestor paths return `conflict`; invalid
portable paths return `invalid_request`; insufficient role returns `forbidden`.

The first namespace mutation durably captures the original materialization path.
It never changes. Modern clients display `entry.logical_path` but materialize
files and historical dependency graphs at `materialization_path`. Legacy catalog,
create, checkout, resume and cancel responses retain that original path without
adding fields to `CatalogEntry`. Both current display names and immutable locators
remain reserved, including tombstones. An ordinary check-in always uses the known
document ID; never create a new identity because its display name changed.
No automatic rename, relink or deletion of a local working copy is authorized.

Deletion is a tombstone. ANY incoming reference from ANY retained managed or
legacy version blocks it with `referenced`, including historical references from
a tombstoned assembly. This conservative first policy deliberately retains all
exact versions. Tombstones disappear from active catalogs, reject new checkout,
path reuse and new dependency references, but remain queryable/downloadable by
exact ID/version. There is no purge or implicit restore operation.

The serialized writer commits state, per-document namespace revision, bounded
owner/payload retry receipt and audit event in one redb transaction. Audit subject
identifies the document; no physical paths or secrets are exposed. Exact retries
within the 256-receipt window return the original result, which may be historical:
refresh current metadata after acknowledgment. Evicted stale requests fail CAS
rather than repeating a mutation. Preserve an uncertain request ID/journal; never
fall back to filesystem operations or an unguarded create.

Focused verification covers role/lease/head/revision conflicts, retry, case-folded
collision/traversal, tombstone/path reservation, immutable history/references,
restart and backup/restore, real pinned HTTPS helpers/errors, a fresh materialized
workspace with the original relative reference, and a legacy TLS peer's 404 probe
without identity loss. No user archive or industrial file was used. Native menu
integration and its separate trial belong to the client owner.
