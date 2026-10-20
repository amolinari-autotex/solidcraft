# Negotiated PDM user administration

The native server and client share one server-enforced administration API.
Ordinary document RPC remains `solidcraft-pdm/2` at `/pdm/v2/rpc`; no new request
variant is added to that enum. All extension calls require the existing configured
bearer over verified HTTPS and the pinned server identity.

1. POST `/pdm/v1/capabilities` with
   `{"protocol":"solidcraft-pdm-capabilities/1","server_id":"..."}`.
2. Inspect server `features.users_admin_v1` and actual account `permissions`.
   JSON-generation stores advertise no administration support; no request migrates
   them. An older server's 404 means unavailable, preserving ordinary PDM use.
3. POST `/pdm/v1/admin` with protocol `solidcraft-pdm-admin/1`, server_id and request.

The exact request/response grammar is in
[pdm-admin-api.schema.json](pdm-admin-api.schema.json). Native helpers are
`Client::capabilities()` and `Client::admin(AdminRequest)`. Direct HTTPS is supported;
relay administration requires its own future negotiation and never falls back to
an unverified route. The extension body limit is 64 KiB, while responses remain
bounded by the existing 8 MiB transport frame limit, including escaped audit pages.

Administrators can list accounts, create users, change one of the three fixed
roles, enable/disable accounts, replace credential verifiers and page successful
audit events. Viewer and contributor requests receive HTTP 403. Unknown, replaced
or disabled credentials receive 401; changes apply to the next request, including
ordinary document RPC and existing HTTPS connections. Names never confer a role.

Mutations require a unique request_id and expected_revision from list_users.
Revisions change for effective administration changes; document writes do not
change them. Exact retries by the same currently authorized administrator return
the original public receipt. A no-op stores a durable receipt and user.noop audit
event, preserving its meaning after later changes without advancing admin revision.
There are at most 64 accounts and 256 administration retry receipts, plus existing
prototype metadata quotas. Disabled accounts still reserve their ID and verifier.

New IDs use lowercase ASCII letters, digits, hyphen or underscore, at most 64
bytes; owner is reserved. Existing imported account labels up to 128 UTF-8 bytes
without controls remain valid mutation targets and public summaries. Verifiers
are unique lowercase SHA-256 digests. The native caller generates a fresh 32-byte
OS-random bearer and captures it in private credential storage before sending its
verifier. The server never returns the bearer or verifier. Account creation alone
does not enroll another device or deliver credentials to a remote user.

The last enabled administrator cannot be disabled/demoted. Acting administrators
cannot disable/demote themselves or replace their own credential; the last-admin
error takes precedence when both protections apply. Fixed effective permissions
are returned for display; disabled accounts have none. Per-document ACLs and
custom permission overrides are not implemented.

Credential/role/disabled state, admin revision, retry receipt and successful audit
change share one redb transaction. Live credential authority updates only after
commit. The optional administration section preserves checksums of older imported
images when absent. Logical backup/restore preserves this section and audit; older
server binaries fail closed on unsupported image fields. Audit responses omit
state hashes, credentials and physical server paths. Audit is successful managed
transitions, not a denied-access log or tamper-proof ledger.

Error codes distinguish invalid input/protocol (400), unauthorized (401), forbidden
(403), not_found (404), conflicts/protection/quota/capability errors (409), and
storage_error (503). Stable codes are listed in the schema. Native callers must
retain the exact pending request and private credential capture after uncertain
transport outcomes, retry it unchanged and never issue a second credential reset
just to discover whether the first succeeded.
