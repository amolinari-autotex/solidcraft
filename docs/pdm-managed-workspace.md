# Managed native workspace implementation

This draft extends the local service and native client in #3003. It remains a
loopback prototype for disposable designs. Existing stores, running applications,
and previously supplied trial binaries are not migrated or modified.

## Contracts

- The server owns stable document identities, logical paths, authenticated roles,
  exclusive persistent checkout reservations, and immutable published versions.
  User names supplied by clients never establish authority. Reservation secrets
  remain in the native adapter, outside commands, designs, status and logs.
- One normal workspace maps each document identity to one relative file path.
  Its private manifest records server/workspace identity, base version and hash.
  Unchecked files are read-only; only a successful server reservation enables
  managed saves. A separate Save As is an unmanaged copy.
  Save and export destinations share the same protected-path check, including
  equivalent paths, native hardlink aliases and explicit output formats.
  Multi-file exports preflight
  every destination, including stale animation frames to be removed, before
  their first write or deletion. Exporting to a separate file does not detach
  a historical design from its read-only state.
  A session-long ledger retains known managed paths and historical dependency
  destinations across tab changes, disconnects and workspace switches. A checkout
  in an inactive workspace requires verified reconnection before further saves;
  its server reservation is retained. The ledger holds at most 8,192 paths of
  4,096 bytes each. Conflicting identities or exhaustion disable further PDM
  operations and file outputs until restart rather than discarding protection.
- Local Save does not publish. Check In validates the saved native document,
  reservation, expected base and actual dependency versions; durable publication
  precedes reservation release. A repeated operation returns its original result.
  Lost responses and failed operations preserve local work and recoverable state.
- Refresh Status never replaces local files. Get Latest validates the entire
  requested update and refuses dirty overwrite before installing and reloading.
  Cancel Checkout explicitly restores the archived bytes and preserves a local
  recovery copy before discarding edits. Reservations do not expire silently.
- Working assemblies reference component identity/current workspace copies.
  Local component changes propagate through the CAD update operation without
  requiring publication. Remote publication requires controlled retrieval and
  reload. Each archived assembly records the versions actually consumed, even
  when a component is behind the server head. Open As Archived uses a separate
  exact-version snapshot and never changes normal workspace files.
- Restore as New Version requires an explicit confirmation and a clean local
  copy at the current head. It publishes the selected file's historical bytes
  and dependency references as a new head with the current head as parent,
  preserving earlier versions and the normal workspace path. It does not roll
  back other component files. Receipt reconciliation prevents an acknowledged
  restore from creating another version when retried.
  While the restore is in flight, editors sharing the managed runtime cannot
  modify designs or write managed destinations. Completion clears temporary
  RAM-edit permissions before reloading the restored normal tab.

## Interaction state and explorer redesign (draft)

This interaction increment is not accepted until its integrated tests and native
visual review complete. Earlier historical-restore trials are preserved as
immutable reproductions and do not establish acceptance of the redesigned UI.

The native worker combines authenticated server metadata, workspace identity,
manifest base/hash and a verified reservation capability. The UI reads that
snapshot; optimistic button changes never grant checkout or publication rights.
A shared action policy drives the explorer, active-file ribbon and menus. The
engine, native adapter and server validate again before side effects, including
when a caller bypasses a disabled button.

| State | Extract / Check Out | Publish / Check In | Undo Checkout | Get Latest |
| --- | --- | --- | --- | --- |
| Disconnected, unavailable, or request pending | Disabled | Disabled | Disabled | Disabled |
| No file selected | Disabled | Only explicit first publication of a saved unmanaged active design | Disabled | Disabled |
| Unmanaged saved native design inside the working folder | Disabled | Explicit first publication | Disabled | Disabled |
| Archived, clean and current | Enabled for a writable role | Disabled; checkout required | Disabled | Disabled when the required graph is current |
| Authenticated checkout here, matching workspace and base | Disabled; already extracted | Enabled; pending memory edits are saved before publication | Enabled with explicit discard confirmation | Disabled |
| Verified checkout here whose download failed before manifest installation | Disabled | Disabled | Release only, with explicit no-local-file-replacement confirmation | Disabled |
| Checkout in another workspace/device, or owned by someone else | Disabled with owner/workspace explanation | Disabled | Disabled | Disabled |
| Locally modified without valid checkout, or stale base | Disabled with reconciliation guidance | Disabled | Only an authentic owned checkout can be released | Disabled until local changes are preserved |
| Clean local copy behind the server | Enabled with fresh authority and installation checks | Disabled | Disabled | Enabled with complete dependency preflight |

Historical opening requires a real selected version and read access. Restore
requires a writable role, a clean current working copy, no conflicting checkout
and a selected older version, plus explicit confirmation. Lost-acknowledgement
publication receipts are reconciled before requesting any new reservation;
reconciliation never authorizes a new publication using stale rights.
The explicit `pdm.archive {reconcile:true}` retry verifies an existing receipt
only: it cannot create a document, acquire a checkout or publish new content.
An uncertain previous result requires a fresh status check before another
mutating action. Background Save/Save As workers preserve the exact shared PDM
runtime, historical flag and editor recovery epoch; creating a scratch save
snapshot cannot detach a managed destination or renew a stale editor.
An incomplete checkout is recoverable only when an authenticated resume verifies
the exact cached native grant against the current account, workspace and device.
The public status exposes document identities, never reservation secrets. This
proof permits release alone and cannot authorize publication. A genuinely missing
clean working file can be installed again at its original path; permission errors,
directories, links and reparse points never count as missing files.

The explorer separates folders, files and lower detail tabs. It uses the existing
semantic theme tokens and original icon library, resizable panes and columns,
search, sorting, breadcrumbs and text alongside status badges. Real embedded
version thumbnails load asynchronously through the same single-flight worker;
a bounded cache keys them by immutable document/version/hash. Missing previews
remain explicit. A captured operation target keeps success/error feedback tied
to the file acted on, even if selection changes before the response. Background
refreshes and previews do not replace the last user-operation result.

The central list groups immediate subfolders before immediate files, including
when filtering by name. A folder selection clears file/version actions; double
click enters it and synchronizes the tree and breadcrumb. Double-clicking a file
uses the guarded normal working-copy Open command, without acquiring a checkout.
Only a successful load activates its existing or new document tab and enters
DESIGN. History sorts by numeric version descending; selection and restore
confirmation retain the exact document/version identity when a new head arrives.

The PDM ribbon places original large icons above their labels in whole clickable
buttons, with horizontal scrolling when necessary. Connect is disabled while
pending or already connected; Disconnect is separate. The engine also rejects
duplicate connection mutations. A failed operation that retains its verified
connection does not enable Connect; a real disconnection permits reconnecting.

PDM is optional. A clean native startup constructs only an inert callback and
controller: it does not start a PDM worker/service, inspect an archive, read OS
credentials, log in, or make PDM network requests. The document tab appears only
after an explicit choice of PDM from Home or the workspace selector. Standard
local designs can be edited, saved and reopened without configuring PDM. Saved
connections are reopened only by an explicit action; the disposable trial launcher
performs that action for its own separate profile. An active PDM connection polls
status every ten seconds and keeps bounded metadata/thumbnail caches; disconnected
startup does neither. Recovery fencing does not permanently affect unrelated
ordinary editors. Explicit recovery temporarily serializes file operations while
native authentication identifies the affected files; unavailable protection
metadata still fails closed.

PDM has one application tab next to Home and the document tabs. Home and the
workspace selector both open that tab, including when no design is open. Returning
to a document preserves its workspace, camera, in-memory edits and undo history.
Closing the last document keeps the PDM browser and connection available; closing
the PDM tab with the keyboard returns to Home.

Archive automatically saves the active owned working copy before publishing.
The continuation captures its document, native path, revision and connection;
a failed save or changed editor cancels publication and preserves local work.
Checkout can preserve current unsaved editor changes only after fresh base and
on-disk checks prove the matching working copy. Undo Checkout requires an explicit
discard confirmation for both unsaved memory and saved local changes. Declining
preserves both; release errors retain a truthful reservation state for retry.

The file context menu targets the clicked row and uses the same action policy:
Open, Archive, Download Latest, Check Out, Undo Checkout, Go to Server Folder and
Open Working Folder. Native folder opening validates the working-root boundary.
Rename and Delete require separate server operations and reference-integrity
rules; this increment does not offer those actions.

Italian labels use Estrai, Archivia and Annulla estrazione; initial publication
has its own label. Local Save remains distinct from publishing to the archive.
Native before/after evidence uses only original toy parts and assemblies in a
new isolated profile. Previously delivered applications, profiles and archives
are never used as test targets or silently upgraded.

## Incremental slices and validation

The authorized delivery includes three deployment modes, using the same service
protocol, authorization and CAD workflow:

| Mode | Service and metadata | Blob archive | Access | Current state |
| --- | --- | --- | --- | --- |
| Local / LAN | Local host | Local filesystem | Local client; authenticated TLS for LAN | Native loopback trial verified; HTTPS library verified; guided LAN setup pending |
| Local with remote access | Local host | Filesystem or configured object store | Outbound connector and public HTTPS relay | Connector and relay library under isolated integration tests; installation and pairing UI pending |
| Fully hosted | Hosted independently of local workstations | Filesystem or S3-compatible storage; separate optional Azure adapter | Authenticated HTTPS | HTTPS library verified; deployment, login and provider integration pending |

Setup must guide service installation, first administrator creation, archive
selection and backup policy, workspace selection and client login. Remote mode
adds guided connector pairing. User login, connector identity and storage
credentials are separate capabilities and must never be interchanged. Secure
credential storage, TLS and server-side permissions precede enabling any
non-loopback listener. Installation must not silently expose the current service.

Follow-up implementation slices after the verified native local workflow are:
transport/storage boundaries and bootstrap; secure LAN/hosted endpoint and login;
outbound connector plus local relay integration; optional object-store adapters;
guided setup and mode-specific backup/recovery validation. Reuse existing claims
where cohesive and check ownership before creating focused dependent work.
All development uses disposable local test services and credentials. No public
provisioning, paid service or real-user migration is authorized by this plan.
CAD responsiveness remains the priority; scoped builds run at low priority.

1. Server catalog, authenticated reservations, version metadata and retry receipts;
   test competing callers, stale bases, restart recovery and bypass rejection.
2. Workspace manifest, safe path mapping and same-path file transitions; test
   hostile paths, dirty copies, interrupted updates and read-only state.
3. Shared engine commands and asynchronous native adapter; derive dependencies
   from native links and workspace metadata, never manual document/version input.
   Test saved-document validation, managed save guards and reconnect recovery.
4. Native PDM ribbon and dedicated archive workspace: connection, folder browser,
   file status, owner/time, history, relationships and version preview status.
   All actions reach the same command queue; filesystem/network work stays off
   the UI thread. Show unsupported/unavailable preview state honestly.
5. Isolated native trial of creation, checkout, edit/save/check-in at the same
   path, cancellation, competing clients, local/remote component updates and
   historical reconstruction. Preserve existing trial processes and data.

Run focused domain/native/UI checks, strict Clippy, layering/assets/lists, the
Wasm gate and the repository CI entry point. Record any independently reproduced
baseline failure accurately. Keep the PR draft until the user trial is complete.

## Explicit limits

The local milestone was verified with 34 focused native/engine/UI tests and 40
service/workspace/backup tests, strict Clippy, and a separate native UI trial.
The trial exercised the actual restore confirmation, historical v1 content
published as v3, unchanged historical versions, same-path normal-tab reuse,
read-only saves after publication, and retry without an additional version.
The delivered executable and demo are frozen separately from further development.
A local trial is not a release or a complete-CI result. Each frozen pair records
its source revision, working patch, executable hashes and actual validation
outcomes separately. Current checks and known limitations are reported in
[PR #3003](https://github.com/tangency-labs/solidcraft/pull/3003).

The following validation counts and CI failures describe their original
increment, not the current source or every frozen trial.

The subsequent increment exported and verified the filesystem BlobStore boundary and
one-time local first-administrator enrollment. It does not enable a network
provider, remote login or a non-loopback listener. The legacy loopback owner
credential remains an explicit compatibility path; any secure transport must
exclude it and authenticate configured principals only.

The subsequent HTTPS library increment uses Hyper's HTTP/1 implementation with
rustls and the existing ring provider, plus a native ureq client. It carries the
same protocol in `POST /pdm/v2/rpc`, with a separate bearer header. Configured
principals are mandatory; the legacy loopback owner credential has no fallback
in this transport. The production client validates platform trust, or an
explicit private CA, including certificate validity and hostname. Redirects and
implicit proxies are disabled, and errors do not echo credentials or remote text.

The server serializes domain writes on a dedicated worker and bounds connections,
queued requests, headers, streamed bodies and handshake/body/response deadlines.
It reports readiness only after listener registration and writer startup. Sixty-
eight service tests, including six isolated HTTPS integration tests, passed along
with strict Clippy. The network tests bind only loopback ephemeral ports and
exercise invalid trust/hostname, configured roles, competing checkouts, stale
bases, retry receipts, oversized chunked input and stalled connections. Original
public test keys are confined to fixtures and never enter a production trust store.
These changes are not in the frozen trial. There is no HTTPS CLI, login wizard,
remote provisioning or cloud provider enabled by this increment.

### Outbound relay and identity binding

The following library increment shares the bounded TLS listener between the
service and a relay. A connector polls the relay and forwards each request to
its configured HTTPS service; it does not listen for inbound workstation
connections. Both hops validate their certificates. The relay has bounded,
ephemeral jobs, per-job leases, deadlines and cancellation, with one active
connector poll per tunnel. Losing a relay job cannot release a checkout or
publish a version: the authoritative service owns those operations and their
durable retry receipts.

Each tunnel has an immutable server identity and a separate connector
capability. The connector forwards the caller's user credential; the connector
capability is never a document principal. The user client discovers and pins
the authenticated server identity, then supplies it on subsequent requests.
The service checks that identity in the same serialized operation as user
authorization and execution, so changing a host or restoring another store at
the endpoint cannot silently redirect a write. Initial discovery permits only
the catalog operation without a server identity.

Pairing challenges require an opaque administrator context minted by the
configured service, expire, permit bounded attempts and can be redeemed once.
Pairing secrets and connector capabilities have distinct types and redacted
diagnostics. This registry is currently in memory; it has no pairing network
route or persistent deployment configuration. Revocation in the registry does
not update an already constructed relay configuration. Guided setup must join
those boundaries before remote access is enabled.

The relay operator is trusted with user credentials and request content in
memory under TLS. This is not end-to-end encryption through an untrusted relay.
The increment remains a library exercised with disposable loopback listeners:
there is no public gateway, login wizard, background installation or resumable
large-transfer protocol. Native enrollment can persist its first credential
through a trusted sink before publishing the administrator registry; the sink
must be connected to durable OS credential storage by the installer.

The integrated service suite passed 101 tests in 11 suites, including eight
direct HTTPS tests and the real two-hop user-client/connector cycle. The latter
was extended and passed again with v1, changed v2, historical v1 republished as
v3, retry without v4, and all three payloads checked after reopening the service.
It tests protocol-level republishing; the native restore confirmation was
verified separately in the frozen local trial. Strict Clippy, formatting,
dependency layers and sorted catalogs passed. Repository CI still stops at the
unchanged, independently reproduced Windows accepted-icon hash mismatch.

### Storage and remote access contracts

The authoritative PDM service owns identities, authorization, reservations,
version manifests and relationships. Blob storage is a separate replaceable
boundary: put immutable content by digest, read verified bytes, test existence,
and report durable completion. Filesystem storage is implemented in this slice.
A standalone experimental S3-compatible adapter is implemented separately from
the authoritative store. It uses signed conditional creation, read-back digest
verification and bounded inventory; it never overwrites or deletes objects.
Its tests use the published AWS signature vector and an original loopback HTTPS
mock with conflict, lost-acknowledgment, corruption, quota and pagination faults.
No provider account was accessed and compatibility with an actual provider is
unverified. The default service constructor and launch configuration still select
filesystem storage. Explicit provider injection is available as a library API;
its coordinated backup is verified with memory-only external providers. Azure
Blob requires a separate adapter. Metadata publication must
never reference an unavailable blob; provider retries need idempotency and
integrity checks.
No provider account or cloud dependency is required by the local deployment.

The S3 adapter assumes one writer exclusively owns its configured bucket prefix.
Inventory is neither a cross-object transaction nor a multi-writer quota fence.
It supports bounded single-object transfers, not multipart or resumable uploads.
Storage credentials are supplied explicitly by the service operator and remain
separate from user and connector capabilities.

`Store::open_with_blob_store` requires a fresh managed root or the matching
persisted external binding. The binding identifies the endpoint, bucket, prefix
and region without including storage credentials, so credential rotation does
not retarget the archive. A mismatched or partial marker, an attempted implicit
filesystem fallback, or mixed local/external blobs fails closed. Startup checks
one bounded provider inventory and rejects missing committed digests before
making the store available. Existing filesystem archives are never migrated by
this API. An interrupted initial external setup remains preserved for explicit
recovery; there is no automatic reset.

Remote access to an on-premises service should use an outbound connector to an
HTTPS relay, guided pairing and authenticated user login. Clients should not
require a VPN or incoming router ports. The connector authenticates the service;
it does not grant a remote caller document access. User authentication through
OIDC authorization code with PKCE and optional MFA remains a separate boundary
from server-side authorization. The relay must not bypass checkout fencing or
hold an unrestricted owner capability on behalf of all users.

An object store alone does not make a local service reachable or keep it running
when its host is off. A fully hosted deployment needs the authoritative service
and metadata storage hosted as well. Open S3-compatible storage and self-hosted
relay implementations require license, protocol and security review before any
integration; no compatibility is assumed from their advertised protocol names.
Provider provisioning, public endpoints and real credentials are outside this
increment. These contracts must not delay verification of the local workflow.

No public listener, remote deployment, external identity provider, approvals or
revision lifecycle is implied by this increment. Backup
must include the complete service store and metadata; version history alone is
not a backup. Any incomplete behavior remains disabled or explicitly reported.

### Local HTTPS packaging rehearsal

`solidcraft-pdm rehearse-https CONFIG` starts a disposable, already enrolled
service from a bounded configuration file. The configuration contains only
absolute paths to the existing store, DER certificate-chain files, a PKCS8 key
file, and a loopback bind address. It rejects unknown fields, embedded tokens,
public addresses, links/reparse paths, oversized TLS material and missing
enrollment before starting the service. It never enrolls or resets an archive.

```json
{
  "store": "/private/pdm/store",
  "bind": "127.0.0.1:0",
  "certificate_chain": ["/private/pdm/service.der"],
  "private_key": "/private/pdm/service-key.der"
}
```

The launcher reads one credential-free readiness receipt containing the bound
address and existing server identity. Its private stdin stays open for the
rehearsal; sending `shutdown` followed by a newline, or closing stdin, stops
that process. This is a packaging test entry point, not an installed daemon or
a hosted deployment. An installer must supply its own trusted certificate and
private key; repository test fixtures are intentionally public test material.

The expanded backend suite passed 114 tests, including the real CLI subprocess,
authenticated HTTPS publication, clean shutdown/store-lock release and rejection
of a public bind without creating an archive. Strict Clippy and resolved licence
checks passed; the licence report notes the expected generated-file update on
main. The authenticated identity operation returns the actual configured
principal and role; it accepts no caller-selected account or permission fields.

### Native credential and login boundary

The native application has separate worker APIs for enrollment, verified login,
resume and forgetting a saved user credential. Constructors perform neither
network requests nor credential-store access. Login binds the expected server
before the first request and obtains the account and current role from the
authenticated service. It persists a user bearer only after that verification.
Resume retrieves the matching user slot, repeats authentication and checks the
actual account before returning a client session.

The OS credential-store namespace is `SolidCraft PDM`, separate from agent-chat
credentials. User and connector purposes cannot share slots. A user slot binds
the normalized origin, server identity, actual account, certificate trust
fingerprint and direct/relay tunnel context. An imported profile with changed
trust or route cannot automatically retrieve the credential from the old slot.
Profiles contain only public identity and trust data; the bounded JSON loader
rejects inputs above 384 KiB before deserialization. Unsupported native operating
systems report credential storage unavailable rather than using a mock backend.

Native enrollment connects the first-administrator bootstrap to a credential
sink before publishing the principal registry. A failed sink permits retry; a
failed registry publication retains the captured credential for recovery.
Neither path resets an existing archive. Guided private-local setup and saved
connection reopening now use these native workers. External identity-provider
login remains pending. Tests use an in-memory credential store and disposable
HTTPS services; they do not access the actual OS keyring.

All 19 focused native PDM tests and strict native Clippy passed. Coverage includes
real disposable HTTPS login/resume, wrong-server and wrong-credential rejection,
selective forgetting, first-admin sink failure/retry and imported trust/route
changes. The public-client relay test also passed with authenticated identity
checked across both TLS hops before its historical v1/v2/v3 publication cycle.
Repository CI again passed formatting/assets before the existing Windows icon
hash failure. These foundations are not part of the frozen user trial.

Saved profiles now have a bounded, versioned public-metadata directory with
deterministic identifiers. Reads never create a missing directory. Installation
uses a private staging file, the OS writer lock and no-replace publication;
corrupt records, links, unknown files and quota violations fail closed. It stores
no bearer and never signs in as a side effect of listing or importing a profile.
All 23 native PDM tests and strict native Clippy passed with this persistence
boundary, including interrupted staging, corruption and capacity checks.

### Recoverable private local setup

The native `LocalSetup` worker creates a dedicated private installation with a
new filesystem archive, public profile records and an original loopback TLS
certificate. Its private key stays in that installation; certificate trust is
explicit in the profile and never added to the operating system. The worker
reserves a loopback socket before enrollment and retains that exact listener
through service startup. It never selects, resets or migrates an existing archive.

Setup captures the administrator bearer in the credential store, then publishes
the public enrollment intent, before publishing server authority. A restart
after capture can finish an absent principal registry using the same captured
credential and existing server identity. Partial registries are preserved and
rejected. The trusted native finalization helper has no RPC route; it requires
validated installer intent and an empty existing archive under the writer lock.
It does not infer a prior administrator identity from an unconfigured archive.

Resume retains the recorded port, certificate, profile and server identity. An
occupied port, changed trust, inconsistent journal or missing credential stops
recovery. A prior verification receipt is public journal state only: each resume
authenticates over HTTPS and verifies the current administrator role before
returning an active service. Failed authentication releases its own listener and
locks while preserving installation files. No retry rotates a captured credential
after a committed enrollment intent. A crash before both TLS files and the
prepared completion record leaves an incomplete installation for inspection;
automatic repair of that earlier boundary is not implemented.

Guided private-local creation and saved connection reopening now invoke the
same native worker. The form sends public labels and connection identifiers;
credentials, TLS and filesystem operations remain native-only. Tests use only disposable installation roots
and an in-memory credential store, with actual loopback TLS authentication.
All 30 native PDM tests and 130 service tests passed, including recovery after
credential capture and rejection of stale verification after account demotion
or removal of the saved credential.
Strict native/service Clippy, dependency-layer, sorted-list and resolved licence
checks passed. The added `rcgen` dependency generates original private TLS
material and uses its permissive MIT/Apache-2.0 licensing. Repository CI passed
formatting/assets before the unchanged Windows accepted-icon hash failure.

## Guided connections and verified editor reopening

The native connection window creates a new private local archive from a display
label and administrator account ID. Recent rows contain bounded public metadata;
listing them does not read credentials, create missing settings or authenticate.
A saved row remains unverified until an explicit open freshly checks its HTTPS
server identity and current account role. The active header displays that actual
identity, origin and working folder. Partial local setup remains discoverable and
resumes its recorded installation without replacing trust or starting a second
owned service. Existing foreign listeners are never taken over.

Only a new unnamed design suggests the verified working folder in Save As.
Existing designs and other exports retain their normal destination behavior.
Public commands use labels and opaque connection IDs; bearer values and unknown
credential fields are rejected before command recording:

- `pdm.connections {}`
- `pdm.setup.create {"label":"Private archive","administrator":"admin"}`
- `pdm.connection.open {"connection_id":"<64 lowercase hexadecimal characters>"}`
- `pdm.connection.recover {"connection_id":"<64 lowercase hexadecimal characters>","restore":true}`

Reconnection resumes only a still-existing reservation for the authenticated
owner and exact workspace/machine tuple. The read-only resume RPC returns the
persisted capability without creating a checkout, rotating its token or writing
metadata. Unsupported older servers have no fallback to a mutating checkout.
New reservations still require the user's explicit Check Out action.

Workspace recovery repairs an interrupted local transaction after explicit
confirmation and fresh authentication; recorded base hashes must match the
bound server. It preserves replaced current bytes in recovery files. Every managed saved
editor sharing the runtime then requires a verified disk reopen before edits or
writes to its original destination, even if recovery later fails or status is
refreshed. Reopening one tab does not authorize another cached tab. A separate
Save As can preserve its memory contents without replacing the recovered file.
An asynchronous load captures its recovery state before reading and refuses a
result if recovery changed that state; rejection preserves the existing editor.

The connection inventory contains at most 64 records. It publishes local intent
before installation side effects and uses OS locks and no-replace records.
New directory entries are synchronized through their parents on Unix; Windows
recovery is tested for process interruption, without a power-loss guarantee.
Unattended native and GUI tests inject memory credentials and use actual private
loopback TLS. The production OS credential store is not automated by those tests.
Guided LAN enrollment, remote pairing, provider selection and hosted installation
remain separate work; this increment does not provision any external service.

## Verified offline backup and restore foundation

Stop the local service before using these commands. The backup command acquires
the same exclusive store lock and refuses a running service. Both output paths
must be new directories whose parents already exist:

```sh
solidcraft-pdm backup /private/toy-store /private/toy-backup
solidcraft-pdm verify-backup /private/toy-backup
solidcraft-pdm restore /private/toy-backup /private/restored-toy-store
```

The snapshot includes legacy content, managed version metadata and blobs, catalog,
server identity, checkout reservations, retry receipts and configured principal
hashes. It excludes process locks and unpublished staging data. The backup copies
only recognized store files, validates the copied domain and dependency references,
and writes its completion manifest last. Verification checks every listed file's
size and SHA-256 and rejects links, extra files and bounded-input violations.
Limits are 10,000 files, 8 MiB per file and 256 MiB total; metadata is also subject
to the service's smaller limits. Output JSON is an integrity receipt, not a design
export, credential dump or cryptographic attestation.

Restore verifies the manifest before creating its destination, holds the writer
lock while copying, and validates domain metadata and referenced content before
removing `restore.pending`. An interrupted or invalid restore remains marked and
cannot start as a service; preserve it for diagnosis and retry into another new
directory. Existing destinations are never replaced. Test the restored service
in isolation: it retains the same identity and reservations, so the original and
restored copies must not operate simultaneously as authoritative servers.

Backups contain private design data and checkout capabilities. Unix output roots
use mode 0700; Windows inherits its destination-parent ACL. Choose a private parent
directory. The owner bearer credential comes from the service environment and is
not included; preserve it separately or explicitly configure replacement ownership.
This foundation does not encrypt/sign backups, schedule retention, compact metadata,
configure a remote provider, or establish recovery objectives. File sync and
interrupted-process tests do not establish power-loss durability on every filesystem.

The provider-aware backup holds the same authoritative writer lock while
capturing identity, metadata generation and referenced digests. It obtains all
blobs, including published orphans, from the active provider and independently
checks their hashes, sizes and quotas. It ignores any stale local blob cache.
It writes a portable filesystem copy, verifies domain/dependency closure and the
captured generation, then publishes the completion manifest. Provider bindings,
configuration and storage credentials are excluded. Restore remains a new
filesystem destination; restoring into an object-store prefix is unsupported.

The expanded service suite passed 127 tests and strict Clippy. Tests cover
external-provider backup/restore with identity, history, checkout and retry
receipts preserved; missing/corrupt content; invalid inventories and quotas;
orphan upload recovery; wrong-provider/fallback rejection; and reserved
loopback-listener startup without closing and rebinding its port. No actual
external storage account or provider was used. Exclusive ownership of the remote
prefix remains required: an OS lock does not coordinate other independent hosts.
