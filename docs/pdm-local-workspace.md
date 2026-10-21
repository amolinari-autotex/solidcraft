# Experimental authenticated local PDM workspace

Follow-up #2995 / #2996, built on the immutable version prototype in #2870.
This increment is a native **file client**, not a CAD GUI. It adds a mandatory local
owner credential, document/version listing, file check-in and verified retrieval of
an exact dependency closure. Use public-safe toy files only.

The separate follow-up [#3003](https://github.com/tangency-labs/solidcraft/pull/3003) adds a bounded CAD desktop panel
using this client. This document records the prerequisite #2996 file-client scope;
the follow-up's GUI does not add remote transport or automatic CAD link resolution.

The same domain model is intended for local and cloud hosting. This implementation
still accepts only IPv4 loopback connections; it has no public bind option, TLS,
outbound relay, pairing, multi-user identity provider or role enforcement. No
external account is required to use the local service. No infrastructure is deployed.

Later managed-server increments reserve new `m-` document IDs for server-generated
identities. Existing legacy documents using that prefix retain verified retrieval,
history, Where Used and further versions; no archive conversion is needed. Managed
IDs, including tombstones, never fall back to legacy writes. A newly generated
managed identity cannot shadow an existing legacy filesystem entry.

## Bootstrap and credential lifecycle

`solidcraft-pdm token` requests 32 random bytes from the operating system through
getrandom and intentionally writes their hexadecimal encoding to stdout. **Capture
that output in a private environment variable; do not echo, log, commit or pass it
as a command-line argument.** All other commands require `SOLIDCRAFT_PDM_TOKEN` to
contain exactly that 64-character string. The service refuses to start without it.
There is no default credential and no credential file written by this application.

For example, in one PowerShell session, after building the binary:

```powershell
$pdm = 'C:\path\to\solidcraft-pdm.exe'
$env:SOLIDCRAFT_PDM_TOKEN = & $pdm token
# Use a private, disposable folder you own for every path below.
$server = Start-Process -FilePath $pdm -ArgumentList @('serve', 'C:\private\toy-store', '48231') -WindowStyle Hidden -PassThru
& $pdm list 48231
# Other client operations run in this same session and inherit the credential.
# Stop only the process created above when finished.
Stop-Process -Id $server.Id
Remove-Item Env:SOLIDCRAFT_PDM_TOKEN
```

The service inherits the token once at startup. To rotate/revoke it, stop that
service, capture a new generated token, and restart with the same store. Requests
with the former token then fail; an operation already executing before shutdown
may finish. Existing document versions remain unchanged. The caller is responsible
for securely distributing the new token to authorized local processes. There are
no per-device credentials, leases or per-user revocation yet.

The credential is process environment data: the same OS user and administrators
may inspect it. It is transmitted in plaintext over the local socket, so this is
not safe to expose through a tunnel/proxy or on a shared untrusted host. Memory
zeroization, keychain storage and encrypted transport are not provided. Debug
formatting redacts the token and normal command output contains no credential.
The explicitly requested `token` command is the sole intentional secret output.
Keep shell tracing/transcripts disabled for credential setup.

Every socket request uses protocol `solidcraft-pdm/2` and a token-bearing envelope.
The server compares equal-length credentials using subtle's constant-time equality
before entering any domain operation, including listing, downloads and writes.
This is one owner capability granting read/write access to the whole store, not
a replacement for the roles and audit policy proposed in the RFC. Anonymous raw
requests from the original prototype are deliberately incompatible. `request PORT`
still accepts a request JSON line on stdin; the client supplies the envelope from
its environment and never prints it.

## File workflow

Run clients in the session carrying the token. All paths below are disposable toy
paths; the source file is read, never modified by check-in.

```powershell
& $pdm check-in 48231 part - 'C:\private\part.solidcraft'
& $pdm list 48231 part
# A dependency file is an array of exact references, for example:
# [{"document":"part","version":1}]
& $pdm check-in 48231 assembly - 'C:\private\assembly.solidcraft' 'C:\private\dependencies.json'
# After saving a different local part file, publish the next working version:
& $pdm check-in 48231 part 1 'C:\private\part.solidcraft'
& $pdm list 48231
& $pdm retrieve 48231 assembly 1 'C:\private\new-workspace'
```

`-` is creation with no parent; otherwise the parent must equal the latest working
version. A stale parent returns `conflict`. The input must be a regular file at
most 1 MiB; the dependency JSON file is limited to 64 KiB. This client preserves
opaque bytes, not semantic CAD validation or merging. Dependencies are declared
PDM metadata: this increment does not discover or rewrite CAD link paths, and
opening an assembly does not yet resolve links through the PDM service.

Retrieval requests the exact root and every pinned dependency, verifies reference
identity and SHA-256, validates IDs and limits, rejects missing versions, duplicate
edges and cycles, and only then starts writing locally. It does not follow latest.
No server-provided filename is used as a local path. Each version has a distinct
namespace, including when two versions of one document occur in the same graph:

```text
new-workspace/
  snapshot/
    snapshot.json
    documents/d-assembly/v-1/content
    documents/d-part/v-1/content
```

`snapshot.json` records the root, exact version metadata, hashes and graph. The
`content` files contain original bytes without renaming/deleting a user's source.
Use the manifest to identify them; there is no flat filename namespace or silent
collision handling. CAD open/download UI will later supply a suitable local working
copy filename and record its source version.

The destination must not already exist, even as an empty directory or symlink.
Its parent must already exist and be a trusted private directory chosen by the
operator. The client reserves the new destination with `create_dir`, writes into
its `.pending` child, then publishes one `snapshot` child with a same-filesystem
rename. It never renames over the caller's destination or an existing snapshot.
On an ordinary write failure it removes only the directory created by that call.
A cleanup failure or process crash can leave an unpublished `.pending` directory;
do not treat it as a completed snapshot or automatically reuse it. Parent directory
flushes and power-loss durability are still unverified.

Permissions inherit from the selected private parent and the OS; the application
does not harden arbitrary directory ACLs. On Unix choose a restrictive umask such
as `077`; on Windows use a private user-owned directory with appropriate inherited
ACLs. The caller must keep that directory free of hostile local mutation while a
snapshot is being written. Token authentication does not encrypt files at rest,
protect against the host administrator or provide tested backup/restore.

The existing limits remain: 256 committed versions, 64 MiB content in a store and
in one retrieved closure, 256 direct dependencies per version, 8 MiB frames and
separate five-second socket read/write budgets. Domain/disk execution does not have
an end-to-end deadline. The service is synchronous and remains susceptible to
repeated local connections; no general denial-of-service resistance is claimed.

## Verification and next increment

Tests exercise authenticated native CLI/TCP check-in, listing and retrieval;
unauthorized operations and token rotation; preservation of pinned v1 after v2;
separate paths for multiple versions; hostile reference paths; missing content,
hash/reference mismatches and cycles; graph limits; existing-destination refusal;
and cleanup after injected partial disk failure. Credential generation and redacted
Debug output are also checked. These are bounded prototype tests, not a production
security certification.

The next product increment is **CAD UI integration**, not more general CLI features:
an engine-command-backed local connection panel, browse versions, check in the
saved active document with explicit expected parent, retrieve/open an exact version
into a new working copy and show its pinned dependency metadata. The UI must surface
conflicts and keep local edits intact; linked-file resolution must be explicit.
Only after reviewing these local flows should identity/roles, durable transactions,
backup/restore and authenticated encrypted outbound pairing/relay be implemented.
Remote access must avoid end-user router setup while respecting network policy;
none of that remote functionality is present in this increment.
