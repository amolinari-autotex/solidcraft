# RFC: a SolidCraft PDM service for local and cloud installations

Status: proposal; #2869. The accompanying `solidcraft-pdm` app is an experimental
loopback vertical slice, not a production vault. Research checked 2026-10-19.
All behavior below is proposed unless listed under **Implemented slice**.

The first-slice implementation section below records the historical #2870 baseline.
The bounded follow-up #2996 adds mandatory local owner-token authentication and a
native file workspace; its current behavior, protocol and limitations are documented
in [Authenticated local PDM workspace](pdm-local-workspace.md). It adds no CAD GUI
or remote transport and does not imply production readiness.

## Problem and scope

Teams need reproducible assemblies, controlled edits and a durable record of what
was released. A shared directory with thumbnails cannot supply these guarantees.
The same Rust service, domain operations and client workspace should work on one
computer, an on-premises server or a cloud host. Hosting changes the endpoint and
storage configuration, not document semantics. No router configuration should be
required from the end user. Restricted corporate networks may require administrator
approval for permitted outbound destinations; this design does not bypass policy.

Repository searches found no dedicated PDM/vault implementation or open claim.
[#626](https://github.com/tangency-labs/solidcraft/issues/626) covers stable text,
semantic diff and merge, explicitly excluding locking and history UI.
[#1017](https://github.com/tangency-labs/solidcraft/issues/1017) concerns IDs inside
designs, not cross-service document identity. Linked-design support (#596), revision
metadata (#1189), BOM (#1899), Open Linked Design (#2349), copying links (#2433) and
Relink Source (#2773) are integration points, not substitutes for version history.
Their implementation is outside this slice. Existing issue/PR searches are a
point-in-time check, not a claim that every related discussion was discovered.

## Domain model and invariants

- **Vault**: an authorization and backup boundary owned by an organization or person.
- **Document**: an enduring identity independent of filename, folder or CAD entity IDs.
  Production IDs are server-issued random identifiers scoped by vault identity.
- **Version**: an immutable snapshot of bytes, metadata and exact dependencies.
  Its identity is `(vault, document, version)`; a digest verifies bytes but is not
  the document identity. Equal bytes can belong to different documents.
- **Dependency**: an edge from one version to an exact target version, carrying
  occurrence/link identity and relation kind. It never silently follows latest.
- **Revision**: an approved release designation pointing to one immutable version
  and its frozen dependency closure. Working versions do not increment this label.
- **Checkout**: an exclusive, renewable editing lease associated with a principal,
  device, base version, expiry and monotonically increasing fencing token.

Uses returns outbound edges for an exact version. Where-used supports exact-version
and document-wide queries, with historical/latest/released filters kept explicit.
Multiple occurrences of one part remain separate edges; a BOM aggregates them by
defined quantity rules. The prototype only records unique direct target versions,
so it cannot represent occurrence quantities. Dependency closure export must resolve
all bytes before reporting success. Cycles in assembly containment are rejected;
other relation kinds can have different cycle rules.

Renaming and moving changes document catalog metadata without rewriting historical
versions. Deleted documents become tombstones; referenced or released versions are
retained. Restoring an older design creates a new working version. No operation
overwrites an existing version or rewrites a released assembly's dependencies.

## Transactions, editing and release

Upload blobs to a temporary namespace, enforce quotas and verify hashes. Then one
metadata transaction checks permission, expected parent, checkout owner/fencing
token, dependency availability and cycle constraints; it commits version, edges,
head pointer, audit event and an idempotency receipt together. Blob publication
precedes that transaction; an unreferenced blob can later be garbage collected,
whereas committed metadata must never refer to an unavailable blob. Receipt IDs
make retries safe when an acknowledgement is lost. Multi-document check-in uses one
transaction and a proposed graph so new assembly/part versions appear together.

Checkout acquisition, renewal, expiry and administrative revocation are serialized
transactions. A stale token fails even after a lease is reissued. Offline editing
is permitted in a local workspace but cannot promise an exclusive lock while
disconnected; reconnection checks the base version and either checks in or offers
explicit conflict resolution. Semantic merge can later use #626 without changing
the service's concurrency rules. Administrative unlocks require a reason and audit.

Release requires a separate approver capability, an explicit revision scheme,
validated closure and an audit event in the same transaction. A released version
is immutable; correction creates another version/revision. The document's existing
free-text revision property must not automatically count as an approved PDM release.

## Authentication, authorization and ownership

Use a replaceable identity provider (OIDC for managed organizations), with explicit
vault membership and stable principal IDs independent of email addresses. Roles
are viewer, contributor, release approver and vault administrator. Check capabilities
on each operation, dependency traversal, blob download and where-used result; do not
leak another project's filenames or existence. A transport peer key identifies a
device, not a user's permission to read a vault. Revoke device and principal access
independently. Invitations are scoped, short-lived and single-use. Bootstrap creates
one local owner through an interactive one-time secret; there are no default passwords.

The owner controls membership, exports, relay configuration and recovery keys.
Cloud account ownership must not silently transfer ownership of an on-premises
vault. Account recovery and ownership transfer require documented administrator
procedures. Encrypt storage using OS/service key protection or managed KMS as
appropriate; endpoint compromise is outside transport encryption's protection.

## One client experience and outbound remote access

The workspace offers Create vault, Join vault and Open recent vault. Local setup
starts a background service with a private data directory and stores a stable vault
identity. Local discovery can advertise only a non-secret ID; it does not confer trust.
Joining scans/enters an invitation that binds vault identity, server public key,
expiry and approved relay/discovery configuration. The owner confirms enrollment;
the client verifies the server key and exchanges device credentials. Pairing codes
must resist guessing and cannot be reusable bearer keys for the entire vault.

For remote access, client and on-premises server initiate outbound connections to
configured rendezvous/relay infrastructure. Direct encrypted paths are preferred
when allowed; an authenticated relay carries end-to-end encrypted application data
otherwise. Authenticate both endpoint keys, then apply user/vault authorization
inside the channel. The relay has its own admission control and quotas; knowing a
vault ID is insufficient to use it. Use a reviewed transport implementation instead
of inventing cryptography. No automatic UPnP, port mapping or firewall exceptions.

Discovery maps a stable vault identity to signed endpoint/relay hints. Its operator
can deny availability and observe connection metadata, but cannot replace the pinned
server identity unnoticed. Private installations can embed their own discovery URL
and relay addresses in invitations and disable public lookup. Rotation is signed by
the prior key or explicitly re-approved by the owner through a recovery procedure.

| Approach | Fit and tradeoff |
| --- | --- |
| Embedded iroh (candidate) | Rust library with authenticated encrypted direct/relay connections. Best fit for joining from the app without a separate VPN. Validate browser support, proxy restrictions, relay access control and pinned-version licenses before adoption. |
| Tailscale/DERP (optional deployment integration) | Existing device network and encrypted relay fallback. Useful for organizations already operating it; enrollment and a separate network agent add installation steps. Keep it external to the application. |
| Conventional public HTTPS endpoint | Straightforward for a cloud-hosted service, but an on-premises service behind NAT would still need an outbound tunnel/relay component. |

Iroh's public documentation describes encrypted direct connections with relay
fallback and self-hosted infrastructure [1]. Its repository offers MIT licensing
[2]. These are reasons to evaluate it, not proof that this prototype supports it.
Tailscale documents WireGuard encryption through DERP [3] and outbound HTTPS 443
for coordination/relays [4]; allowing those connections still depends on local
policy. Its open-source page distinguishes client/DERP components and the external
Headscale coordination option [5]. No Tailscale or Headscale source was used.

An effortless default requires somebody to operate reliable rendezvous, relay,
identity and update services. A vendor-hosted option therefore has a real service
dependency and future operating costs; do not describe it as free or offline.
A self-hosted option removes the vendor dependency but requires an administrator
to provide reachable relay infrastructure and certificates. End users still do
not configure their home routers. Without any reachable permitted relay/direct
path the client reports offline and offers diagnostics; it never circumvents policy.
No such infrastructure has been provisioned by this change.

## Persistence, audit and recovery

Keep one domain service and schema for both deployment modes. A pure Rust embedded
transaction store such as redb (MIT OR Apache-2.0) is a candidate for a single-node
server [6]; secondary indexes must be updated in the same transaction as versions.
PostgreSQL offers a permissive server license [7] and could be an external deployment
backend later, at the cost of a second persistence adapter and operational service.
SQLite documents strong transactional recovery [8], but its C engine does not meet
the repository's pure Rust application dependency goal; do not silently add it.
The slice deliberately adds no new third-party dependency and chooses no production DB.

Production blobs are content-addressed within the vault, with size/hash verification,
streaming/resumable transfer and optional object-storage adapter. Deduplication must
not become a cross-tenant existence oracle. Audit records include actor, device,
operation, affected IDs, prior/new version, UTC server time, correlation ID and reason;
they exclude credentials and design content. Append-only application records alone
are not tamper-proof against the host administrator; export signed checkpoints to
an independently controlled destination if that assurance is needed.

Backups capture a transaction-consistent metadata snapshot, all referenced blobs,
schema version, configuration and encrypted recovery key material. Record a manifest
and verify hashes. A restore rehearsal on an isolated instance checks closure,
revisions, audit continuity and permissions before reopening access. Define RPO/RTO
and retention with the owner. Garbage collection must honor releases, legal holds
and backup retention; perform mark/sweep against a consistent generation with a grace
period. Cloud object versioning is useful but does not replace a tested restore.

## Implemented slice (#2870 historical baseline)

`apps/solidcraft-pdm` is a native app with a library for storage/protocol tests and
one server/client binary. It depends only on existing workspace serde, serde_json,
sha2 and thiserror. No CAD libraries, assets or proprietary product code are used.
No design file format changes are made. The application is registered as an exempt
native app in the layering table; no layered library depends on native networking.
Desktop/CLI/MCP CAD integration remains future work through engine commands, with
the UI staying thin. The prototype request CLI is a separate experimental harness.

Implemented operations are `check_in`, `download`, `where_used`; downloaded version
metadata contains direct uses. Document IDs are caller-selected lowercase ASCII
identifiers (1–64 bytes), not production-issued identities. Versions start at 1;
parent `null` means creation, otherwise it must match the current latest version.
A process OS file lock permits one writer; one synchronous request is handled at a
time. Dependencies must already exist, be unique, and refer to other documents;
historical edges can therefore point only at previously committed versions. Self
references are conservatively rejected. No delete/update endpoint exists.

Each version directory contains bytes and JSON metadata with SHA-256. Files are
synced, then a same-filesystem directory rename publishes them together. An
unpublished `pending` directory is ignored and replaced on retry. This is process
interruption recovery, **not a validated power-loss durability guarantee**: parent
directory flushes, filesystem behavior, fault injection and transactional metadata
remain unresolved. Lost acknowledgements are not idempotently retried. Local disk
tampering can replace both metadata and digest; hashes are integrity checks, not
authentication. Use a private, trusted local directory, not an SMB/NFS share.

The binary binds only `127.0.0.1` and accepts a single JSON line per TCP connection.
There is no configurable public bind address. It has **no authentication, TLS,
permissions, checkout leases, release workflow, audit, backup or remote relay**.
Any local process can read/write while it runs; loopback is not an authorization
boundary. Use public-safe toy documents only and stop it after experiments.
Content is limited to 1 MiB, request frames to 8 MiB, direct dependencies to 256,
with a five-second absolute socket frame-read budget (remaining time recomputed on
each read) and a separate five-second absolute response-write budget. Responses
are serialized once before bounded socket writes. The store admits at most 256 versions
and 64 MiB of total committed content; metadata is bounded by version/dependency
limits. Unpublished stages can temporarily add one upload. Historical scans remain
linear within those caps; repeated connections can still monopolize the single server, so
this is not hardened against denial of service. The protocol is
experimental and not a compatibility promise. Both hosting modes will use the same
versioned service contract after security/transport work; this slice cannot yet be
deployed safely in cloud or used remotely.

Budgets apply separately to reading and writing, not end-to-end execution or disk
I/O. Response frames, including the newline, must fit the same 8 MiB cap. Private
clock/I/O seams used by the socket adapters test five successful partial reads and
writes with residual budgets of 100, 80, 60, 40 and 20 ms, followed by timeout;
these regressions do not depend on thread scheduling. Real TCP remains an
additional integration check.

## Reproduction and validation

Run in two terminals from the repository (choose a free local port):

```sh
cargo run -p solidcraft-pdm -- serve /private/toy-pdm-store 48191
```

Send each line through `cargo run -p solidcraft-pdm -- request 48191` on stdin:

```json
{"operation":"check_in","document":"part","parent":null,"content":[112,49],"dependencies":[]}
{"operation":"check_in","document":"assembly","parent":null,"content":[97,49],"dependencies":[{"document":"part","version":1}]}
{"operation":"check_in","document":"part","parent":1,"content":[112,50],"dependencies":[]}
{"operation":"download","reference":{"document":"assembly","version":1}}
{"operation":"where_used","reference":{"document":"part","version":1}}
```

The assembly keeps part version 1 after part version 2 is uploaded. Stop/restart the
server and repeat downloads. Repeating the first creation returns `conflict`.
`cargo test -p solidcraft-pdm` exercises actual TCP, persistence/restart, stale
parents, missing dependencies, path/ID validation, integrity failure, frame/content
limits, total content/version quotas, loopback binding and rejection of external
bind arguments, single-writer exclusion and recovery of an unpublished stage. No screenshots
are useful for this protocol-only change. No real CAD data or external service is used.

## Incremental delivery and open decisions

1. Review this RFC and bounded prototype. Keep experimental tooling out of installers.
2. Select/pin a pure Rust transaction backend; add idempotency, transactional graph
   indexes, multi-document commits, crash/fault tests and verified backup/restore.
3. Implement identity, roles, fenced checkout and audit; test unauthorized traversal
   and revocation before accepting real designs.
4. Add the reviewed outbound transport, authenticated relay and pairing UX, with
   self-hosted instructions and restricted-network interoperability tests. Verify
   Windows/macOS/Linux and browser capability independently.
5. Add engine commands/client workspace, exact linked-source resolution and release
   approval/closure export. Reuse existing linked-design features without rewriting
   their pending changes. Add visible UI evidence at that point.

Product choices before production: default relay operator and availability/cost
model; organization identity provider; release numbering and approval policy;
offline checkout expectations; retention and restore objectives. None blocks this
toy vertical slice. A production readiness review must cover the omitted security
and operational features, not simply enable a non-loopback listener.

## Sources

Public documentation and license metadata only; no commercial CAD automation or
copyleft source was read. Descriptions above are original summaries. Accessed
2026-10-19; current pages are not dependency pins.

1. [Iroh documentation](https://docs.iroh.computer/), including its [documentation index](https://docs.iroh.computer/llms.txt) listing address lookup, relay and self-hosting topics. Detailed linked relay/security pages could not be retrieved in this research run; exact admission-control, proxy support and deployment requirements remain unverified.
2. [Iroh MIT license](https://github.com/n0-computer/iroh/blob/main/LICENSE-MIT).
3. [Tailscale DERP servers](https://tailscale.com/docs/reference/derp-servers).
4. [Tailscale firewall ports](https://tailscale.com/docs/reference/faq/firewall-ports).
5. [Tailscale open-source components](https://tailscale.com/opensource).
6. [redb project and licenses](https://github.com/cberner/redb), [transaction API overview](https://docs.rs/redb/latest/redb/).
7. [PostgreSQL license](https://www.postgresql.org/about/licence/).
8. [SQLite atomic commit documentation](https://www.sqlite.org/atomiccommit.html).
