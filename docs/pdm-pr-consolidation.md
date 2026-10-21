# PDM pull request consolidation provenance

The server and shared infrastructure in #3711 replace the useful backend scope of
#2870 and #2996. CAD integration remains in #3003, which must descend from the
verified #3711 server commit and remains blocked on that prerequisite.

## Original source coverage

Every original changed path remains at the same path in the server consolidation.
Manifests, lock records and application layer entries are reconciled with the current
workspace; application source and tests retain the contracts described below.

| Original PR | Original head | Retained final paths |
| --- | --- | --- |
| #2870 | `953d4e2a24efb29aab59b2c3818534212cfe8ef7` | `Cargo.lock`<br>`apps/solidcraft-pdm/Cargo.toml`<br>`apps/solidcraft-pdm/src/lib.rs`<br>`apps/solidcraft-pdm/src/main.rs`<br>`apps/solidcraft-pdm/tests/versioned.rs`<br>`docs/pdm-rfc.md`<br>`xtask/src/layers.rs` |
| #2996 | `16337fb89ac71a835efac38810d674c59e526e80` | `Cargo.lock`<br>`apps/solidcraft-pdm/Cargo.toml`<br>`apps/solidcraft-pdm/src/client.rs`<br>`apps/solidcraft-pdm/src/lib.rs`<br>`apps/solidcraft-pdm/src/main.rs`<br>`apps/solidcraft-pdm/src/workspace.rs`<br>`apps/solidcraft-pdm/tests/versioned.rs`<br>`apps/solidcraft-pdm/tests/workspace.rs`<br>`docs/pdm-local-workspace.md`<br>`docs/pdm-rfc.md`<br>`xtask/src/layers.rs` |

## Retained contracts and explicit transitions

- Immutable versions, parent conflict checks, exact historical bytes, pinned dependency
  closure, Where Used, bounded frames/content/quotas and unpublished-stage recovery
  remain covered by `apps/solidcraft-pdm/tests/versioned.rs`.
- Mandatory credentials, rotation, redaction, rejection of anonymous/wrong-protocol
  requests, bounded workspace materialization, no overwrite and native CLI file commands
  remain covered by `apps/solidcraft-pdm/tests/workspace.rs`.
- The anonymous prototype transport from #2870 was intentionally superseded by the
  authenticated `solidcraft-pdm/2` envelope in #2996. No anonymous fallback is restored.
- Existing legacy document IDs beginning with `m-` retain verified reads, Where Used
  and further versions after reopening. New legacy IDs with that prefix stay reserved
  for managed identities. Exact managed IDs, including tombstones, never fall through
  to legacy writes; generated managed IDs reject existing legacy filesystem entries.
- The original seven versioned and eight workspace integration test bodies remain;
  two additional versioned regressions pin the legacy-prefix compatibility above.
  Existing library regressions retain bounded read/write deadlines.
- Transactional metadata, TLS, managed authority, streamed transfers and recovery,
  administration, the native server console and shared credential custody are additive
  server/shared scope. CAD panels, engine integration, icons and local UI state belong
  to #3003.
- `docs/pdm-rfc.md` and `docs/pdm-local-workspace.md` retain their architecture and
  historical increment descriptions; later implementation boundaries are recorded in
  the managed workspace, namespace, binary transfer and explicit remote documents.

## Verification boundary

The consolidation is based on main `728f753b8094e1a54c5cc8b7e453982afa028023`.
Focused native backend and console checks do not certify all workspace/platform CI,
production migration or the separately owned CAD trial. Closing the historical PRs
requires verification of the published replacement heads and their dependency order.
The deployed server and user documents are outside this source-only consolidation.
