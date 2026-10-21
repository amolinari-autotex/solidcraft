# PDM in the CAD desktop

The native desktop integrates the managed PDM service through engine commands.
The service and SDK are provided by [#3711](https://github.com/tangency-labs/solidcraft/pull/3711);
the CAD integration is tracked by [#3003](https://github.com/tangency-labs/solidcraft/pull/3003).

## Connect and choose a working folder

Open the **PDM** workspace and select a saved connection. Remote connections use
the pinned HTTPS service identity and the host credential adapter. Bearer tokens
are not entered in the browser or stored in CAD documents or ordinary preferences.
Legacy loopback diagnostics remain a separate compatibility path.

Each connection has a managed working folder. The browser shows the archive tree,
the current server version and author, local-copy state, and checkout ownership.
Use **Refresh** to reread the catalog and local inventory. Selecting a row loads
its history, references and preview without silently rescanning working files.
Displayed dates use the computer's local time, with an explicit UTC fallback.

Dropping a regular file into the PDM workspace requests an exclusive import into
the selected folder: copy it into the working folder, create a new archive identity
and publish its first version. Existing destinations are refused rather than
overwritten. A linked native assembly requires its complete working-folder graph;
single-file import refuses to relocate its components implicitly. Busy, disconnected,
permission, size and path failures are reported. A control-channel `ui.drop_path`
check exercises import after dispatch; it does not prove Windows drag delivery.

## Edit, archive and retrieve

Check out a managed file before editing it. **Archive** publishes the saved bytes
and releases the checkout. Native assemblies are inspected recursively, and their
contained working-folder parts are archived through the same managed workflow.
Unresolved links and files outside the working folder fail validation. Component
operations are bounded; a recursive archive is not a transaction across all files.

**Get latest** retrieves verified current bytes into managed working copies.
**Cancel checkout** restores the recorded base and releases the checkout. Modified
or open editors have explicit guards; PDM actions do not silently discard them.
Saving or exporting to protected managed paths also passes the native path policy,
including hardlink aliases. Ordinary files outside a managed folder cannot be
archived directly; explicit import creates a separate managed copy first.

Active assemblies refresh their linked working copies after successful publication
or retrieval. Their current editing workflow follows the current working parts.
Historical archive versions remain immutable and record exact dependency versions.
History restores are explicit actions, not an alternative archived-open button.

Rename and deletion use the managed namespace: document identity and existing
physical working-copy paths remain stable. Tombstoned names can be reused under a
new document identity. See [managed namespace](pdm-managed-namespace.md).

## Administration and limits

Authenticated administrators can open the read-only users and audit browser.
Contributors and viewers do not see that entry. The CAD browser does not create
users, change roles, enroll devices or mutate server policy. Server authorization
remains authoritative. See [managed workspace](pdm-managed-workspace.md),
[remote connections](pdm-explicit-remote.md), [binary transfer](pdm-binary-transfer.md)
and [transfer staging](pdm-transfer-staging-slice.md) for service contracts and limits.

The web application currently reports the native PDM adapter as unavailable. This
integration does not change the upstream native document format or claim production
deployment, a transaction across an assembly graph, or WAN throughput validation.
Tests and manual-trial evidence must identify their exact source and scope.

For isolated native testing, set absolute `SOLIDCRAFT_SETTINGS_DIR`,
`SOLIDCRAFT_RECOVERY_DIR`, `SOLIDCRAFT_CRASH_DIR` and `SOLIDCRAFT_CONTROL_DIR` paths
before launch. Changing `APPDATA` alone does not isolate Windows eframe settings.
The [control protocol](control-protocol.md) documents the owned-app test interface.
