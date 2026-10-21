//! Display namespace operations never rename or delete working files.
use super::*;
use solidcraft_engine::pdm::{NamespaceEntry, NamespaceState};
use solidcraft_pdm::managed::{NamespaceAction, NamespaceMutation};

impl Host {
    pub(super) fn apply_namespace_state(&self, client: &Client, state: &mut ManagedState) -> Result<(), Failure> {
        let Some(capabilities) = client.namespace_capabilities().map_err(error)? else { return Ok(()) };
        if capabilities.server_id != self.server_id {
            return Err(fail("The namespace service identity changed; reconnect explicitly"));
        }
        if !capabilities.supported || !capabilities.stable_materialization_paths {
            return Ok(());
        }
        let metadata = client.namespace_catalog().map_err(error)?;
        state.namespace = NamespaceState {
            supported: true,
            can_mutate: capabilities.can_mutate,
            entries: metadata
                .iter()
                .map(|item| NamespaceEntry {
                    document: item.entry.document.clone(),
                    materialization_path: item.materialization_path.clone(),
                    revision: item.revision,
                    tombstoned: item.tombstoned,
                })
                .collect(),
        };
        state.catalog = convert(metadata.into_iter().filter(|item| !item.tombstoned).map(|item| item.entry).collect::<Vec<_>>())?;
        Ok(())
    }

    pub(super) fn namespace_mutation(
        &self,
        client: &Client,
        ws: &Workspace,
        document: &str,
        expected_head: Option<u64>,
        expected_revision: u64,
        action: NamespaceAction,
    ) -> Result<(), Failure> {
        let caps = client.namespace_capabilities().map_err(error)?.ok_or_else(|| fail("ui.pdm_namespace_unavailable"))?;
        if caps.server_id != self.server_id || !caps.supported || !caps.stable_materialization_paths || !caps.can_mutate {
            return Err(fail("ui.pdm_namespace_unavailable"));
        }
        // The server checks current checkout/CAS and reconciles the exact
        // request receipt first. A local metadata preflight would reject a
        // successful operation whose acknowledgement was lost.
        let request_id = hash(
            &serde_json::to_vec(&(
                "namespace-mutation/1",
                &self.server_id,
                &caps.principal.id,
                &ws.manifest().workspace_id,
                document,
                expected_head,
                expected_revision,
                &action,
            ))
            .map_err(|_| fail("Could not identify the namespace operation"))?,
        );
        client
            .managed_namespace(NamespaceMutation { document: document.into(), request_id, expected_head, expected_revision, action })
            .map_err(error)?;
        Ok(())
    }
}
