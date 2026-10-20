//! Native managed workspace adapter. Reservation capabilities never cross into UI state.
use solidcraft_engine::{
    Session,
    pdm::{CatalogEntry, Failure, LocalEntry, ManagedState, ManagedTask, Outcome, Reference},
};
use solidcraft_pdm::{
    AuthToken, Error, VersionRef,
    client::{Client, read_file},
    managed::{CheckoutGrant, ManagedCheckIn},
    managed_workspace::Workspace,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Default)]
pub struct Host {
    client: Option<Client>,
    port: u16,
    root: Option<PathBuf>,
    server_id: String,
    machine: String,
    grants: BTreeMap<String, CheckoutGrant>,
}
fn fail(message: &str) -> Failure {
    Failure { message: message.into(), disconnect: false }
}
fn error(error: Error) -> Failure {
    super::pdm::map_error(error)
}
fn convert<T: serde::de::DeserializeOwned>(value: impl serde::Serialize) -> Result<T, Failure> {
    serde_json::from_value(serde_json::to_value(value).map_err(|_| fail("Invalid managed metadata"))?).map_err(|_| fail("Invalid managed metadata"))
}
fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

impl Host {
    pub fn connected(&self) -> bool {
        self.client.is_some()
    }
    pub fn disconnect(&mut self) {
        self.client = None;
    }
    pub(crate) fn client(&self) -> Result<Client, Failure> {
        self.client.clone().ok_or_else(|| fail("Connect to a local PDM service first"))
    }
    fn workspace(&self) -> Result<Workspace, Failure> {
        Workspace::open(self.root.as_deref().ok_or_else(|| fail("Choose a working folder first"))?, &self.server_id).map_err(error)
    }
    /// Revalidate the persisted capability against current authenticated server
    /// authority before any publication or destructive local replacement.
    fn verified_grant(&self, client: &Client, ws: &Workspace, document: &str, parent: Option<u64>) -> Result<CheckoutGrant, Failure> {
        let cached = self.grants.get(document).ok_or_else(|| fail("Check out this managed design in this working folder before continuing"))?;
        let fresh = client.managed_resume_checkout(document.into(), ws.manifest().workspace_id.clone(), self.machine.clone()).map_err(error)?;
        if fresh != *cached || fresh.entry.head != parent || fresh.entry.checkout.as_ref().is_none_or(|checkout| checkout.base_version != parent) {
            return Err(fail("The checkout or archived base changed; refresh and recover the correct working folder"));
        }
        Ok(fresh)
    }
    /// Only a genuinely absent regular-file destination may be materialized.
    /// Permission errors, directories, links and reparse points remain failures.
    fn local_digest(&self, ws: &Workspace, document: &str) -> Result<Option<String>, Failure> {
        let path = ws.path(document).map_err(error)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(fail("The working copy cannot be inspected; check its permissions before updating")),
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(fail("The working-copy path is not a regular file"));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(fail("Working-copy reparse points are forbidden"));
                    }
                }
            }
        }
        ws.local_sha256(document).map(Some).map_err(error)
    }
    fn state(&self, ws: &Workspace, selected: Option<&str>) -> Result<ManagedState, Failure> {
        let client = self.client()?;
        let catalog = client.managed_catalog().map_err(error)?;
        if catalog.server_id != self.server_id {
            return Err(fail("The service identity changed; reconnect explicitly"));
        }
        let mut local = Vec::new();
        for (document, entry) in &ws.manifest().documents {
            let path = ws.path(document).map_err(error)?;
            let actual = ws.local_sha256(document);
            local.push(LocalEntry {
                document: document.clone(),
                path: path.to_string_lossy().into_owned(),
                relative_path: entry.relative_path.clone(),
                base_version: entry.base_version,
                sha256: entry.base_sha256.clone(),
                checked_out: entry.checked_out
                    && self.grants.get(document).is_some_and(|grant| {
                        catalog.entries.iter().any(|remote| {
                            remote.document == *document
                                && remote.head == Some(entry.base_version)
                                && remote.checkout.as_ref().is_some_and(|checkout| {
                                    checkout.workspace == ws.manifest().workspace_id
                                        && checkout.machine == self.machine
                                        && checkout.base_version == Some(entry.base_version)
                                })
                                && remote.checkout == grant.entry.checkout
                        })
                    }),
                modified: actual.as_ref().is_ok_and(|hash| hash != &entry.base_sha256),
                present: actual.is_ok(),
            });
        }
        let dependency_updates = dependency_updates(ws, &local, &catalog.entries);
        let recoverable_checkouts = catalog
            .entries
            .iter()
            .filter(|remote| {
                !ws.manifest().documents.contains_key(&remote.document)
                    && self.grants.get(&remote.document).is_some_and(|cached| {
                        remote.head == cached.entry.head
                            && remote.checkout == cached.entry.checkout
                            && remote
                                .checkout
                                .as_ref()
                                .is_some_and(|checkout| checkout.workspace == ws.manifest().workspace_id && checkout.machine == self.machine)
                            && client
                                .managed_resume_checkout(remote.document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone())
                                .is_ok_and(|fresh| fresh == *cached)
                    })
            })
            .take(solidcraft_pdm::MAX_VERSIONS)
            .map(|remote| remote.document.clone())
            .collect();
        let mut state = ManagedState {
            server_id: Some(self.server_id.clone()),
            root: Some(ws.root().to_string_lossy().into_owned()),
            workspace: Some(ws.manifest().workspace_id.clone()),
            catalog: convert::<Vec<CatalogEntry>>(catalog.entries)?,
            dependency_updates,
            recoverable_checkouts,
            local,
            history: vec![],
            where_used: vec![],
            preview: None,
            historical_paths: vec![],
        };
        if let Some(document) = selected {
            state.history = convert(client.managed_history(document.into()).map_err(error)?)?;
            if let Some(latest) = state.history.last() {
                state.preview = self.preview(&client, &latest.version.reference)?;
                let response = client
                    .request(solidcraft_pdm::Request::WhereUsed {
                        reference: VersionRef { document: document.into(), version: latest.version.reference.version },
                    })
                    .map_err(error)?;
                if let solidcraft_pdm::Response::WhereUsed { versions } = response {
                    state.where_used = convert::<Vec<Reference>>(versions)?;
                }
            }
        }
        Ok(state)
    }
    pub fn refresh(&self) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        let ws = self.workspace()?;
        Ok((Outcome::ManagedRefreshed { port: self.port, state: self.state(&ws, None)? }, None))
    }
    fn preview(&self, client: &Client, reference: &Reference) -> Result<Option<solidcraft_engine::pdm::Preview>, Failure> {
        let (version, bytes) = client.download(&VersionRef { document: reference.document.clone(), version: reference.version }).map_err(error)?;
        Ok(solidcraft_engine::io::read_design_thumbnail(&bytes).map(|png| solidcraft_engine::pdm::Preview {
            reference: reference.clone(),
            sha256: version.sha256,
            png,
        }))
    }
    fn target(&self, ws: &Workspace, document: Option<String>, path: Option<String>) -> Result<String, Failure> {
        if let Some(document) = document {
            return Ok(document);
        }
        let wanted = fs::canonicalize(path.ok_or_else(|| fail("Select an archived file"))?).map_err(|_| fail("The active file is unavailable"))?;
        for document in ws.manifest().documents.keys() {
            if fs::canonicalize(ws.path(document).map_err(error)?).ok().as_ref() == Some(&wanted) {
                return Ok(document.clone());
            }
        }
        Err(fail("The active design is not managed in this working folder"))
    }
    pub fn execute(&mut self, task: ManagedTask, default_root: Option<&Path>) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        if let ManagedTask::Recover { port, root } = &task {
            let client = Client::new(*port, AuthToken::from_env().map_err(error)?);
            let catalog = client.managed_catalog().map_err(error)?;
            let path = Path::new(root);
            if !path.is_absolute() {
                return Err(fail("Recovery requires an absolute workspace path"));
            }
            let mut workspace = Workspace::open_for_recovery(path, &catalog.server_id).map_err(error)?;
            for (document, entry) in &workspace.manifest().documents {
                let (version, _) = client.download(&VersionRef { document: document.clone(), version: entry.base_version }).map_err(error)?;
                if version.sha256 != entry.base_sha256 {
                    return Err(fail("Recovery refused: the recorded base does not match this server"));
                }
            }
            workspace.recover_pending(true).map_err(error)?;
            drop(workspace);
            return self.execute(ManagedTask::Connect { port: *port, root: Some(root.clone()) }, default_root);
        }
        if let ManagedTask::Connect { port, root } = task {
            let client = Client::new(port, AuthToken::from_env().map_err(error)?);
            let root = root
                .map(PathBuf::from)
                .or_else(|| default_root.map(|p| p.join("working")))
                .ok_or_else(|| fail("Choose an absolute working folder"))?;
            if !root.is_absolute() {
                return Err(fail("The working folder must be absolute"));
            }
            if let Some(parent) = root.parent() {
                fs::create_dir_all(parent).map_err(|_| fail("Could not create working folder parent"))?;
            }
            let prepared = Self::prepare_connection(client, &root, port, None)?;
            *self = prepared.host;
            return Ok((Outcome::Managed { port, state: prepared.state }, None));
        }
        let reconcile_only = matches!(&task, ManagedTask::ReconcileArchive { .. });
        let task = match task {
            ManagedTask::ReconcileArchive { path, logical_path, saved, visibility } => ManagedTask::Archive { path, logical_path, saved, visibility },
            other => other,
        };
        let client = self.client()?;
        if client.managed_catalog().map_err(error)?.server_id != self.server_id {
            return Err(fail("The service identity changed; reconnect before modifying this workspace"));
        }
        let mut ws = self.workspace()?;
        let mut opened = None;
        let selected = match task {
            ManagedTask::ListConnections
            | ManagedTask::CreateLocal { .. }
            | ManagedTask::OpenConnection { .. }
            | ManagedTask::RecoverConnection { .. } => {
                return Err(fail("Connection setup requires the native connection controller"));
            }
            ManagedTask::Recover { .. } => return Err(fail("Invalid recovery state")),
            ManagedTask::Preview { reference } => {
                let mut state = self.state(&ws, Some(&reference.document))?;
                state.preview = self.preview(&client, &reference)?;
                let response = client
                    .request(solidcraft_pdm::Request::WhereUsed {
                        reference: VersionRef { document: reference.document, version: reference.version },
                    })
                    .map_err(error)?;
                if let solidcraft_pdm::Response::WhereUsed { versions } = response {
                    state.where_used = convert(versions)?;
                }
                return Ok((Outcome::Managed { port: self.port, state }, None));
            }
            ManagedTask::Restore { reference } => {
                let local = ws
                    .manifest()
                    .documents
                    .get(&reference.document)
                    .cloned()
                    .ok_or_else(|| fail("Retrieve this document into the working folder before restoring history"))?;
                if local.checked_out || ws.local_sha256(&reference.document).map_err(error)? != local.base_sha256 {
                    return Err(fail("Restore refused: the local copy is modified or checked out"));
                }
                let requested = VersionRef { document: reference.document.clone(), version: reference.version };
                let (source, bytes) = client.download(&requested).map_err(error)?;
                if source.reference != requested || hash(&bytes) != source.sha256 {
                    return Err(fail("Historical content integrity verification failed"));
                }
                solidcraft_engine::io::read_design(&bytes).map_err(|_| fail("The historical version is not a readable native design"))?;
                let history = client.managed_history(reference.document.clone()).map_err(error)?;
                let receipt = restore_receipt(&ws.manifest().workspace_id, &reference, local.base_version, &source.sha256, &source.dependencies)?;
                // Check receipts before acquiring a grant. This covers a lost publication reply
                // and retries after the local manifest has already advanced to the restored head.
                let published = history.into_iter().find(|version| {
                    if version.version.sha256 != source.sha256 || version.version.dependencies != source.dependencies {
                        return false;
                    }
                    version.request_id == receipt
                        || (version.version.reference.version == local.base_version
                            && version.version.sha256 == local.base_sha256
                            && version.version.parent.is_some_and(|parent| {
                                restore_receipt(&ws.manifest().workspace_id, &reference, parent, &source.sha256, &source.dependencies)
                                    .is_ok_and(|id| id == version.request_id)
                            }))
                });
                let remote = client
                    .managed_catalog()
                    .map_err(error)?
                    .entries
                    .into_iter()
                    .find(|entry| entry.document == reference.document)
                    .ok_or_else(|| fail("The archived document is missing"))?;
                let published = match published {
                    Some(version) => {
                        if remote.head != Some(version.version.reference.version) {
                            return Err(fail("Restore was already published, but a newer head exists; update the working copy first"));
                        }
                        version
                    }
                    None => {
                        if remote.head != Some(local.base_version) {
                            return Err(fail("Restore refused: update the clean working copy to the current head first"));
                        }
                        let grant = if self.grants.contains_key(&reference.document) {
                            self.verified_grant(&client, &ws, &reference.document, Some(local.base_version))?
                        } else {
                            client
                                .managed_checkout(reference.document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone())
                                .map_err(error)?
                        };
                        self.grants.insert(reference.document.clone(), grant.clone());
                        if grant.entry.head != Some(local.base_version) {
                            return Err(fail("The archive changed before restore; your checkout is preserved for reconciliation"));
                        }
                        client
                            .managed_check_in(ManagedCheckIn {
                                document: reference.document.clone(),
                                workspace: ws.manifest().workspace_id.clone(),
                                machine: self.machine.clone(),
                                checkout_token: grant.token,
                                request_id: receipt,
                                parent: Some(local.base_version),
                                content: bytes.clone(),
                                dependencies: source.dependencies.clone(),
                                comment: format!("Restore archived version {}", reference.version),
                            })
                            .map_err(error)?
                    }
                };
                if local.base_version != published.version.reference.version {
                    ws.install(&reference.document, &local.relative_path, published.version.reference.version, &published.version.sha256, &bytes)
                        .map_err(error)?;
                }
                self.grants.remove(&reference.document);
                // This is the normal managed path; runtime and filesystem permissions
                // enforce readonly until checkout. The historical flag is snapshot-only.
                opened = Some(load(&ws.path(&reference.document).map_err(error)?)?);
                Some(reference.document)
            }
            ManagedTask::OpenArchived { reference } => {
                let catalog = client.managed_catalog().map_err(error)?;
                let entries: BTreeMap<_, _> = catalog.entries.into_iter().map(|entry| (entry.document.clone(), entry)).collect();
                let mut entropy = [0u8; 16];
                getrandom::fill(&mut entropy).map_err(|_| fail("Could not allocate historical snapshot"))?;
                let name: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
                let destination = ws.root().parent().ok_or_else(|| fail("Snapshot parent unavailable"))?.join(format!("history-{name}"));
                let mut history = Workspace::create(&destination, &self.server_id).map_err(error)?;
                let mut queue = vec![VersionRef { document: reference.document.clone(), version: reference.version }];
                let mut resolved = BTreeMap::new();
                while let Some(requested) = queue.pop() {
                    if let Some(previous) = resolved.get(&requested.document) {
                        if *previous != requested.version {
                            return Err(fail("Historical graph needs multiple versions at one path; this snapshot cannot be opened safely"));
                        }
                        continue;
                    }
                    if resolved.len() >= 256 {
                        return Err(fail("Historical dependency limit exceeded"));
                    }
                    let entry = entries.get(&requested.document).ok_or_else(|| fail("Historical document metadata missing"))?;
                    let (metadata, bytes) = client.download(&requested).map_err(error)?;
                    history.install(&requested.document, &entry.logical_path, requested.version, &metadata.sha256, &bytes).map_err(error)?;
                    resolved.insert(requested.document, requested.version);
                    queue.extend(metadata.dependencies);
                }
                let mut session = load(&history.path(&reference.document).map_err(error)?)?;
                session.pdm_read_only = true;
                opened = Some(session);
                let mut state = self.state(&ws, Some(&reference.document))?;
                state.historical_paths = history
                    .manifest()
                    .documents
                    .keys()
                    .map(|document| history.path(document).map(|path| path.to_string_lossy().into_owned()).map_err(error))
                    .collect::<Result<_, _>>()?;
                return Ok((Outcome::Managed { port: self.port, state }, opened));
            }
            ManagedTask::Connect { .. } | ManagedTask::ReconcileArchive { .. } => return Err(fail("Invalid connection state")),
            ManagedTask::History { document } => Some(document),
            ManagedTask::Archive { path, logical_path, saved, visibility } => {
                let bytes = read_file(Path::new(&path), solidcraft_pdm::MAX_CONTENT).map_err(error)?;
                super::pdm::validate_saved(&bytes, &saved, &visibility)?;
                let absolute = fs::canonicalize(&path).map_err(|_| fail("Saved design unavailable"))?;
                let relative = absolute
                    .strip_prefix(ws.root())
                    .map_err(|_| fail("Save the design inside the configured working folder before archiving"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                if logical_path.as_ref().is_some_and(|p| !p.is_empty() && p != &relative) {
                    return Err(fail("The archive path must match the saved path inside the working folder"));
                }
                let entry = if reconcile_only {
                    client
                        .managed_catalog()
                        .map_err(error)?
                        .entries
                        .into_iter()
                        .find(|entry| entry.logical_path == relative)
                        .ok_or_else(|| fail("No archived publication exists for this path; reconciliation cannot create one"))?
                } else {
                    client.managed_create(relative.clone()).map_err(error)?
                };
                let existing = ws.manifest().documents.get(&entry.document).cloned();
                let dependencies = dependencies(&client, &ws, &path, &saved)?;
                let parent = existing.as_ref().map(|e| e.base_version);
                let mut receipt_bytes =
                    serde_json::to_vec(&(ws.manifest().workspace_id.clone(), entry.document.clone(), parent, hash(&bytes), &dependencies))
                        .map_err(|_| fail("Could not identify publication"))?;
                let request_id = hash(&receipt_bytes);
                receipt_bytes.clear();
                // Receipts are scoped to the current authenticated principal as well
                // as this exact workspace, base and payload. Never reconcile another
                // account's publication merely because its public metadata is visible.
                let principal = match client.request(solidcraft_pdm::Request::Identity {}).map_err(error)? {
                    solidcraft_pdm::Response::Identity { identity } if identity.server_id == self.server_id => identity.principal.id,
                    _ => return Err(fail("Could not confirm the publication account")),
                };
                // Reconcile an acknowledged-on-server publication before obtaining a new lock.
                let published = client
                    .managed_history(entry.document.clone())
                    .map_err(error)?
                    .into_iter()
                    .find(|v| v.request_id == request_id && v.version.sha256 == hash(&bytes) && v.author == principal);
                let published = match published {
                    Some(version) => {
                        if entry.head != Some(version.version.reference.version) {
                            return Err(fail("The publication was acknowledged, but a newer archived version exists; update the working copy first"));
                        }
                        version
                    }
                    None if reconcile_only => {
                        return Err(fail(
                            "No matching publication receipt exists for this account, working folder, base and saved design; no checkout or version was created",
                        ));
                    }
                    None => {
                        let grant = if self.grants.contains_key(&entry.document) {
                            if existing.as_ref().is_some_and(|entry| !entry.checked_out) {
                                return Err(fail("This working copy is not checked out; refresh before archiving"));
                            }
                            self.verified_grant(&client, &ws, &entry.document, parent)?
                        } else {
                            if existing.is_some() {
                                return Err(fail("Check out this managed design before archiving changes"));
                            }
                            if entry.head.is_some() {
                                return Err(fail("This path is already archived; open its working copy before checking out and archiving changes"));
                            }
                            let grant = client
                                .managed_checkout(entry.document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone())
                                .map_err(error)?;
                            self.grants.insert(entry.document.clone(), grant.clone());
                            grant
                        };
                        client
                            .managed_check_in(ManagedCheckIn {
                                document: entry.document.clone(),
                                workspace: ws.manifest().workspace_id.clone(),
                                machine: self.machine.clone(),
                                checkout_token: grant.token,
                                request_id,
                                parent,
                                content: bytes,
                                dependencies,
                                comment: String::new(),
                            })
                            .map_err(error)?
                    }
                };
                if existing.is_some() {
                    ws.record_checkin(&entry.document, published.version.reference.version, &published.version.sha256).map_err(error)?;
                } else {
                    ws.adopt(&entry.document, &relative, published.version.reference.version, &published.version.sha256).map_err(error)?;
                }
                self.grants.remove(&entry.document);
                Some(entry.document)
            }
            ManagedTask::Checkout { document, path } => {
                let document = self.target(&ws, document, path)?;
                let remote = client
                    .managed_catalog()
                    .map_err(error)?
                    .entries
                    .into_iter()
                    .find(|entry| entry.document == document)
                    .ok_or_else(|| fail("The archived document is missing"))?;
                if remote.checkout.is_some() {
                    return Err(fail("This design is already checked out; refresh to see its owner and working folder"));
                }
                if let Some(local) = ws.manifest().documents.get(&document)
                    && (local.checked_out || self.local_digest(&ws, &document)?.is_some_and(|actual| actual != local.base_sha256))
                {
                    return Err(fail("Checkout refused: preserve local changes and refresh the working copy first"));
                }
                let grant = client.managed_checkout(document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone()).map_err(error)?;
                self.grants.insert(document.clone(), grant.clone());
                let installed = if let Some(entry) = ws.manifest().documents.get(&document) {
                    Some(entry.base_version) == grant.entry.head
                        && self.local_digest(&ws, &document)?.is_some_and(|actual| actual == entry.base_sha256)
                } else {
                    false
                };
                if !installed {
                    self.install_graph(&client, &mut ws, &document)?;
                }
                ws.checkout(&document).map_err(error)?;
                opened = Some(load(&ws.path(&document).map_err(error)?)?);
                Some(document)
            }
            ManagedTask::GetLatest { document, path } => {
                let document = self.target(&ws, document, path)?;
                if !self.install_graph(&client, &mut ws, &document)? {
                    return Err(fail("The working copy and its managed components are already up to date"));
                }
                let mut loaded = load(&ws.path(&document).map_err(error)?)?;
                if !loaded.doc.links.is_empty() {
                    loaded
                        .execute("component.update_links", &serde_json::json!({}))
                        .map_err(|_| fail("Files retrieved; assembly update failed. Review links before saving"))?;
                }
                opened = Some(loaded);
                Some(document)
            }
            ManagedTask::Open { document } => {
                if !ws.manifest().documents.contains_key(&document) || self.local_digest(&ws, &document)?.is_none() {
                    self.install_graph(&client, &mut ws, &document)?;
                }
                let mut loaded = load(&ws.path(&document).map_err(error)?)?;
                if !loaded.doc.links.is_empty() {
                    loaded
                        .execute("component.update_links", &serde_json::json!({}))
                        .map_err(|_| fail("The working assembly could not update its local components"))?;
                }
                opened = Some(loaded);
                Some(document)
            }
            ManagedTask::CancelCheckout { document, path } => {
                let document = self.target(&ws, document, path)?;
                let parent = ws
                    .manifest()
                    .documents
                    .get(&document)
                    .map(|entry| entry.base_version)
                    .or_else(|| self.grants.get(&document).and_then(|grant| grant.entry.head));
                let grant = self.verified_grant(&client, &ws, &document, parent)?;
                if !ws.manifest().documents.contains_key(&document) {
                    client
                        .managed_cancel_checkout(document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone(), grant.token)
                        .map_err(error)?;
                    self.grants.remove(&document);
                    return Ok((Outcome::Managed { port: self.port, state: self.state(&ws, Some(&document))? }, None));
                }
                let entry = ws.manifest().documents.get(&document).cloned().ok_or_else(|| fail("Working copy is missing"))?;
                let (_, bytes) = client.download(&VersionRef { document: document.clone(), version: entry.base_version }).map_err(error)?;
                ws.undo_checkout(&document, &bytes, true).map_err(error)?;
                let reserved = client
                    .managed_catalog()
                    .map_err(error)?
                    .entries
                    .into_iter()
                    .find(|e| e.document == document)
                    .is_some_and(|e| e.checkout.as_ref().is_some_and(|checkout| Some(checkout) == grant.entry.checkout.as_ref()));
                if reserved {
                    client
                        .managed_cancel_checkout(document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone(), grant.token)
                        .map_err(error)?;
                }
                self.grants.remove(&document);
                opened = Some(load(&ws.path(&document).map_err(error)?)?);
                Some(document)
            }
        };
        Ok((Outcome::Managed { port: self.port, state: self.state(&ws, selected.as_deref())? }, opened))
    }

    fn install_graph(&self, client: &Client, ws: &mut Workspace, root: &str) -> Result<bool, Failure> {
        let catalog = client.managed_catalog().map_err(error)?;
        let entries: BTreeMap<_, _> = catalog.entries.into_iter().map(|e| (e.document.clone(), e)).collect();
        let mut queue = vec![root.to_string()];
        let mut seen = BTreeSet::new();
        let mut downloads = Vec::new();
        while let Some(document) = queue.pop() {
            if !seen.insert(document.clone()) {
                continue;
            }
            if seen.len() > 256 {
                return Err(fail("Assembly exceeds managed dependency limit"));
            }
            let entry = entries.get(&document).ok_or_else(|| fail("A managed dependency is missing"))?;
            let version = entry.head.ok_or_else(|| fail("The selected document has no archived version"))?;
            if let Some(old) = ws.manifest().documents.get(&document)
                && (old.checked_out || self.local_digest(ws, &document)?.is_some_and(|actual| actual != old.base_sha256))
            {
                return Err(fail("Update refused: a local dependency is modified or checked out"));
            }
            let (metadata, bytes) = client.download(&VersionRef { document: document.clone(), version }).map_err(error)?;
            if hash(&bytes) != metadata.sha256 {
                return Err(fail("Dependency integrity verification failed"));
            }
            queue.extend(metadata.dependencies.iter().map(|r| r.document.clone()));
            downloads.push((entry.clone(), metadata, bytes));
        }
        let changed = downloads.iter().any(|(entry, metadata, _)| {
            ws.manifest()
                .documents
                .get(&entry.document)
                .is_none_or(|local| local.base_version != metadata.reference.version || local.base_sha256 != metadata.sha256)
                || ws.local_sha256(&entry.document).is_err()
        });
        if !changed {
            return Ok(false);
        }
        // Every participating file is checked before any replacement. Each individual
        // installation is journaled; a later I/O failure leaves accurately recorded bases.
        for (entry, metadata, bytes) in downloads {
            ws.install(&entry.document, &entry.logical_path, metadata.reference.version, &metadata.sha256, &bytes).map_err(error)?;
        }
        Ok(true)
    }
}

fn dependency_updates(ws: &Workspace, local: &[LocalEntry], catalog: &[solidcraft_pdm::managed::CatalogEntry]) -> Vec<String> {
    let path_key =
        |path: &Path| solidcraft_engine::pdm::cached_path_key(&fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()).to_string_lossy());
    let paths: BTreeMap<_, _> = local.iter().map(|entry| (path_key(Path::new(&entry.path)), entry.document.clone())).collect();
    let mut graph = BTreeMap::new();
    for entry in local {
        let links: Vec<String> = ws
            .path(&entry.document)
            .ok()
            .and_then(|path| {
                read_file(&path, solidcraft_pdm::MAX_CONTENT)
                    .ok()
                    .and_then(|bytes| solidcraft_engine::io::read_design(&bytes).ok())
                    .map(|document| (path, document))
            })
            .map(|(path, document)| {
                document
                    .links
                    .values()
                    .filter_map(|link| path.parent().and_then(|parent| paths.get(&path_key(&parent.join(&link.path))).cloned()))
                    .collect()
            })
            .unwrap_or_default();
        graph.insert(entry.document.clone(), links);
    }
    let outdated: BTreeSet<_> = local
        .iter()
        .filter(|entry| {
            !entry.present
                || catalog.iter().find(|remote| remote.document == entry.document).is_none_or(|remote| remote.head != Some(entry.base_version))
        })
        .map(|entry| entry.document.as_str())
        .collect();
    local
        .iter()
        .filter(|root| {
            let mut queue = graph.get(&root.document).cloned().unwrap_or_default();
            let mut seen = BTreeSet::new();
            while let Some(document) = queue.pop() {
                if !seen.insert(document.clone()) {
                    continue;
                }
                if outdated.contains(document.as_str()) {
                    return true;
                }
                if seen.len() >= 256 {
                    return true;
                }
                queue.extend(graph.get(&document).into_iter().flatten().cloned());
            }
            false
        })
        .map(|entry| entry.document.clone())
        .collect()
}

fn restore_receipt(workspace: &str, reference: &Reference, parent: u64, sha256: &str, dependencies: &[VersionRef]) -> Result<String, Failure> {
    let bytes = serde_json::to_vec(&("managed-restore/1", workspace, &reference.document, reference.version, parent, sha256, dependencies))
        .map_err(|_| fail("Could not identify historical restoration"))?;
    Ok(hash(&bytes))
}
fn load(path: &Path) -> Result<Box<Session>, Failure> {
    let mut session = Session::default();
    session.execute("doc.open", &serde_json::json!({"path":path})).map_err(|_| fail("The managed copy is not a readable native design"))?;
    Ok(Box::new(session))
}

fn dependencies(
    client: &Client,
    ws: &Workspace,
    path: &str,
    saved: &std::sync::Arc<solidcraft_engine::doc::Document>,
) -> Result<Vec<VersionRef>, Failure> {
    let mut references = BTreeSet::new();
    for link in saved.links.values() {
        let source = Path::new(path).parent().ok_or_else(|| fail("Saved design has no folder"))?.join(&link.path);
        let source = fs::canonicalize(source).map_err(|_| fail("A linked native component is missing"))?;
        let document = ws
            .manifest()
            .documents
            .keys()
            .find(|document| ws.path(document).ok().and_then(|p| fs::canonicalize(p).ok()).as_ref() == Some(&source))
            .ok_or_else(|| fail("Archive each linked component in this workspace before archiving the assembly"))?;
        let entry = ws.manifest().documents.get(document).ok_or_else(|| fail("Dependency metadata is missing"))?;
        if ws.local_sha256(document).map_err(error)? != entry.base_sha256 {
            return Err(fail("Archive local component edits before archiving the assembly"));
        }
        let reference = VersionRef { document: document.clone(), version: entry.base_version };
        let (version, bytes) = client.download(&reference).map_err(error)?;
        if version.sha256 != entry.base_sha256 || hash(&bytes) != entry.base_sha256 {
            return Err(fail("Dependency base does not match the archived content"));
        }
        references.insert(reference);
    }
    if !saved.links.is_empty() {
        let mut probe = Session::default();
        probe.doc = saved.clone();
        probe.path = Some(path.into());
        probe.execute("component.update_links", &serde_json::json!({})).map_err(|_| fail("Could not validate the assembly's consumed components"))?;
        if *probe.doc != **saved {
            return Err(fail("Update native links and save the assembly before archiving; its embedded components are out of date"));
        }
    }
    Ok(references.into_iter().collect())
}

pub struct AuthenticatedHost {
    pub host: Host,
    pub port: u16,
    pub state: ManagedState,
}

impl Host {
    pub fn connect_authenticated(session: crate::pdm_login::AuthenticatedSession, root: &Path, recover: bool) -> Result<AuthenticatedHost, Failure> {
        if !root.is_absolute() || root.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
            return Err(fail("The working folder must be absolute"));
        }
        // Do not trust a manually assembled AuthenticatedSession's public fields.
        let actual = session.client.authenticated_identity().map_err(error)?;
        if actual != session.identity || actual.server_id != session.profile.server_id() || actual.principal.id != session.profile.principal_id() {
            return Err(fail("PDM authenticated identity changed; sign in again"));
        }
        let origin: ureq::http::Uri = session.profile.origin().parse().map_err(|_| fail("Invalid PDM HTTPS origin"))?;
        let port = origin.port_u16().unwrap_or(443);
        if recover {
            let catalog = session.client.managed_catalog().map_err(error)?;
            let mut workspace = Workspace::open_for_recovery(root, &catalog.server_id).map_err(error)?;
            for (document, entry) in &workspace.manifest().documents {
                let (version, _) = session.client.download(&VersionRef { document: document.clone(), version: entry.base_version }).map_err(error)?;
                if version.sha256 != entry.base_sha256 {
                    return Err(fail("Recovery refused: the recorded base does not match this server"));
                }
            }
            workspace.recover_pending(true).map_err(error)?;
        }
        Self::prepare_connection(session.client, root, port, Some(&actual.principal.id))
    }

    fn prepare_connection(client: Client, root: &Path, port: u16, principal: Option<&str>) -> Result<AuthenticatedHost, Failure> {
        if !root.is_absolute() || root.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
            return Err(fail("The working folder must be absolute"));
        }
        let catalog = client.managed_catalog().map_err(error)?;
        // The native controller/index creates the fixed private parent. This
        // helper never recursively creates arbitrary user-selected ancestors.
        let ws = if root.join(".solidcraft-pdm").try_exists().map_err(|_| fail("Working folder unavailable"))? {
            Workspace::open(root, &catalog.server_id)
        } else {
            Workspace::create(root, &catalog.server_id)
        }
        .map_err(error)?;
        let machine = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "desktop".into());
        let mut candidate =
            Self { client: Some(client.clone()), port, root: Some(ws.root().into()), server_id: catalog.server_id, machine, grants: BTreeMap::new() };
        for entry in catalog.entries {
            if entry.checkout.as_ref().is_some_and(|checkout| {
                checkout.workspace == ws.manifest().workspace_id
                    && checkout.machine == candidate.machine
                    && principal.is_none_or(|principal| checkout.owner == principal)
            }) {
                // A missing or changed reservation stays readonly. Connecting
                // cannot create a checkout, rotate a token, or publish metadata.
                if let Ok(grant) =
                    client.managed_resume_checkout(entry.document.clone(), ws.manifest().workspace_id.clone(), candidate.machine.clone())
                {
                    candidate.grants.insert(entry.document, grant);
                }
            }
        }
        let state = candidate.state(&ws, None)?;
        Ok(AuthenticatedHost { host: candidate, port, state })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct Trial {
        root: PathBuf,
        port: u16,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Trial {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("solidcraft-managed-native-{}-{}", std::process::id(), AuthToken::generate().unwrap()));
            fs::create_dir(&root).unwrap();
            let mut store = solidcraft_pdm::Store::open(&root.join("store")).unwrap();
            let listener = solidcraft_pdm::bind_loopback(0).unwrap();
            let port = listener.local_addr().unwrap().port();
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = stop.clone();
            let thread = std::thread::spawn(move || {
                for connection in listener.incoming() {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    if let Ok(stream) = connection {
                        let _ = solidcraft_pdm::serve_connection(&mut store, stream, &token());
                    }
                }
            });
            Self { root, port, stop, thread: Some(thread) }
        }
        fn host(&self, name: &str) -> Host {
            let client = Client::new(self.port, token());
            let catalog = client.managed_catalog().unwrap();
            let root = self.root.join(name);
            let ws = Workspace::create(&root, &catalog.server_id).unwrap();
            drop(ws);
            Host {
                client: Some(client),
                port: self.port,
                root: Some(root),
                server_id: catalog.server_id,
                machine: "test-desktop".into(),
                grants: BTreeMap::new(),
            }
        }
    }
    impl Drop for Trial {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, self.port));
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            // Restore permissions only inside the unique disposable test directory.
            fn writable(path: &Path) {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_dir() {
                            writable(&p);
                        } else if let Ok(meta) = fs::metadata(&p) {
                            let mut permissions = meta.permissions();
                            #[allow(clippy::permissions_set_readonly_false)]
                            permissions.set_readonly(false);
                            let _ = fs::set_permissions(&p, permissions);
                        }
                    }
                }
            }
            writable(&self.root);
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn token() -> AuthToken {
        AuthToken::parse("ab".repeat(32)).unwrap()
    }
    fn run(host: &mut Host, task: ManagedTask) -> (Outcome, Option<Box<Session>>) {
        host.execute(task, None).unwrap_or_else(|e| panic!("{}", e.message))
    }
    fn archive(host: &mut Host, session: &Session) -> String {
        let (outcome, _) = run(
            host,
            ManagedTask::Archive {
                path: session.path.clone().unwrap(),
                logical_path: None,
                saved: session.doc.clone(),
                visibility: Box::new(session.visibility.clone()),
            },
        );
        match outcome {
            Outcome::Managed { state, .. } => state
                .local
                .iter()
                .find(|e| session.path.as_deref().is_some_and(|path| solidcraft_engine::pdm::same_file_path(&e.path, path)))
                .unwrap()
                .document
                .clone(),
            _ => panic!("unexpected outcome"),
        }
    }
    fn remove_copy(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
        fs::remove_file(path).unwrap();
    }
    fn part(path: &Path) -> Session {
        let mut session = Session::default();
        session.execute("solid.box", &serde_json::json!({"length":10,"width":20,"height":3})).unwrap();
        session.execute("file.save", &serde_json::json!({"path":path})).unwrap();
        session
    }
    #[test]
    fn failed_guided_holder_commit_preserves_existing_host_and_checkout_authority() {
        let trial = Trial::new();
        let mut host = trial.host("original");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut host, &design);
        run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let before_root = host.root.clone();
        let before_server = host.server_id.clone();
        let grant = host.grants.get(&document).unwrap().clone();
        let holder = std::sync::Mutex::new(Some(host.client().unwrap()));
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = holder.lock().unwrap();
            panic!("test-only holder poisoning");
        }));
        assert!(poisoned.is_err());
        let candidate = trial.host("candidate");
        let failure = super::super::pdm::commit_guided_host(&mut host, &holder, candidate).unwrap_err();
        assert!(!failure.disconnect);
        assert_eq!(host.root, before_root);
        assert_eq!(host.server_id, before_server);
        assert!(host.grants.get(&document).unwrap() == &grant);
        let client = host.client().unwrap();
        assert!(client.managed_catalog().unwrap().entries.iter().any(|entry| entry.document == document && entry.checkout == grant.entry.checkout));
        let ws = host.workspace().unwrap();
        assert!(host.state(&ws, None).unwrap().local.iter().any(|entry| entry.document == document && entry.checked_out));
    }

    #[test]
    fn managed_native_keeps_one_path_excludes_other_workspace_and_opens_history_separately() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let mut other = trial.host("other");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let session = part(&path);
        let original = fs::read(&path).unwrap();
        let document = archive(&mut host, &session);
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        let (_, loaded) = run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let mut session = *loaded.unwrap();
        assert!(solidcraft_engine::pdm::same_file_path(session.path.as_ref().unwrap(), path.to_str().unwrap()));
        assert!(other.execute(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None).is_err());
        session.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        session.execute("file.save", &serde_json::json!({})).unwrap();
        archive(&mut host, &session);
        assert_eq!(host.client().unwrap().managed_history(document.clone()).unwrap().len(), 2);
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        let (outcome, loaded) = run(&mut host, ManagedTask::OpenArchived { reference: Reference { document, version: 1 } });
        let historic = loaded.unwrap();
        assert_ne!(historic.path.as_ref(), session.path.as_ref());
        assert!(historic.pdm_read_only);
        let Outcome::Managed { state, .. } = outcome else { panic!("expected managed snapshot") };
        assert_eq!(state.historical_paths, vec![historic.path.clone().unwrap()]);
        assert_eq!(fs::read(historic.path.unwrap()).unwrap(), original);
        assert_ne!(fs::read(&path).unwrap(), original);
    }
    #[test]
    fn undo_restores_same_path_and_dirty_get_latest_preserves_disk_bytes() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let session = part(&path);
        let original = fs::read(&path).unwrap();
        let document = archive(&mut host, &session);
        let (_, loaded) = run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let mut session = *loaded.unwrap();
        session.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        session.execute("file.save", &serde_json::json!({})).unwrap();
        let edited = fs::read(&path).unwrap();
        assert!(host.execute(ManagedTask::GetLatest { document: Some(document.clone()), path: None }, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), edited);
        run(&mut host, ManagedTask::CancelCheckout { document: Some(document.clone()), path: None });
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(host.client().unwrap().managed_catalog().unwrap().entries.into_iter().find(|e| e.document == document).unwrap().checkout.is_none());
        assert_eq!(host.client().unwrap().managed_history(document).unwrap().len(), 1);
    }

    #[test]
    fn working_assembly_updates_components_while_historical_manifest_retains_consumed_versions() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let mut other = trial.host("other");
        let root = host.root.clone().unwrap();
        let part_path = root.join("part.solidcraft");
        let original_part = part(&part_path);
        let part_id = archive(&mut host, &original_part);
        let assembly_path = root.join("assembly.solidcraft");
        let mut assembly = Session::default();
        assembly.execute("file.save", &serde_json::json!({"path":assembly_path})).unwrap();
        assembly.execute("component.insert_design", &serde_json::json!({"path":part_path})).unwrap();
        assembly.execute("file.save", &serde_json::json!({})).unwrap();
        let original_doc = assembly.doc.clone();
        let assembly_id = archive(&mut host, &assembly);
        run(&mut other, ManagedTask::Open { document: assembly_id.clone() });
        let archived = host.client().unwrap().managed_history(assembly_id.clone()).unwrap();
        assert_eq!(archived[0].version.dependencies, vec![VersionRef { document: part_id.clone(), version: 1 }]);
        let (_, part_copy) = run(&mut host, ManagedTask::Checkout { document: Some(part_id.clone()), path: None });
        let mut changed = *part_copy.unwrap();
        changed.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        changed.execute("file.save", &serde_json::json!({})).unwrap();
        // Local saved component changes propagate without a check-in.
        assembly.execute("component.update_links", &serde_json::json!({})).unwrap();
        assert_ne!(*assembly.doc, *original_doc);
        archive(&mut host, &changed);
        remove_copy(&other.root.as_ref().unwrap().join("part.solidcraft"));
        let ws = other.workspace().unwrap();
        let state = other.state(&ws, None).unwrap();
        assert!(state.dependency_updates.contains(&assembly_id));
        drop(ws);
        let (_, working) = run(&mut other, ManagedTask::GetLatest { document: Some(assembly_id.clone()), path: None });
        let working = working.unwrap();
        assert_ne!(*working.doc, *original_doc);
        assert!(working.is_dirty());
        let (_, historic) = run(&mut host, ManagedTask::OpenArchived { reference: Reference { document: assembly_id, version: 1 } });
        let historic = historic.unwrap();
        assert_eq!(*historic.doc, *original_doc);
        assert!(historic.pdm_read_only);
        let history_root = Path::new(historic.path.as_ref().unwrap()).parent().unwrap();
        assert_eq!(
            fs::read(history_root.join("part.solidcraft")).unwrap(),
            host.client().unwrap().download(&VersionRef { document: part_id, version: 1 }).unwrap().1
        );
    }
    #[test]
    fn restore_history_publishes_new_head_once_and_preserves_normal_path() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let original = part(&path);
        let original_bytes = fs::read(&path).unwrap();
        let document = archive(&mut host, &original);
        let (_, loaded) = run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let mut changed = *loaded.unwrap();
        changed.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        changed.execute("file.save", &serde_json::json!({})).unwrap();
        let changed_bytes = fs::read(&path).unwrap();
        archive(&mut host, &changed);
        let task = ManagedTask::Restore { reference: Reference { document: document.clone(), version: 1 } };
        let (_, loaded) = run(&mut host, task.clone());
        let restored = loaded.unwrap();
        assert!(solidcraft_engine::pdm::same_file_path(restored.path.as_ref().unwrap(), path.to_str().unwrap()));
        assert!(!restored.pdm_read_only);
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        let history = host.client().unwrap().managed_history(document.clone()).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[2].version.parent, Some(2));
        assert_eq!(history[2].version.reference.version, 3);
        assert_eq!(host.client().unwrap().download(&VersionRef { document: document.clone(), version: 2 }).unwrap().1, changed_bytes);
        run(&mut host, task.clone());
        assert_eq!(host.client().unwrap().managed_history(document.clone()).unwrap().len(), 3);
        let (_, editable) = run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let editable = editable.unwrap();
        assert!(!editable.pdm_read_only);
        assert!(solidcraft_engine::pdm::same_file_path(editable.path.as_ref().unwrap(), path.to_str().unwrap()));
        assert!(!fs::metadata(&path).unwrap().permissions().readonly());
        assert!(
            host.client()
                .unwrap()
                .managed_catalog()
                .unwrap()
                .entries
                .into_iter()
                .find(|entry| entry.document == document)
                .unwrap()
                .checkout
                .is_some()
        );
        run(&mut host, ManagedTask::CancelCheckout { document: Some(document.clone()), path: None });
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
        assert_eq!(host.client().unwrap().managed_history(document.clone()).unwrap().len(), 3);
        assert!(
            host.client()
                .unwrap()
                .managed_catalog()
                .unwrap()
                .entries
                .into_iter()
                .find(|entry| entry.document == document)
                .unwrap()
                .checkout
                .is_none()
        );
        // Simulate an external edit bypassing the readonly convenience bit.
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
        fs::write(&path, b"external unsaved-to-archive edits").unwrap();
        assert!(host.execute(task, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"external unsaved-to-archive edits");
        assert_eq!(host.client().unwrap().managed_history(document).unwrap().len(), 3);
    }

    #[test]
    fn restore_reconciles_lost_publish_reply_before_acquiring_another_grant() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let original = part(&path);
        let document = archive(&mut host, &original);
        let (_, loaded) = run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let mut changed = *loaded.unwrap();
        changed.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        changed.execute("file.save", &serde_json::json!({})).unwrap();
        archive(&mut host, &changed);
        let client = host.client().unwrap();
        let reference = Reference { document: document.clone(), version: 1 };
        let (source, bytes) = client.download(&VersionRef { document: document.clone(), version: 1 }).unwrap();
        let ws = host.workspace().unwrap();
        let workspace = ws.manifest().workspace_id.clone();
        let receipt = restore_receipt(&workspace, &reference, 2, &source.sha256, &source.dependencies).unwrap();
        drop(ws);
        let grant = client.managed_checkout(document.clone(), workspace.clone(), host.machine.clone()).unwrap();
        // The server commits, but the caller loses its response and does not change local state.
        client
            .managed_check_in(ManagedCheckIn {
                document: document.clone(),
                workspace,
                machine: host.machine.clone(),
                checkout_token: grant.token,
                request_id: receipt,
                parent: Some(2),
                content: bytes.clone(),
                dependencies: source.dependencies,
                comment: "Restore archived version 1".into(),
            })
            .unwrap();
        assert_eq!(host.workspace().unwrap().manifest().documents.get(&document).unwrap().base_version, 2);
        // A different workspace may acquire a new grant after publication. Reconciliation
        // must not attempt to acquire it or release this other workspace's reservation.
        let other = trial.host("other");
        let other_ws = other.workspace().unwrap();
        let other_grant = client.managed_checkout(document.clone(), other_ws.manifest().workspace_id.clone(), other.machine.clone()).unwrap();
        drop(other_ws);
        run(&mut host, ManagedTask::Restore { reference });
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        assert_eq!(client.managed_history(document.clone()).unwrap().len(), 3);
        assert_eq!(
            client.managed_catalog().unwrap().entries.into_iter().find(|e| e.document == document).unwrap().checkout,
            other_grant.entry.checkout
        );
    }
    #[test]
    fn archive_without_checkout_and_duplicate_checkout_are_errors_without_changing_authority() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut host, &design);
        let before = fs::read(&path).unwrap();
        let task = ManagedTask::Archive {
            path: path.to_string_lossy().into_owned(),
            logical_path: None,
            saved: design.doc.clone(),
            visibility: Box::new(design.visibility.clone()),
        };
        assert!(host.execute(task, None).is_err());
        assert_eq!(host.client().unwrap().managed_history(document.clone()).unwrap().len(), 1);
        run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let grant = host.grants.get(&document).unwrap().clone();
        assert!(host.execute(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None).is_err());
        assert_eq!(host.grants.get(&document), Some(&grant));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            host.client().unwrap().managed_catalog().unwrap().entries.into_iter().find(|entry| entry.document == document).unwrap().checkout,
            grant.entry.checkout
        );
    }

    #[test]
    fn stale_checkout_cannot_replace_local_bytes_during_cancel() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut host, &design);
        let (_, opened) = run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let mut edited = *opened.unwrap();
        edited.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        edited.execute("file.save", &serde_json::json!({})).unwrap();
        let before = fs::read(&path).unwrap();
        let ws = host.workspace().unwrap();
        let workspace = ws.manifest().workspace_id.clone();
        drop(ws);
        let grant = host.grants.get(&document).unwrap();
        host.client().unwrap().managed_cancel_checkout(document.clone(), workspace, host.machine.clone(), grant.token.clone()).unwrap();
        assert!(host.execute(ManagedTask::CancelCheckout { document: Some(document.clone()), path: None }, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(host.grants.contains_key(&document));
    }
    #[test]
    fn managed_native_https_action_authority_rejects_duplicates_other_workspaces_and_offline_cancel() {
        use sha2::{Digest, Sha256};
        use solidcraft_pdm::{
            http_server::{HttpsConfig, HttpsServer},
            managed::{Principal, PrincipalCredential, Role},
        };
        let trial = Trial::new();
        let store_root = trial.root.join("https-store");
        fs::create_dir(&store_root).unwrap();
        let alice_token = "a".repeat(64);
        let bob_token = "b".repeat(64);
        let viewer_token = "c".repeat(64);
        let users: Vec<_> =
            [("alice", Role::Contributor, &alice_token), ("bob", Role::Contributor, &bob_token), ("reader", Role::Viewer, &viewer_token)]
                .into_iter()
                .map(|(id, role, token)| PrincipalCredential {
                    principal: Principal { id: id.into(), role },
                    token_sha256: format!("{:x}", Sha256::digest(token.as_bytes())),
                })
                .collect();
        fs::write(store_root.join("managed-principals.json"), serde_json::to_vec(&users).unwrap()).unwrap();
        let config = HttpsConfig::from_der(
            "127.0.0.1:0".parse().unwrap(),
            vec![include_bytes!("../../solidcraft-pdm/tests/fixtures/pdm-https/server.der").to_vec()],
            include_bytes!("../../solidcraft-pdm/tests/fixtures/pdm-https/server-key.der").to_vec(),
        )
        .unwrap();
        let server = HttpsServer::start(solidcraft_pdm::Store::open(&store_root).unwrap(), config).unwrap();
        let client = |token: &str| {
            Client::https_with_ca(
                &format!("https://{}", server.address()),
                AuthToken::parse(token.into()).unwrap(),
                include_bytes!("../../solidcraft-pdm/tests/fixtures/pdm-https/ca.der"),
            )
            .unwrap()
        };
        let alice = client(&alice_token);
        let bob = client(&bob_token);
        let viewer = client(&viewer_token);
        let mut host = Host::prepare_connection(alice.clone(), &trial.root.join("alice"), server.address().port(), Some("alice")).unwrap().host;
        let mut other =
            Host::prepare_connection(alice.clone(), &trial.root.join("alice-other-workspace"), server.address().port(), Some("alice")).unwrap().host;
        let mut bob_host = Host::prepare_connection(bob.clone(), &trial.root.join("bob"), server.address().port(), Some("bob")).unwrap().host;
        assert_eq!(alice.authenticated_identity().unwrap().principal.id, "alice");
        assert_eq!(bob.authenticated_identity().unwrap().principal.id, "bob");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut host, &design);
        let archived = fs::read(&path).unwrap();
        let bob_path = bob_host.root.as_ref().unwrap().join("part.solidcraft");
        fs::write(&bob_path, &archived).unwrap();
        assert!(
            bob_host
                .execute(
                    ManagedTask::ReconcileArchive {
                        path: bob_path.to_string_lossy().into_owned(),
                        logical_path: None,
                        saved: design.doc.clone(),
                        visibility: Box::new(design.visibility.clone())
                    },
                    None
                )
                .is_err()
        );
        assert!(bob_host.workspace().unwrap().manifest().documents.is_empty());
        assert!(bob_host.execute(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None).is_err());
        let bob_grant = bob_host.grants.get(&document).unwrap().clone();
        let ws = bob_host.workspace().unwrap();
        assert!(bob_host.state(&ws, None).unwrap().recoverable_checkouts.contains(&document));
        drop(ws);
        let wrong_account = Host {
            client: Some(alice.clone()),
            port: server.address().port(),
            root: bob_host.root.clone(),
            server_id: bob_host.server_id.clone(),
            machine: bob_host.machine.clone(),
            grants: bob_host.grants.clone(),
        };
        let ws = wrong_account.workspace().unwrap();
        assert!(wrong_account.state(&ws, None).unwrap().recoverable_checkouts.is_empty());
        drop(ws);
        bob_host.machine.push_str("-other");
        let ws = bob_host.workspace().unwrap();
        assert!(bob_host.state(&ws, None).unwrap().recoverable_checkouts.is_empty());
        drop(ws);
        bob_host.machine = bob_grant.entry.checkout.as_ref().unwrap().machine.clone();
        run(&mut bob_host, ManagedTask::CancelCheckout { document: Some(document.clone()), path: None });
        assert_eq!(fs::read(&bob_path).unwrap(), archived);
        let archive_task = ManagedTask::Archive {
            path: path.to_string_lossy().into_owned(),
            logical_path: None,
            saved: design.doc.clone(),
            visibility: Box::new(design.visibility.clone()),
        };
        assert!(host.execute(archive_task, None).is_err());
        run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let grant = host.grants.get(&document).unwrap().clone();
        assert!(host.execute(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None).is_err());
        assert!(other.execute(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None).is_err());
        assert!(bob_host.execute(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None).is_err());
        assert!(viewer.managed_checkout(document.clone(), "reader-workspace".into(), "reader-machine".into()).is_err());
        let workspace = host.workspace().unwrap().manifest().workspace_id.clone();
        let forbidden = ManagedCheckIn {
            document: document.clone(),
            workspace,
            machine: host.machine.clone(),
            checkout_token: grant.token.clone(),
            request_id: "https-foreign-owner".into(),
            parent: Some(1),
            content: archived.clone(),
            dependencies: vec![],
            comment: String::new(),
        };
        assert!(bob.managed_check_in(forbidden).is_err());
        assert_eq!(alice.managed_history(document.clone()).unwrap().len(), 1);
        assert_eq!(host.grants.get(&document), Some(&grant));
        let ws = host.workspace().unwrap();
        let snapshot = host.state(&ws, None).unwrap();
        assert!(snapshot.local.iter().any(|entry| entry.document == document && entry.checked_out));
        drop(ws);
        server.shutdown().unwrap();
        assert!(host.execute(ManagedTask::CancelCheckout { document: Some(document.clone()), path: None }, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), archived);
        assert_eq!(host.grants.get(&document), Some(&grant));
    }
    #[test]
    fn initial_archive_reconciles_acknowledged_publication_before_requiring_checkout() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let bytes = fs::read(&path).unwrap();
        let client = host.client().unwrap();
        let entry = client.managed_create("part.solidcraft".into()).unwrap();
        let ws = host.workspace().unwrap();
        let workspace = ws.manifest().workspace_id.clone();
        drop(ws);
        let grant = client.managed_checkout(entry.document.clone(), workspace.clone(), host.machine.clone()).unwrap();
        let dependencies: Vec<VersionRef> = vec![];
        let request_id = hash(&serde_json::to_vec(&(workspace.clone(), entry.document.clone(), None::<u64>, hash(&bytes), &dependencies)).unwrap());
        client
            .managed_check_in(ManagedCheckIn {
                document: entry.document.clone(),
                workspace,
                machine: host.machine.clone(),
                checkout_token: grant.token,
                request_id,
                parent: None,
                content: bytes.clone(),
                dependencies,
                comment: String::new(),
            })
            .unwrap();
        assert!(host.workspace().unwrap().manifest().documents.is_empty());
        let (outcome, _) = run(
            &mut host,
            ManagedTask::ReconcileArchive {
                path: path.to_string_lossy().into_owned(),
                logical_path: None,
                saved: design.doc.clone(),
                visibility: Box::new(design.visibility.clone()),
            },
        );
        assert!(
            matches!(outcome, Outcome::Managed { state, .. } if state.local.iter().any(|local| local.document == entry.document && local.base_version == 1))
        );
        assert_eq!(client.managed_history(entry.document).unwrap().len(), 1);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(fs::metadata(path).unwrap().permissions().readonly());
    }
    #[test]
    fn receipt_only_reconciliation_without_receipt_never_creates_document_checkout_or_version() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let before = fs::read(&path).unwrap();
        let verify = || ManagedTask::ReconcileArchive {
            path: path.to_string_lossy().into_owned(),
            logical_path: None,
            saved: design.doc.clone(),
            visibility: Box::new(design.visibility.clone()),
        };
        assert!(host.execute(verify(), None).is_err());
        assert!(host.client().unwrap().managed_catalog().unwrap().entries.is_empty());
        let document = archive(&mut host, &design);
        assert!(host.execute(verify(), None).is_err(), "an already finished archive is not a pending publication");
        let catalog = host.client().unwrap().managed_catalog().unwrap();
        assert_eq!(catalog.entries.len(), 1);
        assert!(catalog.entries[0].checkout.is_none());
        assert_eq!(catalog.entries[0].head, Some(1));
        assert_eq!(host.client().unwrap().managed_history(document).unwrap().len(), 1);
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    #[test]
    fn missing_clean_copy_can_update_open_and_checkout_at_the_same_path() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let original = fs::read(&path).unwrap();
        let document = archive(&mut host, &design);
        remove_copy(&path);
        let (_, opened) = run(&mut host, ManagedTask::GetLatest { document: Some(document.clone()), path: None });
        assert_eq!(
            opened.unwrap().path.as_deref().map(solidcraft_engine::pdm::cached_path_key),
            path.to_str().map(solidcraft_engine::pdm::cached_path_key)
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        remove_copy(&path);
        let (_, opened) = run(&mut host, ManagedTask::Open { document: document.clone() });
        assert_eq!(
            opened.unwrap().path.as_deref().map(solidcraft_engine::pdm::cached_path_key),
            path.to_str().map(solidcraft_engine::pdm::cached_path_key)
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        remove_copy(&path);
        let (_, opened) = run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        assert_eq!(
            opened.unwrap().path.as_deref().map(solidcraft_engine::pdm::cached_path_key),
            path.to_str().map(solidcraft_engine::pdm::cached_path_key)
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!fs::metadata(&path).unwrap().permissions().readonly());
        assert!(host.workspace().unwrap().manifest().documents[&document].checked_out);
        assert!(host.grants.contains_key(&document));
    }

    #[test]
    fn directory_at_missing_working_copy_is_never_treated_as_absent_or_overwritten() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut host, &design);
        remove_copy(&path);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep.txt"), b"unrelated data").unwrap();
        assert!(host.execute(ManagedTask::GetLatest { document: Some(document.clone()), path: None }, None).is_err());
        assert!(host.execute(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None).is_err());
        assert!(host.execute(ManagedTask::Open { document: document.clone() }, None).is_err());
        assert_eq!(fs::read(path.join("keep.txt")).unwrap(), b"unrelated data");
        assert!(host.grants.is_empty());
        assert!(
            host.client()
                .unwrap()
                .managed_catalog()
                .unwrap()
                .entries
                .into_iter()
                .find(|entry| entry.document == document)
                .unwrap()
                .checkout
                .is_none()
        );
    }

    #[test]
    fn failed_checkout_install_can_release_verified_reservation_through_engine_policy() {
        let trial = Trial::new();
        let mut producer = trial.host("producer");
        let path = producer.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut producer, &design);
        let mut consumer = trial.host("consumer");
        let destination = consumer.root.as_ref().unwrap().join("part.solidcraft");
        fs::write(&destination, b"existing unmanaged design").unwrap();
        assert!(consumer.execute(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None).is_err());
        assert!(consumer.workspace().unwrap().manifest().documents.is_empty());
        let (outcome, _) = consumer.refresh().unwrap();
        let mut session = Session::default();
        session.pdm.set_available(true).unwrap();
        let id = session.pdm.enqueue(solidcraft_engine::pdm::Task::Connect { port: trial.port }).unwrap();
        session.pdm.finish(id, Ok(outcome)).unwrap();
        let state = session.pdm.status().unwrap();
        assert!(state.managed.recoverable_checkouts.contains(&document));
        assert_eq!(state.document_state(Some(&document), None, false), "ui.pdm_state_checkout_incomplete");
        let id =
            session.execute("pdm.cancel_checkout", &serde_json::json!({"document":document,"discard":true})).unwrap()["request"].as_u64().unwrap();
        let job = session.pdm.take_job().unwrap().unwrap();
        let solidcraft_engine::pdm::Task::Managed(task) = job.task else { panic!("expected managed cancellation") };
        let (outcome, _) = consumer.execute(task, None).unwrap();
        session.pdm.finish(id, Ok(outcome)).unwrap();
        assert!(consumer.grants.is_empty());
        assert!(consumer.workspace().unwrap().manifest().documents.is_empty());
        assert_eq!(fs::read(&destination).unwrap(), b"existing unmanaged design");
        assert!(
            consumer
                .client()
                .unwrap()
                .managed_catalog()
                .unwrap()
                .entries
                .into_iter()
                .find(|entry| entry.document == document)
                .unwrap()
                .checkout
                .is_none()
        );
    }
}
