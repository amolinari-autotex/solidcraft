//! Native managed workspace adapter. Reservation capabilities never cross into UI state.
use solidcraft_engine::{
    Session,
    pdm::{CatalogEntry, Failure, LocalEntry, ManagedState, ManagedTask, Outcome, Reference, WhereUsedEntry},
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

#[path = "pdm_import.rs"]
mod import;
#[path = "pdm_namespace.rs"]
mod namespace;
#[path = "pdm_transfer.rs"]
mod transfer;

struct ArchiveNode {
    task: ManagedTask,
    path: String,
    relative: String,
    sha256: String,
    bytes: u64,
    children: Vec<String>,
}

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
fn administration_role(role: solidcraft_pdm::managed::Role) -> &'static str {
    match role {
        solidcraft_pdm::managed::Role::Viewer => "viewer",
        solidcraft_pdm::managed::Role::Contributor => "contributor",
        solidcraft_pdm::managed::Role::Administrator => "administrator",
    }
}
fn administration_error(error: Error) -> Result<solidcraft_engine::pdm::AdminReadStatus, Failure> {
    use solidcraft_engine::pdm::AdminReadStatus;
    match error {
        Error::Forbidden => Ok(AdminReadStatus::Forbidden),
        Error::Server(code) => match code.as_str() {
            "unauthorized" => Err(Failure { message: "ui.pdm_admin_unauthorized".into(), disconnect: true }),
            "server_identity_mismatch" => Err(Failure { message: "ui.pdm_error_identity_mismatch".into(), disconnect: true }),
            "forbidden" => Ok(AdminReadStatus::Forbidden),
            "capability_unavailable" | "not_found" => Ok(AdminReadStatus::Unsupported),
            _ => Ok(AdminReadStatus::Unavailable),
        },
        _ => Ok(AdminReadStatus::Unavailable),
    }
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
    fn administration_read(&self) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        use solidcraft_engine::pdm::{AdminAuditEvent, AdminPrincipal, AdminReadStatus, AdminState, AdminUser};
        use solidcraft_pdm::administration::{AdminRequest, AdminResponse};
        let client = self.client()?;
        let capabilities = match client.capabilities() {
            Ok(capabilities) => capabilities,
            Err(error) => {
                let status = administration_error(error)?;
                return Ok((Outcome::Administration(AdminState { users_status: status, audit_status: status, ..Default::default() }), None));
            }
        };
        if capabilities.server_id != self.server_id {
            return Err(Failure { message: "ui.pdm_error_identity_mismatch".into(), disconnect: true });
        }
        let allowed = |feature: bool, permission: &str| {
            if !feature {
                AdminReadStatus::Unsupported
            } else if capabilities.permissions.iter().any(|value| value == permission) {
                AdminReadStatus::Available
            } else {
                AdminReadStatus::Forbidden
            }
        };
        let mut state = AdminState {
            server_id: Some(capabilities.server_id.clone()),
            metadata_backend: Some(capabilities.metadata_backend.clone()),
            principal: Some(AdminPrincipal {
                id: capabilities.principal.id.clone(),
                role: administration_role(capabilities.principal.role).into(),
                permissions: capabilities.permissions.clone(),
            }),
            users_status: allowed(capabilities.features.users_admin_v1, "users.manage"),
            audit_status: allowed(capabilities.features.audit_read_v1, "audit.read"),
            ..Default::default()
        };
        if state.users_status == AdminReadStatus::Available {
            match client.admin(AdminRequest::ListUsers {}) {
                Ok(AdminResponse::Users { revision, users }) => {
                    state.users_revision = Some(revision);
                    state.users = users
                        .into_iter()
                        .take(64)
                        .map(|user| AdminUser { id: user.id, role: administration_role(user.role).into(), enabled: user.enabled })
                        .collect();
                }
                Ok(_) => state.users_status = AdminReadStatus::Unavailable,
                Err(error) => state.users_status = administration_error(error)?,
            }
        }
        if state.audit_status == AdminReadStatus::Available {
            match client.admin(AdminRequest::ListAudit { after_generation: None, limit: 32 }) {
                Ok(AdminResponse::Audit { events, next_after_generation }) => {
                    state.more_audit = next_after_generation.is_some();
                    state.audit = events
                        .into_iter()
                        .take(32)
                        .map(|event| AdminAuditEvent {
                            generation: event.generation,
                            actor: event.actor,
                            operation: event.operation,
                            unix_ms: event.unix_ms,
                            subject: event.subject,
                        })
                        .collect();
                }
                Ok(_) => state.audit_status = AdminReadStatus::Unavailable,
                Err(error) => state.audit_status = administration_error(error)?,
            }
        }
        Ok((Outcome::Administration(state), None))
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
            Err(_) => {
                return Err(fail("The working copy cannot be inspected; check its permissions before updating"));
            }
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
        self.state_for_reference(ws, selected, None, false)
    }
    fn state_for_reference(
        &self,
        ws: &Workspace,
        selected: Option<&str>,
        exact: Option<&Reference>,
        metadata_only: bool,
    ) -> Result<ManagedState, Failure> {
        let client = self.client()?;
        let catalog = client.managed_catalog().map_err(error)?;
        if catalog.server_id != self.server_id {
            return Err(fail("The service identity changed; reconnect explicitly"));
        }
        let mut local = Vec::new();
        for (document, entry) in ws.manifest().documents.iter().filter(|_| !metadata_only) {
            let path = ws.path(document).map_err(error)?;
            let actual = ws.local_sha256(document);
            local.push(LocalEntry {
                document: document.clone(),
                path: path.to_string_lossy().into_owned(),
                relative_path: entry.relative_path.clone(),
                base_version: entry.base_version,
                sha256: entry.base_sha256.clone(),
                checked_out: self.grants.get(document).is_some_and(|grant| {
                    catalog.entries.iter().any(|remote| {
                        remote.document == *document
                            && remote.head == Some(entry.base_version)
                            && remote.checkout.as_ref().is_some_and(|checkout| {
                                checkout.workspace == ws.manifest().workspace_id
                                    && checkout.machine == self.machine
                                    && checkout.base_version == Some(entry.base_version)
                            })
                            && remote.checkout == grant.entry.checkout
                    }) && (entry.checked_out
                        // A completed local discard can precede a failed server release.
                        // Its read-only convenience flag must not hide the still-valid
                        // reservation needed to retry cancellation. Confirm the exact
                        // capability rather than inferring ownership from public metadata.
                        || client
                            .managed_resume_checkout(document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone())
                            .is_ok_and(|fresh| fresh == *grant))
                }),
                modified: actual.as_ref().is_ok_and(|hash| hash != &entry.base_sha256),
                present: actual.is_ok(),
            });
        }
        let dependency_updates = if metadata_only { vec![] } else { dependency_updates(ws, &local, &catalog.entries) };
        let recoverable_checkouts = catalog
            .entries
            .iter()
            .filter(|remote| {
                !metadata_only
                    && !ws.manifest().documents.contains_key(&remote.document)
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
            namespace: Default::default(),
            history: vec![],
            where_used: vec![],
            where_used_details: vec![],
            preview: None,
            historical_paths: vec![],
        };
        self.apply_namespace_state(&client, &mut state)?;
        if let Some(document) = selected {
            state.history = convert(client.managed_history(document.into()).map_err(error)?)?;
            if state.history.len() > solidcraft_pdm::MAX_VERSIONS {
                return Err(fail("Managed history limit exceeded"));
            }
            let mut versions = BTreeSet::new();
            for version in &state.history {
                let reference = &version.version.reference;
                reference.validate().map_err(|_| fail("Invalid managed history reference"))?;
                if reference.document != document || !versions.insert(reference.version) {
                    return Err(fail("Invalid managed history reference"));
                }
            }
            let native = state
                .namespace
                .entries
                .iter()
                .find(|entry| entry.document == document)
                .map(|entry| entry.materialization_path.as_str())
                .or_else(|| state.catalog.iter().find(|entry| entry.document == document).map(|entry| entry.logical_path.as_str()))
                .is_some_and(|path| is_native_design(Path::new(path)));
            if native && let Some(reference) = exact.or_else(|| state.history.last().map(|version| &version.version.reference)) {
                state.preview = self.preview(&client, ws, reference)?;
            }
            // History describes the document across all its actual archived pins;
            // an explicit preview describes only that exact source version.
            let references = match exact {
                Some(reference) => vec![reference.clone()],
                None => state.history.iter().map(|version| version.version.reference.clone()).collect(),
            };
            state.where_used_details = Self::where_used_details(&client, &references)?;
            let mut parents = BTreeSet::new();
            for edge in &state.where_used_details {
                if parents.insert((edge.parent.document.clone(), edge.parent.version)) {
                    state.where_used.push(edge.parent.clone());
                }
            }
        }
        Ok(state)
    }
    fn where_used_details(client: &Client, references: &[Reference]) -> Result<Vec<WhereUsedEntry>, Failure> {
        const MAX_EDGES: usize = solidcraft_pdm::MAX_VERSIONS * solidcraft_pdm::MAX_VERSIONS;
        if references.len() > solidcraft_pdm::MAX_VERSIONS {
            return Err(fail("Managed history limit exceeded"));
        }
        let mut details = Vec::new();
        let mut seen = BTreeSet::new();
        for used in references {
            used.validate().map_err(|_| fail("Invalid managed source reference"))?;
            let response = client
                .request(solidcraft_pdm::Request::WhereUsed { reference: VersionRef { document: used.document.clone(), version: used.version } })
                .map_err(error)?;
            let solidcraft_pdm::Response::WhereUsed { versions } = response else {
                return Err(fail("Invalid managed where-used response"));
            };
            if versions.len() > MAX_EDGES {
                return Err(fail("Managed where-used limit exceeded"));
            }
            for parent in convert::<Vec<Reference>>(versions)? {
                parent.validate().map_err(|_| fail("Invalid managed parent reference"))?;
                if seen.insert((parent.document.clone(), parent.version, used.document.clone(), used.version)) {
                    if details.len() >= MAX_EDGES {
                        return Err(fail("Managed where-used limit exceeded"));
                    }
                    // Only an authoritative response to this queried pin creates
                    // an edge; never infer it from paths or current dependency heads.
                    details.push(WhereUsedEntry { parent, used: used.clone() });
                }
            }
        }
        Ok(details)
    }
    pub fn refresh(&self) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        let ws = self.workspace()?;
        Ok((Outcome::ManagedRefreshed { port: self.port, state: self.state(&ws, None)? }, None))
    }
    fn preview(&self, client: &Client, ws: &Workspace, reference: &Reference) -> Result<Option<solidcraft_engine::pdm::Preview>, Failure> {
        let staged = transfer::download(client, ws, &VersionRef { document: reference.document.clone(), version: reference.version })?;
        let bytes = read_file(&staged.path, solidcraft_engine::io::MAX_DESIGN_BYTES).map_err(error)?;
        let version = &staged.version;
        let png = solidcraft_engine::io::read_design_thumbnail(&bytes).or_else(|| {
            let session = Session::new(solidcraft_engine::io::read_design(&bytes).ok()?);
            let world = session.world_state();
            if world.bodies.is_empty() || world.bodies.len() > 1024 {
                return None;
            }
            let (mut points, mut triangles) = (0usize, 0usize);
            for body in &world.bodies {
                let mesh = body.mesh();
                points = points.checked_add(mesh.positions.len())?;
                triangles = triangles.checked_add(mesh.triangles.len())?;
                if points > 100_000 || triangles > 100_000 {
                    return None;
                }
            }
            // Exact downloaded bytes only: never refresh links to live files,
            // save the document, or change a normal working-copy path here.
            session.design_thumbnail()
        });
        Ok(png.map(|png| solidcraft_engine::pdm::Preview { reference: reference.clone(), sha256: version.sha256.clone(), png }))
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
        if matches!(&task, ManagedTask::Archive { path, .. } if is_native_design(Path::new(path))) {
            return self.archive_graph(task, default_root);
        }
        self.execute_single(task, default_root)
    }
    fn execute_single(&mut self, task: ManagedTask, default_root: Option<&Path>) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        self.execute_single_with_opener(task, default_root, crate::pdm_external::open)
    }
    fn execute_single_with_opener(
        &mut self,
        task: ManagedTask,
        default_root: Option<&Path>,
        opener: fn(&Path) -> Result<(), String>,
    ) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        if let ManagedTask::Recover { port, root } = &task {
            let client = Client::new(*port, AuthToken::from_env().map_err(error)?);
            let catalog = client.managed_catalog().map_err(error)?;
            let path = Path::new(root);
            if !path.is_absolute() {
                return Err(fail("Recovery requires an absolute workspace path"));
            }
            let mut workspace = Workspace::open_for_recovery(path, &catalog.server_id).map_err(error)?;
            for (document, entry) in &workspace.manifest().documents {
                let staged = transfer::download(&client, &workspace, &VersionRef { document: document.clone(), version: entry.base_version })?;
                if staged.version.sha256 != entry.base_sha256 {
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
        if matches!(&task, ManagedTask::AdministrationRead) {
            return self.administration_read();
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
        if let ManagedTask::ImportNew { source_path, folder, expected_workspace } = task {
            return self.import_new(source_path, folder, expected_workspace);
        }
        let mut ws = self.workspace()?;
        let mut opened = None;
        let selected = match task {
            ManagedTask::Rename { document, logical_path, expected_head, expected_revision, expected_epoch: _ } => {
                self.namespace_mutation(
                    &client,
                    &ws,
                    &document,
                    expected_head,
                    expected_revision,
                    solidcraft_pdm::managed::NamespaceAction::Rename { logical_path },
                )?;
                return Ok((Outcome::Managed { port: self.port, state: self.state(&ws, None)? }, None));
            }
            ManagedTask::Delete { document, expected_head, expected_revision, expected_epoch: _ } => {
                self.namespace_mutation(
                    &client,
                    &ws,
                    &document,
                    expected_head,
                    expected_revision,
                    solidcraft_pdm::managed::NamespaceAction::Tombstone,
                )?;
                return Ok((Outcome::Managed { port: self.port, state: self.state(&ws, None)? }, None));
            }
            ManagedTask::ListConnections
            | ManagedTask::CreateLocal { .. }
            | ManagedTask::OpenConnection { .. }
            | ManagedTask::RecoverConnection { .. }
            | ManagedTask::ChangeWorkspace { .. } => {
                return Err(fail("Connection setup requires the native connection controller"));
            }
            ManagedTask::Recover { .. } | ManagedTask::ImportNew { .. } | ManagedTask::AdministrationRead => {
                return Err(fail("Invalid recovery, import or administration state"));
            }
            ManagedTask::Preview { reference } => {
                let state = self.state_for_reference(&ws, Some(&reference.document), Some(&reference), true)?;
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
                if !is_native_design(Path::new(&local.relative_path)) {
                    return Err(fail("The historical version is not a readable native design"));
                }
                let caps = client.transfer_capabilities().map_err(error)?.filter(|caps| caps.binary_transfer_v1);
                if caps.as_ref().is_some_and(|caps| caps.server_id != self.server_id || !caps.can_upload) {
                    return Err(fail("This account cannot restore designs into this service"));
                }
                let principal = match client.request(solidcraft_pdm::Request::Identity {}).map_err(error)? {
                    solidcraft_pdm::Response::Identity { identity } if identity.server_id == self.server_id => identity.principal.id,
                    _ => return Err(fail("Could not confirm the restoration account")),
                };
                let requested = VersionRef { document: reference.document.clone(), version: reference.version };
                let staged = transfer::download(&client, &ws, &requested)?;
                let source = &staged.version;
                let limit = if caps.is_some() { solidcraft_engine::io::MAX_DESIGN_BYTES } else { solidcraft_pdm::MAX_CONTENT };
                let bytes = read_file(&staged.path, limit).map_err(error)?;
                if source.reference != requested || hash(&bytes) != source.sha256 {
                    return Err(fail("Historical content integrity verification failed"));
                }
                solidcraft_engine::io::read_design(&bytes).map_err(|_| fail("The historical version is not a readable native design"))?;
                let source_info = solidcraft_pdm::transfer_source::SourceInfo { bytes: bytes.len() as u64, sha256: source.sha256.clone() };
                let legacy_bytes = if caps.is_some() {
                    drop(bytes);
                    None
                } else {
                    Some(bytes)
                };
                let history = client.managed_history(reference.document.clone()).map_err(error)?;
                let receipt = restore_receipt(&ws.manifest().workspace_id, &reference, local.base_version, &source.sha256, &source.dependencies)?;
                // Check receipts before acquiring a grant. This covers a lost publication reply
                // and retries after the local manifest has already advanced to the restored head.
                let published = history.into_iter().find(|version| {
                    if version.author != principal || version.version.sha256 != source.sha256 || version.version.dependencies != source.dependencies {
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
                        if let Some(caps) = &caps {
                            transfer::upload_with_request(
                                &client,
                                caps,
                                &staged.path,
                                solidcraft_pdm::transfers::TransferTarget::CheckIn {
                                    document: reference.document.clone(),
                                    workspace: ws.manifest().workspace_id.clone(),
                                    machine: self.machine.clone(),
                                    checkout_token: grant.token,
                                    parent: Some(local.base_version),
                                },
                                source.dependencies.clone(),
                                &ws.manifest().workspace_id,
                                &source_info,
                                receipt,
                                format!("Restore archived version {}", reference.version),
                            )?
                        } else {
                            client
                                .managed_check_in(ManagedCheckIn {
                                    document: reference.document.clone(),
                                    workspace: ws.manifest().workspace_id.clone(),
                                    machine: self.machine.clone(),
                                    checkout_token: grant.token,
                                    request_id: receipt,
                                    parent: Some(local.base_version),
                                    content: legacy_bytes.ok_or_else(|| fail("The legacy restoration payload is unavailable"))?,
                                    dependencies: source.dependencies.clone(),
                                    comment: format!("Restore archived version {}", reference.version),
                                })
                                .map_err(error)?
                        }
                    }
                };
                if local.base_version != published.version.reference.version {
                    ws.install_stream(
                        &reference.document,
                        &local.relative_path,
                        published.version.reference.version,
                        &published.version.sha256,
                        staged.bytes,
                        &mut staged.reader()?,
                    )
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
                    let staged = transfer::download(&client, &history, &requested)?;
                    staged.install(&mut history, &entry.logical_path)?;
                    resolved.insert(requested.document, requested.version);
                    queue.extend(staged.version.dependencies.iter().cloned());
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
            ManagedTask::Connect { .. } | ManagedTask::ReconcileArchive { .. } => {
                return Err(fail("Invalid connection state"));
            }
            ManagedTask::History { document } => {
                let state = self.state_for_reference(&ws, Some(&document), None, true)?;
                return Ok((Outcome::Managed { port: self.port, state }, None));
            }
            ManagedTask::Archive { path, logical_path, saved, visibility } => {
                let native = is_native_design(Path::new(&path));
                let caps = client.transfer_capabilities().map_err(error)?.filter(|caps| caps.binary_transfer_v1);
                if !native && let Some(caps) = &caps {
                    return self.archive_attachment_stream(&client, &mut ws, &path, logical_path.as_deref(), reconcile_only, caps);
                }
                let limit = if let Some(caps) = &caps {
                    if caps.server_id != self.server_id || !caps.can_upload {
                        return Err(fail("This account cannot archive designs into this service"));
                    }
                    let policy = caps.limits.as_ref().ok_or_else(|| fail("The server did not advertise a file policy"))?;
                    policy.max_file_bytes.min(solidcraft_engine::io::MAX_DESIGN_BYTES as u64) as usize
                } else {
                    solidcraft_pdm::MAX_CONTENT
                };
                let bytes = read_file(Path::new(&path), limit).map_err(error)?;
                if native {
                    super::pdm::validate_saved(&bytes, &saved, &visibility)?;
                }
                let source_info = solidcraft_pdm::transfer_source::SourceInfo { bytes: bytes.len() as u64, sha256: hash(&bytes) };
                // Keep native parsing bounded by its own format, then release the complete
                // validation buffer before streaming the captured source from disk.
                let legacy_bytes = if caps.is_some() {
                    drop(bytes);
                    None
                } else {
                    Some(bytes)
                };
                let absolute = fs::canonicalize(&path).map_err(|_| fail("Saved design unavailable"))?;
                let relative = absolute
                    .strip_prefix(ws.root())
                    .map_err(|_| fail("Save the design inside the configured working folder before archiving"))?
                    .to_string_lossy()
                    .replace('\\', "/");
                if logical_path.as_ref().is_some_and(|p| !p.is_empty() && p != &relative) {
                    return Err(fail("The archive path must match the saved path inside the working folder"));
                }
                let entry = if reconcile_only || !native {
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
                let history = client.managed_history(entry.document.clone()).map_err(error)?;
                let dependencies = if native {
                    dependencies(&client, &ws, &path, &saved)?
                } else {
                    let local = existing.as_ref().ok_or_else(|| fail("The attachment must have a managed working copy before checking in"))?;
                    history
                        .iter()
                        .find(|version| version.version.reference.version == local.base_version)
                        .ok_or_else(|| fail("The attachment base version is missing"))?
                        .version
                        .dependencies
                        .clone()
                };
                let parent = existing.as_ref().map(|e| e.base_version);
                let request_id = archive_request_id(&ws.manifest().workspace_id, &entry.document, parent, &source_info.sha256, &dependencies)?;
                // Receipts are scoped to the current authenticated principal as well
                // as this exact workspace, base and payload. Never reconcile another
                // account's publication merely because its public metadata is visible.
                let principal = match client.request(solidcraft_pdm::Request::Identity {}).map_err(error)? {
                    solidcraft_pdm::Response::Identity { identity } if identity.server_id == self.server_id => identity.principal.id,
                    _ => return Err(fail("Could not confirm the publication account")),
                };
                // Reconcile an acknowledged-on-server publication before obtaining a new lock.
                let published =
                    history.into_iter().find(|v| v.request_id == request_id && v.version.sha256 == source_info.sha256 && v.author == principal);
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
                        if let Some(caps) = &caps {
                            transfer::upload_with_request(
                                &client,
                                caps,
                                &absolute,
                                solidcraft_pdm::transfers::TransferTarget::CheckIn {
                                    document: entry.document.clone(),
                                    workspace: ws.manifest().workspace_id.clone(),
                                    machine: self.machine.clone(),
                                    checkout_token: grant.token,
                                    parent,
                                },
                                dependencies,
                                &ws.manifest().workspace_id,
                                &source_info,
                                request_id,
                                String::new(),
                            )?
                        } else {
                            client
                                .managed_check_in(ManagedCheckIn {
                                    document: entry.document.clone(),
                                    workspace: ws.manifest().workspace_id.clone(),
                                    machine: self.machine.clone(),
                                    checkout_token: grant.token,
                                    request_id,
                                    parent,
                                    content: legacy_bytes.ok_or_else(|| fail("The legacy archive payload is unavailable"))?,
                                    dependencies,
                                    comment: String::new(),
                                })
                                .map_err(error)?
                        }
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
            ManagedTask::CheckoutPreservingMemory { document, path, expected_base } => {
                let local = ws
                    .manifest()
                    .documents
                    .get(&document)
                    .cloned()
                    .ok_or_else(|| fail("Open an existing managed working copy before checking out in-memory changes"))?;
                let working_path = ws.path(&document).map_err(error)?;
                if expected_base == 0
                    || local.checked_out
                    || local.base_version != expected_base
                    || !solidcraft_engine::pdm::same_file_path(&path, &working_path.to_string_lossy())
                    || self.local_digest(&ws, &document)?.is_none_or(|actual| actual != local.base_sha256)
                {
                    return Err(fail("Checkout refused: the saved working copy changed; preserve in-memory changes and refresh its status"));
                }
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
                if remote.head != Some(expected_base) {
                    return Err(fail("Checkout refused: a newer archived base exists; preserve in-memory changes before updating"));
                }
                let grant = client.managed_checkout(document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone()).map_err(error)?;
                self.grants.insert(document.clone(), grant.clone());
                if grant.entry.head != Some(expected_base)
                    || grant.entry.checkout.as_ref().is_none_or(|checkout| {
                        checkout.base_version != Some(expected_base)
                            || checkout.workspace != ws.manifest().workspace_id
                            || checkout.machine != self.machine
                    })
                {
                    // Another publication may win between the catalog read and this
                    // atomic grant. Never install its bytes over the editor's base.
                    if client.managed_cancel_checkout(document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone(), grant.token).is_ok()
                    {
                        self.grants.remove(&document);
                        return Err(fail(
                            "Checkout refused: the archived base changed; the temporary reservation was released and in-memory changes are preserved",
                        ));
                    }
                    return Err(fail(
                        "Checkout refused: the archived base changed and the temporary reservation could not be released; preserve in-memory changes and recover this working folder",
                    ));
                }
                // This rechecks the original base hash before changing permissions.
                // A concurrent disk edit remains intact and keeps this grant available
                // for explicit reconciliation; it is never replaced by a download.
                ws.checkout(&document).map_err(error)?;
                // The editor owns newer in-memory changes. Returning no loaded session
                // prevents replacing it with the older on-disk document.
                Some(document)
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
                let path = ws.path(&document).map_err(error)?;
                if is_native_design(&path) {
                    opened = open_managed(&path, opener, false)?;
                }
                Some(document)
            }
            ManagedTask::GetLatest { document, path } => {
                let document = self.target(&ws, document, path)?;
                if !self.install_graph(&client, &mut ws, &document)? {
                    return Err(fail("The working copy and its managed components are already up to date"));
                }
                let path = ws.path(&document).map_err(error)?;
                if is_native_design(&path) {
                    opened = open_managed(&path, opener, true)?;
                }
                Some(document)
            }
            ManagedTask::Open { document } | ManagedTask::OpenReferenced { document } => {
                self.prepare_live_open(&client, &mut ws, &document)?;
                opened = open_managed(&ws.path(&document).map_err(error)?, opener, true)?;
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
                let staged = transfer::download(&client, &ws, &VersionRef { document: document.clone(), version: entry.base_version })?;
                ws.cancel_checkout_stream(&document, staged.bytes, &mut staged.reader()?).map_err(error)?;
                // Only the authenticated server release acknowledges cancellation.
                // A changed or missing reservation is an error, never a silent success
                // inferred from a later catalog read. Retain the grant on failure.
                client
                    .managed_cancel_checkout(document.clone(), ws.manifest().workspace_id.clone(), self.machine.clone(), grant.token)
                    .map_err(error)?;
                self.grants.remove(&document);
                let path = ws.path(&document).map_err(error)?;
                if is_native_design(&path) {
                    opened = open_managed(&path, opener, false)?;
                }
                Some(document)
            }
        };
        Ok((Outcome::Managed { port: self.port, state: self.state(&ws, selected.as_deref())? }, opened))
    }

    fn archive_graph(&mut self, task: ManagedTask, default_root: Option<&Path>) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        let client = self.client()?;
        let ws = self.workspace()?;
        let caps = client.transfer_capabilities().map_err(error)?.filter(|caps| caps.binary_transfer_v1);
        let file_limit = if let Some(caps) = &caps {
            if caps.server_id != self.server_id || !caps.can_upload {
                return Err(fail("This account cannot archive designs into this service"));
            }
            caps.limits
                .as_ref()
                .ok_or_else(|| fail("The server did not advertise a file policy"))?
                .max_file_bytes
                .min(solidcraft_engine::io::MAX_DESIGN_BYTES as u64) as usize
        } else {
            solidcraft_pdm::MAX_CONTENT
        };
        let store_limit =
            caps.as_ref().and_then(|caps| caps.limits.as_ref()).map_or(solidcraft_pdm::MAX_STORED_CONTENT, |policy| policy.max_store_bytes);
        let nodes = archive_nodes(&ws, task, file_limit)?;
        let catalog = client.managed_catalog().map_err(error)?;
        if catalog.server_id != self.server_id {
            return Err(fail("The service identity changed; reconnect before archiving"));
        }
        let identity = match client.request(solidcraft_pdm::Request::Identity {}).map_err(error)? {
            solidcraft_pdm::Response::Identity { identity } if identity.server_id == self.server_id => identity,
            _ => return Err(fail("Could not confirm the archive account")),
        };
        if identity.principal.role == solidcraft_pdm::managed::Role::Viewer {
            return Err(fail("This account cannot archive designs"));
        }
        if catalog.entries.len() > solidcraft_pdm::MAX_VERSIONS {
            return Err(fail("Archive document limit exceeded"));
        }
        let mut histories = BTreeMap::new();
        let mut version_count = 0usize;
        for entry in &catalog.entries {
            let history = client.managed_history(entry.document.clone()).map_err(error)?;
            version_count = version_count.checked_add(history.len()).ok_or_else(|| fail("Archive capacity exceeded"))?;
            if version_count > solidcraft_pdm::MAX_VERSIONS {
                return Err(fail("Archive capacity exceeded"));
            }
            histories.insert(entry.document.clone(), history);
        }
        let by_path: BTreeMap<_, _> = ws.manifest().documents.iter().map(|(id, entry)| (entry.relative_path.as_str(), (id, entry))).collect();
        let mut selected = Vec::new();
        let mut publications = 0usize;
        let mut publication_bytes = 0u64;
        let mut new_documents = 0usize;
        for (index, node) in nodes.iter().enumerate() {
            let root = index + 1 == nodes.len();
            let remote = catalog.entries.iter().find(|entry| entry.logical_path.eq_ignore_ascii_case(&node.relative));
            if remote.is_some_and(|entry| entry.logical_path != node.relative) {
                return Err(fail("An archived path has different letter casing; use its existing working copy"));
            }
            let local = by_path.get(node.relative.as_str()).copied();
            if let Some(remote) = remote {
                if local.is_some_and(|(document, _)| document != &remote.document) {
                    return Err(fail("The archive path identity changed; refresh before archiving"));
                }
                if remote.checkout.as_ref().is_some_and(|checkout| {
                    checkout.owner != identity.principal.id || checkout.workspace != ws.manifest().workspace_id || checkout.machine != self.machine
                }) {
                    return Err(fail("A contained design is checked out by another account or working folder; nothing was archived"));
                }
                if let Some((document, entry)) = local {
                    if !root
                        && remote.checkout.is_none()
                        && !entry.checked_out
                        && remote.head == Some(entry.base_version)
                        && node.sha256 == entry.base_sha256
                    {
                        continue;
                    }
                    let mut dependencies = BTreeSet::new();
                    let mut known_dependencies = true;
                    for child in &node.children {
                        let Some((child_id, child_entry)) = by_path.get(child.as_str()) else {
                            known_dependencies = false;
                            break;
                        };
                        dependencies.insert(VersionRef { document: child_id.to_string(), version: child_entry.base_version });
                    }
                    let request = archive_request_id(
                        &ws.manifest().workspace_id,
                        document,
                        Some(entry.base_version),
                        &node.sha256,
                        &dependencies.into_iter().collect::<Vec<_>>(),
                    )?;
                    let acknowledged = known_dependencies
                        && histories.get(document).is_some_and(|history| {
                            history.iter().any(|version| {
                                version.request_id == request
                                    && version.version.sha256 == node.sha256
                                    && version.author == identity.principal.id
                                    && remote.head == Some(version.version.reference.version)
                            })
                        });
                    if !acknowledged {
                        self.verified_grant(&client, &ws, document, Some(entry.base_version))?;
                        if !entry.checked_out {
                            return Err(fail("A contained managed design is not checked out; nothing was archived"));
                        }
                        publications += 1;
                        publication_bytes = publication_bytes.checked_add(node.bytes).ok_or_else(|| fail("Archive capacity exceeded"))?;
                    }
                } else {
                    let dependencies: Option<Vec<_>> = node
                        .children
                        .iter()
                        .map(|child| {
                            by_path.get(child.as_str()).map(|(id, entry)| VersionRef { document: id.to_string(), version: entry.base_version })
                        })
                        .collect();
                    let acknowledged = if let Some(dependencies) = dependencies {
                        let dependencies: Vec<_> = dependencies.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
                        let request = archive_request_id(&ws.manifest().workspace_id, &remote.document, None, &node.sha256, &dependencies)?;
                        histories.get(&remote.document).is_some_and(|history| {
                            history.iter().any(|version| {
                                version.request_id == request
                                    && version.version.sha256 == node.sha256
                                    && version.author == identity.principal.id
                                    && remote.head == Some(version.version.reference.version)
                            })
                        })
                    } else {
                        false
                    };
                    if !acknowledged {
                        if remote.head.is_some() {
                            return Err(fail("Open every existing archived component in this working folder before archiving"));
                        }
                        if remote.checkout.is_some() {
                            self.verified_grant(&client, &ws, &remote.document, None)?;
                        }
                        publications += 1;
                        publication_bytes = publication_bytes.checked_add(node.bytes).ok_or_else(|| fail("Archive capacity exceeded"))?;
                    }
                }
            } else {
                if local.is_some() {
                    return Err(fail("A contained managed design disappeared from the server"));
                }
                new_documents += 1;
                publications += 1;
                publication_bytes = publication_bytes.checked_add(node.bytes).ok_or_else(|| fail("Archive capacity exceeded"))?;
            }
            selected.push(index);
        }
        if publication_bytes > store_limit
            || catalog.entries.len().checked_add(new_documents).is_none_or(|count| count > solidcraft_pdm::MAX_VERSIONS)
            || version_count.checked_add(publications).is_none_or(|count| count > solidcraft_pdm::MAX_VERSIONS)
        {
            return Err(fail("The archive cannot hold this complete assembly; nothing was archived"));
        }
        drop(ws);
        let mut completed = 0usize;
        let mut outcome = None;
        for index in selected {
            // Revalidate the complete captured graph before each publication. A
            // later concurrent edit can leave a truthful committed prefix only.
            for node in &nodes {
                let source = solidcraft_pdm::transfer_source::FileSource::open(
                    Path::new(&node.path), file_limit as u64, &std::sync::atomic::AtomicBool::new(false),
                ).map_err(|failure| {
                    if completed == 0 { transfer::source_failure(Path::new(&node.path), failure) } else { fail("Some contained designs may already be archived; a component became unreadable. Preserve the files and retry the assembly archive") }
                })?;
                if source.info().sha256 != node.sha256 || source.info().bytes != node.bytes {
                    return Err(fail(if completed == 0 {
                        "A saved component changed during archive preflight; nothing was archived"
                    } else {
                        "Some contained designs may already be archived; a saved component changed. Preserve the files and retry the assembly archive"
                    }));
                }
            }
            match self.execute_single(nodes[index].task.clone(), default_root) {
                Ok(result) => {
                    completed += 1;
                    outcome = Some(result);
                }
                Err(failure) => {
                    return Err(Failure {message:"Some contained designs may already be archived; the assembly archive did not complete. Preserve the files and retry; existing publication receipts prevent duplicate versions".into(),disconnect:failure.disconnect});
                }
            }
        }
        outcome.ok_or_else(|| fail("No assembly publication was performed"))
    }

    fn prepare_live_open(&self, client: &Client, ws: &mut Workspace, root: &str) -> Result<(), Failure> {
        let catalog = client.managed_catalog().map_err(error)?;
        let entries: BTreeMap<_, _> = catalog.entries.into_iter().map(|entry| (entry.document.clone(), entry)).collect();
        let mut queue = vec![(root.to_string(), 0usize)];
        let mut seen = BTreeSet::new();
        let mut downloads = Vec::new();
        while let Some((document, depth)) = queue.pop() {
            if !seen.insert(document.clone()) {
                continue;
            }
            if seen.len() > solidcraft_pdm::MAX_VERSIONS || depth > 32 {
                return Err(fail("Assembly dependency limit exceeded"));
            }
            let remote = entries.get(&document).ok_or_else(|| fail("A live managed component is missing"))?;
            let version = remote.head.ok_or_else(|| fail("A live managed component has no archived version"))?;
            let local = ws.manifest().documents.get(&document);
            let digest = if local.is_some() { self.local_digest(ws, &document)? } else { None };
            let protected = local.is_some_and(|entry| entry.checked_out || digest.as_ref().is_some_and(|digest| *digest != entry.base_sha256));
            if document != root && protected {
                return Err(fail("A live component is modified or checked out; preserve its changes before opening the current assembly"));
            }
            let current =
                local.is_some_and(|entry| entry.base_version == version && digest.as_ref().is_some_and(|digest| *digest == entry.base_sha256));
            if document == root && protected {
                // Preserve an owned root exactly; current component copies may
                // still be refreshed without replacing the root's bytes.
                let path = ws.path(&document).map_err(error)?;
                if !is_native_design(&path) {
                    continue;
                }
                let saved = solidcraft_engine::io::read_design(&read_file(&path, solidcraft_engine::io::MAX_DESIGN_BYTES).map_err(error)?)
                    .map_err(|_| fail("Invalid working assembly"))?;
                for link in saved.links.values() {
                    let target = path.parent().ok_or_else(|| fail("Working assembly folder unavailable"))?.join(&link.path);
                    let dependency = ws
                        .manifest()
                        .documents
                        .keys()
                        .find(|id| {
                            ws.path(id).is_ok_and(|known| solidcraft_engine::pdm::same_file_path(&known.to_string_lossy(), &target.to_string_lossy()))
                        })
                        .ok_or_else(|| fail("A working assembly component is not managed in this folder"))?;
                    queue.push((dependency.clone(), depth + 1));
                }
                continue;
            }
            let staged = transfer::download(client, ws, &VersionRef { document: document.clone(), version })?;
            let metadata = &staged.version;
            queue.extend(metadata.dependencies.iter().map(|reference| (reference.document.clone(), depth + 1)));
            if !current {
                downloads.push((remote.clone(), staged));
            }
        }
        for (entry, staged) in downloads {
            staged.install(ws, &entry.logical_path)?;
        }
        Ok(())
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
            let staged = transfer::download(client, ws, &VersionRef { document: document.clone(), version })?;
            let metadata = &staged.version;
            queue.extend(metadata.dependencies.iter().map(|r| r.document.clone()));
            downloads.push((entry.clone(), staged));
        }
        let changed = downloads.iter().any(|(entry, staged)| {
            let metadata = &staged.version;
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
        for (entry, staged) in downloads {
            staged.install(ws, &entry.logical_path)?;
        }
        Ok(true)
    }
}

fn archive_request_id(workspace: &str, document: &str, parent: Option<u64>, sha256: &str, dependencies: &[VersionRef]) -> Result<String, Failure> {
    let bytes = serde_json::to_vec(&(workspace, document, parent, sha256, dependencies)).map_err(|_| fail("Could not identify publication"))?;
    Ok(hash(&bytes))
}

fn archive_nodes(ws: &Workspace, root: ManagedTask, file_limit: usize) -> Result<Vec<ArchiveNode>, Failure> {
    fn visit(
        ws: &Workspace,
        task: ManagedTask,
        visiting: &mut BTreeSet<String>,
        complete: &mut BTreeSet<String>,
        nodes: &mut Vec<ArchiveNode>,
        depth: usize,
        file_limit: usize,
    ) -> Result<(), Failure> {
        let ManagedTask::Archive { path, logical_path, saved, visibility } = &task else {
            return Err(fail("Invalid assembly archive request"));
        };
        crate::pdm_connections::guard_workspace_path(Path::new(path)).map_err(|_| fail("Archive source links and reparse points are forbidden"))?;
        let absolute = fs::canonicalize(path).map_err(|_| fail("A saved assembly component is missing"))?;
        let relative = absolute
            .strip_prefix(ws.root())
            .map_err(|_| fail("Save every assembly component inside the current working folder before archiving"))?
            .to_string_lossy()
            .replace('\\', "/");
        solidcraft_pdm::managed::validate_logical_path(&relative).map_err(error)?;
        if relative.split('/').any(|part| part.eq_ignore_ascii_case(".solidcraft-pdm")) {
            return Err(fail("Private workspace metadata cannot be archived as a design"));
        }
        if logical_path.as_ref().is_some_and(|logical| !logical.is_empty() && *logical != relative) {
            return Err(fail("The archive path must match the saved working-folder path"));
        }
        let key = solidcraft_engine::pdm::cached_path_key(&absolute.to_string_lossy());
        if complete.contains(&key) {
            return Ok(());
        }
        if depth > 32 || visiting.len() + complete.len() >= solidcraft_pdm::MAX_VERSIONS {
            return Err(fail("Assembly archive graph limit exceeded"));
        }
        if !visiting.insert(key.clone()) {
            return Err(fail("Assembly archive graph contains a cycle"));
        }
        let captured = solidcraft_pdm::transfer_source::FileSource::open(&absolute, file_limit as u64, &std::sync::atomic::AtomicBool::new(false))
            .map_err(|failure| transfer::source_failure(&absolute, failure))?;
        let size = captured.info().bytes;
        let sha256 = captured.info().sha256.clone();
        let bytes = read_file(&absolute, file_limit).map_err(error)?;
        if bytes.len() as u64 != size || hash(&bytes) != sha256 {
            return Err(fail("A saved component changed during archive preflight; nothing was archived"));
        }
        super::pdm::validate_saved(&bytes, saved, visibility)?;
        drop(bytes);
        drop(captured);
        let mut children = Vec::new();
        for link in saved.links.values() {
            let source = absolute.parent().ok_or_else(|| fail("Saved assembly folder unavailable"))?.join(&link.path);
            crate::pdm_connections::guard_workspace_path(&source).map_err(|_| fail("Archive component links and reparse points are forbidden"))?;
            let source = fs::canonicalize(source).map_err(|_| fail("A linked native component is missing"))?;
            let child_relative = source
                .strip_prefix(ws.root())
                .map_err(|_| fail("Save every assembly component inside the current working folder before archiving"))?
                .to_string_lossy()
                .replace('\\', "/");
            let loaded = load(&source)?;
            visit(
                ws,
                ManagedTask::Archive {
                    path: source.to_string_lossy().into_owned(),
                    logical_path: None,
                    saved: loaded.doc.clone(),
                    visibility: Box::new(loaded.visibility.clone()),
                },
                visiting,
                complete,
                nodes,
                depth + 1,
                file_limit,
            )?;
            children.push(child_relative);
        }
        if !saved.links.is_empty() {
            let mut probe = Session::default();
            probe.doc = saved.clone();
            probe.path = Some(absolute.to_string_lossy().into_owned());
            probe
                .execute("component.update_links", &serde_json::json!({"recursive":true}))
                .map_err(|_| fail("Could not resolve the saved assembly components before archiving"))?;
            if *probe.doc != **saved {
                return Err(fail("Update and save every assembly's current components before archiving"));
            }
        }
        visiting.remove(&key);
        complete.insert(key);
        nodes.push(ArchiveNode { task, path: absolute.to_string_lossy().into_owned(), relative, sha256, bytes: size, children });
        Ok(())
    }
    let mut nodes = Vec::new();
    visit(ws, root, &mut BTreeSet::new(), &mut BTreeSet::new(), &mut nodes, 0, file_limit)?;
    Ok(nodes)
}

fn dependency_updates(ws: &Workspace, local: &[LocalEntry], catalog: &[solidcraft_pdm::managed::CatalogEntry]) -> Vec<String> {
    let path_key =
        |path: &Path| solidcraft_engine::pdm::cached_path_key(&fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()).to_string_lossy());
    let paths: BTreeMap<_, _> = local.iter().map(|entry| (path_key(Path::new(&entry.path)), entry.document.clone())).collect();
    let mut graph = BTreeMap::new();
    let mut embedded_stale = BTreeSet::new();
    for entry in local {
        let links: Vec<String> = ws
            .path(&entry.document)
            .ok()
            .filter(|path| is_native_design(path))
            .and_then(|path| {
                read_file(&path, solidcraft_engine::io::MAX_DESIGN_BYTES)
                    .ok()
                    .and_then(|bytes| solidcraft_engine::io::read_design(&bytes).ok())
                    .map(|document| (path, document))
            })
            .map(|(path, document)| {
                if !document.links.is_empty() {
                    let mut probe = Session::default();
                    probe.doc = std::sync::Arc::new(document.clone());
                    probe.path = Some(path.to_string_lossy().into_owned());
                    if probe.execute("component.update_links", &serde_json::json!({"recursive":true})).is_err() || *probe.doc != document {
                        embedded_stale.insert(entry.document.clone());
                    }
                }
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
            if embedded_stale.contains(&root.document) {
                return true;
            }
            let mut queue = graph.get(&root.document).cloned().unwrap_or_default();
            let mut seen = BTreeSet::new();
            while let Some(document) = queue.pop() {
                if !seen.insert(document.clone()) {
                    continue;
                }
                if outdated.contains(document.as_str()) || embedded_stale.contains(&document) {
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
fn is_native_design(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| extension.eq_ignore_ascii_case("solidcraft"))
}
fn open_managed(path: &Path, opener: fn(&Path) -> Result<(), String>, refresh_links: bool) -> Result<Option<Box<Session>>, Failure> {
    if !is_native_design(path) {
        opener(path).map_err(|message| fail(&message))?;
        return Ok(None);
    }
    let mut loaded = load(path)?;
    if refresh_links && !loaded.doc.links.is_empty() {
        loaded
            .execute("component.update_links", &serde_json::json!({"recursive":true}))
            .map_err(|_| fail("The working assembly could not update its local components"))?;
    }
    Ok(Some(loaded))
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
        let staged = transfer::download(client, ws, &reference)?;
        if staged.version.sha256 != entry.base_sha256 {
            return Err(fail("Dependency base does not match the archived content"));
        }
        references.insert(reference);
    }
    if !saved.links.is_empty() {
        let mut probe = Session::default();
        probe.doc = saved.clone();
        probe.path = Some(path.into());
        probe
            .execute("component.update_links", &serde_json::json!({"recursive":true}))
            .map_err(|_| fail("Could not validate the assembly's consumed components"))?;
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
    /// Keep the source lock alive until preference publication and Host swap.
    /// Public catalog reservations are checked even when local installation failed.
    pub(crate) fn begin_workspace_change(&self, expected: &str, same: bool) -> Result<Workspace, Failure> {
        let client = self.client()?;
        let ws = self.workspace()?;
        if !same && ws.manifest().workspace_id != expected {
            return Err(fail("The current working folder changed; refresh settings before retrying"));
        }
        let catalog = client.managed_catalog().map_err(error)?;
        if catalog.server_id != self.server_id {
            return Err(fail("PDM service identity changed"));
        }
        if !same
            && (!self.grants.is_empty()
                || ws.manifest().documents.values().any(|entry| entry.checked_out)
                || catalog
                    .entries
                    .iter()
                    .any(|entry| entry.checkout.as_ref().is_some_and(|checkout| checkout.workspace == ws.manifest().workspace_id)))
        {
            return Err(fail("Finish or undo all checkouts in the current working folder before changing it"));
        }
        Ok(ws)
    }
    pub(crate) fn prepare_workspace_candidate(
        &self,
        session: crate::pdm_login::AuthenticatedSession,
        selection: &crate::pdm_connections::WorkspaceSelection,
        source: &Workspace,
    ) -> Result<AuthenticatedHost, Failure> {
        let actual = session.client.authenticated_identity().map_err(error)?;
        let previous = self.client()?.authenticated_identity().map_err(error)?;
        if actual != session.identity
            || actual != previous
            || actual.server_id != self.server_id
            || actual.server_id != session.profile.server_id()
            || actual.principal.id != session.profile.principal_id()
            || solidcraft_engine::pdm::cached_path_key(source.root().to_str().ok_or_else(|| fail("Invalid working folder"))?)
                != solidcraft_engine::pdm::cached_path_key(selection.source.to_str().ok_or_else(|| fail("Invalid working folder"))?)
        {
            return Err(fail("The saved connection no longer matches the active authenticated working folder"));
        }
        if selection.same {
            if selection
                .previous
                .as_ref()
                .is_none_or(|preference| preference.workspace != source.manifest().workspace_id || preference.server != self.server_id)
            {
                return Err(fail("The saved working folder identity changed; reconnect explicitly"));
            }
            let candidate = Self {
                client: Some(session.client),
                port: self.port,
                root: self.root.clone(),
                server_id: self.server_id.clone(),
                machine: self.machine.clone(),
                grants: self.grants.clone(),
            };
            return Ok(AuthenticatedHost { port: self.port, state: candidate.state(source, None)?, host: candidate });
        }
        crate::pdm_connections::guard_workspace_path(&selection.destination)
            .map_err(|_| fail("Working folder links and reparse points are forbidden"))?;
        if fs::read_dir(&selection.destination)
            .map_err(|_| fail("The new working folder cannot be inspected"))?
            .next()
            .transpose()
            .map_err(|_| fail("The new working folder cannot be inspected"))?
            .is_some()
        {
            return Err(fail("Choose an empty working folder; the previous working folder is preserved"));
        }
        // Repeat reservation preflight after fresh authentication, before any destination write.
        let catalog = session.client.managed_catalog().map_err(error)?;
        if catalog.server_id != self.server_id
            || catalog
                .entries
                .iter()
                .any(|entry| entry.checkout.as_ref().is_some_and(|checkout| checkout.workspace == source.manifest().workspace_id))
        {
            return Err(fail("The current working folder has server reservations; finish or undo them first"));
        }
        let candidate = Self::connect_authenticated(session, &selection.destination, false)?;
        if fs::read_dir(&selection.destination)
            .map_err(|_| fail("The new working folder cannot be inspected"))?
            .any(|entry| entry.map_or(true, |entry| entry.file_name() != ".solidcraft-pdm"))
        {
            return Err(fail("The previous working folder is preserved; the new folder is no longer empty"));
        }
        crate::pdm_connections::guard_workspace_path(&selection.destination)
            .map_err(|_| fail("Working folder links and reparse points are forbidden"))?;
        Ok(candidate)
    }

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
                let staged =
                    transfer::download(&session.client, &workspace, &VersionRef { document: document.clone(), version: entry.base_version })?;
                if staged.version.sha256 != entry.base_sha256 {
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
    #[test]
    fn opaque_attachment_import_open_preserves_bytes_and_authority() {
        use std::sync::atomic::AtomicUsize;
        static OPENED: AtomicUsize = AtomicUsize::new(0);
        fn record(path: &Path) -> Result<(), String> {
            assert_eq!(path.extension().and_then(|extension| extension.to_str()), Some("ipt"));
            assert!(fs::metadata(path).unwrap().permissions().readonly());
            OPENED.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn record_owned(path: &Path) -> Result<(), String> {
            assert!(!fs::metadata(path).unwrap().permissions().readonly());
            OPENED.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        let trial = Trial::new();
        let mut producer = trial.host("producer");
        let source = trial.root.join("sample.ipt");
        let bytes: Vec<u8> = (0..4096).map(|index| (index % 256) as u8).collect();
        fs::write(&source, &bytes).unwrap();
        let workspace = producer.workspace().unwrap().manifest().workspace_id.clone();
        let task = || ManagedTask::ImportNew {
            source_path: source.to_string_lossy().into_owned(),
            folder: "Imports".into(),
            expected_workspace: workspace.clone(),
        };
        run(&mut producer, task());
        assert!(producer.execute(task(), None).is_err());
        let catalog = producer.client().unwrap().managed_catalog().unwrap();
        assert_eq!(catalog.entries.len(), 1);
        let document = catalog.entries[0].document.clone();
        assert_eq!(catalog.entries[0].head, Some(1));
        assert!(catalog.entries[0].checkout.is_none());
        let mut consumer = trial.host("consumer");
        for task in [ManagedTask::Open { document: document.clone() }, ManagedTask::OpenReferenced { document: document.clone() }] {
            let (_, loaded) = consumer.execute_single_with_opener(task, None, record).unwrap_or_else(|error| panic!("{}", error.message));
            assert!(loaded.is_none(), "an opaque attachment must not create a design tab");
        }
        let copy = consumer.workspace().unwrap().path(&document).unwrap();
        assert_eq!(fs::read(&copy).unwrap(), bytes);
        assert_eq!(fs::read(source).unwrap(), bytes);
        assert_eq!(OPENED.load(Ordering::SeqCst), 2);
        assert!(consumer.grants.is_empty());
        consumer.execute_single_with_opener(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None, record_owned).unwrap();
        assert_eq!(OPENED.load(Ordering::SeqCst), 2, "checkout must only change authority and permissions, never open the attachment");
        fs::write(&copy, b"owned external edit").unwrap();
        consumer.execute_single_with_opener(ManagedTask::OpenReferenced { document: document.clone() }, None, record_owned).unwrap();
        assert_eq!(fs::read(&copy).unwrap(), b"owned external edit", "opening must preserve the owned modified attachment");
        consumer.execute_single_with_opener(ManagedTask::CancelCheckout { document: Some(document.clone()), path: None }, None, record).unwrap();
        assert_eq!(fs::read(&copy).unwrap(), bytes);
        assert_eq!(OPENED.load(Ordering::SeqCst), 3, "cancel checkout must not reopen the attachment");
        assert!(consumer.grants.is_empty());
        assert_eq!(consumer.client().unwrap().managed_history(document).unwrap().len(), 1);
    }
    #[test]
    fn opaque_attachment_owned_checkin_reads_working_bytes_without_a_cad_session() {
        fn no_launch(_: &Path) -> Result<(), String> {
            Ok(())
        }
        let trial = Trial::new();
        let mut host = trial.host("working");
        let source = trial.root.join("notes.txt");
        fs::write(&source, b"version one").unwrap();
        let workspace = host.workspace().unwrap().manifest().workspace_id.clone();
        run(
            &mut host,
            ManagedTask::ImportNew { source_path: source.to_string_lossy().into_owned(), folder: "Imports".into(), expected_workspace: workspace },
        );
        let document = host.client().unwrap().managed_catalog().unwrap().entries[0].document.clone();
        host.execute_single_with_opener(ManagedTask::Checkout { document: Some(document.clone()), path: None }, None, no_launch).unwrap();
        let copy = host.workspace().unwrap().path(&document).unwrap();
        fs::write(&copy, b"edited externally").unwrap();
        let session = Session::default();
        let task = || ManagedTask::Archive {
            path: copy.to_string_lossy().into_owned(),
            logical_path: None,
            saved: session.doc.clone(),
            visibility: Box::new(session.visibility.clone()),
        };
        let (_, opened) = host.execute(task(), None).unwrap_or_else(|error| panic!("{}", error.message));
        assert!(opened.is_none());
        let catalog = host.client().unwrap().managed_catalog().unwrap();
        assert_eq!(catalog.entries[0].head, Some(2));
        assert!(catalog.entries[0].checkout.is_none());
        assert!(host.grants.is_empty());
        assert_eq!(host.client().unwrap().download(&VersionRef { document, version: 2 }).unwrap().1, b"edited externally");
        assert_eq!(fs::read(&source).unwrap(), b"version one");
        assert!(fs::metadata(&copy).unwrap().permissions().readonly());
        assert!(host.execute(task(), None).is_err(), "after check-in another publication requires an explicit new checkout");
        assert_eq!(host.client().unwrap().managed_catalog().unwrap().entries[0].head, Some(2));
    }
    #[test]
    fn opaque_attachment_txt_working_copy_open_skips_native_parser() {
        fn record(path: &Path) -> Result<(), String> {
            assert_eq!(path.extension().and_then(|extension| extension.to_str()), Some("txt"));
            assert_eq!(fs::read(path).unwrap(), b"Archive this text without parsing a design");
            assert!(fs::metadata(path).unwrap().permissions().readonly());
            Ok(())
        }
        let trial = Trial::new();
        let mut producer = trial.host("producer");
        let source = trial.root.join("drop-here.txt");
        fs::write(&source, b"Archive this text without parsing a design").unwrap();
        let workspace = producer.workspace().unwrap().manifest().workspace_id.clone();
        run(
            &mut producer,
            ManagedTask::ImportNew { source_path: source.to_string_lossy().into_owned(), folder: "Imports".into(), expected_workspace: workspace },
        );
        let document = producer.client().unwrap().managed_catalog().unwrap().entries[0].document.clone();
        let mut consumer = trial.host("consumer");
        for task in [ManagedTask::Open { document: document.clone() }, ManagedTask::OpenReferenced { document: document.clone() }] {
            let (_, loaded) = consumer.execute_single_with_opener(task, None, record).unwrap_or_else(|error| panic!("{}", error.message));
            assert!(loaded.is_none(), "opening text must not replace the CAD session");
        }
        let copy = consumer.workspace().unwrap().path(&document).unwrap();
        assert!(load(&copy).is_err(), "the old unconditional native parser must reject this reproduction");
        assert!(consumer.grants.is_empty());
        let catalog = consumer.client().unwrap().managed_catalog().unwrap();
        assert_eq!(catalog.entries[0].head, Some(1));
        assert!(catalog.entries[0].checkout.is_none());
    }
    #[test]
    fn opaque_attachment_import_accepts_exact_legacy_file_boundary() {
        fn record(path: &Path) -> Result<(), String> {
            assert_eq!(fs::read(path).unwrap(), vec![255; 1_048_576]);
            assert!(fs::metadata(path).unwrap().permissions().readonly());
            Ok(())
        }
        let trial = Trial::new();
        let mut producer = trial.host("producer");
        let source = trial.root.join("boundary.ipt");
        fs::write(&source, vec![255; 1_048_576]).unwrap();
        let workspace = producer.workspace().unwrap().manifest().workspace_id.clone();
        run(
            &mut producer,
            ManagedTask::ImportNew { source_path: source.to_string_lossy().into_owned(), folder: "Imports".into(), expected_workspace: workspace },
        );
        let document = producer.client().unwrap().managed_catalog().unwrap().entries[0].document.clone();
        let mut consumer = trial.host("consumer");
        let (_, loaded) = consumer.execute_single_with_opener(ManagedTask::Open { document }, None, record).unwrap();
        assert!(loaded.is_none());
        assert_eq!(fs::metadata(source).unwrap().len(), 1_048_576);
    }
    #[test]
    fn opaque_attachment_size_failure_reports_limit_without_credential_advice_or_writes() {
        for size in [1_048_577, 1_290_000, 1_352_663] {
            let trial = Trial::new();
            let mut host = trial.host("working");
            let source = trial.root.join("oversized.ipt");
            fs::write(&source, vec![0x51; size]).unwrap();
            let workspace = host.workspace().unwrap().manifest().workspace_id.clone();
            let result = host.execute(
                ManagedTask::ImportNew { source_path: source.to_string_lossy().into_owned(), folder: String::new(), expected_workspace: workspace },
                None,
            );
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("oversized import must be rejected"),
            };
            let detail: serde_json::Value =
                serde_json::from_str(&error.message).unwrap_or_else(|_| panic!("Missing size details: {}", error.message));
            assert_eq!(detail["pdm_error"], "file_size_limit");
            assert_eq!(detail["filename"], "oversized.ipt");
            assert_eq!(detail["actual_bytes"], size);
            assert_eq!(detail["limit_bytes"], 1_048_576);
            assert!(!error.message.contains(&trial.root.to_string_lossy().to_string()));
            assert!(!error.message.contains("credential"));
            assert!(!error.disconnect);
            assert!(host.client().unwrap().managed_catalog().unwrap().entries.is_empty());
            assert!(!host.root.as_ref().unwrap().join("oversized.ipt").exists());
            assert_eq!(fs::metadata(source).unwrap().len(), size as u64);
        }
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
    fn workspace_settings_source_rejects_remote_reservation_missing_from_manifest() {
        let trial = Trial::new();
        let host = trial.host("source-reservation");
        let workspace = host.workspace().unwrap().manifest().workspace_id.clone();
        let client = host.client().unwrap();
        let entry = client.managed_create("remote-only.solidcraft".into()).unwrap();
        let grant = client.managed_checkout(entry.document.clone(), workspace.clone(), "other-machine".into()).unwrap();
        assert!(host.grants.is_empty());
        assert!(host.workspace().unwrap().manifest().documents.is_empty());
        let failure = host.begin_workspace_change(&workspace, false).err().unwrap();
        assert!(failure.message.contains("checkouts"));
        assert_eq!(client.managed_resume_checkout(entry.document.clone(), workspace.clone(), "other-machine".into()).unwrap(), grant);
        assert!(host.workspace().unwrap().manifest().documents.is_empty());
    }
    #[test]
    fn workspace_settings_source_rejects_stale_identity_pending_journal_and_local_checkout() {
        let trial = Trial::new();
        let mut host = trial.host("source-fences");
        let workspace = host.workspace().unwrap().manifest().workspace_id.clone();
        assert!(host.begin_workspace_change("stale", false).is_err());
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let before = fs::read(&path).unwrap();
        let document = archive(&mut host, &design);
        run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        assert!(host.begin_workspace_change(&workspace, false).is_err());
        run(&mut host, ManagedTask::CancelCheckout { document: Some(document), path: None });
        fs::write(host.root.as_ref().unwrap().join(".solidcraft-pdm").join("pending"), b"interrupted").unwrap();
        assert!(host.begin_workspace_change(&workspace, false).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }
    #[test]
    fn workspace_settings_failed_preference_publish_keeps_original_host_and_checkout_grant() {
        let trial = Trial::new();
        let mut host = trial.host("source-publish");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut host, &design);
        run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let root = host.root.clone();
        let grant = host.grants[&document].clone();
        let holder = std::sync::Mutex::new(Some(host.client().unwrap()));
        let candidate = trial.host("candidate-publish");
        assert!(super::super::pdm::commit_workspace_host(&mut host, &holder, candidate, || Err(fail("injected preference failure"))).is_err());
        assert_eq!(host.root, root);
        assert_eq!(host.grants[&document], grant);
        let ws = host.workspace().unwrap();
        assert_eq!(
            host.client().unwrap().managed_resume_checkout(document, ws.manifest().workspace_id.clone(), host.machine.clone()).unwrap(),
            grant
        );
    }
    #[test]
    fn workspace_settings_poisoned_holder_never_calls_preference_publisher() {
        let trial = Trial::new();
        let mut host = trial.host("source-poison");
        let root = host.root.clone();
        let holder = std::sync::Mutex::new(Some(host.client().unwrap()));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = holder.lock().unwrap();
                panic!("test poison")
            }))
            .is_err()
        );
        let called = std::cell::Cell::new(false);
        let candidate = trial.host("candidate-poison");
        assert!(
            super::super::pdm::commit_workspace_host(&mut host, &holder, candidate, || {
                called.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!called.get());
        assert_eq!(host.root, root);
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
    // USER8 regression fixture: a saved assembly consumes component v1 while
    // the normal managed component working copy has already advanced to v2.
    fn user8_old_pin_fixture(trial: &Trial) -> (Host, String, String, Session) {
        let mut host = trial.host("user8-reference-working");
        let root = host.root.clone().unwrap();
        let bracket_path = root.join("Bracket.solidcraft");
        let bracket = part(&bracket_path);
        let bracket_id = archive(&mut host, &bracket);
        let mut fixture = Session::default();
        fixture.execute("file.save", &serde_json::json!({"path":root.join("Fixture.solidcraft")})).unwrap();
        fixture.execute("component.insert_design", &serde_json::json!({"path":bracket_path})).unwrap();
        fixture.execute("file.save", &serde_json::json!({})).unwrap();
        let fixture_id = archive(&mut host, &fixture);
        let (_, loaded) = run(&mut host, ManagedTask::Checkout { document: Some(bracket_id.clone()), path: None });
        let mut changed = *loaded.unwrap();
        changed.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        changed.execute("file.save", &serde_json::json!({})).unwrap();
        assert_eq!(archive(&mut host, &changed), bracket_id);
        assert_eq!(host.client().unwrap().managed_history(bracket_id.clone()).unwrap().len(), 2);
        assert_eq!(
            host.client().unwrap().managed_history(fixture_id.clone()).unwrap()[0].version.dependencies,
            vec![VersionRef { document: bracket_id.clone(), version: 1 }]
        );
        (host, bracket_id, fixture_id, fixture)
    }

    #[test]
    fn user8_history_where_used_keeps_old_source_pins_and_preview_is_exact() {
        let trial = Trial::new();
        let (mut host, bracket, fixture, _) = user8_old_pin_fixture(&trial);
        let parent = Reference { document: fixture, version: 1 };
        let used = Reference { document: bracket.clone(), version: 1 };
        let (Outcome::Managed { state, .. }, opened) = run(&mut host, ManagedTask::History { document: bracket.clone() }) else {
            panic!("expected managed history");
        };
        assert!(opened.is_none());
        assert_eq!(state.history.len(), 2);
        assert_eq!(state.where_used, vec![parent.clone()], "history must retain a parent consuming an older source pin");
        assert_eq!(state.where_used_details.len(), 1);
        assert_eq!(state.where_used_details[0].parent, parent);
        assert_eq!(state.where_used_details[0].used, used);
        let (Outcome::Managed { state, .. }, _) = run(&mut host, ManagedTask::Preview { reference: Reference { document: bracket, version: 2 } })
        else {
            panic!("expected exact preview");
        };
        assert!(state.where_used.is_empty(), "Fixture consumes v1, so it is not an exact v2 reference");
        assert!(state.where_used_details.is_empty());
        let (Outcome::Managed { state, .. }, _) = run(&mut host, ManagedTask::Preview { reference: used.clone() }) else {
            panic!("expected exact preview");
        };
        assert_eq!(state.where_used, vec![parent.clone()]);
        assert_eq!(state.where_used_details.len(), 1);
        assert_eq!(state.where_used_details[0].parent, parent);
        assert_eq!(state.where_used_details[0].used, used);
        assert!(host.grants.is_empty());
        assert!(host.client().unwrap().managed_catalog().unwrap().entries.iter().all(|entry| entry.checkout.is_none()));
    }

    #[test]
    fn user9_referenced_working_open_resolves_current_components_without_checkout() {
        let trial = Trial::new();
        let (mut host, bracket, fixture, saved) = user8_old_pin_fixture(&trial);
        let path = saved.path.as_ref().unwrap();
        let bytes = fs::read(path).unwrap();
        let (_, opened) = run(&mut host, ManagedTask::OpenReferenced { document: fixture.clone() });
        let opened = opened.unwrap();
        assert!(solidcraft_engine::pdm::same_file_path(opened.path.as_deref().unwrap(), path));
        assert_ne!(*opened.doc, *saved.doc, "a live working assembly must resolve the current saved component");
        assert!(opened.world_state().bodies.len() > saved.world_state().bodies.len());
        assert!(opened.is_dirty(), "derived current geometry is not silently saved or republished");
        assert!(!opened.pdm_read_only, "normal reference navigation opens the managed working copy, not a historical snapshot");
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert!(host.grants.is_empty());
        let client = host.client().unwrap();
        assert!(client.managed_catalog().unwrap().entries.iter().all(|entry| entry.checkout.is_none()));
        assert_eq!(client.managed_history(fixture).unwrap().len(), 1);
        assert_eq!(client.managed_history(bracket).unwrap().len(), 2);
    }

    #[test]
    fn user9_existing_assembly_refreshes_clean_components_but_preserves_owned_edits() {
        let trial = Trial::new();
        let (publisher, bracket, fixture, saved) = user8_old_pin_fixture(&trial);
        let mut consumer = trial.host("user9-live-consumer");
        let client = publisher.client().unwrap();
        {
            let mut ws = consumer.workspace().unwrap();
            let catalog = client.managed_catalog().unwrap();
            for document in [&bracket, &fixture] {
                let logical = &catalog.entries.iter().find(|entry| &entry.document == document).unwrap().logical_path;
                let (metadata, bytes) = client.download(&VersionRef { document: document.clone(), version: 1 }).unwrap();
                ws.install(document, logical, 1, &metadata.sha256, &bytes).unwrap();
            }
        }
        let fixture_path = consumer.workspace().unwrap().path(&fixture).unwrap();
        let before = fs::read(&fixture_path).unwrap();
        let (_, opened) = run(&mut consumer, ManagedTask::OpenReferenced { document: fixture.clone() });
        let opened = opened.unwrap();
        assert!(opened.world_state().bodies.len() > saved.world_state().bodies.len());
        assert_eq!(consumer.workspace().unwrap().manifest().documents[&bracket].base_version, 2);
        assert_eq!(fs::read(&fixture_path).unwrap(), before, "live resolution must not rewrite the saved assembly");
        let (_, owned) = run(&mut consumer, ManagedTask::Checkout { document: Some(bracket.clone()), path: None });
        let mut owned = *owned.unwrap();
        owned.execute("solid.box", &serde_json::json!({"length":1,"width":1,"height":1})).unwrap();
        owned.execute("file.save", &serde_json::json!({})).unwrap();
        let owned_bytes = fs::read(owned.path.as_ref().unwrap()).unwrap();
        assert!(consumer.execute(ManagedTask::OpenReferenced { document: fixture }, None).is_err());
        assert_eq!(fs::read(owned.path.as_ref().unwrap()).unwrap(), owned_bytes);
        assert!(consumer.grants.contains_key(&bracket));
    }

    #[test]
    fn user9_recursive_archive_publishes_parts_before_parent_and_skips_clean_children() {
        let trial = Trial::new();
        let mut host = trial.host("user9-recursive-archive");
        let root = host.root.clone().unwrap();
        let child = part(&root.join("new-part.solidcraft"));
        let mut assembly = Session::default();
        assembly.execute("file.save", &serde_json::json!({"path":root.join("new-assembly.solidcraft")})).unwrap();
        assembly.execute("component.insert_design", &serde_json::json!({"path":child.path})).unwrap();
        assembly.execute("file.save", &serde_json::json!({})).unwrap();
        let parent = archive(&mut host, &assembly);
        let client = host.client().unwrap();
        let catalog = client.managed_catalog().unwrap();
        assert_eq!(catalog.entries.len(), 2);
        let child = catalog.entries.iter().find(|entry| entry.logical_path == "new-part.solidcraft").unwrap().document.clone();
        assert_eq!(client.managed_history(parent.clone()).unwrap()[0].version.dependencies, vec![VersionRef { document: child.clone(), version: 1 }]);
        let (_, checked) = run(&mut host, ManagedTask::Checkout { document: Some(parent.clone()), path: None });
        assert_eq!(archive(&mut host, &checked.unwrap()), parent);
        assert_eq!(client.managed_history(parent).unwrap().len(), 2);
        assert_eq!(client.managed_history(child).unwrap().len(), 1, "unchanged clean parts must not gain duplicate versions");
        assert!(client.managed_catalog().unwrap().entries.iter().all(|entry| entry.checkout.is_none()));
    }

    #[test]
    fn user9_recursive_archive_outside_link_fails_before_creating_any_server_document() {
        let trial = Trial::new();
        let mut host = trial.host("user9-outside-link");
        let external = part(&trial.root.join("outside.solidcraft"));
        let mut assembly = Session::default();
        assembly.execute("file.save", &serde_json::json!({"path":host.root.as_ref().unwrap().join("assembly.solidcraft")})).unwrap();
        assembly.execute("component.insert_design", &serde_json::json!({"path":external.path})).unwrap();
        assembly.execute("file.save", &serde_json::json!({})).unwrap();
        let result = host.execute(
            ManagedTask::Archive {
                path: assembly.path.clone().unwrap(),
                logical_path: None,
                saved: assembly.doc.clone(),
                visibility: Box::new(assembly.visibility.clone()),
            },
            None,
        );
        assert!(result.is_err());
        assert!(host.client().unwrap().managed_catalog().unwrap().entries.is_empty(), "outside graph rejection precedes even managed_create");
        assert!(host.grants.is_empty());
    }

    #[test]
    fn user9_missing_thumbnail_renders_exact_archived_assembly_without_updating_live_links() {
        use std::sync::atomic::AtomicUsize;
        let trial = Trial::new();
        let (host, _, fixture, saved) = user8_old_pin_fixture(&trial);
        let client = host.client().unwrap();
        let reference = Reference { document: fixture, version: 1 };
        let archived = client.download(&VersionRef { document: reference.document.clone(), version: 1 }).unwrap().1;
        assert!(solidcraft_engine::io::read_design_thumbnail(&archived).is_none());
        let rendered = Arc::new(AtomicUsize::new(0));
        let observed = rendered.clone();
        solidcraft_engine::capture::install(Arc::new(move |scene, _, width, height| {
            observed.store(scene.meshes.len(), Ordering::SeqCst);
            Ok(solidcraft_engine::capture::Picture { rgba: vec![200; (width * height * 4) as usize], renderer: "gpu" })
        }));
        let before = fs::read(saved.path.as_ref().unwrap()).unwrap();
        let workspace = host.workspace().unwrap();
        let preview = host.preview(&client, &workspace, &reference).unwrap().expect("missing archived thumbnails are rendered on the native worker");
        assert_eq!(preview.reference, reference);
        assert!(preview.png.starts_with(b"\x89PNG"));
        assert_eq!(rendered.load(Ordering::SeqCst), 1, "snapshot preview keeps its embedded v1 component, not current live v2");
        assert_eq!(fs::read(saved.path.as_ref().unwrap()).unwrap(), before);
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
    fn autosave_checkout_preserving_memory_returns_no_loaded_session_and_archives_current_saved_bytes() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let mut editor = part(&path);
        let archived = fs::read(&path).unwrap();
        let document = archive(&mut host, &editor);
        editor.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        assert!(editor.is_dirty());
        let (outcome, loaded) = run(
            &mut host,
            ManagedTask::CheckoutPreservingMemory { document: document.clone(), path: path.to_string_lossy().into_owned(), expected_base: 1 },
        );
        assert!(loaded.is_none(), "checkout must not supply an older disk session that could replace the dirty editor");
        assert_eq!(fs::read(&path).unwrap(), archived);
        assert!(!fs::metadata(&path).unwrap().permissions().readonly());
        let Outcome::Managed { state, .. } = outcome else { panic!("expected managed checkout") };
        assert!(state.local.iter().any(|entry| entry.document == document && entry.checked_out && entry.base_version == 1));
        assert!(host.grants.contains_key(&document));
        assert_eq!(host.client().unwrap().managed_history(document.clone()).unwrap().len(), 1);
        // The UI's existing asynchronous save writes this editor before publication.
        // Native archive validates that exact saved document, rather than old disk bytes.
        editor.execute("file.save", &serde_json::json!({})).unwrap();
        let current = fs::read(&path).unwrap();
        assert_ne!(current, archived);
        assert_eq!(archive(&mut host, &editor), document);
        let (version, published) = host.client().unwrap().download(&VersionRef { document: document.clone(), version: 2 }).unwrap();
        assert_eq!(published, current);
        assert_eq!(version.sha256, hash(&current));
        assert_eq!(host.client().unwrap().managed_history(document).unwrap().len(), 2);
    }

    #[test]
    fn autosave_checkout_preserving_memory_rejects_stale_base_without_installing_or_reserving() {
        let trial = Trial::new();
        let mut producer = trial.host("producer");
        let source = producer.root.as_ref().unwrap().join("part.solidcraft");
        let original = part(&source);
        let document = archive(&mut producer, &original);
        let mut consumer = trial.host("consumer");
        let (_, loaded) = run(&mut consumer, ManagedTask::Open { document: document.clone() });
        let consumer_path = PathBuf::from(loaded.unwrap().path.unwrap());
        let before = fs::read(&consumer_path).unwrap();
        let (_, loaded) = run(&mut producer, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let mut newer = *loaded.unwrap();
        newer.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        newer.execute("file.save", &serde_json::json!({})).unwrap();
        archive(&mut producer, &newer);
        for expected_base in [1, 2] {
            assert!(
                consumer
                    .execute(
                        ManagedTask::CheckoutPreservingMemory {
                            document: document.clone(),
                            path: consumer_path.to_string_lossy().into_owned(),
                            expected_base,
                        },
                        None
                    )
                    .is_err()
            );
            assert_eq!(fs::read(&consumer_path).unwrap(), before);
            assert!(consumer.grants.is_empty());
        }
        assert_eq!(consumer.workspace().unwrap().manifest().documents[&document].base_version, 1);
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

    #[test]
    fn autosave_checkout_preserving_memory_rejects_modified_disk_or_unregistered_path() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut host, &design);
        let original = fs::read(&path).unwrap();
        let unrelated = trial.root.join("other.solidcraft");
        fs::write(&unrelated, &original).unwrap();
        assert!(
            host.execute(
                ManagedTask::CheckoutPreservingMemory {
                    document: document.clone(),
                    path: unrelated.to_string_lossy().into_owned(),
                    expected_base: 1,
                },
                None
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        remove_copy(&path);
        fs::write(&path, b"externally modified local content").unwrap();
        assert!(
            host.execute(
                ManagedTask::CheckoutPreservingMemory { document: document.clone(), path: path.to_string_lossy().into_owned(), expected_base: 1 },
                None
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"externally modified local content");
        assert_eq!(fs::read(&unrelated).unwrap(), original);
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
    fn discard_failed_release_keeps_verified_checkout_visible_for_safe_retry() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let archived = fs::read(&path).unwrap();
        let document = archive(&mut host, &design);
        let (_, opened) = run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let mut edited = *opened.unwrap();
        edited.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        edited.execute("file.save", &serde_json::json!({})).unwrap();
        let changed = fs::read(&path).unwrap();
        assert_ne!(changed, archived);
        let grant = host.grants.get(&document).unwrap().clone();
        let generation = host.workspace().unwrap().manifest().generation;
        // A real metadata-storage failure: reads remain available, but the next
        // immutable server generation cannot be staged until this obstacle is removed.
        let blocked_staging = trial.root.join("store/managed/generations/pending");
        fs::write(&blocked_staging, b"temporarily unavailable metadata storage").unwrap();
        assert!(host.execute(ManagedTask::CancelCheckout { document: Some(document.clone()), path: None }, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), archived);
        assert_eq!(fs::read(host.root.as_ref().unwrap().join(format!(".solidcraft-pdm/backup-{generation}"))).unwrap(), changed);
        assert_eq!(host.grants.get(&document), Some(&grant));
        let client = host.client().unwrap();
        assert_eq!(
            client.managed_catalog().unwrap().entries.into_iter().find(|entry| entry.document == document).unwrap().checkout,
            grant.entry.checkout
        );
        let workspace = host.workspace().unwrap();
        assert!(!workspace.manifest().documents[&document].checked_out, "the local restore finished before server release failed");
        let state = host.state(&workspace, Some(&document)).unwrap();
        assert!(
            state.local.iter().any(|entry| entry.document == document && entry.checked_out),
            "the still-valid server grant must remain visible for cancellation retry"
        );
        drop(workspace);
        fs::remove_file(&blocked_staging).unwrap();
        let (_, opened) = run(&mut host, ManagedTask::CancelCheckout { document: Some(document.clone()), path: None });
        assert!(opened.is_some());
        assert_eq!(fs::read(&path).unwrap(), archived);
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        assert!(host.grants.is_empty());
        assert!(client.managed_catalog().unwrap().entries.into_iter().find(|entry| entry.document == document).unwrap().checkout.is_none());
        assert_eq!(client.managed_history(document).unwrap().len(), 1);
    }

    #[test]
    fn discard_restore_failure_keeps_server_grant_and_unrelated_local_data() {
        let trial = Trial::new();
        let mut host = trial.host("working");
        let path = host.root.as_ref().unwrap().join("part.solidcraft");
        let design = part(&path);
        let document = archive(&mut host, &design);
        run(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
        let grant = host.grants.get(&document).unwrap().clone();
        remove_copy(&path);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep.txt"), b"unrelated local data").unwrap();
        assert!(host.execute(ManagedTask::CancelCheckout { document: Some(document.clone()), path: None }, None).is_err());
        assert_eq!(fs::read(path.join("keep.txt")).unwrap(), b"unrelated local data");
        assert_eq!(host.grants.get(&document), Some(&grant));
        assert_eq!(
            host.client().unwrap().managed_catalog().unwrap().entries.into_iter().find(|entry| entry.document == document).unwrap().checkout,
            grant.entry.checkout
        );
        assert_eq!(host.client().unwrap().managed_history(document).unwrap().len(), 1);
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

#[cfg(test)]
mod administration_tests {
    use super::*;
    #[test]
    fn admin_read_on_legacy_transport_is_unavailable_without_touching_normal_host_or_disk() {
        let mut host = Host { client: Some(Client::new(1, AuthToken::parse("b".repeat(64)).unwrap())), ..Default::default() };
        let (outcome, opened) = host.execute(ManagedTask::AdministrationRead, None).unwrap();
        let Outcome::Administration(snapshot) = outcome else { panic!("expected bounded administration metadata") };
        assert_eq!(snapshot.users_status, solidcraft_engine::pdm::AdminReadStatus::Unsupported);
        assert_eq!(snapshot.audit_status, solidcraft_engine::pdm::AdminReadStatus::Unsupported);
        assert!(snapshot.principal.is_none() && snapshot.users.is_empty() && snapshot.audit.is_empty());
        assert!(opened.is_none() && host.connected() && host.root.is_none());
    }
}
