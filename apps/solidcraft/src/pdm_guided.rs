//! Worker-owned local setup and saved login with candidate-only connection handoff.
#![cfg(not(target_arch = "wasm32"))]
use crate::{
    pdm_connections::{ConnectionDirectory, ConnectionRow, ConnectionState, IndexError, WorkspaceSelection},
    pdm_credentials::CredentialStore,
    pdm_login::{self, AuthenticatedSession, LoginError},
    pdm_profiles::ProfileDirectory,
    pdm_setup::{LocalSetup, RunningLocalSetup, SetupError},
};
use solidcraft_pdm::managed::Role;
use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
};

const MAX_CONNECTIONS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureCode {
    Invalid,
    NotFound,
    Busy,
    Capacity,
    Metadata,
    SetupIncomplete,
    CredentialUnavailable,
    CredentialMissing,
    ConnectionUnavailable,
    Authentication,
    IdentityMismatch,
    WorkingFolderMissing,
    WorkingFolderUnavailable,
    Attach,
}
/// Safe for a native worker to map into public engine status. No underlying
/// transport/server/keyring/Host error strings may be copied into this value.
#[derive(Debug, PartialEq, Eq)]
pub struct GuidedFailure {
    pub code: FailureCode,
    pub pending_connection_id: Option<String>,
}
impl fmt::Display for GuidedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.code {
            FailureCode::Invalid => "Invalid PDM connection request",
            FailureCode::NotFound => "Saved PDM connection not found",
            FailureCode::Busy => "PDM connection is busy",
            FailureCode::Capacity => "PDM connection limit reached",
            FailureCode::Metadata => "PDM connection metadata unavailable; preserve installation data",
            FailureCode::SetupIncomplete => "PDM local setup incomplete; preserve existing trust and credentials",
            FailureCode::CredentialUnavailable => "PDM saved credential unavailable",
            FailureCode::CredentialMissing => "PDM login required",
            FailureCode::ConnectionUnavailable => "PDM secure connection unavailable",
            FailureCode::IdentityMismatch => "PDM authenticated identity mismatch",
            FailureCode::WorkingFolderMissing => "PDM configured working folder is missing",
            FailureCode::WorkingFolderUnavailable => "PDM configured working folder unavailable",
            FailureCode::Authentication => "PDM connection authentication failed",
            FailureCode::Attach => "PDM workspace connection failed; previous connection preserved",
        })
    }
}
impl std::error::Error for GuidedFailure {}

/// Deliberately static: the root adapter maps its private Host errors here.
#[derive(Debug)]
pub struct AttachFailure;

/// Actual fresh server identity only; this may be converted into an engine DTO.
/// Rows returned by list() never gain authentication authority from this receipt.
#[derive(Debug)]
pub struct ActiveConnection {
    pub connection_id: String,
    pub label: String,
    pub origin: String,
    pub server_id: String,
    pub account: String,
    pub role: Role,
}

/// Candidate stays native-only. Extract/swap it only on successful controller
/// return; never serialize/debug this generic value into engine/UI status.
pub struct PreparedConnection<T> {
    candidate: T,
    connection: ActiveConnection,
    rows: Vec<ConnectionRow>,
}
impl<T> PreparedConnection<T> {
    pub fn into_parts(self) -> (T, ActiveConnection, Vec<ConnectionRow>) {
        (self.candidate, self.connection, self.rows)
    }
}

pub struct PreparedWorkspaceChange<T> {
    prepared: PreparedConnection<T>,
    selection: WorkspaceSelection,
}
impl<T> PreparedWorkspaceChange<T> {
    pub fn into_parts(self) -> (T, ActiveConnection, Vec<ConnectionRow>, WorkspaceSelection) {
        let (candidate, connection, rows) = self.prepared.into_parts();
        (candidate, connection, rows, self.selection)
    }
}

pub struct Controller<S: CredentialStore> {
    directory: ConnectionDirectory,
    credentials: S,
    owned: BTreeMap<String, RunningLocalSetup>,
}
impl<S: CredentialStore> fmt::Debug for Controller<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdmGuidedController").field("owned_local_services", &self.owned.len()).finish()
    }
}
impl<S: CredentialStore> Controller<S> {
    /// Pure constructor. CredentialStore construction/injection must also be
    /// side-effect-free; OS operations happen only inside invoked worker methods.
    pub fn new(private_base: PathBuf, credentials: S) -> Result<Self, GuidedFailure> {
        Self::with_boundaries(private_base, credentials, Vec::new())
    }
    pub fn with_boundaries(private_base: PathBuf, credentials: S, protected_roots: Vec<PathBuf>) -> Result<Self, GuidedFailure> {
        let directory =
            ConnectionDirectory::new(private_base).and_then(|directory| directory.with_boundaries(protected_roots)).map_err(index_failure)?;
        Ok(Self { directory, credentials, owned: BTreeMap::new() })
    }
    pub fn list(&self) -> Result<Vec<ConnectionRow>, GuidedFailure> {
        self.directory.list().map_err(index_failure)
    }

    pub fn create_local<T>(
        &mut self,
        label: &str,
        administrator: &str,
        attach: impl FnOnce(AuthenticatedSession, &Path) -> Result<T, AttachFailure>,
    ) -> Result<PreparedConnection<T>, GuidedFailure> {
        // Crash ordering is essential: a recoverable immutable index intent is
        // durable before installation/workspace parents, TLS or keyring effects.
        self.directory.prepare_settings_parent().map_err(index_failure)?;
        let reservation = self.directory.reserve_local(label, administrator).map_err(index_failure)?;
        self.open(&reservation.connection_id, attach).map_err(|mut error| {
            error.pending_connection_id = Some(reservation.connection_id);
            error
        })
    }

    pub fn open<T>(
        &mut self,
        connection_id: &str,
        attach: impl FnOnce(AuthenticatedSession, &Path) -> Result<T, AttachFailure>,
    ) -> Result<PreparedConnection<T>, GuidedFailure> {
        // Validate ID before list/lookup, using the canonical derived-path API.
        self.directory.workspace_path(connection_id).map_err(index_failure)?;
        let row = self.list()?.into_iter().find(|row| row.connection_id == connection_id).ok_or_else(|| failure(FailureCode::NotFound))?;
        let workspace = self.directory.workspace_path(connection_id).map_err(index_failure)?;
        let local_admin = match &row.state {
            ConnectionState::PendingLocal { administrator } | ConnectionState::LocalReadyRecorded { administrator, .. } => {
                Some(administrator.as_str())
            }
            ConnectionState::SavedProfileUnverified { .. } => None,
        };
        let (profile, local_profile_id) = match &row.state {
            ConnectionState::PendingLocal { administrator } => {
                self.ensure_owned_local(connection_id, administrator)?;
                let running = self.owned.get(connection_id).ok_or_else(|| failure(FailureCode::SetupIncomplete))?;
                (running.profile.clone(), Some(running.profile_id.clone()))
            }
            ConnectionState::LocalReadyRecorded { administrator, profile_id } => {
                self.ensure_owned_local(connection_id, administrator)?;
                let running = self.owned.get(connection_id).ok_or_else(|| failure(FailureCode::SetupIncomplete))?;
                if running.profile_id != *profile_id {
                    return Err(failure(FailureCode::Metadata));
                }
                (running.profile.clone(), Some(profile_id.clone()))
            }
            ConnectionState::SavedProfileUnverified { profile_id } => {
                let profiles = ProfileDirectory::new(self.directory.imported_profiles_path()).map_err(|_| failure(FailureCode::Metadata))?;
                (profiles.load(profile_id).map_err(|_| failure(FailureCode::Metadata))?, None)
            }
        };
        // Always authenticate freshly. An owned running service is reused here;
        // no attempt is made to bind its occupied port or restart its process.
        let session = pdm_login::resume(profile, &self.credentials).map_err(login_failure)?;
        if self
            .directory
            .workspace_preference(connection_id)
            .map_err(index_failure)?
            .is_some_and(|preference| preference.server != session.identity.server_id)
        {
            return Err(failure(FailureCode::Metadata));
        }
        // A committed folder preference binds identity; it never authorizes
        // initializing a replacement when the configured folder disappeared.
        let preference = self.directory.workspace_preference(connection_id).map_err(index_failure)?;
        if preference.is_some() {
            // Classify only the configured root's known I/O cause. Missing or
            // corrupt manifest metadata remains distinct from a missing folder.
            let metadata = fs::symlink_metadata(&workspace).map_err(configured_folder_io_failure)?;
            if !metadata.is_dir() {
                return Err(failure(FailureCode::WorkingFolderUnavailable));
            }
        }
        crate::pdm_connections::guard_workspace_path(&workspace).map_err(index_failure)?;
        if let Some(preference) = preference {
            let existing = solidcraft_pdm::managed_workspace::Workspace::open_for_recovery(&workspace, &session.identity.server_id).map_err(
                |error| match error {
                    solidcraft_pdm::Error::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        failure(FailureCode::WorkingFolderUnavailable)
                    }
                    _ => failure(FailureCode::Metadata),
                },
            )?;
            if existing.manifest().workspace_id != preference.workspace {
                return Err(failure(FailureCode::Metadata));
            }
        }
        self.directory.prepare_workspace_parent(connection_id).map_err(index_failure)?;
        let connection = ActiveConnection {
            connection_id: connection_id.into(),
            label: row.label,
            origin: session.profile.origin().into(),
            server_id: session.identity.server_id.clone(),
            account: session.identity.principal.id.clone(),
            role: session.identity.principal.role,
        };
        // The candidate must be connected already, but the old live Host remains
        // unchanged until the whole operation (including index publication) succeeds.
        let candidate = attach(session, &workspace).map_err(|_| failure(FailureCode::Attach))?;
        if let (Some(administrator), Some(profile_id)) = (local_admin, local_profile_id.as_deref()) {
            self.directory.record_local_ready(connection_id, administrator, profile_id).map_err(index_failure)?;
        }
        let rows = self.list()?;
        Ok(PreparedConnection { candidate, connection, rows })
    }

    pub fn prepare_workspace_change<T>(
        &mut self,
        connection_id: &str,
        destination: &Path,
        attach: impl FnOnce(AuthenticatedSession, &WorkspaceSelection) -> Result<T, AttachFailure>,
    ) -> Result<PreparedWorkspaceChange<T>, GuidedFailure> {
        let selection = self.directory.select_workspace(connection_id, destination).map_err(index_failure)?;
        let prepared = self.open(connection_id, |session, root| {
            if root != selection.source && fs::canonicalize(root).map_err(|_| AttachFailure)? != selection.source {
                return Err(AttachFailure);
            }
            attach(session, &selection)
        })?;
        Ok(PreparedWorkspaceChange { prepared, selection })
    }
    pub fn verify_configured_workspace(&self, connection_id: &str, workspace: Option<&str>, server: Option<&str>) -> Result<(), GuidedFailure> {
        if let Some(preference) = self.directory.workspace_preference(connection_id).map_err(index_failure)?
            && (Some(preference.workspace.as_str()) != workspace || Some(preference.server.as_str()) != server)
        {
            return Err(failure(FailureCode::Metadata));
        }
        Ok(())
    }
    pub fn publish_workspace_change(&self, selection: &WorkspaceSelection, workspace: &str, server: &str) -> Result<(), GuidedFailure> {
        self.directory.record_workspace(selection, workspace, server).map_err(index_failure)
    }

    fn ensure_owned_local(&mut self, connection_id: &str, administrator: &str) -> Result<(), GuidedFailure> {
        if let Some(running) = self.owned.get(connection_id) {
            validate_running(running, administrator)?;
            return Ok(());
        }
        if self.owned.len() >= MAX_CONNECTIONS {
            return Err(failure(FailureCode::Capacity));
        }
        self.directory.prepare_local_parents(connection_id).map_err(index_failure)?;
        let root = self.directory.installation_path(connection_id).map_err(index_failure)?;
        let setup = LocalSetup::new(root.clone()).map_err(setup_failure)?;
        let running = match fs::symlink_metadata(&root) {
            Ok(_) => setup.resume(&self.credentials),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => setup.begin(administrator, &self.credentials),
            Err(_) => return Err(failure(FailureCode::Metadata)),
        }
        .map_err(setup_failure)?;
        validate_running(&running, administrator)?;
        // Keep our own server alive even after later attachment/publication failure.
        // Retrying the preserved pending connection reuses this exact handle.
        self.owned.insert(connection_id.into(), running);
        Ok(())
    }
}

fn validate_running(running: &RunningLocalSetup, administrator: &str) -> Result<(), GuidedFailure> {
    if running.receipt.administrator != administrator
        || running.profile.principal_id() != administrator
        || running.receipt.server_id != running.profile.server_id()
        || ProfileDirectory::profile_id(&running.profile).map_err(|_| failure(FailureCode::Metadata))? != running.profile_id
    {
        return Err(failure(FailureCode::Metadata));
    }
    Ok(())
}
fn failure(code: FailureCode) -> GuidedFailure {
    GuidedFailure { code, pending_connection_id: None }
}
fn configured_folder_io_failure(error: std::io::Error) -> GuidedFailure {
    failure(match error.kind() {
        std::io::ErrorKind::NotFound => FailureCode::WorkingFolderMissing,
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotADirectory => FailureCode::WorkingFolderUnavailable,
        _ => FailureCode::Metadata,
    })
}
fn index_failure(error: IndexError) -> GuidedFailure {
    failure(match error {
        IndexError::Invalid => FailureCode::Invalid,
        IndexError::NotFound => FailureCode::NotFound,
        IndexError::Busy => FailureCode::Busy,
        IndexError::Capacity => FailureCode::Capacity,
        _ => FailureCode::Metadata,
    })
}
fn setup_failure(error: SetupError) -> GuidedFailure {
    failure(match error {
        SetupError::Busy => FailureCode::Busy,
        SetupError::Credentials => FailureCode::CredentialUnavailable,
        SetupError::Service => FailureCode::Attach,
        _ => FailureCode::SetupIncomplete,
    })
}
fn login_failure(error: LoginError) -> GuidedFailure {
    failure(match error {
        LoginError::CredentialMissing => FailureCode::CredentialMissing,
        LoginError::CredentialUnavailable => FailureCode::CredentialUnavailable,
        LoginError::ConnectionUnavailable => FailureCode::ConnectionUnavailable,
        LoginError::IdentityMismatch => FailureCode::IdentityMismatch,
        LoginError::InvalidProfile => FailureCode::Metadata,
        LoginError::AuthenticationFailed => FailureCode::Authentication,
        LoginError::ConnectionFailed | LoginError::EnrollmentFailed => FailureCode::Attach,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdm_credentials::{BearerSecret, CredentialError, CredentialKey};
    use std::{
        cell::{Cell, RefCell},
        net::TcpListener,
    };
    #[derive(Default)]
    struct Memory {
        values: RefCell<BTreeMap<CredentialKey, String>>,
        fail_set: Cell<bool>,
        reads: Cell<usize>,
    }
    impl CredentialStore for Memory {
        fn get(&self, key: &CredentialKey) -> Result<Option<BearerSecret>, CredentialError> {
            self.reads.set(self.reads.get() + 1);
            self.values.borrow().get(key).cloned().map(BearerSecret::parse).transpose()
        }
        fn set(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError> {
            if self.fail_set.get() {
                return Err(CredentialError::Unavailable);
            }
            self.values.borrow_mut().insert(key.clone(), secret.expose().into());
            Ok(())
        }
        fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError> {
            self.values.borrow_mut().remove(key);
            Ok(())
        }
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self(std::env::temp_dir().join(format!("solidcraft-guided-{}", solidcraft_pdm::AuthToken::generate()?))))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct Candidate {
        session: AuthenticatedSession,
    }
    fn attach(session: AuthenticatedSession, workspace: &Path) -> Result<Candidate, AttachFailure> {
        if !workspace.is_absolute() {
            return Err(AttachFailure);
        }
        // Root replaces this with an actual candidate Host connection adapter.
        Ok(Candidate { session })
    }

    #[test]
    fn guided_error_missing_credential_storage_failure_and_identity_mismatch_remain_distinct() {
        let missing = login_failure(LoginError::CredentialMissing);
        let unavailable = login_failure(LoginError::CredentialUnavailable);
        let mismatch = login_failure(LoginError::IdentityMismatch);
        assert_eq!(missing.code, FailureCode::CredentialMissing);
        assert_ne!(missing.code, unavailable.code, "no saved access is different from an inaccessible/corrupt credential slot");
        assert_eq!(unavailable.code, FailureCode::CredentialUnavailable);
        assert_eq!(mismatch.code, FailureCode::IdentityMismatch);
        assert_ne!(mismatch.code, FailureCode::Authentication, "a known identity fence failure is not an inferred bad credential");
        assert_eq!(login_failure(LoginError::ConnectionUnavailable).code, FailureCode::ConnectionUnavailable);
        assert_eq!(login_failure(LoginError::ConnectionFailed).code, FailureCode::Attach);
        assert_eq!(setup_failure(SetupError::Service).code, FailureCode::Attach, "setup already erased the private cause");
        assert_eq!(configured_folder_io_failure(std::io::ErrorKind::PermissionDenied.into()).code, FailureCode::WorkingFolderUnavailable);
        assert_eq!(configured_folder_io_failure(std::io::ErrorKind::InvalidData.into()).code, FailureCode::Metadata);
        assert_eq!(
            index_failure(IndexError::Unavailable).code,
            FailureCode::Metadata,
            "an opaque index error cannot be labeled as permission denied"
        );
    }
    #[test]
    fn guided_error_configured_missing_or_inaccessible_folder_never_recreates_or_retargets_it() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let mut controller = Controller::new(root.0.clone(), Memory::default())?;
        let (_, active, _) = controller.create_local("Folder error proof", "admin", attach)?.into_parts();
        let source = controller.directory.workspace_path(&active.connection_id)?;
        drop(solidcraft_pdm::managed_workspace::Workspace::create(&source, &active.server_id)?);
        let source_manifest = fs::read(source.join(".solidcraft-pdm").join("0.json"))?;
        let destination = Temp::new()?;
        fs::create_dir(&destination.0)?;
        let selection = controller.directory.select_workspace(&active.connection_id, &destination.0)?;
        let workspace = solidcraft_pdm::managed_workspace::Workspace::create(&destination.0, &active.server_id)?;
        let id = workspace.manifest().workspace_id.clone();
        drop(workspace);
        controller.directory.record_workspace(&selection, &id, &active.server_id)?;
        let preference = controller.directory.workspace_preference(&active.connection_id)?;
        let credentials = controller.credentials.values.borrow().clone();
        let backup = Temp::new()?;
        fs::rename(&destination.0, &backup.0)?;
        let missing = controller.open(&active.connection_id, attach).err().ok_or_else(|| failure(FailureCode::Attach))?;
        assert!(!destination.0.exists(), "missing configured folder must never be automatically initialized");
        fs::write(&destination.0, b"an existing regular file, not a working folder")?;
        let inaccessible = controller.open(&active.connection_id, attach).err().ok_or_else(|| failure(FailureCode::Attach))?;
        assert_eq!(fs::read(&destination.0)?, b"an existing regular file, not a working folder");
        fs::remove_file(&destination.0)?;
        assert_eq!(controller.directory.workspace_preference(&active.connection_id)?, preference);
        assert_eq!(fs::read(source.join(".solidcraft-pdm").join("0.json"))?, source_manifest);
        assert!(controller.credentials.values.borrow().eq(&credentials), "access and trust must remain intact after a folder failure");
        assert_eq!(missing.code, FailureCode::WorkingFolderMissing);
        assert_eq!(inaccessible.code, FailureCode::WorkingFolderUnavailable);
        assert_ne!(missing.code, FailureCode::Metadata, "known NotFound from the configured root must retain its safe category");
        assert_ne!(missing.code, inaccessible.code, "a missing root and an existing non-directory are known different causes");
        Ok(())
    }
    #[test]
    fn guided_error_opaque_attachment_stays_generic_and_preserves_pending_configuration() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let mut controller = Controller::new(root.0.clone(), Memory::default())?;
        let error = controller
            .create_local::<Candidate>("Opaque attachment", "admin", |_, _| Err(AttachFailure))
            .err()
            .ok_or_else(|| failure(FailureCode::Attach))?;
        assert_eq!(error.code, FailureCode::Attach, "do not guess permission, folder or service causes after an opaque attach failure");
        let id = error.pending_connection_id.ok_or_else(|| failure(FailureCode::Metadata))?;
        assert!(controller.list()?.iter().any(|row| row.connection_id == id));
        assert_eq!(controller.owned.len(), 1);
        assert!(!controller.credentials.values.borrow().is_empty());
        Ok(())
    }
    #[test]
    fn pure_constructor_and_list_do_not_create_directories_or_read_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let controller = Controller::new(root.0.clone(), Memory::default())?;
        assert!(controller.list()?.is_empty());
        assert!(!root.0.try_exists()?);
        assert_eq!(controller.credentials.reads.get(), 0);
        Ok(())
    }
    #[test]
    fn workspace_settings_failed_fresh_login_never_prepares_or_publishes_destination() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let mut controller = Controller::new(root.0.clone(), Memory::default())?;
        let (_, active, _) = controller.create_local("Settings proof", "admin", attach)?.into_parts();
        let source = controller.directory.workspace_path(&active.connection_id)?;
        fs::create_dir(&source)?;
        let destination = Temp::new()?;
        fs::create_dir(&destination.0)?;
        controller.credentials.values.borrow_mut().clear();
        let called = std::cell::Cell::new(false);
        let result = controller.prepare_workspace_change(&active.connection_id, &destination.0, |session, selection| {
            called.set(true);
            attach(session, &selection.destination)
        });
        assert_eq!(result.err().ok_or_else(|| failure(FailureCode::Metadata))?.code, FailureCode::CredentialMissing);
        assert!(!called.get());
        assert_eq!(fs::read_dir(&destination.0)?.count(), 0);
        assert_eq!(controller.directory.workspace_path(&active.connection_id)?, source);
        assert_eq!(controller.directory.workspace_preference(&active.connection_id)?, None);
        assert_eq!(controller.owned.len(), 1);
        Ok(())
    }
    #[test]
    fn real_disposable_tls_and_reconnect_reuse_owned_listener() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let mut controller = Controller::new(root.0.clone(), Memory::default())?;
        let prepared = controller.create_local("Private archive", "admin", attach)?;
        let (candidate, active, rows) = prepared.into_parts();
        assert_eq!(candidate.session.identity.principal.role, Role::Administrator);
        assert_eq!(rows.len(), 1);
        let running = controller.owned.get(&active.connection_id).ok_or_else(|| failure(FailureCode::Metadata))?;
        let address = running.address();
        assert!(address.ip().is_loopback());
        assert!(TcpListener::bind(address).is_err());
        let (_, reopened, _) = controller.open(&active.connection_id, attach)?.into_parts();
        assert_eq!(reopened.server_id, active.server_id);
        assert_eq!(controller.owned.get(&active.connection_id).ok_or_else(|| failure(FailureCode::Metadata))?.address(), address);
        assert_eq!(controller.owned.len(), 1);
        for bearer in controller.credentials.values.borrow().values() {
            assert!(!format!("{active:?}").contains(bearer));
            assert!(!format!("{controller:?}").contains(bearer));
        }
        Ok(())
    }
    #[test]
    fn failed_attachment_keeps_previous_candidate_and_pending_local_server() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let mut controller = Controller::new(root.0.clone(), Memory::default())?;
        let (previous, active, _) = controller.create_local("Previous", "admin", attach)?.into_parts();
        let previous_server = previous.session.identity.server_id.clone();
        let failed = controller.create_local::<Candidate>("Pending", "admin", |_, _| Err(AttachFailure));
        let error = failed.err().ok_or_else(|| failure(FailureCode::Attach))?;
        assert_eq!(error.code, FailureCode::Attach);
        let pending_id = error.pending_connection_id.ok_or_else(|| failure(FailureCode::Metadata))?;
        assert_eq!(previous.session.identity.server_id, previous_server);
        assert_eq!(active.server_id, previous_server);
        assert_eq!(controller.owned.len(), 2);
        assert!(controller.list()?.iter().any(|row| row.connection_id == pending_id && matches!(row.state, ConnectionState::PendingLocal { .. })));
        let (_, retried, _) = controller.open(&pending_id, attach)?.into_parts();
        assert_eq!(retried.connection_id, pending_id);
        assert_eq!(controller.owned.len(), 2);
        Ok(())
    }
    #[test]
    fn failed_index_publish_drops_only_candidate_not_previous_connection() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let mut controller = Controller::new(root.0.clone(), Memory::default())?;
        let (previous, active, _) = controller.create_local("Previous", "admin", attach)?.into_parts();
        let result = controller.create_local::<Candidate>("Pending", "admin", |session, workspace| {
            let id = workspace.file_name().and_then(|id| id.to_str()).ok_or(AttachFailure)?;
            // Simulate durable metadata failure after candidate attachment but
            // before ready publication, while the old Host remains untouched.
            fs::write(root.0.join("connections").join(format!("{id}.ready.json")), b"{partial").map_err(|_| AttachFailure)?;
            attach(session, workspace)
        });
        assert_eq!(result.err().ok_or_else(|| failure(FailureCode::Metadata))?.code, FailureCode::Metadata);
        assert_eq!(previous.session.identity.server_id, active.server_id);
        assert_eq!(controller.owned.len(), 2);
        Ok(())
    }
    #[test]
    fn credential_failure_preserves_discoverable_intent_and_retries_without_reset() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let credentials = Memory::default();
        credentials.fail_set.set(true);
        let mut controller = Controller::new(root.0.clone(), credentials)?;
        let error = controller.create_local("Pending", "admin", attach).err().ok_or_else(|| failure(FailureCode::Metadata))?;
        let id = error.pending_connection_id.ok_or_else(|| failure(FailureCode::Metadata))?;
        assert_eq!(controller.list()?.len(), 1);
        assert!(controller.owned.is_empty());
        let installation = controller.directory.installation_path(&id)?;
        let original_tls = fs::read(installation.join("tls/ca.der"))?;
        controller.credentials.fail_set.set(false);
        controller.open(&id, attach)?;
        assert_eq!(fs::read(installation.join("tls/ca.der"))?, original_tls);
        assert_eq!(controller.owned.len(), 1);
        Ok(())
    }
    #[test]
    fn installed_saved_profile_freshly_authenticates_without_starting_another_server() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let mut controller = Controller::new(root.0.clone(), Memory::default())?;
        let (_, active, _) = controller.create_local("Source", "admin", attach)?.into_parts();
        let profile = controller.owned.get(&active.connection_id).ok_or_else(|| failure(FailureCode::Metadata))?.profile.clone();
        let directory = ProfileDirectory::new(controller.directory.imported_profiles_path())?;
        let profile_id = directory.install_new(profile)?;
        let saved_id = controller.directory.record_saved_profile("Saved", &profile_id)?;
        let before = controller.credentials.reads.get();
        assert!(
            controller.list()?.iter().any(|row| row.connection_id == saved_id && matches!(row.state, ConnectionState::SavedProfileUnverified { .. }))
        );
        assert_eq!(controller.credentials.reads.get(), before);
        let (_, saved_active, _) = controller.open(&saved_id, attach)?.into_parts();
        assert_eq!(saved_active.server_id, active.server_id);
        assert!(controller.credentials.reads.get() > before);
        assert_eq!(controller.owned.len(), 1);
        Ok(())
    }
    #[test]
    fn saved_only_index_creates_its_missing_working_parent_after_fresh_authentication() -> Result<(), Box<dyn std::error::Error>> {
        let source_root = Temp::new()?;
        let mut source = Controller::new(source_root.0.clone(), Memory::default())?;
        let (_, active, _) = source.create_local("Source", "admin", attach)?.into_parts();
        let profile = source.owned.get(&active.connection_id).ok_or_else(|| failure(FailureCode::Metadata))?.profile.clone();
        let saved_root = Temp::new()?;
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(&saved_root.0)?;
        let credentials = Memory::default();
        *credentials.values.borrow_mut() = source.credentials.values.borrow().clone();
        let mut saved = Controller::new(saved_root.0.clone(), credentials)?;
        let profile_id = ProfileDirectory::new(saved.directory.imported_profiles_path())?.install_new(profile)?;
        let id = saved.directory.record_saved_profile("Existing archive", &profile_id)?;
        assert!(!saved_root.0.join("workspaces").exists());
        let (_, reopened, _) = saved
            .open(&id, |session, root| {
                assert!(root.parent().is_some_and(Path::is_dir));
                attach(session, root)
            })?
            .into_parts();
        assert_eq!(reopened.server_id, active.server_id);
        assert_eq!(reopened.account, "admin");
        assert!(saved.owned.is_empty(), "saved login must not start or take over another service");
        assert!(saved.credentials.reads.get() > 0);
        Ok(())
    }
}
