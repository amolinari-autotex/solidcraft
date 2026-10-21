//! Native PDM adapter: all credentials, sockets and private working-copy I/O stay here.
use solidcraft_engine::{
    Session,
    pdm::{Failure, Job, Outcome, Reference, Retrieved, Task, Version},
};
use solidcraft_pdm::{AuthToken, Error, client::Client, workspace::content_path};
use solidcraft_ui_egui::pdm_panel::{Completion, Start};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
};

fn failure(message: &str, disconnect: bool) -> Failure {
    Failure { message: message.into(), disconnect }
}
pub(crate) fn map_error(error: Error) -> Failure {
    match error {
        Error::Server(code) if code == "conflict" => {
            failure("The file changed or is checked out elsewhere. Refresh status and review the checkout owner before retrying.", false)
        }
        Error::Server(code) if code == "forbidden" => {
            failure("The server did not authorize this action. Confirm your account, role and checkout.", false)
        }
        Error::Server(code) if code == "unauthorized" => {
            failure("Local PDM authentication failed. Restart the app with the updated local credential.", true)
        }
        Error::Server(code) if code == "not_found" => failure("That exact PDM version is unavailable.", false),
        Error::Server(code) if code == "referenced" => failure("ui.pdm_namespace_referenced", false),
        Error::Server(code) if matches!(code.as_str(), "unsupported" | "unsupported_protocol") => failure("ui.pdm_namespace_unavailable", false),
        Error::FileTooLarge { actual, max } => failure(&format!("The file has {actual} bytes; this archive allows at most {max} bytes."), false),
        Error::Integrity => failure("PDM content integrity verification failed.", false),
        Error::Io(_) => failure("Could not read or write the private PDM working files. The connection remains available.", false),
        Error::Network(_) => {
            failure("Local PDM connection failed. A write may have completed; reconnect and refresh versions before retrying.", true)
        }
        Error::Invalid("workspace recovery required") => {
            failure("An interrupted workspace update needs explicit recovery. Open connection settings and choose Recover Workspace.", false)
        }
        Error::Invalid("source exceeds size limit") => failure(
            &format!(
                "The file exceeds this PDM version's {} MiB per-file limit. Nothing was imported; the source is unchanged.",
                solidcraft_pdm::MAX_CONTENT / (1024 * 1024)
            ),
            false,
        ),
        Error::Invalid("logical path" | "logical path component" | "reserved logical path") => {
            failure("The selected archive folder or filename is invalid. Choose a portable relative archive path.", false)
        }
        Error::Invalid(_) => failure("Local PDM input or credential is unavailable or invalid. Check the local setup instructions.", false),
        _ => failure("Local PDM operation failed. Check the service and private workspace directory.", true),
    }
}
fn versions(rows: Vec<solidcraft_pdm::Version>) -> Result<Vec<Version>, Failure> {
    if rows.len() > 256 {
        return Err(failure("Invalid local PDM version list.", true));
    }
    let rows: Vec<Version> = serde_json::from_value(serde_json::to_value(rows).map_err(|_| failure("Invalid PDM metadata.", true))?)
        .map_err(|_| failure("Invalid PDM metadata.", true))?;
    for row in &rows {
        row.reference.validate().map_err(|_| failure("Invalid PDM reference.", true))?;
        if row.sha256.len() != 64
            || !row.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || row.parent.is_some_and(|parent| parent == 0 || parent >= row.reference.version)
        {
            return Err(failure("Invalid PDM metadata.", true));
        }
        if row.dependencies.len() > 256 {
            return Err(failure("Invalid PDM dependencies.", true));
        }
        for reference in &row.dependencies {
            reference.validate().map_err(|_| failure("Invalid PDM reference.", true))?;
        }
    }
    Ok(rows)
}
fn client(holder: &Mutex<Option<Client>>) -> Result<Client, Failure> {
    holder
        .lock()
        .map_err(|_| failure("Local PDM connection unavailable.", true))?
        .clone()
        .ok_or_else(|| failure("Connect to a local PDM service first.", true))
}

pub fn service(workspace_root: Option<PathBuf>, connections_root: Option<PathBuf>) -> Start {
    service_with_credentials(workspace_root, connections_root, super::pdm_credentials::OsCredentialStore)
}

/// Injectable for native integration tests; production always uses the OS credential store.
pub(crate) fn service_with_credentials<S: super::pdm_credentials::CredentialStore + Send + 'static>(
    workspace_root: Option<PathBuf>,
    connections_root: Option<PathBuf>,
    credentials: S,
) -> Start {
    service_with_credentials_and_boundaries(workspace_root, connections_root, credentials, Vec::new())
}
/// Explicit native boundaries; test injection never consults global user settings.
pub fn service_with_boundaries(workspace_root: Option<PathBuf>, connections_root: Option<PathBuf>, protected_roots: Vec<PathBuf>) -> Start {
    if protected_roots.is_empty() {
        service(workspace_root, connections_root)
    } else {
        service_with_credentials_and_boundaries(workspace_root, connections_root, super::pdm_credentials::OsCredentialStore, protected_roots)
    }
}
pub(crate) fn service_with_credentials_and_boundaries<S: super::pdm_credentials::CredentialStore + Send + 'static>(
    workspace_root: Option<PathBuf>,
    connections_root: Option<PathBuf>,
    credentials: S,
    protected_roots: Vec<PathBuf>,
) -> Start {
    let controller =
        Arc::new(Mutex::new(connections_root.map(|base| super::pdm_guided::Controller::with_boundaries(base, credentials, protected_roots))));
    let holder = Arc::new(Mutex::new(None::<Client>));
    let managed = Arc::new(Mutex::new(super::pdm_managed::Host::default()));
    Arc::new(move |job: Job| {
        let (sender, receiver) = mpsc::channel();
        let holder = holder.clone();
        let root = workspace_root.clone();
        let managed = managed.clone();
        let controller = controller.clone();
        let fallback = sender.clone();
        if std::thread::Builder::new()
            .name("solidcraft-pdm".into())
            .spawn(move || {
                let result = (|| {
                    let mut host = managed.lock().map_err(|_| failure("Managed workspace state unavailable", false))?;
                    let result = match job.task {
                        Task::Managed(solidcraft_engine::pdm::ManagedTask::ListConnections) => {
                            let controller = controller.lock().map_err(|_| failure("PDM connection controller unavailable", false))?;
                            let controller = controller
                                .as_ref()
                                .ok_or_else(|| failure("Private PDM connection directory unavailable", false))?
                                .as_ref()
                                .map_err(|_| failure("Private PDM connection directory invalid", false))?;
                            let rows = controller.list().map_err(guided_failure)?;
                            Ok((Outcome::Connections(connection_rows(rows)), None))
                        }
                        Task::Managed(solidcraft_engine::pdm::ManagedTask::ChangeWorkspace {connection_id, path, expected_workspace}) => {
                            let mut controller = controller.lock().map_err(|_| failure("PDM connection controller unavailable", false))?;
                            let controller = controller.as_mut().ok_or_else(|| failure("Private PDM connection directory unavailable", false))?
                                .as_mut().map_err(|_| failure("Private PDM connection directory invalid", false))?;
                            let mut attach_error = None;
                            let prepared = controller.prepare_workspace_change(&connection_id, Path::new(&path), |session, selection| {
                                let prepare = (|| {
                                    let source = host.begin_workspace_change(&expected_workspace, selection.same)?;
                                    let candidate = host.prepare_workspace_candidate(session, selection, &source)?;
                                    Ok((candidate, source))
                                })();
                                prepare.map_err(|error| { attach_error = Some(error); super::pdm_guided::AttachFailure })
                            }).map_err(|error| attach_error.unwrap_or_else(|| {
                                if matches!(error.code,
                                    super::pdm_guided::FailureCode::Authentication
                                    | super::pdm_guided::FailureCode::CredentialUnavailable
                                    | super::pdm_guided::FailureCode::CredentialMissing
                                    | super::pdm_guided::FailureCode::ConnectionUnavailable
                                    | super::pdm_guided::FailureCode::IdentityMismatch
                                    | super::pdm_guided::FailureCode::WorkingFolderMissing
                                    | super::pdm_guided::FailureCode::WorkingFolderUnavailable) {
                                    guided_failure(error)
                                } else {
                                    failure("The previous working folder is preserved. Choose an empty absolute folder outside settings, installation and the current workspace, then retry.",false)
                                }
                            }))?;
                            let ((candidate, _source_guard), connection, rows, selection) = prepared.into_parts();
                            let workspace = candidate.state.workspace.clone().ok_or_else(|| failure("The new working folder has no verified identity",false))?;
                            let server = candidate.state.server_id.clone().ok_or_else(|| failure("The new working folder has no verified server",false))?;
                            let outcome = guided_outcome(candidate.port, candidate.state, connection, rows);
                            commit_workspace_host(&mut host,&holder,candidate.host,|| {
                                controller.publish_workspace_change(&selection,&workspace,&server).map_err(|_| failure(
                                    "The previous working folder is preserved. The new folder may contain initialization metadata; choose a different empty folder and retry.",false))
                            })?;
                            return Ok((outcome,None));
                        }
                        Task::Managed(
                            task @ (solidcraft_engine::pdm::ManagedTask::CreateLocal { .. }
                            | solidcraft_engine::pdm::ManagedTask::OpenConnection { .. }
                            | solidcraft_engine::pdm::ManagedTask::RecoverConnection { .. }),
                        ) => {
                            let mut controller = controller.lock().map_err(|_| failure("PDM connection controller unavailable", false))?;
                            let controller = controller
                                .as_mut()
                                .ok_or_else(|| failure("Private PDM connection directory unavailable", false))?
                                .as_mut()
                                .map_err(|_| failure("Private PDM connection directory invalid", false))?;
                            let recover = matches!(&task, solidcraft_engine::pdm::ManagedTask::RecoverConnection { .. });
                            let attach = |session, path: &Path| {
                                super::pdm_managed::Host::connect_authenticated(session, path, recover).map_err(|_| super::pdm_guided::AttachFailure)
                            };
                            let prepared = match task {
                                solidcraft_engine::pdm::ManagedTask::CreateLocal { label, administrator } => {
                                    controller.create_local(&label, &administrator, attach)
                                }
                                solidcraft_engine::pdm::ManagedTask::OpenConnection { connection_id }
                                | solidcraft_engine::pdm::ManagedTask::RecoverConnection { connection_id } => controller.open(&connection_id, attach),
                                _ => return Err(failure("Invalid PDM connection request", false)),
                            }
                            .map_err(guided_failure)?;
                            let (candidate, connection, rows) = prepared.into_parts();
                            controller.verify_configured_workspace(&connection.connection_id, candidate.state.workspace.as_deref(), candidate.state.server_id.as_deref()).map_err(guided_failure)?;
                            let outcome = guided_outcome(candidate.port, candidate.state, connection, rows);
                            commit_guided_host(&mut host, &holder, candidate.host)?;
                            // Both holders are committed. Bypass the common tail:
                            // no fallible lock or client lookup may follow this swap.
                            return Ok((outcome, None));
                        }
                        Task::Managed(task) => host.execute(task, root.as_deref()),
                        Task::Connect { port } => host.execute(solidcraft_engine::pdm::ManagedTask::Connect { port, root: None }, root.as_deref()),
                        Task::Refresh if host.connected() => host.refresh(),
                        Task::Retrieve { reference, open: true } if host.connected() => {
                            host.execute(solidcraft_engine::pdm::ManagedTask::OpenArchived { reference }, root.as_deref())
                        }
                        Task::Disconnect => {
                            host.disconnect();
                            execute(Task::Disconnect, &holder, root.as_deref())
                        }
                        task => execute(task, &holder, root.as_deref()),
                    };
                    if result.is_ok() && host.connected() {
                        *holder.lock().map_err(|_| failure("Local PDM connection unavailable", true))? = Some(host.client()?);
                    }
                    result
                })();
                let completion = match result {
                    Ok((outcome, open)) => Completion { result: Ok(outcome), open },
                    Err(error) => {
                        if error.disconnect
                            && let Ok(mut held) = holder.lock()
                        {
                            *held = None;
                        }
                        Completion { result: Err(error), open: None }
                    }
                };
                let _ = sender.send(completion);
            })
            .is_err()
        {
            let _ = fallback.send(Completion { result: Err(failure("Could not start the local PDM worker.", true)), open: None });
        }
        receiver
    })
}

fn guided_outcome(
    port: u16,
    state: solidcraft_engine::pdm::ManagedState,
    connection: super::pdm_guided::ActiveConnection,
    rows: Vec<super::pdm_connections::ConnectionRow>,
) -> Outcome {
    Outcome::ManagedConnected {
        port,
        state,
        connections: connection_rows(rows),
        connection: solidcraft_engine::pdm::ActiveConnection {
            id: connection.connection_id,
            label: connection.label,
            origin: connection.origin,
            server_id: connection.server_id,
            account: connection.account,
            role: match connection.role {
                solidcraft_pdm::managed::Role::Administrator => "Administrator",
                solidcraft_pdm::managed::Role::Contributor => "Contributor",
                solidcraft_pdm::managed::Role::Viewer => "Viewer",
            }
            .into(),
        },
    }
}

/// Preference publication is the only commit point; no fallible work follows it.
pub(crate) fn commit_workspace_host(
    host: &mut super::pdm_managed::Host,
    holder: &Mutex<Option<Client>>,
    candidate: super::pdm_managed::Host,
    publish: impl FnOnce() -> Result<(), Failure>,
) -> Result<(), Failure> {
    let connected = candidate.client()?;
    let mut held = holder.lock().map_err(|_| failure("The previous working folder is preserved; PDM connection state unavailable", false))?;
    publish()?;
    *host = candidate;
    *held = Some(connected);
    Ok(())
}

/// Finish native candidate handoff only after all fallible work has succeeded.
/// Errors preserve both the previous Host/grants and the legacy client holder.
pub(crate) fn commit_guided_host(
    host: &mut super::pdm_managed::Host,
    holder: &Mutex<Option<Client>>,
    candidate: super::pdm_managed::Host,
) -> Result<(), Failure> {
    let connected = candidate.client().map_err(|_| failure("PDM candidate connection unavailable; previous connection preserved", false))?;
    let mut held = holder.lock().map_err(|_| failure("PDM connection state unavailable; previous connection preserved", false))?;
    *host = candidate;
    *held = Some(connected);
    Ok(())
}

fn execute(task: Task, holder: &Mutex<Option<Client>>, workspace_root: Option<&Path>) -> Result<(Outcome, Option<Box<Session>>), Failure> {
    let outcome = match task {
        Task::Managed(_) => {
            return Err(failure("Managed tasks require the managed native adapter", false));
        }
        Task::Connect { port } => {
            // The environment is read only here, never into a command, preferences or a design.
            let connected = Client::new(port, AuthToken::from_env().map_err(map_error)?);
            let rows = versions(connected.list(None).map_err(map_error)?)?;
            *holder.lock().map_err(|_| failure("Local PDM connection unavailable.", true))? = Some(connected);
            Outcome::Connected { port, versions: rows }
        }
        Task::Disconnect => {
            *holder.lock().map_err(|_| failure("Local PDM connection unavailable.", true))? = None;
            Outcome::Disconnected
        }
        Task::Refresh => Outcome::Listed(versions(client(holder)?.list(None).map_err(map_error)?)?),
        Task::CheckIn { document, parent, path, dependencies, saved, visibility } => {
            let bytes = solidcraft_pdm::client::read_file(Path::new(&path), solidcraft_pdm::MAX_CONTENT)
                .map_err(|_| failure("Could not read the saved design. Check its path, file type and 1 MiB size limit.", false))?;
            validate_saved(&bytes, &saved, &visibility)?;
            let dependencies = dependencies.into_iter().map(|r| solidcraft_pdm::VersionRef { document: r.document, version: r.version }).collect();
            let response =
                client(holder)?.request(solidcraft_pdm::Request::CheckIn { document, parent, content: bytes, dependencies }).map_err(map_error)?;
            let returned = match response {
                solidcraft_pdm::Response::CheckedIn { version } => version,
                _ => return Err(failure("PDM check-in returned no version.", true)),
            };
            let version = versions(vec![returned])?.into_iter().next().ok_or_else(|| failure("PDM check-in returned no version.", true))?;
            Outcome::CheckedIn(version)
        }
        Task::Retrieve { reference, open } => {
            let root = workspace_root.ok_or_else(|| failure("Private PDM workspace directory is unavailable.", false))?;
            fs::create_dir_all(root).map_err(|_| failure("Private PDM workspace directory is unavailable.", false))?;
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).map_err(|_| failure("Could not allocate a new PDM working-copy identifier.", false))?;
            let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let destination = root.join(format!("copy-{name}"));
            let requested = solidcraft_pdm::VersionRef { document: reference.document.clone(), version: reference.version };
            let snapshot = client(holder)?.retrieve(requested.clone(), &destination).map_err(map_error)?;
            let input = destination.join("snapshot").join(content_path(&requested).map_err(map_error)?);
            let bytes = solidcraft_pdm::client::read_file(&input, solidcraft_pdm::MAX_CONTENT).map_err(map_error)?;
            let copy = destination.join("working.solidcraft");
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&copy)
                .map_err(|_| failure("Could not create the new PDM working copy.", false))?;
            file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|_| failure("Could not write the new PDM working copy.", false))?;
            let path = copy.to_string_lossy().into_owned();
            let retrieved = Retrieved {
                reference: Reference { document: reference.document, version: reference.version },
                path: path.clone(),
                versions: versions(snapshot.versions)?,
            };
            if open {
                let mut session = Session::default();
                session
                    .execute("doc.open", &serde_json::json!({"path":path}))
                    .map_err(|_| failure("The new PDM copy was saved but is not a readable CAD design. The active design is unchanged.", false))?;
                return Ok((Outcome::Retrieved(retrieved), Some(Box::new(session))));
            }
            Outcome::Retrieved(retrieved)
        }
    };
    Ok((outcome, None))
}

pub(crate) fn validate_saved(
    bytes: &[u8],
    saved: &solidcraft_engine::doc::Document,
    visibility: &solidcraft_engine::Visibility,
) -> Result<(), Failure> {
    let mut disk = solidcraft_engine::io::read_design(bytes).map_err(|_| failure("The saved file is not a readable CAD design.", false))?;
    if disk.visibility != *visibility {
        return Err(failure("The saved file changed outside this design. Reopen or save explicitly before check-in.", false));
    }
    disk.visibility = saved.visibility.clone();
    if disk != *saved {
        return Err(failure("The saved file changed outside this design. Reopen or save explicitly before check-in.", false));
    }
    Ok(())
}

fn guided_failure(error: super::pdm_guided::GuidedFailure) -> Failure {
    use super::pdm_guided::FailureCode;
    let key = match error.code {
        FailureCode::Invalid => "ui.pdm_error_invalid",
        FailureCode::NotFound => "ui.pdm_error_not_found",
        FailureCode::Busy => "ui.pdm_error_busy",
        FailureCode::Capacity => "ui.pdm_error_capacity",
        FailureCode::Metadata => "ui.pdm_error_metadata",
        FailureCode::SetupIncomplete => "ui.pdm_error_setup_incomplete",
        FailureCode::CredentialMissing => "ui.pdm_error_credential_missing",
        FailureCode::CredentialUnavailable => "ui.pdm_error_credential_unavailable",
        FailureCode::ConnectionUnavailable => "ui.pdm_error_connection_unavailable",
        FailureCode::Authentication => "ui.pdm_error_authentication",
        FailureCode::IdentityMismatch => "ui.pdm_error_identity_mismatch",
        FailureCode::WorkingFolderMissing => "ui.pdm_error_working_folder_missing",
        FailureCode::WorkingFolderUnavailable => "ui.pdm_error_working_folder_unavailable",
        FailureCode::Attach => "ui.pdm_error_attach",
    };
    failure(key, false)
}
fn connection_rows(rows: Vec<super::pdm_connections::ConnectionRow>) -> Vec<solidcraft_engine::pdm::ConnectionSummary> {
    use super::pdm_connections::ConnectionState;
    use solidcraft_engine::pdm::{ConnectionKind, ConnectionStage, ConnectionSummary};
    rows.into_iter()
        .map(|row| {
            let (kind, stage) = match row.state {
                ConnectionState::PendingLocal { .. } => (ConnectionKind::Local, ConnectionStage::Pending),
                ConnectionState::LocalReadyRecorded { .. } => (ConnectionKind::Local, ConnectionStage::SavedUnverified),
                ConnectionState::SavedProfileUnverified { .. } => (ConnectionKind::Saved, ConnectionStage::SavedUnverified),
            };
            ConnectionSummary { id: row.connection_id, label: row.label, kind, stage }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("solidcraft-pdm-native-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn token() -> AuthToken {
        AuthToken::parse("ab".repeat(32)).unwrap()
    }

    #[test]
    fn guided_error_public_failure_messages_are_finite_localization_keys_without_private_context() {
        use super::super::pdm_guided::{FailureCode, GuidedFailure};
        for (code, key) in [
            (FailureCode::Invalid, "ui.pdm_error_invalid"),
            (FailureCode::NotFound, "ui.pdm_error_not_found"),
            (FailureCode::Busy, "ui.pdm_error_busy"),
            (FailureCode::Capacity, "ui.pdm_error_capacity"),
            (FailureCode::Metadata, "ui.pdm_error_metadata"),
            (FailureCode::SetupIncomplete, "ui.pdm_error_setup_incomplete"),
            (FailureCode::CredentialUnavailable, "ui.pdm_error_credential_unavailable"),
            (FailureCode::CredentialMissing, "ui.pdm_error_credential_missing"),
            (FailureCode::ConnectionUnavailable, "ui.pdm_error_connection_unavailable"),
            (FailureCode::IdentityMismatch, "ui.pdm_error_identity_mismatch"),
            (FailureCode::WorkingFolderMissing, "ui.pdm_error_working_folder_missing"),
            (FailureCode::WorkingFolderUnavailable, "ui.pdm_error_working_folder_unavailable"),
            (FailureCode::Authentication, "ui.pdm_error_authentication"),
            (FailureCode::Attach, "ui.pdm_error_attach"),
        ] {
            let result = guided_failure(GuidedFailure { code, pending_connection_id: Some("private-installation-context".into()) });
            assert_eq!(result.message, key);
            assert!(!result.disconnect, "a failed candidate must preserve the existing authenticated connection");
            assert!(!result.message.contains("private-installation-context"));
        }
    }
    #[test]
    fn malformed_service_metadata_is_rejected_without_echoing_values() {
        let mut row = solidcraft_pdm::Version {
            reference: solidcraft_pdm::VersionRef { document: "part".into(), version: 2 },
            parent: Some(1),
            sha256: "ab".repeat(32),
            dependencies: vec![],
        };
        assert!(versions(vec![row.clone()]).is_ok());
        row.sha256 = "private-invalid-value".into();
        let error = versions(vec![row.clone()]).unwrap_err();
        assert!(error.disconnect);
        assert!(!error.message.contains(&row.sha256));
        row.sha256 = "ab".repeat(32);
        row.parent = Some(2);
        assert!(versions(vec![row]).is_err());
    }
    fn design() -> Session {
        let mut session = Session::default();
        session.execute("solid.box", &serde_json::json!({"length":10,"width":20,"height":3})).unwrap();
        session
    }

    #[test]
    fn changed_saved_file_is_rejected_before_network_or_document_mutation() {
        let temp = Temp::new();
        let path = temp.0.join("saved.solidcraft");
        let mut session = design();
        session.execute("file.save", &serde_json::json!({"path":path})).unwrap();
        let expected = session.doc.clone();
        let other = Session::default();
        fs::write(&path, solidcraft_engine::io::write_design(&other.doc)).unwrap();
        let holder = Mutex::new(Some(Client::new(1, token())));
        let result = execute(
            Task::CheckIn {
                document: "part".into(),
                parent: None,
                path: path.to_string_lossy().into_owned(),
                dependencies: vec![],
                saved: expected.clone(),
                visibility: Box::new(session.visibility.clone()),
            },
            &holder,
            None,
        );
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("changed disk file was accepted"),
        };
        assert!(failure.message.contains("changed outside"));
        assert!(!failure.disconnect);
        assert_eq!(*session.doc, *expected);
        assert!(!session.is_dirty());
    }

    #[test]
    fn native_saved_design_check_in_and_exact_retrieval_load_a_separate_session() {
        let temp = Temp::new();
        let path = temp.0.join("saved.solidcraft");
        let mut session = design();
        session.execute("file.save", &serde_json::json!({"path":path})).unwrap();
        let expected = session.doc.clone();
        let mut store = solidcraft_pdm::Store::open(&temp.0.join("store")).unwrap();
        let listener = solidcraft_pdm::bind_loopback(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                solidcraft_pdm::serve_connection(&mut store, stream, &token()).unwrap();
            }
        });
        let holder = Mutex::new(Some(Client::new(port, token())));
        let checked = execute(
            Task::CheckIn {
                document: "part".into(),
                parent: None,
                path: path.to_string_lossy().into_owned(),
                dependencies: vec![],
                saved: expected.clone(),
                visibility: Box::new(session.visibility.clone()),
            },
            &holder,
            None,
        )
        .unwrap_or_else(|error| panic!("{}", error.message));
        assert!(matches!(checked.0, Outcome::CheckedIn(_)));
        let workspace = temp.0.join("workspaces");
        let (outcome, loaded) =
            execute(Task::Retrieve { reference: Reference { document: "part".into(), version: 1 }, open: true }, &holder, Some(&workspace))
                .unwrap_or_else(|error| panic!("{}", error.message));
        assert!(matches!(outcome, Outcome::Retrieved(_)));
        let loaded = loaded.expect("separate loaded design");
        assert_eq!(*loaded.doc, *expected);
        assert_eq!(*session.doc, *expected);
        assert!(!session.is_dirty());
        assert!(!loaded.is_dirty());
        let copy = PathBuf::from(loaded.path.as_deref().unwrap());
        assert!(copy.starts_with(&workspace));
        assert!(copy.ends_with("working.solidcraft"));
        assert_ne!(copy, path);
        assert_eq!(fs::read(copy).unwrap(), fs::read(path).unwrap());
        server.join().unwrap();
    }
    #[test]
    fn workspace_settings_native_https_change_persists_across_reconnect_without_moving_files() {
        use solidcraft_engine::pdm::ManagedTask;
        let temp = Temp::new();
        let settings = temp.0.join("settings");
        let connections = settings.join("connections");
        let installation = temp.0.join("application");
        fs::create_dir(&installation).unwrap();
        let worker = service_with_credentials_and_boundaries(
            None,
            Some(connections.clone()),
            super::test_support::Memory::default(),
            vec![settings.clone(), installation.clone()],
        );
        let run = |task| worker(Job { id: 1, task }).recv_timeout(std::time::Duration::from_secs(30)).unwrap();
        let created = run(Task::Managed(ManagedTask::CreateLocal { label: "Folder settings proof".into(), administrator: "admin".into() }));
        let (connection, old) = match created.result {
            Ok(Outcome::ManagedConnected { connection, state, .. }) => (connection, state),
            other => panic!("setup failed: {other:?}"),
        };
        let old_root = PathBuf::from(old.root.clone().unwrap());
        let old_workspace = old.workspace.clone().unwrap();
        let old_manifest = fs::read(old_root.join(".solidcraft-pdm").join("0.json")).unwrap();
        fs::write(old_root.join("ordinary.txt"), b"old folder stays untouched").unwrap();
        let destination = temp.0.join("working");
        fs::create_dir(&destination).unwrap();
        let changed = run(Task::Managed(ManagedTask::ChangeWorkspace {
            connection_id: connection.id.clone(),
            path: destination.to_str().unwrap().into(),
            expected_workspace: old_workspace.clone(),
        }));
        let state = match changed.result {
            Ok(Outcome::ManagedConnected { connection: active, state, .. }) => {
                assert_eq!(active.id, connection.id);
                assert_eq!(active.account, connection.account);
                assert_eq!(active.origin, connection.origin);
                state
            }
            other => panic!("change failed: {other:?}"),
        };
        assert_eq!(
            solidcraft_engine::pdm::cached_path_key(state.root.as_deref().unwrap()),
            solidcraft_engine::pdm::cached_path_key(fs::canonicalize(&destination).unwrap().to_str().unwrap())
        );
        assert_ne!(state.workspace, old.workspace);
        assert!(state.local.is_empty());
        assert_eq!(fs::read(old_root.join("ordinary.txt")).unwrap(), b"old folder stays untouched");
        assert_eq!(fs::read(old_root.join(".solidcraft-pdm").join("0.json")).unwrap(), old_manifest);
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
        let again = run(Task::Managed(ManagedTask::ChangeWorkspace {
            connection_id: connection.id.clone(),
            path: destination.to_str().unwrap().into(),
            expected_workspace: state.workspace.clone().unwrap(),
        }));
        assert!(matches!(again.result,Ok(Outcome::ManagedConnected{state:again,..}) if again.workspace==state.workspace));
        assert!(run(Task::Disconnect).result.is_ok());
        let reopened = run(Task::Managed(ManagedTask::OpenConnection { connection_id: connection.id.clone() }));
        assert!(
            matches!(reopened.result,Ok(Outcome::ManagedConnected{state:reopened,..}) if reopened.root==state.root && reopened.workspace==state.workspace)
        );
        assert!(run(Task::Disconnect).result.is_ok());
        let moved = temp.0.join("temporarily-moved");
        fs::rename(&destination, &moved).unwrap();
        assert!(run(Task::Managed(ManagedTask::OpenConnection { connection_id: connection.id.clone() })).result.is_err());
        assert!(!destination.exists(), "reconnect must not initialize a substitute or silently fall back to the old folder");
        assert_eq!(fs::read(old_root.join("ordinary.txt")).unwrap(), b"old folder stays untouched");
        fs::rename(&moved, &destination).unwrap();
        assert!(
            matches!(run(Task::Managed(ManagedTask::OpenConnection{connection_id:connection.id})).result,Ok(Outcome::ManagedConnected{state:reopened,..}) if reopened.workspace==state.workspace)
        );
    }
    #[test]
    fn workspace_settings_native_rejects_stale_nonempty_and_protected_targets_before_destination_writes() {
        use solidcraft_engine::pdm::ManagedTask;
        let temp = Temp::new();
        let settings = temp.0.join("settings");
        let connections = settings.join("connections");
        let worker = service_with_credentials_and_boundaries(None, Some(connections), super::test_support::Memory::default(), vec![settings.clone()]);
        let run = |task| worker(Job { id: 1, task }).recv_timeout(std::time::Duration::from_secs(30)).unwrap();
        let (connection, state) =
            match run(Task::Managed(ManagedTask::CreateLocal { label: "Fences proof".into(), administrator: "admin".into() })).result {
                Ok(Outcome::ManagedConnected { connection, state, .. }) => (connection, state),
                other => panic!("setup failed: {other:?}"),
            };
        let empty = temp.0.join("empty");
        fs::create_dir(&empty).unwrap();
        let nonempty = temp.0.join("nonempty");
        fs::create_dir(&nonempty).unwrap();
        fs::write(nonempty.join("keep.txt"), b"keep").unwrap();
        let forbidden = settings.join("empty");
        fs::create_dir(&forbidden).unwrap();
        for (target, expected) in
            [(&empty, "stale"), (&nonempty, state.workspace.as_deref().unwrap()), (&forbidden, state.workspace.as_deref().unwrap())]
        {
            let result = run(Task::Managed(ManagedTask::ChangeWorkspace {
                connection_id: connection.id.clone(),
                path: target.to_str().unwrap().into(),
                expected_workspace: expected.into(),
            }));
            assert!(result.result.is_err());
            assert!(!target.join(".solidcraft-pdm").exists());
            assert!(
                matches!(run(Task::Refresh).result,Ok(Outcome::ManagedRefreshed{state:current,..}) if current.root==state.root && current.workspace==state.workspace)
            );
        }
        assert_eq!(fs::read(nonempty.join("keep.txt")).unwrap(), b"keep");
    }
    #[test]
    fn guided_native_setup_reopen_and_historical_restore_preserve_one_working_path() {
        use solidcraft_engine::pdm::ManagedTask;
        let temp = Temp::new();
        let connections = temp.0.join("settings").join("connections");
        let worker = service_with_credentials(None, Some(connections.clone()), super::test_support::Memory::default());
        assert!(!connections.exists());
        let run = |task| worker(Job { id: 1, task }).recv_timeout(std::time::Duration::from_secs(30)).unwrap();
        let empty = run(Task::Managed(ManagedTask::ListConnections));
        assert!(matches!(empty.result, Ok(Outcome::Connections(rows)) if rows.is_empty()));
        assert!(!temp.0.join("settings").exists(), "read-only inventory must not create settings");
        let created = run(Task::Managed(ManagedTask::CreateLocal { label: "Private proof".into(), administrator: "admin".into() }));
        let (connection, state) = match created.result {
            Ok(Outcome::ManagedConnected { connection, state, .. }) => (connection, state),
            other => panic!("guided setup failed: {other:?}"),
        };
        assert_eq!(connection.account, "admin");
        assert_eq!(connection.role, "Administrator");
        assert!(connection.origin.starts_with("https://127.0.0.1:"));
        assert_eq!(state.server_id.as_deref(), Some(connection.server_id.as_str()));
        let root = PathBuf::from(state.root.unwrap());
        let path = root.join("proof.solidcraft");
        let mut design = design();
        design.execute("file.save", &serde_json::json!({"path":path})).unwrap();
        let original = fs::read(&path).unwrap();
        let archive = |design: &Session| {
            Task::Managed(ManagedTask::Archive {
                path: path.to_string_lossy().into_owned(),
                logical_path: None,
                saved: design.doc.clone(),
                visibility: Box::new(design.visibility.clone()),
            })
        };
        let first = run(archive(&design));
        let document = match first.result {
            Ok(Outcome::Managed { state, .. }) => state.local.first().unwrap().document.clone(),
            other => panic!("first archive failed: {other:?}"),
        };
        let checked_out = run(Task::Managed(ManagedTask::Checkout { document: Some(document.clone()), path: None }));
        assert!(checked_out.result.is_ok());
        let mut editable = checked_out.open.unwrap();
        assert!(run(Task::Disconnect).result.is_ok());
        let resumed_checkout = run(Task::Managed(ManagedTask::OpenConnection { connection_id: connection.id.clone() }));
        match resumed_checkout.result {
            Ok(Outcome::ManagedConnected { connection: actual, state, .. }) => {
                assert_eq!(actual.server_id, connection.server_id);
                assert_eq!(actual.account, "admin");
                assert_eq!(state.root.as_deref(), Some(root.to_str().unwrap()));
                let local = state.local.iter().find(|entry| entry.document == document).unwrap();
                assert!(local.checked_out, "saved login must resume the existing checkout capability");
                assert_eq!(local.base_version, 1);
            }
            other => panic!("active checkout resume failed: {other:?}"),
        }
        editable.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        editable.execute("file.save", &serde_json::json!({})).unwrap();
        assert!(run(archive(&editable)).result.is_ok());
        assert_ne!(fs::read(&path).unwrap(), original);
        assert!(run(Task::Disconnect).result.is_ok());
        let reopened = run(Task::Managed(ManagedTask::OpenConnection { connection_id: connection.id.clone() }));
        match reopened.result {
            Ok(Outcome::ManagedConnected { connection: actual, state, .. }) => {
                assert_eq!(actual.server_id, connection.server_id);
                assert_eq!(actual.account, "admin");
                assert_eq!(state.root.as_deref(), Some(root.to_str().unwrap()));
            }
            other => panic!("saved login failed: {other:?}"),
        }
        for _ in 0..2 {
            let restored = run(Task::Managed(ManagedTask::Restore { reference: Reference { document: document.clone(), version: 1 } }));
            match restored.result {
                Ok(Outcome::Managed { state, .. }) => {
                    assert_eq!(state.history.len(), 3);
                    assert_eq!(state.local.first().unwrap().base_version, 3);
                }
                other => panic!("historical restore failed: {other:?}"),
            }
            let opened = restored.open.unwrap();
            assert_eq!(opened.path.as_deref(), Some(path.to_str().unwrap()));
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }
    #[test]
    fn guided_workspace_recovery_fences_stale_clean_editors_until_verified_reopen() {
        use solidcraft_engine::pdm::{ManagedTask, Runtime};
        let temp = Temp::new();
        let worker = service_with_credentials(None, Some(temp.0.join("settings").join("connections")), super::test_support::Memory::default());
        let runtime = Runtime::default();
        runtime.set_available(true).unwrap();
        let run = |task| {
            let load_epoch = runtime.begin_pdm_reload().unwrap();
            let id = runtime.enqueue(task).unwrap();
            let job = runtime.take_job().unwrap().unwrap();
            let mut completion = worker(job).recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            runtime.finish(id, completion.result.clone()).unwrap();
            if let Some(session) = completion.open.as_mut() {
                session.pdm = runtime.clone();
                session.mark_pdm_reloaded_from(load_epoch).unwrap();
            }
            completion
        };
        let created = run(Task::Managed(ManagedTask::CreateLocal { label: "Recovery proof".into(), administrator: "admin".into() }));
        let (connection, state) = match created.result {
            Ok(Outcome::ManagedConnected { connection, state, .. }) => (connection, state),
            other => panic!("setup failed: {other:?}"),
        };
        let root = PathBuf::from(state.root.unwrap());
        let path = root.join("recover.solidcraft");
        let mut initial = design();
        initial.execute("file.save", &serde_json::json!({"path":path})).unwrap();
        let original = fs::read(&path).unwrap();
        let archived = run(Task::Managed(ManagedTask::Archive {
            path: path.to_string_lossy().into_owned(),
            logical_path: None,
            saved: initial.doc.clone(),
            visibility: Box::new(initial.visibility.clone()),
        }));
        let document = match archived.result {
            Ok(Outcome::Managed { state, .. }) => state.local.first().unwrap().document.clone(),
            other => panic!("archive failed: {other:?}"),
        };
        let checked_out = run(Task::Managed(ManagedTask::Checkout { document: Some(document.clone()), path: None }));
        let mut stale = checked_out.open.unwrap();
        stale.execute("solid.box", &serde_json::json!({"length":2,"width":2,"height":2})).unwrap();
        stale.execute("file.save", &serde_json::json!({})).unwrap();
        assert!(!stale.is_dirty());
        let interrupted = fs::read(&path).unwrap();
        assert_ne!(interrupted, original);
        // A disposable fixture reproduces interruption after replacement but
        // before publication. The old checkout remains authoritative.
        let workspace = solidcraft_pdm::managed_workspace::Workspace::open(&root, &connection.server_id).unwrap();
        let manifest = workspace.manifest();
        let generation = manifest.generation;
        let relative = manifest.documents.get(&document).unwrap().relative_path.clone();
        assert!(manifest.documents.get(&document).unwrap().checked_out);
        let metadata = root.join(".solidcraft-pdm");
        let pending = metadata.join("pending");
        let backup = metadata.join(format!("backup-{generation}"));
        assert!(!pending.exists() && !backup.exists());
        fs::write(&backup, &original).unwrap();
        fs::write(&pending, serde_json::to_vec(&serde_json::json!({"manifest":manifest,"relative_path":relative})).unwrap()).unwrap();
        drop(workspace);
        let recovered = run(Task::Managed(ManagedTask::RecoverConnection { connection_id: connection.id }));
        match recovered.result {
            Ok(Outcome::ManagedConnected { state, .. }) => {
                assert!(state.local.first().unwrap().checked_out)
            }
            other => panic!("recovery failed: {other:?}"),
        }
        assert!(recovered.open.is_none());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read(metadata.join(format!("recovery-current-{generation}"))).unwrap(), interrupted);
        assert!(stale.execute("file.save", &serde_json::json!({})).unwrap_err().to_string().contains("Reopen"));
        assert!(stale.execute("solid.box", &serde_json::json!({"length":3,"width":3,"height":3})).is_err());
        assert!(stale.execute("pdm.archive", &serde_json::json!({})).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        let reopened = run(Task::Managed(ManagedTask::Open { document }));
        let mut fresh = reopened.open.unwrap();
        assert!(stale.execute("file.save", &serde_json::json!({})).is_err(), "reloading another editor cannot lift the old editor's fence");
        fresh.execute("solid.box", &serde_json::json!({"length":3,"width":3,"height":3})).unwrap();
        fresh.execute("file.save", &serde_json::json!({})).unwrap();
        assert_ne!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read(metadata.join(format!("recovery-current-{generation}"))).unwrap(), interrupted);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::pdm_credentials::{BearerSecret, CredentialError, CredentialKey, CredentialStore};
    use std::collections::BTreeMap;
    #[derive(Clone, Default)]
    pub struct Memory(Arc<Mutex<BTreeMap<CredentialKey, String>>>);
    impl CredentialStore for Memory {
        fn get(&self, key: &CredentialKey) -> Result<Option<BearerSecret>, CredentialError> {
            self.0.lock().map_err(|_| CredentialError::Unavailable)?.get(key).cloned().map(BearerSecret::parse).transpose()
        }
        fn set(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError> {
            self.0.lock().map_err(|_| CredentialError::Unavailable)?.insert(key.clone(), secret.expose().into());
            Ok(())
        }
        fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError> {
            self.0.lock().map_err(|_| CredentialError::Unavailable)?.remove(key);
            Ok(())
        }
    }
}
