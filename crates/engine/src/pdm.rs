//! Host-only local PDM work queue. No credentials, sockets or document serialization live here.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub document: String,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Version {
    pub reference: Reference,
    pub parent: Option<u64>,
    pub sha256: String,
    pub dependencies: Vec<Reference>,
}

/// Public server metadata only. Reservation credentials never enter engine state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkout {
    pub owner: String,
    pub workspace: String,
    pub machine: String,
    pub checked_out_unix_ms: u64,
    pub base_version: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub document: String,
    pub logical_path: String,
    pub head: Option<u64>,
    pub checkout: Option<Checkout>,
    #[serde(default)]
    pub head_checked_in_unix_ms: Option<u64>,
    #[serde(default)]
    pub head_author: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalEntry {
    pub document: String,
    pub path: String,
    pub relative_path: String,
    pub base_version: u64,
    pub sha256: String,
    pub checked_out: bool,
    pub modified: bool,
    pub present: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedVersion {
    pub version: Version,
    pub author: String,
    pub checked_in_unix_ms: u64,
    pub comment: String,
    pub request_id: String,
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ManagedState {
    pub server_id: Option<String>,
    pub root: Option<String>,
    pub workspace: Option<String>,
    pub catalog: Vec<CatalogEntry>,
    pub local: Vec<LocalEntry>,
    /// Native-verified installed assemblies with a newer managed component.
    #[serde(default)]
    pub dependency_updates: Vec<String>,
    /// Native-verified grants with no installed manifest entry. Release only;
    /// never authorizes publication or filesystem writes.
    #[serde(default)]
    pub recoverable_checkouts: Vec<String>,
    pub history: Vec<ManagedVersion>,
    pub where_used: Vec<Reference>,
    pub preview: Option<Preview>,
    /// Immutable snapshot destinations, including their dependency files.
    #[serde(default)]
    pub historical_paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Preview {
    pub reference: Reference,
    pub sha256: String,
    pub png: Vec<u8>,
}

/// Public connection inventory. A saved row never establishes authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionKind {
    Local,
    Saved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionStage {
    Pending,
    SavedUnverified,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionSummary {
    pub id: String,
    pub label: String,
    pub kind: ConnectionKind,
    pub stage: ConnectionStage,
}
/// Fresh native authentication only; contains no credential or capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveConnection {
    pub id: String,
    pub label: String,
    pub origin: String,
    pub server_id: String,
    pub account: String,
    pub role: String,
}

#[derive(Clone)]
pub enum ManagedTask {
    ListConnections,
    CreateLocal {
        label: String,
        administrator: String,
    },
    OpenConnection {
        connection_id: String,
    },
    RecoverConnection {
        connection_id: String,
    },
    Recover {
        port: u16,
        root: String,
    },
    Preview {
        reference: Reference,
    },
    OpenArchived {
        reference: Reference,
    },
    Restore {
        reference: Reference,
    },
    Connect {
        port: u16,
        root: Option<String>,
    },
    Archive {
        path: String,
        logical_path: Option<String>,
        saved: Arc<solidcraft_doc::Document>,
        visibility: Box<crate::Visibility>,
    },
    /// Reconcile only an existing publication receipt; cannot acquire or publish.
    ReconcileArchive {
        path: String,
        logical_path: Option<String>,
        saved: Arc<solidcraft_doc::Document>,
        visibility: Box<crate::Visibility>,
    },
    Checkout {
        document: Option<String>,
        path: Option<String>,
    },
    CancelCheckout {
        document: Option<String>,
        path: Option<String>,
    },
    GetLatest {
        document: Option<String>,
        path: Option<String>,
    },
    Open {
        document: String,
    },
    History {
        document: String,
    },
}

#[derive(Clone)]
pub enum Task {
    Managed(ManagedTask),
    Connect {
        port: u16,
    },
    Disconnect,
    Refresh,
    CheckIn {
        document: String,
        parent: Option<u64>,
        path: String,
        dependencies: Vec<Reference>,
        saved: Arc<solidcraft_doc::Document>,
        visibility: Box<crate::Visibility>,
    },
    Retrieve {
        reference: Reference,
        open: bool,
    },
}
impl std::fmt::Debug for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Managed(_) => "Managed([host-only task])",
            Self::Connect { .. } => "Connect",
            Self::Disconnect => "Disconnect",
            Self::Refresh => "Refresh",
            Self::CheckIn { .. } => "CheckIn([host-only snapshot])",
            Self::Retrieve { .. } => "Retrieve",
        })
    }
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: u64,
    pub task: Task,
}

#[derive(Clone, Debug, Serialize)]
pub struct Retrieved {
    pub reference: Reference,
    pub path: String,
    pub versions: Vec<Version>,
}

#[derive(Clone, Debug)]
pub enum Outcome {
    Connections(Vec<ConnectionSummary>),
    ManagedConnected { port: u16, state: ManagedState, connections: Vec<ConnectionSummary>, connection: ActiveConnection },
    ManagedRefreshed { port: u16, state: ManagedState },
    Managed { port: u16, state: ManagedState },
    Connected { port: u16, versions: Vec<Version> },
    Disconnected,
    Listed(Vec<Version>),
    CheckedIn(Version),
    Retrieved(Retrieved),
}

#[derive(Clone, Debug)]
pub struct Failure {
    pub message: String,
    pub disconnect: bool,
}

#[derive(Clone, Default, Debug, Serialize)]
pub struct Status {
    pub connections: Vec<ConnectionSummary>,
    pub connection: Option<ActiveConnection>,
    pub available: bool,
    pub port: Option<u16>,
    pub busy: Option<u64>,
    /// Only local file replacement/publication prevents editing. Metadata refreshes do not.
    pub blocking: bool,
    pub versions: Vec<Version>,
    pub retrieved: Option<Retrieved>,
    pub error: Option<String>,
    #[serde(flatten)]
    pub managed: ManagedState,
}

impl Status {
    fn action_entries(&self, document: Option<&str>, path: Option<&str>) -> (Option<&CatalogEntry>, Option<&LocalEntry>) {
        let local = self.managed.local.iter().find(|entry| {
            document
                .map_or_else(|| path.is_some_and(|path| cached_path_key(path) == cached_path_key(&entry.path)), |document| entry.document == document)
        });
        let document = document.or_else(|| local.map(|entry| entry.document.as_str()));
        (self.managed.catalog.iter().find(|entry| Some(entry.document.as_str()) == document), local)
    }
    fn owns_here(&self, remote: &CatalogEntry, local: Option<&LocalEntry>) -> bool {
        local.is_some_and(|local| local.checked_out)
            && remote.checkout.as_ref().is_some_and(|checkout| {
                Some(checkout.workspace.as_str()) == self.managed.workspace.as_deref()
                    && self.connection.as_ref().is_none_or(|connection| connection.account == checkout.owner)
            })
    }
    fn recoverable_here(&self, remote: &CatalogEntry, local: Option<&LocalEntry>) -> bool {
        local.is_none()
            && self.managed.recoverable_checkouts.contains(&remote.document)
            && remote.checkout.as_ref().is_some_and(|checkout| {
                Some(checkout.workspace.as_str()) == self.managed.workspace.as_deref()
                    && self.connection.as_ref().is_none_or(|connection| connection.account == checkout.owner)
            })
    }
    fn lock_reason(&self, remote: &CatalogEntry, local: Option<&LocalEntry>) -> &'static str {
        if self.owns_here(remote, local) {
            "ui.pdm_reason_checked_out_here"
        } else if remote
            .checkout
            .as_ref()
            .is_some_and(|checkout| self.connection.as_ref().is_some_and(|connection| checkout.owner != connection.account))
        {
            "ui.pdm_reason_checked_out_other"
        } else {
            "ui.pdm_reason_checked_out_elsewhere"
        }
    }
    /// Shared presentation and command policy. Native execution revalidates fresh server authority.
    pub fn action_unavailable(
        &self,
        command: &str,
        document: Option<&str>,
        path: Option<&str>,
        dirty: bool,
        historical: bool,
        version: Option<u64>,
    ) -> Option<&'static str> {
        if self.busy.is_some() {
            return Some("ui.pdm_reason_busy");
        }
        if matches!(
            command,
            "pdm.connections" | "pdm.setup.create" | "pdm.connection.open" | "pdm.connect" | "pdm.connection.recover" | "pdm.recover_workspace"
        ) {
            return None;
        }
        if !self.available || self.port.is_none() {
            return Some("ui.pdm_reason_disconnected");
        }
        if matches!(command, "pdm.refresh" | "pdm.disconnect" | "pdm.status" | "pdm.panel") {
            return None;
        }
        let (remote, local) = self.action_entries(document, path);
        let writes = matches!(command, "pdm.archive" | "pdm.checkout" | "pdm.cancel_checkout" | "pdm.restore_version" | "pdm.check_in");
        if writes && self.connection.as_ref().is_some_and(|connection| connection.role.eq_ignore_ascii_case("viewer")) {
            return Some("ui.pdm_reason_viewer");
        }
        if writes && self.error.is_some() {
            return Some("ui.pdm_reason_refresh_required");
        }
        if historical && matches!(command, "pdm.archive" | "pdm.check_in") {
            return Some("ui.pdm_reason_historical");
        }
        if command == "pdm.archive" {
            if path.is_none() || dirty {
                return Some("ui.pdm_reason_save_first");
            }
            if let (Some(root), Some(path)) = (self.managed.root.as_deref(), path) {
                let root = format!("{}/", cached_path_key(root).trim_end_matches('/'));
                if !cached_path_key(path).starts_with(&root) {
                    return Some("ui.pdm_reason_working_folder");
                }
            }
            if document.is_some() && local.is_none_or(|local| path.is_none_or(|path| cached_path_key(path) != cached_path_key(&local.path))) {
                return Some("ui.pdm_reason_open_selected");
            }
            if let Some(remote) = remote {
                if !self.owns_here(remote, local) {
                    return Some(if remote.checkout.is_some() { self.lock_reason(remote, local) } else { "ui.pdm_reason_checkout_required" });
                }
                if local.is_none_or(|local| {
                    Some(local.base_version) != remote.head
                        || remote.checkout.as_ref().is_none_or(|checkout| checkout.base_version != Some(local.base_version))
                }) {
                    return Some("ui.pdm_reason_stale_base");
                }
            } else if local.is_some() {
                return Some("ui.pdm_reason_unavailable");
            }
            return None;
        }
        if document.is_none() && local.is_none() {
            return Some(if path.is_some() { "ui.pdm_reason_unmanaged" } else { "ui.pdm_reason_select_document" });
        }
        let Some(remote) = remote else {
            return Some("ui.pdm_reason_unmanaged");
        };
        if matches!(command, "pdm.open_archived" | "pdm.retrieve" | "pdm.preview" | "pdm.restore_version")
            && version.is_none_or(|version| version == 0 || remote.head.is_none_or(|head| version > head))
        {
            return Some("ui.pdm_reason_select_version");
        }
        match command {
            "pdm.checkout" => {
                if remote.checkout.is_some() {
                    return Some(self.lock_reason(remote, local));
                }
                if dirty || local.is_some_and(|local| local.modified) {
                    return Some("ui.pdm_reason_modified");
                }
            }
            "pdm.cancel_checkout" => {
                if !self.owns_here(remote, local) && !self.recoverable_here(remote, local) {
                    return Some(if remote.checkout.is_some() { self.lock_reason(remote, local) } else { "ui.pdm_reason_checkout_required" });
                }
                if dirty {
                    return Some("ui.pdm_reason_save_first");
                }
            }
            "pdm.get_latest" | "pdm.restore_version" => {
                if remote.checkout.is_some() {
                    return Some(self.lock_reason(remote, local));
                }
                if dirty || local.is_some_and(|local| local.modified) {
                    return Some("ui.pdm_reason_modified");
                }
                if command == "pdm.get_latest"
                    && local.is_some_and(|local| local.present && Some(local.base_version) == remote.head)
                    && !self.managed.dependency_updates.contains(&remote.document)
                {
                    return Some("ui.pdm_reason_up_to_date");
                }
                if command == "pdm.restore_version" {
                    if local.is_none_or(|local| !local.present || Some(local.base_version) != remote.head) {
                        return Some("ui.pdm_reason_stale_base");
                    }
                    if version == remote.head {
                        return Some("ui.pdm_reason_current_version");
                    }
                }
            }
            _ => {}
        }
        None
    }
    pub fn document_state(&self, document: Option<&str>, path: Option<&str>, dirty: bool) -> &'static str {
        if self.busy.is_some() {
            return "ui.pdm_state_busy";
        }
        if !self.available || self.port.is_none() {
            return "ui.pdm_state_disconnected";
        }
        if self.error.is_some() {
            return "ui.pdm_state_error";
        }
        let (remote, local) = self.action_entries(document, path);
        let Some(remote) = remote else {
            return if document.is_none() && path.is_none() { "ui.pdm_state_no_selection" } else { "ui.pdm_state_unmanaged" };
        };
        if remote.checkout.is_some() {
            if self.recoverable_here(remote, local) {
                return "ui.pdm_state_checkout_incomplete";
            }
            return match self.lock_reason(remote, local) {
                "ui.pdm_reason_checked_out_here" if dirty || local.is_some_and(|local| local.modified) => "ui.pdm_state_modified",
                "ui.pdm_reason_checked_out_here" => "ui.pdm_state_checked_out_here",
                "ui.pdm_reason_checked_out_other" => "ui.pdm_state_checked_out_other",
                _ => "ui.pdm_state_checked_out_elsewhere",
            };
        }
        if dirty || local.is_some_and(|local| local.modified) {
            return "ui.pdm_state_modified";
        }
        if local.is_some_and(|local| Some(local.base_version) != remote.head) || self.managed.dependency_updates.contains(&remote.document) {
            return "ui.pdm_state_outdated";
        }
        "ui.pdm_state_archived"
    }
}

#[derive(Default)]
struct State {
    status: Status,
    next: u64,
    job: Option<Job>,
    blocked_paths: Vec<String>,
    block_all_paths: bool,
    known_paths: BTreeMap<String, KnownPath>,
    historical_paths: BTreeMap<String, String>,
    protection_failed: bool,
    recovery_epoch: u64,
}

struct KnownPath {
    server_id: Option<String>,
    workspace: Option<String>,
    entry: LocalEntry,
}

// A bounded, session-long protection ledger survives workspace and tab switches.
// Exhaustion disables further PDM jobs and writes rather than dropping a guard.
const MAX_PROTECTED_PATHS: usize = 8192;
const MAX_PROTECTED_PATH_BYTES: usize = 4096;

impl State {
    fn remember(&mut self, managed: &ManagedState) -> Result<(), String> {
        let additions = managed.local.len().saturating_add(managed.historical_paths.len());
        if additions > MAX_PROTECTED_PATHS {
            return Err("PDM path protection limit reached; restart the application before continuing".into());
        }
        for entry in &managed.local {
            if entry.path.is_empty() || entry.path.len() > MAX_PROTECTED_PATH_BYTES {
                return Err("Invalid PDM protected path".into());
            }
            let key = cached_path_key(&entry.path);
            if let Some(previous) = self.known_paths.get(&key) {
                if previous.server_id != managed.server_id || previous.workspace != managed.workspace || previous.entry.document != entry.document {
                    return Err("A PDM path belongs to a different workspace or document".into());
                }
            } else if self.known_paths.len().saturating_add(self.historical_paths.len()) >= MAX_PROTECTED_PATHS {
                return Err("PDM path protection limit reached; restart the application before continuing".into());
            }
            let mut entry = entry.clone();
            // Only the active, freshly verified snapshot may authorize writes.
            // Inactive workspace grants remain reserved on the server.
            entry.checked_out = false;
            self.known_paths.insert(key, KnownPath { server_id: managed.server_id.clone(), workspace: managed.workspace.clone(), entry });
        }
        for path in &managed.historical_paths {
            if path.is_empty() || path.len() > MAX_PROTECTED_PATH_BYTES {
                return Err("Invalid PDM historical path".into());
            }
            let key = cached_path_key(path);
            if !self.historical_paths.contains_key(&key) && self.known_paths.len().saturating_add(self.historical_paths.len()) >= MAX_PROTECTED_PATHS
            {
                return Err("PDM path protection limit reached; restart the application before continuing".into());
            }
            self.historical_paths.insert(key, path.clone());
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct Runtime(Arc<Mutex<State>>);

pub fn valid_connection(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn valid_document(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// Cached display-path identity, without filesystem access on UI frames.
pub fn cached_path_key(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let normalized = if cfg!(target_os = "windows") {
        normalized
            .strip_prefix("//?/")
            .map(|rest| {
                if rest.get(..4).is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC/")) {
                    format!("//{}", rest.get(4..).unwrap_or_default())
                } else {
                    rest.to_owned()
                }
            })
            .unwrap_or(normalized)
    } else {
        normalized
    };
    let rooted = normalized.starts_with('/');
    let mut parts = Vec::new();
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p: &&str| *p != ".." && !p.ends_with(':')) => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    let mut result = parts.join("/");
    if rooted {
        result.insert(0, '/');
    }
    if cfg!(target_os = "windows") {
        result.make_ascii_lowercase();
    }
    result
}

/// Save-time identity check. The UI uses cached paths; filesystem resolution is
/// limited to operations that already perform filesystem writes.
pub fn same_file_path(a: &str, b: &str) -> bool {
    // Canonical names do not detect hardlinks. Restrict native handle opens to
    // regular files so pipes and devices are not opened for an identity probe.
    #[cfg(not(target_arch = "wasm32"))]
    if std::fs::metadata(a).is_ok_and(|metadata| metadata.is_file())
        && std::fs::metadata(b).is_ok_and(|metadata| metadata.is_file())
        && same_file::is_same_file(a, b).is_ok_and(|same| same)
    {
        return true;
    }
    fn resolve(value: &str) -> std::path::PathBuf {
        let path = std::path::Path::new(value);
        std::fs::canonicalize(path).unwrap_or_else(|_| {
            path.parent()
                .and_then(|p| std::fs::canonicalize(p).ok())
                .and_then(|p| path.file_name().map(|n| p.join(n)))
                .unwrap_or_else(|| path.to_path_buf())
        })
    }
    let a = resolve(a).to_string_lossy().replace('\\', "/");
    let b = resolve(b).to_string_lossy().replace('\\', "/");
    if cfg!(target_os = "windows") { a.eq_ignore_ascii_case(&b) } else { a == b }
}

impl Reference {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_document(&self.document) || self.version == 0 {
            return Err("Invalid PDM version reference".into());
        }
        Ok(())
    }
}

impl Runtime {
    pub fn recovery_epoch(&self) -> Result<u64, String> {
        let state = self.0.lock().map_err(|_| "PDM recovery protection unavailable")?;
        if state.protection_failed {
            return Err("PDM recovery protection unavailable".into());
        }
        Ok(state.recovery_epoch)
    }
    /// Saved editors are fenced individually. An unnamed design has no disk state.
    pub fn requires_reopen(&self, epoch: u64, path: Option<&str>) -> bool {
        path.is_some() && self.0.lock().map_or(true, |state| state.protection_failed || state.recovery_epoch != epoch)
    }
    /// Capture BEFORE fresh file I/O. Reuse this exact token after the read,
    /// including across asynchronous native work; never sample after reading.
    pub fn begin_pdm_reload(&self) -> Result<u64, String> {
        let state = self.0.lock().map_err(|_| "PDM recovery protection unavailable")?;
        if state.protection_failed {
            return Err("PDM recovery protection unavailable".into());
        }
        if state.status.blocking && state.block_all_paths {
            return Err("Wait for PDM recovery before reopening this design".into());
        }
        Ok(state.recovery_epoch)
    }
    fn validate_reload_epoch(&self, expected: u64) -> Result<(), String> {
        let state = self.0.lock().map_err(|_| "PDM recovery protection unavailable")?;
        if state.protection_failed || state.recovery_epoch != expected {
            return Err("PDM recovery changed files while loading; reopen this design again".into());
        }
        if state.status.blocking && state.block_all_paths {
            return Err("Wait for PDM recovery before reopening this design".into());
        }
        Ok(())
    }

    pub fn set_available(&self, available: bool) -> Result<(), String> {
        self.0.lock().map_err(|_| "Local PDM state unavailable")?.status.available = available;
        Ok(())
    }
    pub fn status(&self) -> Result<Status, String> {
        Ok(self.0.lock().map_err(|_| "Local PDM state unavailable")?.status.clone())
    }
    pub fn enqueue(&self, task: Task) -> Result<u64, String> {
        let mut state = self.0.lock().map_err(|_| "Local PDM state unavailable")?;
        if !state.status.available {
            return Err("Local PDM is unavailable in this host".into());
        }
        if state.protection_failed {
            return Err("PDM path protection is unavailable; restart the application before continuing".into());
        }
        if state.status.busy.is_some() {
            return Err("A local PDM operation is in progress".into());
        }
        if !matches!(
            task,
            Task::Connect { .. }
                | Task::Managed(
                    ManagedTask::Connect { .. }
                        | ManagedTask::Recover { .. }
                        | ManagedTask::ListConnections
                        | ManagedTask::CreateLocal { .. }
                        | ManagedTask::OpenConnection { .. }
                        | ManagedTask::RecoverConnection { .. }
                )
        ) && state.status.port.is_none()
        {
            return Err("Connect to a local PDM service first".into());
        }
        let action = match &task {
            Task::Managed(ManagedTask::Archive { path, .. } | ManagedTask::ReconcileArchive { path, .. }) => {
                Some(("pdm.archive", None, Some(path.as_str()), None))
            }
            Task::Managed(ManagedTask::Checkout { document, path }) => Some(("pdm.checkout", document.as_deref(), path.as_deref(), None)),
            Task::Managed(ManagedTask::CancelCheckout { document, path }) => {
                Some(("pdm.cancel_checkout", document.as_deref(), path.as_deref(), None))
            }
            Task::Managed(ManagedTask::GetLatest { document, path }) => Some(("pdm.get_latest", document.as_deref(), path.as_deref(), None)),
            Task::Managed(ManagedTask::Restore { reference }) => {
                Some(("pdm.restore_version", Some(reference.document.as_str()), None, Some(reference.version)))
            }
            _ => None,
        };
        let mut policy_status = state.status.clone();
        if matches!(&task, Task::Managed(ManagedTask::ReconcileArchive { .. })) {
            policy_status.error = None;
        }
        if let Some((command, document, path, version)) = action
            && let Some(reason) = policy_status.action_unavailable(command, document, path, false, false, version)
        {
            // A lost restore acknowledgement is reconciled against the native
            // durable receipt before any new checkout/publication. Cached lock or
            // base metadata must not prevent that authenticated retry.
            let receipt_only = matches!(&task, Task::Managed(ManagedTask::ReconcileArchive { .. }))
                && matches!(
                    reason,
                    "ui.pdm_reason_checkout_required"
                        | "ui.pdm_reason_stale_base"
                        | "ui.pdm_reason_checked_out_here"
                        | "ui.pdm_reason_checked_out_elsewhere"
                        | "ui.pdm_reason_checked_out_other"
                );
            if !receipt_only
                && (command != "pdm.restore_version"
                    || !matches!(
                        reason,
                        "ui.pdm_reason_stale_base"
                            | "ui.pdm_reason_checked_out_here"
                            | "ui.pdm_reason_checked_out_elsewhere"
                            | "ui.pdm_reason_checked_out_other"
                    ))
            {
                return Err(reason.into());
            }
        }
        if matches!(&task, Task::Managed(ManagedTask::Recover { .. } | ManagedTask::RecoverConnection { .. })) {
            state.recovery_epoch = match state.recovery_epoch.checked_add(1) {
                Some(epoch) => epoch,
                None => {
                    state.protection_failed = true;
                    return Err("PDM recovery protection exhausted; restart the application".into());
                }
            };
        }
        state.next = state.next.checked_add(1).ok_or("Local PDM request limit reached")?;
        let id = state.next;
        state.blocked_paths = state.status.managed.local.iter().map(|entry| entry.path.clone()).collect();
        if let Task::Managed(ManagedTask::Archive { path, .. } | ManagedTask::ReconcileArchive { path, .. }) | Task::CheckIn { path, .. } = &task {
            state.blocked_paths.push(path.clone());
        }
        // A connection ID keeps native paths out of commands. Until native
        // authentication identifies its recovery root, reserve every saved path.
        state.block_all_paths = matches!(&task, Task::Managed(ManagedTask::Recover { .. } | ManagedTask::RecoverConnection { .. }));
        state.job = Some(Job { id, task });
        state.status.blocking = state.job.as_ref().is_some_and(|job| {
            matches!(
                &job.task,
                Task::CheckIn { .. }
                    | Task::Managed(
                        ManagedTask::Archive { .. }
                            | ManagedTask::ReconcileArchive { .. }
                            | ManagedTask::Checkout { .. }
                            | ManagedTask::CancelCheckout { .. }
                            | ManagedTask::GetLatest { .. }
                            | ManagedTask::Open { .. }
                            | ManagedTask::Recover { .. }
                            | ManagedTask::RecoverConnection { .. }
                            | ManagedTask::Restore { .. }
                    )
            )
        });
        state.status.busy = Some(id);
        Ok(id)
    }
    pub fn take_job(&self) -> Result<Option<Job>, String> {
        Ok(self.0.lock().map_err(|_| "Local PDM state unavailable")?.job.take())
    }
    pub fn finish(&self, id: u64, result: Result<Outcome, Failure>) -> Result<(), String> {
        let mut state = self.0.lock().map_err(|_| "Local PDM state unavailable")?;
        if state.status.busy != Some(id) {
            return Err("Stale local PDM result".into());
        }
        state.status.busy = None;
        state.status.blocking = false;
        state.blocked_paths.clear();
        state.block_all_paths = false;
        state.job = None;
        if let Ok(
            Outcome::Managed { state: managed, .. }
            | Outcome::ManagedRefreshed { state: managed, .. }
            | Outcome::ManagedConnected { state: managed, .. },
        ) = &result
            && let Err(error) = state.remember(managed)
        {
            state.protection_failed = true;
            state.status.port = None;
            state.status.connection = None;
            state.status.error = Some(error.clone());
            return Err(error);
        }
        if matches!(
            &result,
            Ok(Outcome::Managed { .. }
                | Outcome::ManagedRefreshed { .. }
                | Outcome::ManagedConnected { .. }
                | Outcome::Connected { .. }
                | Outcome::Disconnected)
        ) {
            state.status.error = None;
        }
        match result {
            Err(failure) => {
                state.status.error = Some(failure.message);
                if failure.disconnect {
                    state.status.port = None;
                    state.status.connection = None;
                    state.status.versions.clear();
                }
            }
            Ok(Outcome::Disconnected) => {
                state.status.port = None;
                state.status.connection = None;
                state.status.versions.clear();
                state.status.retrieved = None;
            }
            Ok(Outcome::Connections(connections)) => state.status.connections = connections,
            Ok(Outcome::ManagedConnected { port, state: mut managed, connections, connection }) => {
                if state.status.port == Some(port)
                    && state.status.managed.server_id == managed.server_id
                    && state.status.managed.workspace == managed.workspace
                {
                    managed.history = state.status.managed.history.clone();
                    managed.where_used = state.status.managed.where_used.clone();
                    managed.preview = state.status.managed.preview.clone();
                }
                state.status.port = Some(port);
                state.status.managed = managed;
                state.status.connections = connections;
                state.status.connection = Some(connection);
            }
            Ok(Outcome::Managed { port, state: managed }) => {
                if state.status.port != Some(port)
                    || state.status.managed.server_id != managed.server_id
                    || state.status.managed.workspace != managed.workspace
                {
                    state.status.connection = None;
                }
                state.status.port = Some(port);
                state.status.managed = managed;
            }
            Ok(Outcome::ManagedRefreshed { port, state: mut managed }) => {
                if state.status.port == Some(port)
                    && state.status.managed.server_id == managed.server_id
                    && state.status.managed.workspace == managed.workspace
                {
                    managed.history = state.status.managed.history.clone();
                    managed.where_used = state.status.managed.where_used.clone();
                    managed.preview = state.status.managed.preview.clone();
                } else {
                    state.status.connection = None;
                }
                state.status.port = Some(port);
                state.status.managed = managed;
            }
            Ok(Outcome::Connected { port, versions }) => {
                state.status.connection = None;
                state.status.port = Some(port);
                state.status.versions = versions;
            }
            Ok(Outcome::Listed(versions)) => state.status.versions = versions,
            Ok(Outcome::CheckedIn(version)) => {
                state.status.versions.retain(|v| v.reference != version.reference);
                state.status.versions.push(version);
            }
            Ok(Outcome::Retrieved(retrieved)) => state.status.retrieved = Some(retrieved),
        }
        state.status.versions.sort_by(|a, b| (&a.reference.document, a.reference.version).cmp(&(&b.reference.document, b.reference.version)));
        Ok(())
    }

    pub fn managed_for_path(&self, path: &str) -> Option<LocalEntry> {
        let key = cached_path_key(path);
        let state = self.0.lock().ok()?;
        let mut entry = state
            .status
            .managed
            .local
            .iter()
            .find(|entry| cached_path_key(&entry.path) == key)
            .cloned()
            .or_else(|| state.known_paths.get(&key).map(|known| known.entry.clone()))?;
        if state.protection_failed || state.historical_paths.contains_key(&key) {
            entry.checked_out = false;
        }
        Some(entry)
    }

    pub fn blocks_path(&self, path: &str) -> bool {
        self.0.lock().map_or(true, |state| {
            state.status.blocking
                && (state.block_all_paths || state.blocked_paths.iter().any(|blocked| cached_path_key(blocked) == cached_path_key(path)))
        })
    }

    pub fn may_save(&self, path: &str) -> Result<(), String> {
        let state = self.0.lock().map_err(|_| "Local PDM state unavailable")?;
        if state.protection_failed {
            return Err("PDM path protection is unavailable; restart the application before saving".into());
        }
        if state.status.blocking && (state.block_all_paths || state.blocked_paths.iter().any(|blocked| same_file_path(blocked, path))) {
            return Err("Wait for the managed operation before saving this file".into());
        }
        if state.historical_paths.values().any(|historical| same_file_path(historical, path)) {
            return Err("Historical copies are read-only; export to a separate file".into());
        }
        if state.known_paths.values().any(|known| {
            same_file_path(&known.entry.path, path)
                && !state
                    .status
                    .managed
                    .local
                    .iter()
                    .any(|active| active.checked_out && cached_path_key(&active.path) == cached_path_key(&known.entry.path))
        }) {
            return Err("Extract this managed design before saving, or Save As a separate copy".into());
        }
        Ok(())
    }
}

impl crate::Session {
    /// Trusted fresh-I/O/replacement boundary only, with the token captured BEFORE
    /// I/O. Never call for a cached tab or per-frame shared-runtime binding.
    pub fn mark_pdm_reloaded_from(&mut self, expected_epoch: u64) -> Result<(), String> {
        self.pdm.validate_reload_epoch(expected_epoch)?;
        self.pdm_recovery_epoch = expected_epoch;
        Ok(())
    }
    pub fn check_pdm_reopen(&self) -> crate::Result<()> {
        if self.pdm.requires_reopen(self.pdm_recovery_epoch, self.path.as_deref()) {
            return Err(crate::EngineError::Other("PDM recovery changed saved files. Reopen this design from disk before editing or saving its original path; Save As a separate copy preserves this editor.".into()));
        }
        Ok(())
    }

    /// Check each destination before an export writes, creates or removes files.
    /// Multi-file exports must check every target before their first side effect.
    pub fn check_output_path(&self, path: &str) -> crate::Result<()> {
        if self.path.as_deref().is_some_and(|original| same_file_path(original, path)) {
            self.check_pdm_reopen()?;
        }
        self.pdm.may_save(path).map_err(crate::EngineError::Other)?;
        if self.pdm_read_only && self.path.as_deref().is_some_and(|original| same_file_path(original, path)) {
            return Err(crate::EngineError::Other("Historical copies are read-only; export to a separate file".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "pdm_tests.rs"]
mod tests;
