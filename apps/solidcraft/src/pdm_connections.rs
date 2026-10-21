//! Bounded native connection inventory; saved receipts never establish authentication.
//! Unix publication synchronizes new directory entries through their parents.
//! Windows recovery covers process interruption; no power-loss durability is
//! claimed without a verified platform-specific directory flush primitive.
#![cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

const MAX_RECORD: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 64;
const MAX_FILES: usize = 256;
const LOCK: &str = ".connections.lock";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexError {
    Invalid,
    Corrupt,
    Capacity,
    Busy,
    Unavailable,
    NotFound,
    Conflict,
}
impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "Invalid native PDM connection metadata",
            Self::Corrupt => "Native PDM connection index integrity failure",
            Self::Capacity => "Native PDM connection index capacity exceeded",
            Self::Busy => "Native PDM connection index is in use",
            Self::Unavailable => "Native PDM connection index unavailable",
            Self::NotFound => "Native PDM connection not found",
            Self::Conflict => "Native PDM connection receipt conflict",
        })
    }
}
impl std::error::Error for IndexError {}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspacePreference {
    version: u32,
    connection_id: String,
    pub path: String,
    pub workspace: String,
    pub server: String,
}
impl WorkspacePreference {
    fn validate(&self, id: &str) -> Result<(), IndexError> {
        if self.version != 1
            || !valid_id(&self.connection_id)
            || self.connection_id != id
            || !absolute_normal(Path::new(&self.path))
            || self.path.len() > 4096
            || !valid_identity(&self.workspace)
            || !valid_identity(&self.server)
        {
            return Err(IndexError::Corrupt);
        }
        Ok(())
    }
}
pub struct WorkspaceSelection {
    pub connection_id: String,
    pub source: PathBuf,
    pub destination: PathBuf,
    pub previous: Option<WorkspacePreference>,
    pub same: bool,
}
fn valid_identity(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_'))
}
fn absolute_normal(path: &Path) -> bool {
    path.is_absolute() && !path.components().any(|component| matches!(component, Component::ParentDir))
}
fn path_key(path: &Path) -> Result<String, IndexError> {
    let canonical = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => path.to_path_buf(),
        Err(_) => return Err(IndexError::Unavailable),
    };
    Ok(solidcraft_engine::pdm::cached_path_key(canonical.to_str().ok_or(IndexError::Invalid)?))
}
fn overlaps(first: &Path, second: &Path) -> Result<bool, IndexError> {
    let first = path_key(first)?;
    let second = path_key(second)?;
    let first = first.trim_end_matches('/');
    let second = second.trim_end_matches('/');
    Ok(first == second || first.starts_with(&format!("{second}/")) || second.starts_with(&format!("{first}/")))
}
/// Native-only all-ancestor link/reparse guard, with no repair or directory creation.
pub(crate) fn guard_workspace_path(path: &Path) -> Result<(), IndexError> {
    if !absolute_normal(path) {
        return Err(IndexError::Invalid);
    }
    guarded(path)
}

// Every tagged variant is a struct: unknown fields are rejected for every kind.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Intent {
    PendingLocal {
        version: u32,
        connection_id: String,
        label: String,
        administrator: String,
    },
    SavedProfile {
        version: u32,
        connection_id: String,
        label: String,
        profile_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_workspace: Option<WorkspacePreference>,
    },
}
impl Intent {
    fn fields(&self) -> (u32, &str, &str) {
        match self {
            Self::PendingLocal { version, connection_id, label, .. } | Self::SavedProfile { version, connection_id, label, .. } => {
                (*version, connection_id, label)
            }
        }
    }
    fn validate(&self, filename_id: &str) -> Result<(), IndexError> {
        let (version, id, label) = self.fields();
        if version != 1 || !valid_id(id) || id != filename_id || !valid_label(label) {
            return Err(IndexError::Corrupt);
        }
        if let Self::SavedProfile { initial_workspace: Some(workspace), .. } = self {
            workspace.validate(id)?;
        }
        match self {
            Self::PendingLocal { administrator, .. } if !valid_admin(administrator) => Err(IndexError::Corrupt),
            Self::SavedProfile { profile_id, .. } if !valid_id(profile_id) => Err(IndexError::Corrupt),
            _ => Ok(()),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u32,
    connection_id: String,
    profile_id: String,
}
impl Ready {
    fn validate(&self, id: &str) -> Result<(), IndexError> {
        if self.version != 1 || !valid_id(&self.connection_id) || self.connection_id != id || !valid_id(&self.profile_id) {
            return Err(IndexError::Corrupt);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionState {
    PendingLocal { administrator: String },
    LocalReadyRecorded { administrator: String, profile_id: String },
    SavedProfileUnverified { profile_id: String },
}
#[derive(Debug, PartialEq, Eq)]
pub struct ConnectionRow {
    pub connection_id: String,
    pub label: String,
    pub state: ConnectionState,
}

/// Public reserved identity and derived paths, never a login or account grant.
#[derive(Debug)]
pub struct LocalReservation {
    pub connection_id: String,
    pub installation: PathBuf,
    pub workspace: PathBuf,
}

#[derive(Debug)]
pub struct ConnectionDirectory {
    base: PathBuf,
    protected_roots: Vec<PathBuf>,
}
struct Snapshot {
    intents: BTreeMap<String, Intent>,
    ready: BTreeMap<String, Ready>,
    workspaces: BTreeMap<String, WorkspacePreference>,
    files: usize,
}

fn valid_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn valid_admin(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "owner"
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}
fn guarded(path: &Path) -> Result<(), IndexError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(IndexError::Invalid);
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(IndexError::Invalid);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(IndexError::Unavailable),
        }
    }
    Ok(())
}
fn private_dir(path: &Path) -> Result<(), IndexError> {
    guarded(path)?;
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(path) {
        Ok(()) => {
            #[cfg(unix)]
            sync_created_parent(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(IndexError::Unavailable),
    }
    validate_private_dir(path)
}
#[cfg(unix)]
fn sync_created_parent(path: &Path) -> Result<(), IndexError> {
    let parent = path.parent().ok_or(IndexError::Invalid)?;
    fs::File::open(parent).and_then(|directory| directory.sync_all()).map_err(|_| IndexError::Unavailable)
}
fn validate_private_dir(path: &Path) -> Result<(), IndexError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| IndexError::Unavailable)?;
    if !metadata.is_dir() {
        return Err(IndexError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(IndexError::Invalid);
        }
    }
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>, IndexError> {
    guarded(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| IndexError::Unavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_RECORD as u64 {
        return Err(IndexError::Corrupt);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| IndexError::Unavailable)?
        .take(MAX_RECORD as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| IndexError::Unavailable)?;
    if bytes.len() > MAX_RECORD {
        return Err(IndexError::Corrupt);
    }
    Ok(bytes)
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, IndexError> {
    serde_json::from_slice(&read(path)?).map_err(|_| IndexError::Corrupt)
}

impl ConnectionDirectory {
    /// Pure syntax validation: no directory creation, credential lookup or network.
    pub fn new(base: PathBuf) -> Result<Self, IndexError> {
        if !base.is_absolute() || base.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(IndexError::Invalid);
        }
        Ok(Self { base, protected_roots: Vec::new() })
    }
    /// Explicit setup only: create missing fixed settings ancestors privately.
    /// Construction and inventory remain read-only. Existing directories are not chmodded.
    pub fn prepare_settings_parent(&self) -> Result<(), IndexError> {
        let parent = self.base.parent().ok_or(IndexError::Invalid)?;
        guarded(parent)?;
        let mut missing = Vec::new();
        for ancestor in parent.ancestors() {
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.is_dir() => break,
                Ok(_) => return Err(IndexError::Invalid),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if missing.len() >= 16 {
                        return Err(IndexError::Invalid);
                    }
                    missing.push(ancestor);
                }
                Err(_) => return Err(IndexError::Unavailable),
            }
        }
        for path in missing.into_iter().rev() {
            private_dir(path)?;
        }
        guarded(parent)
    }
    fn root(&self) -> PathBuf {
        self.base.join("connections")
    }
    pub fn installation_path(&self, connection_id: &str) -> Result<PathBuf, IndexError> {
        if !valid_id(connection_id) {
            return Err(IndexError::Invalid);
        }
        Ok(self.base.join("installations").join(connection_id))
    }
    fn default_workspace_path(&self, connection_id: &str) -> Result<PathBuf, IndexError> {
        if !valid_id(connection_id) {
            return Err(IndexError::Invalid);
        }
        Ok(self.base.join("workspaces").join(connection_id))
    }
    pub fn workspace_path(&self, connection_id: &str) -> Result<PathBuf, IndexError> {
        Ok(match self.workspace_preference(connection_id)? {
            Some(preference) => PathBuf::from(preference.path),
            None => self.default_workspace_path(connection_id)?,
        })
    }
    pub fn with_boundaries(mut self, protected_roots: Vec<PathBuf>) -> Result<Self, IndexError> {
        if protected_roots.iter().any(|root| !absolute_normal(root)) {
            return Err(IndexError::Invalid);
        }
        self.protected_roots = protected_roots;
        Ok(self)
    }
    pub fn workspace_preference(&self, connection_id: &str) -> Result<Option<WorkspacePreference>, IndexError> {
        if !valid_id(connection_id) {
            return Err(IndexError::Invalid);
        }
        if !self.existing_root()? {
            return Ok(None);
        }
        let _lock = self.existing_lock(false)?;
        Ok(self.scan()?.workspaces.remove(connection_id))
    }
    pub fn select_workspace(&self, connection_id: &str, destination: &Path) -> Result<WorkspaceSelection, IndexError> {
        if !absolute_normal(destination) {
            return Err(IndexError::Invalid);
        }
        let previous = self.workspace_preference(connection_id)?;
        let source = match &previous {
            Some(preference) => PathBuf::from(&preference.path),
            None => self.default_workspace_path(connection_id)?,
        };
        guarded(&source)?;
        guarded(destination)?;
        let source = fs::canonicalize(source).map_err(|_| IndexError::Unavailable)?;
        let destination = fs::canonicalize(destination).map_err(|_| IndexError::Unavailable)?;
        if !fs::symlink_metadata(&destination).map_err(|_| IndexError::Unavailable)?.is_dir() {
            return Err(IndexError::Invalid);
        }
        let same = path_key(&source)? == path_key(&destination)?;
        if same {
            // Only a committed override identifies an idempotent settings retry.
            if previous.is_none() {
                return Err(IndexError::Conflict);
            }
        } else {
            if overlaps(&source, &destination)? || overlaps(&self.base, &destination)? {
                return Err(IndexError::Invalid);
            }
            for boundary in &self.protected_roots {
                guarded(boundary)?;
                if overlaps(boundary, &destination)? {
                    return Err(IndexError::Invalid);
                }
            }
            if fs::read_dir(&destination).map_err(|_| IndexError::Unavailable)?.next().transpose().map_err(|_| IndexError::Unavailable)?.is_some() {
                return Err(IndexError::Conflict);
            }
        }
        Ok(WorkspaceSelection { connection_id: connection_id.into(), source, destination, previous, same })
    }
    pub fn record_workspace(&self, selection: &WorkspaceSelection, workspace: &str, server: &str) -> Result<(), IndexError> {
        let _lock = self.writer()?;
        let snapshot = self.scan()?;
        if !snapshot.intents.contains_key(&selection.connection_id)
            || snapshot.workspaces.get(&selection.connection_id) != selection.previous.as_ref()
        {
            return Err(IndexError::Conflict);
        }
        let preference = WorkspacePreference {
            version: 1,
            connection_id: selection.connection_id.clone(),
            path: selection.destination.to_str().ok_or(IndexError::Invalid)?.into(),
            workspace: workspace.into(),
            server: server.into(),
        };
        preference.validate(&selection.connection_id)?;
        if selection.same {
            return if selection.previous.as_ref() == Some(&preference) { Ok(()) } else { Err(IndexError::Conflict) };
        }
        if !self.root().join(format!("{}.workspace.json", selection.connection_id)).try_exists().map_err(|_| IndexError::Unavailable)?
            && snapshot.files + 2 > MAX_FILES
        {
            return Err(IndexError::Capacity);
        }
        replace_preference(&self.root().join(format!("{}.workspace.json", selection.connection_id)), &preference)
    }
    /// Imported profiles live here. LocalSetup owns profiles inside its dedicated
    /// installation root; neither location is inferred from arbitrary UI paths.
    pub fn imported_profiles_path(&self) -> PathBuf {
        self.base.join("profiles")
    }
    // Caller holds an existing shared or exclusive index lock for the whole scan.
    fn scan(&self) -> Result<Snapshot, IndexError> {
        guarded(&self.base)?;
        guarded(&self.root())?;
        let directory = match fs::read_dir(self.root()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Snapshot { intents: BTreeMap::new(), ready: BTreeMap::new(), workspaces: BTreeMap::new(), files: 0 });
            }
            Err(_) => return Err(IndexError::Unavailable),
        };
        validate_private_dir(&self.base)?;
        validate_private_dir(&self.root())?;
        let mut snapshot = Snapshot { intents: BTreeMap::new(), ready: BTreeMap::new(), workspaces: BTreeMap::new(), files: 0 };
        for entry in directory {
            snapshot.files += 1;
            if snapshot.files > MAX_FILES {
                return Err(IndexError::Capacity);
            }
            let entry = entry.map_err(|_| IndexError::Unavailable)?;
            let path = entry.path();
            guarded(&path)?;
            let metadata = fs::symlink_metadata(&path).map_err(|_| IndexError::Unavailable)?;
            if !metadata.is_file() || metadata.len() > MAX_RECORD as u64 {
                return Err(IndexError::Corrupt);
            }
            let name = entry.file_name().into_string().map_err(|_| IndexError::Corrupt)?;
            if name == LOCK {
                if metadata.len() != 0 {
                    return Err(IndexError::Corrupt);
                }
                continue;
            }
            if name.strip_prefix(".connection-").and_then(|name| name.strip_suffix(".pending")).is_some_and(valid_id) {
                continue;
            }
            if let Some(id) = name.strip_suffix(".intent.json").filter(|id| valid_id(id)) {
                let intent: Intent = read_json(&path)?;
                intent.validate(id)?;
                snapshot.intents.insert(id.into(), intent);
            } else if let Some(id) = name.strip_suffix(".ready.json").filter(|id| valid_id(id)) {
                let ready: Ready = read_json(&path)?;
                ready.validate(id)?;
                snapshot.ready.insert(id.into(), ready);
            } else if let Some(id) = name.strip_suffix(".workspace.json").filter(|id| valid_id(id)) {
                let preference: WorkspacePreference = read_json(&path)?;
                preference.validate(id)?;
                snapshot.workspaces.insert(id.into(), preference);
            } else {
                return Err(IndexError::Corrupt);
            }
        }
        for (id, intent) in &snapshot.intents {
            if let Intent::SavedProfile { initial_workspace: Some(workspace), .. } = intent {
                // A later explicit Settings change overrides the initial binding.
                snapshot.workspaces.entry(id.clone()).or_insert_with(|| workspace.clone());
            }
        }
        if snapshot.workspaces.keys().any(|id| !snapshot.intents.contains_key(id)) {
            return Err(IndexError::Corrupt);
        }
        if snapshot.intents.len() > MAX_CONNECTIONS {
            return Err(IndexError::Capacity);
        }
        for id in snapshot.ready.keys() {
            if !matches!(snapshot.intents.get(id), Some(Intent::PendingLocal { .. })) {
                return Err(IndexError::Corrupt);
            }
        }
        Ok(snapshot)
    }
    pub fn list(&self) -> Result<Vec<ConnectionRow>, IndexError> {
        if !self.existing_root()? {
            return Ok(Vec::new());
        }
        let _reader_lock = self.existing_lock(false)?;
        let snapshot = self.scan()?;
        snapshot
            .intents
            .into_iter()
            .map(|(id, intent)| {
                let (_, _, label) = intent.fields();
                let label = label.to_owned();
                let state = match intent {
                    Intent::PendingLocal { administrator, .. } => match snapshot.ready.get(&id) {
                        Some(ready) => ConnectionState::LocalReadyRecorded { administrator, profile_id: ready.profile_id.clone() },
                        None => ConnectionState::PendingLocal { administrator },
                    },
                    Intent::SavedProfile { profile_id, .. } => ConnectionState::SavedProfileUnverified { profile_id },
                };
                Ok(ConnectionRow { connection_id: id, label, state })
            })
            .collect()
    }
    // Missing root is empty, but an existing incomplete root without its lock
    // is not repaired. This helper never creates any directory or file.
    fn existing_root(&self) -> Result<bool, IndexError> {
        guarded(&self.base)?;
        guarded(&self.root())?;
        match fs::symlink_metadata(&self.base) {
            Ok(_) => validate_private_dir(&self.base)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(IndexError::Unavailable),
        }
        match fs::symlink_metadata(self.root()) {
            Ok(_) => {
                validate_private_dir(&self.root())?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(IndexError::Unavailable),
        }
    }
    fn existing_lock(&self, exclusive: bool) -> Result<fs::File, IndexError> {
        let path = self.root().join(LOCK);
        guarded(&path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| if error.kind() == std::io::ErrorKind::NotFound { IndexError::Corrupt } else { IndexError::Unavailable })?;
        if !metadata.is_file() || metadata.len() != 0 {
            return Err(IndexError::Corrupt);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(IndexError::Invalid);
            }
        }
        let lock = fs::OpenOptions::new().read(true).write(exclusive).open(path).map_err(|_| IndexError::Unavailable)?;
        if exclusive {
            lock.try_lock().map_err(|_| IndexError::Busy)?;
        } else {
            lock.try_lock_shared().map_err(|_| IndexError::Busy)?;
        }
        Ok(lock)
    }
    fn writer(&self) -> Result<fs::File, IndexError> {
        let lock = if self.existing_root()? {
            // Acquire the existing lock BEFORE inspecting intent/ready pairs.
            self.existing_lock(true)?
        } else {
            private_dir(&self.base)?;
            guarded(&self.root())?;
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            match builder.create(self.root()) {
                Ok(()) => {
                    #[cfg(unix)]
                    sync_created_parent(&self.root())?;
                    // Only the creator of the root may create its initial lock.
                    // Crashes before lock publication leave a preserved incomplete
                    // root; later readers/writers refuse rather than repairing it.
                    let mut options = fs::OpenOptions::new();
                    options.create_new(true).read(true).write(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    let lock = options.open(self.root().join(LOCK)).map_err(|_| IndexError::Unavailable)?;
                    lock.try_lock().map_err(|_| IndexError::Busy)?;
                    lock.sync_all().map_err(|_| IndexError::Unavailable)?;
                    #[cfg(unix)]
                    fs::File::open(self.root()).and_then(|directory| directory.sync_all()).map_err(|_| IndexError::Unavailable)?;
                    lock
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Another initializer won. Never create a missing lock in its
                    // partial directory or inspect pairs while it holds the lock.
                    if !self.existing_root()? {
                        return Err(IndexError::Corrupt);
                    }
                    self.existing_lock(true)?
                }
                Err(_) => return Err(IndexError::Unavailable),
            }
        };
        self.scan()?;
        Ok(lock)
    }
    /// Publish intent BEFORE the caller creates a LocalSetup installation or its
    /// workspace. A crash after this return leaves a discoverable pending row.
    pub fn reserve_local(&self, label: &str, administrator: &str) -> Result<LocalReservation, IndexError> {
        if !valid_label(label) || !valid_admin(administrator) {
            return Err(IndexError::Invalid);
        }
        let _lock = self.writer()?;
        let id = solidcraft_pdm::AuthToken::generate().map_err(|_| IndexError::Unavailable)?;
        self.new_intent(Intent::PendingLocal { version: 1, connection_id: id.clone(), label: label.into(), administrator: administrator.into() })?;
        Ok(LocalReservation { installation: self.installation_path(&id)?, workspace: self.default_workspace_path(&id)?, connection_id: id })
    }
    /// Caller must have installed/validated the public profile through the native
    /// ProfileDirectory API first. This records a reference, never an auto-login.
    pub fn record_saved_profile(&self, label: &str, profile_id: &str) -> Result<String, IndexError> {
        if !valid_label(label) || !valid_id(profile_id) {
            return Err(IndexError::Invalid);
        }
        // Validate the actual installed public metadata before recording a reference.
        // This neither authenticates nor retrieves a bearer.
        crate::pdm_profiles::ProfileDirectory::new(self.imported_profiles_path())
            .map_err(|_| IndexError::Invalid)?
            .load(profile_id)
            .map_err(|_| IndexError::NotFound)?;
        let _lock = self.writer()?;
        let id = solidcraft_pdm::AuthToken::generate().map_err(|_| IndexError::Unavailable)?;
        self.new_intent(Intent::SavedProfile {
            version: 1,
            connection_id: id.clone(),
            label: label.into(),
            profile_id: profile_id.into(),
            initial_workspace: None,
        })?;
        Ok(id)
    }
    /// Explicit native import only: create private metadata parents without a
    /// discoverable connection row. Authentication has already succeeded.
    pub(crate) fn prepare_import_parent(&self) -> Result<(), IndexError> {
        self.prepare_settings_parent()?;
        let _lock = self.writer()?;
        Ok(())
    }
    /// Publish the saved profile reference and its verified initial workspace in
    /// one immutable intent. A reader never observes a row with a wrong default.
    pub fn record_saved_profile_at(&self, label: &str, profile_id: &str, path: &Path, workspace: &str, server: &str) -> Result<String, IndexError> {
        if !valid_label(label) || !valid_id(profile_id) || !absolute_normal(path) {
            return Err(IndexError::Invalid);
        }
        guarded(path)?;
        if !fs::symlink_metadata(path).map_err(|_| IndexError::Unavailable)?.is_dir() {
            return Err(IndexError::Invalid);
        }
        crate::pdm_profiles::ProfileDirectory::new(self.imported_profiles_path())
            .map_err(|_| IndexError::Invalid)?
            .load(profile_id)
            .map_err(|_| IndexError::NotFound)?;
        let _lock = self.writer()?;
        let snapshot = self.scan()?;
        if snapshot.intents.values().any(|intent| matches!(intent, Intent::SavedProfile {profile_id: existing, ..} if existing == profile_id)) {
            return Err(IndexError::Conflict);
        }
        let id = solidcraft_pdm::AuthToken::generate().map_err(|_| IndexError::Unavailable)?;
        let preference = WorkspacePreference {
            version: 1,
            connection_id: id.clone(),
            path: path.to_str().ok_or(IndexError::Invalid)?.into(),
            workspace: workspace.into(),
            server: server.into(),
        };
        preference.validate(&id)?;
        self.new_intent(Intent::SavedProfile {
            version: 1,
            connection_id: id.clone(),
            label: label.into(),
            profile_id: profile_id.into(),
            initial_workspace: Some(preference),
        })?;
        Ok(id)
    }
    fn new_intent(&self, intent: Intent) -> Result<(), IndexError> {
        let snapshot = self.scan()?;
        let (_, id, _) = intent.fields();
        if snapshot.intents.contains_key(id) {
            return Err(IndexError::Conflict);
        }
        if snapshot.intents.len() >= MAX_CONNECTIONS || snapshot.files + 2 > MAX_FILES {
            return Err(IndexError::Capacity);
        }
        publish(&self.root().join(format!("{id}.intent.json")), &intent)
    }
    /// Trusted native coordinator only: invoke after setup + fresh TLS identity +
    /// Host.connect_authenticated succeeded. The index cannot prove those gates.
    /// First publication binds the profile; later calls accept only that same ID.
    pub fn record_local_ready(&self, connection_id: &str, administrator: &str, profile_id: &str) -> Result<(), IndexError> {
        if !valid_id(connection_id) || !valid_admin(administrator) || !valid_id(profile_id) {
            return Err(IndexError::Invalid);
        }
        let _lock = self.writer()?;
        let snapshot = self.scan()?;
        match snapshot.intents.get(connection_id) {
            Some(Intent::PendingLocal { administrator: expected, .. }) if expected == administrator => {}
            Some(_) => return Err(IndexError::Conflict),
            None => return Err(IndexError::NotFound),
        }
        if let Some(ready) = snapshot.ready.get(connection_id) {
            return if ready.profile_id == profile_id { Ok(()) } else { Err(IndexError::Conflict) };
        }
        if snapshot.files + 2 > MAX_FILES {
            return Err(IndexError::Capacity);
        }
        publish(
            &self.root().join(format!("{connection_id}.ready.json")),
            &Ready { version: 1, connection_id: connection_id.into(), profile_id: profile_id.into() },
        )
    }
    /// Create only fixed parents explicitly after a durable intent. The install
    /// leaf remains absent so LocalSetup::begin can create it exclusively.
    pub fn prepare_local_parents(&self, connection_id: &str) -> Result<(), IndexError> {
        if !valid_id(connection_id) {
            return Err(IndexError::Invalid);
        }
        let _lock = self.writer()?;
        if !matches!(self.scan()?.intents.get(connection_id), Some(Intent::PendingLocal { .. })) {
            return Err(IndexError::NotFound);
        }
        private_dir(&self.base.join("installations"))?;
        private_dir(&self.base.join("workspaces"))?;
        Ok(())
    }
    /// A saved HTTPS profile also needs its own derived working-folder parent.
    /// Require an existing durable intent; unknown IDs never create an index.
    pub fn prepare_workspace_parent(&self, connection_id: &str) -> Result<(), IndexError> {
        if !valid_id(connection_id) {
            return Err(IndexError::Invalid);
        }
        if !self.existing_root()? {
            return Err(IndexError::NotFound);
        }
        let _lock = self.existing_lock(true)?;
        if !self.scan()?.intents.contains_key(connection_id) {
            return Err(IndexError::NotFound);
        }
        private_dir(&self.base.join("workspaces"))
    }
}

struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn publish(path: &Path, record: &impl Serialize) -> Result<(), IndexError> {
    guarded(path)?;
    let bytes = serde_json::to_vec(record).map_err(|_| IndexError::Invalid)?;
    if bytes.len() > MAX_RECORD {
        return Err(IndexError::Capacity);
    }
    let parent = path.parent().ok_or(IndexError::Invalid)?;
    let random = solidcraft_pdm::AuthToken::generate().map_err(|_| IndexError::Unavailable)?;
    let staging = parent.join(format!(".connection-{random}.pending"));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staging).map_err(|_| IndexError::Unavailable)?;
    let stage = Stage(staging);
    file.write_all(&bytes).map_err(|_| IndexError::Unavailable)?;
    file.sync_all().map_err(|_| IndexError::Unavailable)?;
    drop(file);
    match fs::hard_link(&stage.0, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read(path)? != bytes {
                return Err(IndexError::Conflict);
            }
        }
        Err(_) => return Err(IndexError::Unavailable),
    }
    #[cfg(unix)]
    fs::File::open(parent).and_then(|directory| directory.sync_all()).map_err(|_| IndexError::Unavailable)?;
    Ok(())
}

// Replacement is the commit point. After rename, no fallible work is reported to
// the caller. Parent flush is best effort; process recovery, not power-loss
// durability, is the promise on every platform for this settings operation.
fn replace_preference(path: &Path, record: &WorkspacePreference) -> Result<(), IndexError> {
    guarded(path)?;
    let bytes = serde_json::to_vec(record).map_err(|_| IndexError::Invalid)?;
    if bytes.len() > MAX_RECORD {
        return Err(IndexError::Capacity);
    }
    let parent = path.parent().ok_or(IndexError::Invalid)?;
    let random = solidcraft_pdm::AuthToken::generate().map_err(|_| IndexError::Unavailable)?;
    let stage = Stage(parent.join(format!(".connection-{random}.pending")));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&stage.0).map_err(|_| IndexError::Unavailable)?;
    file.write_all(&bytes).map_err(|_| IndexError::Unavailable)?;
    file.sync_all().map_err(|_| IndexError::Unavailable)?;
    drop(file);
    fs::rename(&stage.0, path).map_err(|_| IndexError::Unavailable)?;
    #[cfg(unix)]
    {
        let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self(std::env::temp_dir().join(format!("solidcraft-connections-{}", solidcraft_pdm::AuthToken::generate()?))))
        }
        fn index(&self) -> Result<ConnectionDirectory, IndexError> {
            ConnectionDirectory::new(self.0.clone())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn paired_import_initial_folder_is_one_record_and_later_settings_remain_explicit() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        index.prepare_import_parent()?;
        let profile = crate::pdm_login::Profile::from_json(&serde_json::to_vec(
            &serde_json::json!({"target":{"origin":"https://example.com","tunnel":null,"server_id":"a".repeat(64),"trust":{"kind":"platform"}},"principal_id":"Alice"}),
        )?)?;
        let profile_id = crate::pdm_profiles::ProfileDirectory::new(index.imported_profiles_path())?.install_new(profile)?;
        let destination = Temp::new()?;
        fs::create_dir(&destination.0)?;
        let workspace = solidcraft_pdm::managed_workspace::Workspace::create(&destination.0, &"a".repeat(64))?;
        let identity = workspace.manifest().workspace_id.clone();
        drop(workspace);
        let id = index.record_saved_profile_at("Imported", &profile_id, &destination.0, &identity, &"a".repeat(64))?;
        assert!(!index.root().join(format!("{id}.workspace.json")).exists());
        let intent = index.root().join(format!("{id}.intent.json"));
        let bytes = fs::read(&intent)?;
        assert_eq!(path_key(&root.index()?.workspace_path(&id)?)?, path_key(&destination.0)?);
        assert_eq!(index.record_saved_profile_at("Duplicate", &profile_id, &destination.0, &identity, &"a".repeat(64)), Err(IndexError::Conflict));
        assert_eq!(fs::read(&intent)?, bytes);
        assert_eq!(index.list()?.len(), 1);
        let changed = Temp::new()?;
        fs::create_dir(&changed.0)?;
        let selection = index.select_workspace(&id, &changed.0)?;
        index.record_workspace(&selection, &"b".repeat(32), &"a".repeat(64))?;
        assert_eq!(path_key(&root.index()?.workspace_path(&id)?)?, path_key(&changed.0)?);
        assert_eq!(index.list()?.len(), 1);
        Ok(())
    }

    #[test]
    fn workspace_settings_publish_atomically_compare_previous_and_survive_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        let reserved = index.reserve_local("Local", "admin")?;
        index.prepare_local_parents(&reserved.connection_id)?;
        fs::create_dir(&reserved.workspace)?;
        let destination = Temp::new()?;
        fs::create_dir(&destination.0)?;
        let selection = index.select_workspace(&reserved.connection_id, &destination.0)?;
        index.record_workspace(&selection, &"a".repeat(32), &"b".repeat(32))?;
        assert_eq!(path_key(&index.workspace_path(&reserved.connection_id)?)?, path_key(&destination.0)?);
        let reopened = root.index()?;
        assert_eq!(reopened.workspace_preference(&reserved.connection_id)?.ok_or(IndexError::NotFound)?.workspace, "a".repeat(32));
        assert_eq!(index.record_workspace(&selection, &"c".repeat(32), &"b".repeat(32)), Err(IndexError::Conflict));
        let same = index.select_workspace(&reserved.connection_id, &destination.0)?;
        assert!(same.same);
        index.record_workspace(&same, &"a".repeat(32), &"b".repeat(32))?;
        assert_eq!(index.record_workspace(&same, &"c".repeat(32), &"b".repeat(32)), Err(IndexError::Conflict));
        Ok(())
    }
    #[test]
    fn workspace_settings_reject_nonempty_overlap_protected_and_interrupted_destination() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let protected = Temp::new()?;
        fs::create_dir(&protected.0)?;
        let forbidden = protected.0.join("empty");
        fs::create_dir(&forbidden)?;
        let index = root.index()?.with_boundaries(vec![protected.0.clone()])?;
        let reserved = index.reserve_local("Local", "admin")?;
        index.prepare_local_parents(&reserved.connection_id)?;
        fs::create_dir(&reserved.workspace)?;
        assert!(index.select_workspace(&reserved.connection_id, &forbidden).is_err());
        assert!(index.select_workspace(&reserved.connection_id, &root.0).is_err());
        assert!(index.select_workspace(&reserved.connection_id, Path::new("relative")).is_err());
        let destination = Temp::new()?;
        fs::create_dir(&destination.0)?;
        fs::create_dir(destination.0.join(".solidcraft-pdm"))?;
        assert!(index.select_workspace(&reserved.connection_id, &destination.0).is_err());
        assert_eq!(index.workspace_preference(&reserved.connection_id)?, None);
        assert_eq!(index.workspace_path(&reserved.connection_id)?, reserved.workspace);
        Ok(())
    }
    #[test]
    fn workspace_settings_shared_index_lock_prevents_publication_without_changing_preference() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        let reserved = index.reserve_local("Local", "admin")?;
        index.prepare_local_parents(&reserved.connection_id)?;
        fs::create_dir(&reserved.workspace)?;
        let destination = Temp::new()?;
        fs::create_dir(&destination.0)?;
        let selection = index.select_workspace(&reserved.connection_id, &destination.0)?;
        let reader = index.existing_lock(false)?;
        assert_eq!(index.record_workspace(&selection, &"a".repeat(32), &"b".repeat(32)), Err(IndexError::Busy));
        drop(reader);
        assert_eq!(index.workspace_preference(&reserved.connection_id)?, None);
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn workspace_settings_reject_symlink_ancestors_without_following_them() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        let reserved = index.reserve_local("Local", "admin")?;
        index.prepare_local_parents(&reserved.connection_id)?;
        fs::create_dir(&reserved.workspace)?;
        let destination = Temp::new()?;
        fs::create_dir(&destination.0)?;
        fs::create_dir(destination.0.join("empty"))?;
        let alias = root.0.join("alias");
        std::os::unix::fs::symlink(&destination.0, &alias)?;
        assert!(index.select_workspace(&reserved.connection_id, &alias.join("empty")).is_err());
        assert_eq!(index.workspace_preference(&reserved.connection_id)?, None);
        Ok(())
    }
    #[test]
    fn pure_missing_reads_and_durable_pending_before_install() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        assert!(index.list()?.is_empty());
        assert!(!root.0.try_exists()?);
        let reservation = index.reserve_local("Office archive", "admin")?;
        assert!(!reservation.installation.try_exists()?);
        assert!(!reservation.workspace.try_exists()?);
        drop(index);
        let recovered = root.index()?;
        assert!(matches!(recovered.list()?.first().map(|row| &row.state), Some(ConnectionState::PendingLocal { .. })));
        recovered.prepare_local_parents(&reservation.connection_id)?;
        assert!(!reservation.installation.try_exists()?);
        Ok(())
    }
    #[test]
    fn ready_is_idempotent_and_wrong_profile_never_overwrites() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        let reserved = index.reserve_local("Local", "admin")?;
        let profile = "a".repeat(64);
        index.record_local_ready(&reserved.connection_id, "admin", &profile)?;
        let path = index.root().join(format!("{}.ready.json", reserved.connection_id));
        let before = fs::read(&path)?;
        index.record_local_ready(&reserved.connection_id, "admin", &profile)?;
        assert!(index.record_local_ready(&reserved.connection_id, "admin", &"b".repeat(64)).is_err());
        assert!(index.record_local_ready(&reserved.connection_id, "other-admin", &profile).is_err());
        assert_eq!(fs::read(path)?, before);
        assert!(index.root().join(format!("{}.intent.json", reserved.connection_id)).try_exists()?);
        assert!(matches!(index.list()?.first().map(|row| &row.state), Some(ConnectionState::LocalReadyRecorded { .. })));
        Ok(())
    }
    #[test]
    fn partial_unknown_or_orphan_receipts_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        let reserved = index.reserve_local("Local", "admin")?;
        let intent = index.root().join(format!("{}.intent.json", reserved.connection_id));
        let original = fs::read(&intent)?;
        fs::write(&intent, b"{")?;
        assert!(index.list().is_err());
        assert!(index.reserve_local("Other", "other").is_err());
        assert_eq!(fs::read(&intent)?, b"{");
        let mut value: serde_json::Value = serde_json::from_slice(&original)?;
        value.as_object_mut().ok_or(IndexError::Corrupt)?.insert("unknown".into(), true.into());
        fs::write(&intent, serde_json::to_vec(&value)?)?;
        assert!(index.list().is_err());
        fs::write(&intent, &original)?;
        index.record_local_ready(&reserved.connection_id, "admin", &"a".repeat(64))?;
        fs::remove_file(&intent)?;
        assert!(index.list().is_err());
        Ok(())
    }
    #[test]
    fn quotas_staging_and_input_paths_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        assert!(index.reserve_local("bad\nlabel", "admin").is_err());
        assert!(index.installation_path("../escape").is_err());
        assert!(ConnectionDirectory::new(PathBuf::from("relative")).is_err());
        assert!(!root.0.try_exists()?);
        for number in 0..MAX_CONNECTIONS {
            index.reserve_local(&format!("Local {number}"), "admin")?;
        }
        assert!(matches!(index.reserve_local("Overflow", "admin"), Err(IndexError::Capacity)));
        fs::write(index.root().join(format!(".connection-{}.pending", "a".repeat(64))), b"{interrupted")?;
        assert_eq!(index.list()?.len(), MAX_CONNECTIONS);
        fs::write(index.root().join(format!(".connection-{}.pending", "a".repeat(64))), vec![0; MAX_RECORD + 1])?;
        assert!(index.list().is_err());
        Ok(())
    }
    #[test]
    fn readers_take_existing_shared_lock_without_creating_or_repairing_files() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        assert!(index.list()?.is_empty());
        assert!(!root.0.try_exists()?);
        let reservation = index.reserve_local("Local", "admin")?;
        let writer = index.writer()?;
        assert!(matches!(index.list(), Err(IndexError::Busy)));
        assert!(matches!(index.record_local_ready(&reservation.connection_id, "admin", &"a".repeat(64)), Err(IndexError::Busy)));
        drop(writer);
        assert_eq!(index.list()?.len(), 1);
        let shared = index.existing_lock(false)?;
        assert_eq!(index.list()?.len(), 1);
        assert!(matches!(index.writer(), Err(IndexError::Busy)));
        drop(shared);
        let lock_path = index.root().join(LOCK);
        fs::remove_file(&lock_path)?;
        assert!(matches!(index.list(), Err(IndexError::Corrupt)));
        assert!(matches!(index.reserve_local("Other", "admin"), Err(IndexError::Corrupt)));
        assert!(!lock_path.try_exists()?);
        assert!(index.root().join(format!("{}.intent.json", reservation.connection_id)).try_exists()?);
        Ok(())
    }
    #[test]
    fn saved_profile_requires_installed_metadata_and_remains_unverified() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        assert!(index.record_saved_profile("Missing", &"a".repeat(64)).is_err());
        assert!(!root.0.try_exists()?);
        private_dir(&root.0)?;
        let value = serde_json::json!({"target":{"origin":"https://example.com","tunnel":null,"server_id":"a".repeat(64),"trust":{"kind":"platform"}},"principal_id":"Alice"});
        let profile = crate::pdm_login::Profile::from_json(&serde_json::to_vec(&value)?)?;
        let profiles = crate::pdm_profiles::ProfileDirectory::new(index.imported_profiles_path())?;
        let profile_id = profiles.install_new(profile)?;
        index.record_saved_profile("Imported", &profile_id)?;
        assert!(matches!(index.list()?.first().map(|row| &row.state), Some(ConnectionState::SavedProfileUnverified { .. })));
        Ok(())
    }
    #[test]
    fn unknown_names_and_total_file_quota_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        index.reserve_local("Local", "admin")?;
        fs::write(index.root().join("unknown.json"), b"{}")?;
        assert!(index.list().is_err());
        fs::remove_file(index.root().join("unknown.json"))?;
        for number in 0..MAX_FILES {
            fs::write(index.root().join(format!(".connection-{number:064x}.pending")), b"interrupted")?;
        }
        assert!(matches!(index.list(), Err(IndexError::Capacity)));
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn linked_index_is_rejected_without_following_it() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let index = root.index()?;
        index.reserve_local("Local", "admin")?;
        let other = Temp::new()?;
        private_dir(&other.0)?;
        let saved = root.0.join("saved-connections");
        fs::rename(index.root(), &saved)?;
        std::os::unix::fs::symlink(&other.0, index.root())?;
        assert!(index.list().is_err());
        fs::remove_file(index.root())?;
        Ok(())
    }
}
