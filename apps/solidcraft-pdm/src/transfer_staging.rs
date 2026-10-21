//! Bounded durable raw-byte staging. The trusted caller supplies authorization,
//! deadline-bound readers and the durable catalog-commit boundary for completion.
//! Two precreated fsynced ledger slots avoid Windows replace/rename semantics.
//! A sealed publication stays reserved and non-abortable until explicit completion.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
pub const CHUNK_BYTES: u64 = 1024 * 1024;
const HARD_CHUNK_BYTES: u64 = crate::transfers::HARD_CHUNK_BYTES;
const BUFFER: usize = 64 * 1024;
const TTL: u64 = 1_800_000;
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("file exceeds limit: {actual} bytes; maximum {max} bytes")]
    FileTooLarge { actual: u64, max: u64 },
    #[error("archive quota exceeded")]
    StorageQuota,
    #[error("temporary storage quota exceeded")]
    TemporaryQuota,
    #[error("transfer busy")]
    Busy,
    #[error("transfer authorization denied")]
    Forbidden,
    #[error("transfer expired")]
    Expired,
    #[error("transfer checksum mismatch")]
    Checksum,
    #[error("invalid transfer input or state")]
    Invalid,
    #[error("transfer I/O failure")]
    Io(#[from] std::io::Error),
}
type Result<T> = std::result::Result<T, TransferError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_store_bytes: u64,
    pub max_temporary_bytes: u64,
    pub max_sessions: usize,
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if self.max_file_bytes == 0
            || self.max_file_bytes > 8 * 1024 * 1024 * 1024
            || self.max_store_bytes < self.max_file_bytes
            || self.max_store_bytes > 16 * 1024 * 1024 * 1024 * 1024
            || self.max_temporary_bytes < self.max_file_bytes
            || self.max_temporary_bytes > self.max_store_bytes
            || !(1..=8).contains(&self.max_sessions)
        {
            return Err(TransferError::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub server_id: String,
    pub principal: String,
    pub epoch: u64,
}
fn hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn binding_valid(who: &Binding) -> bool {
    hex(&who.server_id) && !who.principal.is_empty() && who.principal.len() <= 128 && !who.principal.chars().any(char::is_control)
}
fn no_links(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.components().any(|p| matches!(p, std::path::Component::ParentDir)) {
        return Err(TransferError::Invalid);
    }
    for part in path.ancestors() {
        match fs::symlink_metadata(part) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    return Err(TransferError::Invalid);
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if m.file_attributes() & 0x400 != 0 {
                        return Err(TransferError::Invalid);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn private_directory(root: &Path) -> Result<()> {
    no_links(root)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    #[cfg(not(unix))]
    let _ = &mut builder;
    builder.create(root)?;
    #[cfg(windows)]
    {
        use std::{os::windows::process::CommandExt, process::Command};
        let system = PathBuf::from(std::env::var_os("SystemRoot").ok_or(TransferError::Invalid)?).join("System32");
        if !system.is_absolute() {
            return Err(TransferError::Invalid);
        }
        let result = Command::new(system.join("whoami.exe")).args(["/user", "/fo", "csv", "/nh"]).creation_flags(0x08000000).output()?;
        if !result.status.success() {
            return Err(TransferError::Invalid);
        }
        let text = String::from_utf8_lossy(&result.stdout);
        let sid = text.lines().find(|s| !s.trim().is_empty()).and_then(|s| s.rsplit(',').next()).unwrap_or_default().trim().trim_matches('"');
        if sid.len() > 128 || !sid.starts_with("S-1-") || sid.split('-').skip(1).any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit())) {
            return Err(TransferError::Invalid);
        }
        if !Command::new(system.join("icacls.exe"))
            .arg(root)
            .args(["/inheritance:r", "/grant:r", &format!("*{sid}:(OI)(CI)F"), "*S-1-5-18:(OI)(CI)F"])
            .creation_flags(0x08000000)
            .output()?
            .status
            .success()
        {
            return Err(TransferError::Invalid);
        }
    }
    Ok(())
}
const MAX_LEDGER: usize = 64 * 1024;
const FORMAT: &str = "solidcraft-pdm-staging/1";
const FIXED: [&str; 4] = ["policy.json", "writer.lock", "state-0.json", "state-1.json"];
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Allocating,
    Uploading,
    Sealing,
    Sealed,
    Aborting,
    Completing,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    who: Binding,
    total: u64,
    digest: String,
    offset: u64,
    expires: u64,
    last: Option<(u64, u64, String)>,
    phase: Phase,
    staging_link_retained: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    limits: Limits,
    sessions: BTreeMap<String, Session>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    format: String,
    generation: u64,
    ledger: Ledger,
    sha256: String,
}
struct State {
    generation: u64,
    ledger: Ledger,
    poisoned: bool,
}
pub struct Stager {
    root: PathBuf,
    limits: Limits,
    state: Mutex<State>,
    _writer_lock: fs::File,
}

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_PERSIST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_COMPLETE_DELETE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn fail_next_persist_for_test() {
    FAIL_NEXT_PERSIST.with(|flag| flag.set(true));
}
#[cfg(test)]
pub(crate) fn fail_next_complete_delete_for_test() {
    FAIL_NEXT_COMPLETE_DELETE.with(|flag| flag.set(true));
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferStatus {
    pub offset: u64,
    pub total: u64,
    pub sha256: String,
    pub expires: u64,
    pub sealed: bool,
    pub staging_link_retained: bool,
}
/// Trusted-local reconciliation metadata. This inventory has no per-user
/// filtering and must never be exposed directly by an authenticated HTTP route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedSession {
    pub id: String,
    pub binding: Binding,
    pub expires: u64,
    /// Includes an ambiguous Sealing publication; ordinary abort is unsafe.
    pub sealed: bool,
}
pub struct Sealed {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub staging_link_retained: bool,
}

fn regular(path: &Path) -> Result<fs::Metadata> {
    no_links(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(TransferError::Invalid);
    }
    Ok(metadata)
}
fn exists(path: &Path) -> Result<bool> {
    no_links(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(TransferError::Invalid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    // Windows acknowledgements flush existing regular-file handles. In
    // particular the ledger slots never rely on replacing a directory entry.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn private_file(path: &Path) -> Result<fs::File> {
    no_links(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    if regular(path)?.len() > limit as u64 {
        return Err(TransferError::Invalid);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(TransferError::Invalid);
    }
    Ok(bytes)
}
fn ledger_hash(generation: u64, ledger: &Ledger) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(FORMAT.as_bytes());
    hash.update(generation.to_be_bytes());
    hash.update(serde_json::to_vec(ledger).map_err(|_| TransferError::Invalid)?);
    Ok(format!("{:x}", hash.finalize()))
}
fn validate_ledger(ledger: &Ledger, limits: Limits) -> Result<u64> {
    if ledger.limits != limits || ledger.sessions.len() > limits.max_sessions {
        return Err(TransferError::Invalid);
    }
    let mut reserved = 0u64;
    let mut owners = std::collections::BTreeSet::new();
    for (id, session) in &ledger.sessions {
        if !hex(id)
            || !binding_valid(&session.who)
            || !hex(&session.digest)
            || session.total > limits.max_file_bytes
            || session.offset > session.total
            || session.expires < TTL
            || !owners.insert((&session.who.server_id, &session.who.principal))
        {
            return Err(TransferError::Invalid);
        }
        if matches!(session.phase, Phase::Sealing | Phase::Sealed | Phase::Completing) && session.offset != session.total {
            return Err(TransferError::Invalid);
        }
        if (session.phase == Phase::Allocating && (session.offset != 0 || session.last.is_some()))
            || (session.staging_link_retained && !matches!(session.phase, Phase::Sealed | Phase::Completing))
        {
            return Err(TransferError::Invalid);
        }
        if let Some((offset, length, digest)) = &session.last {
            if *length == 0 || *length > HARD_CHUNK_BYTES || !hex(digest) || offset.checked_add(*length) != Some(session.offset) {
                return Err(TransferError::Invalid);
            }
        } else if session.offset != 0 {
            return Err(TransferError::Invalid);
        }
        reserved = reserved.checked_add(session.total).ok_or(TransferError::Invalid)?;
    }
    if reserved > limits.max_temporary_bytes {
        return Err(TransferError::Invalid);
    }
    Ok(reserved)
}
fn read_slot(path: &Path, limits: Limits) -> Result<Option<Slot>> {
    let bytes = bounded_read(path, MAX_LEDGER)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let slot: Slot = match serde_json::from_slice(&bytes) {
        Ok(slot) => slot,
        // Only an incomplete write is recoverable. Complete but corrupt or
        // unknown JSON is not permission to downgrade to an older generation.
        Err(error) if error.is_eof() => return Ok(None),
        Err(_) => return Err(TransferError::Invalid),
    };
    if slot.format != FORMAT || !hex(&slot.sha256) || slot.sha256 != ledger_hash(slot.generation, &slot.ledger)? {
        return Err(TransferError::Invalid);
    }
    validate_ledger(&slot.ledger, limits)?;
    Ok(Some(slot))
}
impl Stager {
    pub fn create(root: &Path, limits: Limits) -> Result<Self> {
        limits.validate()?;
        private_directory(root)?;
        let writer = private_file(&root.join("writer.lock"))?;
        writer.try_lock().map_err(|_| TransferError::Busy)?;
        writer.sync_all()?;
        let mut policy = private_file(&root.join("policy.json"))?;
        policy.write_all(&serde_json::to_vec(&limits).map_err(|_| TransferError::Invalid)?)?;
        policy.sync_all()?;
        fs::create_dir(root.join("sealed"))?;
        let ledger = Ledger { limits, sessions: BTreeMap::new() };
        let slot = Slot { format: FORMAT.into(), generation: 0, sha256: ledger_hash(0, &ledger)?, ledger: ledger.clone() };
        let mut first = private_file(&root.join("state-0.json"))?;
        first.write_all(&serde_json::to_vec(&slot).map_err(|_| TransferError::Invalid)?)?;
        first.sync_all()?;
        private_file(&root.join("state-1.json"))?.sync_all()?;
        sync_directory(root)?;
        Ok(Self { root: root.into(), limits, state: Mutex::new(State { generation: 0, ledger, poisoned: false }), _writer_lock: writer })
    }
    /// Open only this format's existing private root. Metadata inventory and
    /// acknowledged sizes are bounded; full content hashes are checked at seal.
    pub fn open(root: &Path, limits: Limits) -> Result<Self> {
        limits.validate()?;
        no_links(root)?;
        if !fs::symlink_metadata(root)?.is_dir() {
            return Err(TransferError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(root)?.permissions().mode() & 0o077 != 0 {
                return Err(TransferError::Invalid);
            }
        }
        for name in FIXED {
            regular(&root.join(name))?;
        }
        let writer = fs::OpenOptions::new().read(true).write(true).open(root.join("writer.lock"))?;
        writer.try_lock().map_err(|_| TransferError::Busy)?;
        let policy: Limits = serde_json::from_slice(&bounded_read(&root.join("policy.json"), 4096)?).map_err(|_| TransferError::Invalid)?;
        if policy != limits {
            return Err(TransferError::Invalid);
        }
        let first = read_slot(&root.join("state-0.json"), limits)?;
        let second = read_slot(&root.join("state-1.json"), limits)?;
        let slot = match (first, second) {
            (Some(a), Some(b)) => {
                if a.generation.abs_diff(b.generation) > 1 || (a.generation == b.generation && a.sha256 != b.sha256) {
                    return Err(TransferError::Invalid);
                }
                if a.generation >= b.generation { a } else { b }
            }
            (Some(slot), None) | (None, Some(slot)) => slot,
            _ => return Err(TransferError::Invalid),
        };
        let stager = Self {
            root: root.into(),
            limits,
            state: Mutex::new(State { generation: slot.generation, ledger: slot.ledger, poisoned: false }),
            _writer_lock: writer,
        };
        {
            let mut state = stager.lock()?;
            stager.validate_inventory(&state.ledger)?;
            stager.recover(&mut state)?;
        }
        Ok(stager)
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        let state = self.state.try_lock().map_err(|_| TransferError::Busy)?;
        if state.poisoned {
            return Err(TransferError::Invalid);
        }
        Ok(state)
    }
    fn persist(&self, state: &mut State, ledger: Ledger) -> Result<()> {
        validate_ledger(&ledger, self.limits)?;
        let generation = state.generation.checked_add(1).ok_or(TransferError::Invalid)?;
        let slot = Slot { format: FORMAT.into(), generation, sha256: ledger_hash(generation, &ledger)?, ledger: ledger.clone() };
        let bytes = serde_json::to_vec(&slot).map_err(|_| TransferError::Invalid)?;
        if bytes.len() > MAX_LEDGER {
            return Err(TransferError::Invalid);
        }
        let path = self.root.join(if generation.is_multiple_of(2) { "state-0.json" } else { "state-1.json" });
        let result = (|| {
            regular(&path)?;
            let mut file = fs::OpenOptions::new().write(true).open(path)?;
            file.set_len(0)?;
            #[cfg(test)]
            if FAIL_NEXT_PERSIST.with(|flag| flag.replace(false)) {
                file.write_all(b"{")?;
                file.sync_all()?;
                return Err(TransferError::Io(std::io::Error::other("injected torn ledger persistence")));
            }
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok::<(), TransferError>(())
        })();
        if let Err(error) = result {
            state.poisoned = true;
            return Err(error);
        }
        state.generation = generation;
        state.ledger = ledger;
        Ok(())
    }
    fn validate_inventory(&self, ledger: &Ledger) -> Result<()> {
        let sealed = self.root.join("sealed");
        no_links(&sealed)?;
        if !fs::symlink_metadata(&sealed)?.is_dir() {
            return Err(TransferError::Invalid);
        }
        for (count, entry) in fs::read_dir(&self.root)?.enumerate() {
            if count >= FIXED.len() + 1 + self.limits.max_sessions {
                return Err(TransferError::Invalid);
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(TransferError::Invalid)?;
            no_links(&entry.path())?;
            if name == "sealed" {
                continue;
            }
            if FIXED.contains(&name) {
                regular(&entry.path())?;
                continue;
            }
            if !hex(name) || !ledger.sessions.contains_key(name) {
                return Err(TransferError::Invalid);
            }
            regular(&entry.path())?;
        }
        for (count, entry) in fs::read_dir(&sealed)?.enumerate() {
            if count >= self.limits.max_sessions {
                return Err(TransferError::Invalid);
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(TransferError::Invalid)?;
            let session = ledger.sessions.get(name).ok_or(TransferError::Invalid)?;
            if !hex(name) || !matches!(session.phase, Phase::Sealing | Phase::Sealed | Phase::Completing) {
                return Err(TransferError::Invalid);
            }
            regular(&entry.path())?;
        }
        Ok(())
    }
    fn recover(&self, state: &mut State) -> Result<()> {
        let ids: Vec<_> = state.ledger.sessions.keys().cloned().collect();
        for id in ids {
            let session = state.ledger.sessions.get(&id).cloned().ok_or(TransferError::Invalid)?;
            let raw = self.root.join(&id);
            let sealed = self.root.join("sealed").join(&id);
            match session.phase {
                Phase::Allocating => {
                    if !exists(&raw)? {
                        private_file(&raw)?.sync_all()?;
                        sync_directory(&self.root)?;
                    }
                    if regular(&raw)?.len() != 0 {
                        return Err(TransferError::Invalid);
                    }
                    let mut ledger = state.ledger.clone();
                    ledger.sessions.get_mut(&id).ok_or(TransferError::Invalid)?.phase = Phase::Uploading;
                    self.persist(state, ledger)?;
                }
                Phase::Uploading => {
                    let length = regular(&raw)?.len();
                    if length < session.offset || length > self.limits.max_file_bytes {
                        return Err(TransferError::Invalid);
                    }
                    if length > session.offset {
                        let file = fs::OpenOptions::new().write(true).open(&raw)?;
                        file.set_len(session.offset)?;
                        file.sync_all()?;
                    }
                }
                Phase::Sealing | Phase::Sealed => {
                    let raw_exists = exists(&raw)?;
                    let sealed_exists = exists(&sealed)?;
                    if !raw_exists && !sealed_exists {
                        return Err(TransferError::Invalid);
                    }
                    if raw_exists && regular(&raw)?.len() != session.total {
                        return Err(TransferError::Invalid);
                    }
                    if sealed_exists && regular(&sealed)?.len() != session.total {
                        return Err(TransferError::Invalid);
                    }
                    if session.phase == Phase::Sealed && !sealed_exists {
                        return Err(TransferError::Invalid);
                    }
                    if sealed_exists && (session.phase != Phase::Sealed || session.staging_link_retained != raw_exists) {
                        let mut ledger = state.ledger.clone();
                        let entry = ledger.sessions.get_mut(&id).ok_or(TransferError::Invalid)?;
                        entry.phase = Phase::Sealed;
                        entry.staging_link_retained = raw_exists;
                        self.persist(state, ledger)?;
                    }
                }
                Phase::Aborting | Phase::Completing => {
                    // A failed deletion keeps its reservation, including across
                    // restart. Other owners may still query their own sessions.
                    if let Err(error) = self.finish_delete(state, &id, |path| fs::remove_file(path))
                        && state.poisoned
                    {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }
    fn checked<'a>(state: &'a State, who: &Binding, id: &str, now: Option<u64>) -> Result<&'a Session> {
        if !binding_valid(who) || !hex(id) {
            return Err(TransferError::Forbidden);
        }
        let session = state.ledger.sessions.get(id).ok_or(TransferError::Forbidden)?;
        if session.who != *who {
            return Err(TransferError::Forbidden);
        }
        if now.is_some_and(|now| now >= session.expires) && matches!(session.phase, Phase::Allocating | Phase::Uploading) {
            return Err(TransferError::Expired);
        }
        Ok(session)
    }
    pub fn status(&self, who: &Binding, id: &str, now: u64, authorize: impl FnOnce(&Binding) -> Result<()>) -> Result<TransferStatus> {
        let state = self.lock()?;
        authorize(who)?;
        let session = Self::checked(&state, who, id, Some(now))?;
        if matches!(session.phase, Phase::Aborting | Phase::Completing) {
            return Err(TransferError::Invalid);
        }
        Ok(TransferStatus {
            offset: session.offset,
            total: session.total,
            sha256: session.digest.clone(),
            expires: session.expires,
            sealed: session.phase == Phase::Sealed,
            staging_link_retained: session.staging_link_retained,
        })
    }
    /// Only the trusted serialized catalog writer may compare this bounded
    /// inventory with its authoritative durable transfer records.
    pub fn inventory(&self) -> Result<Vec<StagedSession>> {
        let state = self.lock()?;
        Ok(state
            .ledger
            .sessions
            .iter()
            .map(|(id, session)| StagedSession {
                id: id.clone(),
                binding: session.who.clone(),
                expires: session.expires,
                sealed: matches!(session.phase, Phase::Sealing | Phase::Sealed | Phase::Completing),
            })
            .collect())
    }
    pub fn begin(
        &self,
        who: &Binding,
        total: u64,
        digest: String,
        committed_bytes: u64,
        now: u64,
        authorize: impl FnOnce(&Binding) -> Result<()>,
    ) -> Result<String> {
        let mut state = self.lock()?;
        authorize(who)?;
        if !binding_valid(who) || !hex(&digest) {
            return Err(TransferError::Invalid);
        }
        if total > self.limits.max_file_bytes {
            return Err(TransferError::FileTooLarge { actual: total, max: self.limits.max_file_bytes });
        }
        if state.ledger.sessions.len() >= self.limits.max_sessions
            || state.ledger.sessions.values().any(|s| s.who.server_id == who.server_id && s.who.principal == who.principal)
        {
            return Err(TransferError::Busy);
        }
        let reserved = validate_ledger(&state.ledger, self.limits)?.checked_add(total).ok_or(TransferError::TemporaryQuota)?;
        if reserved > self.limits.max_temporary_bytes {
            return Err(TransferError::TemporaryQuota);
        }
        if committed_bytes.checked_add(reserved).is_none_or(|n| n > self.limits.max_store_bytes) {
            return Err(TransferError::StorageQuota);
        }
        let expires = now.checked_add(TTL).ok_or(TransferError::Invalid)?;
        let id = crate::AuthToken::generate().map_err(|_| TransferError::Invalid)?;
        let mut ledger = state.ledger.clone();
        ledger.sessions.insert(
            id.clone(),
            Session { who: who.clone(), total, digest, offset: 0, expires, last: None, phase: Phase::Allocating, staging_link_retained: false },
        );
        self.persist(&mut state, ledger)?;
        private_file(&self.root.join(&id))?.sync_all()?;
        sync_directory(&self.root)?;
        let mut ledger = state.ledger.clone();
        ledger.sessions.get_mut(&id).ok_or(TransferError::Invalid)?.phase = Phase::Uploading;
        self.persist(&mut state, ledger)?;
        Ok(id)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn chunk(
        &self,
        who: &Binding,
        id: &str,
        offset: u64,
        length: u64,
        digest: &str,
        body: &mut impl Read,
        now: u64,
        authorize: impl FnOnce(&Binding) -> Result<()>,
    ) -> Result<u64> {
        let mut state = self.lock()?;
        authorize(who)?;
        let session = Self::checked(&state, who, id, Some(now))?.clone();
        if session.phase != Phase::Uploading
            || !hex(digest)
            || length == 0
            || length > HARD_CHUNK_BYTES
            || offset.checked_add(length).is_none_or(|end| end > session.total)
        {
            return Err(TransferError::Invalid);
        }
        if session.last.as_ref().is_some_and(|(o, n, h)| *o == offset && *n == length && h == digest) {
            return Ok(session.offset);
        }
        if offset != session.offset {
            return Err(TransferError::Invalid);
        }
        let path = self.root.join(id);
        if regular(&path)?.len() != offset {
            return Err(TransferError::Invalid);
        }
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let result = (|| {
            let mut remaining = length;
            let mut buffer = [0u8; BUFFER];
            let mut hasher = Sha256::new();
            while remaining > 0 {
                let wanted = usize::try_from(remaining.min(BUFFER as u64)).map_err(|_| TransferError::Invalid)?;
                let count = body.read(buffer.get_mut(..wanted).ok_or(TransferError::Invalid)?)?;
                if count == 0 || count > wanted {
                    return Err(TransferError::Invalid);
                }
                let bytes = buffer.get(..count).ok_or(TransferError::Invalid)?;
                hasher.update(bytes);
                file.write_all(bytes)?;
                remaining -= count as u64;
            }
            if body.read(&mut [0u8; 1])? != 0 {
                return Err(TransferError::Invalid);
            }
            if format!("{:x}", hasher.finalize()) != digest {
                return Err(TransferError::Checksum);
            }
            file.sync_all()?;
            Ok::<(), TransferError>(())
        })();
        if let Err(error) = result {
            if file.set_len(offset).and_then(|_| file.sync_all()).is_err() {
                state.poisoned = true;
            }
            return Err(error);
        }
        let mut ledger = state.ledger.clone();
        let entry = ledger.sessions.get_mut(id).ok_or(TransferError::Invalid)?;
        entry.offset = offset.checked_add(length).ok_or(TransferError::Invalid)?;
        entry.last = Some((offset, length, digest.into()));
        let acknowledged = entry.offset;
        self.persist(&mut state, ledger)?;
        Ok(acknowledged)
    }
    pub fn seal(&self, who: &Binding, id: &str, now: u64, authorize: impl FnOnce(&Binding) -> Result<()>) -> Result<Sealed> {
        self.seal_with_cleanup(who, id, now, authorize, |path| fs::remove_file(path))
    }
    fn seal_with_cleanup(
        &self,
        who: &Binding,
        id: &str,
        now: u64,
        authorize: impl FnOnce(&Binding) -> Result<()>,
        cleanup: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<Sealed> {
        let mut state = self.lock()?;
        authorize(who)?;
        let session = Self::checked(&state, who, id, Some(now))?.clone();
        let raw = self.root.join(id);
        let sealed = self.root.join("sealed").join(id);
        if session.phase == Phase::Sealed {
            if regular(&sealed)?.len() != session.total {
                return Err(TransferError::Invalid);
            }
            return Ok(Sealed { path: sealed, bytes: session.total, sha256: session.digest, staging_link_retained: session.staging_link_retained });
        }
        if !matches!(session.phase, Phase::Uploading | Phase::Sealing) || session.offset != session.total {
            return Err(TransferError::Invalid);
        }
        if regular(&raw)?.len() != session.total {
            return Err(TransferError::Checksum);
        }
        let mut file = fs::File::open(&raw)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; BUFFER];
        let mut bytes = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes = bytes.checked_add(count as u64).ok_or(TransferError::Invalid)?;
            if bytes > session.total {
                return Err(TransferError::Checksum);
            }
            hasher.update(buffer.get(..count).ok_or(TransferError::Invalid)?);
        }
        if bytes != session.total || format!("{:x}", hasher.finalize()) != session.digest {
            return Err(TransferError::Checksum);
        }
        drop(file);
        if session.phase != Phase::Sealing {
            let mut ledger = state.ledger.clone();
            ledger.sessions.get_mut(id).ok_or(TransferError::Invalid)?.phase = Phase::Sealing;
            self.persist(&mut state, ledger)?;
        }
        if !exists(&sealed)? {
            fs::hard_link(&raw, &sealed)?;
        }
        if regular(&sealed)?.len() != session.total {
            return Err(TransferError::Invalid);
        }
        fs::OpenOptions::new().write(true).open(&sealed)?.sync_all()?;
        sync_directory(&self.root.join("sealed"))?;
        let staging_link_retained = cleanup(&raw).is_err();
        if !staging_link_retained {
            sync_directory(&self.root)?;
        }
        let mut ledger = state.ledger.clone();
        let entry = ledger.sessions.get_mut(id).ok_or(TransferError::Invalid)?;
        entry.phase = Phase::Sealed;
        entry.staging_link_retained = staging_link_retained;
        self.persist(&mut state, ledger)?;
        Ok(Sealed { path: sealed, bytes: session.total, sha256: session.digest, staging_link_retained })
    }
    fn finish_delete(&self, state: &mut State, id: &str, mut remove: impl FnMut(&Path) -> std::io::Result<()>) -> Result<()> {
        let session = state.ledger.sessions.get(id).ok_or(TransferError::Forbidden)?;
        if !matches!(session.phase, Phase::Aborting | Phase::Completing) {
            return Err(TransferError::Invalid);
        }
        let raw = self.root.join(id);
        let sealed = self.root.join("sealed").join(id);
        if session.phase == Phase::Aborting && exists(&sealed)? {
            return Err(TransferError::Invalid);
        }
        if exists(&raw)? {
            remove(&raw)?;
            sync_directory(&self.root)?;
        }
        if session.phase == Phase::Completing && exists(&sealed)? {
            remove(&sealed)?;
            sync_directory(&self.root.join("sealed"))?;
        }
        let mut ledger = state.ledger.clone();
        ledger.sessions.remove(id);
        self.persist(state, ledger)
    }
    pub fn abort(&self, who: &Binding, id: &str, authorize: impl FnOnce(&Binding) -> Result<()>) -> Result<()> {
        let mut state = self.lock()?;
        authorize(who)?;
        let session = Self::checked(&state, who, id, None)?;
        if !matches!(session.phase, Phase::Allocating | Phase::Uploading | Phase::Aborting) {
            return Err(TransferError::Forbidden);
        }
        if session.phase != Phase::Aborting {
            let mut ledger = state.ledger.clone();
            ledger.sessions.get_mut(id).ok_or(TransferError::Invalid)?.phase = Phase::Aborting;
            self.persist(&mut state, ledger)?;
        }
        self.finish_delete(&mut state, id, |path| fs::remove_file(path))
    }
    /// The caller must invoke this only AFTER its catalog transaction durably
    /// commits ownership of the bytes. Unknown IDs are an authenticated no-op;
    /// they never cause arbitrary paths to be removed.
    pub fn complete(&self, who: &Binding, id: &str, authorize: impl FnOnce(&Binding) -> Result<()>) -> Result<()> {
        #[cfg(test)]
        if FAIL_NEXT_COMPLETE_DELETE.with(|flag| flag.replace(false)) {
            return self.complete_with_cleanup(who, id, authorize, |_| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)));
        }
        self.complete_with_cleanup(who, id, authorize, |path| fs::remove_file(path))
    }
    /// Trusted-local cross-domain cancellation only. The caller must ALREADY
    /// hold a durable catalog cancellation intent, or prove that this ID is not
    /// tracked by the authoritative catalog. Unlike ordinary abort, this may
    /// delete Sealing/Sealed bytes. Never expose it as a generic HTTP operation.
    pub fn discard(&self, who: &Binding, id: &str, authorize: impl FnOnce(&Binding) -> Result<()>) -> Result<()> {
        let mut state = self.lock()?;
        authorize(who)?;
        if !binding_valid(who) || !hex(id) {
            return Err(TransferError::Forbidden);
        }
        if !state.ledger.sessions.contains_key(id) {
            return Ok(());
        }
        let session = Self::checked(&state, who, id, None)?;
        let phase = if matches!(session.phase, Phase::Sealing | Phase::Sealed | Phase::Completing) { Phase::Completing } else { Phase::Aborting };
        if session.phase != phase {
            let mut ledger = state.ledger.clone();
            ledger.sessions.get_mut(id).ok_or(TransferError::Invalid)?.phase = phase;
            self.persist(&mut state, ledger)?;
        }
        self.finish_delete(&mut state, id, |path| fs::remove_file(path))
    }
    fn complete_with_cleanup(
        &self,
        who: &Binding,
        id: &str,
        authorize: impl FnOnce(&Binding) -> Result<()>,
        remove: impl FnMut(&Path) -> std::io::Result<()>,
    ) -> Result<()> {
        let mut state = self.lock()?;
        authorize(who)?;
        if !binding_valid(who) || !hex(id) {
            return Err(TransferError::Forbidden);
        }
        if !state.ledger.sessions.contains_key(id) {
            return Ok(());
        }
        let session = Self::checked(&state, who, id, None)?;
        if !matches!(session.phase, Phase::Sealed | Phase::Completing) {
            return Err(TransferError::Invalid);
        }
        if session.phase != Phase::Completing {
            let mut ledger = state.ledger.clone();
            ledger.sessions.get_mut(id).ok_or(TransferError::Invalid)?.phase = Phase::Completing;
            self.persist(&mut state, ledger)?;
        }
        self.finish_delete(&mut state, id, remove)
    }
    /// Expiry cannot release published or ambiguous-publication reservations.
    /// Cleanup is restricted to the exact authorized binding, including epoch.
    pub fn cleanup_expired(&self, who: &Binding, now: u64, authorize: impl FnOnce(&Binding) -> Result<()>) -> Result<usize> {
        let mut state = self.lock()?;
        authorize(who)?;
        if !binding_valid(who) {
            return Err(TransferError::Forbidden);
        }
        let ids: Vec<_> = state
            .ledger
            .sessions
            .iter()
            .filter(|(_, s)| s.who == *who && now >= s.expires && matches!(s.phase, Phase::Allocating | Phase::Uploading | Phase::Aborting))
            .map(|(id, _)| id.clone())
            .collect();
        let mut removed = 0;
        for id in ids {
            let mut ledger = state.ledger.clone();
            ledger.sessions.get_mut(&id).ok_or(TransferError::Invalid)?.phase = Phase::Aborting;
            self.persist(&mut state, ledger)?;
            self.finish_delete(&mut state, &id, |path| fs::remove_file(path))?;
            removed += 1;
        }
        Ok(removed)
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn fixture() -> (PathBuf, Limits, Binding) {
        (
            std::env::temp_dir().join(format!("transfer-durable-{}", crate::AuthToken::generate().unwrap())),
            Limits { max_file_bytes: 1, max_store_bytes: 2, max_temporary_bytes: 1, max_sessions: 2 },
            Binding { server_id: "a".repeat(64), principal: "alice".into(), epoch: 1 },
        )
    }
    fn filled(stage: &Stager, who: &Binding) -> String {
        let hash = format!("{:x}", Sha256::digest(b"x"));
        let id = stage.begin(who, 1, hash.clone(), 0, 0, |_| Ok(())).unwrap();
        stage.chunk(who, &id, 0, 1, &hash, &mut &b"x"[..], 1, |_| Ok(())).unwrap();
        id
    }
    #[test]
    fn trusted_discard_cleans_raw_only_publication_intent_and_recovers_cancel_journal() {
        let (root, limits, who) = fixture();
        let stage = Stager::create(&root, limits).unwrap();
        let id = filled(&stage, &who);
        {
            let mut state = stage.lock().unwrap();
            let mut ledger = state.ledger.clone();
            ledger.sessions.get_mut(&id).unwrap().phase = Phase::Sealing;
            stage.persist(&mut state, ledger).unwrap();
        }
        drop(stage);
        let stage = Stager::open(&root, limits).unwrap();
        assert!(stage.inventory().unwrap().first().unwrap().sealed);
        assert!(!root.join("sealed").join(&id).exists());
        stage.discard(&who, &id, |_| Ok(())).unwrap();
        assert!(!root.join(&id).exists());
        let next = filled(&stage, &who);
        // Crash after the trusted cancellation is durably journaled, before
        // unlinking a raw-only Sealing session.
        {
            let mut state = stage.lock().unwrap();
            let mut ledger = state.ledger.clone();
            ledger.sessions.get_mut(&next).unwrap().phase = Phase::Sealing;
            stage.persist(&mut state, ledger.clone()).unwrap();
            ledger.sessions.get_mut(&next).unwrap().phase = Phase::Completing;
            stage.persist(&mut state, ledger).unwrap();
        }
        drop(stage);
        let stage = Stager::open(&root, limits).unwrap();
        assert!(stage.inventory().unwrap().is_empty());
        assert!(!root.join(&next).exists());
        stage.discard(&who, &next, |_| Ok(())).unwrap();
        drop(stage);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn durable_publication_intent_recovers_hardlink_and_never_becomes_abortable() {
        let (root, limits, who) = fixture();
        let stage = Stager::create(&root, limits).unwrap();
        let id = filled(&stage, &who);
        {
            let mut state = stage.lock().unwrap();
            let mut ledger = state.ledger.clone();
            ledger.sessions.get_mut(&id).unwrap().phase = Phase::Sealing;
            stage.persist(&mut state, ledger).unwrap();
        }
        // Crash after the new-only publication, before its success ledger/ACK.
        fs::hard_link(root.join(&id), root.join("sealed").join(&id)).unwrap();
        drop(stage);
        let stage = Stager::open(&root, limits).unwrap();
        let status = stage.status(&who, &id, 2_000_000, |_| Ok(())).unwrap();
        assert!(status.sealed);
        assert!(status.staging_link_retained);
        assert!(matches!(stage.abort(&who, &id, |_| Ok(())), Err(TransferError::Forbidden)));
        assert_eq!(stage.cleanup_expired(&who, 2_000_000, |_| Ok(())).unwrap(), 0);
        let sealed = stage.seal(&who, &id, 2_000_000, |_| Ok(())).unwrap();
        assert!(sealed.path.is_file());
        stage.complete(&who, &id, |_| Ok(())).unwrap();
        assert!(!root.join(&id).exists());
        assert!(!sealed.path.exists());
        drop(stage);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_completion_delete_keeps_durable_reservation_until_real_cleanup() {
        let (root, limits, who) = fixture();
        let stage = Stager::create(&root, limits).unwrap();
        let id = filled(&stage, &who);
        let sealed = stage.seal(&who, &id, 2, |_| Ok(())).unwrap();
        assert!(stage.complete_with_cleanup(&who, &id, |_| Ok(()), |_| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))).is_err());
        assert!(sealed.path.is_file());
        {
            let state = stage.lock().unwrap();
            assert_eq!(validate_ledger(&state.ledger, limits).unwrap(), 1);
            assert!(state.ledger.sessions.get(&id).unwrap().phase == Phase::Completing);
        }
        let bob = Binding { principal: "bob".into(), ..who.clone() };
        assert!(matches!(stage.begin(&bob, 1, format!("{:x}", Sha256::digest(b"x")), 0, 3, |_| Ok(())), Err(TransferError::TemporaryQuota)));
        drop(stage);
        let stage = Stager::open(&root, limits).unwrap();
        assert!(!sealed.path.exists());
        assert!(stage.complete(&who, &id, |_| Ok(())).is_ok());
        let next = stage.begin(&bob, 1, format!("{:x}", Sha256::digest(b"x")), 1, 4, |_| Ok(())).unwrap();
        stage.abort(&bob, &next, |_| Ok(())).unwrap();
        drop(stage);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn torn_inactive_slot_recovers_but_complete_corruption_fails_closed() {
        let (root, limits, who) = fixture();
        let stage = Stager::create(&root, limits).unwrap();
        let id = filled(&stage, &who);
        let generation = stage.lock().unwrap().generation;
        let inactive = root.join(if generation.is_multiple_of(2) { "state-1.json" } else { "state-0.json" });
        drop(stage);
        fs::write(&inactive, b"{\"format\":").unwrap();
        let stage = Stager::open(&root, limits).unwrap();
        assert_eq!(stage.status(&who, &id, 2, |_| Ok(())).unwrap().offset, 1);
        drop(stage);
        fs::write(&inactive, b"{\"format\":\"unexpected\"}").unwrap();
        assert!(Stager::open(&root, limits).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_seal_unlink_retains_charge_and_cannot_abort_published_bytes() {
        let root = std::env::temp_dir().join(format!("transfer-unlink-{}", crate::AuthToken::generate().unwrap()));
        let stage = Stager::create(&root, Limits { max_file_bytes: 1, max_store_bytes: 2, max_temporary_bytes: 1, max_sessions: 2 }).unwrap();
        let who = Binding { server_id: "a".repeat(64), principal: "alice".into(), epoch: 1 };
        let hash = format!("{:x}", Sha256::digest(b"x"));
        let id = stage.begin(&who, 1, hash.clone(), 0, 0, |_| Ok(())).unwrap();
        let mut new_epoch = who.clone();
        new_epoch.epoch = 2;
        assert!(matches!(stage.begin(&new_epoch, 1, hash.clone(), 0, 0, |_| Ok(())), Err(TransferError::Busy)));
        stage.chunk(&who, &id, 0, 1, &hash, &mut &b"x"[..], 1, |_| Ok(())).unwrap();
        let sealed = stage.seal_with_cleanup(&who, &id, 2, |_| Ok(()), |_| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))).unwrap();
        assert!(sealed.staging_link_retained);
        assert!(sealed.path.is_file());
        assert!(root.join(&id).is_file());
        assert!(matches!(stage.abort(&who, &id, |_| Ok(())), Err(TransferError::Forbidden)));
        let bob = Binding { principal: "bob".into(), ..who };
        assert!(matches!(stage.begin(&bob, 1, hash, 0, 3, |_| Ok(())), Err(TransferError::TemporaryQuota)));
        drop(stage);
        fs::remove_dir_all(root).unwrap();
    }
}
