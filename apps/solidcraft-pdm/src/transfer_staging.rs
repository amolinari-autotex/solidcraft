//! Experimental bounded raw-byte staging, deliberately not advertised by HTTP.
//! The trusted adapter must supply current authorization and a deadline-bound
//! reader. No remote authentication, durable session resume or catalog commit is
//! implemented here. Sealed bytes retain their staging reservation until a
//! future transactional handoff; reopening existing staging roots is refused.
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
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Eq)]
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
struct Session {
    who: Binding,
    total: u64,
    digest: String,
    offset: u64,
    expires: u64,
    last: Option<(u64, u64, String)>,
    poisoned: bool,
}
struct State {
    sessions: BTreeMap<String, Session>,
    reserved: u64,
}
pub struct Stager {
    root: PathBuf,
    limits: Limits,
    state: Mutex<State>,
}
pub struct Sealed {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub staging_link_retained: bool,
}
impl Stager {
    pub fn create(root: &Path, limits: Limits) -> Result<Self> {
        limits.validate()?;
        private_directory(root)?;
        let mut policy = fs::OpenOptions::new().write(true).create_new(true).open(root.join("policy.json"))?;
        policy.write_all(&serde_json::to_vec(&limits).map_err(|_| TransferError::Invalid)?)?;
        policy.sync_all()?;
        fs::create_dir(root.join("sealed"))?;
        Ok(Self { root: root.into(), limits, state: Mutex::new(State { sessions: BTreeMap::new(), reserved: 0 }) })
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state.try_lock().map_err(|_| TransferError::Busy)
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
        if state.sessions.len() >= self.limits.max_sessions
            || state.sessions.values().any(|s| s.who.server_id == who.server_id && s.who.principal == who.principal)
        {
            return Err(TransferError::Busy);
        }
        let reserved = state.reserved.checked_add(total).ok_or(TransferError::TemporaryQuota)?;
        if reserved > self.limits.max_temporary_bytes {
            return Err(TransferError::TemporaryQuota);
        }
        if committed_bytes.checked_add(reserved).is_none_or(|n| n > self.limits.max_store_bytes) {
            return Err(TransferError::StorageQuota);
        }
        let expires = now.checked_add(TTL).ok_or(TransferError::Invalid)?;
        let id = crate::AuthToken::generate().map_err(|_| TransferError::Invalid)?.to_string();
        let file = fs::OpenOptions::new().write(true).create_new(true).open(self.root.join(&id))?;
        file.sync_all()?;
        state.sessions.insert(id.clone(), Session { who: who.clone(), total, digest, offset: 0, expires, last: None, poisoned: false });
        state.reserved = reserved;
        Ok(id)
    }
    fn checked<'a>(state: &'a mut State, who: &Binding, id: &str, now: u64) -> Result<&'a mut Session> {
        let session = state.sessions.get_mut(id).ok_or(TransferError::Forbidden)?;
        if session.who != *who {
            return Err(TransferError::Forbidden);
        }
        if now >= session.expires {
            return Err(TransferError::Expired);
        }
        if session.poisoned {
            return Err(TransferError::Invalid);
        }
        Ok(session)
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
        let session = Self::checked(&mut state, who, id, now)?;
        if !hex(digest) || length == 0 || length > CHUNK_BYTES || offset.checked_add(length).is_none_or(|end| end > session.total) {
            return Err(TransferError::Invalid);
        }
        if session.last.as_ref().is_some_and(|(o, n, h)| *o == offset && *n == length && h == digest) {
            return Ok(session.offset);
        }
        if offset != session.offset {
            return Err(TransferError::Invalid);
        }
        let path = self.root.join(id);
        no_links(&path)?;
        // A Windows append-only handle cannot reliably truncate a rejected tail.
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        if file.metadata()?.len() != offset {
            session.poisoned = true;
            return Err(TransferError::Invalid);
        }
        file.seek(SeekFrom::Start(offset))?;
        let result = (|| {
            let mut remaining = length;
            let mut buffer = [0u8; BUFFER];
            let mut hasher = Sha256::new();
            while remaining > 0 {
                let wanted = usize::try_from(remaining.min(BUFFER as u64)).map_err(|_| TransferError::Invalid)?;
                let count = body.read(buffer.get_mut(..wanted).ok_or(TransferError::Invalid)?)?;
                if count == 0 {
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
            Ok(())
        })();
        if let Err(error) = result {
            if file.set_len(offset).and_then(|_| file.sync_all()).is_err() {
                session.poisoned = true;
            }
            return Err(error);
        }
        session.offset += length;
        session.last = Some((offset, length, digest.into()));
        Ok(session.offset)
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
        let session = Self::checked(&mut state, who, id, now)?;
        if session.offset != session.total {
            return Err(TransferError::Invalid);
        }
        let path = self.root.join(id);
        no_links(&path)?;
        let mut file = fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; BUFFER];
        let mut bytes = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(buffer.get(..count).ok_or(TransferError::Invalid)?);
            bytes = bytes.checked_add(count as u64).ok_or(TransferError::Invalid)?;
            if bytes > session.total {
                return Err(TransferError::Checksum);
            }
        }
        let sha256 = format!("{:x}", hasher.finalize());
        if bytes != session.total || sha256 != session.digest {
            return Err(TransferError::Checksum);
        }
        drop(file);
        let sealed = self.root.join("sealed").join(id);
        no_links(&sealed)?;
        fs::hard_link(&path, &sealed)?;
        // The new-only sealed publication succeeded. A redundant private link
        // must not turn it into an abortable session and release its quota.
        let staging_link_retained = cleanup(&path).is_err();
        state.sessions.remove(id);
        // Keep reserved bytes charged: no transactional catalog handoff exists yet.
        Ok(Sealed { path: sealed, bytes, sha256, staging_link_retained })
    }
    pub fn abort(&self, who: &Binding, id: &str, authorize: impl FnOnce(&Binding) -> Result<()>) -> Result<()> {
        let mut state = self.lock()?;
        authorize(who)?;
        let session = state.sessions.get(id).ok_or(TransferError::Forbidden)?;
        if session.who != *who {
            return Err(TransferError::Forbidden);
        }
        let total = session.total;
        let path = self.root.join(id);
        no_links(&path)?;
        fs::remove_file(path)?;
        state.sessions.remove(id);
        state.reserved = state.reserved.checked_sub(total).ok_or(TransferError::Invalid)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
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
