//! Private public-profile metadata only. No credential store or network access.
//! Windows directories inherit permissions from an installer-owned private parent;
//! Unix directories/files are created with 0700/0600. Static path checks do not
//! defend against concurrent tampering by the owning local account.
#![cfg(not(target_arch = "wasm32"))]
use crate::pdm_login::Profile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

const MAX_BYTES: usize = 384 * 1024;
const MAX_PROFILES: usize = 64;
const MAX_ENTRIES: usize = 128;
const STAGING_PREFIX: &str = ".pdm-profile-";
const STAGING_SUFFIX: &str = ".pending";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    InvalidPath,
    InvalidProfile,
    Integrity,
    Capacity,
    Unavailable,
    NotFound,
}
impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "Invalid private PDM profile directory",
            Self::InvalidProfile => "Invalid saved PDM profile",
            Self::Integrity => "PDM profile integrity check failed",
            Self::Capacity => "PDM profile directory capacity exceeded",
            Self::Unavailable => "PDM profile storage unavailable",
            Self::NotFound => "PDM profile not found",
        })
    }
}
impl std::error::Error for ProfileError {}

#[derive(Debug)]
pub struct StoredProfile {
    pub id: String,
    pub profile: Profile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    profile: Profile,
}

/// Construction validates path syntax only and performs no filesystem access.
#[derive(Debug)]
pub struct ProfileDirectory {
    root: PathBuf,
}

fn hash_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn check_path(path: &Path) -> Result<(), ProfileError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ProfileError::InvalidPath);
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(ProfileError::InvalidPath);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ProfileError::Unavailable),
        }
    }
    Ok(())
}

fn profile_bytes(profile: &Profile) -> Result<Vec<u8>, ProfileError> {
    let bytes = serde_json::to_vec(profile).map_err(|_| ProfileError::InvalidProfile)?;
    Profile::from_json(&bytes).map_err(|_| ProfileError::InvalidProfile)?;
    Ok(bytes)
}

fn identity(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"solidcraft-pdm-public-profile-v1\0");
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    format!("{:x}", hash.finalize())
}

fn read_record(path: &Path, id: &str) -> Result<Profile, ProfileError> {
    check_path(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ProfileError::Unavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
        return Err(ProfileError::Integrity);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| ProfileError::Unavailable)?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProfileError::Unavailable)?;
    if bytes.len() > MAX_BYTES {
        return Err(ProfileError::Integrity);
    }
    let record: Record = serde_json::from_slice(&bytes).map_err(|_| ProfileError::Integrity)?;
    if record.version != 1 || identity(&profile_bytes(&record.profile)?) != id {
        return Err(ProfileError::Integrity);
    }
    Ok(record.profile)
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl ProfileDirectory {
    /// Pure canonical public-profile identity; no filesystem or credentials.
    pub fn profile_id(profile: &Profile) -> Result<String, ProfileError> {
        profile_bytes(profile).map(|bytes| identity(&bytes))
    }
    pub fn new(root: PathBuf) -> Result<Self, ProfileError> {
        if !root.is_absolute() || root.components().any(|part| matches!(part, Component::ParentDir)) {
            return Err(ProfileError::InvalidPath);
        }
        Ok(Self { root })
    }

    /// Validate all directory entries before returning any profile. Missing roots
    /// are empty and are never created by reads.
    fn scan(&self) -> Result<(Vec<StoredProfile>, usize), ProfileError> {
        check_path(&self.root)?;
        let directory = match fs::read_dir(&self.root) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(_) => return Err(ProfileError::Unavailable),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&self.root).map_err(|_| ProfileError::Unavailable)?.permissions().mode() & 0o077 != 0 {
                return Err(ProfileError::InvalidPath);
            }
        }
        let mut profiles = Vec::new();
        let mut count = 0usize;
        for entry in directory {
            count += 1;
            if count > MAX_ENTRIES {
                return Err(ProfileError::Capacity);
            }
            let entry = entry.map_err(|_| ProfileError::Unavailable)?;
            check_path(&entry.path())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| ProfileError::Unavailable)?;
            if !metadata.is_file() || metadata.len() > MAX_BYTES as u64 {
                return Err(ProfileError::Integrity);
            }
            let name = entry.file_name().into_string().map_err(|_| ProfileError::Integrity)?;
            if let Some(staging_id) = name.strip_prefix(STAGING_PREFIX).and_then(|name| name.strip_suffix(STAGING_SUFFIX))
                && hash_id(staging_id)
            {
                continue;
            }
            let id = name.strip_suffix(".json").filter(|id| hash_id(id)).ok_or(ProfileError::Integrity)?;
            if profiles.len() >= MAX_PROFILES {
                return Err(ProfileError::Capacity);
            }
            profiles.push(StoredProfile { id: id.into(), profile: read_record(&entry.path(), id)? });
        }
        profiles.sort_by(|left, right| left.id.cmp(&right.id));
        Ok((profiles, count))
    }

    pub fn list(&self) -> Result<Vec<StoredProfile>, ProfileError> {
        self.scan().map(|(profiles, _)| profiles)
    }

    pub fn load(&self, profile_id: &str) -> Result<Profile, ProfileError> {
        if !hash_id(profile_id) {
            return Err(ProfileError::InvalidProfile);
        }
        self.list()?.into_iter().find(|profile| profile.id == profile_id).map(|profile| profile.profile).ok_or(ProfileError::NotFound)
    }

    /// Explicit no-replace installation. The owning parent must already exist.
    /// A failed publish never falls back to overwrite or a different location.
    pub fn install_new(&self, profile: Profile) -> Result<String, ProfileError> {
        let canonical = profile_bytes(&profile)?;
        let id = identity(&canonical);
        let bytes = serde_json::to_vec(&Record { version: 1, profile }).map_err(|_| ProfileError::InvalidProfile)?;
        if bytes.len() > MAX_BYTES {
            return Err(ProfileError::Capacity);
        }
        let (existing, count) = self.scan()?;
        if existing.iter().any(|profile| profile.id == id) {
            return Ok(id);
        }
        if existing.len() >= MAX_PROFILES || count >= MAX_ENTRIES {
            return Err(ProfileError::Capacity);
        }
        check_path(&self.root)?;
        let builder = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder
            }
            #[cfg(not(unix))]
            {
                fs::DirBuilder::new()
            }
        };
        match builder.create(&self.root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ProfileError::Unavailable),
        }
        // A fixed owned unpublished file carries the OS writer lock. Keep its
        // inode/name after release so concurrent installers cannot split locks.
        let lock_path = self.root.join(format!("{STAGING_PREFIX}{}{STAGING_SUFFIX}", "0".repeat(64)));
        check_path(&lock_path)?;
        let mut lock_options = fs::OpenOptions::new();
        lock_options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let lock = lock_options.open(lock_path).map_err(|_| ProfileError::Unavailable)?;
        lock.try_lock().map_err(|_| ProfileError::Unavailable)?;
        // Recheck limits and publication while serialized with other installers.
        let (existing, count) = self.scan()?;
        if existing.iter().any(|profile| profile.id == id) {
            return Ok(id);
        }
        if existing.len() >= MAX_PROFILES || count >= MAX_ENTRIES {
            return Err(ProfileError::Capacity);
        }
        let staging_id = solidcraft_pdm::AuthToken::generate().map_err(|_| ProfileError::Unavailable)?;
        let staging_path = self.root.join(format!("{STAGING_PREFIX}{staging_id}{STAGING_SUFFIX}"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&staging_path).map_err(|_| ProfileError::Unavailable)?;
        let staging = Staging(staging_path);
        file.write_all(&bytes).map_err(|_| ProfileError::Unavailable)?;
        file.sync_all().map_err(|_| ProfileError::Unavailable)?;
        drop(file);
        let final_path = self.root.join(format!("{id}.json"));
        match fs::hard_link(&staging.0, &final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let published = read_record(&final_path, &id)?;
                if profile_bytes(&published)? != canonical {
                    return Err(ProfileError::Integrity);
                }
            }
            Err(_) => return Err(ProfileError::Unavailable),
        }
        #[cfg(unix)]
        fs::File::open(&self.root).and_then(|directory| directory.sync_all()).map_err(|_| ProfileError::Unavailable)?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self(std::env::temp_dir().join(format!("solidcraft-profiles-{}", solidcraft_pdm::AuthToken::generate()?))))
        }
        fn directory(&self) -> Result<ProfileDirectory, ProfileError> {
            ProfileDirectory::new(self.0.clone())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn profile(principal: &str) -> Result<Profile, Box<dyn std::error::Error>> {
        let value = serde_json::json!({"target":{"origin":"https://EXAMPLE.COM:443/","tunnel":null,"server_id":"a".repeat(64),"trust":{"kind":"platform"}},"principal_id":principal});
        Ok(Profile::from_json(&serde_json::to_vec(&value)?)?)
    }
    #[test]
    fn missing_reads_roundtrip_and_idempotent_install() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let directory = root.directory()?;
        assert!(directory.list()?.is_empty());
        assert!(!root.0.try_exists()?);
        let id = directory.install_new(profile("Alice")?)?;
        let final_path = root.0.join(format!("{id}.json"));
        let before = fs::read(&final_path)?;
        assert_eq!(directory.load(&id)?.principal_id(), "Alice");
        assert_eq!(directory.install_new(profile("Alice")?)?, id);
        assert_eq!(fs::read(final_path)?, before);
        assert_eq!(directory.list()?.len(), 1);
        assert!(directory.load("../invalid").is_err());
        Ok(())
    }
    #[test]
    fn unknown_schema_corrupt_hash_and_original_are_never_overwritten() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let directory = root.directory()?;
        let id = directory.install_new(profile("Alice")?)?;
        let path = root.0.join(format!("{id}.json"));
        let original = fs::read(&path)?;
        let mut record: serde_json::Value = serde_json::from_slice(&original)?;
        record.as_object_mut().ok_or(ProfileError::Integrity)?.insert("unexpected".into(), true.into());
        fs::write(&path, serde_json::to_vec(&record)?)?;
        let corrupt = fs::read(&path)?;
        assert!(directory.install_new(profile("Alice")?).is_err());
        assert_eq!(fs::read(&path)?, corrupt);
        fs::write(&path, &original)?;
        let wrong = root.0.join(format!("{}.json", "0".repeat(64)));
        fs::rename(&path, &wrong)?;
        assert!(directory.list().is_err());
        fs::rename(&wrong, &path)?;
        fs::write(root.0.join("unknown.txt"), b"unrecognized")?;
        assert!(directory.load(&id).is_err());
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }
    #[test]
    fn interrupted_staging_is_not_a_published_profile() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let directory = root.directory()?;
        let id = directory.install_new(profile("Alice")?)?;
        fs::write(root.0.join(format!("{STAGING_PREFIX}{}{STAGING_SUFFIX}", "a".repeat(64))), b"{partial")?;
        assert_eq!(directory.list()?.len(), 1);
        assert_eq!(directory.load(&id)?.principal_id(), "Alice");
        Ok(())
    }
    #[test]
    fn bounded_entry_file_and_profile_counts() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let directory = root.directory()?;
        for index in 0..MAX_PROFILES {
            directory.install_new(profile(&format!("user-{index}"))?)?;
        }
        assert!(matches!(directory.install_new(profile("overflow")?), Err(ProfileError::Capacity)));
        let entries = directory.list()?;
        let first = entries.first().ok_or(ProfileError::Integrity)?;
        fs::write(root.0.join(format!("{}.json", first.id)), vec![b' '; MAX_BYTES + 1])?;
        assert!(directory.list().is_err());
        let staging_root = Temp::new()?;
        let staging_directory = staging_root.directory()?;
        staging_directory.install_new(profile("Alice")?)?;
        for index in 0..MAX_ENTRIES {
            fs::write(staging_root.0.join(format!("{STAGING_PREFIX}{index:064x}{STAGING_SUFFIX}")), b"pending")?;
        }
        assert!(matches!(staging_directory.list(), Err(ProfileError::Capacity)));
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn linked_profile_and_directory_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let directory = root.directory()?;
        let id = directory.install_new(profile("Alice")?)?;
        let original = root.0.join(format!("{id}.json"));
        let saved = fs::read(&original)?;
        fs::remove_file(&original)?;
        let external = Temp::new()?;
        fs::write(&external.0, &saved)?;
        std::os::unix::fs::symlink(&external.0, &original)?;
        assert!(directory.list().is_err());
        fs::remove_file(&original)?;
        fs::remove_file(&external.0)?;
        std::os::unix::fs::symlink(&root.0, &external.0)?;
        assert!(external.directory()?.list().is_err());
        fs::remove_file(&external.0)?;
        Ok(())
    }
}
