//! Offline, bounded, verified backup/restore foundation. No power-loss durability claim.
//! Backups contain private metadata, including checkout capabilities; protect their directory.
use crate::{
    Error, MAX_CONTENT, MAX_STORED_CONTENT, MAX_VERSIONS, Store,
    blob_store::BlobReceipt,
    digest,
    stream_io::{self, StreamPolicy},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    path::Path,
};

const FORMAT: &str = "solidcraft-pdm-backup/1";
const MAX_FILES: usize = 10_000;
const MAX_FILE: usize = 8 * 1024 * 1024;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stream_policy: Option<StreamPolicy>,
    server_id: String,
    files: Vec<BackupFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupReceipt {
    pub format: String,
    pub server_id: String,
    pub files: u64,
    pub bytes: u64,
    pub manifest_sha256: String,
}

fn hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn number(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|n| n > 0 && n.to_string() == value)
}

fn allowed(path: &str) -> bool {
    let components: Vec<_> = path.split('/').collect();
    match components.as_slice() {
        ["managed-principals.json"] => true,
        ["managed", "blobs", hash] => hex(hash),
        [document, version, file] => {
            document.strip_prefix("d-").is_some_and(crate::valid_id) && number(version) && matches!(*file, "content" | "version.json")
        }
        ["managed", "generations", generation, "state.json"] => number(generation),
        ["managed", "metadata-snapshot.json"] => true,
        ["managed", "stream-policy.json"] => true,
        _ => false,
    }
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn collect(
    root: &Path,
    directory: &Path,
    result: &mut Vec<String>,
    depth: usize,
    visited: &mut usize,
    ignore_uncommitted: bool,
) -> Result<(), Error> {
    if depth > 4 {
        return Err(Error::Invalid("backup directory depth"));
    }
    for item in fs::read_dir(directory)? {
        *visited += 1;
        if *visited > 2 * MAX_FILES {
            return Err(Error::Invalid("backup entry count"));
        }
        let item = item?;
        let metadata = fs::symlink_metadata(item.path())?;
        if is_link(&metadata) {
            return Err(Error::Invalid("backup source links are forbidden"));
        }
        let relative =
            item.path().strip_prefix(root).map_err(|_| Error::Integrity)?.to_str().ok_or(Error::Invalid("backup path encoding"))?.replace('\\', "/");
        if ignore_uncommitted
            && root.join("managed/metadata.redb").try_exists()?
            && matches!(relative.as_str(), "managed/metadata.redb" | "managed/generations" | "managed-principals.json")
        {
            continue;
        }
        // Unpublished stages and the process lock are not part of a committed snapshot.
        if ignore_uncommitted
            && (relative == "writer.lock"
                || relative == "managed/blobs"
                || relative == "managed/uploads"
                || relative == "managed/blob-provider.json"
                || relative == "managed/blobs/pending"
                || relative == "managed/generations/pending"
                || (relative.starts_with("d-") && relative.ends_with("/pending")))
        {
            continue;
        }
        if metadata.is_dir() {
            collect(root, &item.path(), result, depth + 1, visited, ignore_uncommitted)?;
        } else if metadata.is_file() && allowed(&relative) {
            if result.len() >= MAX_FILES {
                return Err(Error::Invalid("backup file count"));
            }
            result.push(relative);
        } else {
            return Err(Error::Invalid("unexpected file in store snapshot"));
        }
    }
    Ok(())
}

fn new_private_directory(path: &Path) -> Result<(), Error> {
    crate::reject_symlink_ancestors(path)?;
    fs::create_dir(path)?; // Deliberately never create/open an existing destination.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn verify_domain(store: &Store) -> Result<(), Error> {
    let versions = store.list(None)?;
    if versions.len() > 2 * crate::MAX_VERSIONS {
        return Err(Error::Invalid("backup version count"));
    }
    for version in versions {
        if !hex(&version.sha256) || !crate::valid_id(&version.reference.document) || version.dependencies.len() > crate::MAX_DEPENDENCIES {
            return Err(Error::Integrity);
        }
        let verified = store.verify_reference(&version.reference)?;
        if verified != version {
            return Err(Error::Integrity);
        }
        for dependency in version.dependencies {
            store.verify_reference(&dependency)?;
        }
    }
    Ok(())
}

impl Store {
    /// The caller holds this store's exclusive process lock for the entire copy.
    /// CLI callers must stop the service; an in-process caller cannot mutate via `&self`.
    pub fn backup(&self, destination: &Path) -> Result<BackupReceipt, Error> {
        // The OS writer lock is owned by self throughout. Metadata and provider
        // inventory are captured before reading any blob; no service mutation can
        // interleave. Another independent writer of the same remote prefix is not
        // supported or made safe by this process-local lock.
        let snapshot = self.managed_snapshot()?;
        let mut inventory = self.blob_inventory()?;
        let policy = self.managed.stream_policy().cloned();
        validate_inventory(&inventory, policy.as_ref())?;
        let max_bytes = policy.as_ref().map_or(MAX_BYTES, |p| p.max_store_bytes.saturating_add(MAX_BYTES));
        let referenced: BTreeSet<_> = snapshot.digests.iter().collect();
        let available: BTreeSet<_> = inventory.iter().map(|blob| &blob.sha256).collect();
        if !referenced.is_subset(&available) {
            return Err(Error::Integrity);
        }
        inventory.sort_by(|left, right| left.sha256.cmp(&right.sha256));
        let source = fs::canonicalize(&self.root)?;
        crate::reject_symlink_ancestors(destination)?;
        // Avoid recursively copying a destination nested inside its own store.
        let destination_parent = fs::canonicalize(destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
        if destination_parent.starts_with(&source) {
            return Err(Error::Invalid("backup must be outside the store"));
        }
        let mut paths = Vec::new();
        collect(&source, &source, &mut paths, 0, &mut 0, true)?;
        paths.sort();
        new_private_directory(destination)?;
        let data = destination.join("data");
        fs::create_dir(&data)?;
        let mut files = Vec::new();
        let mut total = 0u64;
        for path in paths {
            let (_, receipt) = stream_io::verified_file(&source.join(&path), MAX_FILE as u64)?;
            total = total.checked_add(receipt.bytes).ok_or(Error::Invalid("backup size quota"))?;
            if total > max_bytes {
                return Err(Error::Invalid("backup size quota"));
            }
            let target = data.join(&path);
            fs::create_dir_all(target.parent().ok_or(Error::Integrity)?)?;
            stream_io::copy_new(&source.join(&path), &target, &receipt, MAX_FILE as u64)?;
            files.push(BackupFile { path, bytes: receipt.bytes, sha256: receipt.sha256 });
        }
        // Export the committed logical aggregate, never copy an open redb file.
        // The store lock and immutable borrow exclude domain mutations throughout.
        if let Some(bytes) = self.managed.database_snapshot()? {
            total = total.checked_add(bytes.len() as u64).ok_or(Error::Invalid("backup size quota"))?;
            if total > max_bytes {
                return Err(Error::Invalid("backup size quota"));
            }
            let path = "managed/metadata-snapshot.json".to_owned();
            fs::create_dir_all(data.join("managed"))?;
            crate::write_synced(&data.join(&path), &bytes)?;
            files.push(BackupFile { path, bytes: bytes.len() as u64, sha256: digest(&bytes) });
        }
        // Never copy a local managed/blobs cache. The active provider is the only
        // authority for both referenced bytes and complete published orphan blobs.
        fs::create_dir_all(data.join("managed/blobs"))?;
        for blob in inventory {
            total = total.checked_add(blob.bytes).ok_or(Error::Invalid("backup size quota"))?;
            if total > max_bytes || files.len() >= MAX_FILES {
                return Err(Error::Invalid("backup quota"));
            }
            let path = format!("managed/blobs/{}", blob.sha256);
            let mut input = self.managed.open_blob_stream(&blob.sha256)?;
            let mut output = OpenOptions::new().write(true).create_new(true).open(data.join(&path))?;
            if stream_io::copy_hash(&mut input, &mut output, policy.as_ref().map_or(MAX_CONTENT as u64, |_| stream_io::HARD_FILE_BYTES))? != blob {
                return Err(Error::Integrity);
            }
            output.sync_all()?;
            files.push(BackupFile { path, bytes: blob.bytes, sha256: blob.sha256 });
        }
        // Re-open copied metadata without creating a lock file in the immutable backup.
        // The original lock remains held, and no public Store exposes this copy.
        let copied = Store {
            root: data,
            _lock: self._lock.try_clone()?,
            managed: crate::managed::ManagedStore::open_portable_snapshot(&destination.join("data"))?,
        };
        verify_domain(&copied)?;
        let copied_snapshot = copied.managed_snapshot()?;
        if copied_snapshot.server_id != snapshot.server_id
            || copied_snapshot.generation != snapshot.generation
            || copied_snapshot.digests != snapshot.digests
        {
            return Err(Error::Integrity);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = Manifest {
            format: if policy.is_some() { "solidcraft-pdm-backup/2" } else { FORMAT }.into(),
            stream_policy: policy,
            server_id: snapshot.server_id,
            files,
        };
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        if bytes.len() > MAX_MANIFEST {
            return Err(Error::Invalid("backup manifest quota"));
        }
        // This immutable completion record is written last; interrupted copies lack it.
        crate::write_synced(&destination.join("backup.json"), &bytes)?;
        verify_backup(destination)
    }
}

fn validate_inventory(inventory: &[BlobReceipt], policy: Option<&StreamPolicy>) -> Result<(), Error> {
    if inventory.len() > MAX_VERSIONS {
        return Err(Error::Invalid("backup blob count"));
    }
    let mut hashes = BTreeSet::new();
    let mut total = 0u64;
    for blob in inventory {
        if !hex(&blob.sha256) || blob.bytes > policy.map_or(MAX_CONTENT as u64, |_| stream_io::HARD_FILE_BYTES) || !hashes.insert(&blob.sha256) {
            return Err(Error::Integrity);
        }
        total = total.checked_add(blob.bytes).ok_or(Error::Integrity)?;
        if total > policy.map_or(MAX_STORED_CONTENT, |p| p.max_store_bytes) {
            return Err(Error::Invalid("backup blob quota"));
        }
    }
    Ok(())
}

fn manifest(root: &Path) -> Result<(Manifest, Vec<u8>), Error> {
    crate::reject_symlink_ancestors(root)?;
    let bytes = crate::client::read_file(&root.join("backup.json"), MAX_MANIFEST)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    let expected_format = if manifest.stream_policy.is_some() { "solidcraft-pdm-backup/2" } else { FORMAT };
    if let Some(policy) = &manifest.stream_policy {
        policy.validate()?;
    }
    if manifest.format != expected_format || !hex(&manifest.server_id) || manifest.files.is_empty() || manifest.files.len() > MAX_FILES {
        return Err(Error::Integrity);
    }
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for file in &manifest.files {
        let limit = if file.path.starts_with("managed/blobs/") {
            manifest.stream_policy.as_ref().map_or(MAX_FILE as u64, |_| stream_io::HARD_FILE_BYTES)
        } else {
            MAX_FILE as u64
        };
        if !allowed(&file.path) || !hex(&file.sha256) || file.bytes > limit || !names.insert(&file.path) {
            return Err(Error::Integrity);
        }
        total = total.checked_add(file.bytes).ok_or(Error::Integrity)?;
        if total > manifest.stream_policy.as_ref().map_or(MAX_BYTES, |p| p.max_store_bytes.saturating_add(MAX_BYTES)) {
            return Err(Error::Invalid("backup size quota"));
        }
    }
    if names.contains(&"managed/stream-policy.json".to_owned()) != manifest.stream_policy.is_some() {
        return Err(Error::Integrity);
    }
    if !manifest.files.iter().any(|file| file.path.starts_with("managed/generations/") || file.path == "managed/metadata-snapshot.json") {
        return Err(Error::Integrity);
    }
    Ok((manifest, bytes))
}

/// Verify the complete file manifest without opening or modifying the backed-up store.
pub fn verify_backup(root: &Path) -> Result<BackupReceipt, Error> {
    let (manifest, bytes) = manifest(root)?;
    let data = root.join("data");
    crate::reject_symlink_ancestors(&data)?;
    let mut actual = Vec::new();
    collect(&data, &data, &mut actual, 0, &mut 0, false)?;
    actual.sort();
    let mut expected: Vec<_> = manifest.files.iter().map(|f| f.path.clone()).collect();
    expected.sort();
    if actual != expected {
        return Err(Error::Integrity);
    }
    let mut total = 0;
    for file in &manifest.files {
        let (_, receipt) = stream_io::verified_file(&data.join(&file.path), file.bytes)?;
        if receipt.bytes != file.bytes || receipt.sha256 != file.sha256 {
            return Err(Error::Integrity);
        }
        total += file.bytes;
    }
    if StreamPolicy::read(&data.join("managed"))? != manifest.stream_policy {
        return Err(Error::Integrity);
    }
    Ok(BackupReceipt {
        format: manifest.format,
        server_id: manifest.server_id,
        files: manifest.files.len() as u64,
        bytes: total,
        manifest_sha256: digest(&bytes),
    })
}

/// Restore only to a new directory, leaving the source and existing stores untouched.
/// A failed/interrupted restore remains marked and cannot be opened as a service store.
pub fn restore_backup(source: &Path, destination: &Path) -> Result<BackupReceipt, Error> {
    restore_backup_inner(source, destination, false)
}

fn restore_backup_inner(source: &Path, destination: &Path, database: bool) -> Result<BackupReceipt, Error> {
    let receipt = verify_backup(source)?; // Reject corrupt/unbounded input before destination creation.
    let (manifest, _) = manifest(source)?;
    new_private_directory(destination)?;
    let lock = OpenOptions::new().read(true).write(true).create_new(true).open(destination.join("writer.lock"))?;
    lock.try_lock().map_err(|_| Error::Invalid("restore destination is open"))?;
    crate::write_synced(&destination.join("restore.pending"), b"Restore incomplete; preserve and restore into another new directory.\n")?;
    for file in &manifest.files {
        let target = destination.join(&file.path);
        fs::create_dir_all(target.parent().ok_or(Error::Integrity)?)?;
        stream_io::copy_new(
            &source.join("data").join(&file.path),
            &target,
            &BlobReceipt { bytes: file.bytes, sha256: file.sha256.clone() },
            file.bytes,
        )?;
    }
    let managed = crate::managed::ManagedStore::open(destination)?;
    let mut store = Store { root: destination.to_path_buf(), _lock: lock, managed };
    verify_domain(&store)?;
    if store.managed.catalog().server_id != receipt.server_id {
        return Err(Error::Integrity);
    }
    // Keep the same writer lock and incomplete-restore fence throughout the
    // conversion. A failed/aborted import must never expose a usable JSON store.
    if database {
        store.managed.convert_restored_to_database()?;
    }
    store.managed.reset_transfers_after_restore()?;
    fs::remove_file(destination.join("restore.pending"))?;
    Ok(receipt)
}

/// Explicit JSON-to-database import, only via a verified backup and new directory.
/// A failed conversion preserves its destination for diagnosis; never retry in place.
pub fn restore_backup_to_redb(source: &Path, destination: &Path) -> Result<BackupReceipt, Error> {
    restore_backup_inner(source, destination, true)
}
