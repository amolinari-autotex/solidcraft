//! Immutable content storage only: catalog authority, checkout and receipts remain
//! the responsibility of the managed service. No network provider is implied.
//!
//! The service must serialize writers and exclusively own the store directory.
//! Static link checks do not protect against concurrent privileged host tampering.
//! File contents are synced before no-replace publication. Directory-entry
//! durability across power loss, especially on Windows, is not established here.

use crate::{Error, MAX_CONTENT, MAX_STORED_CONTENT, MAX_VERSIONS, digest};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobReceipt {
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum BlobBinding {
    Filesystem,
    External { fingerprint: String },
}
impl BlobBinding {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if let Self::External { fingerprint } = self {
            validate_digest(fingerprint)?;
        }
        Ok(())
    }
}

/// Bounded enumeration for a coordinated backup. Callers must also capture the
/// matching catalog generation; a blob listing alone is not a complete backup.
pub trait BlobStore: Send {
    fn binding(&self) -> BlobBinding;
    fn put_verified_if_absent(&mut self, sha256: &str, content: &[u8]) -> Result<BlobReceipt, Error>;
    fn get_verified(&self, sha256: &str) -> Result<Vec<u8>, Error>;
    fn inventory(&self) -> Result<Vec<BlobReceipt>, Error>;
    fn open_verified_stream(&self, sha256: &str) -> Result<Box<dyn Read + Send>, Error> {
        let bytes = self.get_verified(sha256)?;
        if bytes.len() > MAX_CONTENT || digest(&bytes) != sha256 {
            return Err(Error::Integrity);
        }
        Ok(Box::new(std::io::Cursor::new(bytes)))
    }
    fn put_stream_if_absent(&mut self, _sha256: &str, _bytes: u64, _reader: &mut dyn Read) -> Result<BlobReceipt, Error> {
        Err(Error::Invalid("streaming provider unsupported"))
    }
}

/// Uses the existing managed-root/blobs/<lowercase-sha256> layout.
pub struct FsBlobStore {
    directory: PathBuf,
    policy: Option<crate::stream_io::StreamPolicy>,
}

pub(crate) fn validate_digest(value: &str) -> Result<(), Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(Error::Invalid("blob digest"));
    }
    Ok(())
}

fn reject_links(path: &Path) -> Result<(), Error> {
    crate::reject_symlink_ancestors(path)?;
    // Windows junctions and other reparse points must also fail closed, even
    // when their file type is not reported as a symbolic link.
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        for ancestor in path.ancestors() {
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.file_attributes() & 0x400 != 0 => return Err(Error::Invalid("reparse blob path")),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

impl FsBlobStore {
    pub fn open(managed_root: &Path) -> Result<Self, Error> {
        let policy = crate::stream_io::StreamPolicy::read(managed_root)?;
        // Preserve Store::open's existing support for trusted relative roots,
        // without canonicalizing away a pre-existing symlink or junction.
        let directory = std::path::absolute(managed_root)?.join("blobs");
        match fs::symlink_metadata(managed_root.join("blob-provider.json")) {
            Ok(_) => return Err(Error::Invalid("external or partial blob provider binding")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        reject_links(&directory)?;
        fs::create_dir_all(&directory)?;
        reject_links(&directory)?;
        let store = Self { directory, policy };
        store.scan()?;
        Ok(store)
    }

    fn path(&self, sha256: &str) -> Result<PathBuf, Error> {
        validate_digest(sha256)?;
        let path = self.directory.join(sha256);
        reject_links(&path)?;
        Ok(path)
    }
    fn file_limit(&self) -> u64 {
        self.policy.as_ref().map_or(MAX_CONTENT as u64, |p| p.max_file_bytes)
    }
    fn read_limit(&self) -> u64 {
        if self.policy.is_some() { crate::stream_io::HARD_FILE_BYTES } else { MAX_CONTENT as u64 }
    }
    fn store_limit(&self) -> u64 {
        self.policy.as_ref().map_or(MAX_STORED_CONTENT, |p| p.max_store_bytes)
    }

    /// Count even a leftover staging file against both quotas. Unknown entries
    /// are errors rather than silently skipped backup data or unlimited garbage.
    fn scan(&self) -> Result<(Vec<BlobReceipt>, usize, u64), Error> {
        reject_links(&self.directory)?;
        let mut blobs = Vec::new();
        let mut count = 0usize;
        let mut bytes = 0u64;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            count += 1;
            if count > MAX_VERSIONS + 1 {
                return Err(Error::Invalid("blob storage quota"));
            }
            let path = entry.path();
            reject_links(&path)?;
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.len() > self.read_limit() {
                return Err(Error::Integrity);
            }
            bytes = bytes.checked_add(metadata.len()).ok_or(Error::Integrity)?;
            if bytes > self.store_limit() {
                return Err(Error::Invalid("blob storage quota"));
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::Integrity)?;
            if name == "pending" {
                continue;
            }
            validate_digest(name).map_err(|_| Error::Integrity)?;
            blobs.push(BlobReceipt { sha256: name.to_owned(), bytes: metadata.len() });
            if blobs.len() > MAX_VERSIONS {
                return Err(Error::Invalid("blob storage quota"));
            }
        }
        blobs.sort_by(|left, right| left.sha256.cmp(&right.sha256));
        Ok((blobs, count, bytes))
    }
}

impl BlobStore for FsBlobStore {
    fn binding(&self) -> BlobBinding {
        BlobBinding::Filesystem
    }
    fn put_verified_if_absent(&mut self, sha256: &str, content: &[u8]) -> Result<BlobReceipt, Error> {
        let path = self.path(sha256)?;
        if content.len() > MAX_CONTENT || content.len() as u64 > self.file_limit() {
            return Err(Error::Invalid("blob content size"));
        }
        if digest(content) != sha256 {
            return Err(Error::Integrity);
        }
        let receipt = BlobReceipt { sha256: sha256.to_owned(), bytes: content.len() as u64 };
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if self.get_verified(sha256)? != content {
                    return Err(Error::Integrity);
                }
                return Ok(receipt);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let (blobs, _, bytes) = self.scan()?;
        if blobs.len() >= MAX_VERSIONS || bytes.checked_add(content.len() as u64).is_none_or(|sum| sum > self.store_limit()) {
            return Err(Error::Invalid("blob storage quota"));
        }
        // create_new refuses a leftover or another writer's staging file. Never
        // delete an existing staging file automatically: recovery is explicit.
        let pending = self.directory.join("pending");
        reject_links(&pending)?;
        crate::write_synced(&pending, content)?;
        // A hard link publishes the already-synced inode without replacing an
        // existing destination (rename can replace it on some platforms).
        let published = match fs::hard_link(&pending, &path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.get_verified(sha256).and_then(|existing| if existing == content { Ok(()) } else { Err(Error::Integrity) })
            }
            Err(error) => Err(error.into()),
        };
        // Preserve the published directory entry where directory fsync is
        // available. Windows directory flush semantics remain unvalidated.
        #[cfg(unix)]
        let published = published.and_then(|()| fs::File::open(&self.directory)?.sync_all().map_err(Error::from));
        let cleanup = fs::remove_file(&pending);
        published?;
        cleanup?;
        Ok(receipt)
    }

    fn get_verified(&self, sha256: &str) -> Result<Vec<u8>, Error> {
        let path = self.path(sha256)?;
        let content = crate::client::read_file(&path, MAX_CONTENT)?;
        if digest(&content) != sha256 {
            return Err(Error::Integrity);
        }
        Ok(content)
    }

    fn inventory(&self) -> Result<Vec<BlobReceipt>, Error> {
        let (blobs, _, _) = self.scan()?;
        for blob in &blobs {
            let (_, actual) = crate::stream_io::verified_file(&self.path(&blob.sha256)?, self.read_limit())?;
            if actual != *blob {
                return Err(Error::Integrity);
            }
        }
        Ok(blobs)
    }
    fn open_verified_stream(&self, sha256: &str) -> Result<Box<dyn Read + Send>, Error> {
        let (file, receipt) = crate::stream_io::verified_file(&self.path(sha256)?, self.read_limit())?;
        if receipt.sha256 != sha256 {
            return Err(Error::Integrity);
        }
        Ok(Box::new(file))
    }
    fn put_stream_if_absent(&mut self, sha256: &str, bytes: u64, reader: &mut dyn Read) -> Result<BlobReceipt, Error> {
        let target = self.path(sha256)?;
        if self.policy.is_none() || bytes > self.file_limit() {
            return Err(Error::Invalid("streaming file limit"));
        }
        let expected = BlobReceipt { sha256: sha256.into(), bytes };
        if target.try_exists()? {
            let (_, actual) = crate::stream_io::verified_file(&target, self.file_limit())?;
            if actual != expected {
                return Err(Error::Integrity);
            }
            return Ok(actual);
        }
        let (blobs, _, used) = self.scan()?;
        if blobs.len() >= MAX_VERSIONS || used.checked_add(bytes).is_none_or(|n| n > self.store_limit()) {
            return Err(Error::Invalid("blob storage quota"));
        }
        let pending = self.directory.join("pending");
        reject_links(&pending)?;
        let mut file = fs::OpenOptions::new().read(true).write(true).create_new(true).open(&pending)?;
        let result = (|| {
            if crate::stream_io::copy_hash(reader, &mut file, bytes)? != expected {
                return Err(Error::Integrity);
            }
            file.sync_all()?;
            // Re-read the actual private file before making it immutable/published.
            file.seek(SeekFrom::Start(0))?;
            if crate::stream_io::copy_hash(&mut file, &mut std::io::sink(), bytes)? != expected {
                return Err(Error::Integrity);
            }
            fs::hard_link(&pending, &target)?;
            #[cfg(unix)]
            fs::File::open(&self.directory)?.sync_all()?;
            Ok(expected)
        })();
        drop(file);
        let cleanup = fs::remove_file(&pending);
        let receipt = result?;
        // Publication is already complete. Retained pending bytes remain counted
        // by scan and block the next writer; do not misreport a lost publication.
        let _ = cleanup;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).expect("random test root");
            Self(std::env::temp_dir().join(format!("solidcraft-blob-test-{}", digest(&random))))
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn verified_roundtrip_deduplicates_and_reopens() {
        let root = TestRoot::new();
        let mut store = FsBlobStore::open(&root.0).unwrap();
        let hash = digest(b"saved native content");
        let first = store.put_verified_if_absent(&hash, b"saved native content").unwrap();
        assert_eq!(first, store.put_verified_if_absent(&hash, b"saved native content").unwrap());
        assert_eq!(store.inventory().unwrap(), vec![first]);
        assert_eq!(FsBlobStore::open(&root.0).unwrap().get_verified(&hash).unwrap(), b"saved native content");
    }

    #[test]
    fn rejects_mismatch_path_injection_and_oversize_without_publication() {
        let root = TestRoot::new();
        let mut store = FsBlobStore::open(&root.0).unwrap();
        assert!(store.put_verified_if_absent(&digest(b"other"), b"content").is_err());
        assert!(store.get_verified("../state.json").is_err());
        let oversized = vec![0; MAX_CONTENT + 1];
        assert!(store.put_verified_if_absent(&digest(&oversized), &oversized).is_err());
        assert!(store.inventory().unwrap().is_empty());
    }

    #[test]
    fn corrupt_existing_content_is_never_overwritten_or_backed_up() {
        let root = TestRoot::new();
        let mut store = FsBlobStore::open(&root.0).unwrap();
        let hash = digest(b"original");
        fs::write(store.directory.join(&hash), b"damaged").unwrap();
        assert!(store.put_verified_if_absent(&hash, b"original").is_err());
        assert!(store.get_verified(&hash).is_err());
        assert!(store.inventory().is_err());
        assert_eq!(fs::read(store.directory.join(hash)).unwrap(), b"damaged");
    }

    #[test]
    fn pending_recovery_is_explicit_and_unknown_files_fail_closed() {
        let root = TestRoot::new();
        let mut store = FsBlobStore::open(&root.0).unwrap();
        fs::write(store.directory.join("pending"), b"interrupted").unwrap();
        assert!(store.put_verified_if_absent(&digest(b"new"), b"new").is_err());
        assert_eq!(fs::read(store.directory.join("pending")).unwrap(), b"interrupted");
        fs::write(store.directory.join("unexpected"), b"untracked").unwrap();
        assert!(store.inventory().is_err());
    }

    #[test]
    fn inventory_count_is_bounded_even_for_empty_blobs() {
        let root = TestRoot::new();
        let store = FsBlobStore::open(&root.0).unwrap();
        for number in 0..=MAX_VERSIONS {
            fs::write(store.directory.join(digest(&number.to_le_bytes())), []).unwrap();
        }
        assert!(store.inventory().is_err());
        assert!(FsBlobStore::open(&root.0).is_err());
    }

    #[test]
    fn orphan_bytes_count_toward_storage_quota() {
        let root = TestRoot::new();
        let mut store = FsBlobStore::open(&root.0).unwrap();
        for number in 0..(MAX_STORED_CONTENT / MAX_CONTENT as u64) {
            let file = fs::File::create(store.directory.join(digest(&number.to_le_bytes()))).unwrap();
            file.set_len(MAX_CONTENT as u64).unwrap();
        }
        assert!(store.put_verified_if_absent(&digest(b"one more byte"), b"one more byte").is_err());
        assert!(!store.directory.join("pending").exists());
    }

    #[test]
    fn rejects_directory_in_place_of_blob() {
        let root = TestRoot::new();
        let mut store = FsBlobStore::open(&root.0).unwrap();
        let hash = digest(b"content");
        fs::create_dir(store.directory.join(&hash)).unwrap();
        assert!(store.put_verified_if_absent(&hash, b"content").is_err());
        assert!(store.inventory().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_static_symlink_blob_and_root() {
        use std::os::unix::fs::symlink;
        let root = TestRoot::new();
        let store = FsBlobStore::open(&root.0).unwrap();
        let hash = digest(b"target");
        let target = root.0.join("outside");
        fs::write(&target, b"target").unwrap();
        symlink(&target, store.directory.join(&hash)).unwrap();
        assert!(store.get_verified(&hash).is_err());
        assert!(store.inventory().is_err());
        let alias = root.0.join("alias");
        symlink(&root.0, &alias).unwrap();
        assert!(FsBlobStore::open(&alias).is_err());
    }
}
