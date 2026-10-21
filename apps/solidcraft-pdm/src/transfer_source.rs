//! Read-only bounded source for a future negotiated binary transport.
//! This does not enable uploads, change legacy limits or advertise a capability.
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata},
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::SystemTime,
};

pub const CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("invalid transfer source: {0}")]
    Invalid(&'static str),
    #[error("file has {actual_bytes} bytes; limit is {limit_bytes} bytes")]
    TooLarge { actual_bytes: u64, limit_bytes: u64 },
    #[error("source changed during transfer")]
    Changed,
    #[error("transfer cancelled")]
    Cancelled,
    #[error("could not read transfer source: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub struct SourceInfo {
    pub bytes: u64,
    pub sha256: String,
}

pub struct SourceChunk {
    pub offset: u64,
    pub content: Vec<u8>,
    pub sha256: String,
}

pub struct FileSource {
    file: File,
    info: SourceInfo,
    modified: Option<SystemTime>,
}

impl std::fmt::Debug for FileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSource").field("info", &self.info).finish_non_exhaustive()
    }
}

impl std::fmt::Debug for SourceChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceChunk").field("offset", &self.offset).field("bytes", &self.content.len()).field("sha256", &self.sha256).finish()
    }
}

fn cancelled(cancel: &AtomicBool) -> Result<(), SourceError> {
    if cancel.load(Ordering::Relaxed) { Err(SourceError::Cancelled) } else { Ok(()) }
}

fn reject_links(path: &Path) -> Result<(), SourceError> {
    if !path.is_absolute() {
        return Err(SourceError::Invalid("absolute source path required"));
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() {
            return Err(SourceError::Invalid("source links are not supported"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(SourceError::Invalid("source reparse points are not supported"));
            }
        }
    }
    Ok(())
}

impl FileSource {
    pub fn open(path: &Path, limit: u64, cancel: &AtomicBool) -> Result<Self, SourceError> {
        cancelled(cancel)?;
        if limit == 0 {
            return Err(SourceError::Invalid("a finite positive file policy is required"));
        }
        reject_links(path)?;
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(SourceError::Invalid("regular source file required"));
        }
        let bytes = metadata.len();
        if bytes > limit {
            return Err(SourceError::TooLarge { actual_bytes: bytes, limit_bytes: limit });
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut remaining = bytes;
        while remaining > 0 {
            cancelled(cancel)?;
            let count = remaining.min(buffer.len() as u64) as usize;
            let buffer = buffer.get_mut(..count).ok_or(SourceError::Changed)?;
            let read = file.read(buffer)?;
            if read == 0 {
                return Err(SourceError::Changed);
            }
            hash.update(buffer.get(..read).ok_or(SourceError::Changed)?);
            remaining -= read as u64;
        }
        cancelled(cancel)?;
        if file.read(&mut [0])? != 0 {
            return Err(SourceError::Changed);
        }
        let info = SourceInfo { bytes, sha256: format!("{:x}", hash.finalize()) };
        let mut source = Self { file, info, modified: metadata.modified().ok() };
        source.check_metadata(&source.file.metadata()?)?;
        source.file.seek(SeekFrom::Start(0))?;
        Ok(source)
    }
    pub fn info(&self) -> &SourceInfo {
        &self.info
    }
    fn check_metadata(&self, metadata: &Metadata) -> Result<(), SourceError> {
        if !metadata.is_file() || metadata.len() != self.info.bytes || metadata.modified().ok() != self.modified {
            Err(SourceError::Changed)
        } else {
            Ok(())
        }
    }
    /// Offset comes from an authenticated, session-bound durable receipt.
    /// Caller must retain the full source digest for the server's final seal.
    pub fn read_chunk(&mut self, offset: u64, cancel: &AtomicBool) -> Result<Option<SourceChunk>, SourceError> {
        self.read_chunk_with_limit(offset, CHUNK_BYTES, cancel)
    }
    pub fn read_chunk_with_limit(&mut self, offset: u64, chunk_bytes: usize, cancel: &AtomicBool) -> Result<Option<SourceChunk>, SourceError> {
        if chunk_bytes == 0 || chunk_bytes > MAX_CHUNK_BYTES {
            return Err(SourceError::Invalid("invalid bounded chunk size"));
        }
        cancelled(cancel)?;
        self.check_metadata(&self.file.metadata()?)?;
        let remaining = self.info.bytes.checked_sub(offset).ok_or(SourceError::Invalid("source offset exceeds file size"))?;
        if remaining == 0 {
            return Ok(None);
        }
        let mut content = vec![0; remaining.min(chunk_bytes as u64) as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file
            .read_exact(&mut content)
            .map_err(|error| if error.kind() == std::io::ErrorKind::UnexpectedEof { SourceError::Changed } else { SourceError::Io(error) })?;
        cancelled(cancel)?;
        self.check_metadata(&self.file.metadata()?)?;
        let sha256 = crate::digest(&content);
        Ok(Some(SourceChunk { offset, content, sha256 }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, sync::atomic::Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(content: &[u8]) -> Self {
            let root = std::env::temp_dir().join(format!("pdm-transfer-source-{}", crate::AuthToken::generate().unwrap()));
            fs::create_dir(&root).unwrap();
            fs::write(root.join("source.opaque"), content).unwrap();
            Self(root)
        }
        fn path(&self) -> PathBuf {
            self.0.join("source.opaque")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for name in ["source.opaque", "original.opaque"] {
                let _ = fs::remove_file(self.0.join(name));
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn transfer_source_negotiated_chunks_preserve_legacy_and_enforce_eight_mib_bound() {
        let fixture = Fixture::new(&vec![b'Z'; MAX_CHUNK_BYTES + 73]);
        let cancel = AtomicBool::new(false);
        let mut source = FileSource::open(&fixture.path(), (MAX_CHUNK_BYTES + 73) as u64, &cancel).unwrap();
        assert_eq!(source.read_chunk(0, &cancel).unwrap().unwrap().content.len(), CHUNK_BYTES);
        for size in [CHUNK_BYTES, 4 * CHUNK_BYTES, MAX_CHUNK_BYTES] {
            let chunk = source.read_chunk_with_limit(0, size, &cancel).unwrap().unwrap();
            assert_eq!(chunk.content.len(), size, "use the negotiated chunk size");
            assert!(chunk.content.iter().all(|byte| *byte == b'Z'));
            let tail = source.read_chunk_with_limit(MAX_CHUNK_BYTES as u64, size, &cancel).unwrap().unwrap();
            assert_eq!(tail.content, vec![b'Z'; 73]);
            assert!(source.read_chunk_with_limit((MAX_CHUNK_BYTES + 73) as u64, size, &cancel).unwrap().is_none());
        }
        for invalid in [0, MAX_CHUNK_BYTES + 1, usize::MAX] {
            assert!(matches!(source.read_chunk_with_limit(0, invalid, &cancel), Err(SourceError::Invalid("invalid bounded chunk size"))));
        }
    }

    #[test]
    fn transfer_source_streams_129mb_without_legacy_inline_limit_and_supports_resume_offsets() {
        let fixture = Fixture::new(&vec![b'Z'; 1_290_000]);
        let cancel = AtomicBool::new(false);
        let mut source = FileSource::open(&fixture.path(), 1_290_000, &cancel).unwrap();
        assert_eq!(source.info().bytes, 1_290_000);
        assert_eq!(source.info().sha256, "5d04569a93eb9592cda3e75bbf303b9348192f8c49425091c4393f4529025e28");
        let first = source.read_chunk(0, &cancel).unwrap().unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(first.content, vec![b'Z'; 1_048_576]);
        assert_eq!(first.sha256, "bf63d8a95fcc2e64619813aae35fdcbe871fdd9264caa3f365eb3aed0f679129");
        let resumed = source.read_chunk(1_048_576, &cancel).unwrap().unwrap();
        assert_eq!(resumed.offset, 1_048_576);
        assert_eq!(resumed.content, vec![b'Z'; 241_424]);
        assert_eq!(resumed.sha256, "7cd56a3c0e2cede3f0b8c1120ee2c2c5c0b53e338ceb393f811c4ce8bcb2e3f0");
        assert!(source.read_chunk(1_290_000, &cancel).unwrap().is_none());
        assert!(matches!(source.read_chunk(1_290_001, &cancel), Err(SourceError::Invalid(_))));
        assert_eq!(fs::read(fixture.path()).unwrap(), vec![b'Z'; 1_290_000]);
    }

    #[test]
    fn transfer_source_rejects_policy_limit_and_cancellation_without_writing_source() {
        let fixture = Fixture::new(b"123456789");
        let cancel = AtomicBool::new(false);
        assert!(matches!(FileSource::open(&fixture.path(), 8, &cancel), Err(SourceError::TooLarge { actual_bytes: 9, limit_bytes: 8 })));
        let mut source = FileSource::open(&fixture.path(), 9, &cancel).unwrap();
        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(source.read_chunk(0, &cancel), Err(SourceError::Cancelled)));
        assert!(matches!(FileSource::open(&fixture.path(), 9, &cancel), Err(SourceError::Cancelled)));
        assert_eq!(fs::read(fixture.path()).unwrap(), b"123456789");
    }

    #[test]
    fn transfer_source_rejects_mutated_bytes_before_sending_a_chunk() {
        let fixture = Fixture::new(b"original");
        let cancel = AtomicBool::new(false);
        let mut source = FileSource::open(&fixture.path(), 64, &cancel).unwrap();
        fs::write(fixture.path(), b"modified").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(fixture.path())
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();
        assert!(matches!(source.read_chunk(0, &cancel), Err(SourceError::Changed)));
        assert_eq!(fs::read(fixture.path()).unwrap(), b"modified");
    }

    #[test]
    fn transfer_source_keeps_original_open_handle_when_path_is_replaced() {
        let fixture = Fixture::new(b"original");
        let cancel = AtomicBool::new(false);
        let mut source = FileSource::open(&fixture.path(), 64, &cancel).unwrap();
        fs::rename(fixture.path(), fixture.0.join("original.opaque")).unwrap();
        fs::write(fixture.path(), b"replaced").unwrap();
        let chunk = source.read_chunk(0, &cancel).unwrap().unwrap();
        assert_eq!(chunk.content, b"original");
        assert_eq!(fs::read(fixture.path()).unwrap(), b"replaced");
    }
}
