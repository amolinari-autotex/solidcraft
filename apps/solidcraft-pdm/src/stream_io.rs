//! Fixed-buffer content verification. Inline JSON limits are intentionally separate.
use crate::{Error, blob_store::BlobReceipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
pub const BUFFER_BYTES: usize = 64 * 1024;
pub const HARD_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const HARD_STORE_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
pub(crate) const POLICY: &str = "stream-policy.json";
pub(crate) const PENDING: &str = "stream-policy.pending";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamPolicy {
    pub version: u32,
    pub max_file_bytes: u64,
    pub max_store_bytes: u64,
}
impl StreamPolicy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != 1
            || self.max_file_bytes == 0
            || self.max_file_bytes > HARD_FILE_BYTES
            || self.max_store_bytes < self.max_file_bytes
            || self.max_store_bytes > HARD_STORE_BYTES
        {
            return Err(Error::Invalid("stream policy"));
        }
        Ok(())
    }
    pub(crate) fn read(root: &Path) -> Result<Option<Self>, Error> {
        crate::reject_symlink_ancestors(root)?;
        if root.join(PENDING).try_exists()? {
            return Err(Error::Invalid("incomplete stream policy initialization"));
        }
        let path = root.join(POLICY);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                crate::reject_symlink_ancestors(&path)?;
                let policy: Self = serde_json::from_slice(&crate::client::read_file(&path, 1024)?)?;
                policy.validate()?;
                Ok(Some(policy))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Exactly one fixed buffer, independent of total file length. Readers with a
/// network origin must have their own deadline/cancellation bound.
pub fn copy_hash(reader: &mut dyn Read, writer: &mut dyn Write, limit: u64) -> Result<BlobReceipt, Error> {
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; BUFFER_BYTES];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes.checked_add(n as u64).ok_or(Error::Integrity)?;
        if bytes > limit {
            return Err(Error::Invalid("stream size limit"));
        }
        let data = buffer.get(..n).ok_or(Error::Integrity)?;
        hash.update(data);
        writer.write_all(data)?;
    }
    Ok(BlobReceipt { sha256: format!("{:x}", hash.finalize()), bytes })
}
pub fn verified_file(path: &Path, limit: u64) -> Result<(fs::File, BlobReceipt), Error> {
    crate::reject_symlink_ancestors(path)?;
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::Invalid("stream file limit"));
    }
    let receipt = copy_hash(&mut file, &mut std::io::sink(), limit)?;
    if receipt.bytes != metadata.len() {
        return Err(Error::Integrity);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((file, receipt))
}
pub(crate) fn copy_new(source: &Path, target: &Path, expected: &BlobReceipt, limit: u64) -> Result<(), Error> {
    crate::reject_symlink_ancestors(source)?;
    crate::reject_symlink_ancestors(target)?;
    let mut input = fs::File::open(source)?;
    if !input.metadata()?.is_file() || input.metadata()?.len() != expected.bytes || expected.bytes > limit {
        return Err(Error::Integrity);
    }
    let mut output = fs::OpenOptions::new().write(true).create_new(true).open(target)?;
    if copy_hash(&mut input, &mut output, limit)? != *expected {
        return Err(Error::Integrity);
    }
    output.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    struct Pattern {
        left: u64,
        max_read: usize,
    }
    impl Read for Pattern {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.max_read = self.max_read.max(buffer.len());
            let n = self.left.min(buffer.len() as u64) as usize;
            buffer.get_mut(..n).ok_or(std::io::ErrorKind::InvalidInput)?.fill(92);
            self.left -= n as u64;
            Ok(n)
        }
    }
    #[test]
    fn generated_large_source_never_receives_a_file_sized_buffer() {
        let length = 64 * 1024 * 1024 + 17;
        let mut source = Pattern { left: length, max_read: 0 };
        let receipt = copy_hash(&mut source, &mut std::io::sink(), length).unwrap();
        assert_eq!(receipt.bytes, length);
        assert_eq!(source.left, 0);
        assert_eq!(source.max_read, BUFFER_BYTES);
        let mut too_long = Pattern { left: length, max_read: 0 };
        assert!(copy_hash(&mut too_long, &mut std::io::sink(), length - 1).is_err());
        assert_eq!(too_long.max_read, BUFFER_BYTES);
    }
}
