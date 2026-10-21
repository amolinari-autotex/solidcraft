//! Verify a bounded dependency closure before publishing a new local snapshot.
use crate::{Error, MAX_CONTENT, MAX_STORED_CONTENT, MAX_VERSIONS, Version, VersionRef, digest, valid_id};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub format: String,
    pub root: VersionRef,
    pub versions: Vec<Version>,
}

/// Every version has its own namespace: two versions of a part cannot collide.
pub fn content_path(reference: &VersionRef) -> Result<PathBuf, Error> {
    validate_reference(reference)?;
    Ok(PathBuf::from(format!("documents/d-{}/v-{}/content", reference.document, reference.version)))
}

fn validate_reference(reference: &VersionRef) -> Result<(), Error> {
    if !valid_id(&reference.document) || reference.version == 0 {
        return Err(Error::Invalid("invalid snapshot reference"));
    }
    Ok(())
}

pub fn retrieve(
    root: VersionRef,
    destination: &Path,
    fetch: impl FnMut(&VersionRef) -> Result<(Version, Vec<u8>), Error>,
) -> Result<Snapshot, Error> {
    retrieve_with_writer(root, destination, fetch, write_new)
}

fn retrieve_with_writer(
    root: VersionRef,
    destination: &Path,
    mut fetch: impl FnMut(&VersionRef) -> Result<(Version, Vec<u8>), Error>,
    mut write: impl FnMut(&Path, &[u8]) -> Result<(), Error>,
) -> Result<Snapshot, Error> {
    validate_reference(&root)?;
    // Early feedback only; create_dir below is the authoritative no-overwrite check.
    if destination.try_exists()? {
        return Err(Error::Invalid("destination already exists"));
    }
    let mut nodes = BTreeMap::<VersionRef, (Version, Vec<u8>)>::new();
    let mut pending = vec![root.clone()];
    let mut total = 0u64;
    while let Some(reference) = pending.pop() {
        validate_reference(&reference)?;
        if nodes.contains_key(&reference) {
            continue;
        }
        if nodes.len() >= MAX_VERSIONS {
            return Err(Error::Invalid("snapshot version limit"));
        }
        let (metadata, content) = fetch(&reference)?;
        if metadata.reference != reference || content.len() > MAX_CONTENT || digest(&content) != metadata.sha256 {
            return Err(Error::Integrity);
        }
        if metadata.dependencies.len() > 256 {
            return Err(Error::Invalid("snapshot dependency limit"));
        }
        let unique: BTreeSet<_> = metadata.dependencies.iter().collect();
        if unique.len() != metadata.dependencies.len() {
            return Err(Error::Invalid("duplicate dependency"));
        }
        total = total.checked_add(content.len() as u64).ok_or(Error::Invalid("snapshot size limit"))?;
        if total > MAX_STORED_CONTENT {
            return Err(Error::Invalid("snapshot size limit"));
        }
        for dependency in &metadata.dependencies {
            validate_reference(dependency)?;
        }
        pending.extend(metadata.dependencies.iter().cloned());
        nodes.insert(reference, (metadata, content));
    }
    // Iterative DFS distinguishes a shared dependency from a cycle, without recursion.
    let mut active = BTreeSet::new();
    let mut done = BTreeSet::new();
    let mut stack = vec![(root.clone(), false)];
    while let Some((reference, leaving)) = stack.pop() {
        if leaving {
            active.remove(&reference);
            done.insert(reference);
            continue;
        }
        if done.contains(&reference) {
            continue;
        }
        if !active.insert(reference.clone()) {
            return Err(Error::Invalid("cyclic dependency graph"));
        }
        let (metadata, _) = nodes.get(&reference).ok_or(Error::NotFound)?;
        stack.push((reference, true));
        stack.extend(metadata.dependencies.iter().cloned().map(|reference| (reference, false)));
    }
    let snapshot = Snapshot { format: "solidcraft-pdm-snapshot/1".into(), root, versions: nodes.values().map(|(v, _)| v.clone()).collect() };
    // This directory must be NEW. Existing files, directories and symlinks are never replaced.
    // All network validation has finished before any local destination is created.
    fs::create_dir(destination)?;
    let result = (|| {
        let staging = destination.join(".pending");
        fs::create_dir(&staging)?;
        for (reference, (_, content)) in &nodes {
            let path = staging.join(content_path(reference)?);
            fs::create_dir_all(path.parent().ok_or(Error::Invalid("snapshot path"))?)?;
            write(&path, content)?;
        }
        write(&staging.join("snapshot.json"), &serde_json::to_vec_pretty(&snapshot)?)?;
        // Publish exactly one child in our newly owned directory. Unlike renaming onto the
        // caller's destination, this cannot replace a pre-existing empty directory on Unix.
        fs::rename(&staging, destination.join("snapshot"))?;
        Ok(())
    })();
    if let Err(error) = result {
        // Only the directory created by this invocation is disposable, never its parent.
        // A cleanup failure may leave an unpublished .pending directory, never a success.
        let _ = fs::remove_dir_all(destination);
        return Err(error);
    }
    Ok(snapshot)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_disk_failure_does_not_publish_or_remove_siblings() -> Result<(), Error> {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| Error::Invalid("test clock"))?.as_nanos();
        let parent = std::env::temp_dir().join(format!("solidcraft-pdm-write-{}-{stamp}", std::process::id()));
        fs::create_dir(&parent)?;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(parent.clone());
        fs::write(parent.join("keep"), b"keep")?;
        let destination = parent.join("new");
        let reference = VersionRef { document: "part".into(), version: 1 };
        let version = Version { reference: reference.clone(), parent: None, sha256: digest(b"toy"), dependencies: vec![] };
        let mut writes = 0;
        let result = retrieve_with_writer(
            reference,
            &destination,
            |_| Ok((version.clone(), b"toy".to_vec())),
            |path, bytes| {
                assert!(path.starts_with(&destination));
                writes += 1;
                if writes == 2 {
                    return Err(std::io::Error::other("injected disk failure").into());
                }
                write_new(path, bytes)
            },
        );
        assert!(result.is_err());
        assert_eq!(writes, 2);
        assert!(!destination.exists());
        assert_eq!(fs::read(parent.join("keep"))?, b"keep");
        Ok(())
    }
}
