//! Exclusive new-file import. Existing local/server targets are never reused.
use super::*;
use std::io::Write;

fn regular(path: &Path) -> Result<fs::Metadata, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|_| fail("The import source is unavailable"))?;
    if metadata.file_type().is_symlink() {
        return Err(fail("Import links are not supported"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(fail("Import reparse points are not supported"));
        }
    }
    Ok(metadata)
}

fn relative(source: &Path, folder: &str) -> Result<String, Failure> {
    let name = source.file_name().and_then(|name| name.to_str()).ok_or_else(|| fail("Invalid import filename"))?;
    let relative = if folder.is_empty() { name.into() } else { format!("{folder}/{name}") };
    solidcraft_pdm::managed::validate_logical_path(&relative).map_err(error)?;
    if relative.split('/').any(|part| part.eq_ignore_ascii_case(".solidcraft-pdm")) {
        return Err(fail("The private workspace metadata folder cannot receive imports"));
    }
    Ok(relative)
}

fn destination(root: &Path, folder: &str, relative: &str) -> Result<PathBuf, Failure> {
    let mut parent = root.to_path_buf();
    for part in folder.split('/').filter(|part| !part.is_empty()) {
        parent.push(part);
        match fs::create_dir(&parent) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(fail("Could not create the selected import folder")),
        }
        if !regular(&parent)?.is_dir() {
            return Err(fail("The selected import folder is not a directory"));
        }
        if !fs::canonicalize(&parent).map_err(|_| fail("Import folder unavailable"))?.starts_with(root) {
            return Err(fail("The selected import folder is outside the working folder"));
        }
    }
    let path = root.join(relative);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
        _ => Err(fail("A local file or directory already exists at the import destination; nothing was overwritten")),
    }
}

fn copy_new(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| fail("The import destination already exists or cannot be created; nothing was overwritten"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| fail(&format!("Could not finish the new local copy at {}; the source was preserved", path.display())))
}

fn import_bytes(source: &Path, limit: usize) -> Result<Vec<u8>, Failure> {
    let size_failure = |actual_bytes| {
        solidcraft_engine::pdm::FileFailure::FileSizeLimit {
            filename: source.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default(),
            actual_bytes,
            limit_bytes: limit as u64,
        }
        .failure()
    };
    let metadata = regular(source)?;
    if metadata.len() > limit as u64 {
        return Err(size_failure(metadata.len()));
    }
    read_file(source, limit).map_err(|failure| match failure {
        Error::Invalid("source exceeds size limit") => {
            size_failure(fs::metadata(source).map(|metadata| metadata.len()).unwrap_or(limit as u64 + 1).max(limit as u64 + 1))
        }
        other => error(other),
    })
}

impl Host {
    pub(super) fn import_new(
        &mut self,
        source_path: String,
        folder: String,
        expected_workspace: String,
    ) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        let client = self.client()?;
        let mut ws = self.workspace()?;
        if ws.manifest().workspace_id != expected_workspace {
            return Err(fail("The working-folder context changed; retry the import in the current archive"));
        }
        let source = Path::new(&source_path);
        if !source.is_absolute() || !regular(source)?.is_file() {
            return Err(fail("Choose a regular file to import"));
        }
        let relative = relative(source, &folder)?;
        if let Some(caps) = client.transfer_capabilities().map_err(error)?.filter(|caps| caps.binary_transfer_v1) {
            return self.import_streamed(&client, &mut ws, source, &folder, &relative, caps);
        }
        let catalog = client.managed_catalog().map_err(error)?;
        if catalog.server_id != self.server_id {
            return Err(fail("The service identity changed; reconnect before importing"));
        }
        if catalog.entries.iter().any(|entry| entry.logical_path.eq_ignore_ascii_case(&relative)) {
            return Err(fail("This archive path already exists; importing a new file never overwrites an archived document"));
        }
        let bytes = import_bytes(source, solidcraft_pdm::MAX_CONTENT)?;
        if source.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| extension.eq_ignore_ascii_case("solidcraft")) {
            let document = solidcraft_engine::io::read_design(&bytes).map_err(|_| fail("The native design is corrupt or unsupported"))?;
            if !document.links.is_empty() {
                return Err(fail(
                    "Import linked native assemblies through their complete working-folder graph; a single-file drop cannot safely relocate their components",
                ));
            }
        }
        let destination = destination(ws.root(), &folder, &relative)?;
        copy_new(&destination, &bytes)?;
        let published = (|| {
            let entry = client.managed_create_new(relative.clone()).map_err(error)?;
            if entry.head.is_some() || entry.checkout.is_some() {
                return Err(fail("The exclusive import did not create a new empty document"));
            }
            let grant = client.managed_checkout(entry.document.clone(), expected_workspace.clone(), self.machine.clone()).map_err(error)?;
            self.grants.insert(entry.document.clone(), grant.clone());
            let request_id = hash(
                &serde_json::to_vec(&(expected_workspace.clone(), entry.document.clone(), hash(&bytes)))
                    .map_err(|_| fail("Could not identify the import"))?,
            );
            let version = client
                .managed_check_in(ManagedCheckIn {
                    document: entry.document.clone(),
                    workspace: expected_workspace,
                    machine: self.machine.clone(),
                    checkout_token: grant.token,
                    request_id,
                    parent: None,
                    content: bytes,
                    dependencies: Vec::new(),
                    comment: String::new(),
                })
                .map_err(error)?;
            self.grants.remove(&entry.document);
            ws.adopt(&entry.document, &relative, version.version.reference.version, &version.version.sha256).map_err(error)?;
            self.state(&ws, Some(&entry.document))
        })()
        .map_err(|failure: Failure| {
            fail(&format!("Import did not complete. The new local copy remains at {}: {}", destination.display(), failure.message))
        })?;
        Ok((Outcome::Managed { port: self.port, state: published }, None))
    }

    fn import_streamed(
        &self,
        client: &Client,
        ws: &mut Workspace,
        source: &Path,
        folder: &str,
        relative: &str,
        caps: solidcraft_pdm::transfers::TransferCapabilities,
    ) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        use solidcraft_pdm::{transfer_source::FileSource, transfers::TransferTarget};
        use std::sync::atomic::AtomicBool;
        if caps.server_id != self.server_id || !caps.can_upload {
            return Err(fail("This account cannot import files into this archive"));
        }
        let limit = caps.limits.as_ref().ok_or_else(|| fail("The server did not advertise a file policy"))?.max_file_bytes;
        // Native parsing retains the format's own finite bound, independently
        // of the negotiated binary transport and its legacy inline limit.
        if is_native_design(source) {
            let bytes = import_bytes(source, limit.min(solidcraft_engine::io::MAX_DESIGN_BYTES as u64) as usize)?;
            let design = solidcraft_engine::io::read_design(&bytes).map_err(|_| fail("The native design is corrupt or unsupported"))?;
            if !design.links.is_empty() {
                return Err(fail("Import linked assemblies through their complete working-folder graph"));
            }
        }
        let verified =
            FileSource::open(source, limit, &AtomicBool::new(false)).map_err(|failure| super::transfer::source_failure(source, failure))?;
        let binding = serde_json::to_vec(&(
            "native-import/1",
            &caps.server_id,
            caps.recovery_epoch,
            &caps.principal.id,
            &ws.manifest().workspace_id,
            relative,
            verified.info().bytes,
            &verified.info().sha256,
        ))
        .map_err(|_| fail("Could not identify the import"))?;
        let receipt = ws.root().join(".solidcraft-pdm").join(format!("import-{}.json", hash(&binding)));
        crate::pdm_connections::guard_workspace_path(&receipt).map_err(|_| fail("Unsafe import receipt path"))?;
        let resumed = receipt.try_exists().map_err(|_| fail("Import receipt unavailable"))?;
        let catalog = client.managed_catalog().map_err(error)?;
        if catalog.server_id != self.server_id {
            return Err(fail("The service identity changed; reconnect before importing"));
        }
        if !resumed && catalog.entries.iter().any(|entry| entry.logical_path.eq_ignore_ascii_case(relative)) {
            return Err(fail("This archive path already exists; nothing was overwritten"));
        }
        let local = if resumed {
            if read_file(&receipt, 4096).map_err(error)? != binding {
                return Err(fail("Import receipt mismatch"));
            }
            let local = ws.root().join(relative);
            if local.try_exists().map_err(|_| fail("Import destination unavailable"))? {
                let copy =
                    FileSource::open(&local, limit, &AtomicBool::new(false)).map_err(|failure| super::transfer::source_failure(&local, failure))?;
                if copy.info() != verified.info() {
                    return Err(fail("The pending import copy changed; preserve it before retrying"));
                }
            } else {
                let local = destination(ws.root(), folder, relative)?;
                let copied = super::transfer::copy_source_new(source, &local, limit)?;
                if copied != (verified.info().bytes, verified.info().sha256.clone()) {
                    return Err(fail("The import source changed before copying; nothing was published"));
                }
            }
            local
        } else {
            let local = destination(ws.root(), folder, relative)?;
            copy_new(&receipt, &binding)?;
            let copied = super::transfer::copy_source_new(source, &local, limit)?;
            if copied != (verified.info().bytes, verified.info().sha256.clone()) {
                return Err(fail("The import source changed before copying; nothing was published"));
            }
            local
        };
        let published = super::transfer::upload(
            client,
            &caps,
            &local,
            TransferTarget::NewOnly { logical_path: relative.into() },
            vec![],
            &ws.manifest().workspace_id,
            verified.info(),
        )?;
        if published.version.sha256 != verified.info().sha256 {
            return Err(fail("Import publication hash mismatch"));
        }
        ws.adopt(&published.version.reference.document, relative, published.version.reference.version, &published.version.sha256).map_err(error)?;
        // Keep the immutable intent so a lost completion can reconcile this exact
        // publication; it contains no credentials and cannot authorize an overwrite.
        Ok((Outcome::Managed { port: self.port, state: self.state(ws, Some(&published.version.reference.document))? }, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn import_new_copy_is_exclusive_and_rejects_metadata_or_traversal() {
        let root = std::env::temp_dir().join(format!("solidcraft-import-new-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        assert!(relative(Path::new("manual.pdf"), "../escape").is_err());
        assert!(relative(Path::new("manual.pdf"), ".solidcraft-pdm").is_err());
        let path = destination(&root, "Parts", "Parts/manual.pdf").unwrap();
        copy_new(&path, b"original").unwrap();
        assert!(copy_new(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert!(destination(&root, "Parts", "Parts/manual.pdf").is_err());
        fs::remove_file(path).unwrap();
        fs::remove_dir(root.join("Parts")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
