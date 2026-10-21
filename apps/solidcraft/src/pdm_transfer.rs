//! Bounded negotiated transfer and private download staging for the native host.
#[cfg(test)]
#[path = "pdm_transfer_tests.rs"]
mod tests;
use super::*;
use solidcraft_pdm::{
    client::BinaryTransferSession,
    transfer_source::{FileSource, SourceError},
    transfers::{TransferCapabilities, TransferInput, TransferProgress, TransferTarget},
};
use std::{io::Write, sync::atomic::AtomicBool};

pub(super) fn source_failure(path: &Path, failure: SourceError) -> Failure {
    match failure {
        SourceError::TooLarge { actual_bytes, limit_bytes } => solidcraft_engine::pdm::FileFailure::FileSizeLimit {
            filename: path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default(),
            actual_bytes,
            limit_bytes,
        }
        .failure(),
        SourceError::Changed => fail("The source changed during transfer; the archive was not committed"),
        SourceError::Cancelled => fail("The transfer was cancelled"),
        _ => fail("The transfer source is unavailable or is not a regular file"),
    }
}

fn publication_id(
    caps: &TransferCapabilities,
    workspace: &str,
    target: &TransferTarget,
    bytes: u64,
    sha256: &str,
    dependencies: &[VersionRef],
) -> Result<String, Failure> {
    let identity = match target {
        TransferTarget::NewOnly { logical_path } => serde_json::json!({"new":logical_path}),
        TransferTarget::CheckIn { document, workspace, machine, parent, .. } => {
            serde_json::json!({"document":document,"workspace":workspace,"machine":machine,"parent":parent})
        }
    };
    Ok(hash(
        &serde_json::to_vec(&(
            "native-transfer/1",
            &caps.server_id,
            caps.recovery_epoch,
            &caps.principal.id,
            workspace,
            identity,
            bytes,
            sha256,
            dependencies,
        ))
        .map_err(|_| fail("Could not identify transfer"))?,
    ))
}
pub(super) fn upload(
    client: &Client,
    caps: &TransferCapabilities,
    path: &Path,
    target: TransferTarget,
    dependencies: Vec<VersionRef>,
    workspace: &str,
    expected_source: &solidcraft_pdm::transfer_source::SourceInfo,
) -> Result<solidcraft_pdm::managed::ManagedVersion, Failure> {
    let request_id = publication_id(caps, workspace, &target, expected_source.bytes, &expected_source.sha256, &dependencies)?;
    upload_with_request(client, caps, path, target, dependencies, workspace, expected_source, request_id, String::new())
}

/// Native design archives retain their graph-scoped receipt identity across transports.
#[allow(clippy::too_many_arguments)]
pub(super) fn upload_with_request(
    client: &Client,
    caps: &TransferCapabilities,
    path: &Path,
    target: TransferTarget,
    dependencies: Vec<VersionRef>,
    _workspace: &str,
    expected_source: &solidcraft_pdm::transfer_source::SourceInfo,
    request_id: String,
    comment: String,
) -> Result<solidcraft_pdm::managed::ManagedVersion, Failure> {
    if !caps.binary_transfer_v1 || !caps.can_upload {
        return Err(fail("This account cannot upload files"));
    }
    let limit = caps.limits.as_ref().ok_or_else(|| fail("The server did not advertise a file policy"))?.max_file_bytes;
    let cancel = AtomicBool::new(false);
    let mut source = FileSource::open(path, limit, &cancel).map_err(|failure| source_failure(path, failure))?;
    if source.info() != expected_source {
        return Err(fail("The intended source changed before transfer; nothing was published"));
    }
    // Do not negotiate or contact the server until the complete captured file fingerprint
    // is verified. The intended-source refusal must remain a purely local operation.
    let session = client.transfer_session_with_chunk_bytes(8 * 1024 * 1024).map_err(error)?;
    let mut chunk_bytes = session_chunk_bytes(&session, caps)?;
    if !session.capabilities().can_upload {
        return Err(fail("This account cannot upload files"));
    }
    let total = source.info().bytes;
    let sha256 = source.info().sha256.clone();
    let expected = target.clone();
    let expected_dependencies = dependencies.clone();
    let mut progress = session
        .begin_transfer(TransferInput {
            server_id: caps.server_id.clone(),
            recovery_epoch: caps.recovery_epoch,
            request_id: request_id.clone(),
            target,
            total_bytes: total,
            sha256: sha256.clone(),
            dependencies,
            comment,
        })
        .map_err(error)?;
    validate_progress(&progress, None, total, &sha256)?;
    if let Some(version) = progress.completed.take() {
        validate_publication(&version, caps, &expected, &request_id, &sha256, &expected_dependencies)?;
        return Ok(version);
    }
    while progress.offset < total {
        let offset = progress.offset;
        let mut floor_retried = false;
        loop {
            let chunk = source
                .read_chunk_with_limit(offset, chunk_bytes, &cancel)
                .map_err(|failure| source_failure(path, failure))?
                .ok_or_else(|| fail("Transfer source ended early"))?;
            let payload_bytes = chunk.content.len();
            let end = offset.checked_add(payload_bytes as u64).ok_or_else(|| fail("Invalid transfer offset"))?;
            let next = match session.upload_chunk(&progress.transfer_id, offset, &chunk.content, &chunk.sha256) {
                Ok(next) => next,
                Err(first) if recoverable_body_error(&first) => {
                    // Only authenticated durable status can authorize a smaller retry.
                    // A lost reply can also mean that this exact chunk was accepted.
                    let current = durable_status(&session, &progress.transfer_id, total, &sha256)?;
                    if current.offset == end {
                        current
                    } else if current.offset == offset && current.completed.is_none() {
                        // Shrink below the ACTUAL attempted payload, including a short tail:
                        // an attempted 2 MiB tail must not be resent at the 4 MiB ceiling.
                        if let Some(smaller) =
                            [4 * 1024 * 1024, 1024 * 1024, 256 * 1024, 64 * 1024].into_iter().find(|candidate| *candidate < payload_bytes)
                        {
                            chunk_bytes = smaller;
                            continue;
                        }
                        if !floor_retried {
                            floor_retried = true;
                            chunk_bytes = payload_bytes;
                            continue;
                        }
                        return Err(error(first));
                    } else {
                        return Err(fail(
                            "The transfer offset changed unexpectedly; publication is uncertain. Preserve the file and retry the same publication",
                        ));
                    }
                }
                Err(failure) => return Err(error(failure)),
            };
            validate_progress(&next, Some(&progress.transfer_id), total, &sha256)?;
            if next.offset != end {
                return Err(fail("Invalid chunk acknowledgement; publication is uncertain. Preserve the file and retry the same publication"));
            }
            if let Some(version) = &next.completed {
                validate_publication(version, caps, &expected, &request_id, &sha256, &expected_dependencies)?;
                return Ok(version.clone());
            }
            progress = next;
            break;
        }
    }
    let version = match session.commit_transfer(&progress.transfer_id, &request_id) {
        Ok(version) => version,
        Err(first) if recoverable_body_error(&first) => {
            let current = durable_status(&session, &progress.transfer_id, total, &sha256)?;
            if current.offset != total {
                return Err(fail("Transfer publication is uncertain; retry the same file to reconcile it"));
            }
            current.completed.ok_or_else(|| fail("Transfer publication is uncertain; retry the same file to reconcile it"))?
        }
        Err(failure) => return Err(error(failure)),
    };
    validate_publication(&version, caps, &expected, &request_id, &sha256, &expected_dependencies)?;
    Ok(version)
}

fn session_chunk_bytes(session: &BinaryTransferSession, captured: &TransferCapabilities) -> Result<usize, Failure> {
    let actual = session.capabilities();
    if !actual.binary_transfer_v1
        || actual.protocol != captured.protocol
        || actual.server_id != captured.server_id
        || actual.recovery_epoch != captured.recovery_epoch
        || actual.principal != captured.principal
    {
        return Err(fail("The transfer account or service changed; refresh before retrying"));
    }
    // Wire capabilities retain their legacy 1 MiB value. The verified session owns
    // the separately negotiated ceiling, so the two chunk fields must not be compared.
    usize::try_from(session.chunk_bytes())
        .ok()
        .filter(|size| (1..=8 * 1024 * 1024).contains(size))
        .ok_or_else(|| fail("Invalid negotiated transfer chunk size"))
}

fn recoverable_body_error(failure: &Error) -> bool {
    matches!(failure, Error::Network(_)) || matches!(failure, Error::Server(code) if code == "invalid_request")
}

fn validate_progress(progress: &TransferProgress, expected_id: Option<&str>, total: u64, sha256: &str) -> Result<(), Failure> {
    if progress.transfer_id.len() != 64
        || !progress.transfer_id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || expected_id.is_some_and(|id| progress.transfer_id != id)
        || progress.total_bytes != total
        || progress.sha256 != sha256
        || progress.offset > total
        || (progress.completed.is_some() && progress.offset != total)
    {
        return Err(fail("Transfer progress identity or hash changed; publication is uncertain. Preserve the file and retry the same publication"));
    }
    Ok(())
}

fn durable_status(session: &BinaryTransferSession, transfer_id: &str, total: u64, sha256: &str) -> Result<TransferProgress, Failure> {
    use std::time::{Duration, Instant};
    let started = Instant::now();
    let budget = Duration::from_secs(5);
    // A timed-out request body can still own the server's write guard. Poll only
    // busy/network reads, with one body in flight and a bounded retry/backoff budget.
    for delay in [50, 100, 200, 400, 800, 1000, 1000, 1000] {
        match session.transfer_status(transfer_id) {
            Ok(progress) => {
                validate_progress(&progress, Some(transfer_id), total, sha256)?;
                return Ok(progress);
            }
            Err(Error::Network(_)) => {}
            Err(Error::Server(code)) if code == "transfer_busy" => {}
            Err(failure) => return Err(error(failure)),
        }
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(Duration::from_millis(delay).min(remaining));
        if started.elapsed() >= budget {
            break;
        }
    }
    Err(fail("Transfer status remains uncertain; preserve the file and retry the same publication"))
}

fn validate_publication(
    version: &solidcraft_pdm::managed::ManagedVersion,
    caps: &TransferCapabilities,
    target: &TransferTarget,
    request: &str,
    sha256: &str,
    dependencies: &[VersionRef],
) -> Result<(), Failure> {
    let target_matches = match target {
        TransferTarget::NewOnly { .. } => version.version.parent.is_none(),
        TransferTarget::CheckIn { document, parent, .. } => version.version.reference.document == *document && version.version.parent == *parent,
    };
    if !target_matches
        || version.version.reference.version == 0
        || version.author != caps.principal.id
        || version.request_id != request
        || version.version.sha256 != sha256
        || version.version.dependencies != dependencies
    {
        return Err(fail("Transfer publication identity or hash mismatch"));
    }
    Ok(())
}

impl Host {
    pub(super) fn archive_attachment_stream(
        &mut self,
        client: &Client,
        ws: &mut Workspace,
        path: &str,
        logical_path: Option<&str>,
        reconcile: bool,
        caps: &TransferCapabilities,
    ) -> Result<(Outcome, Option<Box<Session>>), Failure> {
        let absolute = fs::canonicalize(path).map_err(|_| fail("The managed file is unavailable"))?;
        let relative = absolute
            .strip_prefix(ws.root())
            .map_err(|_| fail("Save the file inside the configured working folder before archiving"))?
            .to_string_lossy()
            .replace('\\', "/");
        if logical_path.is_some_and(|value| !value.is_empty() && value != relative) {
            return Err(fail("The archive path must match its immutable working-folder path"));
        }
        let (document, local) = ws
            .manifest()
            .documents
            .iter()
            .find(|(_, local)| local.relative_path == relative)
            .map(|(document, local)| (document.clone(), local.clone()))
            .ok_or_else(|| fail("The attachment must have a managed working copy before checking in"))?;
        let history = client.managed_history(document.clone()).map_err(error)?;
        let dependencies = history
            .iter()
            .find(|version| version.version.reference.version == local.base_version)
            .ok_or_else(|| fail("The attachment base version is missing"))?
            .version
            .dependencies
            .clone();
        let limit = caps.limits.as_ref().ok_or_else(|| fail("Missing server file policy"))?.max_file_bytes;
        let source = FileSource::open(&absolute, limit, &AtomicBool::new(false)).map_err(|failure| source_failure(&absolute, failure))?;
        let mut acknowledged = None;
        for version in history {
            let pending_base = version.version.parent == Some(local.base_version);
            let completed_base =
                !local.checked_out && version.version.reference.version == local.base_version && version.version.sha256 == local.base_sha256;
            if !(pending_base || completed_base)
                || version.author != caps.principal.id
                || version.version.sha256 != source.info().sha256
                || version.version.dependencies != dependencies
            {
                continue;
            }
            let target = TransferTarget::CheckIn {
                document: document.clone(),
                workspace: ws.manifest().workspace_id.clone(),
                machine: self.machine.clone(),
                checkout_token: String::new(),
                parent: version.version.parent,
            };
            let request = publication_id(caps, &ws.manifest().workspace_id, &target, source.info().bytes, &source.info().sha256, &dependencies)?;
            if version.request_id == request {
                acknowledged = Some(version);
                break;
            }
        }
        let published = if let Some(version) = acknowledged {
            let catalog = client.managed_catalog().map_err(error)?;
            if catalog.entries.iter().find(|entry| entry.document == document).and_then(|entry| entry.head) != Some(version.version.reference.version)
            {
                return Err(fail("A newer archived version exists; preserve your changes and refresh"));
            }
            version
        } else {
            if reconcile {
                return Err(fail("No matching publication receipt exists; nothing was published"));
            }
            if !local.checked_out {
                return Err(fail("Check out this managed file before archiving changes"));
            }
            let grant = self.verified_grant(client, ws, &document, Some(local.base_version))?;
            upload(
                client,
                caps,
                &absolute,
                TransferTarget::CheckIn {
                    document: document.clone(),
                    workspace: ws.manifest().workspace_id.clone(),
                    machine: self.machine.clone(),
                    checkout_token: grant.token,
                    parent: Some(local.base_version),
                },
                dependencies,
                &ws.manifest().workspace_id,
                source.info(),
            )?
        };
        if local.checked_out {
            ws.record_checkin(&document, published.version.reference.version, &published.version.sha256).map_err(error)?;
        } else if local.base_version != published.version.reference.version || local.base_sha256 != published.version.sha256 {
            return Err(fail("The local publication receipt changed; recover the working folder"));
        }
        self.grants.remove(&document);
        Ok((Outcome::Managed { port: self.port, state: self.state(ws, Some(&document))? }, None))
    }
}

pub(super) struct Download {
    pub path: PathBuf,
    pub version: solidcraft_pdm::Version,
    pub bytes: u64,
}
impl Download {
    pub fn reader(&self) -> Result<fs::File, Failure> {
        crate::pdm_connections::guard_workspace_path(&self.path).map_err(|_| fail("Unsafe download staging path"))?;
        fs::File::open(&self.path).map_err(|_| fail("Private download is unavailable"))
    }
    pub fn install(&self, ws: &mut Workspace, relative: &str) -> Result<(), Failure> {
        ws.install_stream(
            &self.version.reference.document,
            relative,
            self.version.reference.version,
            &self.version.sha256,
            self.bytes,
            &mut self.reader()?,
        )
        .map_err(error)
    }
}
impl Drop for Download {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
pub(super) fn download(client: &Client, ws: &Workspace, reference: &VersionRef) -> Result<Download, Failure> {
    let metadata = ws.root().join(".solidcraft-pdm");
    crate::pdm_connections::guard_workspace_path(&metadata).map_err(|_| fail("Unsafe download staging folder"))?;
    let path = metadata.join(format!("download-{}", AuthToken::generate().map_err(error)?));
    let mut output =
        fs::OpenOptions::new().create_new(true).write(true).open(&path).map_err(|_| fail("Could not create private download staging"))?;
    let result = (|| {
        let version = if let Some(caps) = client.transfer_capabilities().map_err(error)?.filter(|caps| caps.binary_transfer_v1) {
            let session = client.transfer_session_with_chunk_bytes(8 * 1024 * 1024).map_err(error)?;
            session_chunk_bytes(&session, &caps)?;
            session.download_stream(reference, &mut output).map_err(error)?
        } else {
            let (version, bytes) = client.download(reference).map_err(error)?;
            if bytes.len() > solidcraft_pdm::MAX_CONTENT || hash(&bytes) != version.sha256 {
                return Err(fail("Download integrity verification failed"));
            }
            output.write_all(&bytes).map_err(|_| fail("Could not write private download staging"))?;
            version
        };
        output.sync_all().map_err(|_| fail("Could not sync private download staging"))?;
        let bytes = output.metadata().map_err(|_| fail("Download staging is unavailable"))?.len();
        if version.reference != *reference {
            return Err(fail("Download identity mismatch"));
        }
        Ok((version, bytes))
    })();
    drop(output);
    match result {
        Ok((version, bytes)) => Ok(Download { path, version, bytes }),
        Err(failure) => {
            let _ = fs::remove_file(path);
            Err(failure)
        }
    }
}

pub(super) fn copy_source_new(source: &Path, destination: &Path, limit: u64) -> Result<(u64, String), Failure> {
    let cancel = AtomicBool::new(false);
    let mut source_file = FileSource::open(source, limit, &cancel).map_err(|failure| source_failure(source, failure))?;
    let total = source_file.info().bytes;
    let expected = source_file.info().sha256.clone();
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|_| fail("The destination already exists; nothing was overwritten"))?;
    let mut offset = 0;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    while let Some(chunk) = source_file.read_chunk(offset, &cancel).map_err(|failure| source_failure(source, failure))? {
        output.write_all(&chunk.content).map_err(|_| fail("Could not complete the new local copy"))?;
        hasher.update(&chunk.content);
        offset += chunk.content.len() as u64;
    }
    if offset != total || format!("{:x}", hasher.finalize()) != expected {
        return Err(fail("The source changed while being copied"));
    }
    output.sync_all().map_err(|_| fail("Could not sync the new local copy"))?;
    Ok((total, expected))
}
