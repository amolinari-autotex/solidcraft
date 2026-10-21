//! Authenticated document fences around durable byte staging. No file body is
//! decoded as JSON; only small controls and receipt fingerprints enter redb.
use super::*;
use crate::{
    transfer_staging::{Binding, Limits, Stager, TransferError},
    transfers::{ContentMetadata, TransferCapabilities, TransferInput, TransferProgress, TransferTarget},
};
use std::{
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};

#[derive(PartialEq, Eq)]
struct StagerContext {
    root: std::path::PathBuf,
    server_id: String,
    epoch: u64,
    limits: Limits,
}

/// Valid only under the archive's exclusive writer and trusted private-directory
/// ownership. Out-of-band file changes are checked on reopen, not each request.
/// This cache is never serialized or included in a portable snapshot.
pub(super) struct CachedStager {
    context: StagerContext,
    stage: Arc<Stager>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    pub epoch: u64,
    records: BTreeMap<String, Record>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    owner: String,
    input: TransferInput,
    document: String,
    expires: u64,
    completed: Option<ManagedVersion>,
    #[serde(default)]
    cancelled: bool,
}
impl Ledger {
    pub(super) fn new() -> Result<Self, Error> {
        let entropy = crate::AuthToken::generate()?;
        let epoch = u64::from_str_radix(entropy.get(..16).ok_or(Error::Integrity)?, 16).map_err(|_| Error::Integrity)?.max(1);
        Ok(Self { epoch, records: BTreeMap::new() })
    }
    pub(super) fn validate(&self, state: &State) -> Result<(), Error> {
        if self.epoch == 0 || state.stream_policy.is_none() || self.records.len() > MAX_VERSIONS + 2 {
            return Err(Error::Integrity);
        }
        let mut pending = 0;
        for (id, record) in &self.records {
            if !hash_id(id)
                || !label(&record.owner)
                || !crate::valid_id(&record.document)
                || !crate::valid_id(&record.input.request_id)
                || record.input.server_id != state.server_id
                || record.input.recovery_epoch != self.epoch
                || !hash_id(&record.input.sha256)
            {
                return Err(Error::Integrity);
            }
            if let Some(version) = &record.completed {
                let receipt = state.receipts.get(&record.input.request_id).ok_or(Error::Integrity)?;
                if receipt.owner != record.owner || receipt.version != *version || version.version.reference.document != record.document {
                    return Err(Error::Integrity);
                }
            } else if !record.cancelled {
                pending += 1;
            }
        }
        if pending > 2 {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}
fn stage_error(error: TransferError) -> Error {
    Error::Server(
        match error {
            TransferError::FileTooLarge { .. } => "file_too_large",
            TransferError::StorageQuota => "storage_quota_exceeded",
            TransferError::TemporaryQuota => "temporary_quota_exceeded",
            TransferError::Busy => "transfer_busy",
            TransferError::Forbidden => "forbidden",
            TransferError::Expired => "transfer_expired",
            TransferError::Checksum => "checksum_mismatch",
            TransferError::Invalid => "chunk_conflict",
            TransferError::Io(_) => "storage_error",
        }
        .into(),
    )
}
fn normalized(mut input: TransferInput) -> TransferInput {
    if let TransferTarget::CheckIn { checkout_token, .. } = &mut input.target {
        *checkout_token = digest(checkout_token.as_bytes());
    }
    input
}
fn fingerprint(input: &TransferInput) -> Result<String, Error> {
    let mut clean = input.clone();
    if let TransferTarget::CheckIn { checkout_token, .. } = &mut clean.target {
        checkout_token.clear();
    }
    Ok(digest(&serde_json::to_vec(&clean)?))
}
impl ManagedStore {
    pub(crate) fn transfer_capabilities(&self, principal: &Principal) -> TransferCapabilities {
        TransferCapabilities {
            protocol: crate::transfers::PROTOCOL.into(),
            server_id: self.server_id().into(),
            recovery_epoch: self.state.transfers.as_ref().map_or(0, |l| l.epoch),
            principal: principal.clone(),
            binary_transfer_v1: self.state.stream_policy.is_some(),
            can_upload: self.state.stream_policy.is_some() && principal.role != Role::Viewer,
            limits: self.state.stream_policy.clone(),
            chunk_bytes: crate::transfers::CHUNK_BYTES,
        }
    }
    fn binding(&self, owner: &str) -> Result<Binding, Error> {
        Ok(Binding {
            server_id: self.server_id().into(),
            principal: owner.into(),
            epoch: self.state.transfers.as_ref().ok_or(Error::Invalid("streaming not enabled"))?.epoch,
        })
    }
    pub(super) fn invalidate_stager(&self) {
        if let Ok(mut cached) = self.staging.lock() {
            *cached = None;
        }
    }

    pub(super) fn finish_stager_operation<T>(&self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.invalidate_stager();
        }
        result
    }

    fn stager(&self) -> Result<Arc<Stager>, Error> {
        let result = self.stager_inner();
        self.finish_stager_operation(result)
    }

    fn stager_inner(&self) -> Result<Arc<Stager>, Error> {
        let policy = self.state.stream_policy.as_ref().ok_or(Error::Invalid("streaming not enabled"))?;
        let limits = Limits {
            max_file_bytes: policy.max_file_bytes,
            max_store_bytes: policy.max_store_bytes,
            max_temporary_bytes: policy.max_store_bytes.min(policy.max_file_bytes.saturating_mul(2)),
            max_sessions: 2,
        };
        let path = std::path::absolute(&self.root)?.join("uploads");
        let context = StagerContext {
            root: path.clone(),
            server_id: self.server_id().into(),
            epoch: self.state.transfers.as_ref().ok_or(Error::Invalid("streaming not enabled"))?.epoch,
            limits,
        };
        let mut cached = self.staging.lock().map_err(|_| Error::Integrity)?;
        if let Some(cached) = cached.as_ref()
            && cached.context == context
        {
            return Ok(cached.stage.clone());
        }
        // Release the old writer lock before opening a different context.
        *cached = None;
        let stage = Arc::new(if path.try_exists()? { Stager::open(&path, limits) } else { Stager::create(&path, limits) }.map_err(stage_error)?);
        *cached = Some(CachedStager { context, stage: stage.clone() });
        Ok(stage)
    }
    fn reconcile_staging(&self, stage: &Stager) -> Result<(), Error> {
        let ledger = self.state.transfers.as_ref().ok_or(Error::Integrity)?;
        for session in stage.inventory().map_err(stage_error)? {
            if session.binding.server_id != self.server_id() || session.binding.epoch != ledger.epoch {
                return Err(Error::Integrity);
            }
            match ledger.records.get(&session.id) {
                Some(record) if record.owner != session.binding.principal => return Err(Error::Integrity),
                Some(record) if record.cancelled => stage.discard(&session.binding, &session.id, |_| Ok(())).map_err(stage_error)?,
                Some(record) if record.completed.is_some() => stage.complete(&session.binding, &session.id, |_| Ok(())).map_err(stage_error)?,
                None => {
                    // No begin ACK or catalog version can exist without this
                    // ID's record in the authoritative serialized redb writer.
                    stage.discard(&session.binding, &session.id, |_| Ok(())).map_err(stage_error)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
    pub(super) fn reserved_transfer_bytes(&self) -> Result<u64, Error> {
        let result = self.reserved_transfer_bytes_inner();
        self.finish_stager_operation(result)
    }

    fn reserved_transfer_bytes_inner(&self) -> Result<u64, Error> {
        let stage = self.stager()?;
        self.reconcile_staging(&stage)?;
        self.state
            .transfers
            .as_ref()
            .ok_or(Error::Integrity)?
            .records
            .values()
            .filter(|r| r.completed.is_none())
            .try_fold(0u64, |sum, r| sum.checked_add(r.input.total_bytes).ok_or(Error::Integrity))
    }
    fn transfer_record(&self, principal: &Principal, id: &str) -> Result<Record, Error> {
        if !hash_id(id) {
            return Err(Error::Invalid("transfer id"));
        }
        let record = self.state.transfers.as_ref().and_then(|l| l.records.get(id)).ok_or(Error::NotFound)?;
        if record.owner != principal.id {
            return Err(Error::Forbidden);
        }
        Ok(record.clone())
    }
    fn transfer_fence(&self, principal: &Principal, input: &TransferInput) -> Result<(), Error> {
        Self::write_permission(principal)?;
        if input.server_id != self.server_id() {
            return Err(Error::Server("server_identity_mismatch".into()));
        }
        if self.state.transfers.as_ref().is_none_or(|l| l.epoch != input.recovery_epoch) {
            return Err(Error::Server("recovery_epoch_mismatch".into()));
        }
        match &input.target {
            TransferTarget::NewOnly { logical_path } => {
                validate_logical_path(logical_path)?;
                if self.namespace_path_conflict(logical_path, None) {
                    return Err(Error::Conflict);
                }
                if self.state.documents.len() >= MAX_VERSIONS {
                    return Err(Error::Invalid("document quota"));
                }
            }
            TransferTarget::CheckIn { document, workspace, machine, checkout_token, parent } => {
                if self.tombstoned(document) {
                    return Err(Error::NotFound);
                }
                let entry = self.state.documents.get(document).ok_or(Error::NotFound)?;
                let checkout = entry.checkout.as_ref().ok_or(Error::Forbidden)?;
                if checkout.owner != principal.id
                    || checkout.workspace != *workspace
                    || checkout.machine != *machine
                    || self.state.checkout_tokens.get(document).is_none_or(|token| digest(token.as_bytes()) != *checkout_token)
                {
                    return Err(Error::Forbidden);
                }
                if entry.head != *parent || checkout.base_version != *parent {
                    return Err(Error::Conflict);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn begin_transfer(&mut self, principal: &Principal, input: TransferInput) -> Result<TransferProgress, Error> {
        let result = self.begin_transfer_inner(principal, input);
        self.finish_stager_operation(result)
    }

    fn begin_transfer_inner(&mut self, principal: &Principal, input: TransferInput) -> Result<TransferProgress, Error> {
        let input = normalized(input);
        if !crate::valid_id(&input.request_id)
            || !hash_id(&input.sha256)
            || input.dependencies.len() > MAX_DEPENDENCIES
            || input.comment.len() > 1024
            || input.comment.chars().any(|c| c.is_control() && c != '\n')
        {
            return Err(Error::Invalid("transfer control limits"));
        }
        Self::write_permission(principal)?;
        if let Some((id, record)) = self.state.transfers.as_ref().and_then(|l| l.records.iter().find(|(_, r)| r.input.request_id == input.request_id))
        {
            if record.owner != principal.id || fingerprint(&record.input)? != fingerprint(&input)? {
                return Err(Error::Conflict);
            }
            return self.transfer_status(principal, id);
        }
        if self.state.receipts.contains_key(&input.request_id) {
            return Err(Error::Conflict);
        }
        self.transfer_fence(principal, &input)?;
        // Cleanup is server-owned and uses only persisted records and expiry.
        let stage = self.stager()?;
        self.reconcile_staging(&stage)?;
        drop(stage);
        let time = now()?;
        let expired: Vec<_> = self
            .state
            .transfers
            .as_ref()
            .ok_or(Error::Integrity)?
            .records
            .iter()
            .filter(|(_, r)| r.completed.is_none() && (r.cancelled || time >= r.expires))
            .map(|(id, r)| (id.clone(), r.clone()))
            .collect();
        for (id, record) in expired {
            self.cancel_record(&id, &record, "system")?;
        }
        let stage = self.stager()?;
        let mut state = self.state.clone();
        let used = self.blob_inventory()?.iter().try_fold(0u64, |sum, b| sum.checked_add(b.bytes).ok_or(Error::Integrity))?;
        let who = self.binding(&principal.id)?;
        let id = stage.begin(&who, input.total_bytes, input.sha256.clone(), used, time, |_| Ok(())).map_err(stage_error)?;
        let status = stage.status(&who, &id, time, |_| Ok(())).map_err(stage_error)?;
        let document = match &input.target {
            TransferTarget::NewOnly { .. } => format!("m-{}", crate::AuthToken::generate()?.get(..32).ok_or(Error::Integrity)?),
            TransferTarget::CheckIn { document, .. } => document.clone(),
        };
        let ledger = state.transfers.as_mut().ok_or(Error::Integrity)?;
        ledger
            .records
            .insert(id.clone(), Record { owner: principal.id.clone(), input, document, expires: status.expires, completed: None, cancelled: false });
        if let Err(error) = self.publish_as(state, &principal.id, "transfer.begin") {
            if stage.abort(&who, &id, |_| Ok(())).is_err() {
                self.invalidate_stager();
            }
            return Err(error);
        }
        drop(stage);
        self.transfer_status(principal, &id)
    }
    pub(crate) fn transfer_status(&self, principal: &Principal, id: &str) -> Result<TransferProgress, Error> {
        let result = self.transfer_status_inner(principal, id);
        self.finish_stager_operation(result)
    }

    fn transfer_status_inner(&self, principal: &Principal, id: &str) -> Result<TransferProgress, Error> {
        let record = self.transfer_record(principal, id)?;
        if record.cancelled {
            return Err(Error::Server("transfer_cancelled".into()));
        }
        if record.completed.is_none() {
            self.transfer_fence(principal, &record.input)?;
            let stage = self.stager()?;
            let status = stage.status(&self.binding(&principal.id)?, id, now()?, |_| Ok(())).map_err(stage_error)?;
            return Ok(TransferProgress {
                transfer_id: id.into(),
                offset: status.offset,
                total_bytes: status.total,
                sha256: status.sha256,
                expires_at: status.expires,
                completed: None,
            });
        }
        Ok(TransferProgress {
            transfer_id: id.into(),
            offset: record.input.total_bytes,
            total_bytes: record.input.total_bytes,
            sha256: record.input.sha256,
            expires_at: record.expires,
            completed: record.completed,
        })
    }
    pub(crate) fn prepare_chunk(&self, principal: &Principal, id: &str, offset: u64, bytes: u64, sha256: &str) -> Result<(), Error> {
        let result = self.prepare_chunk_inner(principal, id, offset, bytes, sha256);
        self.finish_stager_operation(result)
    }

    fn prepare_chunk_inner(&self, principal: &Principal, id: &str, offset: u64, bytes: u64, sha256: &str) -> Result<(), Error> {
        let record = self.transfer_record(principal, id)?;
        self.transfer_fence(principal, &record.input)?;
        if record.completed.is_some()
            || !hash_id(sha256)
            || bytes == 0
            || bytes > crate::transfers::HARD_CHUNK_BYTES
            || offset.checked_add(bytes).is_none_or(|n| n > record.input.total_bytes)
        {
            return Err(Error::Invalid("chunk limits"));
        }
        let status = self.transfer_status(principal, id)?;
        if offset > status.offset {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn transfer_chunk(
        &mut self,
        principal: &Principal,
        id: &str,
        offset: u64,
        content: &[u8],
        hash: &str,
    ) -> Result<TransferProgress, Error> {
        let result = self.transfer_chunk_inner(principal, id, offset, content, hash);
        self.finish_stager_operation(result)
    }

    fn transfer_chunk_inner(&mut self, principal: &Principal, id: &str, offset: u64, content: &[u8], hash: &str) -> Result<TransferProgress, Error> {
        self.prepare_chunk(principal, id, offset, content.len() as u64, hash)?;
        let stage = self.stager()?;
        stage
            .chunk(&self.binding(&principal.id)?, id, offset, content.len() as u64, hash, &mut &content[..], now()?, |_| Ok(()))
            .map_err(stage_error)?;
        drop(stage);
        self.transfer_status(principal, id)
    }
    pub(crate) fn cancel_transfer(&mut self, principal: &Principal, id: &str) -> Result<(), Error> {
        let result = self.cancel_transfer_inner(principal, id);
        self.finish_stager_operation(result)
    }

    fn cancel_transfer_inner(&mut self, principal: &Principal, id: &str) -> Result<(), Error> {
        Self::write_permission(principal)?;
        let record = match self.transfer_record(principal, id) {
            Ok(record) => record,
            Err(Error::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        };
        if record.completed.is_some() {
            return Err(Error::Conflict);
        }
        self.cancel_record(id, &record, &principal.id)
    }
    fn cancel_record(&mut self, id: &str, record: &Record, actor: &str) -> Result<(), Error> {
        if !record.cancelled {
            let mut state = self.state.clone();
            state.transfers.as_mut().and_then(|l| l.records.get_mut(id)).ok_or(Error::Integrity)?.cancelled = true;
            // Persist destructive intent first. A failed deletion/removal commit
            // leaves a retryable cancellation, never a missing active prefix.
            self.publish_as(state, actor, "transfer.cancel")?;
        }
        let stage = self.stager()?;
        let who = self.binding(&record.owner)?;
        stage.discard(&who, id, |_| Ok(())).map_err(stage_error)?;
        let mut state = self.state.clone();
        state.transfers.as_mut().ok_or(Error::Integrity)?.records.remove(id);
        self.publish_as(state, actor, "transfer.cancel")
    }
    pub(crate) fn commit_transfer(&mut self, principal: &Principal, id: &str, request_id: &str) -> Result<ManagedVersion, Error> {
        let result = self.commit_transfer_inner(principal, id, request_id);
        self.finish_stager_operation(result)
    }

    fn commit_transfer_inner(&mut self, principal: &Principal, id: &str, request_id: &str) -> Result<ManagedVersion, Error> {
        let record = self.transfer_record(principal, id)?;
        if record.cancelled {
            return Err(Error::Server("transfer_cancelled".into()));
        }
        Self::write_permission(principal)?;
        if record.input.request_id != request_id {
            return Err(Error::Conflict);
        }
        if let Some(version) = record.completed {
            let stage = self.stager()?;
            if stage.complete(&self.binding(&principal.id)?, id, |_| Ok(())).is_err() {
                self.invalidate_stager();
            }
            return Ok(version);
        }
        self.transfer_fence(principal, &record.input)?;
        if self.state.versions.len() >= MAX_VERSIONS || self.state.receipts.contains_key(request_id) {
            return Err(Error::Conflict);
        }
        let mut unique = BTreeSet::new();
        for dependency in &record.input.dependencies {
            if dependency.document == record.document || !unique.insert(dependency) {
                return Err(Error::Invalid("self or duplicate dependency"));
            }
            if self.tombstoned(&dependency.document) {
                return Err(Error::Referenced);
            }
            self.verify_reference(dependency)?;
        }
        let stage = self.stager()?;
        let who = self.binding(&principal.id)?;
        let sealed = stage.seal(&who, id, now()?, |_| Ok(())).map_err(stage_error)?;
        if sealed.bytes != record.input.total_bytes || sealed.sha256 != record.input.sha256 {
            return Err(Error::Integrity);
        }
        let mut source = fs::File::open(&sealed.path)?;
        let receipt = self.blobs.put_stream_if_absent(&sealed.sha256, sealed.bytes, &mut source)?;
        if receipt.bytes != sealed.bytes || receipt.sha256 != sealed.sha256 {
            return Err(Error::Integrity);
        }
        let mut state = self.state.clone();
        let mut entry = match &record.input.target {
            TransferTarget::NewOnly { logical_path } => CatalogEntry {
                document: record.document.clone(),
                logical_path: logical_path.clone(),
                head: None,
                head_checked_in_unix_ms: None,
                head_author: None,
                checkout: None,
            },
            TransferTarget::CheckIn { document, .. } => state.documents.get(document).ok_or(Error::NotFound)?.clone(),
        };
        let number = entry.head.unwrap_or(0).checked_add(1).ok_or(Error::Integrity)?;
        let version = ManagedVersion {
            version: Version {
                reference: VersionRef { document: record.document.clone(), version: number },
                parent: entry.head,
                sha256: sealed.sha256,
                dependencies: record.input.dependencies.clone(),
            },
            author: principal.id.clone(),
            checked_in_unix_ms: now()?,
            comment: record.input.comment.clone(),
            request_id: request_id.into(),
        };
        entry.head = Some(number);
        entry.head_author = Some(principal.id.clone());
        entry.head_checked_in_unix_ms = Some(version.checked_in_unix_ms);
        entry.checkout = None;
        state.documents.insert(record.document.clone(), entry);
        state.checkout_tokens.remove(&record.document);
        state.content_bytes = state.content_bytes.checked_add(sealed.bytes).ok_or(Error::Integrity)?;
        state.versions.push(version.clone());
        state
            .receipts
            .insert(request_id.into(), Receipt { owner: principal.id.clone(), fingerprint: fingerprint(&record.input)?, version: version.clone() });
        state.transfers.as_mut().and_then(|l| l.records.get_mut(id)).ok_or(Error::Integrity)?.completed = Some(version.clone());
        self.publish_as(state, &principal.id, "check_in")?;
        if stage.complete(&who, id, |_| Ok(())).is_err() {
            self.invalidate_stager();
        }
        Ok(version)
    }
    pub(crate) fn prepare_transfer_commit(&self, principal: &Principal, id: &str) -> Result<(), Error> {
        let result = self.prepare_transfer_commit_inner(principal, id);
        self.finish_stager_operation(result)
    }

    fn prepare_transfer_commit_inner(&self, principal: &Principal, id: &str) -> Result<(), Error> {
        Self::write_permission(principal)?;
        let record = self.transfer_record(principal, id)?;
        if record.cancelled {
            return Err(Error::Server("transfer_cancelled".into()));
        }
        if record.completed.is_none() {
            self.transfer_fence(principal, &record.input)?;
            self.transfer_status(principal, id)?;
        }
        Ok(())
    }
    pub(crate) fn content_metadata(&self, reference: &VersionRef) -> Result<ContentMetadata, Error> {
        let version = self.state.versions.iter().find(|v| v.version.reference == *reference).ok_or(Error::NotFound)?.version.clone();
        let path = self.root.join("blobs").join(&version.sha256);
        crate::reject_symlink_ancestors(&path)?;
        let file = fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || self.state.stream_policy.is_none() || metadata.len() > crate::stream_io::HARD_FILE_BYTES {
            return Err(Error::Integrity);
        }
        Ok(ContentMetadata { version, total_bytes: metadata.len() })
    }
    pub(crate) fn content_range(&self, reference: &VersionRef, offset: u64, bytes: u64) -> Result<(ContentMetadata, Vec<u8>), Error> {
        if bytes > crate::transfers::HARD_CHUNK_BYTES {
            return Err(Error::Invalid("range length"));
        }
        let metadata = self.content_metadata(reference)?;
        if offset.checked_add(bytes).is_none_or(|n| n > metadata.total_bytes) {
            return Err(Error::Invalid("range bounds"));
        }
        // Only the filesystem adapter advertises streaming. Resolve opaque digest,
        // never a client path, and keep each allocation bounded to one chunk.
        let path = self.root.join("blobs").join(&metadata.version.sha256);
        crate::reject_symlink_ancestors(&path)?;
        let mut file = fs::File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut content = vec![0u8; usize::try_from(bytes).map_err(|_| Error::Integrity)?];
        file.read_exact(&mut content)?;
        Ok((metadata, content))
    }
    pub(crate) fn reset_transfers_after_restore(&mut self) -> Result<(), Error> {
        self.invalidate_stager();
        if self.state.transfers.is_none() {
            return Ok(());
        }
        let mut state = self.state.clone();
        state.transfers = Some(Ledger::new()?);
        self.publish_as(state, "system", "import")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cache_fixture() -> (std::path::PathBuf, crate::Store, Principal, TransferInput, Limits) {
        let root = std::env::temp_dir().join(format!("pdm-stager-cache-{}", crate::AuthToken::generate().unwrap()));
        let principal = Principal { id: "alice".into(), role: Role::Contributor };
        let mut store = crate::Store::open(&root).unwrap();
        store.managed.convert_restored_to_database().unwrap();
        store.initialize_streaming(crate::stream_io::StreamPolicy { version: 1, max_file_bytes: 1024, max_store_bytes: 2048 }).unwrap();
        let caps = store.managed.transfer_capabilities(&principal);
        let input = TransferInput {
            server_id: caps.server_id,
            recovery_epoch: caps.recovery_epoch,
            request_id: "cache-transfer".into(),
            target: TransferTarget::NewOnly { logical_path: "cached.bin".into() },
            total_bytes: 6,
            sha256: digest(b"abcdef"),
            dependencies: vec![],
            comment: String::new(),
        };
        let limits = Limits { max_file_bytes: 1024, max_store_bytes: 2048, max_temporary_bytes: 2048, max_sessions: 2 };
        (root, store, principal, input, limits)
    }

    #[test]
    fn cached_stager_keeps_exclusive_lock_until_store_drop() {
        let (root, mut store, principal, input, limits) = cache_fixture();
        let uploads = root.join("managed/uploads");
        let progress = store.managed.begin_transfer(&principal, input).unwrap();
        assert!(Stager::open(&uploads, limits).is_err(), "successful begin released the store-owned staging lock");
        store.managed.transfer_chunk(&principal, &progress.transfer_id, 0, b"abcdef", &digest(b"abcdef")).unwrap();
        store.managed.transfer_status(&principal, &progress.transfer_id).unwrap();
        store.managed.commit_transfer(&principal, &progress.transfer_id, "cache-transfer").unwrap();
        assert!(Stager::open(&uploads, limits).is_err(), "healthy operations released the store-owned staging lock");
        drop(store);
        drop(Stager::open(&uploads, limits).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_stager_ignored_completion_error_releases_lock_and_recovers_once() {
        let (root, mut store, principal, input, limits) = cache_fixture();
        let progress = store.managed.begin_transfer(&principal, input).unwrap();
        store.managed.transfer_chunk(&principal, &progress.transfer_id, 0, b"abcdef", &digest(b"abcdef")).unwrap();
        crate::transfer_staging::fail_next_complete_delete_for_test();
        let version = store.managed.commit_transfer(&principal, &progress.transfer_id, "cache-transfer").unwrap();
        let uploads = root.join("managed/uploads");
        assert!(uploads.join("sealed").join(&progress.transfer_id).exists(), "cleanup failure was not exercised");
        let recovered = Stager::open(&uploads, limits).unwrap();
        assert!(recovered.inventory().unwrap().is_empty());
        drop(recovered);
        assert_eq!(store.managed.commit_transfer(&principal, &progress.transfer_id, "cache-transfer").unwrap(), version);
        assert_eq!(store.managed.state.versions.len(), 1);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_stager_persist_failure_discards_unacknowledged_tail_before_exact_retry() {
        let (root, mut store, principal, input, limits) = cache_fixture();
        let progress = store.managed.begin_transfer(&principal, input).unwrap();
        store.managed.transfer_chunk(&principal, &progress.transfer_id, 0, b"ab", &digest(b"ab")).unwrap();
        crate::transfer_staging::fail_next_persist_for_test();
        assert!(store.managed.transfer_chunk(&principal, &progress.transfer_id, 2, b"cd", &digest(b"cd")).is_err());
        let uploads = root.join("managed/uploads");
        let raw = uploads.join(&progress.transfer_id);
        assert_eq!(fs::metadata(&raw).unwrap().len(), 4, "fault did not leave an unacknowledged durable tail");
        let recovered = Stager::open(&uploads, limits).unwrap();
        assert_eq!(fs::metadata(&raw).unwrap().len(), 2);
        drop(recovered);
        assert_eq!(store.managed.transfer_status(&principal, &progress.transfer_id).unwrap().offset, 2);
        store.managed.transfer_chunk(&principal, &progress.transfer_id, 2, b"cd", &digest(b"cd")).unwrap();
        store.managed.transfer_chunk(&principal, &progress.transfer_id, 4, b"ef", &digest(b"ef")).unwrap();
        let version = store.managed.commit_transfer(&principal, &progress.transfer_id, "cache-transfer").unwrap();
        assert_eq!(store.managed.download(&version.version.reference).unwrap().1, b"abcdef");
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_stager_direct_preflight_errors_evict_without_http_wrapper() {
        let (root, mut store, principal, input, limits) = cache_fixture();
        let progress = store.managed.begin_transfer(&principal, input).unwrap();
        let viewer = Principal { id: principal.id.clone(), role: Role::Viewer };
        assert!(matches!(store.managed.prepare_chunk(&viewer, &progress.transfer_id, 0, 2, &digest(b"ab")), Err(Error::Forbidden)));
        drop(Stager::open(&root.join("managed/uploads"), limits).unwrap());
        assert_eq!(store.managed.transfer_status(&principal, &progress.transfer_id).unwrap().offset, 0);
        assert!(store.managed.commit_transfer(&principal, &progress.transfer_id, "wrong-request").is_err());
        drop(Stager::open(&root.join("managed/uploads"), limits).unwrap());
        store.managed.cancel_transfer(&principal, &progress.transfer_id).unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_stager_outer_metadata_error_after_seal_evicts_and_retries_one_version() {
        let (root, mut store, principal, input, limits) = cache_fixture();
        let progress = store.managed.begin_transfer(&principal, input).unwrap();
        store.managed.transfer_chunk(&principal, &progress.transfer_id, 0, b"abcdef", &digest(b"abcdef")).unwrap();
        let image = store.managed.metadata.as_ref().unwrap().image.clone();
        // Fail image.next deterministically after seal/blob publication without
        // changing the durable database or adding a production failure API.
        store.managed.metadata.as_mut().unwrap().image.generation = u64::MAX;
        assert!(store.managed.commit_transfer(&principal, &progress.transfer_id, "cache-transfer").is_err());
        assert!(store.managed.state.versions.is_empty());
        let uploads = root.join("managed/uploads");
        assert!(uploads.join("sealed").join(&progress.transfer_id).exists());
        drop(Stager::open(&uploads, limits).unwrap());
        store.managed.metadata.as_mut().unwrap().image = image;
        let version = store.managed.commit_transfer(&principal, &progress.transfer_id, "cache-transfer").unwrap();
        assert_eq!(store.managed.download(&version.version.reference).unwrap().1, b"abcdef");
        assert_eq!(store.managed.state.versions.len(), 1);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_stager_restore_epoch_boundary_releases_writer_and_rejects_old_controls() {
        let (root, mut store, principal, input, limits) = cache_fixture();
        let progress = store.managed.begin_transfer(&principal, input.clone()).unwrap();
        store.managed.transfer_chunk(&principal, &progress.transfer_id, 0, b"abcdef", &digest(b"abcdef")).unwrap();
        store.managed.commit_transfer(&principal, &progress.transfer_id, "cache-transfer").unwrap();
        store.managed.reset_transfers_after_restore().unwrap();
        drop(Stager::open(&root.join("managed/uploads"), limits).unwrap());
        let mut stale = input.clone();
        stale.request_id = "stale-epoch".into();
        stale.target = TransferTarget::NewOnly { logical_path: "stale-epoch.bin".into() };
        assert!(matches!(store.managed.begin_transfer(&principal, stale), Err(Error::Server(code)) if code == "recovery_epoch_mismatch"));
        let mut next = input;
        next.recovery_epoch = store.managed.transfer_capabilities(&principal).recovery_epoch;
        next.request_id = "after-restore".into();
        next.target = TransferTarget::NewOnly { logical_path: "after-restore.bin".into() };
        let progress = store.managed.begin_transfer(&principal, next).unwrap();
        store.managed.cancel_transfer(&principal, &progress.transfer_id).unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_stager_policy_context_change_fails_closed_and_releases_old_writer() {
        let (root, mut store, principal, input, limits) = cache_fixture();
        let progress = store.managed.begin_transfer(&principal, input).unwrap();
        // No live edit API is added: model an unexpected internal policy change.
        store.managed.state.stream_policy.as_mut().unwrap().max_file_bytes = 512;
        assert!(store.managed.transfer_status(&principal, &progress.transfer_id).is_err());
        drop(Stager::open(&root.join("managed/uploads"), limits).unwrap());
        store.managed.state.stream_policy.as_mut().unwrap().max_file_bytes = 1024;
        assert_eq!(store.managed.transfer_status(&principal, &progress.transfer_id).unwrap().offset, 0);
        store.managed.cancel_transfer(&principal, &progress.transfer_id).unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_content_read_and_backup_use_hard_read_bound_not_new_write_policy() {
        let root = std::env::temp_dir().join(format!("pdm-read-policy-{}", crate::AuthToken::generate().unwrap()));
        let token = crate::AuthToken::generate().unwrap();
        let principal = Principal { id: "alice".into(), role: Role::Contributor };
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("managed-principals.json"),
            serde_json::to_vec(&vec![PrincipalCredential { principal: principal.clone(), token_sha256: digest(token.as_bytes()) }]).unwrap(),
        )
        .unwrap();
        let mut store = crate::Store::open(&root).unwrap();
        store.managed.convert_restored_to_database().unwrap();
        store
            .initialize_streaming(crate::stream_io::StreamPolicy { version: 1, max_file_bytes: 3 * 1024 * 1024, max_store_bytes: 6 * 1024 * 1024 })
            .unwrap();
        let caps = store.managed.transfer_capabilities(&principal);
        let bytes = vec![71u8; 2 * 1024 * 1024 + 7];
        let input = TransferInput {
            server_id: caps.server_id,
            recovery_epoch: caps.recovery_epoch,
            request_id: "old-write-policy".into(),
            target: TransferTarget::NewOnly { logical_path: "retained.bin".into() },
            total_bytes: bytes.len() as u64,
            sha256: digest(&bytes),
            dependencies: vec![],
            comment: String::new(),
        };
        let progress = store.managed.begin_transfer(&principal, input).unwrap();
        for (n, chunk) in bytes.chunks(1024 * 1024).enumerate() {
            store.managed.transfer_chunk(&principal, &progress.transfer_id, (n * 1024 * 1024) as u64, chunk, &digest(chunk)).unwrap();
        }
        let version = store.managed.commit_transfer(&principal, &progress.transfer_id, "old-write-policy").unwrap();
        // Model an internally committed operator policy revision; this does not
        // introduce an automatic migration or a live policy-edit endpoint.
        let policy = crate::stream_io::StreamPolicy { version: 1, max_file_bytes: 1024 * 1024, max_store_bytes: 6 * 1024 * 1024 };
        let mut state = store.managed.state.clone();
        state.stream_policy = Some(policy.clone());
        store.managed.publish_as(state, "system", "import").unwrap();
        fs::write(root.join("managed/stream-policy.json"), serde_json::to_vec(&policy).unwrap()).unwrap();
        drop(store);
        let config = crate::http_server::HttpsConfig::from_der(
            "127.0.0.1:0".parse().unwrap(),
            vec![include_bytes!("../../tests/fixtures/pdm-https/server.der").to_vec()],
            include_bytes!("../../tests/fixtures/pdm-https/server-key.der").to_vec(),
        )
        .unwrap();
        let server = crate::http_server::HttpsServer::start(crate::Store::open(&root).unwrap(), config).unwrap();
        let client = crate::client::Client::https_with_ca(
            &format!("https://{}", server.address()),
            crate::AuthToken::parse(token).unwrap(),
            include_bytes!("../../tests/fixtures/pdm-https/ca.der"),
        )
        .unwrap();
        assert_eq!(client.transfer_capabilities().unwrap().unwrap().limits.unwrap().max_file_bytes, 1024 * 1024);
        let mut downloaded = Vec::new();
        client.download_stream(&version.version.reference, &mut downloaded).unwrap();
        assert_eq!(downloaded, bytes);
        server.shutdown().unwrap();
        let backup = root.with_extension("backup");
        let restored = root.with_extension("restored");
        crate::Store::open(&root).unwrap().backup(&backup).unwrap();
        crate::backup_restore::restore_backup_to_redb(&backup, &restored).unwrap();
        assert_eq!(
            crate::Store::open(&restored).unwrap().managed.content_metadata(&version.version.reference).unwrap().total_bytes,
            bytes.len() as u64
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(backup).unwrap();
        fs::remove_dir_all(restored).unwrap();
    }
    #[test]
    fn undisclosed_durable_allocation_is_reconciled_before_next_begin() {
        let root = std::env::temp_dir().join(format!("pdm-orphan-begin-{}", crate::AuthToken::generate().unwrap()));
        let principal = Principal { id: "alice".into(), role: Role::Contributor };
        let mut store = crate::Store::open(&root).unwrap();
        store.managed.convert_restored_to_database().unwrap();
        store
            .initialize_streaming(crate::stream_io::StreamPolicy { version: 1, max_file_bytes: 2 * 1024 * 1024, max_store_bytes: 4 * 1024 * 1024 })
            .unwrap();
        let caps = store.managed.transfer_capabilities(&principal);
        let stage = store.managed.stager().unwrap();
        let abandoned =
            stage.begin(&store.managed.binding("alice").unwrap(), 1024, crate::digest(&vec![0; 1024]), 0, now().unwrap(), |_| Ok(())).unwrap();
        drop(stage);
        drop(store);
        let mut store = crate::Store::open(&root).unwrap();
        let input = TransferInput {
            server_id: caps.server_id,
            recovery_epoch: caps.recovery_epoch,
            request_id: "retry-after-crash".into(),
            target: TransferTarget::NewOnly { logical_path: "new.bin".into() },
            total_bytes: 0,
            sha256: crate::digest(&[]),
            dependencies: vec![],
            comment: String::new(),
        };
        let accepted = store.managed.begin_transfer(&principal, input).unwrap();
        assert_ne!(accepted.transfer_id, abandoned);
        assert!(!root.join("managed/uploads").join(abandoned).exists());
        store.managed.cancel_transfer(&principal, &accepted.transfer_id).unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
