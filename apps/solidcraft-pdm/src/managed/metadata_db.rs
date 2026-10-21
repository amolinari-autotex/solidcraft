//! Bounded aggregate adapter. Blob bytes never enter the database.
use super::{MAX_GENERATIONS, PrincipalCredential, State, label, now};
use crate::administration::{AdminResponse, AuditChange, PublicAuditEvent};
use crate::{Error, digest};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path};

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata_v1");
const FORMAT: &str = "solidcraft-pdm-metadata/1";
pub(super) const SNAPSHOT: &str = "metadata-snapshot.json";
pub(super) const DATABASE: &str = "metadata.redb";
pub(super) const PENDING: &str = "metadata.pending";
const MAX_IMAGE: usize = 8 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditEvent {
    generation: u64,
    actor: String,
    operation: String,
    unix_ms: u64,
    state_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    change: Option<AuditChange>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminReceipt {
    pub owner: String,
    pub fingerprint: String,
    pub response: AdminResponse,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminState {
    pub revision: u64,
    pub disabled: BTreeSet<String>,
    pub receipts: std::collections::BTreeMap<String, AdminReceipt>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Image {
    format: String,
    pub generation: u64,
    pub state: State,
    pub credentials: Vec<PrincipalCredential>,
    pub audit: Vec<AuditEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub administration: Option<AdminState>,
}

pub(super) fn validate_credentials(credentials: &[PrincipalCredential]) -> Result<(), Error> {
    let mut hashes = BTreeSet::new();
    let mut principals = BTreeSet::new();
    if credentials.len() > 64 {
        return Err(Error::Invalid("principal count"));
    }
    for item in credentials {
        if !label(&item.principal.id)
            || item.principal.id == "owner"
            || item.token_sha256.len() != 64
            || !item.token_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || !hashes.insert(item.token_sha256.to_ascii_lowercase())
            || !principals.insert(&item.principal.id)
        {
            return Err(Error::Invalid("principal configuration"));
        }
    }
    Ok(())
}

impl Image {
    pub(super) fn imported(generation: u64, state: State, credentials: Vec<PrincipalCredential>) -> Result<Self, Error> {
        let mut image = Self { format: FORMAT.into(), generation, state, credentials, audit: vec![], administration: None };
        image.record("migration", "import")?;
        image.validate()?;
        Ok(image)
    }
    pub(super) fn next(&self, state: State, actor: &str, operation: &str) -> Result<Self, Error> {
        let mut image = self.clone();
        image.generation = image.generation.checked_add(1).ok_or(Error::Integrity)?;
        image.state = state;
        image.record(actor, operation)?;
        image.validate()?;
        Ok(image)
    }
    fn fingerprint(&self) -> Result<String, Error> {
        if let Some(admin) = &self.administration {
            return Ok(digest(&serde_json::to_vec(&(&self.state, &self.credentials, admin))?));
        }
        Ok(digest(&serde_json::to_vec(&(&self.state, &self.credentials))?))
    }
    fn record(&mut self, actor: &str, operation: &str) -> Result<(), Error> {
        self.audit.push(AuditEvent {
            generation: self.generation,
            actor: actor.into(),
            operation: operation.into(),
            unix_ms: now()?,
            state_sha256: self.fingerprint()?,
            subject: if operation.starts_with("document.") { self.state.namespace.as_ref().map(|state| state.last_document.clone()) } else { None },
            change: None,
        });
        Ok(())
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.format != FORMAT
            || self.generation == 0
            || self.generation > MAX_GENERATIONS
            || self.audit.is_empty()
            || self.audit.len() > MAX_GENERATIONS as usize
        {
            return Err(Error::Integrity);
        }
        self.state.validate()?;
        validate_credentials(&self.credentials)?;
        if let Some(admin) = &self.administration {
            if admin.revision > self.generation
                || admin.receipts.len() > 256
                || admin.disabled.iter().any(|id| !self.credentials.iter().any(|item| item.principal.id == *id))
                || !self
                    .credentials
                    .iter()
                    .any(|item| item.principal.role == super::Role::Administrator && !admin.disabled.contains(&item.principal.id))
            {
                return Err(Error::Integrity);
            }
            for (id, receipt) in &admin.receipts {
                if !crate::valid_id(id) || !label(&receipt.owner) || !super::hash_id(&receipt.fingerprint) {
                    return Err(Error::Integrity);
                }
                match &receipt.response {
                    AdminResponse::UserChanged { revision, user }
                        if *revision <= admin.revision
                            && label(&user.id)
                            && user.id != "owner"
                            && user.permissions == if user.enabled { crate::administration::permissions(user.role) } else { vec![] } => {}
                    _ => return Err(Error::Integrity),
                }
            }
        }
        if serde_json::to_vec(&self.state)?.len() > super::MAX_STATE {
            return Err(Error::Invalid("metadata quota"));
        }
        let mut previous = None;
        for event in &self.audit {
            let document_event = matches!(event.operation.as_str(), "document.rename" | "document.tombstone");
            if document_event {
                if event.change.is_some() || event.subject.as_ref().is_none_or(|id| !self.state.documents.contains_key(id)) {
                    return Err(Error::Integrity);
                }
            } else if event.operation.starts_with("user.") != event.subject.is_some()
                || event.subject.is_some() != event.change.is_some()
                || event.subject.as_ref().is_some_and(|subject| !label(subject) || subject == "owner")
            {
                return Err(Error::Integrity);
            }
            if !label(&event.actor)
                || !matches!(
                    event.operation.as_str(),
                    "import"
                        | "create"
                        | "checkout"
                        | "cancel_checkout"
                        | "check_in"
                        | "transfer.begin"
                        | "transfer.cancel"
                        | "document.rename"
                        | "document.tombstone"
                        | "user.create"
                        | "user.set_role"
                        | "user.set_enabled"
                        | "user.replace_credential"
                        | "user.noop"
                )
                || !super::hash_id(&event.state_sha256)
                || event.generation == 0
                || previous.is_some_and(|value: u64| value.checked_add(1) != Some(event.generation))
            {
                return Err(Error::Integrity);
            }
            previous = Some(event.generation);
        }
        let last = self.audit.last().ok_or(Error::Integrity)?;
        if last.generation != self.generation || last.state_sha256 != self.fingerprint()? {
            return Err(Error::Integrity);
        }
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Invalid("database snapshot quota"));
        }
        Ok(bytes)
    }
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_IMAGE {
            return Err(Error::Invalid("database snapshot quota"));
        }
        let image: Self = serde_json::from_slice(bytes)?;
        image.validate()?;
        Ok(image)
    }
    pub(super) fn from_file(path: &Path) -> Result<Self, Error> {
        Self::parse(&crate::client::read_file(path, MAX_IMAGE)?)
    }
    pub(super) fn disabled(&self, id: &str) -> bool {
        self.administration.as_ref().is_some_and(|admin| admin.disabled.contains(id))
    }
    pub(super) fn admin_next(
        &self,
        credentials: Vec<PrincipalCredential>,
        administration: AdminState,
        actor: &str,
        operation: &str,
        subject: String,
        change: AuditChange,
    ) -> Result<Self, Error> {
        let mut image = self.clone();
        image.generation = image.generation.checked_add(1).ok_or(Error::Integrity)?;
        image.credentials = credentials;
        image.administration = Some(administration);
        image.record(actor, operation)?;
        let event = image.audit.last_mut().ok_or(Error::Integrity)?;
        event.subject = Some(subject);
        event.change = Some(change);
        image.validate()?;
        Ok(image)
    }
    pub(super) fn public_audit(&self) -> Vec<PublicAuditEvent> {
        self.audit
            .iter()
            .map(|event| PublicAuditEvent {
                generation: event.generation,
                actor: event.actor.clone(),
                operation: event.operation.clone(),
                unix_ms: event.unix_ms,
                subject: event.subject.clone(),
                change: event.change.clone(),
            })
            .collect()
    }
}

fn database_error(_: impl std::fmt::Display) -> Error {
    Error::Invalid("transactional metadata storage failure")
}

pub(super) struct MetadataDb {
    database: Database,
    pub image: Image,
    #[cfg(test)]
    abort_next: bool,
}
impl MetadataDb {
    pub(super) fn open(path: &Path) -> Result<Self, Error> {
        crate::reject_symlink_ancestors(path)?;
        let database = Database::builder().set_cache_size(8 * 1024 * 1024).open(path).map_err(database_error)?;
        let image = Self::read(&database)?;
        Ok(Self {
            database,
            image,
            #[cfg(test)]
            abort_next: false,
        })
    }
    fn read(database: &Database) -> Result<Image, Error> {
        let transaction = database.begin_read().map_err(database_error)?;
        let table = transaction.open_table(TABLE).map_err(database_error)?;
        let bytes = table.get("current").map_err(database_error)?.ok_or(Error::Integrity)?;
        Image::parse(bytes.value())
    }
    /// Only called for an explicit fresh restore. Pending and downgrade fences
    /// are published before creation; interruption requires another new restore.
    pub(super) fn create(root: &Path, image: Image) -> Result<Self, Error> {
        let bytes = image.bytes()?;
        let path = root.join(DATABASE);
        crate::reject_symlink_ancestors(&path)?;
        if path.try_exists()? {
            return Err(Error::Invalid("database destination exists"));
        }
        crate::write_synced(&root.join(PENDING), b"Incomplete metadata conversion; restore into a new directory.\n")?;
        let fence = root.join("generations").join((MAX_GENERATIONS + 1).to_string());
        crate::reject_symlink_ancestors(&fence)?;
        fs::create_dir_all(&fence)?;
        // Older servers choose the highest JSON generation and reject this number.
        crate::write_synced(&fence.join("state.json"), b"{\"storage_format\":\"redb\"}")?;
        let database = Database::builder().set_cache_size(8 * 1024 * 1024).create(&path).map_err(database_error)?;
        let mut transaction = database.begin_write().map_err(database_error)?;
        transaction.set_durability(Durability::Immediate).map_err(database_error)?;
        {
            transaction.open_table(TABLE).map_err(database_error)?.insert("current", bytes.as_slice()).map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)?;
        if root.join(SNAPSHOT).try_exists()? {
            fs::remove_file(root.join(SNAPSHOT))?;
        }
        fs::remove_file(root.join(PENDING))?;
        Ok(Self {
            database,
            image,
            #[cfg(test)]
            abort_next: false,
        })
    }
    pub(super) fn commit(&mut self, image: Image) -> Result<(), Error> {
        let bytes = image.bytes()?;
        let mut transaction = self.database.begin_write().map_err(database_error)?;
        transaction.set_durability(Durability::Immediate).map_err(database_error)?;
        {
            let mut table = transaction.open_table(TABLE).map_err(database_error)?;
            let saved = Image::parse(table.get("current").map_err(database_error)?.ok_or(Error::Integrity)?.value())?;
            if saved.generation != self.image.generation || image.generation != saved.generation.checked_add(1).ok_or(Error::Integrity)? {
                return Err(Error::Conflict);
            }
            table.insert("current", bytes.as_slice()).map_err(database_error)?;
        }
        #[cfg(test)]
        if std::mem::take(&mut self.abort_next) {
            return Err(Error::Invalid("injected metadata transaction abort"));
        }
        transaction.commit().map_err(database_error)?;
        self.image = image;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    #[test]
    fn aborted_transaction_and_stale_commit_preserve_committed_state() {
        let root = std::env::temp_dir().join(format!("pdm-redb-{}", crate::AuthToken::generate().unwrap()));
        fs::create_dir(&root).unwrap();
        {
            let state = State { server_id: "a".repeat(64), ..State::default() };
            let mut db = MetadataDb::create(&root, Image::imported(1, state.clone(), vec![]).unwrap()).unwrap();
            let next = db.image.next(state.clone(), "alice", "create").unwrap();
            {
                let tx = db.database.begin_write().unwrap();
                tx.open_table(TABLE).unwrap().insert("current", next.bytes().unwrap().as_slice()).unwrap();
                // Dropping an uncommitted transaction must publish nothing.
            }
            assert_eq!(MetadataDb::read(&db.database).unwrap().generation, 1);
            db.commit(next.clone()).unwrap();
            assert!(matches!(db.commit(next), Err(Error::Conflict)));
            assert_eq!(db.image.generation, 2);
            assert_eq!(MetadataDb::read(&db.database).unwrap().generation, 2);
        }
        let reopened = MetadataDb::open(&root.join(DATABASE)).unwrap();
        assert_eq!(reopened.image.generation, 2);
        assert_eq!(reopened.image.audit.len(), 2);
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_check_in_commit_retains_checkout_and_ram_then_retries_once() {
        let root = std::env::temp_dir().join(format!("pdm-redb-checkin-{}", crate::AuthToken::generate().unwrap()));
        let principal = super::super::Principal { id: "alice".into(), role: super::super::Role::Contributor };
        let mut store = crate::Store::open(&root).unwrap();
        store.managed.convert_restored_to_database().unwrap();
        let entry = store.managed.create(&principal, "part.solidcraft".into()).unwrap();
        let grant = store.managed.checkout(&principal, &entry.document, "ws".into(), "machine".into()).unwrap();
        let input = super::super::ManagedCheckIn {
            document: entry.document.clone(),
            workspace: "ws".into(),
            machine: "machine".into(),
            checkout_token: grant.token.clone(),
            request_id: "abort-retry".into(),
            parent: None,
            content: b"toy bytes".to_vec(),
            dependencies: vec![],
            comment: String::new(),
        };
        let generation = store.managed.generation;
        store.managed.metadata.as_mut().unwrap().abort_next = true;
        assert!(store.managed.check_in(&principal, input.clone()).is_err());
        assert_eq!(store.managed.generation, generation);
        assert!(store.managed.history(&entry.document).unwrap().is_empty());
        assert_eq!(store.managed.resume_checkout(&principal, &entry.document, "ws", "machine").unwrap().token, grant.token);
        drop(store);
        let mut store = crate::Store::open(&root).unwrap();
        assert!(store.managed.history(&entry.document).unwrap().is_empty());
        assert_eq!(store.managed.generation, generation);
        let version = store.managed.check_in(&principal, input.clone()).unwrap();
        assert_eq!(version.version.reference.version, 1);
        assert_eq!(store.managed.check_in(&principal, input).unwrap(), version);
        assert_eq!(store.managed.metadata.as_ref().unwrap().image.audit.len(), 4);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_transfer_cancel_intent_preserves_prefix_and_retry_is_idempotent() {
        use crate::transfers::{TransferInput, TransferTarget};
        let root = std::env::temp_dir().join(format!("pdm-cancel-intent-{}", crate::AuthToken::generate().unwrap()));
        let principal = super::super::Principal { id: "alice".into(), role: super::super::Role::Contributor };
        let mut store = crate::Store::open(&root).unwrap();
        store.managed.convert_restored_to_database().unwrap();
        store
            .initialize_streaming(crate::stream_io::StreamPolicy { version: 1, max_file_bytes: 2 * 1024 * 1024, max_store_bytes: 4 * 1024 * 1024 })
            .unwrap();
        let caps = store.managed.transfer_capabilities(&principal);
        let bytes = b"private disposable bytes";
        let input = TransferInput {
            server_id: caps.server_id,
            recovery_epoch: caps.recovery_epoch,
            request_id: "cancel-test".into(),
            target: TransferTarget::NewOnly { logical_path: "cancel.bin".into() },
            total_bytes: bytes.len() as u64,
            sha256: crate::digest(bytes),
            dependencies: vec![],
            comment: String::new(),
        };
        let progress = store.managed.begin_transfer(&principal, input).unwrap();
        store.managed.transfer_chunk(&principal, &progress.transfer_id, 0, bytes, &crate::digest(bytes)).unwrap();
        store.managed.metadata.as_mut().unwrap().abort_next = true;
        assert!(store.managed.cancel_transfer(&principal, &progress.transfer_id).is_err());
        assert_eq!(store.managed.transfer_status(&principal, &progress.transfer_id).unwrap().offset, bytes.len() as u64);
        drop(store);
        let mut store = crate::Store::open(&root).unwrap();
        assert_eq!(store.managed.transfer_status(&principal, &progress.transfer_id).unwrap().offset, bytes.len() as u64);
        store.managed.cancel_transfer(&principal, &progress.transfer_id).unwrap();
        store.managed.cancel_transfer(&principal, &progress.transfer_id).unwrap();
        assert!(store.managed.catalog().entries.is_empty());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_corrupt_or_interrupted_database_never_falls_back_to_legacy_json() {
        for failure in ["missing", "corrupt", "pending"] {
            let root = std::env::temp_dir().join(format!("pdm-redb-invalid-{}", crate::AuthToken::generate().unwrap()));
            let mut store = crate::Store::open(&root).unwrap();
            store.managed.convert_restored_to_database().unwrap();
            drop(store);
            let metadata = root.join("managed");
            // A pre-database server rejects this generation before opening JSON.
            assert!(metadata.join("generations/4097/state.json").is_file());
            match failure {
                "missing" => fs::remove_file(metadata.join(DATABASE)).unwrap(),
                "corrupt" => fs::write(metadata.join(DATABASE), b"corrupt database").unwrap(),
                _ => fs::write(metadata.join(PENDING), b"incomplete").unwrap(),
            }
            assert!(crate::Store::open(&root).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn failed_administration_commit_preserves_authority_revision_receipt_and_audit() {
        use super::super::{Principal, PrincipalCredential, Role};
        use crate::administration::{AdminRequest, AdminResponse};
        let root = std::env::temp_dir().join(format!("pdm-admin-abort-{}", crate::AuthToken::generate().unwrap()));
        fs::create_dir(&root).unwrap();
        let token = "a".repeat(64);
        let credentials = vec![PrincipalCredential {
            principal: Principal { id: "administrator".into(), role: Role::Administrator },
            token_sha256: digest(token.as_bytes()),
        }];
        fs::write(root.join("managed-principals.json"), serde_json::to_vec(&credentials).unwrap()).unwrap();
        let mut store = crate::Store::open(&root).unwrap();
        store.managed.convert_restored_to_database().unwrap();
        let id = store.managed.server_id().to_owned();
        let new_token = "b".repeat(64);
        let request = AdminRequest::CreateUser {
            request_id: "new-user".into(),
            expected_revision: 0,
            id: "new-user".into(),
            role: Role::Contributor,
            credential_sha256: digest(new_token.as_bytes()),
        };
        store.managed.metadata.as_mut().unwrap().abort_next = true;
        assert!(matches!(store.execute_extension(Some(request.clone()), &token, &id), AdminResponse::Error { code } if code == "storage_error"));
        assert!(store.managed.authenticate(&new_token).is_none());
        assert!(store.managed.metadata.as_ref().unwrap().image.administration.is_none());
        assert_eq!(store.managed.metadata.as_ref().unwrap().image.audit.len(), 1);
        drop(store);
        let mut store = crate::Store::open(&root).unwrap();
        assert!(store.managed.authenticate(&new_token).is_none());
        let expected = store.execute_extension(Some(request.clone()), &token, &id);
        assert!(matches!(expected, AdminResponse::UserChanged { revision: 1, .. }));
        assert_eq!(store.execute_extension(Some(request), &token, &id), expected);
        assert!(store.managed.authenticate(&new_token).is_some());
        assert_eq!(store.managed.metadata.as_ref().unwrap().image.audit.len(), 2);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn administration_audit_response_can_exceed_the_request_body_limit() {
        use super::super::{Principal, PrincipalCredential, Role};
        use crate::administration::{AdminRequest, AdminResponse};
        let root = std::env::temp_dir().join(format!("pdm-admin-page-{}", crate::AuthToken::generate().unwrap()));
        fs::create_dir(&root).unwrap();
        let token = "a".repeat(64);
        let target = "\"".repeat(128);
        let credentials = vec![
            PrincipalCredential { principal: Principal { id: "\\".repeat(128), role: Role::Administrator }, token_sha256: digest(token.as_bytes()) },
            PrincipalCredential { principal: Principal { id: target.clone(), role: Role::Viewer }, token_sha256: digest("b".repeat(64).as_bytes()) },
        ];
        fs::write(root.join("managed-principals.json"), serde_json::to_vec(&credentials).unwrap()).unwrap();
        let mut store = crate::Store::open(&root).unwrap();
        store.managed.convert_restored_to_database().unwrap();
        let id = store.managed.server_id().to_owned();
        for index in 0..128 {
            assert!(matches!(
                store.execute_extension(
                    Some(AdminRequest::SetRole { request_id: format!("noop-{index}"), expected_revision: 0, id: target.clone(), role: Role::Viewer }),
                    &token,
                    &id
                ),
                AdminResponse::UserChanged { revision: 0, .. }
            ));
        }
        let request = AdminRequest::ListAudit { after_generation: Some(1), limit: 128 };
        let result = store.execute_extension(Some(request.clone()), &token, &id);
        assert!(serde_json::to_vec(&result).unwrap().len() > crate::administration::MAX_BODY);
        let config = crate::http_server::HttpsConfig::from_der(
            "127.0.0.1:0".parse().unwrap(),
            vec![include_bytes!("../../tests/fixtures/pdm-https/server.der").to_vec()],
            include_bytes!("../../tests/fixtures/pdm-https/server-key.der").to_vec(),
        )
        .unwrap();
        let service = crate::http_server::HttpsServer::start(store, config).unwrap();
        let client = crate::client::Client::https_with_ca(
            &format!("https://{}", service.address()),
            crate::AuthToken::parse(token).unwrap(),
            include_bytes!("../../tests/fixtures/pdm-https/ca.der"),
        )
        .unwrap()
        .bind_server(&id)
        .unwrap();
        assert_eq!(client.admin(request).unwrap(), result);
        service.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
