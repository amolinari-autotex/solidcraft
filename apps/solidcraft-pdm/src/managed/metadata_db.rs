//! Bounded aggregate adapter. Blob bytes never enter the database.
use super::{MAX_GENERATIONS, PrincipalCredential, State, label, now};
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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Image {
    format: String,
    pub generation: u64,
    pub state: State,
    pub credentials: Vec<PrincipalCredential>,
    pub audit: Vec<AuditEvent>,
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
        let mut image = Self { format: FORMAT.into(), generation, state, credentials, audit: vec![] };
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
        Ok(digest(&serde_json::to_vec(&(&self.state, &self.credentials))?))
    }
    fn record(&mut self, actor: &str, operation: &str) -> Result<(), Error> {
        self.audit.push(AuditEvent {
            generation: self.generation,
            actor: actor.into(),
            operation: operation.into(),
            unix_ms: now()?,
            state_sha256: self.fingerprint()?,
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
        if serde_json::to_vec(&self.state)?.len() > super::MAX_STATE {
            return Err(Error::Invalid("metadata quota"));
        }
        let mut previous = None;
        for event in &self.audit {
            if !label(&event.actor)
                || !matches!(event.operation.as_str(), "import" | "create" | "checkout" | "cancel_checkout" | "check_in")
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
}
