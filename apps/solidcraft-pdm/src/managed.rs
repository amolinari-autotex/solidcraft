//! Managed catalog, fenced exclusive checkout and atomic receipt-bearing check-in.
//! Credentials are resolved by the server; request fields never choose a principal.
use crate::blob_store::{BlobBinding, BlobReceipt, BlobStore, FsBlobStore, validate_digest};
use crate::{Error, MAX_CONTENT, MAX_DEPENDENCIES, MAX_STORED_CONTENT, MAX_VERSIONS, Version, VersionRef, digest};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_STATE: usize = 4 * 1024 * 1024;
const MAX_GENERATIONS: u64 = 4096;
const MAX_METADATA_STORAGE: u64 = 64 * 1024 * 1024;
mod administration;
mod metadata_db;
mod namespace;
mod transfers;
pub use namespace::{NamespaceAction, NamespaceCapabilities, NamespaceMetadata, NamespaceMutation};
pub const NAMESPACE_CAPABILITIES_PATH: &str = "/pdm/v1/namespace-capabilities";
pub const NAMESPACE_PROTOCOL: &str = "solidcraft-pdm-namespace/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Contributor,
    Administrator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: String,
    pub role: Role,
}

/// This file is trusted server configuration, never supplied in a network request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalCredential {
    pub principal: Principal,
    pub token_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkout {
    pub owner: String,
    pub workspace: String,
    pub machine: String,
    pub checked_out_unix_ms: u64,
    pub base_version: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutGrant {
    pub entry: CatalogEntry,
    pub token: String,
}

impl std::fmt::Debug for CheckoutGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CheckoutGrant").field("entry", &self.entry).field("token", &"[redacted]").finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedCatalog {
    pub server_id: String,
    pub entries: Vec<CatalogEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub document: String,
    pub logical_path: String,
    pub head: Option<u64>,
    #[serde(default)]
    pub head_checked_in_unix_ms: Option<u64>,
    #[serde(default)]
    pub head_author: Option<String>,
    pub checkout: Option<Checkout>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCheckIn {
    pub document: String,
    pub workspace: String,
    pub machine: String,
    pub checkout_token: String,
    pub request_id: String,
    pub parent: Option<u64>,
    pub content: Vec<u8>,
    pub dependencies: Vec<VersionRef>,
    pub comment: String,
}

impl std::fmt::Debug for ManagedCheckIn {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedCheckIn")
            .field("document", &self.document)
            .field("workspace", &self.workspace)
            .field("machine", &self.machine)
            .field("checkout_token", &"[redacted]")
            .field("request_id", &self.request_id)
            .field("parent", &self.parent)
            .field("content_bytes", &self.content.len())
            .field("dependencies", &self.dependencies)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedVersion {
    pub version: Version,
    pub author: String,
    pub checked_in_unix_ms: u64,
    pub comment: String,
    pub request_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    owner: String,
    fingerprint: String,
    version: ManagedVersion,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transfers: Option<transfers::Ledger>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stream_policy: Option<crate::stream_io::StreamPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    namespace: Option<namespace::NamespaceState>,
    server_id: String,
    checkout_tokens: BTreeMap<String, String>,
    documents: BTreeMap<String, CatalogEntry>,
    versions: Vec<ManagedVersion>,
    receipts: BTreeMap<String, Receipt>,
    content_bytes: u64,
}

fn hash_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl State {
    fn validate(&self) -> Result<(), Error> {
        if let Some(ledger) = &self.transfers {
            ledger.validate(self)?;
        }
        if let Some(policy) = &self.stream_policy {
            policy.validate()?;
        }
        if let Some(namespace) = &self.namespace {
            namespace.validate(self)?;
        }
        if !hash_id(&self.server_id)
            || self.documents.len() > MAX_VERSIONS
            || self.versions.len() > MAX_VERSIONS
            || self.content_bytes
                > self.stream_policy.as_ref().map_or(MAX_STORED_CONTENT, |_| crate::stream_io::HARD_FILE_BYTES.saturating_mul(MAX_VERSIONS as u64))
            || self.receipts.len() != self.versions.len()
        {
            return Err(Error::Integrity);
        }
        let mut seen = BTreeSet::new();
        let mut heads = BTreeMap::new();
        let mut paths = BTreeSet::new();
        for version in &self.versions {
            let reference = &version.version.reference;
            if !self.documents.contains_key(&reference.document)
                || reference.version == 0
                || !hash_id(&version.version.sha256)
                || !label(&version.author)
                || version.comment.len() > 1024
                || !crate::valid_id(&version.request_id)
                || version.version.dependencies.len() > MAX_DEPENDENCIES
                || version.version.parent != heads.get(&reference.document).copied()
                || reference.version != heads.get(&reference.document).copied().unwrap_or(0u64).checked_add(1).ok_or(Error::Integrity)?
            {
                return Err(Error::Integrity);
            }
            let mut dependencies = BTreeSet::new();
            for dependency in &version.version.dependencies {
                if dependency.document == reference.document || !seen.contains(dependency) || !dependencies.insert(dependency) {
                    return Err(Error::Integrity);
                }
            }
            if !seen.insert(reference.clone()) {
                return Err(Error::Integrity);
            }
            heads.insert(reference.document.clone(), reference.version);
            let receipt = self.receipts.get(&version.request_id).ok_or(Error::Integrity)?;
            if receipt.version != *version || receipt.owner != version.author || !hash_id(&receipt.fingerprint) {
                return Err(Error::Integrity);
            }
        }
        let mut locked = 0;
        for (id, entry) in &self.documents {
            let tombstoned = self.namespace.as_ref().is_some_and(|namespace| namespace.tombstoned(id));
            if !crate::valid_id(id)
                || !id.starts_with("m-")
                || entry.document != *id
                || entry.head != heads.get(id).copied()
                || (!tombstoned && !paths.insert(entry.logical_path.to_lowercase()))
            {
                return Err(Error::Integrity);
            }
            validate_logical_path(&entry.logical_path)?;
            let head = self
                .versions
                .iter()
                .find(|version| version.version.reference.document == *id && Some(version.version.reference.version) == entry.head);
            if entry.head_checked_in_unix_ms.is_some_and(|time| head.is_none_or(|version| version.checked_in_unix_ms != time))
                || entry.head_author.as_ref().is_some_and(|author| head.is_none_or(|version| version.author != *author))
            {
                return Err(Error::Integrity);
            }
            if let Some(checkout) = &entry.checkout {
                locked += 1;
                if !label(&checkout.owner)
                    || !label(&checkout.workspace)
                    || !label(&checkout.machine)
                    || checkout.base_version != entry.head
                    || !self.checkout_tokens.get(id).is_some_and(|token| hash_id(token))
                {
                    return Err(Error::Integrity);
                }
            }
        }
        if locked != self.checkout_tokens.len() {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}

pub(crate) struct ManagedStore {
    root: PathBuf,
    blobs: Box<dyn BlobStore>,
    generation: u64,
    state: State,
    credentials: Vec<PrincipalCredential>,
    metadata: Option<metadata_db::MetadataDb>,
    portable_image: Option<metadata_db::Image>,
    staging: std::sync::Mutex<Option<transfers::CachedStager>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderMarker {
    version: u32,
    binding: BlobBinding,
}
pub(crate) struct ManagedSnapshot {
    pub server_id: String,
    pub generation: u64,
    pub digests: Vec<String>,
}

fn now() -> Result<u64, Error> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| Error::Invalid("clock before epoch"))?.as_millis())
        .map_err(|_| Error::Invalid("clock out of range"))
}

fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

/// Portable relative catalog paths; these are never joined onto server disk paths.
/// Workspace metadata components are reserved. Existing state containing them
/// fails validation on open; this does not rename or migrate stored paths.
pub fn validate_logical_path(path: &str) -> Result<(), Error> {
    if path.is_empty() || path.len() > 240 || path.contains('\\') || path.contains(':') || path.chars().any(char::is_control) {
        return Err(Error::Invalid("logical path"));
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with([' ', '.'])
            || component.contains(['<', '>', '"', '|', '?', '*'])
        {
            return Err(Error::Invalid("logical path component"));
        }
        if component.eq_ignore_ascii_case(".solidcraft-pdm") {
            return Err(Error::Invalid("reserved logical path"));
        }
        let stem = component.split('.').next().unwrap_or_default().to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.ends_with(['1', '2', '3', '4', '5', '6', '7', '8', '9']))
        {
            return Err(Error::Invalid("reserved logical path"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod logical_path_tests {
    use super::validate_logical_path;

    #[test]
    fn workspace_metadata_component_is_reserved_at_every_depth_and_case() {
        for path in [".solidcraft-pdm", ".SoLiDcRaFt-PdM/part.solidcraft", "parts/.solidcraft-pdm", "parts/.SoLiDcRaFt-PdM/part.solidcraft"] {
            assert!(validate_logical_path(path).is_err(), "accepted reserved path: {path}");
        }
    }

    #[test]
    fn logical_paths_keep_portable_slash_rules_and_normal_names() {
        for path in ["part.solidcraft", "parts/Part.solidcraft", "parts/.solidcraft-pdm-backup/part.solidcraft"] {
            assert!(validate_logical_path(path).is_ok(), "rejected normal path: {path}");
        }
        for path in [
            "/parts/part.solidcraft",
            "parts//part.solidcraft",
            "parts/",
            "parts\\part.solidcraft",
            "parts/./part.solidcraft",
            "parts/../part.solidcraft",
        ] {
            assert!(validate_logical_path(path).is_err(), "accepted nonportable path: {path}");
        }
    }
}

fn validate_inventory(inventory: &[BlobReceipt], policy: Option<&crate::stream_io::StreamPolicy>) -> Result<(), Error> {
    if inventory.len() > MAX_VERSIONS {
        return Err(Error::Invalid("blob inventory quota"));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for item in inventory {
        validate_digest(&item.sha256)?;
        if !seen.insert(&item.sha256) || item.bytes > policy.map_or(MAX_CONTENT as u64, |_| crate::stream_io::HARD_FILE_BYTES) {
            return Err(Error::Integrity);
        }
        total = total.checked_add(item.bytes).ok_or(Error::Integrity)?;
        if total > policy.map_or(MAX_STORED_CONTENT, |p| p.max_store_bytes) {
            return Err(Error::Invalid("blob inventory quota"));
        }
    }
    Ok(())
}

impl ManagedStore {
    fn validate_stream_policy(&self) -> Result<(), Error> {
        if crate::stream_io::StreamPolicy::read(&self.root)? != self.state.stream_policy {
            return Err(Error::Integrity);
        }
        Ok(())
    }
    pub(crate) fn stream_policy(&self) -> Option<&crate::stream_io::StreamPolicy> {
        self.state.stream_policy.as_ref()
    }
    pub(crate) fn initialize_enrolled_streaming(
        &mut self,
        receipt: &crate::bootstrap::EnrollmentReceipt,
        policy: crate::stream_io::StreamPolicy,
    ) -> Result<(), Error> {
        if self.generation != 1
            || self.portable_image.is_some()
            || self.state.namespace.is_some()
            || self.state.transfers.is_some()
            || !self.state.documents.is_empty()
            || !self.state.versions.is_empty()
            || !self.state.receipts.is_empty()
            || !self.state.checkout_tokens.is_empty()
            || self.state.content_bytes != 0
            || self.blobs.binding() != BlobBinding::Filesystem
            || !self.blobs.inventory()?.is_empty()
            || self.credentials.len() != 1
            || self.credentials.first().is_none_or(|c| c.principal.id != receipt.administrator || c.principal.role != Role::Administrator)
            || self.server_id() != receipt.server_id
        {
            return Err(Error::Invalid("fresh enrollment requires unchanged empty generation-one archive"));
        }
        // This is explicit creation completion, not an automatic legacy-store
        // migration. The same lock, identity and credential registry are held.
        self.convert_restored_to_database()?;
        self.initialize_streaming(policy)
    }
    pub(crate) fn initialize_streaming(&mut self, policy: crate::stream_io::StreamPolicy) -> Result<(), Error> {
        self.invalidate_stager();
        policy.validate()?;
        if self.metadata.is_none()
            || self.blobs.binding() != BlobBinding::Filesystem
            || self.state.stream_policy.is_some()
            || !self.state.documents.is_empty()
            || !self.state.versions.is_empty()
            || !self.blobs.inventory()?.is_empty()
        {
            return Err(Error::Invalid("streaming initialization requires empty transactional filesystem archive"));
        }
        let pending = self.root.join(crate::stream_io::PENDING);
        crate::write_synced(&pending, b"Incomplete stream policy initialization; restore into a new destination.\n")?;
        let mut state = self.state.clone();
        state.stream_policy = Some(policy.clone());
        state.transfers = Some(transfers::Ledger::new()?);
        self.publish_as(state, "system", "import")?;
        crate::write_synced(&self.root.join(crate::stream_io::POLICY), &serde_json::to_vec(&policy)?)?;
        fs::remove_file(pending)?;
        self.validate_stream_policy()?;
        self.blobs = Box::new(FsBlobStore::open(&self.root)?);
        Ok(())
    }
    pub(crate) fn open_blob_stream(&self, hash: &str) -> Result<Box<dyn std::io::Read + Send>, Error> {
        self.blobs.open_verified_stream(hash)
    }
    pub(crate) fn verify_reference(&self, reference: &VersionRef) -> Result<Version, Error> {
        let version = self.state.versions.iter().find(|v| v.version.reference == *reference).ok_or(Error::NotFound)?.version.clone();
        let mut stream = self.open_blob_stream(&version.sha256)?;
        let limit = self.state.stream_policy.as_ref().map_or(MAX_CONTENT as u64, |_| crate::stream_io::HARD_FILE_BYTES);
        if crate::stream_io::copy_hash(&mut stream, &mut std::io::sink(), limit)?.sha256 != version.sha256 {
            return Err(Error::Integrity);
        }
        Ok(version)
    }
    pub(crate) fn blob_inventory(&self) -> Result<Vec<BlobReceipt>, Error> {
        let inventory = self.blobs.inventory()?;
        validate_inventory(&inventory, self.state.stream_policy.as_ref())?;
        Ok(inventory)
    }
    pub(crate) fn get_verified_blob(&self, hash: &str) -> Result<Vec<u8>, Error> {
        validate_digest(hash)?;
        let bytes = self.blobs.get_verified(hash)?;
        if bytes.len() > MAX_CONTENT || digest(&bytes) != hash {
            return Err(Error::Integrity);
        }
        Ok(bytes)
    }
    pub(crate) fn snapshot(&self) -> Result<ManagedSnapshot, Error> {
        self.state.validate()?;
        let inventory = self.blob_inventory()?;
        self.snapshot_from_inventory(&inventory)
    }
    fn snapshot_from_inventory(&self, inventory: &[BlobReceipt]) -> Result<ManagedSnapshot, Error> {
        self.state.validate()?;
        let available: BTreeSet<_> = inventory.iter().map(|item| item.sha256.as_str()).collect();
        let digests: BTreeSet<_> = self.state.versions.iter().map(|version| version.version.sha256.clone()).collect();
        if digests.iter().any(|hash| !available.contains(hash.as_str())) {
            return Err(Error::Integrity);
        }
        Ok(ManagedSnapshot { server_id: self.state.server_id.clone(), generation: self.generation, digests: digests.into_iter().collect() })
    }
    pub(crate) fn open(store_root: &Path) -> Result<Self, Error> {
        let root = store_root.join("managed");
        let blobs = Box::new(FsBlobStore::open(&root)?);
        let store = Self::open_inner(root, blobs, true)?;
        store.validate_stream_policy()?;
        Ok(store)
    }
    pub(crate) fn open_portable_snapshot(store_root: &Path) -> Result<Self, Error> {
        let root = store_root.join("managed");
        crate::reject_symlink_ancestors(&root.join("blobs"))?;
        if !fs::symlink_metadata(root.join("blobs"))?.is_dir() {
            return Err(Error::Integrity);
        }
        let blobs = Box::new(FsBlobStore::open(&root)?);
        let store = Self::open_inner(root, blobs, false)?;
        store.validate_stream_policy()?;
        Ok(store)
    }
    pub(crate) fn open_external(store_root: &Path, blobs: Box<dyn BlobStore>) -> Result<Self, Error> {
        let binding = blobs.binding();
        binding.validate()?;
        if !matches!(binding, BlobBinding::External { .. }) {
            return Err(Error::Invalid("external blob binding required"));
        }
        let root = store_root.join("managed");
        let marker = root.join("blob-provider.json");
        crate::reject_symlink_ancestors(&marker)?;
        let fresh = match fs::symlink_metadata(&marker) {
            Ok(_) => {
                let saved: ProviderMarker = serde_json::from_slice(&crate::client::read_file(&marker, 1024)?)?;
                saved.binding.validate()?;
                if saved.version != 1 || saved.binding != binding {
                    return Err(Error::Invalid("blob provider binding mismatch"));
                }
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if root.try_exists()? {
                    return Err(Error::Invalid("external provider requires fresh managed metadata"));
                }
                fs::create_dir_all(&root)?;
                crate::write_synced(&marker, &serde_json::to_vec(&ProviderMarker { version: 1, binding })?)?;
                true
            }
            Err(error) => return Err(error.into()),
        };
        let local = root.join("blobs");
        crate::reject_symlink_ancestors(&local)?;
        match fs::symlink_metadata(&local) {
            Ok(metadata) => {
                if !metadata.is_dir() || fs::read_dir(&local)?.next().is_some() {
                    return Err(Error::Invalid("mixed local and external blobs"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // One bounded inventory call covers the whole startup preflight. No
        // per-version GET loop or fallback can hide a missing provider namespace.
        let inventory = blobs.inventory()?;
        validate_inventory(&inventory, None)?;
        let store = Self::open_inner(root, blobs, fresh)?;
        store.snapshot_from_inventory(&inventory)?;
        Ok(store)
    }
    fn open_inner(root: PathBuf, blobs: Box<dyn BlobStore>, initialize: bool) -> Result<Self, Error> {
        crate::reject_symlink_ancestors(&root)?;
        if root.join(metadata_db::PENDING).try_exists()? {
            return Err(Error::Invalid("interrupted metadata conversion; restore to a new destination"));
        }
        let database = root.join(metadata_db::DATABASE);
        if database.try_exists()? {
            let metadata = metadata_db::MetadataDb::open(&database)?;
            let image = &metadata.image;
            return Ok(Self {
                root,
                blobs,
                generation: image.generation,
                state: image.state.clone(),
                credentials: image.credentials.clone(),
                metadata: Some(metadata),
                portable_image: None,
                staging: Default::default(),
            });
        }
        // A missing database in a converted store must never fall back to JSON.
        if root.join("generations").join((MAX_GENERATIONS + 1).to_string()).try_exists()? {
            return Err(Error::Invalid("transactional metadata database is missing"));
        }
        let snapshot = root.join(metadata_db::SNAPSHOT);
        if snapshot.try_exists()? {
            let image = metadata_db::Image::from_file(&snapshot)?;
            let mut store = Self {
                root,
                blobs,
                generation: image.generation,
                state: image.state.clone(),
                credentials: image.credentials.clone(),
                metadata: None,
                portable_image: Some(image),
                staging: Default::default(),
            };
            if initialize {
                let image = store.portable_image.take().ok_or(Error::Integrity)?;
                store.metadata = Some(metadata_db::MetadataDb::create(&store.root, image)?);
            }
            return Ok(store);
        }
        crate::reject_symlink_ancestors(&root.join("generations"))?;
        if initialize {
            fs::create_dir_all(root.join("generations"))?;
        }
        let store_root = root.parent().ok_or(Error::Integrity)?;
        let mut generation = 0;
        for (index, entry) in fs::read_dir(root.join("generations"))?.enumerate() {
            if index >= MAX_GENERATIONS as usize {
                return Err(Error::Invalid("metadata generation entry quota"));
            }
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(n) = entry.file_name().to_str().and_then(|n| n.parse::<u64>().ok())
            {
                generation = generation.max(n);
            }
        }
        if generation > MAX_GENERATIONS {
            return Err(Error::Integrity);
        }
        let state: State = if generation == 0 {
            if !initialize {
                return Err(Error::Invalid("incomplete managed metadata"));
            }
            State { server_id: crate::AuthToken::generate()?, ..State::default() }
        } else {
            serde_json::from_slice(&crate::client::read_file(&root.join("generations").join(generation.to_string()).join("state.json"), MAX_STATE)?)?
        };
        state.validate()?;
        let credential_path = store_root.join("managed-principals.json");
        let credentials: Vec<PrincipalCredential> =
            if credential_path.exists() { serde_json::from_slice(&crate::client::read_file(&credential_path, 64 * 1024)?)? } else { Vec::new() };
        let mut hashes = BTreeSet::new();
        let mut principals = BTreeSet::new();
        if credentials.len() > 64 {
            return Err(Error::Invalid("principal count"));
        }
        for item in &credentials {
            if !label(&item.principal.id)
                || item.principal.id == "owner"
                || item.token_sha256.len() != 64
                || !item.token_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                || !hashes.insert(&item.token_sha256)
                || !principals.insert(&item.principal.id)
            {
                return Err(Error::Invalid("principal configuration"));
            }
        }
        let mut store = Self { root, blobs, generation, state, credentials, metadata: None, portable_image: None, staging: Default::default() };
        if generation == 0 {
            store.publish(store.state.clone())?;
        }
        Ok(store)
    }

    pub(crate) fn has_configured_principals(&self) -> bool {
        !self.credentials.is_empty()
    }

    pub(crate) fn server_id(&self) -> &str {
        &self.state.server_id
    }

    pub(crate) fn authenticate(&self, token: &str) -> Option<Principal> {
        use subtle::ConstantTimeEq;
        if token.len() != 64 {
            return None;
        }
        let hash = digest(token.as_bytes());
        self.credentials
            .iter()
            .find(|item| {
                bool::from(hash.as_bytes().ct_eq(item.token_sha256.as_bytes()))
                    && self.metadata.as_ref().is_none_or(|metadata| !metadata.image.disabled(&item.principal.id))
            })
            .map(|item| item.principal.clone())
    }

    fn publish(&mut self, state: State) -> Result<(), Error> {
        self.publish_as(state, "system", "import")
    }

    fn publish_as(&mut self, state: State, actor: &str, operation: &str) -> Result<(), Error> {
        let result = self.publish_as_inner(state, actor, operation);
        self.finish_stager_operation(result)
    }

    fn publish_as_inner(&mut self, state: State, actor: &str, operation: &str) -> Result<(), Error> {
        state.validate()?;
        if self.portable_image.is_some() {
            return Err(Error::Invalid("immutable portable metadata snapshot"));
        }
        if let Some(database) = &mut self.metadata {
            let image = database.image.next(state.clone(), actor, operation)?;
            database.commit(image)?;
            self.generation = database.image.generation;
            self.state = state;
            return Ok(());
        }
        let next = self.generation.checked_add(1).filter(|n| *n <= MAX_GENERATIONS).ok_or(Error::Invalid("metadata generation quota"))?;
        let bytes = serde_json::to_vec(&state)?;
        if bytes.len() > MAX_STATE {
            return Err(Error::Invalid("metadata quota"));
        }
        let mut total = bytes.len() as u64;
        for entry in fs::read_dir(self.root.join("generations"))? {
            let entry = entry?;
            if entry.file_type()?.is_dir() && entry.file_name().to_str().is_some_and(|n| n.parse::<u64>().is_ok()) {
                total = total.checked_add(fs::metadata(entry.path().join("state.json"))?.len()).ok_or(Error::Invalid("metadata storage quota"))?;
                if total > MAX_METADATA_STORAGE {
                    return Err(Error::Invalid("metadata storage quota"));
                }
            }
        }
        let staging = self.root.join("generations/pending");
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        fs::create_dir(&staging)?;
        crate::write_synced(&staging.join("state.json"), &bytes)?;
        // Sync files before publishing a complete immutable metadata generation.
        fs::rename(&staging, self.root.join("generations").join(next.to_string()))?;
        self.state = state;
        self.generation = next;
        Ok(())
    }

    pub(crate) fn database_snapshot(&self) -> Result<Option<Vec<u8>>, Error> {
        self.metadata.as_ref().map(|metadata| metadata.image.bytes()).transpose()
    }

    /// Only used after restoring a verified backup into a freshly reserved path.
    pub(crate) fn convert_restored_to_database(&mut self) -> Result<(), Error> {
        if self.metadata.is_some() {
            return Ok(());
        }
        let image = metadata_db::Image::imported(self.generation, self.state.clone(), self.credentials.clone())?;
        self.metadata = Some(metadata_db::MetadataDb::create(&self.root, image)?);
        Ok(())
    }

    pub(crate) fn contains(&self, document: &str) -> bool {
        self.state.documents.contains_key(document)
    }

    fn ensure_unused_identity(&self, document: &str) -> Result<(), Error> {
        if self.contains(document) {
            return Err(Error::Conflict);
        }
        // A generated managed ID must never shadow an older legacy document,
        // including an incomplete directory or a dangling filesystem entry.
        let root = self.root.parent().ok_or(Error::Integrity)?;
        match fs::symlink_metadata(root.join(format!("d-{document}"))) {
            Ok(_) => Err(Error::Conflict),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn catalog(&self) -> ManagedCatalog {
        ManagedCatalog {
            server_id: self.state.server_id.clone(),
            entries: self.state.documents.values().filter(|e| !self.tombstoned(&e.document)).map(|entry| self.legacy_entry(entry)).collect(),
        }
    }

    pub(crate) fn versions(&self) -> Vec<Version> {
        self.state.versions.iter().map(|v| v.version.clone()).collect()
    }

    pub(crate) fn history(&self, document: &str) -> Result<Vec<ManagedVersion>, Error> {
        if !self.contains(document) {
            return Err(Error::NotFound);
        }
        Ok(self.state.versions.iter().filter(|v| v.version.reference.document == document).cloned().collect())
    }

    pub(crate) fn create(&mut self, principal: &Principal, logical_path: String) -> Result<CatalogEntry, Error> {
        Self::write_permission(principal)?;
        validate_logical_path(&logical_path)?;
        if self.state.documents.len() >= MAX_VERSIONS {
            return Err(Error::Invalid("document quota"));
        }
        // A live alias can reuse a tombstone's display name. Resolve an
        // existing live document before checking retained path reservations.
        if let Some(entry) = self.state.documents.values().filter(|entry| !self.tombstoned(&entry.document)).find(|e| {
            e.logical_path.to_lowercase() == logical_path.to_lowercase() || self.materialization_path(e).to_lowercase() == logical_path.to_lowercase()
        }) {
            return if entry.logical_path == logical_path || self.materialization_path(entry) == logical_path {
                Ok(self.legacy_entry(entry))
            } else {
                Err(Error::Conflict)
            };
        }
        if self.namespace_path_conflict(&logical_path, None) {
            return Err(Error::Conflict);
        }
        let document = format!("m-{}", crate::AuthToken::generate()?.get(..32).ok_or(Error::Integrity)?);
        self.ensure_unused_identity(&document)?;
        let entry =
            CatalogEntry { document: document.clone(), logical_path, head: None, head_checked_in_unix_ms: None, head_author: None, checkout: None };
        let mut state = self.state.clone();
        state.documents.insert(document, entry.clone());
        self.publish_as(state, &principal.id, "create")?;
        Ok(entry)
    }

    /// An import reserves a fresh path under the store's exclusive lock. It
    /// never obtains the identity or checkout of an existing catalog document.
    pub(crate) fn create_new(&mut self, principal: &Principal, logical_path: String) -> Result<CatalogEntry, Error> {
        Self::write_permission(principal)?;
        validate_logical_path(&logical_path)?;
        if self.namespace_path_conflict(&logical_path, None) {
            return Err(Error::Conflict);
        }
        self.create(principal, logical_path)
    }

    fn write_permission(principal: &Principal) -> Result<(), Error> {
        if principal.role == Role::Viewer { Err(Error::Forbidden) } else { Ok(()) }
    }

    pub(crate) fn checkout(&mut self, principal: &Principal, document: &str, workspace: String, machine: String) -> Result<CheckoutGrant, Error> {
        Self::write_permission(principal)?;
        if self.tombstoned(document) {
            return Err(Error::NotFound);
        }
        if !label(&workspace) || !label(&machine) {
            return Err(Error::Invalid("workspace or machine"));
        }
        let entry = self.state.documents.get(document).ok_or(Error::NotFound)?;
        // Mutating checkout is never a resume operation. The explicit read-only
        // resume endpoint recovers an existing authenticated capability.
        if entry.checkout.is_some() {
            return Err(Error::Conflict);
        }
        let mut entry = entry.clone();
        entry.checkout = Some(Checkout { owner: principal.id.clone(), workspace, machine, checked_out_unix_ms: now()?, base_version: entry.head });
        let mut state = self.state.clone();
        let token = crate::AuthToken::generate()?;
        state.checkout_tokens.insert(document.into(), token.clone());
        state.documents.insert(document.into(), entry.clone());
        self.publish_as(state, &principal.id, "checkout")?;
        Ok(CheckoutGrant { entry: self.legacy_entry(&entry), token })
    }

    fn owns(&self, document: &str, checkout: &Checkout, principal: &Principal, workspace: &str, machine: &str, token: &str) -> bool {
        use subtle::ConstantTimeEq;
        checkout.owner == principal.id
            && checkout.workspace == workspace
            && checkout.machine == machine
            && self.state.checkout_tokens.get(document).is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(token.as_bytes())))
    }

    pub(crate) fn cancel(
        &mut self,
        principal: &Principal,
        document: &str,
        workspace: &str,
        machine: &str,
        token: &str,
    ) -> Result<CatalogEntry, Error> {
        Self::write_permission(principal)?;
        let mut entry = self.state.documents.get(document).ok_or(Error::NotFound)?.clone();
        if !entry.checkout.as_ref().is_some_and(|c| self.owns(document, c, principal, workspace, machine, token)) {
            return Err(Error::Forbidden);
        }
        entry.checkout = None;
        let mut state = self.state.clone();
        state.checkout_tokens.remove(document);
        state.documents.insert(document.into(), entry.clone());
        self.publish_as(state, &principal.id, "cancel_checkout")?;
        Ok(self.legacy_entry(&entry))
    }

    pub(crate) fn download(&self, reference: &VersionRef) -> Result<(Version, Vec<u8>), Error> {
        let version = &self.state.versions.iter().find(|v| v.version.reference == *reference).ok_or(Error::NotFound)?.version;
        if let Some(policy) = &self.state.stream_policy {
            let mut content = self.open_blob_stream(&version.sha256)?;
            let mut prefix = Vec::new();
            use std::io::Read;
            content.by_ref().take(MAX_CONTENT as u64 + 1).read_to_end(&mut prefix)?;
            if prefix.len() > MAX_CONTENT {
                return Err(Error::TransferRequired);
            }
            if prefix.len() as u64 > policy.max_file_bytes || digest(&prefix) != version.sha256 {
                return Err(Error::Integrity);
            }
            return Ok((version.clone(), prefix));
        }
        let content = self.get_verified_blob(&version.sha256)?;
        Ok((version.clone(), content))
    }

    pub(crate) fn check_in(&mut self, principal: &Principal, input: ManagedCheckIn) -> Result<ManagedVersion, Error> {
        let result = self.check_in_inner(principal, input);
        self.finish_stager_operation(result)
    }

    fn check_in_inner(&mut self, principal: &Principal, input: ManagedCheckIn) -> Result<ManagedVersion, Error> {
        Self::write_permission(principal)?;
        if !crate::valid_id(&input.request_id)
            || input.comment.len() > 1024
            || input.comment.chars().any(|c| c.is_control() && c != '\n')
            || input.content.len() > MAX_CONTENT
            || input.dependencies.len() > MAX_DEPENDENCIES
        {
            return Err(Error::Invalid("check-in limits"));
        }
        // A completed retry needs the same authenticated principal and exact payload,
        // not a checkout secret that the client may have lost after the acknowledgement.
        let mut receipt_input = input.clone();
        receipt_input.checkout_token.clear();
        let fingerprint = digest(&serde_json::to_vec(&receipt_input)?);
        if let Some(receipt) = self.state.receipts.get(&input.request_id) {
            return if receipt.owner == principal.id && receipt.fingerprint == fingerprint {
                Ok(receipt.version.clone())
            } else {
                Err(Error::Conflict)
            };
        }
        let mut entry = self.state.documents.get(&input.document).ok_or(Error::NotFound)?.clone();
        let checkout = entry.checkout.as_ref().ok_or(Error::Forbidden)?;
        if !self.owns(&input.document, checkout, principal, &input.workspace, &input.machine, &input.checkout_token) {
            return Err(Error::Forbidden);
        }
        if input.parent != entry.head || input.parent != checkout.base_version {
            return Err(Error::Conflict);
        }
        if self.state.versions.len() >= MAX_VERSIONS
            || (self.state.stream_policy.is_none()
                && self.state.content_bytes.checked_add(input.content.len() as u64).is_none_or(|bytes| bytes > MAX_STORED_CONTENT))
        {
            return Err(Error::Invalid("managed storage quota"));
        }
        let mut unique = BTreeSet::new();
        for dependency in &input.dependencies {
            if self.tombstoned(&dependency.document) {
                return Err(Error::Referenced);
            }
            if dependency.document == input.document || !unique.insert(dependency) {
                return Err(Error::Invalid("self or duplicate dependency"));
            }
            self.verify_reference(dependency)?;
        }
        let number = entry.head.unwrap_or(0).checked_add(1).ok_or(Error::Invalid("version exhausted"))?;
        let version = ManagedVersion {
            version: Version {
                reference: VersionRef { document: input.document.clone(), version: number },
                parent: input.parent,
                sha256: digest(&input.content),
                dependencies: input.dependencies,
            },
            author: principal.id.clone(),
            checked_in_unix_ms: now()?,
            comment: input.comment,
            request_id: input.request_id.clone(),
        };
        if let Some(policy) = &self.state.stream_policy {
            let reserved = self.reserved_transfer_bytes()?;
            let inventory = self.blob_inventory()?;
            let used = inventory.iter().try_fold(0u64, |sum, b| sum.checked_add(b.bytes).ok_or(Error::Integrity))?;
            let incoming = if inventory.iter().any(|b| b.sha256 == version.version.sha256) { 0 } else { input.content.len() as u64 };
            if used.checked_add(reserved).and_then(|n| n.checked_add(incoming)).is_none_or(|n| n > policy.max_store_bytes) {
                return Err(Error::Invalid("managed storage quota reserved by transfers"));
            }
        }
        let receipt = self.blobs.put_verified_if_absent(&version.version.sha256, &input.content)?;
        if receipt.sha256 != version.version.sha256 || receipt.bytes != input.content.len() as u64 {
            return Err(Error::Integrity);
        }
        // The receipt, head, immutable version metadata and unlock share one publication.
        // A failed metadata commit leaves the old checkout intact and only an orphan blob.
        entry.head = Some(number);
        entry.head_checked_in_unix_ms = Some(version.checked_in_unix_ms);
        entry.head_author = Some(version.author.clone());
        entry.checkout = None;
        let mut state = self.state.clone();
        state.content_bytes += input.content.len() as u64;
        state.checkout_tokens.remove(&input.document);
        state.documents.insert(input.document, entry);
        state.versions.push(version.clone());
        state.receipts.insert(input.request_id, Receipt { owner: principal.id.clone(), fingerprint, version: version.clone() });
        self.publish_as(state, &principal.id, "check_in")?;
        Ok(version)
    }

    pub(crate) fn where_used(&self, reference: &VersionRef) -> Vec<VersionRef> {
        self.state.versions.iter().filter(|v| v.version.dependencies.contains(reference)).map(|v| v.version.reference.clone()).collect()
    }
}

impl ManagedStore {
    /// Recover only an already-existing capability for this authenticated owner
    /// and exact workspace/machine tuple. Never creates or publishes a checkout.
    pub(crate) fn resume_checkout(&self, principal: &Principal, document: &str, workspace: &str, machine: &str) -> Result<CheckoutGrant, Error> {
        Self::write_permission(principal)?;
        if !label(workspace) || !label(machine) {
            return Err(Error::Invalid("workspace or machine"));
        }
        let entry = self.state.documents.get(document).ok_or(Error::NotFound)?;
        let checkout = entry.checkout.as_ref().ok_or(Error::Conflict)?;
        if checkout.owner != principal.id || checkout.workspace != workspace || checkout.machine != machine {
            return Err(Error::Forbidden);
        }
        let token = self.state.checkout_tokens.get(document).ok_or(Error::Integrity)?;
        Ok(CheckoutGrant { entry: self.legacy_entry(entry), token: token.clone() })
    }
}

#[cfg(test)]
mod provider_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::{Request, Response, Store};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn generated_identity_reserves_existing_legacy_filesystem_entries() {
        let temp = Temp::new();
        let store = Store::open(&temp.0).unwrap();
        fs::create_dir(temp.0.join("d-m-legacy")).unwrap();
        fs::write(temp.0.join("d-m-file"), b"reserved").unwrap();
        assert!(matches!(store.managed.ensure_unused_identity("m-legacy"), Err(Error::Conflict)));
        assert!(matches!(store.managed.ensure_unused_identity("m-file"), Err(Error::Conflict)));
        assert!(store.managed.ensure_unused_identity("m-fresh").is_ok());
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("pdm-provider-{}", crate::AuthToken::generate().unwrap())))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[derive(Clone)]
    struct Fake {
        fingerprint: String,
        data: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        mode: Arc<AtomicUsize>,
        reads: Arc<AtomicUsize>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                fingerprint: "a".repeat(64),
                data: Arc::new(Mutex::new(BTreeMap::new())),
                mode: Arc::new(AtomicUsize::new(0)),
                reads: Arc::new(AtomicUsize::new(0)),
            }
        }
    }
    impl BlobStore for Fake {
        fn binding(&self) -> BlobBinding {
            BlobBinding::External { fingerprint: self.fingerprint.clone() }
        }
        fn put_verified_if_absent(&mut self, hash: &str, content: &[u8]) -> Result<BlobReceipt, Error> {
            if self.mode.load(Ordering::Relaxed) == 1 {
                return Err(Error::Integrity);
            }
            self.data.lock().unwrap().insert(hash.into(), content.to_vec());
            Ok(BlobReceipt { sha256: hash.into(), bytes: content.len() as u64 + u64::from(self.mode.load(Ordering::Relaxed) == 2) })
        }
        fn get_verified(&self, hash: &str) -> Result<Vec<u8>, Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.data.lock().unwrap().get(hash).cloned().ok_or(Error::NotFound)
        }
        fn inventory(&self) -> Result<Vec<BlobReceipt>, Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            match self.mode.load(Ordering::Relaxed) {
                3 => {
                    return Ok(vec![BlobReceipt { sha256: "invalid".into(), bytes: 0 }]);
                }
                4 => {
                    return Ok((0..MAX_VERSIONS + 1).map(|i| BlobReceipt { sha256: digest(&i.to_be_bytes()), bytes: 0 }).collect());
                }
                5 => {
                    return Ok((0..65usize).map(|i| BlobReceipt { sha256: digest(&i.to_be_bytes()), bytes: MAX_CONTENT as u64 }).collect());
                }
                _ => {}
            }
            Ok(self.data.lock().unwrap().iter().map(|(hash, data)| BlobReceipt { sha256: hash.clone(), bytes: data.len() as u64 }).collect())
        }
    }
    #[test]
    fn external_binding_reopens_without_filesystem_fallback_and_rejects_mismatch_before_io() {
        let temp = Temp::new();
        let fake = Fake::new();
        let store = Store::open_with_blob_store(&temp.0, Box::new(fake.clone())).unwrap();
        let id = store.managed.server_id().to_owned();
        drop(store);
        assert!(Store::open(&temp.0).is_err());
        assert!(!temp.0.join("managed/blobs").exists());
        fake.reads.store(0, Ordering::Relaxed);
        let mut wrong = fake.clone();
        wrong.fingerprint = "b".repeat(64);
        assert!(Store::open_with_blob_store(&temp.0, Box::new(wrong)).is_err());
        assert_eq!(fake.reads.load(Ordering::Relaxed), 0);
        let store = Store::open_with_blob_store(&temp.0, Box::new(fake.clone())).unwrap();
        assert_eq!(store.managed.server_id(), id);
        drop(store);
        fs::create_dir(temp.0.join("managed/blobs")).unwrap();
        fs::write(temp.0.join("managed/blobs/garbage"), b"x").unwrap();
        assert!(Store::open_with_blob_store(&temp.0, Box::new(fake)).is_err());
    }
    #[test]
    fn filesystem_roots_and_partial_external_markers_are_never_migrated() {
        let temp = Temp::new();
        drop(Store::open(&temp.0).unwrap());
        assert!(Store::open_with_blob_store(&temp.0, Box::new(Fake::new())).is_err());
        assert!(!temp.0.join("managed/blob-provider.json").exists());
        let partial = Temp::new();
        fs::create_dir_all(partial.0.join("managed")).unwrap();
        fs::write(partial.0.join("managed/blob-provider.json"), b"{").unwrap();
        assert!(Store::open(&partial.0).is_err());
        assert!(!partial.0.join("managed/blobs").exists());
        assert!(Store::open_with_blob_store(&partial.0, Box::new(Fake::new())).is_err());
    }
    #[test]
    fn failed_or_mismatched_put_receipts_preserve_checkout_and_retry_authority() {
        for mode in [1, 2] {
            let temp = Temp::new();
            let fake = Fake::new();
            let mut store = Store::open_with_blob_store(&temp.0, Box::new(fake.clone())).unwrap();
            let entry = match store.execute(Request::ManagedCreate { logical_path: "parts/toy.solidcraft".into() }) {
                Response::ManagedDocument { entry } => entry,
                other => panic!("{other:?}"),
            };
            let grant = match store.execute(Request::ManagedCheckout {
                document: entry.document.clone(),
                workspace: "work".into(),
                machine: "machine".into(),
            }) {
                Response::ManagedCheckout { grant } => grant,
                other => panic!("{other:?}"),
            };
            let input = ManagedCheckIn {
                document: entry.document.clone(),
                workspace: "work".into(),
                machine: "machine".into(),
                checkout_token: grant.token,
                request_id: "retry".into(),
                parent: None,
                content: b"toy".to_vec(),
                dependencies: vec![],
                comment: "Toy".into(),
            };
            fake.mode.store(mode, Ordering::Relaxed);
            assert!(matches!(store.execute(Request::ManagedCheckIn { input: input.clone() }), Response::Error { .. }));
            let catalog = store.managed.catalog();
            assert!(catalog.entries.iter().all(|entry| entry.checkout.is_some() && entry.head.is_none()));
            assert!(store.managed.state.receipts.is_empty());
            fake.mode.store(0, Ordering::Relaxed);
            assert!(matches!(store.execute(Request::ManagedCheckIn { input }), Response::ManagedCheckedIn { .. }));
            let snapshot = store.managed_snapshot().unwrap();
            assert_eq!(snapshot.digests, vec![digest(b"toy")]);
            assert!(snapshot.generation > 0);
            let next_grant =
                store.execute(Request::ManagedCheckout { document: entry.document.clone(), workspace: "work".into(), machine: "machine".into() });
            assert!(matches!(next_grant, Response::ManagedCheckout { .. }));
            let generation = store.managed.generation;
            let metadata_path = temp.0.join("managed/generations").join(generation.to_string()).join("state.json");
            let metadata = fs::read(&metadata_path).unwrap();
            let marker = fs::read(temp.0.join("managed/blob-provider.json")).unwrap();
            let catalog = serde_json::to_value(store.managed.catalog()).unwrap();
            drop(store);
            // Same location fingerprint with an empty/wrong account namespace
            // must fail before any caller can publish over the existing head.
            let wrong_namespace = Fake::new();
            assert!(Store::open_with_blob_store(&temp.0, Box::new(wrong_namespace.clone())).is_err());
            assert_eq!(wrong_namespace.reads.load(Ordering::Relaxed), 1);
            for invalid in [3, 4, 5] {
                wrong_namespace.mode.store(invalid, Ordering::Relaxed);
                assert!(Store::open_with_blob_store(&temp.0, Box::new(wrong_namespace.clone())).is_err());
            }
            assert_eq!(fs::read(&metadata_path).unwrap(), metadata);
            assert_eq!(fs::read(temp.0.join("managed/blob-provider.json")).unwrap(), marker);
            assert_eq!(fs::read_dir(temp.0.join("managed/generations")).unwrap().count(), generation as usize);
            let reopened = Store::open_with_blob_store(&temp.0, Box::new(fake)).unwrap();
            assert_eq!(serde_json::to_value(reopened.managed.catalog()).unwrap(), catalog);
            assert_eq!(reopened.managed.state.versions.len(), 1);
            assert_eq!(reopened.managed.download(&VersionRef { document: entry.document, version: 1 }).unwrap().1, b"toy");
        }
    }
    #[test]
    fn fresh_external_startup_rejects_bad_inventory_before_initial_metadata_publication() {
        for mode in [3, 4, 5] {
            let temp = Temp::new();
            let fake = Fake::new();
            fake.mode.store(mode, Ordering::Relaxed);
            assert!(Store::open_with_blob_store(&temp.0, Box::new(fake.clone())).is_err());
            assert_eq!(fake.reads.load(Ordering::Relaxed), 1);
            assert!(!temp.0.join("managed/generations").exists());
            assert!(!temp.0.join("managed/blobs").exists());
        }
    }
}

#[cfg(test)]
mod resume_checkout_tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
    };

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Result<Self, Error> {
            let root = std::env::temp_dir().join(format!("solidcraft-resume-grant-{}", crate::AuthToken::generate()?));
            fs::create_dir(&root)?;
            Ok(Self(root))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn owner() -> Principal {
        Principal { id: "alice".into(), role: Role::Contributor }
    }
    fn store(root: &Path) -> Result<ManagedStore, Error> {
        ManagedStore::open(root)
    }
    fn snapshot(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Error> {
        let mut pending = vec![root.to_path_buf()];
        let mut result = BTreeMap::new();
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                if entry.file_type()?.is_dir() {
                    pending.push(path);
                } else {
                    result.insert(path.strip_prefix(root).map_err(|_| Error::Integrity)?.into(), fs::read(path)?);
                }
            }
        }
        Ok(result)
    }
    #[test]
    fn same_capability_resumes_without_any_generation_or_file_publication() -> Result<(), Error> {
        let temp = Temp::new()?;
        let mut managed = store(&temp.0)?;
        let entry = managed.create(&owner(), "Parts/example.solidcraft".into())?;
        let grant = managed.checkout(&owner(), &entry.document, "workspace".into(), "machine".into())?;
        let generation = managed.generation;
        let before_state = serde_json::to_vec(&managed.state)?;
        let before_files = snapshot(&temp.0)?;
        for _ in 0..3 {
            let resumed = managed.resume_checkout(&owner(), &entry.document, "workspace", "machine")?;
            assert!(resumed == grant);
        }
        assert_eq!(managed.generation, generation);
        assert_eq!(serde_json::to_vec(&managed.state)?, before_state);
        assert_eq!(snapshot(&temp.0)?, before_files);
        drop(managed);
        let reopened = store(&temp.0)?;
        assert!(reopened.resume_checkout(&owner(), &entry.document, "workspace", "machine")? == grant);
        assert_eq!(snapshot(&temp.0)?, before_files);
        Ok(())
    }
    #[test]
    fn absent_or_disappeared_checkout_never_creates_a_new_reservation() -> Result<(), Error> {
        let temp = Temp::new()?;
        let mut managed = store(&temp.0)?;
        let entry = managed.create(&owner(), "Parts/example.solidcraft".into())?;
        let before = snapshot(&temp.0)?;
        assert!(matches!(managed.resume_checkout(&owner(), &entry.document, "workspace", "machine"), Err(Error::Conflict)));
        assert!(managed.catalog().entries.first().is_some_and(|entry| entry.checkout.is_none()));
        assert_eq!(snapshot(&temp.0)?, before);
        let grant = managed.checkout(&owner(), &entry.document, "workspace".into(), "machine".into())?;
        let observed = managed.catalog();
        assert!(observed.entries.first().is_some_and(|entry| entry.checkout.is_some()));
        // Simulates release between a candidate catalog read and its resume RPC.
        managed.cancel(&owner(), &entry.document, "workspace", "machine", &grant.token)?;
        let after_cancel = snapshot(&temp.0)?;
        let generation = managed.generation;
        assert!(matches!(managed.resume_checkout(&owner(), &entry.document, "workspace", "machine"), Err(Error::Conflict)));
        assert_eq!(managed.generation, generation);
        assert_eq!(snapshot(&temp.0)?, after_cancel);
        assert!(managed.state.checkout_tokens.is_empty());
        Ok(())
    }
    #[test]
    fn wrong_owner_workspace_machine_and_viewer_never_change_authority() -> Result<(), Error> {
        let temp = Temp::new()?;
        let mut managed = store(&temp.0)?;
        let entry = managed.create(&owner(), "Parts/example.solidcraft".into())?;
        let grant = managed.checkout(&owner(), &entry.document, "workspace".into(), "machine".into())?;
        let before = snapshot(&temp.0)?;
        let generation = managed.generation;
        let bob = Principal { id: "bob".into(), role: Role::Administrator };
        let viewer = Principal { id: "alice".into(), role: Role::Viewer };
        for (principal, workspace, machine) in [
            (&bob, "workspace", "machine"),
            (&owner(), "other-workspace", "machine"),
            (&owner(), "workspace", "other-machine"),
            (&viewer, "workspace", "machine"),
        ] {
            assert!(matches!(managed.resume_checkout(principal, &entry.document, workspace, machine), Err(Error::Forbidden)));
        }
        assert!(matches!(managed.resume_checkout(&owner(), &entry.document, "", "machine"), Err(Error::Invalid(_))));
        assert!(matches!(managed.resume_checkout(&owner(), &entry.document, "workspace", "bad\nmachine"), Err(Error::Invalid(_))));
        assert!(matches!(managed.resume_checkout(&owner(), "m-missing", "workspace", "machine"), Err(Error::NotFound)));
        assert_eq!(managed.generation, generation);
        assert_eq!(snapshot(&temp.0)?, before);
        assert!(managed.resume_checkout(&owner(), &entry.document, "workspace", "machine")? == grant);
        Ok(())
    }
}
