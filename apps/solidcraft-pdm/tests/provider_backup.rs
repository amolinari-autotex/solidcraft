//! Memory-only external provider tests. No network/account/provider is contacted.
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    Error, MAX_CONTENT, MAX_STORED_CONTENT, MAX_VERSIONS, Request, Response, Store, VersionRef,
    backup_restore::{restore_backup, verify_backup},
    blob_store::{BlobBinding, BlobReceipt, BlobStore},
    managed::{CheckoutGrant, ManagedCheckIn, ManagedVersion},
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("solidcraft-provider-backup-{}", solidcraft_pdm::AuthToken::generate().unwrap()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const STORAGE_SECRET: &str = "private-memory-storage-credential-not-for-backups";
#[derive(Default)]
struct Memory {
    objects: BTreeMap<String, Vec<u8>>,
    inventory: Option<Vec<BlobReceipt>>,
    fail_after_upload: bool,
}
#[derive(Clone)]
struct Fake {
    memory: Arc<Mutex<Memory>>,
    fingerprint: String,
}
impl Fake {
    fn new() -> Self {
        Self { memory: Arc::new(Mutex::new(Memory::default())), fingerprint: hash(b"memory-endpoint/bucket/exclusive-vault-prefix/") }
    }
    fn open(&self, path: &Path) -> Store {
        Store::open_with_blob_store(path, Box::new(self.clone())).unwrap()
    }
}
impl BlobStore for Fake {
    fn binding(&self) -> BlobBinding {
        BlobBinding::External { fingerprint: self.fingerprint.clone() }
    }
    fn put_verified_if_absent(&mut self, digest: &str, content: &[u8]) -> Result<BlobReceipt, Error> {
        if hash(content) != digest || content.len() > MAX_CONTENT {
            return Err(Error::Integrity);
        }
        let mut memory = self.memory.lock().unwrap();
        match memory.objects.get(digest) {
            Some(existing) if existing != content => return Err(Error::Integrity),
            Some(_) => {}
            None => {
                memory.objects.insert(digest.into(), content.to_vec());
            }
        }
        if std::mem::take(&mut memory.fail_after_upload) {
            return Err(Error::Network(std::io::Error::other("simulated acknowledgement loss")));
        }
        Ok(BlobReceipt { sha256: digest.into(), bytes: content.len() as u64 })
    }
    fn get_verified(&self, digest: &str) -> Result<Vec<u8>, Error> {
        // Intentionally do not verify in this fake: backup must independently
        // reject a broken or malicious implementation returning corrupt bytes.
        self.memory.lock().unwrap().objects.get(digest).cloned().ok_or(Error::NotFound)
    }
    fn inventory(&self) -> Result<Vec<BlobReceipt>, Error> {
        let memory = self.memory.lock().unwrap();
        Ok(memory.inventory.clone().unwrap_or_else(|| {
            memory.objects.iter().map(|(digest, bytes)| BlobReceipt { sha256: digest.clone(), bytes: bytes.len() as u64 }).collect()
        }))
    }
}

fn checkout(store: &mut Store, document: &str) -> CheckoutGrant {
    match store.execute(Request::ManagedCheckout { document: document.into(), workspace: "workspace".into(), machine: "desktop".into() }) {
        Response::ManagedCheckout { grant } => grant,
        other => panic!("{other:?}"),
    }
}
fn resume(store: &mut Store, document: &str) -> CheckoutGrant {
    match store.execute(Request::ManagedResumeCheckout { document: document.into(), workspace: "workspace".into(), machine: "desktop".into() }) {
        Response::ManagedCheckout { grant } => grant,
        other => panic!("{other:?}"),
    }
}
fn input(grant: &CheckoutGrant, request: &str, bytes: &[u8]) -> ManagedCheckIn {
    ManagedCheckIn {
        document: grant.entry.document.clone(),
        workspace: "workspace".into(),
        machine: "desktop".into(),
        checkout_token: grant.token.clone(),
        request_id: request.into(),
        parent: grant.entry.head,
        content: bytes.to_vec(),
        dependencies: vec![],
        comment: "Public-safe provider backup fixture".into(),
    }
}
fn created(store: &mut Store) -> String {
    match store.execute(Request::ManagedCreate { logical_path: "parts/public-toy.solidcraft".into() }) {
        Response::ManagedDocument { entry } => entry.document,
        other => panic!("{other:?}"),
    }
}
fn checked_in(response: Response) -> ManagedVersion {
    match response {
        Response::ManagedCheckedIn { version } => version,
        other => panic!("{other:?}"),
    }
}

#[test]
fn external_snapshot_materializes_all_bytes_and_restores_identity_locks_and_receipts_to_filesystem() {
    let temp = Temp::new();
    let root = temp.0.join("service");
    let provider = Fake::new();
    let mut store = provider.open(&root);
    let document = created(&mut store);
    let first = checkout(&mut store, &document);
    let request = input(&first, "first-publication", b"first public toy");
    let version = checked_in(store.execute(Request::ManagedCheckIn { input: request.clone() }));
    let grant = checkout(&mut store, &document);
    let before = serde_json::to_value(store.execute(Request::ManagedCatalog)).unwrap();
    let orphan = b"complete orphan after interrupted metadata publication";
    provider.memory.lock().unwrap().objects.insert(hash(orphan), orphan.to_vec());
    assert!(!root.join("managed/blobs").exists());
    let backup = temp.0.join("backup");
    let receipt = store.backup(&backup).unwrap();
    assert_eq!(receipt, verify_backup(&backup).unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(backup.join("backup.json")).unwrap()).unwrap();
    let paths: Vec<_> = manifest["files"].as_array().unwrap().iter().map(|file| file["path"].as_str().unwrap()).collect();
    assert!(paths.windows(2).all(|pair| pair.first() < pair.get(1)));
    assert_eq!(fs::read(backup.join("data/managed/blobs").join(hash(orphan))).unwrap(), orphan);
    assert!(!backup.join("data/managed/blob-provider.json").exists());
    let restored = temp.0.join("restored-filesystem");
    restore_backup(&backup, &restored).unwrap();
    let mut reopened = Store::open(&restored).unwrap();
    assert_eq!(serde_json::to_value(reopened.execute(Request::ManagedCatalog)).unwrap(), before);
    assert_eq!(resume(&mut reopened, &document), grant);
    let mut retry = request;
    retry.checkout_token.clear();
    assert_eq!(checked_in(reopened.execute(Request::ManagedCheckIn { input: retry })), version);
    assert_eq!(resume(&mut reopened, &document), grant); // Receipt replay never unlocks the later reservation.
    assert_eq!(reopened.download(&VersionRef { document: document.clone(), version: 1 }).unwrap().1, b"first public toy");
    match reopened.execute(Request::ManagedHistory { document }) {
        Response::ManagedHistory { versions } => assert_eq!(versions, vec![version]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn missing_or_corrupt_referenced_provider_bytes_never_complete_backup() {
    for corrupt in [false, true] {
        let temp = Temp::new();
        let provider = Fake::new();
        let mut store = provider.open(&temp.0.join("service"));
        let document = created(&mut store);
        let grant = checkout(&mut store, &document);
        let version = checked_in(store.execute(Request::ManagedCheckIn { input: input(&grant, "published", b"toy") }));
        if corrupt {
            provider.memory.lock().unwrap().objects.insert(version.version.sha256, b"bad".to_vec());
        } else {
            provider.memory.lock().unwrap().objects.clear();
        }
        let backup = temp.0.join("backup");
        assert!(store.backup(&backup).is_err());
        assert!(!backup.join("backup.json").exists());
    }
}

#[test]
fn inventory_orphans_duplicates_sizes_and_count_are_bounded_before_publication() {
    for mode in ["duplicates", "count", "bytes", "object-size", "foreign-digest"] {
        let temp = Temp::new();
        let provider = Fake::new();
        let store = provider.open(&temp.0.join("service"));
        let one = BlobReceipt { sha256: hash(b"orphan"), bytes: 6 };
        let inventory = match mode {
            "duplicates" => vec![one.clone(), one],
            "count" => (0..=MAX_VERSIONS).map(|number| BlobReceipt { sha256: hash(number.to_string().as_bytes()), bytes: 0 }).collect(),
            "bytes" => (0..=MAX_STORED_CONTENT as usize / MAX_CONTENT)
                .map(|number| BlobReceipt { sha256: hash(number.to_string().as_bytes()), bytes: MAX_CONTENT as u64 })
                .collect(),
            "object-size" => vec![BlobReceipt { sha256: one.sha256, bytes: MAX_CONTENT as u64 + 1 }],
            _ => vec![BlobReceipt { sha256: "../foreign-prefix".into(), bytes: 0 }],
        };
        provider.memory.lock().unwrap().inventory = Some(inventory);
        let backup = temp.0.join("backup");
        assert!(store.backup(&backup).is_err());
        assert!(!backup.join("backup.json").exists());
    }
}

#[test]
fn publication_failure_preserves_checkout_and_backup_captures_complete_orphan() {
    let temp = Temp::new();
    let provider = Fake::new();
    let mut store = provider.open(&temp.0.join("service"));
    let document = created(&mut store);
    let grant = checkout(&mut store, &document);
    provider.memory.lock().unwrap().fail_after_upload = true;
    let request = input(&grant, "lost-upload-response", b"orphan from failed publication");
    assert!(matches!(store.execute(Request::ManagedCheckIn { input: request.clone() }), Response::Error { .. }));
    assert_eq!(resume(&mut store, &document), grant);
    let backup = temp.0.join("backup");
    store.backup(&backup).unwrap();
    assert_eq!(fs::read(backup.join("data/managed/blobs").join(hash(&request.content))).unwrap(), request.content);
    let restored = temp.0.join("restored");
    restore_backup(&backup, &restored).unwrap();
    let mut restored = Store::open(&restored).unwrap();
    assert_eq!(resume(&mut restored, &document), grant);
    let version = checked_in(restored.execute(Request::ManagedCheckIn { input: request }));
    assert_eq!(version.version.reference.version, 1);
}

#[test]
fn provider_binding_prevents_filesystem_fallback_and_never_enters_portable_backup() {
    let temp = Temp::new();
    let root = temp.0.join("service");
    let provider = Fake::new();
    let store = provider.open(&root);
    let backup = temp.0.join("backup");
    store.backup(&backup).unwrap();
    let manifest = fs::read_to_string(backup.join("backup.json")).unwrap();
    assert!(!manifest.contains("blob-provider") && !manifest.contains(STORAGE_SECRET) && !manifest.contains(&provider.fingerprint));
    assert!(!backup.join("data/managed/blob-provider.json").exists());
    fs::copy(root.join("managed/blob-provider.json"), backup.join("data/managed/blob-provider.json")).unwrap();
    assert!(verify_backup(&backup).is_err()); // Injected marker is not silently ignored.
    drop(store);
    assert!(Store::open(&root).is_err());
    assert!(!root.join("managed/blobs").exists());
    let wrong = Fake { fingerprint: hash(b"different bucket or prefix"), ..provider.clone() };
    assert!(Store::open_with_blob_store(&root, Box::new(wrong)).is_err());
    let _reopened = provider.open(&root);
}

#[test]
fn unlisted_local_cache_cannot_be_backed_up_as_provider_content() {
    let temp = Temp::new();
    let root = temp.0.join("service");
    let provider = Fake::new();
    let store = provider.open(&root);
    // An external provider is authoritative. A bogus filesystem cache must not
    // appear in the portable blob set, even if injected after the service opened.
    fs::create_dir_all(root.join("managed/blobs")).unwrap();
    fs::write(root.join("managed/blobs").join(hash(b"stale local cache")), b"stale local cache").unwrap();
    let backup = temp.0.join("backup");
    store.backup(&backup).unwrap();
    assert!(!backup.join("data/managed/blobs").join(hash(b"stale local cache")).exists());
}

#[cfg(unix)]
#[test]
fn live_provider_marker_symlink_is_rejected_before_source_exclusion() {
    let temp = Temp::new();
    let root = temp.0.join("service");
    let provider = Fake::new();
    let store = provider.open(&root);
    let marker = root.join("managed/blob-provider.json");
    let target = temp.0.join("private-provider-config");
    fs::rename(&marker, &target).unwrap();
    std::os::unix::fs::symlink(&target, &marker).unwrap();
    let backup = temp.0.join("backup");
    assert!(store.backup(&backup).is_err());
    assert!(!backup.join("backup.json").exists());
}
