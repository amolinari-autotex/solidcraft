use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Store, backup_restore,
    blob_store::{BlobStore, FsBlobStore},
    stream_io::StreamPolicy,
};
use std::io::Read;

struct Root(std::path::PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn explicit_fresh_enrollment_initializes_in_place_without_changing_identity() {
    let root = Root(std::env::temp_dir().join(format!("enrolled-stream-{}", AuthToken::generate().unwrap())));
    std::fs::create_dir(&root.0).unwrap();
    let path = root.0.join("new");
    let (receipt, _secret) = solidcraft_pdm::bootstrap::initialize(&path, "operator").unwrap();
    let policy = StreamPolicy { version: 1, max_file_bytes: 8 * 1024 * 1024, max_store_bytes: 20 * 1024 * 1024 * 1024 };
    let mut store = Store::open(&path).unwrap();
    let bad = StreamPolicy { version: 1, max_file_bytes: 0, max_store_bytes: 20 * 1024 * 1024 * 1024 };
    assert!(store.initialize_enrolled_streaming(&receipt, bad).is_err());
    assert!(!path.join("managed/metadata.redb").exists());
    store.initialize_enrolled_streaming(&receipt, policy.clone()).unwrap();
    assert!(path.join("managed/metadata.redb").is_file());
    assert!(path.join("managed/stream-policy.json").is_file());
    drop(store);
    let mut store = Store::open(&path).unwrap();
    store.initialize_enrolled_streaming(&receipt, policy.clone()).unwrap();
    match store.execute(solidcraft_pdm::Request::Identity {}) {
        solidcraft_pdm::Response::Identity { identity } => assert_eq!(identity.server_id, receipt.server_id),
        _ => panic!("identity unavailable"),
    }
    drop(store);
    let occupied = root.0.join("occupied");
    let (other, _secret) = solidcraft_pdm::bootstrap::initialize(&occupied, "operator").unwrap();
    let mut store = Store::open(&occupied).unwrap();
    store.execute(solidcraft_pdm::Request::ManagedCreate { logical_path: "existing.bin".into() });
    assert!(store.initialize_enrolled_streaming(&other, policy).is_err());
    assert!(!occupied.join("managed/metadata.redb").exists());
    assert!(!occupied.join("managed/metadata.pending").exists());
    assert!(!occupied.join("managed/stream-policy.pending").exists());
}

#[test]
fn large_blob_streams_through_policy_restart_backup_and_new_restore() {
    let root = Root(std::env::temp_dir().join(format!("stream-store-{}", AuthToken::generate().unwrap())));
    std::fs::create_dir(&root.0).unwrap();
    let seed = root.0.join("seed");
    Store::open(&seed).unwrap().backup(&root.0.join("initial")).unwrap();
    let db = root.0.join("db");
    backup_restore::restore_backup_to_redb(&root.0.join("initial"), &db).unwrap();
    let policy = StreamPolicy { version: 1, max_file_bytes: 3 * 1024 * 1024, max_store_bytes: 8 * 1024 * 1024 };
    let mut store = Store::open(&db).unwrap();
    store.initialize_streaming(policy.clone()).unwrap();
    drop(store);
    let bytes = vec![137u8; 2 * 1024 * 1024 + 17];
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let mut blobs = FsBlobStore::open(&db.join("managed")).unwrap();
    let receipt = blobs.put_stream_if_absent(&hash, bytes.len() as u64, &mut bytes.as_slice()).unwrap();
    assert_eq!(receipt.bytes, bytes.len() as u64);
    assert!(blobs.get_verified(&hash).is_err(), "legacy reads must remain bounded");
    let mut out = Vec::new();
    blobs.open_verified_stream(&hash).unwrap().read_to_end(&mut out).unwrap();
    assert_eq!(out, bytes);
    assert!(blobs.put_stream_if_absent(&"a".repeat(64), bytes.len() as u64, &mut bytes.as_slice()).is_err());
    assert!(blobs.put_stream_if_absent(&hash, policy.max_file_bytes + 1, &mut std::io::empty()).is_err());
    drop(blobs);
    let store = Store::open(&db).unwrap();
    let saved = store.backup(&root.0.join("large-backup")).unwrap();
    assert_eq!(saved.format, "solidcraft-pdm-backup/2");
    drop(store);
    backup_restore::verify_backup(&root.0.join("large-backup")).unwrap();
    backup_restore::restore_backup_to_redb(&root.0.join("large-backup"), &root.0.join("restored")).unwrap();
    let restored = FsBlobStore::open(&root.0.join("restored/managed")).unwrap();
    let mut out = Vec::new();
    restored.open_verified_stream(&hash).unwrap().read_to_end(&mut out).unwrap();
    assert_eq!(out, bytes);
    assert_eq!(restored.inventory().unwrap(), vec![receipt]);
    std::fs::remove_file(root.0.join("restored/managed/stream-policy.json")).unwrap();
    assert!(Store::open(&root.0.join("restored")).is_err(), "policy loss must fail closed");
}
