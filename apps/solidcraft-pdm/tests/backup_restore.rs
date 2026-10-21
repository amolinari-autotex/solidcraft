use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    Request, Response, Store, VersionRef,
    backup_restore::{restore_backup, verify_backup},
    managed::ManagedCheckIn,
};
use std::{fs, path::PathBuf};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let name = solidcraft_pdm::AuthToken::generate().unwrap();
        let root = std::env::temp_dir().join(format!("solidcraft-pdm-backup-{name}"));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn populate(store: &mut Store) -> String {
    store.check_in("legacy".into(), None, b"legacy toy".to_vec(), vec![]).unwrap();
    let document = match store.execute(Request::ManagedCreate { logical_path: "parts/toy.solidcraft".into() }) {
        Response::ManagedDocument { entry } => entry.document,
        other => panic!("{other:?}"),
    };
    let grant = match store.execute(Request::ManagedCheckout { document: document.clone(), workspace: "ws".into(), machine: "desktop".into() }) {
        Response::ManagedCheckout { grant } => grant,
        other => panic!("{other:?}"),
    };
    let input = ManagedCheckIn {
        document: document.clone(),
        workspace: "ws".into(),
        machine: "desktop".into(),
        checkout_token: grant.token,
        request_id: "first".into(),
        parent: None,
        content: b"managed toy".to_vec(),
        dependencies: vec![],
        comment: "Toy backup".into(),
    };
    assert!(matches!(store.execute(Request::ManagedCheckIn { input }), Response::ManagedCheckedIn { .. }));
    assert!(matches!(
        store.execute(Request::ManagedCheckout { document: document.clone(), workspace: "ws".into(), machine: "desktop".into() }),
        Response::ManagedCheckout { .. }
    ));
    document
}

#[test]
fn verified_round_trip_preserves_identity_history_content_and_checkout() {
    let temp = Temp::new();
    let root = temp.0.join("store");
    let mut store = Store::open(&root).unwrap();
    let document = populate(&mut store);
    let before = serde_json::to_value(store.execute(Request::ManagedCatalog)).unwrap();
    let backup = temp.0.join("backup");
    let receipt = store.backup(&backup).unwrap();
    assert_eq!(receipt, verify_backup(&backup).unwrap());
    let destination = temp.0.join("restored");
    assert_eq!(receipt, restore_backup(&backup, &destination).unwrap());
    let mut restored = Store::open(&destination).unwrap();
    assert_eq!(before, serde_json::to_value(restored.execute(Request::ManagedCatalog)).unwrap());
    assert_eq!(restored.download(&VersionRef { document: document.clone(), version: 1 }).unwrap().1, b"managed toy");
    assert_eq!(restored.download(&VersionRef { document: "legacy".into(), version: 1 }).unwrap().1, b"legacy toy");
    assert!(
        matches!(restored.execute(Request::ManagedCheckout { document, workspace: "foreign".into(), machine: "other".into() }), Response::Error { code } if code == "conflict")
    );
    assert!(restored.check_in("legacy".into(), Some(1), b"next".to_vec(), vec![]).is_ok());
}

#[test]
fn corrupt_backup_is_rejected_before_restore_destination_is_created() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0.join("store")).unwrap();
    populate(&mut store);
    let backup = temp.0.join("backup");
    store.backup(&backup).unwrap();
    fs::write(backup.join("data/d-legacy/1/content"), b"corrupted").unwrap();
    let destination = temp.0.join("restored");
    assert!(verify_backup(&backup).is_err());
    assert!(restore_backup(&backup, &destination).is_err());
    assert!(!destination.exists());
}

#[test]
fn existing_destinations_live_stores_and_incomplete_restores_fail_closed() {
    let temp = Temp::new();
    let root = temp.0.join("store");
    let mut store = Store::open(&root).unwrap();
    populate(&mut store);
    let backup = temp.0.join("backup");
    store.backup(&backup).unwrap();
    assert!(store.backup(&backup).is_err());
    assert!(store.backup(&root.join("nested")).is_err());
    let destination = temp.0.join("existing");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("keep"), b"user bytes").unwrap();
    assert!(restore_backup(&backup, &destination).is_err());
    assert_eq!(fs::read(destination.join("keep")).unwrap(), b"user bytes");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_solidcraft-pdm"))
        .args(["backup", root.to_str().unwrap(), temp.0.join("live-backup").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!temp.0.join("live-backup").exists());
    let incomplete = temp.0.join("incomplete");
    fs::create_dir(&incomplete).unwrap();
    fs::write(incomplete.join("restore.pending"), b"interrupted").unwrap();
    assert!(Store::open(&incomplete).is_err());
}

#[test]
fn correctly_hashed_but_invalid_domain_metadata_does_not_publish_restore() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0.join("store")).unwrap();
    populate(&mut store);
    let backup = temp.0.join("backup");
    store.backup(&backup).unwrap();
    let manifest_path = backup.join("backup.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let files = manifest.get_mut("files").unwrap().as_array_mut().unwrap();
    let latest = files
        .iter_mut()
        .filter(|f| f["path"].as_str().unwrap().starts_with("managed/generations/"))
        .max_by_key(|f| f["path"].as_str().unwrap().split('/').nth(2).unwrap().parse::<u64>().unwrap())
        .unwrap();
    let path = backup.join("data").join(latest["path"].as_str().unwrap());
    let mut state: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    state["versions"][0]["version"]["sha256"] = "../outside".into();
    let bytes = serde_json::to_vec(&state).unwrap();
    fs::write(&path, &bytes).unwrap();
    latest["bytes"] = (bytes.len() as u64).into();
    latest["sha256"] = format!("{:x}", Sha256::digest(&bytes)).into();
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    verify_backup(&backup).unwrap(); // Hashes alone are not authentication or schema validation.
    let destination = temp.0.join("invalid-restore");
    assert!(restore_backup(&backup, &destination).is_err());
    assert!(destination.join("restore.pending").exists());
    assert!(Store::open(&destination).is_err());
}

#[test]
fn cancellation_debug_never_exposes_checkout_secret() {
    let secret = solidcraft_pdm::AuthToken::generate().unwrap();
    let request = Request::ManagedCancelCheckout {
        document: "m-toy".into(),
        workspace: "ws".into(),
        machine: "desktop".into(),
        checkout_token: secret.clone(),
    };
    assert!(!format!("{request:?}").contains(&secret));
}
