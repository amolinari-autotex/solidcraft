//! Exercise the storage boundary through managed authority and backup APIs.
use solidcraft_pdm::{
    AuthToken, Request, Response, Store,
    backup_restore::restore_backup,
    managed::{CheckoutGrant, ManagedCheckIn, ManagedVersion},
};
use std::{fs, path::PathBuf};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("solidcraft-blob-managed-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn grant(store: &mut Store) -> CheckoutGrant {
    let document = match store.execute(Request::ManagedCreate { logical_path: "parts/toy.solidcraft".into() }) {
        Response::ManagedDocument { entry } => entry.document,
        other => panic!("{other:?}"),
    };
    match store.execute(Request::ManagedCheckout { document, workspace: "workspace".into(), machine: "desktop".into() }) {
        Response::ManagedCheckout { grant } => grant,
        other => panic!("{other:?}"),
    }
}
fn input(grant: &CheckoutGrant) -> ManagedCheckIn {
    ManagedCheckIn {
        document: grant.entry.document.clone(),
        workspace: "workspace".into(),
        machine: "desktop".into(),
        checkout_token: grant.token.clone(),
        request_id: "initial".into(),
        parent: None,
        content: b"immutable toy content".to_vec(),
        dependencies: vec![],
        comment: "Toy content".into(),
    }
}
fn commit(store: &mut Store, request: ManagedCheckIn) -> ManagedVersion {
    match store.execute(Request::ManagedCheckIn { input: request }) {
        Response::ManagedCheckedIn { version } => version,
        other => panic!("{other:?}"),
    }
}

#[test]
fn interrupted_blob_staging_preserves_checkout_and_retry_receipt() {
    let temp = Temp::new();
    let root = temp.0.join("store");
    let mut store = Store::open(&root).unwrap();
    let grant = grant(&mut store);
    let pending = root.join("managed/blobs/pending");
    fs::write(&pending, b"interrupted transfer").unwrap();
    let request = input(&grant);
    assert!(matches!(store.execute(Request::ManagedCheckIn { input: request.clone() }), Response::Error { .. }));
    assert_eq!(fs::read(&pending).unwrap(), b"interrupted transfer");
    match store.execute(Request::ManagedResumeCheckout {
        document: grant.entry.document.clone(),
        workspace: "workspace".into(),
        machine: "desktop".into(),
    }) {
        Response::ManagedCheckout { grant: current } => assert_eq!(current, grant),
        other => panic!("{other:?}"),
    }
    assert!(store.list(Some(&grant.entry.document)).unwrap().is_empty());
    // Model explicit exclusive-owner recovery; runtime must not silently discard it.
    fs::remove_file(&pending).unwrap();
    let version = commit(&mut store, request.clone());
    assert_eq!(version, commit(&mut store, request));
    assert_eq!(store.list(Some(&grant.entry.document)).unwrap().len(), 1);
    drop(store);
    let reopened = Store::open(&root).unwrap();
    assert_eq!(reopened.download(&version.version.reference).unwrap().1, b"immutable toy content");
}

#[test]
fn existing_blob_layout_roundtrips_coordinated_backup_and_restore() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0.join("source")).unwrap();
    let grant = grant(&mut store);
    let version = commit(&mut store, input(&grant));
    let blob = temp.0.join("source/managed/blobs").join(&version.version.sha256);
    assert_eq!(fs::read(&blob).unwrap(), b"immutable toy content");
    let backup = temp.0.join("backup");
    store.backup(&backup).unwrap();
    let restored = temp.0.join("restored");
    restore_backup(&backup, &restored).unwrap();
    let restored = Store::open(&restored).unwrap();
    assert_eq!(restored.download(&version.version.reference).unwrap().1, b"immutable toy content");
    fs::write(blob, b"damaged").unwrap();
    assert!(store.download(&version.version.reference).is_err());
    assert!(store.backup(&temp.0.join("corrupt-backup")).is_err());
}
