use solidcraft_pdm::{AuthToken, AuthenticatedRequest, Error, MAX_FRAME, Request, Response, Store, VersionRef, read_frame, serve_connection};
use std::{
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn listener_is_loopback_and_external_bind_arguments_are_rejected() {
    let listener = solidcraft_pdm::bind_loopback(0).unwrap();
    assert_eq!(listener.local_addr().unwrap().ip(), std::net::Ipv4Addr::LOCALHOST);
    let temp = Temp::new();
    let binary = env!("CARGO_BIN_EXE_solidcraft-pdm");
    for arguments in [vec!["serve", temp.0.to_str().unwrap(), "0.0.0.0:48191"], vec!["serve", temp.0.to_str().unwrap(), "48191", "--bind", "0.0.0.0"]]
    {
        assert!(!std::process::Command::new(binary).args(arguments).output().unwrap().status.success());
    }
}

#[test]
fn total_content_and_version_quotas_reject_further_writes() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0).unwrap();
    let mut parent = None;
    for n in 1..=solidcraft_pdm::MAX_VERSIONS {
        store.check_in("part".into(), parent, vec![], vec![]).unwrap();
        parent = Some(n as u64);
    }
    assert!(store.check_in("part".into(), parent, vec![], vec![]).is_err());
    assert!(store.check_in("other".into(), None, vec![], vec![]).is_err());
    let bytes_temp = Temp::new();
    let mut bytes_store = Store::open(&bytes_temp.0).unwrap();
    let mut parent = None;
    for n in 1..=solidcraft_pdm::MAX_STORED_CONTENT / solidcraft_pdm::MAX_CONTENT as u64 {
        bytes_store.check_in("part".into(), parent, vec![0; solidcraft_pdm::MAX_CONTENT], vec![]).unwrap();
        parent = Some(n);
    }
    assert!(bytes_store.check_in("part".into(), parent, vec![1], vec![]).is_err());
    assert!(bytes_store.download(&reference("part", parent.unwrap() + 1)).is_err());
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("solidcraft-pdm-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn reference(document: &str, version: u64) -> VersionRef {
    VersionRef { document: document.into(), version }
}

#[test]
fn pinned_dependencies_survive_updates_and_restart() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0).unwrap();
    store.check_in("part".into(), None, b"part v1".to_vec(), vec![]).unwrap();
    store.check_in("assembly".into(), None, b"assembly v1".to_vec(), vec![reference("part", 1)]).unwrap();
    store.check_in("part".into(), Some(1), b"part v2".to_vec(), vec![]).unwrap();
    assert_eq!(store.where_used(&reference("part", 1)).unwrap(), vec![reference("assembly", 1)]);
    assert!(store.where_used(&reference("part", 2)).unwrap().is_empty());
    drop(store);
    let store = Store::open(&temp.0).unwrap();
    assert_eq!(store.download(&reference("part", 1)).unwrap().1, b"part v1");
    assert_eq!(store.download(&reference("assembly", 1)).unwrap().0.dependencies, vec![reference("part", 1)]);
}

#[test]
fn conflicts_invalid_references_and_corruption_do_not_publish() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0).unwrap();
    assert!(Store::open(&temp.0).is_err());
    store.check_in("part".into(), None, vec![1], vec![]).unwrap();
    assert!(matches!(store.check_in("part".into(), None, vec![2], vec![]), Err(Error::Conflict)));
    assert!(store.check_in("assembly".into(), None, vec![2], vec![reference("part", 2)]).is_err());
    assert!(store.download(&reference("assembly", 1)).is_err());
    for id in ["../escape", "", "PART", "a/b", "a\\b"] {
        assert!(store.check_in(id.into(), None, vec![], vec![]).is_err());
    }
    assert!(store.check_in("part".into(), Some(1), vec![2], vec![reference("part", 1)]).is_err());
    fs::write(temp.0.join("d-part/1/content"), b"damaged").unwrap();
    assert!(matches!(store.download(&reference("part", 1)), Err(Error::Integrity)));
}

#[test]
fn unpublished_stage_is_recovered_without_reusing_a_version() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0).unwrap();
    store.check_in("part".into(), None, vec![1], vec![]).unwrap();
    fs::create_dir(temp.0.join("d-part/pending")).unwrap();
    fs::write(temp.0.join("d-part/pending/content"), b"partial").unwrap();
    drop(store);
    let mut store = Store::open(&temp.0).unwrap();
    assert_eq!(store.check_in("part".into(), Some(1), vec![2], vec![]).unwrap().reference.version, 2);
    assert_eq!(store.download(&reference("part", 1)).unwrap().1, vec![1]);
}

#[test]
fn actual_tcp_upload_download_and_malformed_request() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let token = AuthToken::parse("a1".repeat(32)).unwrap();
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(&mut store, stream, &token).unwrap();
        }
    });
    let mut upload = TcpStream::connect(address).unwrap();
    let token = AuthToken::parse("a1".repeat(32)).unwrap();
    serde_json::to_writer(
        &mut upload,
        &AuthenticatedRequest::new(&token, Request::CheckIn { document: "toy".into(), parent: None, content: b"toy".to_vec(), dependencies: vec![] }),
    )
    .unwrap();
    upload.write_all(b"\n").unwrap();
    assert!(matches!(serde_json::from_slice::<Response>(&read_frame(upload).unwrap()).unwrap(), Response::CheckedIn { .. }));
    let mut download = TcpStream::connect(address).unwrap();
    serde_json::to_writer(&mut download, &AuthenticatedRequest::new(&token, Request::Download { reference: reference("toy", 1) })).unwrap();
    download.write_all(b"\n").unwrap();
    match serde_json::from_slice::<Response>(&read_frame(download).unwrap()).unwrap() {
        Response::Downloaded { content, .. } => assert_eq!(content, b"toy"),
        other => panic!("unexpected: {other:?}"),
    }
    let mut malformed = TcpStream::connect(address).unwrap();
    malformed.write_all(b"{}\n").unwrap();
    assert!(matches!(serde_json::from_slice::<Response>(&read_frame(malformed).unwrap()).unwrap(), Response::Error { .. }));
    server.join().unwrap();
}

#[test]
fn frame_and_content_limits_are_enforced() {
    assert!(read_frame(&b"{}"[..]).is_err());
    assert!(read_frame(vec![b'x'; MAX_FRAME as usize + 1].as_slice()).is_err());
    let temp = Temp::new();
    let mut store = Store::open(&temp.0).unwrap();
    assert!(store.check_in("part".into(), None, vec![0; solidcraft_pdm::MAX_CONTENT + 1], vec![]).is_err());
    assert!(store.download(&reference("part", 1)).is_err());
}

fn seed_legacy_managed_prefix(temp: &Temp) -> VersionRef {
    use sha2::{Digest, Sha256};
    let reference = reference("m-part", 1);
    let content = b"legacy part";
    let version = solidcraft_pdm::Version {
        reference: reference.clone(),
        parent: None,
        sha256: format!("{:x}", Sha256::digest(content)),
        dependencies: vec![],
    };
    let path = temp.0.join("d-m-part/1");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("content"), content).unwrap();
    fs::write(path.join("version.json"), serde_json::to_vec(&version).unwrap()).unwrap();
    reference
}

#[test]
fn legacy_managed_prefix_history_and_where_used_remain_readable() {
    let temp = Temp::new();
    let part = seed_legacy_managed_prefix(&temp);
    let mut store = Store::open(&temp.0).unwrap();
    store.check_in("assembly".into(), None, b"assembly".to_vec(), vec![part.clone()]).unwrap();
    assert_eq!(store.where_used(&part).unwrap(), vec![reference("assembly", 1)]);
    assert_eq!(store.download(&part).unwrap().1, b"legacy part");
    drop(store);
    let reopened = Store::open(&temp.0).unwrap();
    assert_eq!(reopened.where_used(&part).unwrap(), vec![reference("assembly", 1)]);
}

#[test]
fn legacy_managed_prefix_existing_document_can_advance_without_new_namespace_claims() {
    let temp = Temp::new();
    let part = seed_legacy_managed_prefix(&temp);
    let mut store = Store::open(&temp.0).unwrap();
    let updated = store.check_in(part.document.clone(), Some(1), b"legacy v2".to_vec(), vec![]).unwrap();
    assert_eq!(updated.reference, reference("m-part", 2));
    assert_eq!(store.download(&part).unwrap().1, b"legacy part");
    assert!(matches!(store.check_in("m-new".into(), None, vec![], vec![]), Err(Error::Forbidden)));
    drop(store);
    let reopened = Store::open(&temp.0).unwrap();
    assert_eq!(reopened.list(Some("m-part")).unwrap().len(), 2);
    assert_eq!(reopened.download(&updated.reference).unwrap().1, b"legacy v2");
}
