use solidcraft_pdm::{
    AuthToken, Error, Request, Store, TOKEN_ENV, Version, VersionRef, bind_loopback,
    client::Client,
    serve_connection,
    workspace::{content_path, retrieve},
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("solidcraft-pdm-workspace-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
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
fn token() -> AuthToken {
    AuthToken::parse("a1".repeat(32)).unwrap()
}
fn fake_nodes() -> BTreeMap<VersionRef, (Version, Vec<u8>)> {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0).unwrap();
    let first = store.check_in("part".into(), None, b"one".to_vec(), vec![]).unwrap();
    let second = store.check_in("part".into(), Some(1), b"two".to_vec(), vec![]).unwrap();
    let root = store.check_in("assembly".into(), None, b"assembly".to_vec(), vec![first.reference.clone(), second.reference.clone()]).unwrap();
    [first, second, root]
        .into_iter()
        .map(|v| {
            let bytes = store.download(&v.reference).unwrap().1;
            (v.reference.clone(), (v, bytes))
        })
        .collect()
}

#[test]
fn exact_closure_uses_separate_paths_and_never_overwrites() {
    let temp = Temp::new();
    let nodes = fake_nodes();
    let destination = temp.0.join("new-workspace");
    let snapshot = retrieve(reference("assembly", 1), &destination, |r| nodes.get(r).cloned().ok_or(Error::NotFound)).unwrap();
    assert_eq!(snapshot.versions.len(), 3);
    for n in [1, 2] {
        let path = destination.join("snapshot").join(content_path(&reference("part", n)).unwrap());
        assert_eq!(fs::read(path).unwrap(), if n == 1 { b"one" } else { b"two" });
    }
    assert!(!destination.join(".pending").exists());
    assert!(destination.join("snapshot/snapshot.json").is_file());
    assert!(retrieve(reference("assembly", 1), &destination, |_| panic!("existing directory must be rejected before fetching")).is_err());
    assert_eq!(fs::read(destination.join("snapshot/documents/d-part/v-1/content")).unwrap(), b"one");
    let file = temp.0.join("existing-file");
    fs::write(&file, b"keep").unwrap();
    assert!(retrieve(reference("assembly", 1), &file, |_| panic!("existing file must remain intact")).is_err());
    assert_eq!(fs::read(file).unwrap(), b"keep");
}

#[test]
fn hostile_graph_missing_content_and_integrity_fail_before_any_write() {
    let temp = Temp::new();
    for (index, malformed) in ["../escape", "a/b", "a\\b", "C:\\escape", "/absolute", "UPPER", ""].into_iter().enumerate() {
        let mut nodes = fake_nodes();
        nodes.get_mut(&reference("assembly", 1)).unwrap().0.dependencies = vec![reference(malformed, 1)];
        let target = temp.0.join(format!("bad-{index}"));
        assert!(retrieve(reference("assembly", 1), &target, |r| nodes.get(r).cloned().ok_or(Error::NotFound)).is_err());
        assert!(!target.exists());
    }
    for mode in 0..4 {
        let mut nodes = fake_nodes();
        match mode {
            0 => {
                nodes.remove(&reference("part", 1));
            }
            1 => {
                nodes.get_mut(&reference("part", 1)).unwrap().1 = b"changed".to_vec();
            }
            2 => {
                nodes.get_mut(&reference("part", 1)).unwrap().0.dependencies = vec![reference("assembly", 1)];
            }
            3 => {
                nodes.get_mut(&reference("part", 1)).unwrap().0.reference = reference("wrong", 1);
            }
            _ => unreachable!(),
        }
        let target = temp.0.join(format!("failure-{mode}"));
        assert!(retrieve(reference("assembly", 1), &target, |r| nodes.get(r).cloned().ok_or(Error::NotFound)).is_err());
        assert!(!target.exists());
    }
    assert!(!temp.0.join("escape").exists());
}

#[test]
fn unauthorized_requests_never_enter_domain_and_rotation_rejects_old_credentials() {
    let temp = Temp::new();
    let mut store = Store::open(&temp.0).unwrap();
    store.check_in("part".into(), None, b"one".to_vec(), vec![]).unwrap();
    let listener = bind_loopback(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        for index in 0..5 {
            let (stream, _) = listener.accept().unwrap();
            let credential = if index < 3 { token() } else { AuthToken::parse("b2".repeat(32)).unwrap() };
            serve_connection(&mut store, stream, &credential).unwrap();
        }
        assert!(store.list(Some("intruder")).unwrap().is_empty());
    });
    let wrong = Client::new(port, AuthToken::parse("c3".repeat(32)).unwrap());
    for request in [
        Request::List { document: None },
        Request::Download { reference: reference("part", 1) },
        Request::CheckIn { document: "intruder".into(), parent: None, content: vec![], dependencies: vec![] },
    ] {
        assert!(matches!(wrong.request(request), Err(Error::Server(code)) if code == "unauthorized"));
    }
    assert!(matches!(Client::new(port, token()).list(None), Err(Error::Server(code)) if code == "unauthorized"));
    let rotated = Client::new(port, AuthToken::parse("b2".repeat(32)).unwrap());
    assert_eq!(rotated.list(None).unwrap().len(), 1);
    server.join().unwrap();
}

#[test]
fn owner_credentials_are_generated_validated_and_redacted() {
    let first = AuthToken::generate().unwrap();
    let second = AuthToken::generate().unwrap();
    assert_eq!(first.len(), 64);
    assert_ne!(first, second);
    let token = AuthToken::parse(first.clone()).unwrap();
    assert!(!format!("{token:?}").contains(&first));
    for invalid in ["", "short", &"g".repeat(64), &"a".repeat(65)] {
        assert!(AuthToken::parse(invalid.into()).is_err());
    }
}

#[test]
fn missing_credentials_legacy_requests_and_wrong_protocol_fail_closed() {
    use std::{io::Write, net::TcpStream};
    let temp = Temp::new();
    let unused_store = temp.0.join("must-not-be-created");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_solidcraft-pdm"))
        .args(["serve", unused_store.to_str().unwrap(), "0"])
        .env_remove(TOKEN_ENV)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!unused_store.exists());
    assert!(out.stdout.is_empty());
    let mut store = Store::open(&temp.0.join("store")).unwrap();
    let listener = bind_loopback(0).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(&mut store, stream, &token()).unwrap();
        }
        assert!(store.list(None).unwrap().is_empty());
    });
    for request in [
        serde_json::json!({"operation":"list","document":null}),
        serde_json::json!({"protocol":solidcraft_pdm::PROTOCOL,"request":{"operation":"list","document":null}}),
        serde_json::json!({"protocol":"wrong","token":"a1".repeat(32),"request":{"operation":"list","document":null}}),
    ] {
        let mut stream = TcpStream::connect(address).unwrap();
        serde_json::to_writer(&mut stream, &request).unwrap();
        stream.write_all(b"\n").unwrap();
        let bytes = solidcraft_pdm::read_frame(stream).unwrap();
        let response: solidcraft_pdm::Response = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(response, solidcraft_pdm::Response::Error { .. }));
        assert!(!String::from_utf8_lossy(&bytes).contains(&"a1".repeat(32)));
    }
    server.join().unwrap();
}

#[test]
fn file_client_rejects_directories_oversized_sources_and_stale_parents() {
    let temp = Temp::new();
    let source = temp.0.join("source");
    fs::write(&source, vec![0; solidcraft_pdm::MAX_CONTENT + 1]).unwrap();
    let client = Client::new(0, token());
    assert!(matches!(client.check_in_file("part".into(), None, &source, vec![]), Err(Error::Invalid(_))));
    assert!(matches!(client.check_in_file("part".into(), None, &temp.0, vec![]), Err(Error::Invalid(_))));
    assert_eq!(fs::metadata(source).unwrap().len(), solidcraft_pdm::MAX_CONTENT as u64 + 1);
    let mut store = Store::open(&temp.0.join("store")).unwrap();
    store.check_in("part".into(), None, b"one".to_vec(), vec![]).unwrap();
    let listener = bind_loopback(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        serve_connection(&mut store, stream, &token()).unwrap();
        assert_eq!(store.list(None).unwrap().len(), 1);
    });
    fs::write(temp.0.join("small"), b"two").unwrap();
    let result = Client::new(port, token()).check_in_file("part".into(), None, &temp.0.join("small"), vec![]);
    assert!(matches!(result, Err(Error::Server(code)) if code == "conflict"));
    server.join().unwrap();
}

#[test]
fn dependency_and_closure_caps_are_checked_before_filesystem_changes() {
    let temp = Temp::new();
    let nodes = fake_nodes();
    let template = nodes.get(&reference("part", 1)).unwrap().clone();
    let target = temp.0.join("too-many");
    let mut fetched = 0;
    assert!(
        retrieve(reference("p0", 1), &target, |r| {
            fetched += 1;
            let mut node = template.clone();
            node.0.reference = r.clone();
            node.0.dependencies = vec![reference(&format!("p{fetched}"), 1)];
            Ok(node)
        })
        .is_err()
    );
    assert_eq!(fetched, solidcraft_pdm::MAX_VERSIONS);
    assert!(!target.exists());
    let target = temp.0.join("too-many-edges");
    assert!(
        retrieve(reference("root", 1), &target, |r| {
            let mut node = template.clone();
            node.0.reference = r.clone();
            node.0.dependencies = (0..257).map(|n| reference(&format!("p{n}"), 1)).collect();
            Ok(node)
        })
        .is_err()
    );
    assert!(!target.exists());
}

#[test]
fn native_cli_checks_in_lists_and_retrieves_exact_versions_without_logging_token() {
    let temp = Temp::new();
    let store_path = temp.0.join("store");
    let mut store = Store::open(&store_path).unwrap();
    let listener = bind_loopback(0).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let server = std::thread::spawn(move || {
        for _ in 0..6 {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(&mut store, stream, &token()).unwrap();
        }
    });
    let part = temp.0.join("part.solidcraft");
    fs::write(&part, b"part version one").unwrap();
    let assembly = temp.0.join("assembly.solidcraft");
    fs::write(&assembly, b"assembly toy").unwrap();
    let deps = temp.0.join("dependencies.json");
    fs::write(&deps, br#"[{"document":"part","version":1}]"#).unwrap();
    let secret = "a1".repeat(32);
    let run = |arguments: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_solidcraft-pdm")).args(arguments).env(TOKEN_ENV, &secret).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(!String::from_utf8_lossy(&out.stdout).contains(&secret));
        assert!(!String::from_utf8_lossy(&out.stderr).contains(&secret));
        out
    };
    run(&["check-in", &port, "part", "-", part.to_str().unwrap()]);
    run(&["check-in", &port, "assembly", "-", assembly.to_str().unwrap(), deps.to_str().unwrap()]);
    fs::write(&part, b"part version two").unwrap();
    run(&["check-in", &port, "part", "1", part.to_str().unwrap()]);
    let listed = run(&["list", &port]);
    assert_eq!(serde_json::from_slice::<Vec<Version>>(&listed.stdout).unwrap().len(), 3);
    let destination = temp.0.join("retrieved");
    run(&["retrieve", &port, "assembly", "1", destination.to_str().unwrap()]);
    assert_eq!(fs::read(destination.join("snapshot/documents/d-part/v-1/content")).unwrap(), b"part version one");
    assert!(!destination.join("snapshot/documents/d-part/v-2").exists());
    server.join().unwrap();
}
