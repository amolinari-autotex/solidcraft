//! Disposable authenticated TLS regressions; no native credentials or delivered archives.
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Error, Store,
    administration::{AdminRequest, AdminResponse},
    backup_restore,
    client::Client,
    http_server::{HttpsConfig, HttpsServer},
    managed::Role,
    stream_io::StreamPolicy,
    transfers::{CHUNK_BYTES, TransferInput, TransferTarget},
};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::{Arc, Barrier},
    time::Duration,
};

const CA: &[u8] = include_bytes!("fixtures/pdm-https/ca.der");
const CERT: &[u8] = include_bytes!("fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("fixtures/pdm-https/server-key.der");
const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VIEWER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const LIMIT: u64 = 2 * CHUNK_BYTES;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn cached_protocol_session_reuses_context_but_revocation_invalidates_it() {
    let f = Fixture::new();
    let session = f.bob.transfer_session().unwrap();
    let caps = session.capabilities();
    let bytes = b"one retained chunk";
    let input = TransferInput {
        server_id: caps.server_id.clone(),
        recovery_epoch: caps.recovery_epoch,
        request_id: "cached-session".into(),
        target: TransferTarget::NewOnly { logical_path: "session.bin".into() },
        total_bytes: bytes.len() as u64,
        sha256: digest(bytes),
        dependencies: vec![],
        comment: String::new(),
    };
    let before = f.server.as_ref().unwrap().metrics();
    let begun = session.begin_transfer(input).unwrap();
    session.upload_chunk(&begun.transfer_id, 0, bytes, &digest(bytes)).unwrap();
    let after = f.server.as_ref().unwrap().metrics();
    assert_eq!(after.http_requests - before.http_requests, 2, "one begin and one chunk, no repeated identity/capability probes");
    assert_eq!(after.tls_connections, before.tls_connections, "SDK must reuse verified TLS connection");
    f.alice
        .admin(AdminRequest::SetRole { request_id: "session-demote".into(), expected_revision: f.revision(), id: "bob".into(), role: Role::Viewer })
        .unwrap();
    denied(session.transfer_status(&begun.transfer_id), "forbidden");
    denied(session.commit_transfer(&begun.transfer_id, "cached-session"), "transfer_session_invalidated");
    assert!(f.alice.managed_catalog().unwrap().entries.is_empty());
}

struct Fixture {
    server: Option<HttpsServer>,
    root: PathBuf,
    alice: Client,
    bob: Client,
    viewer: Client,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("binary-security-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&root).unwrap();
        let seed = root.join("seed");
        fs::create_dir(&seed).unwrap();
        let accounts: Vec<_> = [("alice", Role::Administrator, ALICE), ("bob", Role::Contributor, BOB), ("reader", Role::Viewer, VIEWER)]
            .into_iter()
            .map(|(id, role, token)| serde_json::json!({"principal":{"id":id,"role":role},"token_sha256":digest(token.as_bytes())}))
            .collect();
        fs::write(seed.join("managed-principals.json"), serde_json::to_vec(&accounts).unwrap()).unwrap();
        Store::open(&seed).unwrap().backup(&root.join("initial")).unwrap();
        let db = root.join("db");
        backup_restore::restore_backup_to_redb(&root.join("initial"), &db).unwrap();
        Store::open(&db).unwrap().initialize_streaming(StreamPolicy { version: 1, max_file_bytes: LIMIT, max_store_bytes: 4 * LIMIT }).unwrap();
        let config = HttpsConfig::from_der("127.0.0.1:0".parse().unwrap(), vec![CERT.to_vec()], KEY.to_vec()).unwrap();
        let server = HttpsServer::start(Store::open(&db).unwrap(), config).unwrap();
        let client =
            |token: &str| Client::https_with_ca(&format!("https://{}", server.address()), AuthToken::parse(token.into()).unwrap(), CA).unwrap();
        let alice = client(ALICE);
        let bob = client(BOB);
        let viewer = client(VIEWER);
        Self { server: Some(server), root, alice, bob, viewer }
    }
    fn address(&self) -> SocketAddr {
        self.server.as_ref().unwrap().address()
    }
    fn input(&self, client: &Client, path: &str, request_id: &str, bytes: &[u8]) -> TransferInput {
        let caps = client.transfer_capabilities().unwrap().unwrap();
        TransferInput {
            server_id: caps.server_id,
            recovery_epoch: caps.recovery_epoch,
            request_id: request_id.into(),
            target: TransferTarget::NewOnly { logical_path: path.into() },
            total_bytes: bytes.len() as u64,
            sha256: digest(bytes),
            dependencies: vec![],
            comment: "Synthetic security regression".into(),
        }
    }
    fn revision(&self) -> u64 {
        match self.alice.admin(AdminRequest::ListUsers {}).unwrap() {
            AdminResponse::Users { revision, .. } => revision,
            _ => panic!("unexpected users response"),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            let _ = server.shutdown();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn denied<T>(result: Result<T, Error>, code: &str) {
    match result {
        Err(Error::Server(actual)) => assert_eq!(actual, code),
        Err(error) => panic!("expected {code}, got {error}"),
        Ok(_) => panic!("expected rejection {code}"),
    }
}
fn upload(client: &Client, id: &str, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        client.upload_chunk(id, index as u64 * CHUNK_BYTES, chunk, &digest(chunk)).unwrap();
    }
}
fn tls(address: SocketAddr, name: &'static str) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(CA)).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection = rustls::ClientConnection::new(Arc::new(config), name.try_into().unwrap()).unwrap();
    let socket = TcpStream::connect(address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    rustls::StreamOwned::new(connection, socket)
}
fn raw_chunk(f: &Fixture, id: &str, offset: u64, bytes: &[u8], hash: &str) -> (u16, serde_json::Value) {
    let caps = f.bob.transfer_capabilities().unwrap().unwrap();
    let mut stream = tls(f.address(), "localhost");
    let headers = format!(
        "PUT /pdm/v1/transfers/{id}/chunks/{offset} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {BOB}\r\nX-Pdm-Server-Id: {}\r\nX-Pdm-Recovery-Epoch: {}\r\nContent-Type: application/octet-stream\r\nX-Chunk-Sha256: {hash}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        caps.server_id,
        caps.recovery_epoch,
        bytes.len()
    );
    stream.write_all(headers.as_bytes()).unwrap();
    // Admission may reject the request before the body reaches the server.
    let _ = stream.write_all(bytes);
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.split_whitespace().nth(1).unwrap().parse().unwrap(), serde_json::from_str(body).unwrap())
}
fn raw_begin(f: &Fixture, input: &TransferInput) -> (u16, serde_json::Value) {
    let body = serde_json::to_vec(input).unwrap();
    let mut stream = tls(f.address(), "localhost");
    let headers = format!(
        "POST /pdm/v1/transfers HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {BOB}\r\nX-Pdm-Server-Id: {}\r\nX-Pdm-Recovery-Epoch: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        input.server_id,
        input.recovery_epoch,
        body.len()
    );
    stream.write_all(headers.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.split_whitespace().nth(1).unwrap().parse().unwrap(), serde_json::from_str(body).unwrap())
}

#[test]
fn role_downgrade_and_credential_revocation_fence_every_upload_operation() {
    let f = Fixture::new();
    let bytes = vec![19; CHUNK_BYTES as usize + 1];
    let input = f.input(&f.bob, "security/revoked.bin", "revoked-upload", &bytes);
    let progress = f.bob.begin_transfer(input).unwrap();
    let first = &bytes[..CHUNK_BYTES as usize];
    f.bob.upload_chunk(&progress.transfer_id, 0, first, &digest(first)).unwrap();
    f.alice
        .admin(AdminRequest::SetRole { request_id: "demote-bob".into(), expected_revision: f.revision(), id: "bob".into(), role: Role::Viewer })
        .unwrap();
    let tail = &bytes[CHUNK_BYTES as usize..];
    denied(f.bob.upload_chunk(&progress.transfer_id, CHUNK_BYTES, tail, &digest(tail)), "forbidden");
    denied(f.bob.commit_transfer(&progress.transfer_id, "revoked-upload"), "forbidden");
    denied(f.bob.transfer_status(&progress.transfer_id), "forbidden");
    assert!(f.alice.managed_catalog().unwrap().entries.is_empty());
    f.alice
        .admin(AdminRequest::SetRole { request_id: "restore-bob".into(), expected_revision: f.revision(), id: "bob".into(), role: Role::Contributor })
        .unwrap();
    assert_eq!(f.bob.transfer_status(&progress.transfer_id).unwrap().offset, CHUNK_BYTES);
    f.alice
        .admin(AdminRequest::ReplaceCredential {
            request_id: "revoke-bob".into(),
            expected_revision: f.revision(),
            id: "bob".into(),
            credential_sha256: digest("d".repeat(64).as_bytes()),
        })
        .unwrap();
    denied(f.bob.upload_chunk(&progress.transfer_id, CHUNK_BYTES, tail, &digest(tail)), "unauthorized");
    denied(f.bob.commit_transfer(&progress.transfer_id, "revoked-upload"), "unauthorized");
    denied(f.bob.transfer_status(&progress.transfer_id), "unauthorized");
    assert!(f.alice.managed_catalog().unwrap().entries.is_empty());
}

#[test]
fn cross_principal_hijack_and_bad_chunks_preserve_the_original_offset() {
    let f = Fixture::new();
    let bytes = b"original bytes";
    let progress = f.bob.begin_transfer(f.input(&f.bob, "security/chunks.bin", "chunk-checks", bytes)).unwrap();
    denied(f.alice.transfer_status(&progress.transfer_id), "forbidden");
    denied(f.alice.upload_chunk(&progress.transfer_id, 0, bytes, &digest(bytes)), "forbidden");
    denied(f.alice.commit_transfer(&progress.transfer_id, "chunk-checks"), "forbidden");
    denied(f.alice.cancel_transfer(&progress.transfer_id), "forbidden");
    let (status, error) = raw_chunk(&f, &progress.transfer_id, 0, bytes, &"0".repeat(64));
    assert_eq!(status, 422);
    assert_eq!(error["code"], "checksum_mismatch");
    assert_eq!(f.bob.transfer_status(&progress.transfer_id).unwrap().offset, 0);
    let (status, _) = raw_chunk(&f, &progress.transfer_id, 1, bytes, &digest(bytes));
    assert!(matches!(status, 400 | 409));
    assert_eq!(f.bob.transfer_status(&progress.transfer_id).unwrap().offset, 0);
    upload(&f.bob, &progress.transfer_id, bytes);
    let version = f.bob.commit_transfer(&progress.transfer_id, "chunk-checks").unwrap();
    let mut output = Vec::new();
    f.alice.download_stream(&version.version.reference, &mut output).unwrap();
    assert_eq!(output, bytes);
}

#[test]
fn cancelling_the_document_lease_fences_a_fully_uploaded_check_in() {
    let f = Fixture::new();
    let entry = f.bob.managed_create("security/leased.bin".into()).unwrap();
    let grant = f.bob.managed_checkout(entry.document.clone(), "ws".into(), "machine".into()).unwrap();
    let bytes = b"lease-bound bytes";
    let mut input = f.input(&f.bob, "unused.bin", "lease-upload", bytes);
    input.target = TransferTarget::CheckIn {
        document: entry.document.clone(),
        workspace: "ws".into(),
        machine: "machine".into(),
        checkout_token: grant.token.clone(),
        parent: None,
    };
    let progress = f.bob.begin_transfer(input).unwrap();
    upload(&f.bob, &progress.transfer_id, bytes);
    f.bob.managed_cancel_checkout(entry.document.clone(), "ws".into(), "machine".into(), grant.token).unwrap();
    denied(f.bob.commit_transfer(&progress.transfer_id, "lease-upload"), "forbidden");
    denied(f.bob.transfer_status(&progress.transfer_id), "forbidden");
    assert!(f.alice.managed_history(entry.document.clone()).unwrap().is_empty());
    assert!(f.alice.managed_catalog().unwrap().entries.iter().find(|e| e.document == entry.document).unwrap().head.is_none());
}

#[test]
fn casefolded_new_only_contenders_publish_exactly_one_document() {
    let f = Fixture::new();
    let bytes = b"one winning upload";
    let a = f.alice.begin_transfer(f.input(&f.alice, "security/Shared.bin", "contender-a", bytes)).unwrap();
    let b = f.bob.begin_transfer(f.input(&f.bob, "Security/shared.bin", "contender-b", bytes)).unwrap();
    upload(&f.alice, &a.transfer_id, bytes);
    upload(&f.bob, &b.transfer_id, bytes);
    let barrier = Arc::new(Barrier::new(2));
    let left = f.alice.clone();
    let right = f.bob.clone();
    let gate = barrier.clone();
    let first = std::thread::spawn(move || {
        gate.wait();
        left.commit_transfer(&a.transfer_id, "contender-a")
    });
    let second = std::thread::spawn(move || {
        barrier.wait();
        right.commit_transfer(&b.transfer_id, "contender-b")
    });
    let results = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| matches!(r, Err(Error::Server(code)) if code == "conflict")).count(), 1);
    let catalog = f.alice.managed_catalog().unwrap();
    assert_eq!(catalog.entries.len(), 1);
    assert_eq!(f.alice.managed_history(catalog.entries[0].document.clone()).unwrap().len(), 1);
}

#[test]
fn exact_file_limit_succeeds_and_limit_plus_one_reports_both_sizes() {
    let f = Fixture::new();
    let bytes = vec![73; LIMIT as usize];
    let mut excessive = f.input(&f.bob, "security/too-large.bin", "too-large", &bytes);
    excessive.total_bytes = LIMIT + 1;
    let (status, error) = raw_begin(&f, &excessive);
    assert_eq!(status, 413);
    assert_eq!(error["code"], "file_too_large");
    assert_eq!(error["actual_bytes"], LIMIT + 1);
    assert_eq!(error["max_bytes"], LIMIT);
    assert!(matches!(f.bob.begin_transfer(excessive), Err(Error::FileTooLarge { actual, max }) if actual == LIMIT + 1 && max == LIMIT));
    assert!(f.alice.managed_catalog().unwrap().entries.is_empty());
    let progress = f.bob.begin_transfer(f.input(&f.bob, "security/exact.bin", "exact-limit", &bytes)).unwrap();
    upload(&f.bob, &progress.transfer_id, &bytes);
    let version = f.bob.commit_transfer(&progress.transfer_id, "exact-limit").unwrap();
    let mut output = Vec::new();
    f.viewer.download_stream(&version.version.reference, &mut output).unwrap();
    assert_eq!(output, bytes);
}

fn expect_rejection(f: &Fixture, token: &str, epoch: u64, path: &str, status: u16) {
    let caps = f.alice.transfer_capabilities().unwrap().unwrap();
    let mut stream = tls(f.address(), "localhost");
    // Deliberately send no body. Rejection must precede both body timeout and 100 Continue.
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nX-Pdm-Server-Id: {}\r\nX-Pdm-Recovery-Epoch: {epoch}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        caps.server_id
    );
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).expect("admission must reject before the two-second read deadline");
        head.push(byte[0]);
        assert!(head.len() < 8192);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with(&format!("HTTP/1.1 {status}")), "expected final rejection before 100 Continue: {head}");
}

#[test]
fn expect_continue_controls_reject_viewers_and_stale_epochs_before_body_polling() {
    let f = Fixture::new();
    let caps = f.bob.transfer_capabilities().unwrap().unwrap();
    let progress = f.bob.begin_transfer(f.input(&f.bob, "security/admission.bin", "admission", b"x")).unwrap();
    let commit = format!("/pdm/v1/transfers/{}/commit", progress.transfer_id);
    for path in ["/pdm/v1/transfers", commit.as_str()] {
        expect_rejection(&f, VIEWER, caps.recovery_epoch, path, 403);
        expect_rejection(&f, BOB, caps.recovery_epoch.wrapping_add(1), path, 409);
    }
    assert_eq!(f.bob.transfer_status(&progress.transfer_id).unwrap().offset, 0);
    assert!(f.alice.managed_catalog().unwrap().entries.is_empty());
}

#[test]
fn one_principal_cannot_hold_both_body_slots_while_another_principal_is_admitted() {
    let f = Fixture::new();
    let caps = f.alice.transfer_capabilities().unwrap().unwrap();
    let open_control = |token: &str| {
        let mut stream = tls(f.address(), "localhost");
        let headers = format!(
            "POST /pdm/v1/transfers HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nX-Pdm-Server-Id: {}\r\nX-Pdm-Recovery-Epoch: {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
            caps.server_id, caps.recovery_epoch
        );
        stream.write_all(headers.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).expect("body admission must answer before the two-second read deadline");
            head.push(byte[0]);
            assert!(head.len() < 8192);
        }
        (stream, String::from_utf8(head).unwrap())
    };
    // Leave the first body unread: the next request must be rejected by the
    // HTTP principal guard, independently of any persisted staging session.
    let (first, first_head) = open_control(ALICE);
    assert!(first_head.starts_with("HTTP/1.1 100"), "{first_head}");
    let (same_principal, rejected_head) = open_control(ALICE);
    assert!(rejected_head.starts_with("HTTP/1.1 429"), "same principal obtained a second body slot: {rejected_head}");
    let (other_principal, admitted_head) = open_control(BOB);
    assert!(admitted_head.starts_with("HTTP/1.1 100"), "different principal could not use the second slot: {admitted_head}");
    drop((first, same_principal, other_principal));
    assert!(f.alice.managed_catalog().unwrap().entries.is_empty());
}

#[test]
fn native_tls_rejects_system_untrusted_fixture_wrong_hostname_and_wrong_server_pin() {
    let f = Fixture::new();
    let origin = format!("https://{}", f.address());
    let system = Client::https(&origin, AuthToken::parse(BOB.into()).unwrap()).unwrap();
    assert!(system.transfer_capabilities().is_err(), "fixture CA must not be accepted through system roots");
    let wrong_pin = Client::https_with_ca(&origin, AuthToken::parse(BOB.into()).unwrap(), CA).unwrap().bind_server(&"0".repeat(64)).unwrap();
    denied(wrong_pin.transfer_capabilities(), "server_identity_mismatch");
    let mut wrong_hostname = tls(f.address(), "wrong.invalid");
    assert!(wrong_hostname.write_all(b"GET / HTTP/1.1\r\nHost: wrong.invalid\r\n\r\n").is_err());
    assert!(f.bob.transfer_capabilities().unwrap().unwrap().binary_transfer_v1);
    assert!(f.alice.managed_catalog().unwrap().entries.is_empty());
}
