//! Real reusable TLS connections; all archives and listeners belong to this test.
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Store,
    administration::AdminRequest,
    backup_restore,
    client::Client,
    http_server::{HttpsConfig, HttpsServer},
    stream_io::StreamPolicy,
};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

const CA: &[u8] = include_bytes!("fixtures/pdm-https/ca.der");
const CERT: &[u8] = include_bytes!("fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("fixtures/pdm-https/server-key.der");
const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
struct Fixture {
    server: Option<HttpsServer>,
    root: PathBuf,
    alice: Client,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("pdm-keepalive-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&root).unwrap();
        let seed = root.join("seed");
        fs::create_dir(&seed).unwrap();
        let accounts: Vec<_> = [("alice", "administrator", ALICE), ("bob", "contributor", BOB)].into_iter().map(|(id, role, token)| {
            serde_json::json!({"principal":{"id":id,"role":role},"token_sha256":format!("{:x}",Sha256::digest(token.as_bytes()))})
        }).collect();
        fs::write(seed.join("managed-principals.json"), serde_json::to_vec(&accounts).unwrap()).unwrap();
        Store::open(&seed).unwrap().backup(&root.join("backup")).unwrap();
        let db = root.join("db");
        backup_restore::restore_backup_to_redb(&root.join("backup"), &db).unwrap();
        Store::open(&db)
            .unwrap()
            .initialize_streaming(StreamPolicy { version: 1, max_file_bytes: 2 * 1024 * 1024, max_store_bytes: 8 * 1024 * 1024 })
            .unwrap();
        let server = HttpsServer::start(
            Store::open(&db).unwrap(),
            HttpsConfig::from_der("127.0.0.1:0".parse().unwrap(), vec![CERT.to_vec()], KEY.to_vec()).unwrap(),
        )
        .unwrap();
        let alice = Client::https_with_ca(&format!("https://{}", server.address()), AuthToken::parse(ALICE.into()).unwrap(), CA).unwrap();
        Self { server: Some(server), root, alice }
    }
    fn address(&self) -> SocketAddr {
        self.server.as_ref().unwrap().address()
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

struct Connection(rustls::StreamOwned<rustls::ClientConnection, TcpStream>);
impl Connection {
    fn new(address: SocketAddr) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(CA)).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connection = rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
        let socket = TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        Self(rustls::StreamOwned::new(connection, socket))
    }
    fn request(&mut self, token: &str, path: &str, headers: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
        let bytes = serde_json::to_vec(body).unwrap();
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}\r\n",
            bytes.len()
        );
        self.0.write_all(head.as_bytes()).unwrap();
        self.0.write_all(&bytes).unwrap();
        self.0.flush().unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            self.0.read_exact(&mut byte).expect("same TLS connection must remain usable");
            head.push(byte[0]);
            assert!(head.len() < 16 * 1024);
        }
        let head = String::from_utf8(head).unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        let length: usize = head
            .lines()
            .find_map(|line| {
                line.split_once(':').filter(|(key, _)| key.eq_ignore_ascii_case("content-length")).map(|(_, value)| value.trim().parse().unwrap())
            })
            .unwrap();
        assert!(length < 64 * 1024);
        let mut bytes = vec![0; length];
        self.0.read_exact(&mut bytes).unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    fn catalog(&mut self, token: &str) -> serde_json::Value {
        let (status, body) = self.request(
            token,
            solidcraft_pdm::HTTP_RPC_PATH,
            "",
            &serde_json::json!({"protocol":solidcraft_pdm::PROTOCOL,"server_id":null,"request":{"operation":"managed_catalog"}}),
        );
        assert_eq!(status, 200);
        body
    }
}

#[test]
fn two_rpc_requests_reuse_one_tls_connection_without_caching_authentication() {
    let f = Fixture::new();
    let mut wire = Connection::new(f.address());
    assert_eq!(wire.catalog(BOB)["result"], "managed_catalog");
    assert_eq!(wire.catalog(BOB)["result"], "managed_catalog");
    assert_eq!(wire.catalog(&"d".repeat(64))["code"], "unauthorized");
    assert_eq!(wire.catalog(BOB)["result"], "managed_catalog");
    let observed = f.server.as_ref().unwrap().metrics();
    assert_eq!(observed.http_requests, 4);
    assert_eq!(observed.tls_connections, 1, "count completed TLS handshakes, not requests");
}

#[test]
fn revoked_credentials_and_stale_recovery_epochs_fail_on_reused_connections() {
    let f = Fixture::new();
    let mut bob = Connection::new(f.address());
    assert_eq!(bob.catalog(BOB)["result"], "managed_catalog");
    f.alice
        .admin(AdminRequest::ReplaceCredential {
            request_id: "revoke-keepalive-bob".into(),
            expected_revision: 0,
            id: "bob".into(),
            credential_sha256: format!("{:x}", Sha256::digest("d".repeat(64).as_bytes())),
        })
        .unwrap();
    assert_eq!(bob.catalog(BOB)["code"], "unauthorized");
    let caps = f.alice.transfer_capabilities().unwrap().unwrap();
    let mut alice = Connection::new(f.address());
    assert_eq!(alice.catalog(ALICE)["result"], "managed_catalog");
    let headers = format!("X-Pdm-Server-Id: {}\r\nX-Pdm-Recovery-Epoch: {}\r\n", caps.server_id, caps.recovery_epoch.wrapping_add(1));
    let (status, body) = alice.request(ALICE, "/pdm/v1/transfers", &headers, &serde_json::json!({}));
    assert_eq!(status, 409);
    assert_eq!(body["code"], "recovery_epoch_mismatch");
}

#[test]
fn explicit_shutdown_closes_an_idle_keepalive_without_waiting_for_connection_lifetime() {
    let mut f = Fixture::new();
    let mut wire = Connection::new(f.address());
    assert_eq!(wire.catalog(BOB)["result"], "managed_catalog");
    let started = Instant::now();
    f.server.take().unwrap().shutdown().unwrap();
    assert!(started.elapsed() < Duration::from_secs(3), "idle persistent connection delayed shutdown");
    let mut byte = [0u8; 1];
    assert!(!matches!(wire.0.read(&mut byte),Ok(n) if n>0));
    assert!(Store::open(&f.root.join("db")).is_ok());
}

#[test]
fn idle_header_timeout_also_applies_between_keepalive_requests() {
    let f = Fixture::new();
    let mut wire = Connection::new(f.address());
    assert_eq!(wire.catalog(BOB)["result"], "managed_catalog");
    let started = Instant::now();
    let mut tail = Vec::new();
    let _ = wire.0.read_to_end(&mut tail);
    assert!(tail.is_empty() || tail.starts_with(b"HTTP/1.1 408"), "unexpected idle response");
    assert!(started.elapsed() < Duration::from_secs(7), "idle connection exceeded header deadline");
    assert!(started.elapsed() >= Duration::from_secs(3), "persistent connection was closed immediately instead of timing out");
}
