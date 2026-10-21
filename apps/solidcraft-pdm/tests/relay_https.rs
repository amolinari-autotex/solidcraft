//! Two disposable HTTPS listeners; the connector opens only outbound connections.
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, PROTOCOL, Request, Response, Store,
    connector::{Connector, ConnectorOutcome, RelayTransport},
    http_server::HttpsServer,
    relay::{Relay, TunnelConfig},
    relay_client::RelayHttpClient,
    relay_http::{HttpsConfig, RelayHttpServer},
};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
const CA: &[u8] = include_bytes!("fixtures/pdm-https/ca.der");
const CERT: &[u8] = include_bytes!("fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("fixtures/pdm-https/server-key.der");
const USER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CAP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("pdm-relay-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn token(value: &str) -> AuthToken {
    AuthToken::parse(value.into()).unwrap()
}
fn config() -> HttpsConfig {
    HttpsConfig::from_der("127.0.0.1:0".parse().unwrap(), vec![CERT.to_vec()], KEY.to_vec()).unwrap()
}
fn service_config() -> solidcraft_pdm::http_server::HttpsConfig {
    solidcraft_pdm::http_server::HttpsConfig::from_der("127.0.0.1:0".parse().unwrap(), vec![CERT.to_vec()], KEY.to_vec()).unwrap()
}
fn wire(address: SocketAddr, path: &str, credential: &str, body: &[u8]) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(CA)).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection = rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let socket = TcpStream::connect(address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut tls = rustls::StreamOwned::new(connection, socket);
    tls.write_all(format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).unwrap();
    tls.write_all(body).unwrap();
    let mut bytes = Vec::new();
    let _ = tls.read_to_end(&mut bytes);
    String::from_utf8(bytes).unwrap()
}
#[test]
fn outbound_connector_preserves_authoritative_user_permissions_over_two_https_hops() {
    let root = Temp::new();
    fs::write(
        root.0.join("managed-principals.json"),
        serde_json::to_vec(
            &serde_json::json!([{"principal":{"id":"reader","role":"viewer"},"token_sha256":format!("{:x}",Sha256::digest(USER.as_bytes()))}]),
        )
        .unwrap(),
    )
    .unwrap();
    let mut store = Store::open(&root.0).unwrap();
    let server_id = match store.execute(Request::ManagedCatalog) {
        Response::ManagedCatalog { catalog } => catalog.server_id,
        other => panic!("{other:?}"),
    };
    let service = HttpsServer::start(store, service_config()).unwrap();
    let relay = Relay::new(vec![TunnelConfig::new("office", &server_id, &format!("{:x}", Sha256::digest(CAP.as_bytes()))).unwrap()]).unwrap();
    let gateway = RelayHttpServer::start(relay, config()).unwrap();
    let relay_client = RelayHttpClient::https_with_ca(&format!("https://127.0.0.1:{}", gateway.address().port()), CA).unwrap();
    let connector = Connector::with_ca("office", token(CAP), &server_id, &format!("https://127.0.0.1:{}", service.address().port()), CA).unwrap();
    for (identity, expected) in [(None, "server_identity_required"), (Some("0".repeat(64)), "server_identity_mismatch")] {
        let body = serde_json::to_vec(&serde_json::json!({"protocol":PROTOCOL,"server_id":identity,"request":Request::ManagedCreate { logical_path:"parts/stale.solidcraft".into() }})).unwrap();
        let response = wire(gateway.address(), "/pdm/v2/tunnels/office/rpc", USER, &body);
        assert!(response.starts_with("HTTP/1.1 200"));
        let response: Response = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert!(matches!(response,Response::Error{code} if code==expected));
        // A prequeue fence must not leave work for the connector to execute.
        assert!(relay_client.poll("office", &token(CAP), Duration::ZERO).unwrap().is_none());
    }
    for (credential, request, expected) in [
        (USER, Request::ManagedCatalog, "catalog"),
        (USER, Request::ManagedCreate { logical_path: "parts/blocked.solidcraft".into() }, "forbidden"),
        (CAP, Request::ManagedCatalog, "unauthorized"),
    ] {
        let address = gateway.address();
        let identity = if matches!(&request, Request::ManagedCatalog) { None } else { Some(server_id.as_str()) };
        let body = serde_json::to_vec(&serde_json::json!({"protocol":PROTOCOL,"server_id":identity,"request":request})).unwrap();
        let caller = std::thread::spawn(move || wire(address, "/pdm/v2/tunnels/office/rpc", credential, &body));
        assert_eq!(connector.run_once(&relay_client, Duration::from_secs(5)).unwrap(), ConnectorOutcome::Completed);
        let response = caller.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let response: Response = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        match expected {
            "catalog" => assert!(matches!(response, Response::ManagedCatalog { .. })),
            code => assert!(matches!(response,Response::Error{code:actual} if actual==code)),
        }
    }
    assert!(relay_client.poll("office", &token(USER), Duration::ZERO).is_err());
    assert!(relay_client.poll("office", &token(CAP), Duration::ZERO).unwrap().is_none());
    gateway.shutdown().unwrap();
    service.shutdown().unwrap();
}
#[test]
fn gateway_rejects_malformed_routes_protocol_and_wrong_connector() {
    let server_id = "1".repeat(64);
    let relay = Relay::new(vec![TunnelConfig::new("office", &server_id, &format!("{:x}", Sha256::digest(CAP.as_bytes()))).unwrap()]).unwrap();
    let gateway = RelayHttpServer::start(relay, config()).unwrap();
    assert!(wire(gateway.address(), "/pdm/v2/tunnels/office/poll?x=1", CAP, b"{}").starts_with("HTTP/1.1 404"));
    assert!(wire(gateway.address(), "/pdm/v2/tunnels/office/poll", CAP, b"{\"protocol\":\"wrong\",\"timeout_ms\":0}").starts_with("HTTP/1.1 400"));
    assert!(
        wire(gateway.address(), "/pdm/v2/tunnels/office/poll", USER, format!("{{\"protocol\":\"{PROTOCOL}\",\"timeout_ms\":0}}").as_bytes())
            .starts_with("HTTP/1.1 401")
    );
}
