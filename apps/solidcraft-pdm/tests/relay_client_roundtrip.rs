//! Exercise the public user client over both real, disposable HTTPS hops.
//! Historical recovery is protocol-level republishing, not a native UI command.
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Error, Request, Response, Store,
    client::Client,
    connector::Connector,
    http_server::HttpsServer,
    managed::{ManagedCheckIn, ManagedVersion},
    relay::{Relay, TunnelConfig},
    relay_client::RelayHttpClient,
    relay_http::{HttpsConfig, RelayHttpServer},
};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const CA: &[u8] = include_bytes!("fixtures/pdm-https/ca.der");
const CERT: &[u8] = include_bytes!("fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("fixtures/pdm-https/server-key.der");
const USER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CAPABILITY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONTENT: &[u8] = b"two HTTPS hops, one authoritative version";
const CHANGED_CONTENT: &[u8] = b"changed content retained as immutable version two";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("pdm-public-relay-client-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Finished(Arc<AtomicBool>);
impl Drop for Finished {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn token(value: &str) -> AuthToken {
    AuthToken::parse(value.into()).unwrap()
}
fn tls() -> HttpsConfig {
    HttpsConfig::from_der("127.0.0.1:0".parse().unwrap(), vec![CERT.to_vec()], KEY.to_vec()).unwrap()
}
fn diagnostic(error: Error) -> String {
    format!("{error:?}")
}

fn user_cycle(origin: &str, expected_id: &str) -> Result<[ManagedVersion; 3], String> {
    // Discovery and every subsequent domain call use this public factory. No
    // raw HTTP helper, owner identity, direct store access or alternate route.
    let client = Client::https_relay_with_ca(origin, "office", token(USER), CA).map_err(diagnostic)?;
    let catalog = client.managed_catalog().map_err(diagnostic)?;
    if catalog.server_id != expected_id || !catalog.entries.is_empty() {
        return Err("unexpected initial catalog".into());
    }
    let identity = client.authenticated_identity().map_err(diagnostic)?;
    if identity.server_id != expected_id || identity.principal.id != "alice" || identity.principal.role != solidcraft_pdm::managed::Role::Contributor
    {
        return Err("relay login did not preserve the authenticated server principal and role".into());
    }
    let entry = client.managed_create("parts/toy.solidcraft".into()).map_err(diagnostic)?;
    let checkout = client.managed_checkout(entry.document.clone(), "workspace".into(), "desktop".into()).map_err(diagnostic)?;
    if checkout.entry.checkout.as_ref().map(|value| value.owner.as_str()) != Some("alice") {
        return Err("checkout did not use configured user".into());
    }
    let input = ManagedCheckIn {
        document: entry.document.clone(),
        workspace: "workspace".into(),
        machine: "desktop".into(),
        checkout_token: checkout.token,
        request_id: "public-relay-client-checkin".into(),
        parent: None,
        content: CONTENT.to_vec(),
        dependencies: vec![],
        comment: "Disposable roundtrip".into(),
    };
    let version = client.managed_check_in(input.clone()).map_err(diagnostic)?;
    let retried = client.managed_check_in(input).map_err(diagnostic)?;
    if retried != version || version.author != "alice" || version.version.reference.version != 1 {
        return Err("receipt or authoritative author mismatch".into());
    }
    let (metadata, bytes) = client.download(&version.version.reference).map_err(diagnostic)?;
    if metadata != version.version || bytes != CONTENT {
        return Err("download did not preserve published bytes".into());
    }
    let history = client.managed_history(entry.document.clone()).map_err(diagnostic)?;
    if history != vec![version.clone()] {
        return Err("retry published more than one version".into());
    }

    let checkout = client.managed_checkout(entry.document.clone(), "workspace".into(), "desktop".into()).map_err(diagnostic)?;
    let changed = client
        .managed_check_in(ManagedCheckIn {
            document: entry.document.clone(),
            workspace: "workspace".into(),
            machine: "desktop".into(),
            checkout_token: checkout.token,
            request_id: "public-relay-client-change".into(),
            parent: Some(1),
            content: CHANGED_CONTENT.to_vec(),
            dependencies: vec![],
            comment: "Changed version retained in history".into(),
        })
        .map_err(diagnostic)?;
    if changed.version.reference.version != 2 || changed.version.parent != Some(1) {
        return Err("changed content did not create version two".into());
    }
    // Fetch the historical payload and its actual recorded dependencies after
    // the working head has advanced. Restore publishes these as a new head;
    // neither the old version nor the intervening version is rewritten.
    let (historical_metadata, historical_bytes) = client.download(&version.version.reference).map_err(diagnostic)?;
    if historical_metadata != version.version || historical_bytes != CONTENT {
        return Err("historical version changed after publishing version two".into());
    }
    let checkout = client.managed_checkout(entry.document.clone(), "workspace".into(), "desktop".into()).map_err(diagnostic)?;
    if checkout.entry.head != Some(2) || checkout.entry.checkout.as_ref().and_then(|value| value.base_version) != Some(2) {
        return Err("restore checkout did not reserve current version two".into());
    }
    let resumed = client.managed_resume_checkout(entry.document.clone(), "workspace".into(), "desktop".into()).map_err(diagnostic)?;
    if resumed != checkout {
        return Err("relay reconnect changed the existing restore reservation".into());
    }
    let restore_input = ManagedCheckIn {
        document: entry.document.clone(),
        workspace: "workspace".into(),
        machine: "desktop".into(),
        checkout_token: checkout.token,
        request_id: "public-relay-client-restore-v1".into(),
        parent: Some(2),
        content: historical_bytes,
        dependencies: historical_metadata.dependencies,
        comment: "Republish historical version one as a new version".into(),
    };
    let restored = client.managed_check_in(restore_input.clone()).map_err(diagnostic)?;
    let restore_retry = client.managed_check_in(restore_input).map_err(diagnostic)?;
    if restored != restore_retry
        || restored.version.reference.version != 3
        || restored.version.parent != Some(2)
        || restored.version.sha256 != version.version.sha256
        || restored.version.dependencies != version.version.dependencies
        || restored.author != "alice"
    {
        return Err("historical restore or its receipt did not preserve version three".into());
    }
    // A reconnect after publication must never create a fresh reservation.
    match client.managed_resume_checkout(entry.document.clone(), "workspace".into(), "desktop".into()) {
        Err(Error::Server(code)) if code == "conflict" => {}
        _ => return Err("relay resume recreated authority after restore publication".into()),
    }
    let expected_history = [version, changed, restored];
    if client.managed_history(entry.document).map_err(diagnostic)? != expected_history {
        return Err("restore retry changed the three-version history".into());
    }
    for (version, content) in expected_history.iter().zip([CONTENT, CHANGED_CONTENT, CONTENT]) {
        let (metadata, bytes) = client.download(&version.version.reference).map_err(diagnostic)?;
        if metadata != version.version || bytes != content {
            return Err("restore changed an immutable payload or its dependencies".into());
        }
    }
    let catalog = client.managed_catalog().map_err(diagnostic)?;
    if catalog.entries.len() != 1 || catalog.entries[0].head != Some(3) || catalog.entries[0].checkout.is_some() {
        return Err("successful check-in did not release its checkout".into());
    }
    // A valid relay connector capability is deliberately absent from the local
    // service principal configuration. It must never become an owner fallback.
    let capability_as_user = Client::https_relay_with_ca(origin, "office", token(CAPABILITY), CA).map_err(diagnostic)?;
    match capability_as_user.managed_create("must-not-exist.solidcraft".into()) {
        Err(Error::Server(code)) if code == "unauthorized" => {}
        _ => return Err("connector capability acquired document authority".into()),
    }
    Ok(expected_history)
}

#[test]
fn public_relay_client_completes_domain_cycle_over_outbound_connector() {
    let root = Temp::new();
    let principals = serde_json::json!([{
        "principal":{"id":"alice","role":"contributor"},
        "token_sha256":format!("{:x}", Sha256::digest(USER.as_bytes())),
    }]);
    fs::write(root.0.join("managed-principals.json"), serde_json::to_vec(&principals).unwrap()).unwrap();
    let mut store = Store::open(&root.0).unwrap();
    let server_id = match store.execute(Request::ManagedCatalog) {
        Response::ManagedCatalog { catalog } => catalog.server_id,
        other => panic!("{other:?}"),
    };
    let service = HttpsServer::start(store, tls()).unwrap();
    let relay = Relay::new(vec![TunnelConfig::new("office", &server_id, &format!("{:x}", Sha256::digest(CAPABILITY.as_bytes()))).unwrap()]).unwrap();
    let gateway = RelayHttpServer::start(relay, tls()).unwrap();
    let relay_origin = format!("https://{}", gateway.address());
    let transport = RelayHttpClient::https_with_ca(&relay_origin, CA).unwrap();
    let connector = Connector::with_ca("office", token(CAPABILITY), &server_id, &format!("https://{}", service.address()), CA).unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let caller_finished = finished.clone();
    let caller_id = server_id.clone();
    let caller = std::thread::spawn(move || {
        let _finished = Finished(caller_finished);
        user_cycle(&relay_origin, &caller_id)
    });
    // No assertion/panic or early return until the caller has been joined and
    // both listeners shut down. Failure closes the gateway to wake the caller.
    // The complete cycle includes two TLS hops, checkout resume and immutable
    // history verification. Allow shared CI contention within a bounded overall
    // test budget; individual production protocol deadlines remain unchanged.
    let until = Instant::now() + Duration::from_secs(120);
    let mut connector_error = None;
    while !finished.load(Ordering::Acquire) && Instant::now() < until {
        if let Err(error) = connector.run_once(&transport, Duration::from_millis(100)) {
            connector_error = Some(diagnostic(error));
            break;
        }
    }
    let deadline_reached = !finished.load(Ordering::Acquire) && connector_error.is_none();
    let gateway_shutdown = gateway.shutdown();
    let caller_result = caller.join();
    let service_shutdown = service.shutdown();
    gateway_shutdown.unwrap();
    service_shutdown.unwrap();
    assert!(!deadline_reached, "bounded connector test deadline reached");
    assert!(connector_error.is_none(), "connector failed: {connector_error:?}");
    let versions = caller_result.unwrap().unwrap();
    // Reopen after service shutdown to verify the durable authoritative result,
    // independently of the relay's ephemeral delivery state and user cache.
    let mut reopened = Store::open(&root.0).unwrap();
    assert_eq!(
        reopened.list(Some(&versions[0].version.reference.document)).unwrap(),
        versions.iter().map(|value| value.version.clone()).collect::<Vec<_>>()
    );
    for (version, content) in versions.iter().zip([CONTENT, CHANGED_CONTENT, CONTENT]) {
        let (metadata, bytes) = reopened.download(&version.version.reference).unwrap();
        assert_eq!(metadata, version.version);
        assert_eq!(bytes, content);
    }
    assert_eq!(versions[2].version.parent, Some(2));
    assert_eq!(versions[2].version.sha256, versions[0].version.sha256);
    assert_eq!(versions[2].version.dependencies, versions[0].version.dependencies);
    match reopened.execute(Request::ManagedCatalog) {
        Response::ManagedCatalog { catalog } => {
            assert_eq!(catalog.server_id, server_id);
            assert_eq!(catalog.entries.len(), 1);
            assert_eq!(catalog.entries[0].head, Some(3));
            assert!(catalog.entries[0].checkout.is_none());
        }
        other => panic!("{other:?}"),
    }
}
