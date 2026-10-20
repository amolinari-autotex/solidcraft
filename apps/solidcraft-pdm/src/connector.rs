//! In-memory relay-to-service bridge foundation, not a deployed remote tunnel.
//!
//! Connector capability and service-user identity are separate. The configured
//! capability only polls/completes one relay tunnel; each service request uses
//! the forwarded user's credential and the service verifies its domain role.
//! The fixed service origin/trust are trusted connector configuration, never
//! selected by a forwarded request. Relay operators can see user credentials.

use crate::{
    AuthToken, Error, Response,
    client::Client,
    relay::{ForwardJob, Relay},
};
use std::time::Duration;

enum ServiceTrust {
    Platform,
    Certificate(Vec<u8>),
}

pub struct Connector {
    tunnel: String,
    capability: AuthToken,
    expected_server_id: String,
    service_endpoint: String,
    trust: ServiceTrust,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Connector([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorOutcome {
    Idle,
    Completed,
}

/// The connector only initiates outbound requests. Implementations exchange
/// tunnel-scoped jobs; they do not authorize any PDM document operation.
pub trait RelayTransport: Send + Sync {
    fn poll(&self, tunnel: &str, capability: &AuthToken, timeout: Duration) -> Result<Option<ForwardJob>, Error>;
    fn complete(&self, tunnel: &str, capability: &AuthToken, id: &str, lease: &str, response: Response) -> Result<(), Error>;
}

impl RelayTransport for Relay {
    fn poll(&self, tunnel: &str, capability: &AuthToken, timeout: Duration) -> Result<Option<ForwardJob>, Error> {
        Relay::poll(self, tunnel, capability, timeout)
    }
    fn complete(&self, tunnel: &str, capability: &AuthToken, id: &str, lease: &str, response: Response) -> Result<(), Error> {
        Relay::complete(self, tunnel, capability, id, lease, response)
    }
}

impl Connector {
    /// Use platform certificate verification for the fixed service origin.
    /// Construction validates configuration without performing network I/O.
    pub fn new(tunnel: &str, capability: AuthToken, expected_server_id: &str, service_endpoint: &str) -> Result<Self, Error> {
        Self::configured(tunnel, capability, expected_server_id, service_endpoint, ServiceTrust::Platform)
    }

    /// Trust this explicit service CA, retaining hostname/validity checks.
    pub fn with_ca(tunnel: &str, capability: AuthToken, expected_server_id: &str, service_endpoint: &str, ca_der: &[u8]) -> Result<Self, Error> {
        if ca_der.is_empty() || ca_der.len() > 64 * 1024 {
            return Err(Error::Invalid("connector service CA size"));
        }
        Self::configured(tunnel, capability, expected_server_id, service_endpoint, ServiceTrust::Certificate(ca_der.to_vec()))
    }

    fn configured(tunnel: &str, capability: AuthToken, expected_server_id: &str, service_endpoint: &str, trust: ServiceTrust) -> Result<Self, Error> {
        if expected_server_id.len() != 64 || !expected_server_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::Invalid("connector expected service identity"));
        }
        if service_endpoint.len() > 2048
            || tunnel.is_empty()
            || tunnel.len() > 64
            || !tunnel.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(Error::Invalid("connector tunnel"));
        }
        let connector = Self {
            tunnel: tunnel.into(),
            capability,
            expected_server_id: expected_server_id.to_ascii_lowercase(),
            service_endpoint: service_endpoint.into(),
            trust,
        };
        // Client construction only validates origin/CA and creates an agent; it
        // does not send the capability to the service. run_once supplies only
        // the job's user credential to the client that actually sends requests.
        connector.service_client(connector.capability.clone())?;
        Ok(connector)
    }

    fn service_client(&self, user_credential: AuthToken) -> Result<Client, Error> {
        let client = match &self.trust {
            ServiceTrust::Platform => Client::https(&self.service_endpoint, user_credential),
            ServiceTrust::Certificate(ca) => Client::https_with_ca(&self.service_endpoint, user_credential, ca),
        }?;
        client.bind_server(&self.expected_server_id)
    }

    /// Forward at most one job. A service transport/decoding failure leaves the
    /// relay job leased until its deadline or caller cancellation. It never
    /// changes checkout state or reports fabricated success. An acknowledged
    /// service write whose reply is lost remains ambiguous: reconcile/retry via
    /// the same authoritative request receipt, never assume it was rolled back.
    pub fn run_once(&self, relay: &impl RelayTransport, poll_timeout: Duration) -> Result<ConnectorOutcome, Error> {
        let Some(job) = relay.poll(&self.tunnel, &self.capability, poll_timeout)? else {
            return Ok(ConnectorOutcome::Idle);
        };
        let (id, lease, user_credential, request) = job.into_parts();
        let client = self.service_client(user_credential)?;
        // Bind the fixed endpoint to the identity accepted during pairing before
        // forwarding any operation. The client also carries this immutable pin
        // on every RPC; the service checks it atomically before dispatch.
        let result = match client.managed_catalog() {
            Ok(catalog) if catalog.server_id == self.expected_server_id => client.request(request),
            Ok(_) => return Err(Error::Invalid("connector service identity mismatch")),
            Err(error) => Err(error),
        };
        let response = match result {
            Ok(response) => response,
            Err(Error::Server(code)) if code == "server_identity_mismatch" => return Err(Error::Server(code)),
            Err(Error::Server(code)) => Response::Error { code },
            Err(error) => return Err(error),
        };
        // No domain operation occurs here: completion only delivers the actual
        // service response through the authenticated tunnel's one-use lease.
        relay.complete(&self.tunnel, &self.capability, &id, &lease, response)?;
        Ok(ConnectorOutcome::Completed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        Request, Store,
        http_server::{HttpsConfig, HttpsServer},
        managed::ManagedCheckIn,
        relay::TunnelConfig,
    };
    use std::{fs, net::TcpListener, path::PathBuf};

    const CA: &[u8] = include_bytes!("../tests/fixtures/pdm-https/ca.der");
    const CERT: &[u8] = include_bytes!("../tests/fixtures/pdm-https/server.der");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/pdm-https/server-key.der");
    const USER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CAPABILITY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("pdm-connector-{}", AuthToken::generate().unwrap()));
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
    fn server(temp: &Temp) -> HttpsServer {
        let users = serde_json::json!([{
            "principal":{"id":"alice", "role":"contributor"},
            "token_sha256":crate::digest(USER.as_bytes()),
        }]);
        fs::write(temp.0.join("managed-principals.json"), serde_json::to_vec(&users).unwrap()).unwrap();
        let tls = HttpsConfig::from_der("127.0.0.1:0".parse().unwrap(), vec![CERT.to_vec()], KEY.to_vec()).unwrap();
        HttpsServer::start(Store::open(&temp.0).unwrap(), tls).unwrap()
    }
    fn relay(server_id: &str) -> Relay {
        Relay::new(vec![TunnelConfig::new("office", server_id, &crate::digest(CAPABILITY.as_bytes())).unwrap()]).unwrap()
    }
    fn forward(relay: &Relay, connector: &Connector, credential: &str, request: Request) -> Response {
        let pending = relay.submit("office", token(credential), request, Duration::from_secs(10)).unwrap();
        assert_eq!(connector.run_once(relay, Duration::ZERO).unwrap(), ConnectorOutcome::Completed);
        pending.wait(Duration::ZERO).unwrap()
    }
    fn server_id(endpoint: &str) -> String {
        Client::https_with_ca(endpoint, token(USER), CA).unwrap().managed_catalog().unwrap().server_id
    }

    #[test]
    fn refuses_unsafe_configuration_before_polling() {
        let expected = crate::digest(b"expected paired service");
        assert!(Connector::new("office", token(CAPABILITY), &expected, "http://localhost").is_err());
        assert!(Connector::new("../office", token(CAPABILITY), &expected, "https://localhost").is_err());
        assert!(Connector::with_ca("office", token(CAPABILITY), &expected, "https://localhost", b"invalid CA").is_err());
        assert!(Connector::with_ca("office", token(CAPABILITY), &expected, "https://localhost", &vec![0; 64 * 1024 + 1]).is_err());
        assert!(Connector::new("office", token(CAPABILITY), "invalid identity", "https://localhost").is_err());
    }

    #[test]
    fn verified_service_roundtrip_preserves_user_authority_and_receipt() {
        let temp = Temp::new();
        let server = server(&temp);
        let relay = relay(&server_id(&format!("https://{}", server.address())));
        let endpoint = format!("https://{}", server.address());
        let connector = Connector::with_ca("office", token(CAPABILITY), &server_id(&endpoint), &endpoint, CA).unwrap();
        assert_eq!(connector.run_once(&relay, Duration::ZERO).unwrap(), ConnectorOutcome::Idle);
        let entry = match forward(&relay, &connector, USER, Request::ManagedCreate { logical_path: "parts/toy.solidcraft".into() }) {
            Response::ManagedDocument { entry } => entry,
            other => panic!("{other:?}"),
        };
        let grant = match forward(
            &relay,
            &connector,
            USER,
            Request::ManagedCheckout { document: entry.document.clone(), workspace: "workspace".into(), machine: "desktop".into() },
        ) {
            Response::ManagedCheckout { grant } => grant,
            other => panic!("{other:?}"),
        };
        let input = ManagedCheckIn {
            document: entry.document,
            workspace: "workspace".into(),
            machine: "desktop".into(),
            checkout_token: grant.token,
            request_id: "connector-write".into(),
            parent: None,
            content: b"toy bytes".to_vec(),
            dependencies: vec![],
            comment: "Toy".into(),
        };
        let version = match forward(&relay, &connector, USER, Request::ManagedCheckIn { input: input.clone() }) {
            Response::ManagedCheckedIn { version } => version,
            other => panic!("{other:?}"),
        };
        match forward(&relay, &connector, USER, Request::ManagedCheckIn { input }) {
            Response::ManagedCheckedIn { version: retry } => assert_eq!(retry, version),
            other => panic!("{other:?}"),
        }
        match forward(&relay, &connector, USER, Request::Download { reference: version.version.reference }) {
            Response::Downloaded { content, .. } => assert_eq!(content, b"toy bytes"),
            other => panic!("{other:?}"),
        }
        assert!(!format!("{connector:?}").contains(CAPABILITY));
        assert!(!format!("{connector:?}").contains(USER));
    }

    #[test]
    fn connector_capability_is_not_a_user_and_wrong_connector_cannot_poll() {
        let temp = Temp::new();
        let server = server(&temp);
        let relay = relay(&server_id(&format!("https://{}", server.address())));
        let endpoint = format!("https://{}", server.address());
        let valid = Connector::with_ca("office", token(CAPABILITY), &server_id(&endpoint), &endpoint, CA).unwrap();
        let wrong = Connector::with_ca("office", token(USER), &server_id(&endpoint), &endpoint, CA).unwrap();
        let pending = relay.submit("office", token(USER), Request::ManagedCatalog, Duration::from_secs(10)).unwrap();
        assert!(matches!(wrong.run_once(&relay, Duration::ZERO), Err(Error::Forbidden)));
        assert_eq!(valid.run_once(&relay, Duration::ZERO).unwrap(), ConnectorOutcome::Completed);
        assert!(matches!(pending.wait(Duration::ZERO).unwrap(), Response::ManagedCatalog { .. }));
        assert!(matches!(forward(&relay, &valid, CAPABILITY, Request::ManagedCreate { logical_path: "unauthorized.solidcraft".into() }),
            Response::Error { code } if code == "unauthorized"));
        match forward(&relay, &valid, USER, Request::ManagedCatalog) {
            Response::ManagedCatalog { catalog } => assert!(catalog.entries.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn failed_local_transport_never_releases_checkout_or_completes_job() {
        let temp = Temp::new();
        let server = server(&temp);
        let endpoint = format!("https://{}", server.address());
        let client = Client::https_with_ca(&endpoint, token(USER), CA).unwrap();
        let entry = client.managed_create("part.solidcraft".into()).unwrap();
        let grant = client.managed_checkout(entry.document.clone(), "workspace".into(), "desktop".into()).unwrap();
        let relay = relay(&server_id(&endpoint));
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable = format!("https://{}", unused.local_addr().unwrap());
        drop(unused);
        let connector = Connector::with_ca("office", token(CAPABILITY), &server_id(&endpoint), &unavailable, CA).unwrap();
        let pending = relay
            .submit(
                "office",
                token(USER),
                Request::ManagedCancelCheckout {
                    document: entry.document.clone(),
                    workspace: "workspace".into(),
                    machine: "desktop".into(),
                    checkout_token: grant.token.clone(),
                },
                Duration::from_secs(10),
            )
            .unwrap();
        assert!(matches!(connector.run_once(&relay, Duration::ZERO), Err(Error::Network(_))));
        // A leased failed request is not automatically retried, completed or
        // translated into a successful cancellation. The caller sees timeout.
        assert!(relay.poll("office", &token(CAPABILITY), Duration::ZERO).unwrap().is_none());
        assert!(pending.wait(Duration::ZERO).is_err());
        let catalog = client.managed_catalog().unwrap();
        let current = catalog.entries.iter().find(|item| item.document == entry.document).unwrap();
        assert_eq!(current.checkout, grant.entry.checkout);
        // Verify the retained capability through the read-only resume endpoint;
        // a second mutating checkout is deliberately a conflict.
        assert_eq!(client.managed_resume_checkout(entry.document, "workspace".into(), "desktop".into()).unwrap(), grant);
    }

    #[test]
    fn paired_identity_mismatch_prevents_create_at_another_valid_service() {
        let paired_root = Temp::new();
        let other_root = Temp::new();
        // Both stores deliberately use the same trusted certificate and user
        // token. TLS/user authentication alone cannot distinguish their IDs.
        let paired = server(&paired_root);
        let other = server(&other_root);
        let paired_endpoint = format!("https://{}", paired.address());
        let other_endpoint = format!("https://{}", other.address());
        let expected = server_id(&paired_endpoint);
        assert_ne!(expected, server_id(&other_endpoint));
        let connector = Connector::with_ca("office", token(CAPABILITY), &expected, &other_endpoint, CA).unwrap();
        let relay = relay(&expected);
        let pending = relay
            .submit("office", token(USER), Request::ManagedCreate { logical_path: "must-not-exist.solidcraft".into() }, Duration::from_secs(10))
            .unwrap();
        assert!(matches!(connector.run_once(&relay, Duration::ZERO), Err(Error::Server(code)) if code == "server_identity_mismatch"));
        assert!(pending.wait(Duration::ZERO).is_err());
        for endpoint in [&paired_endpoint, &other_endpoint] {
            assert!(Client::https_with_ca(endpoint, token(USER), CA).unwrap().managed_catalog().unwrap().entries.is_empty());
        }
    }
}
