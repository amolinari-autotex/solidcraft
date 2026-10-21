//! Authenticated native client with loopback and verified HTTPS transports.
use crate::{AuthToken, AuthenticatedRequest, Error, MAX_CONTENT, Request, Response, Version, VersionRef, read_socket_frame, write_socket_frame};
use std::{
    fs::File,
    io::Read,
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
mod transfers;

#[derive(Clone)]
pub struct Client {
    transport: Transport,
    token: AuthToken,
}

#[derive(Clone)]
enum Transport {
    Loopback(u16),
    Https { endpoint: String, agent: ureq::Agent, server_id: Arc<Mutex<Option<String>>> },
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Client")
            .field(
                "transport",
                &match self.transport {
                    Transport::Loopback(_) => "loopback",
                    Transport::Https { .. } => "https",
                },
            )
            .field("token", &"[redacted]")
            .finish()
    }
}

/// Accept an HTTPS origin (optional trailing slash) or that origin with the
/// exact shared RPC path. Normalize the host's case; preserve an explicit port.
/// No userinfo, escaping, query, fragment or alternate path is accepted.
fn https_endpoint(endpoint: &str) -> Result<String, Error> {
    if endpoint.len() > 2048
        || !endpoint.is_ascii()
        || endpoint.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || endpoint.contains(['@', '\\', '?', '#', '%'])
    {
        return Err(Error::Invalid("HTTPS endpoint"));
    }
    let uri: ureq::http::Uri = endpoint.parse().map_err(|_| Error::Invalid("HTTPS endpoint"))?;
    if uri.scheme_str() != Some("https") || !matches!(uri.path(), "" | "/") && uri.path() != crate::HTTP_RPC_PATH {
        return Err(Error::Invalid("HTTPS endpoint origin or RPC path required"));
    }
    let authority = uri.authority().ok_or(Error::Invalid("HTTPS endpoint authority"))?;
    let host = authority.host();
    if host.is_empty() {
        return Err(Error::Invalid("HTTPS endpoint authority"));
    }
    let suffix = authority.as_str().strip_prefix(host).ok_or(Error::Invalid("HTTPS endpoint authority"))?;
    let port = if suffix.is_empty() {
        String::new()
    } else {
        let digits = suffix.strip_prefix(':').ok_or(Error::Invalid("HTTPS endpoint port"))?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Invalid("HTTPS endpoint port"));
        }
        let port: u16 = digits.parse().map_err(|_| Error::Invalid("HTTPS endpoint port"))?;
        if port == 0 {
            return Err(Error::Invalid("HTTPS endpoint port"));
        }
        format!(":{port}")
    };
    Ok(format!("https://{}{port}{}", host.to_ascii_lowercase(), crate::HTTP_RPC_PATH))
}

fn https_network_error() -> Error {
    // Never retain transport errors: they can contain remote-controlled URLs,
    // response text or headers. The caller gets a stable, credential-free error.
    Error::Network(std::io::Error::other("PDM HTTPS transport failed"))
}

fn authorization_header(token: &AuthToken) -> Result<ureq::http::HeaderValue, Error> {
    let mut authorization = ureq::http::HeaderValue::from_str(&format!("Bearer {}", token.0)).map_err(|_| Error::Invalid("HTTPS credential"))?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

fn server_identity(value: &str) -> Result<String, Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Invalid("HTTPS server identity"));
    }
    Ok(value.to_ascii_lowercase())
}

fn pin_server(cache: &Mutex<Option<String>>, identity: &str) -> Result<String, Error> {
    let identity = server_identity(identity)?;
    let mut pinned = cache.lock().map_err(|_| Error::Invalid("HTTPS identity state unavailable"))?;
    match &*pinned {
        Some(expected) if expected != &identity => Err(Error::Server("server_identity_mismatch".into())),
        Some(_) => Ok(identity),
        None => {
            *pinned = Some(identity.clone());
            Ok(identity)
        }
    }
}

fn relay_endpoint(origin: &str, tunnel: &str) -> Result<String, Error> {
    if tunnel.is_empty() || tunnel.len() > 64 || !tunnel.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
        return Err(Error::Invalid("HTTPS relay tunnel"));
    }
    let normalized = https_endpoint(origin)?;
    let uri: ureq::http::Uri = origin.parse().map_err(|_| Error::Invalid("HTTPS relay origin"))?;
    if !matches!(uri.path(), "" | "/") {
        return Err(Error::Invalid("HTTPS relay origin"));
    }
    let origin = normalized.strip_suffix(crate::HTTP_RPC_PATH).ok_or(Error::Invalid("HTTPS relay origin"))?;
    Ok(format!("{origin}/pdm/v2/tunnels/{tunnel}/rpc"))
}

fn ca_roots(ca_der: &[u8]) -> Result<ureq::tls::RootCerts, Error> {
    if ca_der.is_empty() || ca_der.len() > 64 * 1024 {
        return Err(Error::Invalid("HTTPS CA size"));
    }
    let mut validation = rustls::RootCertStore::empty();
    validation.add(rustls::pki_types::CertificateDer::from(ca_der.to_vec())).map_err(|_| Error::Invalid("HTTPS CA certificate"))?;
    Ok(ureq::tls::RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(ca_der).to_owned()]))
}

fn validate_identity(identity: crate::AuthenticatedIdentity, expected: &str) -> Result<crate::AuthenticatedIdentity, Error> {
    if server_identity(&identity.server_id)? != expected || identity.server_id != expected {
        return Err(Error::Server("server_identity_mismatch".into()));
    }
    let id = &identity.principal.id;
    // Match the configured-principal boundary and reject the legacy local-owner
    // identity, which is never a configured HTTPS principal.
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) || id == "owner" {
        return Err(Error::Invalid("authenticated principal identity"));
    }
    Ok(identity)
}

impl Client {
    /// Negotiate only the separate extension route on a direct pinned HTTPS peer.
    /// An old peer's 404 means unavailable, without sending a new legacy operation.
    pub fn capabilities(&self) -> Result<crate::administration::Capabilities, Error> {
        use crate::administration::{AdminResponse, CAPABILITIES_PATH, CAPABILITIES_PROTOCOL, CapabilityRequest};
        self.direct_extension_origin()?;
        let identity = self.authenticated_identity()?;
        let body = serde_json::to_vec(&CapabilityRequest { protocol: CAPABILITIES_PROTOCOL.into(), server_id: identity.server_id.clone() })?;
        match self.extension_exchange(CAPABILITIES_PATH, &body)? {
            AdminResponse::Capabilities { capabilities }
                if capabilities.server_id == identity.server_id && capabilities.protocol == CAPABILITIES_PROTOCOL =>
            {
                Ok(capabilities)
            }
            _ => Err(Error::Invalid("capabilities response")),
        }
    }

    /// The caller captures any new bearer in private native storage before
    /// submitting its verifier. This method never receives or returns that secret.
    pub fn admin(&self, request: crate::administration::AdminRequest) -> Result<crate::administration::AdminResponse, Error> {
        use crate::administration::{ADMIN_PATH, ADMIN_PROTOCOL, AdminEnvelope};
        let capabilities = self.capabilities()?;
        if !capabilities.features.users_admin_v1 {
            return Err(Error::Server("capability_unavailable".into()));
        }
        if !capabilities.permissions.iter().any(|permission| permission == "users.manage") {
            return Err(Error::Server("forbidden".into()));
        }
        let body = serde_json::to_vec(&AdminEnvelope { protocol: ADMIN_PROTOCOL.into(), server_id: capabilities.server_id, request })?;
        self.extension_exchange(ADMIN_PATH, &body)
    }

    fn direct_extension_origin(&self) -> Result<(&str, &ureq::Agent), Error> {
        match &self.transport {
            Transport::Https { endpoint, agent, .. } => endpoint
                .strip_suffix(crate::HTTP_RPC_PATH)
                .map(|origin| (origin, agent))
                .ok_or_else(|| Error::Server("capability_unavailable".into())),
            _ => Err(Error::Server("capability_unavailable".into())),
        }
    }

    fn extension_exchange(&self, path: &str, body: &[u8]) -> Result<crate::administration::AdminResponse, Error> {
        use crate::administration::{AdminResponse, MAX_BODY};
        if body.len() > MAX_BODY {
            return Err(Error::Invalid("administration request size"));
        }
        let (origin, agent) = self.direct_extension_origin()?;
        let mut response = agent
            .post(format!("{origin}{path}"))
            .header(ureq::http::header::AUTHORIZATION, authorization_header(&self.token)?)
            .header(ureq::http::header::CONTENT_TYPE, "application/json")
            .header(ureq::http::header::ACCEPT, "application/json")
            .send(body)
            .map_err(|_| https_network_error())?;
        let status = response.status().as_u16();
        let content_type =
            response.headers().get(ureq::http::header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).and_then(|value| value.split(';').next());
        if !content_type.is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json")) {
            return Err(Error::Invalid("administration response content type"));
        }
        let bytes = response.body_mut().with_config().limit(crate::MAX_FRAME).read_to_vec().map_err(|_| https_network_error())?;
        let decoded: AdminResponse = match serde_json::from_slice(&bytes) {
            Ok(decoded) => decoded,
            Err(_) if status == 404 => return Err(Error::Server("capability_unavailable".into())),
            Err(_) if status == 503 => return Err(Error::Server("storage_error".into())),
            Err(_) => return Err(Error::Invalid("administration response JSON")),
        };
        if decoded.status() != status {
            return Err(Error::Invalid("administration response status"));
        }
        match decoded {
            AdminResponse::Error { code } => match code.as_str() {
                "invalid_request"
                | "unsupported_protocol"
                | "unauthorized"
                | "forbidden"
                | "not_found"
                | "storage_error"
                | "conflict"
                | "self_lockout"
                | "last_administrator"
                | "principal_exists"
                | "duplicate_credential"
                | "idempotency_conflict"
                | "capability_unavailable"
                | "quota"
                | "server_identity_mismatch" => Err(Error::Server(code)),
                _ => Err(Error::Invalid("administration response error code")),
            },
            response => Ok(response),
        }
    }

    pub fn new(port: u16, token: AuthToken) -> Self {
        Self { transport: Transport::Loopback(port), token }
    }

    /// Verify the peer through the platform certificate verifier. HTTPS only;
    /// redirects and environment/system proxies are disabled.
    pub fn https(endpoint: &str, token: AuthToken) -> Result<Self, Error> {
        Self::with_https_roots(endpoint, token, ureq::tls::RootCerts::PlatformVerifier)
    }

    /// Explicit private-CA trust for self-hosted deployments. This CA replaces
    /// platform roots; standard hostname, validity and chain checks stay enabled.
    pub fn https_with_ca(endpoint: &str, token: AuthToken, ca_der: &[u8]) -> Result<Self, Error> {
        Self::with_https_roots(endpoint, token, ca_roots(ca_der)?)
    }

    /// Connect through the fixed user RPC route of a verified relay origin.
    /// The tunnel identifier cannot select another URL path or authority.
    pub fn https_relay(origin: &str, tunnel: &str, token: AuthToken) -> Result<Self, Error> {
        Self::from_https_endpoint(relay_endpoint(origin, tunnel)?, token, ureq::tls::RootCerts::PlatformVerifier)
    }

    pub fn https_relay_with_ca(origin: &str, tunnel: &str, token: AuthToken, ca_der: &[u8]) -> Result<Self, Error> {
        Self::from_https_endpoint(relay_endpoint(origin, tunnel)?, token, ca_roots(ca_der)?)
    }

    /// Bind a paired service identity before the first RPC. All clones share
    /// the immutable pin; neither this method nor discovery can retarget it.
    pub fn bind_server(self, expected_server_id: &str) -> Result<Self, Error> {
        match &self.transport {
            Transport::Https { server_id, .. } => {
                pin_server(server_id, expected_server_id)?;
            }
            Transport::Loopback(_) => return Err(Error::Invalid("server binding requires HTTPS")),
        }
        Ok(self)
    }

    fn with_https_roots(endpoint: &str, token: AuthToken, roots: ureq::tls::RootCerts) -> Result<Self, Error> {
        let endpoint = https_endpoint(endpoint)?;
        Self::from_https_endpoint(endpoint, token, roots)
    }

    fn from_https_endpoint(endpoint: String, token: AuthToken, roots: ureq::tls::RootCerts) -> Result<Self, Error> {
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(roots)
            .unversioned_rustls_crypto_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .https_only(true)
            .proxy(None)
            .http_status_as_error(false)
            .max_redirects(0)
            .max_response_header_size(16 * 1024)
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_global(Some(Duration::from_secs(30)))
            .user_agent("SolidCraft PDM")
            .build()
            .into();
        Ok(Self { transport: Transport::Https { endpoint, agent, server_id: Arc::new(Mutex::new(None)) }, token })
    }

    pub fn request(&self, request: Request) -> Result<Response, Error> {
        self.request_impl(request).map_err(|error| match error {
            Error::Io(error) => Error::Network(error),
            other => other,
        })
    }

    fn request_impl(&self, request: Request) -> Result<Response, Error> {
        let port = match &self.transport {
            Transport::Loopback(port) => *port,
            Transport::Https { endpoint, agent, server_id } => return self.https_request(endpoint, agent, server_id, request),
        };
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        let mut stream = TcpStream::connect_timeout(&address.into(), Duration::from_secs(5))?;
        let envelope = AuthenticatedRequest::new(&self.token, request);
        let bytes = serde_json::to_vec(&envelope)?;
        write_socket_frame(&mut stream, &bytes, Duration::from_secs(5))?;
        let response: Response = serde_json::from_slice(&read_socket_frame(&stream, Duration::from_secs(5))?)?;
        match response {
            Response::Error { code } => Err(Error::Server(code)),
            other => Ok(other),
        }
    }

    fn https_request(&self, endpoint: &str, agent: &ureq::Agent, cache: &Mutex<Option<String>>, request: Request) -> Result<Response, Error> {
        let cached = cache.lock().map_err(|_| Error::Invalid("HTTPS identity state unavailable"))?.clone();
        let expected = if let Some(expected) = cached {
            expected
        } else {
            let handshake = self.https_exchange(endpoint, agent, Request::ManagedCatalog, None)?;
            let Response::ManagedCatalog { catalog } = &handshake else {
                return Err(Error::Invalid("HTTPS identity discovery response"));
            };
            let identity = pin_server(cache, &catalog.server_id)?;
            if matches!(&request, Request::ManagedCatalog) {
                return Ok(handshake);
            }
            identity
        };
        let response = self.https_exchange(endpoint, agent, request, Some(expected.clone()))?;
        if let Response::ManagedCatalog { catalog } = &response
            && server_identity(&catalog.server_id)? != expected
        {
            return Err(Error::Server("server_identity_mismatch".into()));
        }
        Ok(response)
    }

    fn https_exchange(&self, endpoint: &str, agent: &ureq::Agent, request: Request, server_id: Option<String>) -> Result<Response, Error> {
        let body = serde_json::to_vec(&crate::RpcEnvelope { protocol: crate::PROTOCOL.into(), server_id, request })?;
        if body.len() as u64 > crate::MAX_FRAME {
            return Err(Error::Invalid("HTTPS request size"));
        }
        let mut response = agent
            .post(endpoint)
            .header(ureq::http::header::AUTHORIZATION, authorization_header(&self.token)?)
            .header(ureq::http::header::CONTENT_TYPE, "application/json")
            .header(ureq::http::header::ACCEPT, "application/json")
            .send(body.as_slice())
            .map_err(|_| https_network_error())?;
        if response.status() != ureq::http::StatusCode::OK {
            return Err(Error::Invalid("PDM HTTPS response status"));
        }
        let content_type =
            response.headers().get(ureq::http::header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).and_then(|value| value.split(';').next());
        if !content_type.is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json")) {
            return Err(Error::Invalid("PDM HTTPS response content type"));
        }
        let bytes = response.body_mut().with_config().limit(crate::MAX_FRAME).read_to_vec().map_err(|_| https_network_error())?;
        let response: Response = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid("PDM HTTPS response JSON"))?;
        match response {
            Response::Error { code } => match code.as_str() {
                "forbidden"
                | "conflict"
                | "not_found"
                | "referenced"
                | "transfer_required"
                | "invalid_request"
                | "integrity"
                | "storage_error"
                | "unsupported_protocol"
                | "server_identity_required"
                | "server_identity_mismatch"
                | "unauthorized" => Err(Error::Server(code)),
                _ => Err(Error::Invalid("PDM HTTPS response error code")),
            },
            other => Ok(other),
        }
    }

    /// Resolve the actual configured principal over verified HTTPS. Initial
    /// catalog discovery establishes the shared immutable server pin, and the
    /// identity operation itself is sent with that per-request atomic fence.
    pub fn authenticated_identity(&self) -> Result<crate::AuthenticatedIdentity, Error> {
        let Transport::Https { server_id, .. } = &self.transport else {
            return Err(Error::Invalid("authenticated identity requires HTTPS"));
        };
        let response = self.request(Request::Identity {})?;
        let expected = server_id
            .lock()
            .map_err(|_| Error::Invalid("HTTPS identity state unavailable"))?
            .clone()
            .ok_or(Error::Invalid("HTTPS server identity required"))?;
        match response {
            Response::Identity { identity } => validate_identity(identity, &expected),
            _ => Err(Error::Invalid("unexpected authenticated identity response")),
        }
    }

    pub fn managed_catalog(&self) -> Result<crate::managed::ManagedCatalog, Error> {
        match self.request(Request::ManagedCatalog)? {
            Response::ManagedCatalog { catalog } => Ok(catalog),
            _ => Err(Error::Invalid("unexpected managed catalog response")),
        }
    }

    pub fn managed_create(&self, logical_path: String) -> Result<crate::managed::CatalogEntry, Error> {
        match self.request(Request::ManagedCreate { logical_path })? {
            Response::ManagedDocument { entry } => Ok(entry),
            _ => Err(Error::Invalid("unexpected managed create response")),
        }
    }

    pub fn managed_create_new(&self, logical_path: String) -> Result<crate::managed::CatalogEntry, Error> {
        match self.request(Request::ManagedCreateNew { logical_path })? {
            Response::ManagedDocument { entry } => Ok(entry),
            _ => Err(Error::Invalid("unexpected exclusive managed create response")),
        }
    }

    /// A separate authenticated route preserves the original strict capability
    /// schema. Legacy route 404 is unsupported, never an authentication failure.
    pub fn namespace_capabilities(&self) -> Result<Option<crate::managed::NamespaceCapabilities>, Error> {
        let (origin, agent) = match self.direct_extension_origin() {
            Ok(pair) => pair,
            Err(Error::Server(code)) if code == "capability_unavailable" => return Ok(None),
            Err(error) => return Err(error),
        };
        let identity = self.authenticated_identity()?;
        let body = serde_json::to_vec(&crate::administration::CapabilityRequest {
            protocol: crate::managed::NAMESPACE_PROTOCOL.into(),
            server_id: identity.server_id.clone(),
        })?;
        let mut response = agent
            .post(format!("{origin}{}", crate::managed::NAMESPACE_CAPABILITIES_PATH))
            .header(ureq::http::header::AUTHORIZATION, authorization_header(&self.token)?)
            .header(ureq::http::header::CONTENT_TYPE, "application/json")
            .send(body.as_slice())
            .map_err(|_| https_network_error())?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        if response.status().as_u16() != 200 {
            return Err(Error::Invalid("namespace capability response status"));
        }
        if !response
            .headers()
            .get(ureq::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next().is_some_and(|v| v.trim() == "application/json"))
        {
            return Err(Error::Invalid("namespace capability content type"));
        }
        let bytes = response.body_mut().with_config().limit(16 * 1024).read_to_vec().map_err(|_| https_network_error())?;
        match serde_json::from_slice::<Response>(&bytes).map_err(|_| Error::Invalid("namespace capability response JSON"))? {
            Response::ManagedNamespaceCapabilities { capabilities }
                if capabilities.protocol == crate::managed::NAMESPACE_PROTOCOL
                    && capabilities.server_id == identity.server_id
                    && capabilities.principal.id == identity.principal.id =>
            {
                Ok(Some(capabilities))
            }
            Response::Error { code } if matches!(code.as_str(), "unauthorized" | "forbidden" | "server_identity_mismatch") => {
                Err(Error::Server(code))
            }
            _ => Err(Error::Invalid("namespace capability identity")),
        }
    }
    pub fn managed_metadata(&self, document: String) -> Result<crate::managed::NamespaceMetadata, Error> {
        match self.request(Request::ManagedMetadata { document })? {
            Response::ManagedMetadata { metadata } => Ok(metadata),
            _ => Err(Error::Invalid("unexpected namespace metadata response")),
        }
    }
    pub fn namespace_catalog(&self) -> Result<Vec<crate::managed::NamespaceMetadata>, Error> {
        match self.request(Request::ManagedNamespaceCatalog {})? {
            Response::ManagedNamespaceCatalog { entries } => Ok(entries),
            _ => Err(Error::Invalid("unexpected namespace catalog response")),
        }
    }
    pub fn managed_namespace(&self, input: crate::managed::NamespaceMutation) -> Result<crate::managed::NamespaceMetadata, Error> {
        match self.request(Request::ManagedNamespace { input })? {
            Response::ManagedMetadata { metadata } => Ok(metadata),
            _ => Err(Error::Invalid("unexpected namespace mutation response")),
        }
    }

    pub fn managed_checkout(&self, document: String, workspace: String, machine: String) -> Result<crate::managed::CheckoutGrant, Error> {
        match self.request(Request::ManagedCheckout { document, workspace, machine })? {
            Response::ManagedCheckout { grant } => Ok(grant),
            _ => Err(Error::Invalid("unexpected managed checkout response")),
        }
    }

    pub fn managed_cancel_checkout(
        &self,
        document: String,
        workspace: String,
        machine: String,
        checkout_token: String,
    ) -> Result<crate::managed::CatalogEntry, Error> {
        match self.request(Request::ManagedCancelCheckout { document, workspace, machine, checkout_token })? {
            Response::ManagedDocument { entry } => Ok(entry),
            _ => Err(Error::Invalid("unexpected managed cancel response")),
        }
    }

    pub fn managed_check_in(&self, input: crate::managed::ManagedCheckIn) -> Result<crate::managed::ManagedVersion, Error> {
        match self.request(Request::ManagedCheckIn { input })? {
            Response::ManagedCheckedIn { version } => Ok(version),
            _ => Err(Error::Invalid("unexpected managed check-in response")),
        }
    }

    pub fn managed_history(&self, document: String) -> Result<Vec<crate::managed::ManagedVersion>, Error> {
        match self.request(Request::ManagedHistory { document })? {
            Response::ManagedHistory { versions } => Ok(versions),
            _ => Err(Error::Invalid("unexpected managed history response")),
        }
    }

    pub fn list(&self, document: Option<String>) -> Result<Vec<Version>, Error> {
        match self.request(Request::List { document })? {
            Response::Listed { versions } => Ok(versions),
            _ => Err(Error::Invalid("unexpected list response")),
        }
    }

    pub fn check_in_file(&self, document: String, parent: Option<u64>, path: &Path, dependencies: Vec<VersionRef>) -> Result<Version, Error> {
        let content = read_file(path, MAX_CONTENT)?;
        match self.request(Request::CheckIn { document, parent, content, dependencies })? {
            Response::CheckedIn { version } => Ok(version),
            _ => Err(Error::Invalid("unexpected check-in response")),
        }
    }

    pub fn download(&self, reference: &VersionRef) -> Result<(Version, Vec<u8>), Error> {
        match self.request(Request::Download { reference: reference.clone() })? {
            Response::Downloaded { version, content } => Ok((version, content)),
            _ => Err(Error::Invalid("unexpected download response")),
        }
    }

    pub fn retrieve(&self, reference: VersionRef, destination: &Path) -> Result<crate::workspace::Snapshot, Error> {
        crate::workspace::retrieve(reference, destination, |reference| self.download(reference))
    }
}

/// Read only a regular source file, with a bound even if it grows while being read.
pub fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(Error::Invalid("source must be a regular file"));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::Invalid("source must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Invalid("source exceeds size limit"));
    }
    Ok(bytes)
}

impl Client {
    /// Read-only resume of an existing server reservation. There is deliberately
    /// no compatibility fallback to checkout, which could create new authority.
    pub fn managed_resume_checkout(&self, document: String, workspace: String, machine: String) -> Result<crate::managed::CheckoutGrant, Error> {
        match self.request(Request::ManagedResumeCheckout { document, workspace, machine })? {
            Response::ManagedCheckout { grant } => Ok(grant),
            _ => Err(Error::Invalid("unexpected managed resume checkout response")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod https_tests {
    #[test]
    fn legacy_namespace_probe_404_preserves_authenticated_identity() {
        use crate::http_listener::{Handler, HttpListener, HttpsConfig};
        use http_body_util::{BodyExt, Full, Limited};
        use hyper::{Response as HttpResponse, body::Bytes};
        use std::{sync::Arc, time::Duration};
        let handler: Handler = Arc::new(|request| {
            Box::pin(async move {
                if request.uri().path() == crate::managed::NAMESPACE_CAPABILITIES_PATH {
                    return HttpResponse::builder()
                        .status(404)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from_static(b"{}")))
                        .unwrap();
                }
                let body = Limited::new(request.into_body(), 64 * 1024).collect().await.unwrap().to_bytes();
                let envelope: crate::RpcEnvelope = serde_json::from_slice(&body).unwrap();
                let response = match envelope.request {
                    crate::Request::ManagedCatalog => {
                        crate::Response::ManagedCatalog { catalog: crate::managed::ManagedCatalog { server_id: "a".repeat(64), entries: vec![] } }
                    }
                    crate::Request::Identity {} => crate::Response::Identity {
                        identity: crate::AuthenticatedIdentity {
                            server_id: "a".repeat(64),
                            principal: crate::managed::Principal { id: "alice".into(), role: crate::managed::Role::Contributor },
                        },
                    },
                    _ => panic!("legacy peer received a new RPC operation"),
                };
                HttpResponse::builder()
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(serde_json::to_vec(&response).unwrap())))
                    .unwrap()
            })
        });
        let config = HttpsConfig::from_der(
            "127.0.0.1:0".parse().unwrap(),
            vec![include_bytes!("../tests/fixtures/pdm-https/server.der").to_vec()],
            include_bytes!("../tests/fixtures/pdm-https/server-key.der").to_vec(),
        )
        .unwrap();
        let server = HttpListener::start(config, handler, 2, Duration::from_secs(5)).unwrap();
        let client = super::Client::https_with_ca(
            &format!("https://{}", server.address()),
            crate::AuthToken::parse("a".repeat(64)).unwrap(),
            include_bytes!("../tests/fixtures/pdm-https/ca.der"),
        )
        .unwrap();
        assert!(client.namespace_capabilities().unwrap().is_none());
        assert_eq!(client.authenticated_identity().unwrap().principal.id, "alice");
        server.shutdown().unwrap();
    }
    #[test]
    fn unsupported_resume_never_falls_back_to_a_checkout_request() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (done, receive) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body: serde_json::Value = serde_json::from_slice(&read_socket_frame(&stream, Duration::from_secs(5)).unwrap()).unwrap();
            assert_eq!(body["request"]["operation"], "managed_resume_checkout");
            let response = serde_json::to_vec(&Response::Error { code: "invalid_request".into() }).unwrap();
            write_socket_frame(&mut stream, &response, Duration::from_secs(5)).unwrap();
            receive.recv_timeout(Duration::from_secs(10)).unwrap();
            listener.set_nonblocking(true).unwrap();
            assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
        });
        let client = Client::new(port, AuthToken::parse("ab".repeat(32)).unwrap());
        assert!(
            matches!(client.managed_resume_checkout("part".into(), "workspace".into(), "machine".into()), Err(Error::Server(code)) if code == "invalid_request")
        );
        done.send(()).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn resume_request_cannot_choose_the_authenticated_principal_or_supply_capabilities() {
        let original = serde_json::json!({"operation":"managed_resume_checkout","document":"part","workspace":"workspace","machine":"machine"});
        assert!(serde_json::from_value::<Request>(original.clone()).is_ok());
        for key in ["owner", "principal", "role", "token", "checkout_token"] {
            let mut request = original.clone();
            request[key] = serde_json::json!("private-value");
            assert!(serde_json::from_value::<Request>(request).is_err());
        }
        let request: Request = serde_json::from_value(original).unwrap();
        assert_eq!(format!("{request:?}"), "ManagedResumeCheckout");
    }

    use super::*;

    #[test]
    fn normalizes_https_origin_or_exact_rpc_path() {
        let expected = format!("https://example.test{}", crate::HTTP_RPC_PATH);
        assert_eq!(https_endpoint("https://EXAMPLE.test").unwrap(), expected);
        assert_eq!(https_endpoint("https://example.test/").unwrap(), expected);
        assert_eq!(https_endpoint(&expected).unwrap(), expected);
        assert_eq!(https_endpoint("https://localhost:04443").unwrap(), format!("https://localhost:4443{}", crate::HTTP_RPC_PATH));
        assert_eq!(https_endpoint("https://[::1]:4443").unwrap(), format!("https://[::1]:4443{}", crate::HTTP_RPC_PATH));
    }

    #[test]
    fn rejects_downgrades_credentials_queries_escapes_and_other_paths() {
        for endpoint in [
            "http://localhost",
            "//example.test",
            "example.test",
            "https://",
            "https://user:secret@example.test",
            "https://example.test?token=secret",
            "https://example.test#secret",
            "https://example.test/?",
            "https://example.test/other",
            "https://example.test//pdm/v2/rpc",
            "https://example.test/pdm/v2/rpc/",
            "https://example.test/%2e%2e",
            "https://%65xample.test",
            "https://example.test\\evil",
            "https://example.test\n",
            " https://example.test",
            "https://example.test:0",
            "https://example.test:65536",
            "https://example.test:",
            "https://example.test:invalid",
            "https://example.test:+443",
            "https://éxample.test",
        ] {
            assert!(https_endpoint(endpoint).is_err(), "accepted {endpoint:?}");
        }
        assert!(https_endpoint(&format!("https://{}", "a".repeat(2048))).is_err());
    }

    #[test]
    fn credential_is_sensitive_and_absent_from_debug_url_and_rpc_body() {
        let secret = "ab".repeat(32);
        let token = AuthToken::parse(secret.clone()).unwrap();
        let header = authorization_header(&token).unwrap();
        assert!(header.is_sensitive());
        assert_eq!(header.to_str().unwrap(), format!("Bearer {secret}"));
        assert!(!format!("{header:?}").contains(&secret));
        let client = Client::https("https://example.test", token).unwrap();
        assert!(!format!("{client:?}").contains(&secret));
        let body = serde_json::to_string(&crate::RpcEnvelope { protocol: crate::PROTOCOL.into(), server_id: None, request: Request::ManagedCatalog })
            .unwrap();
        assert!(!body.contains(&secret));
        assert!(!body.contains("token"));
        let error = Client::https(&format!("https://{secret}@example.test"), AuthToken::parse(secret.clone()).unwrap()).unwrap_err();
        assert!(!format!("{error:?}: {error}").contains(&secret));
        assert!(!format!("{:?}", https_network_error()).contains(&secret));
    }

    #[test]
    fn explicit_ca_rejects_empty_oversized_and_invalid_der() {
        for bytes in [Vec::new(), vec![0; 64 * 1024 + 1], b"invalid certificate".to_vec()] {
            let token = AuthToken::parse("00".repeat(32)).unwrap();
            assert!(Client::https_with_ca("https://localhost", token, &bytes).is_err());
        }
    }

    #[test]
    fn https_agent_enforces_direct_bounded_verified_transport() {
        let client = Client::https("https://example.test", AuthToken::parse("00".repeat(32)).unwrap()).unwrap();
        let Transport::Https { agent, .. } = client.transport else { panic!("HTTPS transport expected") };
        let config = agent.config();
        assert!(config.https_only());
        assert!(config.proxy().is_none());
        assert_eq!(config.max_redirects(), 0);
        assert_eq!(config.timeouts().global, Some(Duration::from_secs(30)));
        assert_eq!(config.timeouts().connect, Some(Duration::from_secs(5)));
    }

    #[test]
    fn relay_route_is_derived_only_from_origin_and_validated_tunnel() {
        assert_eq!(relay_endpoint("https://EXAMPLE.test:4443/", "office-1").unwrap(), "https://example.test:4443/pdm/v2/tunnels/office-1/rpc");
        for tunnel in ["", "../office", "office/rpc", "office?token=x", "office\r\n"] {
            assert!(relay_endpoint("https://example.test", tunnel).is_err());
        }
        assert!(relay_endpoint("https://example.test/pdm/v2/rpc", "office").is_err());
        let client = Client::https_relay("https://example.test", "office", AuthToken::parse("00".repeat(32)).unwrap()).unwrap();
        let Transport::Https { endpoint, .. } = client.transport else { panic!("HTTPS relay expected") };
        assert_eq!(endpoint, "https://example.test/pdm/v2/tunnels/office/rpc");
    }

    #[test]
    fn paired_identity_pin_is_shared_immutable_and_redacted() {
        let secret = "ab".repeat(32);
        let first = "11".repeat(32);
        let different = "22".repeat(32);
        let client = Client::https("https://example.test", AuthToken::parse(secret.clone()).unwrap()).unwrap();
        let alias = client.clone();
        let pinned = client.bind_server(&first).unwrap();
        assert!(alias.clone().bind_server(&first).is_ok());
        assert!(matches!(alias.bind_server(&different), Err(Error::Server(code)) if code == "server_identity_mismatch"));
        let debug = format!("{pinned:?}");
        assert!(!debug.contains(&secret));
        assert!(!debug.contains(&first));
        assert!(pinned.bind_server("invalid").is_err());
    }

    #[test]
    fn concurrent_clones_cannot_pin_different_service_identities() {
        let client = Client::https("https://example.test", AuthToken::parse("00".repeat(32)).unwrap()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let left = client.clone();
            let right = client.clone();
            let left_barrier = barrier.clone();
            let left = scope.spawn(move || {
                left_barrier.wait();
                left.bind_server(&"11".repeat(32))
            });
            let right = scope.spawn(move || {
                barrier.wait();
                right.bind_server(&"22".repeat(32))
            });
            [left.join().unwrap(), right.join().unwrap()]
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| matches!(result, Err(Error::Server(code)) if code == "server_identity_mismatch")).count(), 1);
    }

    #[test]
    fn authenticated_identity_rejects_unbound_owner_and_malformed_principals() {
        let expected = "11".repeat(32);
        let identity = |id: &str| crate::AuthenticatedIdentity {
            server_id: expected.clone(),
            principal: crate::managed::Principal { id: id.into(), role: crate::managed::Role::Contributor },
        };
        assert!(validate_identity(identity("alice"), &expected).is_ok());
        for invalid in ["", "owner", "alice\nadmin", "alice\0"] {
            assert!(validate_identity(identity(invalid), &expected).is_err());
        }
        assert!(validate_identity(identity(&"a".repeat(129)), &expected).is_err());
        assert!(matches!(validate_identity(identity("alice"), &"22".repeat(32)), Err(Error::Server(code)) if code == "server_identity_mismatch"));
        let mut invalid = identity("alice");
        invalid.server_id = "invalid server".into();
        assert!(validate_identity(invalid, &expected).is_err());
        let unknown_role = serde_json::json!({"server_id":expected,"principal":{"id":"alice","role":"superuser"}});
        assert!(serde_json::from_value::<crate::AuthenticatedIdentity>(unknown_role).is_err());
        let injected = serde_json::json!({"server_id":expected,"principal":{"id":"alice","role":"viewer","token":"secret"}});
        assert!(serde_json::from_value::<crate::AuthenticatedIdentity>(injected).is_err());
        let local = Client::new(1, AuthToken::parse("00".repeat(32)).unwrap());
        assert!(matches!(local.authenticated_identity(), Err(Error::Invalid("authenticated identity requires HTTPS"))));
    }
}
