//! Verified outbound HTTPS relay exchange. This client binds no listener and
//! stores no user or connector credential. Capabilities are supplied per call.
//! The relay remains trusted with forwarded user bearer credentials in memory.

use crate::{AuthToken, Error, MAX_FRAME, PROTOCOL, Request, Response, connector::RelayTransport, relay::ForwardJob};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const TUNNEL_PREFIX: &str = "/pdm/v2/tunnels";
const LEASE: &str = "x-pdm-job-lease";
const FORWARDED: &str = "x-pdm-forwarded-authorization";

#[derive(Clone)]
pub struct RelayHttpClient {
    origin: String,
    agent: ureq::Agent,
}
impl std::fmt::Debug for RelayHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RelayHttpClient([redacted])")
    }
}

#[derive(Serialize)]
struct PollRequest<'a> {
    protocol: &'a str,
    timeout_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PollResponse {
    protocol: String,
    job_id: String,
    request: Request,
}

fn unavailable() -> Error {
    Error::Network(std::io::Error::other("PDM relay HTTPS exchange failed"))
}

fn tunnel_id(id: &str) -> Result<(), Error> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
        return Err(Error::Invalid("relay tunnel identifier"));
    }
    Ok(())
}

fn secret_id(id: &str) -> Result<(), Error> {
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Invalid("relay job identifier or lease"));
    }
    Ok(())
}

fn origin(endpoint: &str) -> Result<String, Error> {
    if endpoint.len() > 2048
        || !endpoint.is_ascii()
        || endpoint.contains(['@', '\\', '?', '#', '%'])
        || endpoint.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(Error::Invalid("relay HTTPS origin"));
    }
    let uri: ureq::http::Uri = endpoint.parse().map_err(|_| Error::Invalid("relay HTTPS origin"))?;
    if uri.scheme_str() != Some("https") || !matches!(uri.path(), "" | "/") {
        return Err(Error::Invalid("relay HTTPS origin"));
    }
    let authority = uri.authority().ok_or(Error::Invalid("relay HTTPS authority"))?;
    let host = authority.host();
    if host.is_empty() {
        return Err(Error::Invalid("relay HTTPS authority"));
    }
    let suffix = authority.as_str().strip_prefix(host).ok_or(Error::Invalid("relay HTTPS authority"))?;
    let port = if suffix.is_empty() {
        String::new()
    } else {
        let digits = suffix.strip_prefix(':').ok_or(Error::Invalid("relay HTTPS port"))?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Invalid("relay HTTPS port"));
        }
        let port: u16 = digits.parse().map_err(|_| Error::Invalid("relay HTTPS port"))?;
        if port == 0 {
            return Err(Error::Invalid("relay HTTPS port"));
        }
        format!(":{port}")
    };
    Ok(format!("https://{}{port}", host.to_ascii_lowercase()))
}

fn sensitive(value: &str) -> Result<ureq::http::HeaderValue, Error> {
    let mut value = ureq::http::HeaderValue::from_str(value).map_err(|_| Error::Invalid("relay authorization header"))?;
    value.set_sensitive(true);
    Ok(value)
}

fn single_header<'a>(response: &'a ureq::http::Response<ureq::Body>, name: &str) -> Result<&'a str, Error> {
    let mut values = response.headers().get_all(name).iter();
    let value = values.next().ok_or(Error::Invalid("relay response header"))?;
    if values.next().is_some() {
        return Err(Error::Invalid("duplicate relay response header"));
    }
    value.to_str().map_err(|_| Error::Invalid("relay response header"))
}

impl RelayHttpClient {
    pub fn https(endpoint: &str) -> Result<Self, Error> {
        Self::configured(endpoint, ureq::tls::RootCerts::PlatformVerifier)
    }

    /// Replace platform roots with an explicitly trusted CA; hostname, chain
    /// and validity verification remain enabled.
    pub fn https_with_ca(endpoint: &str, ca_der: &[u8]) -> Result<Self, Error> {
        if ca_der.is_empty() || ca_der.len() > 64 * 1024 {
            return Err(Error::Invalid("relay CA size"));
        }
        let mut validation = rustls::RootCertStore::empty();
        validation.add(rustls::pki_types::CertificateDer::from(ca_der.to_vec())).map_err(|_| Error::Invalid("relay CA certificate"))?;
        let certificate = ureq::tls::Certificate::from_der(ca_der).to_owned();
        Self::configured(endpoint, ureq::tls::RootCerts::new_with_certs(&[certificate]))
    }

    fn configured(endpoint: &str, roots: ureq::tls::RootCerts) -> Result<Self, Error> {
        let origin = origin(endpoint)?;
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(roots)
            .unversioned_rustls_crypto_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .https_only(true)
            .proxy(None)
            .http_status_as_error(false)
            .max_redirects(0)
            .max_response_header_size(16 * 1024)
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_global(Some(Duration::from_secs(15)))
            .user_agent("SolidCraft PDM connector")
            .build()
            .into();
        Ok(Self { origin, agent })
    }

    fn post(&self, path: &str, capability: &AuthToken, bytes: &[u8], lease: Option<&str>) -> Result<ureq::http::Response<ureq::Body>, Error> {
        if bytes.len() as u64 > MAX_FRAME {
            return Err(Error::Invalid("relay request size"));
        }
        let mut request = self
            .agent
            .post(format!("{}{path}", self.origin))
            .header(ureq::http::header::AUTHORIZATION, sensitive(&format!("Bearer {}", capability.0))?)
            .header(ureq::http::header::CONTENT_TYPE, "application/json")
            .header(ureq::http::header::ACCEPT, "application/json");
        if let Some(lease) = lease {
            request = request.header(LEASE, sensitive(lease)?);
        }
        request.send(bytes).map_err(|_| unavailable())
    }

    fn check_status(status: ureq::http::StatusCode, expected: ureq::http::StatusCode) -> Result<(), Error> {
        if status == expected {
            return Ok(());
        }
        match status.as_u16() {
            401 | 403 => Err(Error::Forbidden),
            404 => Err(Error::NotFound),
            409 => Err(Error::Conflict),
            _ => Err(Error::Invalid("relay HTTPS response status")),
        }
    }
}

impl RelayTransport for RelayHttpClient {
    fn poll(&self, tunnel: &str, capability: &AuthToken, timeout: Duration) -> Result<Option<ForwardJob>, Error> {
        tunnel_id(tunnel)?;
        if timeout > Duration::from_secs(5) {
            return Err(Error::Invalid("relay poll timeout"));
        }
        let timeout_ms = u64::try_from(timeout.as_millis()).map_err(|_| Error::Invalid("relay poll timeout"))?;
        let bytes = serde_json::to_vec(&PollRequest { protocol: PROTOCOL, timeout_ms })?;
        let mut response = self.post(&format!("{TUNNEL_PREFIX}/{tunnel}/poll"), capability, &bytes, None)?;
        if response.status() == ureq::http::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        Self::check_status(response.status(), ureq::http::StatusCode::OK)?;
        let lease = single_header(&response, LEASE)?.to_owned();
        secret_id(&lease)?;
        let credential = single_header(&response, FORWARDED)?.strip_prefix("Bearer ").ok_or(Error::Invalid("relay forwarded authorization"))?;
        // Parsing failure must not expose the remote-controlled header value.
        let credential = AuthToken::parse(credential.to_owned()).map_err(|_| Error::Invalid("relay forwarded credential"))?;
        let content_type = single_header(&response, "content-type")?.split(';').next().unwrap_or_default();
        if !content_type.trim().eq_ignore_ascii_case("application/json") {
            return Err(Error::Invalid("relay response content type"));
        }
        let bytes = response.body_mut().with_config().limit(MAX_FRAME).read_to_vec().map_err(|_| unavailable())?;
        let wire: PollResponse = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid("relay poll JSON"))?;
        if wire.protocol != PROTOCOL {
            return Err(Error::Invalid("relay protocol"));
        }
        secret_id(&wire.job_id)?;
        Ok(Some(ForwardJob::from_parts(wire.job_id, lease, credential, wire.request)?))
    }

    fn complete(&self, tunnel: &str, capability: &AuthToken, id: &str, lease: &str, response: Response) -> Result<(), Error> {
        tunnel_id(tunnel)?;
        secret_id(id)?;
        secret_id(lease)?;
        let bytes = serde_json::to_vec(&response)?;
        let response = self.post(&format!("{TUNNEL_PREFIX}/{tunnel}/complete/{id}"), capability, &bytes, Some(lease))?;
        Self::check_status(response.status(), ureq::http::StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    #[test]
    fn origin_and_job_validation_reject_path_and_header_injection() {
        assert_eq!(origin("https://EXAMPLE.test:04443/").unwrap(), "https://example.test:4443");
        for value in [
            "http://localhost",
            "https://user@localhost",
            "https://localhost/path",
            "https://localhost?x=y",
            "https://localhost#x",
            "https://localhost\\x",
            "https://localhost:0",
            "https://localhost:65536",
            "https://localhost:",
            "https://localhost\r\n",
        ] {
            assert!(origin(value).is_err());
        }
        for value in ["../tunnel", "tunnel/name", "tunnel\r\n"] {
            assert!(tunnel_id(value).is_err());
        }
        assert!(secret_id(&"aa".repeat(32)).is_ok());
        assert!(secret_id(&"z".repeat(64)).is_err());
        assert!(secret_id("short").is_err());
    }
    #[test]
    fn secrets_are_sensitive_and_client_configuration_is_direct_verified_bounded() {
        let secret = "ab".repeat(32);
        let header = sensitive(&format!("Bearer {secret}")).unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains(&secret));
        let client = RelayHttpClient::https("https://localhost").unwrap();
        assert!(!format!("{client:?}").contains(&secret));
        assert!(client.agent.config().https_only());
        assert!(client.agent.config().proxy().is_none());
        assert_eq!(client.agent.config().max_redirects(), 0);
        assert_eq!(client.agent.config().max_response_header_size(), 16 * 1024);
        assert_eq!(client.agent.config().timeouts().global, Some(Duration::from_secs(15)));
        assert!(RelayHttpClient::https_with_ca("https://localhost", b"invalid").is_err());
    }

    #[test]
    fn invalid_scope_timeout_and_lease_fail_before_network() {
        let client = RelayHttpClient::https("https://localhost:1").unwrap();
        let capability = AuthToken::parse("ab".repeat(32)).unwrap();
        assert!(matches!(client.poll("../office", &capability, Duration::ZERO), Err(Error::Invalid(_))));
        assert!(matches!(client.poll("office", &capability, Duration::from_secs(6)), Err(Error::Invalid(_))));
        assert!(matches!(
            client.complete("office", &capability, "invalid", &"aa".repeat(32), Response::Error { code: "conflict".into() }),
            Err(Error::Invalid(_))
        ));
    }
}
