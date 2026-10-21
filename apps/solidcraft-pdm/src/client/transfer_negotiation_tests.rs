//! Native pinned-TLS compatibility regressions for additive chunk negotiation.
//! The synthetic listener has no store and owns only its ephemeral loopback port.
use super::Client;
use crate::{
    AuthToken, AuthenticatedIdentity, Error, HTTP_RPC_PATH, PROTOCOL, Request, Response, RpcEnvelope,
    administration::CapabilityRequest,
    http_listener::{Handler, HttpListener, HttpsConfig, Reply},
    managed::{Principal, Role},
    stream_io::StreamPolicy,
    transfers::{self, TransferCapabilities, TransferLimits, WireResponse},
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    StatusCode,
    body::Bytes,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde_json::Value;
use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const CA: &[u8] = include_bytes!("../../tests/fixtures/pdm-https/ca.der");
const CERTIFICATE: &[u8] = include_bytes!("../../tests/fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/pdm-https/server-key.der");
const PRINCIPAL: &str = "negotiation-author";
fn server_id() -> String {
    "a".repeat(64)
}
fn principal() -> Principal {
    Principal { id: PRINCIPAL.into(), role: Role::Contributor }
}
fn capabilities() -> TransferCapabilities {
    TransferCapabilities {
        protocol: transfers::PROTOCOL.into(),
        server_id: server_id(),
        recovery_epoch: 1,
        principal: principal(),
        binary_transfer_v1: true,
        can_upload: true,
        limits: Some(StreamPolicy { version: 1, max_file_bytes: 64 * transfers::CHUNK_BYTES, max_store_bytes: 20 * 1024 * 1024 * 1024 }),
        chunk_bytes: transfers::CHUNK_BYTES,
    }
}
fn limits(maximum: u64) -> TransferLimits {
    TransferLimits {
        protocol: transfers::LIMITS_PROTOCOL.into(),
        server_id: server_id(),
        recovery_epoch: 1,
        principal: principal(),
        max_chunk_bytes: maximum,
    }
}
#[derive(Clone)]
struct MockReply {
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
}
impl MockReply {
    fn wire(status: StatusCode, body: WireResponse) -> Result<Self, Error> {
        Ok(Self { status, content_type: "application/json", body: serde_json::to_vec(&body)? })
    }
    fn json(status: StatusCode, body: Value) -> Result<Self, Error> {
        Ok(Self { status, content_type: "application/json", body: serde_json::to_vec(&body)? })
    }
    fn response(&self) -> Reply {
        let mut reply = hyper::Response::new(Full::new(Bytes::copy_from_slice(&self.body)));
        *reply.status_mut() = self.status;
        reply.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(self.content_type));
        reply
    }
}
#[derive(Default)]
struct Counts {
    identity: AtomicUsize,
    caps: AtomicUsize,
    limits: AtomicUsize,
    unexpected: AtomicUsize,
}
struct Fixture {
    listener: HttpListener,
    client: Client,
    counts: Arc<Counts>,
}
impl Fixture {
    fn new(caps_reply: MockReply, limits_reply: MockReply) -> Result<Self, Error> {
        let token = "b".repeat(64); // Public synthetic fixture credential, no real account.
        let expected_header = format!("Bearer {token}");
        let counts = Arc::new(Counts::default());
        let observed = counts.clone();
        let identity_reply = MockReply {
            status: StatusCode::OK,
            content_type: "application/json",
            body: serde_json::to_vec(&Response::Identity { identity: AuthenticatedIdentity { server_id: server_id(), principal: principal() } })?,
        };
        let unauthorized = MockReply::wire(StatusCode::UNAUTHORIZED, WireResponse::error("unauthorized"))?;
        let invalid = MockReply::wire(StatusCode::BAD_REQUEST, WireResponse::error("invalid_request"))?;
        let handler: Handler = Arc::new(move |request| {
            let counts = observed.clone();
            let caps_reply = caps_reply.clone();
            let limits_reply = limits_reply.clone();
            let identity_reply = identity_reply.clone();
            let unauthorized = unauthorized.clone();
            let invalid = invalid.clone();
            let expected_header = expected_header.clone();
            Box::pin(async move {
                if request.headers().get(AUTHORIZATION).and_then(|value| value.to_str().ok()) != Some(expected_header.as_str()) {
                    return unauthorized.response();
                }
                let path = request.uri().path().to_owned();
                let body = match Limited::new(request.into_body(), transfers::CONTROL_BYTES).collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(_) => return invalid.response(),
                };
                match path.as_str() {
                    HTTP_RPC_PATH => {
                        counts.identity.fetch_add(1, Ordering::Relaxed);
                        let valid = serde_json::from_slice::<RpcEnvelope>(&body).is_ok_and(|envelope| {
                            envelope.protocol == PROTOCOL
                                && envelope.server_id.as_deref() == Some(server_id().as_str())
                                && matches!(envelope.request, Request::Identity {})
                        });
                        if valid {
                            identity_reply.response()
                        } else {
                            counts.unexpected.fetch_add(1, Ordering::Relaxed);
                            invalid.response()
                        }
                    }
                    transfers::CAPABILITIES_PATH => {
                        counts.caps.fetch_add(1, Ordering::Relaxed);
                        let valid = serde_json::from_slice::<CapabilityRequest>(&body)
                            .is_ok_and(|request| request.protocol == transfers::PROTOCOL && request.server_id == server_id());
                        if valid {
                            caps_reply.response()
                        } else {
                            counts.unexpected.fetch_add(1, Ordering::Relaxed);
                            invalid.response()
                        }
                    }
                    transfers::LIMITS_PATH => {
                        counts.limits.fetch_add(1, Ordering::Relaxed);
                        let valid = serde_json::from_slice::<CapabilityRequest>(&body)
                            .is_ok_and(|request| request.protocol == transfers::LIMITS_PROTOCOL && request.server_id == server_id());
                        if valid {
                            limits_reply.response()
                        } else {
                            counts.unexpected.fetch_add(1, Ordering::Relaxed);
                            invalid.response()
                        }
                    }
                    _ => {
                        counts.unexpected.fetch_add(1, Ordering::Relaxed);
                        invalid.response()
                    }
                }
            })
        });
        let config = HttpsConfig::from_der((Ipv4Addr::LOCALHOST, 0).into(), vec![CERTIFICATE.to_vec()], KEY.to_vec())?;
        let listener = HttpListener::start(config, handler, 4, Duration::from_secs(10))?;
        let client = Client::https_with_ca(&format!("https://{}", listener.address()), AuthToken::parse(token)?, CA)?.bind_server(&server_id())?;
        Ok(Self { listener, client, counts })
    }
    fn with_limits(reply: MockReply) -> Result<Self, Error> {
        Self::new(MockReply::wire(StatusCode::OK, WireResponse::Capabilities { capabilities: capabilities() })?, reply)
    }
    fn assert_route_counts(&self, limits_calls: usize) {
        assert_eq!(self.counts.identity.load(Ordering::Relaxed), 1, "server pin prevents catalog discovery");
        assert_eq!(self.counts.caps.load(Ordering::Relaxed), 1);
        assert_eq!(self.counts.limits.load(Ordering::Relaxed), limits_calls);
        assert_eq!(self.counts.unexpected.load(Ordering::Relaxed), 0);
    }
    fn shutdown(self) -> Result<(), Error> {
        self.listener.shutdown()
    }
}

#[test]
fn real_tls_missing_limits_route_is_the_only_error_fallback_to_one_mib() -> Result<(), Error> {
    // An old server need not return a new DTO or even JSON for an absent route.
    let fixture = Fixture::with_limits(MockReply {
        status: StatusCode::NOT_FOUND,
        content_type: "text/plain",
        body: b"old server has no limits route".to_vec(),
    })?;
    let session = fixture.client.transfer_session_with_chunk_bytes(transfers::HARD_CHUNK_BYTES)?;
    assert_eq!(session.chunk_bytes(), transfers::CHUNK_BYTES);
    assert_eq!(session.capabilities().chunk_bytes, transfers::CHUNK_BYTES);
    fixture.assert_route_counts(1);
    fixture.shutdown()?;
    for (status, code) in
        [(StatusCode::FORBIDDEN, "forbidden"), (StatusCode::UNAUTHORIZED, "unauthorized"), (StatusCode::SERVICE_UNAVAILABLE, "unavailable")]
    {
        let fixture = Fixture::with_limits(MockReply::wire(status, WireResponse::error(code))?)?;
        let result = fixture.client.transfer_session_with_chunk_bytes(transfers::HARD_CHUNK_BYTES);
        assert!(matches!(result, Err(Error::Server(actual)) if actual == code), "auth/server failure must not produce a fallback session");
        fixture.assert_route_counts(1);
        fixture.shutdown()?;
    }
    Ok(())
}

#[test]
fn real_tls_limits_select_four_mib_without_modifying_strict_v2_capabilities() -> Result<(), Error> {
    let fixture = Fixture::with_limits(MockReply::wire(StatusCode::OK, WireResponse::Limits { limits: limits(4 * transfers::CHUNK_BYTES) })?)?;
    let session = fixture.client.transfer_session_with_chunk_bytes(transfers::HARD_CHUNK_BYTES)?;
    assert_eq!(session.chunk_bytes(), 4 * transfers::CHUNK_BYTES);
    assert_eq!(session.capabilities().principal, principal());
    assert_eq!(session.capabilities().recovery_epoch, 1);
    fixture.assert_route_counts(1);
    fixture.shutdown()?;
    // A one-MiB session does not require the additive limits route at all.
    let fixture = Fixture::with_limits(MockReply::wire(StatusCode::FORBIDDEN, WireResponse::error("forbidden"))?)?;
    assert_eq!(fixture.client.transfer_session_with_chunk_bytes(transfers::CHUNK_BYTES)?.chunk_bytes(), transfers::CHUNK_BYTES);
    fixture.assert_route_counts(0);
    fixture.shutdown()?;
    Ok(())
}

#[test]
fn real_tls_limits_identity_protocol_epoch_and_hard_bound_mismatches_fail_closed() -> Result<(), Error> {
    let valid = limits(transfers::HARD_CHUNK_BYTES);
    let mut cases = Vec::new();
    let mut changed = valid.clone();
    changed.server_id = "c".repeat(64);
    cases.push(changed);
    let mut changed = valid.clone();
    changed.principal.id = "different-author".into();
    cases.push(changed);
    let mut changed = valid.clone();
    changed.principal.role = Role::Administrator;
    cases.push(changed);
    let mut changed = valid.clone();
    changed.recovery_epoch = 2;
    cases.push(changed);
    let mut changed = valid.clone();
    changed.protocol = "unknown-limits/1".into();
    cases.push(changed);
    let mut changed = valid.clone();
    changed.max_chunk_bytes = transfers::HARD_CHUNK_BYTES + 1;
    cases.push(changed);
    let mut changed = valid;
    changed.max_chunk_bytes = transfers::CHUNK_BYTES - 1;
    cases.push(changed);
    for limits in cases {
        let fixture = Fixture::with_limits(MockReply::wire(StatusCode::OK, WireResponse::Limits { limits })?)?;
        assert!(fixture.client.transfer_session_with_chunk_bytes(transfers::HARD_CHUNK_BYTES).is_err());
        fixture.assert_route_counts(1);
        fixture.shutdown()?;
    }
    Ok(())
}

#[test]
fn real_tls_malformed_limits_dtos_and_non_json_success_never_fall_back() -> Result<(), Error> {
    let valid = serde_json::to_value(WireResponse::Limits { limits: limits(transfers::HARD_CHUNK_BYTES) })?;
    let mut extra = valid.clone();
    extra.get_mut("limits").and_then(Value::as_object_mut).ok_or(Error::Integrity)?.insert("unexpected".into(), Value::Bool(true));
    let mut wrong_type = valid.clone();
    wrong_type
        .get_mut("limits")
        .and_then(Value::as_object_mut)
        .ok_or(Error::Integrity)?
        .insert("max_chunk_bytes".into(), Value::String("8388608".into()));
    let mut missing = valid;
    missing.get_mut("limits").and_then(Value::as_object_mut).ok_or(Error::Integrity)?.remove("principal");
    for value in [extra, wrong_type, missing, serde_json::json!({"result":"unknown","limits":{}})] {
        let fixture = Fixture::with_limits(MockReply::json(StatusCode::OK, value)?)?;
        assert!(fixture.client.transfer_session_with_chunk_bytes(transfers::HARD_CHUNK_BYTES).is_err());
        fixture.assert_route_counts(1);
        fixture.shutdown()?;
    }
    for reply in [
        MockReply { status: StatusCode::OK, content_type: "application/json", body: b"{truncated".to_vec() },
        MockReply { status: StatusCode::OK, content_type: "text/plain", body: b"unsupported".to_vec() },
    ] {
        let fixture = Fixture::with_limits(reply)?;
        assert!(fixture.client.transfer_session_with_chunk_bytes(transfers::HARD_CHUNK_BYTES).is_err());
        fixture.assert_route_counts(1);
        fixture.shutdown()?;
    }
    Ok(())
}

#[test]
fn real_tls_strict_v2_capability_shape_rejects_extra_field_before_limits() -> Result<(), Error> {
    let valid = serde_json::to_value(WireResponse::Capabilities { capabilities: capabilities() })?;
    let mut extra = valid.clone();
    extra
        .get_mut("capabilities")
        .and_then(Value::as_object_mut)
        .ok_or(Error::Integrity)?
        .insert("max_chunk_bytes".into(), Value::from(transfers::HARD_CHUNK_BYTES));
    let mut changed_chunk = valid.clone();
    changed_chunk
        .get_mut("capabilities")
        .and_then(Value::as_object_mut)
        .ok_or(Error::Integrity)?
        .insert("chunk_bytes".into(), Value::from(transfers::HARD_CHUNK_BYTES));
    let mut changed_server = valid.clone();
    changed_server
        .get_mut("capabilities")
        .and_then(Value::as_object_mut)
        .ok_or(Error::Integrity)?
        .insert("server_id".into(), Value::String("d".repeat(64)));
    let mut changed_principal = valid;
    changed_principal
        .get_mut("capabilities")
        .and_then(Value::as_object_mut)
        .ok_or(Error::Integrity)?
        .insert("principal".into(), serde_json::json!({"id":"other","role":"contributor"}));
    for value in [extra, changed_chunk, changed_server, changed_principal] {
        let fixture = Fixture::new(
            MockReply::json(StatusCode::OK, value)?,
            MockReply::wire(StatusCode::OK, WireResponse::Limits { limits: limits(transfers::HARD_CHUNK_BYTES) })?,
        )?;
        assert!(fixture.client.transfer_session_with_chunk_bytes(transfers::HARD_CHUNK_BYTES).is_err());
        fixture.assert_route_counts(0);
        fixture.shutdown()?;
    }
    Ok(())
}
