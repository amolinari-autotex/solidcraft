//! HTTPS gateway for an outbound connector. The relay has no document store.
pub use crate::http_listener::HttpsConfig;
use crate::{
    AuthToken, Error, MAX_FRAME, PROTOCOL, Response, RpcEnvelope,
    http_listener::{Handler, HttpListener, Reply},
    relay::Relay,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, StatusCode,
    body::{Bytes, Incoming},
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, UPGRADE},
};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

const FORWARDED: &str = "x-pdm-forwarded-authorization";
const LEASE: &str = "x-pdm-job-lease";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    protocol: String,
    timeout_ms: u64,
}
struct PollGuard {
    polls: Arc<Mutex<BTreeSet<String>>>,
    tunnel: String,
}
impl Drop for PollGuard {
    fn drop(&mut self) {
        if let Ok(mut polls) = self.polls.lock() {
            polls.remove(&self.tunnel);
        }
    }
}

pub struct RelayHttpServer {
    listener: HttpListener,
}
impl RelayHttpServer {
    pub fn start(relay: Relay, config: HttpsConfig) -> Result<Self, Error> {
        let polls = Arc::new(Mutex::new(BTreeSet::new()));
        let handler: Handler = Arc::new(move |request| {
            let relay = relay.clone();
            let polls = polls.clone();
            Box::pin(handle(request, relay, polls))
        });
        Ok(Self { listener: HttpListener::start(config, handler, 32, Duration::from_secs(20))? })
    }
    pub fn address(&self) -> SocketAddr {
        self.listener.address()
    }
    pub fn shutdown(self) -> Result<(), Error> {
        self.listener.shutdown()
    }
}
fn reply(status: StatusCode, body: impl Into<Bytes>) -> Reply {
    let mut response = hyper::Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
fn failure(error: Error) -> Reply {
    let status = match error {
        Error::Forbidden => StatusCode::UNAUTHORIZED,
        Error::NotFound => StatusCode::GATEWAY_TIMEOUT,
        Error::Invalid(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_GATEWAY,
    };
    reply(status, "{}")
}
async fn handle(request: Request<Incoming>, relay: Relay, polls: Arc<Mutex<BTreeSet<String>>>) -> Reply {
    if request.method() != hyper::Method::POST {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "{}");
    }
    if request.uri().query().is_some() {
        return reply(StatusCode::NOT_FOUND, "{}");
    }
    let parts: Vec<_> = request.uri().path().split('/').collect();
    let (tunnel, action, job) = match parts.as_slice() {
        ["", "pdm", "v2", "tunnels", tunnel, action] if matches!(*action, "rpc" | "poll") => ((*tunnel).to_owned(), (*action).to_owned(), None),
        ["", "pdm", "v2", "tunnels", tunnel, "complete", job] if job.len() == 64 && job.bytes().all(|b| b.is_ascii_hexdigit()) => {
            ((*tunnel).to_owned(), "complete".to_owned(), Some((*job).to_owned()))
        }
        _ => return reply(StatusCode::NOT_FOUND, "{}"),
    };
    if tunnel.is_empty() || tunnel.len() > 64 || !tunnel.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return reply(StatusCode::NOT_FOUND, "{}");
    }
    if request.headers().contains_key(UPGRADE)
        || request.headers().get_all(AUTHORIZATION).iter().count() != 1
        || request.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) != Some("application/json")
    {
        return reply(StatusCode::BAD_REQUEST, "{}");
    }
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|v| AuthToken::parse(v.into()).ok());
    let Some(token) = token else {
        return reply(StatusCode::UNAUTHORIZED, "{}");
    };
    let lease = request.headers().get(LEASE).and_then(|v| v.to_str().ok()).map(str::to_owned);
    if job.is_some()
        && (request.headers().get_all(LEASE).iter().count() != 1
            || !lease.as_ref().is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())))
    {
        return reply(StatusCode::BAD_REQUEST, "{}");
    }
    if request.headers().get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).is_some_and(|v| v > MAX_FRAME) {
        return reply(StatusCode::PAYLOAD_TOO_LARGE, "{}");
    }
    let body = match tokio::time::timeout(Duration::from_secs(5), Limited::new(request.into_body(), MAX_FRAME as usize).collect()).await {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(_)) => return reply(StatusCode::PAYLOAD_TOO_LARGE, "{}"),
        Err(_) => return reply(StatusCode::REQUEST_TIMEOUT, "{}"),
    };
    if action == "rpc" {
        let envelope: RpcEnvelope = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return reply(StatusCode::BAD_REQUEST, "{}"),
        };
        if envelope.protocol != PROTOCOL {
            return reply(StatusCode::BAD_REQUEST, "{}");
        }
        let paired = match relay.server_id(&tunnel) {
            Ok(id) => id,
            Err(error) => return failure(error),
        };
        let identity_error = match envelope.server_id.as_deref() {
            Some(id) if id != paired => Some("server_identity_mismatch"),
            None if !matches!(&envelope.request, crate::Request::ManagedCatalog) => Some("server_identity_required"),
            _ => None,
        };
        if let Some(code) = identity_error {
            return match serde_json::to_vec(&Response::Error { code: code.into() }) {
                Ok(bytes) => reply(StatusCode::OK, bytes),
                Err(_) => reply(StatusCode::INTERNAL_SERVER_ERROR, "{}"),
            };
        }
        let pending = match relay.submit(&tunnel, token, envelope.request, Duration::from_secs(10)) {
            Ok(v) => v,
            Err(e) => return failure(e),
        };
        return match tokio::task::spawn_blocking(move || pending.wait(Duration::from_secs(10))).await {
            Ok(Ok(response)) => match serde_json::to_vec(&response) {
                Ok(bytes) => reply(StatusCode::OK, bytes),
                Err(_) => reply(StatusCode::BAD_GATEWAY, "{}"),
            },
            Ok(Err(e)) => failure(e),
            Err(_) => reply(StatusCode::BAD_GATEWAY, "{}"),
        };
    }
    if action == "poll" {
        let poll: Poll = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return reply(StatusCode::BAD_REQUEST, "{}"),
        };
        if poll.protocol != PROTOCOL || poll.timeout_ms > 5000 {
            return reply(StatusCode::BAD_REQUEST, "{}");
        }
        {
            let Ok(mut active) = polls.lock() else {
                return reply(StatusCode::SERVICE_UNAVAILABLE, "{}");
            };
            if !active.insert(tunnel.clone()) {
                return reply(StatusCode::TOO_MANY_REQUESTS, "{}");
            }
        }
        let guard = PollGuard { polls, tunnel: tunnel.clone() };
        return match tokio::task::spawn_blocking(move || {
            let _guard = guard;
            relay.poll(&tunnel, &token, Duration::from_millis(poll.timeout_ms))
        })
        .await
        {
            Ok(Ok(Some(job))) => {
                let (id, lease, credential, request) = job.into_parts();
                let bytes = match serde_json::to_vec(&serde_json::json!({"protocol":PROTOCOL,"job_id":id,"request":request})) {
                    Ok(bytes) if bytes.len() <= MAX_FRAME as usize => bytes,
                    _ => return reply(StatusCode::BAD_GATEWAY, "{}"),
                };
                let mut response = reply(StatusCode::OK, bytes);
                let Ok(mut authorization) = HeaderValue::from_str(&format!("Bearer {}", credential.0)) else {
                    return reply(StatusCode::BAD_GATEWAY, "{}");
                };
                authorization.set_sensitive(true);
                let Ok(mut lease) = HeaderValue::from_str(&lease) else {
                    return reply(StatusCode::BAD_GATEWAY, "{}");
                };
                lease.set_sensitive(true);
                response.headers_mut().insert(FORWARDED, authorization);
                response.headers_mut().insert(LEASE, lease);
                response
            }
            Ok(Ok(None)) => reply(StatusCode::NO_CONTENT, Bytes::new()),
            Ok(Err(e)) => failure(e),
            Err(_) => reply(StatusCode::BAD_GATEWAY, "{}"),
        };
    }
    let response: Response = match serde_json::from_slice(&body) {
        Ok(response) => response,
        Err(_) => return reply(StatusCode::BAD_REQUEST, "{}"),
    };
    match relay.complete(&tunnel, &token, job.as_deref().unwrap_or_default(), lease.as_deref().unwrap_or_default(), response) {
        Ok(()) => reply(StatusCode::NO_CONTENT, Bytes::new()),
        Err(e) => failure(e),
    }
}
