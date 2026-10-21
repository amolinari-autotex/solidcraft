//! Bounded HTTPS RPC transport. Only configured principals reach the writer.
use crate::administration::{self, AdminEnvelope, AdminRequest, AdminResponse, CapabilityRequest};
pub use crate::http_listener::HttpsConfig;
use crate::http_listener::{Handler, HttpListener};
use crate::{Error, HTTP_RPC_PATH, MAX_FRAME, PROTOCOL, Request, RpcEnvelope, Store};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request as HttpRequest, Response as HttpResponse, StatusCode,
    body::{Bytes, Incoming},
};
use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
use tokio::sync::oneshot;
const DEADLINE: Duration = Duration::from_secs(5);
type Reply = HttpResponse<Full<Bytes>>;
pub(crate) enum JobRequest {
    Rpc(Request),
    Extension(Option<AdminRequest>),
    Transfer { call: crate::transfers::Call, epoch: Option<u64> },
}
pub(crate) type Job = (JobRequest, String, Option<String>, oneshot::Sender<crate::transfers::HttpReply>);
/// Observed counters only: no credentials, identities or request contents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerMetrics {
    pub http_requests: u64,
    pub tls_connections: u64,
}
pub struct HttpsServer {
    address: SocketAddr,
    listener: Option<HttpListener>,
    writer: Option<thread::JoinHandle<()>>,
    http_requests: Arc<AtomicU64>,
}
impl HttpsServer {
    pub fn start(store: Store, config: HttpsConfig) -> Result<Self, Error> {
        Self::start_impl(store, config, None)
    }
    /// Keep an installer-selected loopback port reserved throughout enrollment.
    /// This consumes the socket and never closes/rebinds it during startup.
    pub fn start_loopback_with_listener(store: Store, config: HttpsConfig, listener: TcpListener) -> Result<Self, Error> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(Error::Invalid("reserved HTTPS listener requires loopback"));
        }
        Self::start_impl(store, config, Some(listener))
    }
    fn start_impl(mut store: Store, mut config: HttpsConfig, reserved: Option<TcpListener>) -> Result<Self, Error> {
        if !store.has_configured_principals() {
            return Err(Error::Invalid("HTTPS requires configured principals"));
        }
        // PDM opts into bounded persistence; shared relay listeners retain the
        // configuration constructor's single-request default.
        config.keep_alive = true;
        let (send, receive) = mpsc::sync_channel::<Job>(16);
        let writer = thread::Builder::new().name("pdm-writer".into()).spawn(move || {
            while let Ok((request, credential, expected, reply)) = receive.recv() {
                let request = match request {
                    JobRequest::Transfer { call, epoch } => {
                        let _ = reply.send(store.execute_transfer(call, &credential, expected.as_deref().unwrap_or(""), epoch));
                        continue;
                    }
                    other => other,
                };
                let (status, bytes) = match request {
                    JobRequest::Rpc(request) => (200, serde_json::to_vec(&store.execute_configured_for(request, &credential, expected.as_deref()))),
                    JobRequest::Extension(request) => {
                        let response = store.execute_extension(request, &credential, expected.as_deref().unwrap_or(""));
                        (response.status(), serde_json::to_vec(&response))
                    }
                    JobRequest::Transfer { .. } => (500, Ok(b"{}".to_vec())),
                };
                let wire = match bytes {
                    Ok(bytes) if bytes.len() <= MAX_FRAME as usize => (status, bytes, vec![]),
                    _ => (500, b"{}".to_vec(), vec![]),
                };
                let _ = reply.send(wire);
            }
        })?;
        let transfer_permits = Arc::new(crate::http_transfer::Admission::new());
        let http_requests = Arc::new(AtomicU64::new(0));
        let observed_requests = http_requests.clone();
        let handler: Handler = Arc::new(move |request| {
            observed_requests.fetch_add(1, Ordering::Relaxed);
            let send = send.clone();
            let permits = transfer_permits.clone();
            Box::pin(async move {
                if request.uri().path() == crate::transfers::CAPABILITIES_PATH
                    || request.uri().path() == crate::transfers::LIMITS_PATH
                    || request.uri().path().starts_with("/pdm/v1/transfers")
                    || request.uri().path().starts_with("/pdm/v1/content/")
                {
                    return crate::http_transfer::serve(request, send, permits).await;
                }
                match rpc(request, send).await {
                    Ok(reply) => reply,
                    Err(never) => match never {},
                }
            })
        });
        let listener = match reserved {
            Some(listener) => HttpListener::start_with_listener(config, listener, handler, 16, Duration::from_secs(15)),
            None => HttpListener::start(config, handler, 16, Duration::from_secs(15)),
        };
        match listener {
            Ok(listener) => Ok(Self { address: listener.address(), listener: Some(listener), writer: Some(writer), http_requests }),
            Err(error) => {
                let _ = writer.join();
                Err(error)
            }
        }
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn metrics(&self) -> ServerMetrics {
        ServerMetrics {
            http_requests: self.http_requests.load(Ordering::Relaxed),
            tls_connections: self.listener.as_ref().map_or(0, HttpListener::tls_connections),
        }
    }
    pub fn shutdown(mut self) -> Result<(), Error> {
        self.close()
    }
    fn close(&mut self) -> Result<(), Error> {
        let listener_result = match self.listener.take() {
            Some(listener) => listener.shutdown(),
            None => Ok(()),
        };
        let writer_result = match self.writer.take() {
            Some(writer) => writer.join().map_err(|_| Error::Invalid("PDM writer failed")),
            None => Ok(()),
        };
        listener_result.and(writer_result)
    }
}
impl Drop for HttpsServer {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn reply(status: StatusCode, body: impl Into<Bytes>) -> Reply {
    let mut response = HttpResponse::new(Full::new(body.into()));
    *response.status_mut() = status;
    response.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    response
}

async fn rpc(request: HttpRequest<Incoming>, send: mpsc::SyncSender<Job>) -> Result<Reply, std::convert::Infallible> {
    if request.method() != hyper::Method::POST {
        return Ok(reply(StatusCode::METHOD_NOT_ALLOWED, "{}"));
    }
    let route = match request.uri().path() {
        HTTP_RPC_PATH => 0,
        administration::CAPABILITIES_PATH => 1,
        administration::ADMIN_PATH => 2,
        crate::managed::NAMESPACE_CAPABILITIES_PATH => 3,
        _ => return Ok(reply(StatusCode::NOT_FOUND, "{}")),
    };
    if request.uri().query().is_some() {
        return Ok(reply(StatusCode::NOT_FOUND, "{}"));
    }
    if request.headers().contains_key(hyper::header::UPGRADE)
        || request.headers().get_all(hyper::header::AUTHORIZATION).iter().count() != 1
        || request.headers().get(hyper::header::CONTENT_TYPE).and_then(|h| h.to_str().ok()) != Some("application/json")
    {
        return Ok(reply(StatusCode::BAD_REQUEST, "{}"));
    }
    let credential = request.headers().get(hyper::header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "));
    let Some(credential) = credential.filter(|c| c.len() == 64 && c.bytes().all(|b| b.is_ascii_hexdigit())).map(str::to_owned) else {
        return Ok(reply(StatusCode::UNAUTHORIZED, "{}"));
    };
    let max_body = if route == 0 { MAX_FRAME as usize } else { administration::MAX_BODY };
    if request
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<u64>().ok())
        .is_some_and(|n| n > max_body as u64)
    {
        return Ok(reply(StatusCode::PAYLOAD_TOO_LARGE, "{}"));
    }
    let bytes = match tokio::time::timeout(DEADLINE, Limited::new(request.into_body(), max_body).collect()).await {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(_)) => return Ok(reply(StatusCode::PAYLOAD_TOO_LARGE, "{}")),
        Err(_) => return Ok(reply(StatusCode::REQUEST_TIMEOUT, "{}")),
    };
    let (request, server_id) = if route == 0 {
        let envelope: RpcEnvelope = match serde_json::from_slice(&bytes) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(reply(StatusCode::BAD_REQUEST, "{}")),
        };
        if envelope.protocol != PROTOCOL {
            return Ok(reply(StatusCode::BAD_REQUEST, "{}"));
        }
        (JobRequest::Rpc(envelope.request), envelope.server_id)
    } else if route == 3 {
        let envelope: CapabilityRequest = match serde_json::from_slice(&bytes) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(extension_error("invalid_request")),
        };
        if envelope.protocol != crate::managed::NAMESPACE_PROTOCOL {
            return Ok(extension_error("unsupported_protocol"));
        }
        (JobRequest::Rpc(Request::ManagedNamespaceCapabilities {}), Some(envelope.server_id))
    } else if route == 1 {
        let envelope: CapabilityRequest = match serde_json::from_slice(&bytes) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(extension_error("invalid_request")),
        };
        if envelope.protocol != administration::CAPABILITIES_PROTOCOL {
            return Ok(extension_error("unsupported_protocol"));
        }
        (JobRequest::Extension(None), Some(envelope.server_id))
    } else {
        let envelope: AdminEnvelope = match serde_json::from_slice(&bytes) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(extension_error("invalid_request")),
        };
        if envelope.protocol != administration::ADMIN_PROTOCOL {
            return Ok(extension_error("unsupported_protocol"));
        }
        (JobRequest::Extension(Some(envelope.request)), Some(envelope.server_id))
    };
    let (result, receive) = oneshot::channel();
    if send.try_send((request, credential, server_id, result)).is_err() {
        return Ok(reply(StatusCode::SERVICE_UNAVAILABLE, "{}"));
    }
    match tokio::time::timeout(DEADLINE, receive).await {
        Ok(Ok((status, bytes, _))) => Ok(reply(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), bytes)),
        _ => Ok(reply(StatusCode::SERVICE_UNAVAILABLE, "{}")),
    }
}

fn extension_error(code: &str) -> Reply {
    let response = AdminResponse::error(code);
    match serde_json::to_vec(&response) {
        Ok(bytes) => reply(StatusCode::from_u16(response.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), bytes),
        Err(_) => reply(StatusCode::INTERNAL_SERVER_ERROR, "{}"),
    }
}
