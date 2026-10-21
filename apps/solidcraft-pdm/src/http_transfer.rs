//! Admission precedes body polling (including Expect:100-continue). At most two
//! bounded chunks/controls are collected, within the 16-connection listener cap.
use crate::{
    http_server::{Job, JobRequest},
    transfers::{self, Call, HttpReply, TransferInput, WireResponse},
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response,
    body::{Bytes, Incoming},
};
use std::{
    sync::{Arc, mpsc},
    time::Duration,
};
use tokio::sync::{Semaphore, oneshot};
pub(crate) struct Admission {
    global: Arc<Semaphore>,
    principals: std::sync::Mutex<std::collections::BTreeSet<String>>,
}
impl Admission {
    pub(crate) fn new() -> Self {
        Self { global: Arc::new(Semaphore::new(2)), principals: std::sync::Mutex::new(std::collections::BTreeSet::new()) }
    }
}
struct PrincipalPermit {
    admission: Arc<Admission>,
    principal: String,
}
impl Drop for PrincipalPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.admission.principals.lock() {
            active.remove(&self.principal);
        }
    }
}
type Reply = Response<Full<Bytes>>;
fn response((status, bytes, headers): HttpReply) -> Reply {
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert("content-type", hyper::header::HeaderValue::from_static("application/json"));
    for (key, value) in headers {
        if let (Ok(key), Ok(value)) = (hyper::header::HeaderName::from_bytes(key.as_bytes()), hyper::header::HeaderValue::from_str(&value)) {
            response.headers_mut().insert(key, value);
        }
    }
    if status == 429 {
        response.headers_mut().insert("retry-after", hyper::header::HeaderValue::from_static("1"));
    }
    response
}
fn error(code: &str) -> Reply {
    response(transfers::json_reply(WireResponse::error(code)))
}
async fn execute(send: &mpsc::SyncSender<Job>, call: Call, credential: &str, server: &str, epoch: Option<u64>) -> HttpReply {
    let (reply, receive) = oneshot::channel();
    if send.try_send((JobRequest::Transfer { call, epoch }, credential.into(), Some(server.into()), reply)).is_err() {
        return transfers::json_reply(WireResponse::error("unavailable"));
    }
    match tokio::time::timeout(Duration::from_secs(10), receive).await {
        Ok(Ok(reply)) => reply,
        _ => transfers::json_reply(WireResponse::error("unavailable")),
    }
}
fn header<'a>(request: &'a Request<Incoming>, key: &str) -> Option<&'a str> {
    if request.headers().get_all(key).iter().count() != 1 {
        return None;
    }
    request.headers().get(key)?.to_str().ok()
}
fn hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn number(value: &str) -> Option<u64> {
    let n = value.parse::<u64>().ok()?;
    if n.to_string() == value { Some(n) } else { None }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    request_id: String,
}
pub(crate) async fn serve(request: Request<Incoming>, send: mpsc::SyncSender<Job>, admission: Arc<Admission>) -> Reply {
    let Ok(_permit) = admission.global.clone().try_acquire_owned() else {
        return error("transfer_busy");
    };
    if request.headers().contains_key("upgrade") || request.headers().contains_key("transfer-encoding") {
        return error("invalid_request");
    }
    let Some(credential) = header(&request, "authorization").and_then(|v| v.strip_prefix("Bearer ")).filter(|v| hex(v)).map(str::to_owned) else {
        return error("unauthorized");
    };
    let Some(server) = header(&request, "x-pdm-server-id").filter(|v| hex(v)).map(str::to_owned) else {
        return error("server_identity_mismatch");
    };
    let epoch = header(&request, "x-pdm-recovery-epoch").and_then(number);
    let length = header(&request, "content-length").and_then(number);
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let parts: Vec<_> = path.split('/').collect();
    let is_caps = path == transfers::CAPABILITIES_PATH;
    let is_limits = path == transfers::LIMITS_PATH;
    let is_begin = path == "/pdm/v1/transfers" && method == Method::POST;
    let is_commit = matches!(parts.as_slice(),["","pdm","v1","transfers",id,"commit"] if hex(id)) && method == Method::POST;
    let is_chunk =
        matches!(parts.as_slice(),["","pdm","v1","transfers",id,"chunks",offset] if hex(id)&&number(offset).is_some()) && method == Method::PUT;
    if (is_caps || is_limits) && method != Method::POST {
        return error("invalid_request");
    }
    if !is_caps && epoch.is_none() {
        return error("recovery_epoch_mismatch");
    }
    let has_control = is_caps || is_limits || is_begin || is_commit;
    if !is_chunk && !has_control && length.is_some_and(|n| n != 0) {
        return error("invalid_request");
    }
    if has_control && (header(&request, "content-type") != Some("application/json") || length.is_none_or(|n| n > transfers::CONTROL_BYTES as u64)) {
        return error("invalid_request");
    }
    if !path.starts_with("/pdm/v1/content/") && request.uri().query().is_some() {
        return error("invalid_request");
    }
    let preflight = if is_chunk {
        if header(&request, "content-type") != Some("application/octet-stream") || length.is_none_or(|n| n == 0 || n > transfers::HARD_CHUNK_BYTES) {
            return error("invalid_request");
        }
        let Some(hash) = header(&request, "x-chunk-sha256").filter(|v| hex(v)) else {
            return error("invalid_request");
        };
        let Some(id) = parts.get(4) else {
            return error("invalid_request");
        };
        let Some(offset) = parts.get(6).and_then(|v| number(v)) else {
            return error("invalid_request");
        };
        Call::Prepare { id: (*id).into(), offset, bytes: length.unwrap_or(0), sha256: hash.into() }
    } else if is_begin {
        Call::PrepareMutation
    } else if is_commit {
        Call::PrepareCommit(parts.get(4).copied().unwrap_or("").into())
    } else {
        Call::Capabilities
    };
    let auth = execute(&send, preflight, &credential, &server, epoch).await;
    if auth.0 != 200 {
        return response(auth);
    }
    let Some(principal) = auth.2.iter().find(|(key, _)| key == "x-pdm-authenticated-principal").map(|(_, value)| value.clone()) else {
        return error("unavailable");
    };
    let principal_permit = {
        let Ok(mut active) = admission.principals.try_lock() else {
            return error("transfer_busy");
        };
        if !active.insert(principal.clone()) {
            return error("transfer_busy");
        }
        PrincipalPermit { admission: admission.clone(), principal }
    };
    let _principal_permit = principal_permit;
    let call = if has_control {
        let bytes = match tokio::time::timeout(Duration::from_secs(5), Limited::new(request.into_body(), transfers::CONTROL_BYTES).collect()).await {
            Ok(Ok(body)) => body.to_bytes(),
            _ => return error("invalid_request"),
        };
        if bytes.len() as u64 != length.unwrap_or(0) {
            return error("invalid_request");
        }
        if is_caps || is_limits {
            let Ok(body) = serde_json::from_slice::<crate::administration::CapabilityRequest>(&bytes) else {
                return error("invalid_request");
            };
            let protocol = if is_limits { transfers::LIMITS_PROTOCOL } else { transfers::PROTOCOL };
            if body.protocol != protocol || body.server_id != server {
                return error("unsupported_protocol");
            }
            if is_limits { Call::Limits } else { Call::Capabilities }
        } else if is_begin {
            let Ok(body) = serde_json::from_slice::<TransferInput>(&bytes) else {
                return error("invalid_request");
            };
            Call::Begin(body)
        } else {
            let Ok(body) = serde_json::from_slice::<Commit>(&bytes) else {
                return error("invalid_request");
            };
            Call::Commit { id: parts.get(4).copied().unwrap_or("").into(), request_id: body.request_id }
        }
    } else if is_chunk {
        let hash = header(&request, "x-chunk-sha256").unwrap_or("").to_owned();
        let bytes =
            match tokio::time::timeout(Duration::from_secs(5), Limited::new(request.into_body(), transfers::HARD_CHUNK_BYTES as usize).collect())
                .await
            {
                Ok(Ok(body)) => body.to_bytes(),
                _ => return error("invalid_request"),
            };
        if bytes.len() as u64 != length.unwrap_or(0) {
            return error("invalid_request");
        }
        Call::Chunk {
            id: parts.get(4).copied().unwrap_or("").into(),
            offset: parts.get(6).and_then(|v| number(v)).unwrap_or(0),
            content: bytes.to_vec(),
            sha256: hash,
        }
    } else {
        match (method, parts.as_slice()) {
            (Method::GET, ["", "pdm", "v1", "transfers", id]) if hex(id) => Call::Status((*id).into()),
            (Method::DELETE, ["", "pdm", "v1", "transfers", id]) if hex(id) => Call::Cancel((*id).into()),
            (Method::GET, ["", "pdm", "v1", "content", document, version, "metadata"])
                if crate::valid_id(document) && number(version).is_some() && request.uri().query().is_none() =>
            {
                Call::Metadata(crate::VersionRef { document: (*document).into(), version: number(version).unwrap_or(0) })
            }
            (Method::GET, ["", "pdm", "v1", "content", document, version]) if crate::valid_id(document) && number(version).is_some() => {
                let Some(query) = request.uri().query() else {
                    return error("invalid_request");
                };
                let Some((offset, bytes)) =
                    query.strip_prefix("offset=").and_then(|s| s.split_once("&length=")).and_then(|(o, n)| Some((number(o)?, number(n)?)))
                else {
                    return error("invalid_request");
                };
                Call::Range { reference: crate::VersionRef { document: (*document).into(), version: number(version).unwrap_or(0) }, offset, bytes }
            }
            _ => return error("not_found"),
        }
    };
    response(execute(&send, call, &credential, &server, epoch).await)
}
