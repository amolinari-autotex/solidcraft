//! Versioned binary transfer control types. Credentials are never Debug output.
use crate::{
    Version,
    managed::{ManagedVersion, Principal},
    stream_io::StreamPolicy,
};
use serde::{Deserialize, Serialize};
pub const CAPABILITIES_PATH: &str = "/pdm/v2/capabilities";
pub const PROTOCOL: &str = "solidcraft-pdm-capabilities/2";
pub const CHUNK_BYTES: u64 = 1024 * 1024;
pub const HARD_CHUNK_BYTES: u64 = 8 * CHUNK_BYTES;
pub const LIMITS_PATH: &str = "/pdm/v1/transfer-limits";
pub const LIMITS_PROTOCOL: &str = "solidcraft-pdm-transfer-limits/1";
pub const CONTROL_BYTES: usize = 64 * 1024;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransferTarget {
    NewOnly { logical_path: String },
    CheckIn { document: String, workspace: String, machine: String, checkout_token: String, parent: Option<u64> },
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferInput {
    pub server_id: String,
    pub recovery_epoch: u64,
    pub request_id: String,
    pub target: TransferTarget,
    pub total_bytes: u64,
    pub sha256: String,
    pub dependencies: Vec<crate::VersionRef>,
    pub comment: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferCapabilities {
    pub protocol: String,
    pub server_id: String,
    pub recovery_epoch: u64,
    pub principal: Principal,
    pub binary_transfer_v1: bool,
    pub can_upload: bool,
    pub limits: Option<StreamPolicy>,
    pub chunk_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferLimits {
    pub protocol: String,
    pub server_id: String,
    pub recovery_epoch: u64,
    pub principal: Principal,
    pub max_chunk_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProgress {
    pub transfer_id: String,
    pub offset: u64,
    pub total_bytes: u64,
    pub sha256: String,
    pub expires_at: u64,
    pub completed: Option<ManagedVersion>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentMetadata {
    pub version: Version,
    pub total_bytes: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WireResponse {
    Capabilities { capabilities: TransferCapabilities },
    Limits { limits: TransferLimits },
    Progress { progress: TransferProgress },
    Committed { version: ManagedVersion },
    Metadata { metadata: ContentMetadata },
    Cancelled {},
    Error { code: String, actual_bytes: Option<u64>, max_bytes: Option<u64>, retryable: bool },
}
impl WireResponse {
    pub(crate) fn error(code: &str) -> Self {
        Self::Error { code: code.into(), actual_bytes: None, max_bytes: None, retryable: matches!(code, "transfer_busy" | "unavailable") }
    }
}
pub(crate) type HttpReply = (u16, Vec<u8>, Vec<(String, String)>);
pub(crate) fn json_reply(response: WireResponse) -> HttpReply {
    let status = match &response {
        WireResponse::Error { code, .. } => match code.as_str() {
            "unauthorized" => 401,
            "forbidden" => 403,
            "not_found" => 404,
            "file_too_large" => 413,
            "transfer_busy" => 429,
            "checksum_mismatch" => 422,
            "transfer_expired" => 410,
            "storage_error" | "unavailable" => 503,
            "conflict"
            | "chunk_conflict"
            | "storage_quota_exceeded"
            | "temporary_quota_exceeded"
            | "server_identity_mismatch"
            | "recovery_epoch_mismatch" => 409,
            _ => 400,
        },
        _ => 200,
    };
    (status, serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec()), vec![])
}
impl crate::Store {
    pub(crate) fn execute_transfer(&mut self, call: Call, credential: &str, expected: &str, epoch: Option<u64>) -> HttpReply {
        let Some(principal) = self.managed.authenticate(credential) else {
            return json_reply(WireResponse::error("unauthorized"));
        };
        if expected != self.managed.server_id() {
            return json_reply(WireResponse::error("server_identity_mismatch"));
        }
        let caps = self.managed.transfer_capabilities(&principal);
        if matches!(call, Call::Capabilities) {
            let mut reply = json_reply(WireResponse::Capabilities { capabilities: caps });
            reply.2.push(("x-pdm-authenticated-principal".into(), principal.id));
            return reply;
        }
        if !caps.binary_transfer_v1 {
            return json_reply(WireResponse::error("unsupported_protocol"));
        }
        if epoch != Some(caps.recovery_epoch) {
            return json_reply(WireResponse::error("recovery_epoch_mismatch"));
        }
        if let Call::Begin(input) = &call
            && let Some(policy) = &caps.limits
            && input.total_bytes > policy.max_file_bytes
        {
            return json_reply(WireResponse::Error {
                code: "file_too_large".into(),
                actual_bytes: Some(input.total_bytes),
                max_bytes: Some(policy.max_file_bytes),
                retryable: false,
            });
        }
        let result = (|| {
            Ok(json_reply(match call {
                Call::Capabilities => return Err(crate::Error::Invalid("capability dispatch")),
                Call::Limits => WireResponse::Limits {
                    limits: TransferLimits {
                        protocol: LIMITS_PROTOCOL.into(),
                        server_id: caps.server_id,
                        recovery_epoch: caps.recovery_epoch,
                        principal: principal.clone(),
                        max_chunk_bytes: HARD_CHUNK_BYTES,
                    },
                },
                Call::PrepareMutation => {
                    if principal.role == crate::managed::Role::Viewer {
                        return Err(crate::Error::Forbidden);
                    }
                    WireResponse::Cancelled {}
                }
                Call::PrepareCommit(id) => {
                    self.managed.prepare_transfer_commit(&principal, &id)?;
                    WireResponse::Cancelled {}
                }
                Call::Begin(input) => WireResponse::Progress { progress: self.managed.begin_transfer(&principal, input)? },
                Call::Status(id) => WireResponse::Progress { progress: self.managed.transfer_status(&principal, &id)? },
                Call::Prepare { id, offset, bytes, sha256 } => {
                    self.managed.prepare_chunk(&principal, &id, offset, bytes, &sha256)?;
                    WireResponse::Progress { progress: self.managed.transfer_status(&principal, &id)? }
                }
                Call::Chunk { id, offset, content, sha256 } => {
                    WireResponse::Progress { progress: self.managed.transfer_chunk(&principal, &id, offset, &content, &sha256)? }
                }
                Call::Commit { id, request_id } => WireResponse::Committed { version: self.managed.commit_transfer(&principal, &id, &request_id)? },
                Call::Cancel(id) => {
                    self.managed.cancel_transfer(&principal, &id)?;
                    WireResponse::Cancelled {}
                }
                Call::Metadata(reference) => WireResponse::Metadata { metadata: self.managed.content_metadata(&reference)? },
                Call::Range { reference, offset, bytes } => {
                    let (metadata, content) = self.managed.content_range(&reference, offset, bytes)?;
                    let length = content.len();
                    let hash = crate::digest(&content);
                    return Ok((
                        200,
                        content,
                        vec![
                            ("content-type".into(), "application/octet-stream".into()),
                            ("x-pdm-sha256".into(), metadata.version.sha256),
                            ("x-chunk-sha256".into(), hash),
                            ("x-pdm-total-bytes".into(), metadata.total_bytes.to_string()),
                            ("x-pdm-offset".into(), offset.to_string()),
                            ("content-length".into(), length.to_string()),
                        ],
                    ));
                }
            }))
        })();
        let mut reply = match result {
            Ok(response) => response,
            Err(error) => json_reply(WireResponse::error(match error {
                crate::Error::Server(ref code) => code,
                crate::Error::Forbidden => "forbidden",
                crate::Error::Conflict => "conflict",
                crate::Error::NotFound => "not_found",
                crate::Error::Referenced => "referenced",
                crate::Error::Integrity => "integrity",
                crate::Error::Invalid(_) => "invalid_request",
                _ => "storage_error",
            })),
        };
        if reply.0 == 200 {
            reply.2.push(("x-pdm-authenticated-principal".into(), principal.id));
        }
        reply
    }
}
pub(crate) enum Call {
    Capabilities,
    Limits,
    PrepareMutation,
    PrepareCommit(String),
    Begin(TransferInput),
    Status(String),
    Prepare { id: String, offset: u64, bytes: u64, sha256: String },
    Chunk { id: String, offset: u64, content: Vec<u8>, sha256: String },
    Commit { id: String, request_id: String },
    Cancel(String),
    Metadata(crate::VersionRef),
    Range { reference: crate::VersionRef, offset: u64, bytes: u64 },
}
