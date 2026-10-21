//! Additive authenticated HTTPS extension. Never placed in the legacy RPC enum.
use crate::managed::{Principal, Role};
use serde::{Deserialize, Serialize};

pub const CAPABILITIES_PATH: &str = "/pdm/v1/capabilities";
pub const ADMIN_PATH: &str = "/pdm/v1/admin";
pub const CAPABILITIES_PROTOCOL: &str = "solidcraft-pdm-capabilities/1";
pub const ADMIN_PROTOCOL: &str = "solidcraft-pdm-admin/1";
pub const MAX_BODY: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequest {
    pub protocol: String,
    pub server_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminEnvelope {
    pub protocol: String,
    pub server_id: String,
    pub request: AdminRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Features {
    pub users_admin_v1: bool,
    pub audit_read_v1: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub protocol: String,
    pub server_id: String,
    pub principal: Principal,
    pub metadata_backend: String,
    pub features: Features,
    pub permissions: Vec<String>,
}

pub fn permissions(role: Role) -> Vec<String> {
    let mut permissions: Vec<String> = ["catalog.read", "versions.read", "content.read", "references.read"].into_iter().map(String::from).collect();
    if role != Role::Viewer {
        permissions.extend(["documents.create", "checkout.manage_own", "versions.publish"].into_iter().map(String::from));
    }
    if role == Role::Administrator {
        permissions.extend(["users.manage", "audit.read"].into_iter().map(String::from));
    }
    permissions
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSummary {
    pub id: String,
    pub role: Role,
    pub enabled: bool,
    pub permissions: Vec<String>,
}
impl UserSummary {
    pub(crate) fn new(principal: &Principal, enabled: bool) -> Self {
        Self { id: principal.id.clone(), role: principal.role, enabled, permissions: if enabled { permissions(principal.role) } else { vec![] } }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    ListUsers {},
    CreateUser { request_id: String, expected_revision: u64, id: String, role: Role, credential_sha256: String },
    SetRole { request_id: String, expected_revision: u64, id: String, role: Role },
    SetEnabled { request_id: String, expected_revision: u64, id: String, enabled: bool },
    ReplaceCredential { request_id: String, expected_revision: u64, id: String, credential_sha256: String },
    ListAudit { after_generation: Option<u64>, limit: u16 },
}
impl std::fmt::Debug for AdminRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ListUsers {} => "ListUsers",
            Self::CreateUser { .. } => "CreateUser([redacted])",
            Self::SetRole { .. } => "SetRole",
            Self::SetEnabled { .. } => "SetEnabled",
            Self::ReplaceCredential { .. } => "ReplaceCredential([redacted])",
            Self::ListAudit { .. } => "ListAudit",
        })
    }
}
impl AdminRequest {
    pub(crate) fn mutation(&self) -> Option<(&str, u64, &str)> {
        match self {
            Self::CreateUser { request_id, expected_revision, id, .. }
            | Self::SetRole { request_id, expected_revision, id, .. }
            | Self::SetEnabled { request_id, expected_revision, id, .. }
            | Self::ReplaceCredential { request_id, expected_revision, id, .. } => Some((request_id, *expected_revision, id)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditChange {
    pub previous_role: Option<Role>,
    pub role: Role,
    pub previous_enabled: Option<bool>,
    pub enabled: bool,
    pub credential_replaced: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAuditEvent {
    pub generation: u64,
    pub actor: String,
    pub operation: String,
    pub unix_ms: u64,
    pub subject: Option<String>,
    pub change: Option<AuditChange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminResponse {
    Capabilities { capabilities: Capabilities },
    Users { revision: u64, users: Vec<UserSummary> },
    UserChanged { revision: u64, user: UserSummary },
    Audit { events: Vec<PublicAuditEvent>, next_after_generation: Option<u64> },
    Error { code: String },
}
impl AdminResponse {
    pub(crate) fn error(code: &str) -> Self {
        Self::Error { code: code.into() }
    }
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::Error { code } => match code.as_str() {
                "invalid_request" | "unsupported_protocol" => 400,
                "unauthorized" => 401,
                "forbidden" => 403,
                "not_found" => 404,
                "storage_error" => 503,
                _ => 409,
            },
            _ => 200,
        }
    }
}

impl crate::Store {
    pub(crate) fn execute_extension(&mut self, request: Option<AdminRequest>, bearer: &str, expected: &str) -> AdminResponse {
        let Some(principal) = self.managed.authenticate(bearer) else {
            return AdminResponse::error("unauthorized");
        };
        if crate::blob_store::validate_digest(expected).is_err() {
            return AdminResponse::error("invalid_request");
        }
        if expected != self.managed.server_id() {
            return AdminResponse::error("server_identity_mismatch");
        }
        match request {
            Some(request) => self.managed.admin(&principal, request),
            None => AdminResponse::Capabilities { capabilities: self.managed.capabilities(&principal) },
        }
    }
}
