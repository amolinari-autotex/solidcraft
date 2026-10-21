//! Server-authoritative user changes share the managed metadata transaction.
use super::metadata_db::AdminReceipt;
use super::{ManagedStore, Principal, PrincipalCredential, Role};
use crate::administration::{AdminRequest, AdminResponse, AuditChange, CAPABILITIES_PROTOCOL, Capabilities, Features, UserSummary, permissions};

impl ManagedStore {
    pub(crate) fn capabilities(&self, principal: &Principal) -> Capabilities {
        let database = self.metadata.is_some();
        let mut effective = permissions(principal.role);
        if !database {
            effective.retain(|permission| permission != "users.manage" && permission != "audit.read");
        }
        Capabilities {
            protocol: CAPABILITIES_PROTOCOL.into(),
            server_id: self.server_id().into(),
            principal: principal.clone(),
            metadata_backend: if database { "redb" } else { "json_generations" }.into(),
            features: Features { users_admin_v1: database, audit_read_v1: database },
            permissions: effective,
        }
    }
    pub(crate) fn admin(&mut self, principal: &Principal, request: AdminRequest) -> AdminResponse {
        match self.admin_result(principal, request) {
            Ok(response) => response,
            Err(code) => AdminResponse::error(code),
        }
    }
    fn admin_result(&mut self, principal: &Principal, request: AdminRequest) -> Result<AdminResponse, &'static str> {
        if principal.role != Role::Administrator {
            return Err("forbidden");
        }
        let metadata = self.metadata.as_mut().ok_or("capability_unavailable")?;
        let mut admin = metadata.image.administration.clone().unwrap_or_default();
        match &request {
            AdminRequest::ListUsers {} => {
                return Ok(AdminResponse::Users {
                    revision: admin.revision,
                    users: metadata
                        .image
                        .credentials
                        .iter()
                        .map(|item| UserSummary::new(&item.principal, !admin.disabled.contains(&item.principal.id)))
                        .collect(),
                });
            }
            AdminRequest::ListAudit { after_generation, limit } => {
                if *limit == 0 || *limit > 128 {
                    return Err("invalid_request");
                }
                let mut events: Vec<_> =
                    metadata.image.public_audit().into_iter().filter(|event| after_generation.is_none_or(|after| event.generation > after)).collect();
                let more = events.len() > usize::from(*limit);
                events.truncate(usize::from(*limit));
                let next_after_generation = if more { events.last().map(|event| event.generation) } else { None };
                return Ok(AdminResponse::Audit { events, next_after_generation });
            }
            _ => {}
        }
        let (request_id, expected, id) = request.mutation().ok_or("invalid_request")?;
        if !crate::valid_id(request_id) || !super::label(id) || id == "owner" {
            return Err("invalid_request");
        }
        let fingerprint = crate::digest(&serde_json::to_vec(&request).map_err(|_| "invalid_request")?);
        if let Some(receipt) = admin.receipts.get(request_id) {
            return if receipt.owner == principal.id && receipt.fingerprint == fingerprint {
                Ok(receipt.response.clone())
            } else {
                Err("idempotency_conflict")
            };
        }
        if expected != admin.revision {
            return Err("conflict");
        }
        if admin.receipts.len() >= 256 || metadata.image.generation >= super::MAX_GENERATIONS {
            return Err("quota");
        }
        let mut credentials = metadata.image.credentials.clone();
        let administrators =
            credentials.iter().filter(|item| item.principal.role == Role::Administrator && !admin.disabled.contains(&item.principal.id)).count();
        let index = credentials.iter().position(|item| item.principal.id == id);
        let previous = index.and_then(|index| credentials.get(index)).map(|item| UserSummary::new(&item.principal, !admin.disabled.contains(id)));
        let mut changed = true;
        let operation;
        let mut credential_replaced = false;
        match &request {
            AdminRequest::CreateUser { role, credential_sha256, .. } => {
                if !crate::valid_id(id) {
                    return Err("invalid_request");
                }
                if index.is_some() {
                    return Err("principal_exists");
                }
                if credentials.len() >= 64 {
                    return Err("quota");
                }
                validate_verifier(&credentials, credential_sha256, None)?;
                credentials
                    .push(PrincipalCredential { principal: Principal { id: id.into(), role: *role }, token_sha256: credential_sha256.clone() });
                operation = "user.create";
                credential_replaced = true;
            }
            AdminRequest::SetRole { role, .. } => {
                let item = credentials.get_mut(index.ok_or("not_found")?).ok_or("not_found")?;
                if item.principal.role == Role::Administrator && !admin.disabled.contains(id) && *role != Role::Administrator && administrators <= 1 {
                    return Err("last_administrator");
                }
                if id == principal.id && *role != Role::Administrator {
                    return Err("self_lockout");
                }
                changed = item.principal.role != *role;
                item.principal.role = *role;
                operation = "user.set_role";
            }
            AdminRequest::SetEnabled { enabled, .. } => {
                index.ok_or("not_found")?;
                if !enabled
                    && administrators <= 1
                    && credentials
                        .iter()
                        .any(|item| item.principal.id == id && item.principal.role == Role::Administrator && !admin.disabled.contains(id))
                {
                    return Err("last_administrator");
                }
                if id == principal.id && !enabled {
                    return Err("self_lockout");
                }
                changed = admin.disabled.contains(id) == *enabled;
                if *enabled {
                    admin.disabled.remove(id);
                } else {
                    admin.disabled.insert(id.into());
                }
                operation = "user.set_enabled";
            }
            AdminRequest::ReplaceCredential { credential_sha256, .. } => {
                let index = index.ok_or("not_found")?;
                if id == principal.id {
                    return Err("self_lockout");
                }
                validate_verifier(&credentials, credential_sha256, Some(id))?;
                let item = credentials.get_mut(index).ok_or("not_found")?;
                changed = item.token_sha256 != *credential_sha256;
                item.token_sha256 = credential_sha256.clone();
                credential_replaced = changed;
                operation = "user.replace_credential";
            }
            _ => return Err("invalid_request"),
        }
        if !credentials.iter().any(|item| item.principal.role == Role::Administrator && !admin.disabled.contains(&item.principal.id)) {
            return Err("last_administrator");
        }
        let user = credentials
            .iter()
            .find(|item| item.principal.id == id)
            .map(|item| UserSummary::new(&item.principal, !admin.disabled.contains(id)))
            .ok_or("not_found")?;
        if changed {
            admin.revision = admin.revision.checked_add(1).ok_or("quota")?;
        }
        let response = AdminResponse::UserChanged { revision: admin.revision, user: user.clone() };
        admin.receipts.insert(request_id.into(), AdminReceipt { owner: principal.id.clone(), fingerprint, response: response.clone() });
        let change = AuditChange {
            previous_role: previous.as_ref().map(|user| user.role),
            role: user.role,
            previous_enabled: previous.as_ref().map(|user| user.enabled),
            enabled: user.enabled,
            credential_replaced,
        };
        let image = metadata
            .image
            .admin_next(credentials.clone(), admin, &principal.id, if changed { operation } else { "user.noop" }, id.into(), change)
            .map_err(|_| "storage_error")?;
        metadata.commit(image).map_err(|_| "storage_error")?;
        self.generation = metadata.image.generation;
        self.credentials = credentials;
        Ok(response)
    }
}

fn validate_verifier(credentials: &[PrincipalCredential], verifier: &str, same: Option<&str>) -> Result<(), &'static str> {
    if !super::hash_id(verifier) {
        return Err("invalid_request");
    }
    if credentials.iter().any(|item| item.principal.id.as_str() != same.unwrap_or("") && item.token_sha256.eq_ignore_ascii_case(verifier)) {
        return Err("duplicate_credential");
    }
    Ok(())
}
