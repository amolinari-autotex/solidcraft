//! Bounded direct HTTPS binary transfer SDK. A caller downloading to disk must
//! use a new private staging file and publish only after this method succeeds.
use super::*;
use crate::transfers::{self, ContentMetadata, TransferCapabilities, TransferInput, TransferProgress, WireResponse};
use sha2::{Digest, Sha256};
use std::io::Write;
fn decode(mut response: ureq::http::Response<ureq::Body>) -> Result<WireResponse, Error> {
    if response.headers().get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json") {
        return Err(Error::Invalid("transfer response content type"));
    }
    let status = response.status().as_u16();
    let bytes = response.body_mut().with_config().limit(transfers::CONTROL_BYTES as u64 + 1).read_to_vec().map_err(|_| https_network_error())?;
    if bytes.len() > transfers::CONTROL_BYTES {
        return Err(Error::Invalid("transfer control response limit"));
    }
    let wire: WireResponse = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid("transfer response JSON"))?;
    if let WireResponse::Error { code, actual_bytes, max_bytes, .. } = wire {
        if code == "file_too_large"
            && let (Some(actual), Some(max)) = (actual_bytes, max_bytes)
        {
            return Err(Error::FileTooLarge { actual, max });
        }
        return match code.as_str() {
            "unauthorized"
            | "forbidden"
            | "not_found"
            | "conflict"
            | "chunk_conflict"
            | "invalid_request"
            | "integrity"
            | "referenced"
            | "storage_error"
            | "unavailable"
            | "transfer_busy"
            | "transfer_expired"
            | "transfer_cancelled"
            | "checksum_mismatch"
            | "storage_quota_exceeded"
            | "temporary_quota_exceeded"
            | "server_identity_mismatch"
            | "recovery_epoch_mismatch"
            | "unsupported_protocol" => Err(Error::Server(code)),
            _ => Err(Error::Invalid("transfer error code")),
        };
    }
    if status != 200 {
        return Err(Error::Invalid("transfer response status"));
    }
    Ok(wire)
}
impl Client {
    fn transfer_send(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        caps: &TransferCapabilities,
        chunk_hash: Option<&str>,
    ) -> Result<ureq::http::Response<ureq::Body>, Error> {
        let (origin, agent) = self.direct_extension_origin()?;
        let mut builder = ureq::http::Request::builder()
            .method(method)
            .uri(format!("{origin}{path}"))
            .header("authorization", authorization_header(&self.token)?)
            .header("x-pdm-server-id", &caps.server_id)
            .header("x-pdm-recovery-epoch", caps.recovery_epoch.to_string())
            .header("content-length", body.len().to_string());
        if let Some(hash) = chunk_hash {
            builder = builder.header("content-type", "application/octet-stream").header("x-chunk-sha256", hash);
        } else if method == "POST" {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder.body(body).map_err(|_| Error::Invalid("transfer request"))?;
        agent.run(request).map_err(|_| https_network_error())
    }
    pub fn transfer_capabilities(&self) -> Result<Option<TransferCapabilities>, Error> {
        let (origin, agent) = match self.direct_extension_origin() {
            Ok(pair) => pair,
            Err(Error::Server(code)) if code == "capability_unavailable" => return Ok(None),
            Err(e) => return Err(e),
        };
        let identity = self.authenticated_identity()?;
        let body = serde_json::to_vec(&crate::administration::CapabilityRequest {
            protocol: transfers::PROTOCOL.into(),
            server_id: identity.server_id.clone(),
        })?;
        let request = ureq::http::Request::builder()
            .method("POST")
            .uri(format!("{origin}{}", transfers::CAPABILITIES_PATH))
            .header("authorization", authorization_header(&self.token)?)
            .header("x-pdm-server-id", &identity.server_id)
            .header("content-type", "application/json")
            .header("content-length", body.len().to_string())
            .body(body.as_slice())
            .map_err(|_| Error::Invalid("transfer capability request"))?;
        let response = agent.run(request).map_err(|_| https_network_error())?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        match decode(response)? {
            WireResponse::Capabilities { capabilities }
                if capabilities.protocol == transfers::PROTOCOL
                    && capabilities.server_id == identity.server_id
                    && capabilities.principal == identity.principal
                    && capabilities.chunk_bytes == transfers::CHUNK_BYTES =>
            {
                if let Some(policy) = &capabilities.limits {
                    policy.validate()?;
                }
                if capabilities.binary_transfer_v1 != (capabilities.limits.is_some() && capabilities.recovery_epoch != 0) {
                    return Err(Error::Invalid("transfer capabilities"));
                }
                Ok(Some(capabilities))
            }
            _ => Err(Error::Invalid("transfer capability identity")),
        }
    }
    fn transfer_ready(&self) -> Result<TransferCapabilities, Error> {
        self.transfer_capabilities()?.filter(|c| c.binary_transfer_v1).ok_or(Error::Server("unsupported_protocol".into()))
    }
    pub fn begin_transfer(&self, input: TransferInput) -> Result<TransferProgress, Error> {
        let caps = self.transfer_ready()?;
        if input.server_id != caps.server_id || input.recovery_epoch != caps.recovery_epoch {
            return Err(Error::Server("recovery_epoch_mismatch".into()));
        }
        if let Some(policy) = &caps.limits
            && input.total_bytes > policy.max_file_bytes
        {
            return Err(Error::FileTooLarge { actual: input.total_bytes, max: policy.max_file_bytes });
        }
        let body = serde_json::to_vec(&input)?;
        if body.len() > transfers::CONTROL_BYTES {
            return Err(Error::Invalid("transfer control limit"));
        }
        match decode(self.transfer_send("POST", "/pdm/v1/transfers", &body, &caps, None)?)? {
            WireResponse::Progress { progress } if progress.total_bytes == input.total_bytes && progress.sha256 == input.sha256 => Ok(progress),
            _ => Err(Error::Invalid("transfer begin response")),
        }
    }
    pub fn transfer_status(&self, id: &str) -> Result<TransferProgress, Error> {
        valid_transfer_id(id)?;
        let caps = self.transfer_ready()?;
        match decode(self.transfer_send("GET", &format!("/pdm/v1/transfers/{id}"), &[], &caps, None)?)? {
            WireResponse::Progress { progress } if progress.transfer_id == id => Ok(progress),
            _ => Err(Error::Invalid("transfer status response")),
        }
    }
    pub fn upload_chunk(&self, id: &str, offset: u64, content: &[u8], hash: &str) -> Result<TransferProgress, Error> {
        valid_transfer_id(id)?;
        valid_transfer_id(hash)?;
        if content.is_empty() || content.len() as u64 > transfers::CHUNK_BYTES || crate::digest(content) != hash {
            return Err(Error::Invalid("chunk input"));
        }
        let caps = self.transfer_ready()?;
        match decode(self.transfer_send("PUT", &format!("/pdm/v1/transfers/{id}/chunks/{offset}"), content, &caps, Some(hash))?)? {
            WireResponse::Progress { progress } if progress.transfer_id == id => Ok(progress),
            _ => Err(Error::Invalid("chunk response")),
        }
    }
    pub fn commit_transfer(&self, id: &str, request_id: &str) -> Result<crate::managed::ManagedVersion, Error> {
        valid_transfer_id(id)?;
        if !crate::valid_id(request_id) {
            return Err(Error::Invalid("request id"));
        }
        let caps = self.transfer_ready()?;
        let body = serde_json::to_vec(&serde_json::json!({"request_id":request_id}))?;
        match decode(self.transfer_send("POST", &format!("/pdm/v1/transfers/{id}/commit"), &body, &caps, None)?)? {
            WireResponse::Committed { version } if version.request_id == request_id => Ok(version),
            _ => Err(Error::Invalid("commit response")),
        }
    }
    pub fn cancel_transfer(&self, id: &str) -> Result<(), Error> {
        valid_transfer_id(id)?;
        let caps = self.transfer_ready()?;
        match decode(self.transfer_send("DELETE", &format!("/pdm/v1/transfers/{id}"), &[], &caps, None)?)? {
            WireResponse::Cancelled {} => Ok(()),
            _ => Err(Error::Invalid("cancel response")),
        }
    }
    /// Writes verified chunks to caller-owned NEW private staging. Only a
    /// successful full-file hash authorizes subsequent working-copy publication.
    pub fn download_stream(&self, reference: &VersionRef, output: &mut dyn Write) -> Result<Version, Error> {
        if !crate::valid_id(&reference.document) || reference.version == 0 {
            return Err(Error::Invalid("content reference"));
        }
        let caps = self.transfer_ready()?;
        let path = format!("/pdm/v1/content/{}/{}", reference.document, reference.version);
        let metadata = match decode(self.transfer_send("GET", &format!("{path}/metadata"), &[], &caps, None)?)? {
            WireResponse::Metadata { metadata } => metadata,
            _ => return Err(Error::Invalid("content metadata")),
        };
        let ContentMetadata { version, total_bytes } = metadata;
        if version.reference != *reference || total_bytes > crate::stream_io::HARD_FILE_BYTES {
            return Err(Error::Integrity);
        }
        valid_transfer_id(&version.sha256)?;
        let mut hasher = Sha256::new();
        let mut offset = 0u64;
        while offset < total_bytes {
            let wanted = transfers::CHUNK_BYTES.min(total_bytes - offset);
            let mut response = self.transfer_send("GET", &format!("{path}?offset={offset}&length={wanted}"), &[], &caps, None)?;
            if response.status().as_u16() != 200 {
                decode(response)?;
                return Err(Error::Invalid("range status"));
            }
            let header = |key: &str| response.headers().get(key).and_then(|v| v.to_str().ok());
            if header("content-type") != Some("application/octet-stream")
                || header("x-pdm-sha256") != Some(version.sha256.as_str())
                || header("x-pdm-offset") != Some(offset.to_string().as_str())
                || header("x-pdm-total-bytes") != Some(total_bytes.to_string().as_str())
                || header("content-length") != Some(wanted.to_string().as_str())
            {
                return Err(Error::Integrity);
            }
            let hash = header("x-chunk-sha256").ok_or(Error::Integrity)?.to_owned();
            valid_transfer_id(&hash)?;
            // ureq's limiter errors when exactly exhausted, before probing EOF.
            // One extra probe byte permits an exact-size chunk; equality below
            // still rejects both a short body and any extra byte.
            let bytes = response.body_mut().with_config().limit(transfers::CHUNK_BYTES + 1).read_to_vec().map_err(|_| https_network_error())?;
            if bytes.len() as u64 != wanted || crate::digest(&bytes) != hash {
                return Err(Error::Integrity);
            }
            hasher.update(&bytes);
            output.write_all(&bytes)?;
            offset += wanted;
        }
        if format!("{:x}", hasher.finalize()) != version.sha256 {
            return Err(Error::Integrity);
        }
        Ok(version)
    }
}
fn valid_transfer_id(value: &str) -> Result<(), Error> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(Error::Invalid("transfer digest/id"));
    }
    Ok(())
}
