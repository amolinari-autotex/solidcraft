//! Explicit HTTPS deployment of an existing enrolled archive. The default
//! loader/start path remains loopback-only; remote binding requires the named
//! opt-in API. Configuration contains no credentials or enrollment instructions.
use crate::{
    Error, Request, Response, Store,
    client::read_file,
    http_server::{HttpsConfig, HttpsServer},
    managed::PrincipalCredential,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};
const MAX_CONFIG: usize = 64 * 1024;
const MAX_TLS: usize = 64 * 1024;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub store: PathBuf,
    pub bind: SocketAddr,
    pub certificate_chain: Vec<PathBuf>,
    pub private_key: PathBuf,
}
impl DeploymentConfig {
    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::load_inner(path, false)
    }
    /// Operator-selected remote deployment. Clients must trust the configured
    /// certificate chain through their normal CA/pinning boundary.
    pub fn load_explicit_remote(path: &Path) -> Result<Self, Error> {
        Self::load_inner(path, true)
    }
    fn load_inner(path: &Path, remote: bool) -> Result<Self, Error> {
        validate_path(path)?;
        let config: Self = serde_json::from_slice(&read_file(path, MAX_CONFIG)?)?;
        if remote {
            config.validate_explicit_remote()?;
        } else {
            config.validate()?;
        }
        Ok(config)
    }
    fn validate(&self) -> Result<(), Error> {
        // Public addresses fail before inspecting any configured archive/key path.
        if !self.bind.ip().is_loopback() {
            return Err(Error::Invalid("deployment rehearsal requires loopback"));
        }
        self.validate_paths()
    }
    fn validate_explicit_remote(&self) -> Result<(), Error> {
        if self.bind.port() == 0 {
            return Err(Error::Invalid("explicit remote deployment requires a nonzero port"));
        }
        self.validate_paths()
    }
    fn validate_paths(&self) -> Result<(), Error> {
        if self.certificate_chain.is_empty() || self.certificate_chain.len() > 8 {
            return Err(Error::Invalid("deployment certificate count"));
        }
        validate_path(&self.store)?;
        validate_path(&self.private_key)?;
        for certificate in &self.certificate_chain {
            validate_path(certificate)?;
        }
        Ok(())
    }
}
fn validate_path(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Error::Invalid("deployment requires absolute paths without parent traversal"));
    }
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(Error::Invalid("deployment link path"));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(Error::Invalid("deployment reparse path"));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
#[derive(Debug, Serialize)]
pub struct ReadinessReceipt {
    pub server_id: String,
    pub address: SocketAddr,
}
pub struct RehearsalServer {
    server: HttpsServer,
    receipt: ReadinessReceipt,
}
impl RehearsalServer {
    pub fn receipt(&self) -> &ReadinessReceipt {
        &self.receipt
    }
    pub fn shutdown(self) -> Result<(), Error> {
        self.server.shutdown()
    }
}
pub fn start_loopback_rehearsal(config: DeploymentConfig) -> Result<RehearsalServer, Error> {
    config.validate()?;
    start_validated(config)
}
/// Start only an explicitly configured HTTPS listener. This never initializes,
/// enrolls or migrates a store, and never falls back to a local owner credential.
pub fn start_explicit_remote(config: DeploymentConfig) -> Result<RehearsalServer, Error> {
    config.validate_explicit_remote()?;
    start_validated(config)
}
fn start_validated(config: DeploymentConfig) -> Result<RehearsalServer, Error> {
    let mut certificates = Vec::new();
    for path in &config.certificate_chain {
        certificates.push(read_file(path, MAX_TLS)?);
    }
    let key = read_file(&config.private_key, MAX_TLS)?;
    let tls = HttpsConfig::from_der(config.bind, certificates, key)?;
    // Refuse missing/unenrolled stores instead of allowing Store::open to create
    // one. The same trusted host account must not mutate paths during preflight.
    if !fs::symlink_metadata(&config.store)?.is_dir() {
        return Err(Error::Invalid("deployment store directory"));
    }
    let transactional = config.store.join("managed/metadata.redb");
    validate_path(&transactional)?;
    if !transactional.try_exists()? {
        let registry = config.store.join("managed-principals.json");
        validate_path(&registry)?;
        let credentials: Vec<PrincipalCredential> = serde_json::from_slice(&read_file(&registry, MAX_CONFIG)?)?;
        if credentials.is_empty() {
            return Err(Error::Invalid("deployment requires enrolled principals"));
        }
        let generations = config.store.join("managed/generations");
        validate_path(&generations)?;
        if !fs::symlink_metadata(&generations)?.is_dir() {
            return Err(Error::Invalid("deployment requires initialized metadata"));
        }
        let mut initialized = false;
        for (index, entry) in fs::read_dir(&generations)?.enumerate() {
            if index >= 4096 {
                return Err(Error::Invalid("deployment generation entry limit"));
            }
            let entry = entry?;
            if entry.file_name().to_str().and_then(|name| name.parse::<u64>().ok()).is_some_and(|number| number > 0) {
                validate_path(&entry.path())?;
                if !entry.file_type()?.is_dir() {
                    return Err(Error::Integrity);
                }
                let state = entry.path().join("state.json");
                validate_path(&state)?;
                if !fs::symlink_metadata(state)?.is_file() {
                    return Err(Error::Integrity);
                }
                initialized = true;
            }
        }
        if !initialized {
            return Err(Error::Invalid("deployment requires initialized metadata"));
        }
    }
    let mut store = Store::open(&config.store)?;
    let server_id = match store.execute(Request::ManagedCatalog) {
        Response::ManagedCatalog { catalog } => catalog.server_id,
        _ => return Err(Error::Integrity),
    };
    let server = HttpsServer::start(store, tls)?;
    let receipt = ReadinessReceipt { server_id, address: server.address() };
    Ok(RehearsalServer { server, receipt })
}
