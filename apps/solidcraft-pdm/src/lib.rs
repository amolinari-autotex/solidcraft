//! Experimental, single-writer PDM storage and bounded JSON-lines loopback protocol.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub mod administration;
pub mod backup_restore;
pub mod blob_store;
pub mod bootstrap;
pub mod client;
pub mod connector;
pub mod deployment;
mod http_listener;
pub mod http_server;
mod http_transfer;
pub mod managed;
pub mod managed_workspace;
pub mod pairing;
pub mod relay;
pub mod relay_client;
pub mod relay_http;
pub mod s3_blob_store;
pub mod stream_io;
pub mod transfer_source;
pub mod transfer_staging;
pub mod transfers;
pub mod workspace;

pub const PROTOCOL: &str = "solidcraft-pdm/2";
pub const HTTP_RPC_PATH: &str = "/pdm/v2/rpc";

/// HTTPS carries authentication in a bearer header, separate from this payload.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RpcEnvelope {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    pub request: Request,
}
pub const TOKEN_ENV: &str = "SOLIDCRAFT_PDM_TOKEN";

/// A local owner credential. Never include its contents in Debug or error messages.
#[derive(Clone)]
pub struct AuthToken(String);

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken([redacted])")
    }
}

impl AuthToken {
    pub fn parse(value: String) -> Result<Self, Error> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid("owner token must contain 64 hexadecimal characters"));
        }
        Ok(Self(value))
    }

    pub fn from_env() -> Result<Self, Error> {
        Self::parse(std::env::var(TOKEN_ENV).map_err(|_| Error::Invalid("SOLIDCRAFT_PDM_TOKEN is required"))?)
    }

    /// Explicit bootstrap command only: callers must capture stdout privately, never log it.
    pub fn generate() -> Result<String, Error> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Invalid("OS randomness unavailable"))?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn matches(&self, provided: &str) -> bool {
        use subtle::ConstantTimeEq;
        provided.len() == 64 && bool::from(self.0.as_bytes().ct_eq(provided.as_bytes()))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRequest {
    protocol: String,
    token: String,
    request: Request,
}

impl AuthenticatedRequest {
    pub fn new(token: &AuthToken, request: Request) -> Self {
        Self { protocol: PROTOCOL.into(), token: token.0.clone(), request }
    }
}

pub const MAX_CONTENT: usize = 1024 * 1024;
pub const MAX_FRAME: u64 = 8 * 1024 * 1024;
const MAX_DEPENDENCIES: usize = 256;
pub const MAX_VERSIONS: usize = 256;
pub const MAX_STORED_CONTENT: u64 = 64 * 1024 * 1024;

/// The transport intentionally has no bind-address option while it lacks authentication.
pub fn bind_loopback(port: u16) -> Result<TcpListener, Error> {
    Ok(TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local PDM connection failed: {0}")]
    Network(#[source] std::io::Error),
    #[error("server rejected the request: {0}")]
    Server(String),
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    #[error("operation forbidden")]
    Forbidden,
    #[error("version conflict")]
    Conflict,
    #[error("document is referenced by retained versions")]
    Referenced,
    #[error("content requires binary transfer")]
    TransferRequired,
    #[error("file exceeds limit: {actual} bytes; maximum {max} bytes")]
    FileTooLarge { actual: u64, max: u64 },
    #[error("version not found")]
    NotFound,
    #[error("storage integrity failure")]
    Integrity,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRef {
    pub document: String,
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    pub reference: VersionRef,
    pub parent: Option<u64>,
    pub sha256: String,
    pub dependencies: Vec<VersionRef>,
}

/// Authenticated server identity and role, with no bearer or checkout secrets.
/// The principal is selected by server authentication, never a request field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedIdentity {
    pub server_id: String,
    pub principal: managed::Principal,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Identity {},
    ManagedCatalog,
    ManagedCreate { logical_path: String },
    ManagedCreateNew { logical_path: String },
    ManagedMetadata { document: String },
    ManagedNamespaceCapabilities {},
    ManagedNamespaceCatalog {},
    ManagedNamespace { input: managed::NamespaceMutation },
    ManagedCheckout { document: String, workspace: String, machine: String },
    ManagedResumeCheckout { document: String, workspace: String, machine: String },
    ManagedCancelCheckout { document: String, workspace: String, machine: String, checkout_token: String },
    ManagedCheckIn { input: managed::ManagedCheckIn },
    ManagedHistory { document: String },
    CheckIn { document: String, parent: Option<u64>, content: Vec<u8>, dependencies: Vec<VersionRef> },
    Download { reference: VersionRef },
    WhereUsed { reference: VersionRef },
    List { document: Option<String> },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operation = match self {
            Self::Identity {} => "Identity",
            Self::ManagedCatalog => "ManagedCatalog",
            Self::ManagedCreate { .. } => "ManagedCreate",
            Self::ManagedCreateNew { .. } => "ManagedCreateNew",
            Self::ManagedMetadata { .. } => "ManagedMetadata",
            Self::ManagedNamespaceCapabilities {} => "ManagedNamespaceCapabilities",
            Self::ManagedNamespaceCatalog {} => "ManagedNamespaceCatalog",
            Self::ManagedNamespace { .. } => "ManagedNamespace",
            Self::ManagedCheckout { .. } => "ManagedCheckout",
            Self::ManagedResumeCheckout { .. } => "ManagedResumeCheckout",
            Self::ManagedCancelCheckout { .. } => "ManagedCancelCheckout",
            Self::ManagedCheckIn { .. } => "ManagedCheckIn",
            Self::ManagedHistory { .. } => "ManagedHistory",
            Self::CheckIn { .. } => "CheckIn",
            Self::Download { .. } => "Download",
            Self::WhereUsed { .. } => "WhereUsed",
            Self::List { .. } => "List",
        };
        formatter.write_str(operation)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Identity { identity: AuthenticatedIdentity },
    ManagedCatalog { catalog: managed::ManagedCatalog },
    ManagedDocument { entry: managed::CatalogEntry },
    ManagedMetadata { metadata: managed::NamespaceMetadata },
    ManagedNamespaceCapabilities { capabilities: managed::NamespaceCapabilities },
    ManagedNamespaceCatalog { entries: Vec<managed::NamespaceMetadata> },
    ManagedCheckout { grant: managed::CheckoutGrant },
    ManagedCheckedIn { version: managed::ManagedVersion },
    ManagedHistory { versions: Vec<managed::ManagedVersion> },
    Listed { versions: Vec<Version> },
    CheckedIn { version: Version },
    Downloaded { version: Version, content: Vec<u8> },
    WhereUsed { versions: Vec<VersionRef> },
    Error { code: String },
}

/// A process-wide OS lock prevents two servers from allocating the same next version.
/// Each immutable version directory is published with one rename on the same filesystem.
pub struct Store {
    root: PathBuf,
    _lock: File,
    managed: managed::ManagedStore,
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub(crate) fn digest(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

impl Store {
    /// Explicit NEW-installation enrollment completion under the existing writer
    /// lock. Call only from a persisted fresh-setup intent, never on ordinary
    /// startup of a legacy installation. Identity and captured credentials stay
    /// unchanged; a failed conversion retains its fail-closed recovery fence.
    pub fn initialize_enrolled_streaming(&mut self, receipt: &bootstrap::EnrollmentReceipt, policy: stream_io::StreamPolicy) -> Result<(), Error> {
        policy.validate()?;
        if self.managed.server_id() != receipt.server_id {
            return Err(Error::Conflict);
        }
        if let Some(current) = self.managed.stream_policy() {
            return if *current == policy { Ok(()) } else { Err(Error::Conflict) };
        }
        for entry in fs::read_dir(&self.root)? {
            if entry?.file_name().to_string_lossy().starts_with("d-") {
                return Err(Error::Invalid("fresh enrollment requires empty archive"));
            }
        }
        self.managed.initialize_enrolled_streaming(receipt, policy)
    }
    /// Explicit operator action for an empty transactional filesystem archive.
    /// Failure leaves an on-disk fence: restore the prior backup to a NEW root.
    pub fn initialize_streaming(&mut self, policy: stream_io::StreamPolicy) -> Result<(), Error> {
        for entry in fs::read_dir(&self.root)? {
            if entry?.file_name().to_string_lossy().starts_with("d-") {
                return Err(Error::Invalid("streaming initialization requires an empty archive"));
            }
        }
        self.managed.initialize_streaming(policy)
    }
    pub(crate) fn verify_reference(&self, reference: &VersionRef) -> Result<Version, Error> {
        if self.managed.contains(&reference.document) { self.managed.verify_reference(reference) } else { self.download(reference).map(|v| v.0) }
    }
    pub fn list(&self, document: Option<&str>) -> Result<Vec<Version>, Error> {
        let mut result = Vec::new();
        if let Some(document) = document {
            for version in self.versions(document)? {
                result.push(self.download(&VersionRef { document: document.into(), version })?.0);
            }
        } else {
            for entry in fs::read_dir(&self.root)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(document) = name.strip_prefix("d-").filter(|id| valid_id(id)) {
                    result.extend(self.list(Some(document))?);
                }
            }
        }
        result.extend(self.managed.versions().into_iter().filter(|v| document.is_none_or(|d| v.reference.document == d)));
        result.sort_by(|a, b| a.reference.cmp(&b.reference));
        result.dedup_by(|a, b| a.reference == b.reference);
        Ok(result)
    }

    fn check_quota(&self, incoming: usize) -> Result<(), Error> {
        let mut count = 0usize;
        let mut bytes = incoming as u64;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let directory = entry.file_name().to_string_lossy().into_owned();
            let Some(name) = directory.strip_prefix("d-") else {
                continue;
            };
            if !valid_id(name) {
                continue;
            }
            for version in self.versions(name)? {
                count += 1;
                let path = self.version_path(&VersionRef { document: name.into(), version })?;
                bytes = bytes.checked_add(fs::metadata(path.join("content"))?.len()).ok_or(Error::Invalid("storage quota"))?;
                if count >= MAX_VERSIONS || bytes > MAX_STORED_CONTENT {
                    return Err(Error::Invalid("storage quota"));
                }
            }
        }
        Ok(())
    }

    pub fn open(root: &Path) -> Result<Self, Error> {
        Self::open_inner(root, None)
    }
    /// Experimental explicit provider selection. Never migrates a filesystem
    /// archive or discovers credentials/configuration from the environment.
    pub fn open_with_blob_store(root: &Path, blobs: Box<dyn blob_store::BlobStore>) -> Result<Self, Error> {
        if !root.is_absolute() || root.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
            return Err(Error::Invalid("external store requires absolute path without parent traversal"));
        }
        let binding = blobs.binding();
        binding.validate()?;
        if !matches!(binding, blob_store::BlobBinding::External { .. }) {
            return Err(Error::Invalid("external blob binding required"));
        }
        Self::open_inner(root, Some(blobs))
    }
    fn open_inner(root: &Path, blobs: Option<Box<dyn blob_store::BlobStore>>) -> Result<Self, Error> {
        reject_symlink_ancestors(root)?;
        reject_symlink_ancestors(&root.join("writer.lock"))?;
        fs::create_dir_all(root)?;
        let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(root.join("writer.lock"))?;
        lock.try_lock().map_err(|_| Error::Invalid("store is already open"))?;
        if root.join("restore.pending").try_exists()? {
            return Err(Error::Invalid("interrupted restore; preserve this directory and restore to a new destination"));
        }
        let managed = match blobs {
            Some(blobs) => managed::ManagedStore::open_external(root, blobs)?,
            None => managed::ManagedStore::open(root)?,
        };
        Ok(Self { root: root.to_path_buf(), _lock: lock, managed })
    }
    pub(crate) fn managed_snapshot(&self) -> Result<managed::ManagedSnapshot, Error> {
        self.managed.snapshot()
    }
    pub(crate) fn blob_inventory(&self) -> Result<Vec<blob_store::BlobReceipt>, Error> {
        self.managed.blob_inventory()
    }

    fn document_path(&self, document: &str) -> Result<PathBuf, Error> {
        if !valid_id(document) {
            return Err(Error::Invalid("document ID"));
        }
        Ok(self.root.join(format!("d-{document}")))
    }

    fn version_path(&self, reference: &VersionRef) -> Result<PathBuf, Error> {
        if reference.version == 0 {
            return Err(Error::Invalid("version must be positive"));
        }
        Ok(self.document_path(&reference.document)?.join(reference.version.to_string()))
    }

    fn versions(&self, document: &str) -> Result<Vec<u64>, Error> {
        let path = self.document_path(document)?;
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut versions = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if let Some(n) = entry.file_name().to_str().and_then(|s| s.parse::<u64>().ok())
                && n > 0
            {
                versions.push(n);
            }
        }
        versions.sort_unstable();
        Ok(versions)
    }

    pub fn download(&self, reference: &VersionRef) -> Result<(Version, Vec<u8>), Error> {
        if self.managed.contains(&reference.document) {
            return self.managed.download(reference);
        }
        let path = self.version_path(reference)?;
        if !path.is_dir() {
            return Err(Error::NotFound);
        }
        let version: Version = serde_json::from_slice(&fs::read(path.join("version.json"))?)?;
        let content = fs::read(path.join("content"))?;
        if version.reference != *reference || digest(&content) != version.sha256 {
            return Err(Error::Integrity);
        }
        Ok((version, content))
    }

    pub fn check_in(&mut self, document: String, parent: Option<u64>, content: Vec<u8>, dependencies: Vec<VersionRef>) -> Result<Version, Error> {
        if self.managed.contains(&document) {
            return Err(Error::Forbidden);
        }
        let path = self.document_path(&document)?;
        if content.len() > MAX_CONTENT || dependencies.len() > MAX_DEPENDENCIES {
            return Err(Error::Invalid("size limit"));
        }
        let latest = self.versions(&document)?.last().copied();
        // Old archives accepted this prefix before managed identities existed.
        // Only a verified, already-published legacy document can retain it.
        if document.starts_with("m-") {
            let version = latest.ok_or(Error::Forbidden)?;
            self.download(&VersionRef { document: document.clone(), version })?;
        }
        if latest != parent {
            return Err(Error::Conflict);
        }
        self.check_quota(content.len())?;
        let mut unique = BTreeSet::new();
        for dep in &dependencies {
            if self.managed.tombstoned(&dep.document) {
                return Err(Error::Referenced);
            }
            if dep.document == document || !unique.insert(dep) {
                return Err(Error::Invalid("self or duplicate dependency"));
            }
            self.download(dep)?;
        }
        let number = latest.unwrap_or(0).checked_add(1).ok_or(Error::Invalid("version exhausted"))?;
        let version = Version { reference: VersionRef { document, version: number }, parent, sha256: digest(&content), dependencies };
        fs::create_dir_all(&path)?;
        let staging = path.join("pending");
        // Only this process owns the store lock. A leftover unpublished stage is disposable.
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        fs::create_dir(&staging)?;
        write_synced(&staging.join("content"), &content)?;
        write_synced(&staging.join("version.json"), &serde_json::to_vec(&version)?)?;
        fs::rename(&staging, self.version_path(&version.reference)?)?;
        Ok(version)
    }

    pub fn where_used(&self, reference: &VersionRef) -> Result<Vec<VersionRef>, Error> {
        self.verify_reference(reference)?;
        let mut result = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let directory = entry.file_name().to_string_lossy().into_owned();
            let Some(name) = directory.strip_prefix("d-") else {
                continue;
            };
            if !valid_id(name) {
                continue;
            }
            for version in self.versions(name)? {
                let reference_candidate = VersionRef { document: name.to_owned(), version };
                let (metadata, _) = self.download(&reference_candidate)?;
                if metadata.dependencies.contains(reference) {
                    result.push(reference_candidate);
                }
            }
        }
        result.extend(self.managed.where_used(reference));
        result.sort();
        result.dedup();
        Ok(result)
    }

    pub fn execute(&mut self, request: Request) -> Response {
        self.execute_as(request, &managed::Principal { id: "owner".into(), role: managed::Role::Administrator })
    }

    /// Secure transports require configured accounts and never the loopback owner.
    pub(crate) fn has_configured_principals(&self) -> bool {
        self.managed.has_configured_principals()
    }

    pub(crate) fn execute_configured_for(&mut self, request: Request, bearer: &str, expected_server: Option<&str>) -> Response {
        let Some(principal) = self.managed.authenticate(bearer) else {
            return Response::Error { code: "unauthorized".into() };
        };
        match expected_server {
            Some(expected) if expected != self.managed.server_id() => {
                return Response::Error { code: "server_identity_mismatch".into() };
            }
            None if !matches!(&request, Request::ManagedCatalog) => {
                return Response::Error { code: "server_identity_required".into() };
            }
            _ => {}
        }
        self.execute_as(request, &principal)
    }

    /// Mint pairing administration from a configured account, bound to this store.
    pub fn pairing_administrator(&self, bearer: &AuthToken) -> Result<pairing::PairingAdmin, Error> {
        let principal =
            self.managed.authenticate(&bearer.0).filter(|principal| principal.role == managed::Role::Administrator).ok_or(Error::Forbidden)?;
        Ok(pairing::PairingAdmin::authenticated(principal.id, self.managed.server_id().to_owned()))
    }

    pub fn execute_as(&mut self, request: Request, principal: &managed::Principal) -> Response {
        let result = match request {
            Request::Identity {} => Ok(Response::Identity {
                identity: AuthenticatedIdentity { server_id: self.managed.server_id().to_owned(), principal: principal.clone() },
            }),
            Request::ManagedCatalog => Ok(Response::ManagedCatalog { catalog: self.managed.catalog() }),
            Request::ManagedCreate { logical_path } => self.managed.create(principal, logical_path).map(|entry| Response::ManagedDocument { entry }),
            Request::ManagedMetadata { document } => {
                self.managed.namespace_metadata(&document).map(|metadata| Response::ManagedMetadata { metadata })
            }
            Request::ManagedNamespaceCapabilities {} => {
                Ok(Response::ManagedNamespaceCapabilities { capabilities: self.managed.namespace_capabilities(principal) })
            }
            Request::ManagedNamespaceCatalog {} => self.managed.namespace_catalog().map(|entries| Response::ManagedNamespaceCatalog { entries }),
            Request::ManagedNamespace { input } => (|| {
                let mut referenced = false;
                if matches!(input.action, managed::NamespaceAction::Tombstone) {
                    for version in self.managed.history(&input.document)? {
                        if !self.where_used(&version.version.reference)?.is_empty() {
                            referenced = true;
                            break;
                        }
                    }
                }
                self.managed.namespace_mutate(principal, input, referenced)
            })()
            .map(|metadata| Response::ManagedMetadata { metadata }),
            Request::ManagedCreateNew { logical_path } => {
                self.managed.create_new(principal, logical_path).map(|entry| Response::ManagedDocument { entry })
            }
            Request::ManagedResumeCheckout { document, workspace, machine } => {
                self.managed.resume_checkout(principal, &document, &workspace, &machine).map(|grant| Response::ManagedCheckout { grant })
            }
            Request::ManagedCheckout { document, workspace, machine } => {
                self.managed.checkout(principal, &document, workspace, machine).map(|grant| Response::ManagedCheckout { grant })
            }
            Request::ManagedCancelCheckout { document, workspace, machine, checkout_token } => {
                self.managed.cancel(principal, &document, &workspace, &machine, &checkout_token).map(|entry| Response::ManagedDocument { entry })
            }
            Request::ManagedCheckIn { input } => self.managed.check_in(principal, input).map(|version| Response::ManagedCheckedIn { version }),
            Request::ManagedHistory { document } => self.managed.history(&document).map(|versions| Response::ManagedHistory { versions }),
            Request::List { document } => self.list(document.as_deref()).map(|versions| Response::Listed { versions }),
            Request::CheckIn { document, parent, content, dependencies } => {
                if principal.role == managed::Role::Viewer {
                    Err(Error::Forbidden)
                } else {
                    self.check_in(document, parent, content, dependencies).map(|version| Response::CheckedIn { version })
                }
            }
            Request::Download { reference } => self.download(&reference).map(|(version, content)| Response::Downloaded { version, content }),
            Request::WhereUsed { reference } => self.where_used(&reference).map(|versions| Response::WhereUsed { versions }),
        };
        result.unwrap_or_else(|error| Response::Error {
            code: match error {
                Error::Forbidden => "forbidden",
                Error::Conflict => "conflict",
                Error::Referenced => "referenced",
                Error::TransferRequired => "transfer_required",
                Error::NotFound => "not_found",
                Error::Invalid(_) => "invalid_request",
                Error::Integrity => "integrity",
                _ => "storage_error",
            }
            .into(),
        })
    }
}

// Fail closed for pre-existing symlink/junction store paths. The store directory
// remains trusted local state: this does not defend against concurrent host tampering.
pub(crate) fn reject_symlink_ancestors(path: &Path) -> Result<(), Error> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Invalid("symlink store path"));
            }
            Ok(metadata) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(Error::Invalid("reparse store path"));
                    }
                }
                #[cfg(not(windows))]
                let _ = metadata;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_synced(path: &Path, content: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

/// Read one bounded frame; callers must provide a reader with appropriate time limits.
pub fn read_frame(reader: impl Read) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    BufReader::new(reader.take(MAX_FRAME + 1)).read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > MAX_FRAME || bytes.last() != Some(&b'\n') {
        return Err(Error::Invalid("frame size or terminator"));
    }
    Ok(bytes)
}

/// An absolute frame budget is recomputed before every underlying socket read.
pub fn read_socket_frame(stream: &TcpStream, budget: Duration) -> Result<Vec<u8>, Error> {
    let started = Instant::now();
    let mut stream = stream;
    read_budgeted_frame(
        |buffer, remaining| {
            stream.set_read_timeout(Some(remaining))?;
            stream.read(buffer)
        },
        || started.elapsed(),
        budget,
    )
}

// Clock and I/O seams keep the repeated-read regression independent of thread scheduling.
fn read_budgeted_frame<R, C>(reader: R, elapsed: C, budget: Duration) -> Result<Vec<u8>, Error>
where
    R: FnMut(&mut [u8], Duration) -> std::io::Result<usize>,
    C: FnMut() -> Duration,
{
    struct BudgetReader<R, C> {
        reader: R,
        elapsed: C,
        budget: Duration,
    }
    impl<R, C> Read for BudgetReader<R, C>
    where
        R: FnMut(&mut [u8], Duration) -> std::io::Result<usize>,
        C: FnMut() -> Duration,
    {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self
                .budget
                .checked_sub((self.elapsed)())
                .filter(|duration| !duration.is_zero())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "frame deadline exceeded"))?;
            (self.reader)(buffer, remaining)
        }
    }
    read_frame(BudgetReader { reader, elapsed, budget })
}

pub fn serve_connection(store: &mut Store, mut stream: TcpStream, token: &AuthToken) -> Result<(), Error> {
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let response =
        match read_socket_frame(&stream, Duration::from_secs(5)).and_then(|bytes| Ok(serde_json::from_slice::<AuthenticatedRequest>(&bytes)?)) {
            Ok(envelope) if envelope.protocol != PROTOCOL => Response::Error { code: "unsupported_protocol".into() },
            Ok(envelope) => {
                let principal = if token.matches(&envelope.token) {
                    Some(managed::Principal { id: "owner".into(), role: managed::Role::Administrator })
                } else {
                    store.managed.authenticate(&envelope.token)
                };
                match principal {
                    Some(principal) => store.execute_as(envelope.request, &principal),
                    None => Response::Error { code: "unauthorized".into() },
                }
            }
            Err(_) => Response::Error { code: "invalid_request".into() },
        };
    let bytes = serde_json::to_vec(&response)?;
    write_socket_frame(&mut stream, &bytes, Duration::from_secs(5))?;
    Ok(())
}

/// Serialize before entering this function so tiny JSON writes cannot extend a connection.
pub fn write_socket_frame(stream: &mut TcpStream, bytes: &[u8], budget: Duration) -> Result<(), Error> {
    let started = Instant::now();
    write_budgeted_frame(
        |bytes, remaining| {
            stream.set_write_timeout(Some(remaining))?;
            stream.write(bytes)
        },
        || started.elapsed(),
        bytes,
        budget,
    )
}

fn write_budgeted_frame<W, C>(writer: W, elapsed: C, bytes: &[u8], budget: Duration) -> Result<(), Error>
where
    W: FnMut(&[u8], Duration) -> std::io::Result<usize>,
    C: FnMut() -> Duration,
{
    if bytes.len() as u64 >= MAX_FRAME {
        return Err(Error::Invalid("response frame size"));
    }
    struct BudgetWriter<W, C> {
        writer: W,
        elapsed: C,
        budget: Duration,
    }
    impl<W, C> Write for BudgetWriter<W, C>
    where
        W: FnMut(&[u8], Duration) -> std::io::Result<usize>,
        C: FnMut() -> Duration,
    {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let remaining = self
                .budget
                .checked_sub((self.elapsed)())
                .filter(|duration| !duration.is_zero())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "response deadline exceeded"))?;
            (self.writer)(bytes, remaining)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = BudgetWriter { writer, elapsed, budget };
    writer.write_all(bytes)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_identity_is_authenticated_fenced_and_preserves_each_role_over_https() {
        let root = std::env::temp_dir().join(format!("solidcraft-identity-{}", AuthToken::generate().unwrap()));
        std::fs::create_dir(&root).unwrap();
        let accounts = [
            ("reader", managed::Role::Viewer, AuthToken::generate().unwrap()),
            ("writer", managed::Role::Contributor, AuthToken::generate().unwrap()),
            ("administrator", managed::Role::Administrator, AuthToken::generate().unwrap()),
        ];
        let credentials = accounts
            .iter()
            .map(|(id, role, bearer)| managed::PrincipalCredential {
                principal: managed::Principal { id: (*id).into(), role: *role },
                token_sha256: digest(bearer.as_bytes()),
            })
            .collect::<Vec<_>>();
        std::fs::write(root.join("managed-principals.json"), serde_json::to_vec(&credentials).unwrap()).unwrap();
        let mut store = Store::open(&root).unwrap();
        let server_id = store.managed.server_id().to_owned();
        let wrong_server = if server_id == "00".repeat(32) { "11".repeat(32) } else { "00".repeat(32) };
        let unknown = AuthToken::generate().unwrap();
        assert!(
            matches!(store.execute_configured_for(Request::Identity {}, &unknown, Some(&server_id)), Response::Error { code } if code == "unauthorized")
        );
        assert!(
            matches!(store.execute_configured_for(Request::Identity {}, &accounts[0].2, None), Response::Error { code } if code == "server_identity_required")
        );
        assert!(
            matches!(store.execute_configured_for(Request::Identity {}, &accounts[0].2, Some(&wrong_server)), Response::Error { code } if code == "server_identity_mismatch")
        );
        assert!(matches!(serde_json::from_str::<Request>(r#"{"operation":"identity"}"#).unwrap(), Request::Identity {}));
        for field in ["username", "principal", "principal_id", "role", "secret", "token"] {
            let fake = serde_json::json!({"operation":"identity", (field):"administrator"});
            assert!(serde_json::from_value::<Request>(fake).is_err());
        }
        for (id, role, bearer) in &accounts {
            match store.execute_configured_for(Request::Identity {}, bearer, Some(&server_id)) {
                Response::Identity { identity } => {
                    assert_eq!(identity.server_id, server_id);
                    assert_eq!(identity.principal, managed::Principal { id: (*id).into(), role: *role });
                    assert!(!serde_json::to_string(&identity).unwrap().contains(bearer));
                }
                other => panic!("{other:?}"),
            }
        }
        let tls = http_server::HttpsConfig::from_der(
            "127.0.0.1:0".parse().unwrap(),
            vec![include_bytes!("../tests/fixtures/pdm-https/server.der").to_vec()],
            include_bytes!("../tests/fixtures/pdm-https/server-key.der").to_vec(),
        )
        .unwrap();
        let server = http_server::HttpsServer::start(store, tls).unwrap();
        let endpoint = format!("https://{}", server.address());
        let ca = include_bytes!("../tests/fixtures/pdm-https/ca.der");
        for (id, role, bearer) in &accounts {
            let client = client::Client::https_with_ca(&endpoint, AuthToken::parse(bearer.clone()).unwrap(), ca).unwrap();
            let identity = client.authenticated_identity().unwrap();
            assert_eq!(identity.server_id, server_id);
            assert_eq!(identity.principal.id, *id);
            assert_eq!(identity.principal.role, *role);
        }
        let unknown_client = client::Client::https_with_ca(&endpoint, AuthToken::parse(unknown).unwrap(), ca).unwrap();
        assert!(matches!(unknown_client.authenticated_identity(), Err(Error::Server(code)) if code == "unauthorized"));
        let wrong = client::Client::https_with_ca(&endpoint, AuthToken::parse(accounts[0].2.clone()).unwrap(), ca)
            .unwrap()
            .bind_server(&wrong_server)
            .unwrap();
        assert!(matches!(wrong.authenticated_identity(), Err(Error::Server(code)) if code == "server_identity_mismatch"));
        server.shutdown().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn configured_dispatch_requires_enrollment_and_rejects_unregistered_owner() {
        let root = std::env::temp_dir().join(format!("solidcraft-configured-auth-{}", AuthToken::generate().unwrap()));
        let unknown_owner = AuthToken::generate().unwrap();
        let mut store = Store::open(&root).unwrap();
        assert!(!store.has_configured_principals());
        assert!(matches!(
            store.execute_configured_for(Request::ManagedCatalog, &unknown_owner, None),
            Response::Error { code } if code == "unauthorized"
        ));
        drop(store);
        let (_, enrolled) = bootstrap::initialize(&root, "administrator").unwrap();
        let enrolled = enrolled.into_bearer();
        let mut store = Store::open(&root).unwrap();
        assert!(store.has_configured_principals());
        assert!(matches!(store.execute_configured_for(Request::ManagedCatalog, &enrolled, None), Response::ManagedCatalog { .. }));
        assert!(matches!(
            store.execute_configured_for(Request::ManagedCatalog, &unknown_owner, None),
            Response::Error { code } if code == "unauthorized"
        ));
        assert!(matches!(
            store.execute_configured_for(Request::ManagedCreate { logical_path: "must-not-exist.solidcraft".into() }, &enrolled, None),
            Response::Error { code } if code == "server_identity_required"
        ));
        let server_id = store.managed.server_id().to_owned();
        let wrong_id = if server_id == "00".repeat(32) { "11".repeat(32) } else { "00".repeat(32) };
        assert!(matches!(
            store.execute_configured_for(Request::ManagedCreate { logical_path: "must-not-exist.solidcraft".into() }, &enrolled, Some(&wrong_id)),
            Response::Error { code } if code == "server_identity_mismatch"
        ));
        assert!(store.managed.catalog().entries.is_empty());
        assert!(store.pairing_administrator(&AuthToken::parse(unknown_owner).unwrap()).is_err());
        let admin = store.pairing_administrator(&AuthToken::parse(enrolled).unwrap()).unwrap();
        let (receipt, _) = pairing::PairingRegistry::default().issue(&admin, "test-tunnel", Duration::from_secs(60)).unwrap();
        assert_eq!(receipt.server_id, server_id);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pairing_administration_is_minted_only_for_configured_administrators() {
        let root = std::env::temp_dir().join(format!("solidcraft-pairing-auth-{}", AuthToken::generate().unwrap()));
        std::fs::create_dir(&root).unwrap();
        let reader = AuthToken::generate().unwrap();
        let contributor = AuthToken::generate().unwrap();
        let administrator = AuthToken::generate().unwrap();
        let entries = [("reader", "viewer", &reader), ("writer", "contributor", &contributor), ("administrator", "administrator", &administrator)]
            .into_iter()
            .map(|(id, role, token)| serde_json::json!({"principal":{"id":id,"role":role},"token_sha256":digest(token.as_bytes())}))
            .collect::<Vec<_>>();
        std::fs::write(root.join("managed-principals.json"), serde_json::to_vec(&entries).unwrap()).unwrap();
        let store = Store::open(&root).unwrap();
        assert!(store.pairing_administrator(&AuthToken::parse(reader).unwrap()).is_err());
        assert!(store.pairing_administrator(&AuthToken::parse(contributor).unwrap()).is_err());
        assert_eq!(store.pairing_administrator(&AuthToken::parse(administrator).unwrap()).unwrap().principal_id(), "administrator");
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_write_retries_with_remaining_budget_and_preserves_bytes() {
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let mut attempts = 0;
        let mut output = Vec::new();
        let mut budgets = Vec::new();
        let result = write_budgeted_frame(
            |bytes, remaining| {
                attempts += 1;
                budgets.push(remaining.as_millis());
                elapsed.set(elapsed.get() + Duration::from_millis(10));
                if attempts == 2 {
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
                }
                if let Some(byte) = bytes.first() {
                    output.push(*byte);
                    Ok(1)
                } else {
                    Err(std::io::Error::other("empty write"))
                }
            },
            || elapsed.get(),
            b"ab",
            Duration::from_millis(100),
        );
        assert!(result.is_ok());
        assert_eq!(attempts, 4);
        assert_eq!(output, b"ab\n");
        assert_eq!(budgets, vec![100, 90, 80, 70]);
    }

    #[test]
    fn repeated_partial_writes_do_not_reset_the_response_deadline() {
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let mut written = 0;
        let mut budgets = Vec::new();
        let result = write_budgeted_frame(
            |bytes, remaining| {
                assert!(!bytes.is_empty());
                written += 1;
                budgets.push(remaining.as_millis());
                elapsed.set(elapsed.get() + Duration::from_millis(20));
                Ok(1)
            },
            || elapsed.get(),
            b"123456",
            Duration::from_millis(100),
        );
        assert!(matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut));
        assert_eq!(written, 5);
        assert_eq!(budgets, vec![100, 80, 60, 40, 20]);
    }

    #[test]
    fn repeated_reads_do_not_reset_the_frame_deadline() {
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let mut reads = 0;
        let mut budgets = Vec::new();
        let result = read_budgeted_frame(
            |buffer, remaining| {
                let byte = buffer.first_mut().ok_or_else(|| std::io::Error::other("empty read buffer"))?;
                *byte = b' ';
                reads += 1;
                budgets.push(remaining.as_millis());
                elapsed.set(elapsed.get() + Duration::from_millis(20));
                Ok(1)
            },
            || elapsed.get(),
            Duration::from_millis(100),
        );
        assert!(matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut));
        assert_eq!(reads, 5);
        assert_eq!(budgets, vec![100, 80, 60, 40, 20]);
    }
}
