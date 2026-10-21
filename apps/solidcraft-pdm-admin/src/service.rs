//! All filesystem, credential and HTTPS operations run on the console worker.
use crate::pdm_credentials::{BearerSecret, CredentialContext, CredentialKey, CredentialStore, Purpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Error, Store,
    administration::{AdminRequest, AdminResponse, Capabilities, PublicAuditEvent, UserSummary},
    backup_restore, bootstrap,
    client::Client,
    http_server::{HttpsConfig, HttpsServer},
    managed::Role,
    stream_io::StreamPolicy,
};
use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener},
    path::{Component, Path, PathBuf},
};

fn invalid(reason: &'static str) -> Error {
    Error::Invalid(reason)
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn default_stream_policy() -> StreamPolicy {
    StreamPolicy { version: 1, max_file_bytes: 512 * 1024 * 1024, max_store_bytes: 20 * 1024 * 1024 * 1024 }
}
/// Pure conversion for the new-installation controls; the worker validates the
/// byte policy again before creating any directory or administrator authority.
pub fn stream_policy_from_units(file_mib: u64, archive_gib: u64) -> Result<StreamPolicy, Error> {
    let policy = StreamPolicy {
        version: 1,
        max_file_bytes: file_mib.checked_mul(1024 * 1024).ok_or(invalid("stream policy"))?,
        max_store_bytes: archive_gib.checked_mul(1024 * 1024 * 1024).ok_or(invalid("stream policy"))?,
    };
    policy.validate()?;
    Ok(policy)
}
fn path_check(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() || path.components().any(|part| matches!(part, Component::ParentDir)) {
        return Err(invalid("absolute physical server path required"));
    }
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(invalid("symlink server path"));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(invalid("reparse server path"));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn directory(path: &Path) -> Result<(), Error> {
    path_check(path)?;
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut private_builder = builder;
        private_builder.mode(0o700);
        private_builder
    };
    builder.create(path)?;
    #[cfg(windows)]
    private_windows_directory(path)?;
    Ok(())
}
#[cfg(windows)]
fn private_windows_directory(path: &Path) -> Result<(), Error> {
    use std::{os::windows::process::CommandExt, process::Command};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let system = PathBuf::from(std::env::var_os("SystemRoot").ok_or(invalid("Windows system directory unavailable"))?).join("System32");
    if !system.is_absolute() {
        return Err(invalid("Windows system directory must be absolute"));
    }
    let identity = Command::new(system.join("whoami.exe")).args(["/user", "/fo", "csv", "/nh"]).creation_flags(CREATE_NO_WINDOW).output()?;
    if !identity.status.success() {
        return Err(invalid("current Windows identity lookup failed"));
    }
    // The display name may use an OEM code page; only the final strictly ASCII
    // SID field is consumed as authority below.
    let identity = String::from_utf8_lossy(&identity.stdout);
    let line = identity.lines().find(|line| !line.trim().is_empty()).ok_or(invalid("Windows identity missing"))?;
    let sid = line.rsplit(',').next().unwrap_or_default().trim().trim_matches('"');
    if sid.len() > 128
        || !sid.starts_with("S-1-")
        || sid.split('-').skip(1).any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(invalid("Windows SID validation failed"));
    }
    let acl = Command::new(system.join("icacls.exe"))
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &format!("*{sid}:(OI)(CI)F"), "*S-1-5-18:(OI)(CI)F"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !acl.status.success() {
        return Err(invalid("private Windows installation ACL could not be applied"));
    }
    Ok(())
}
fn publish(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    path_check(path)?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    path_check(path)?;
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(invalid("regular console metadata file required"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("console metadata limit"));
    }
    Ok(bytes)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    version: u32,
    pub server_id: String,
    pub administrator: String,
    pub port: u16,
    certificate_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stream_policy: Option<StreamPolicy>,
}
impl Installation {
    fn origin(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }
    fn key(&self, der: &[u8], account: &str) -> Result<CredentialKey, Error> {
        let context = CredentialContext::certificate_der(der, None).map_err(|_| invalid("invalid console trust"))?;
        CredentialKey::new_scoped(&self.origin(), &self.server_id, account, Purpose::User, &context).map_err(|_| invalid("invalid credential scope"))
    }
    fn save(&self, root: &Path) -> Result<(), Error> {
        publish(&root.join("console.json"), &serde_json::to_vec_pretty(self)?)
    }
    fn load(root: &Path) -> Result<(Self, Vec<u8>, Vec<u8>), Error> {
        let result = Self::load_record(root, "console.json")?;
        path_check(&root.join("archive/managed/metadata.redb"))?;
        if !root.join("archive/managed/metadata.redb").is_file() {
            return Err(invalid("existing transactional archive required"));
        }
        result.0.verify_saved_policy(root)?;
        Ok(result)
    }
    fn verify_saved_policy(&self, root: &Path) -> Result<(), Error> {
        if let Some(expected) = &self.stream_policy {
            expected.validate()?;
            let managed = root.join("archive/managed");
            path_check(&managed.join("stream-policy.pending"))?;
            if managed.join("stream-policy.pending").try_exists()? {
                return Err(invalid("incomplete stream policy initialization; preserve installation"));
            }
            let actual: StreamPolicy = serde_json::from_slice(&read(&managed.join("stream-policy.json"), 1024)?)?;
            actual.validate()?;
            if actual != *expected {
                return Err(invalid("saved stream policy differs from installation intent"));
            }
        }
        Ok(())
    }
    fn load_record(root: &Path, file: &str) -> Result<(Self, Vec<u8>, Vec<u8>), Error> {
        let record: Self = serde_json::from_slice(&read(&root.join(file), 16 * 1024)?)?;
        if record.version != 1 || record.port == 0 {
            return Err(invalid("unsupported console installation"));
        }
        if let Some(policy) = &record.stream_policy {
            policy.validate()?;
        }
        let der = read(&root.join("tls/certificate.der"), 64 * 1024)?;
        if hash(&der) != record.certificate_sha256 {
            return Err(invalid("console trust changed; preserve installation"));
        }
        record.key(&der, &record.administrator)?;
        let key = read(&root.join("tls/private-key.der"), 16 * 1024)?;
        HttpsConfig::from_der((Ipv4Addr::LOCALHOST, record.port).into(), vec![der.clone()], key.clone())?;
        Ok((record, der, key))
    }
}
#[derive(Clone, Default)]
pub struct Snapshot {
    pub running: bool,
    pub verified: bool,
    pub root: String,
    pub origin: String,
    pub server_id: String,
    pub administrator: String,
    pub backend: String,
    pub revision: u64,
    pub users: Vec<UserSummary>,
    pub audit: Vec<PublicAuditEvent>,
    pub next_audit: Option<u64>,
    pub permissions: Vec<String>,
    pub pending: bool,
    pub warning: Option<String>,
}
pub enum Action {
    Create { root: PathBuf, administrator: String, port: u16 },
    CreateConfigured { root: PathBuf, administrator: String, port: u16, stream_policy: StreamPolicy },
    Open(PathBuf),
    Start,
    Stop,
    Refresh,
    Retry,
    CreateUser { id: String, role: Role },
    Role { id: String, role: Role },
    Enabled { id: String, enabled: bool },
    Reset { id: String },
    Audit { more: bool },
    Backup(PathBuf),
    Restore { source: PathBuf, destination: PathBuf },
}
pub struct Service<C: CredentialStore> {
    pub credentials: C,
    root: Option<PathBuf>,
    installation: Option<Installation>,
    running: Option<HttpsServer>,
    client: Option<Client>,
    pub snapshot: Snapshot,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u32,
    server_id: String,
    administrator: String,
    request: AdminRequest,
}
impl<C: CredentialStore> Service<C> {
    pub fn new(credentials: C) -> Self {
        Self { credentials, root: None, installation: None, running: None, client: None, snapshot: Snapshot::default() }
    }
    fn require_stopped(&self) -> Result<(), Error> {
        if self.running.is_some() { Err(invalid("stop the owned service first")) } else { Ok(()) }
    }
    fn root(&self) -> Result<&Path, Error> {
        self.root.as_deref().ok_or(invalid("choose an installation first"))
    }
    fn client(&self) -> Result<&Client, Error> {
        self.client.as_ref().ok_or(invalid("start service first"))
    }
    pub fn perform(&mut self, action: Action) -> Result<String, Error> {
        self.snapshot.warning = None;
        let result = self.execute(action);
        if result.is_err() {
            self.snapshot.verified = false;
            self.snapshot.permissions.clear();
        }
        result
    }
    fn execute(&mut self, action: Action) -> Result<String, Error> {
        match action {
            Action::Create { root, administrator, port } => {
                self.execute(Action::CreateConfigured { root, administrator, port, stream_policy: default_stream_policy() })
            }
            Action::CreateConfigured { root, administrator, port, stream_policy } => {
                stream_policy.validate()?;
                self.require_stopped()?;
                if self.root.is_some() {
                    self.require_no_pending()?;
                }
                path_check(&root)?;
                if administrator.is_empty()
                    || administrator.len() > 64
                    || administrator == "owner"
                    || !administrator.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
                {
                    return Err(invalid("administrator ID: lowercase letters, digits, hyphen, underscore; owner reserved"));
                }
                // Reserve socket before creating any authority, including auto-port.
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
                let port = listener.local_addr()?.port();
                let certificate =
                    rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).map_err(|_| invalid("TLS generation failed"))?;
                let der = certificate.cert.der().to_vec();
                let key = certificate.signing_key.serialize_der();
                HttpsConfig::from_der((Ipv4Addr::LOCALHOST, port).into(), vec![der.clone()], key.clone())?;
                directory(&root)?;
                directory(&root.join("tls"))?;
                publish(&root.join("tls/certificate.der"), &der)?;
                publish(&root.join("tls/private-key.der"), &key)?;
                directory(&root.join("seed"))?;
                let credentials = &self.credentials;
                let receipt = bootstrap::initialize_to(&root.join("seed"), &administrator, |receipt, bearer| {
                    let installation = Installation {
                        version: 1,
                        server_id: receipt.server_id.clone(),
                        administrator: receipt.administrator.clone(),
                        port,
                        certificate_sha256: hash(&der),
                        stream_policy: Some(stream_policy.clone()),
                    };
                    // Durable public trusted intent precedes secret capture and
                    // authority publication. Interrupted setup never invents identity.
                    publish(&root.join("prepared.json"), &serde_json::to_vec_pretty(&installation)?)?;
                    let secret = BearerSecret::parse(bearer.into()).map_err(|_| invalid("invalid enrollment secret"))?;
                    credentials
                        .set(&installation.key(&der, &administrator)?, &secret)
                        .map_err(|_| invalid("native credential capture failed; no authority published"))?;
                    Ok(())
                })?;
                Store::open(&root.join("seed"))?.backup(&root.join("seed-backup"))?;
                backup_restore::restore_backup_to_redb(&root.join("seed-backup"), &root.join("archive"))?;
                Store::open(&root.join("archive"))?.initialize_streaming(stream_policy.clone())?;
                let installation = Installation {
                    version: 1,
                    server_id: receipt.server_id,
                    administrator,
                    port,
                    certificate_sha256: hash(&der),
                    stream_policy: Some(stream_policy),
                };
                installation.save(&root)?;
                let previous_root = self.root.replace(root);
                let previous_installation = self.installation.replace(installation);
                let previous_snapshot = self.snapshot.clone();
                if let Err(error) = self.start_reserved(listener) {
                    self.root = previous_root;
                    self.installation = previous_installation;
                    self.snapshot = previous_snapshot;
                    return Err(error);
                }
                Ok("Created new physical server archive; administrator captured in native credential storage".into())
            }
            Action::Open(root) => {
                self.require_stopped()?;
                if self.root.is_some() {
                    self.require_no_pending()?;
                }
                path_check(&root)?;
                if !root.join("console.json").try_exists()? && root.join("prepared.json").try_exists()? {
                    self.finish_prepared(&root)?;
                }
                let (installation, der, _) = Installation::load(&root)?;
                self.credentials
                    .get(&installation.key(&der, &installation.administrator)?)
                    .map_err(|_| invalid("native credentials unavailable"))?
                    .ok_or(invalid("captured administrator credential missing"))?;
                self.snapshot = Snapshot {
                    root: root.display().to_string(),
                    origin: installation.origin(),
                    server_id: installation.server_id.clone(),
                    administrator: installation.administrator.clone(),
                    pending: self.load_pending_at(&root)?.is_some(),
                    ..Snapshot::default()
                };
                self.root = Some(root);
                self.installation = Some(installation);
                Ok("Existing console installation selected; start to verify live identity".into())
            }
            Action::Start => {
                self.require_stopped()?;
                let record = self.installation.as_ref().ok_or(invalid("choose installation first"))?;
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, record.port))?;
                self.start_reserved(listener)?;
                Ok("Owned service running; HTTPS identity and administrator verified".into())
            }
            Action::Stop => {
                self.stop()?;
                Ok("Owned service stopped".into())
            }
            Action::Refresh => {
                self.refresh()?;
                Ok("Live identity, capabilities and account revision refreshed".into())
            }
            Action::Retry => {
                self.retry()?;
                self.refresh()?;
                Ok(self.snapshot.warning.clone().unwrap_or_else(|| "Pending administration request resolved with its original request ID".into()))
            }
            Action::Audit { more } => {
                let after = if more { self.snapshot.next_audit } else { None };
                match self.client()?.admin(AdminRequest::ListAudit { after_generation: after, limit: 64 })? {
                    AdminResponse::Audit { events, next_after_generation } => {
                        self.snapshot.audit = events;
                        self.snapshot.next_audit = next_after_generation;
                    }
                    _ => return Err(invalid("unexpected audit response")),
                }
                Ok("Audit page loaded (successful transitions)".into())
            }
            Action::Backup(destination) => {
                self.require_stopped()?;
                self.require_no_pending()?;
                path_check(&destination)?;
                Store::open(&self.root()?.join("archive"))?.backup(&destination)?;
                Ok("Offline archive backup verified; protect this private directory".into())
            }
            Action::Restore { source, destination } => {
                self.require_stopped()?;
                self.require_no_pending()?;
                path_check(&source)?;
                path_check(&destination)?;
                let (record, der, key) = Installation::load(self.root()?)?;
                let receipt = backup_restore::verify_backup(&source)?;
                if receipt.server_id != record.server_id {
                    return Err(invalid("backup identity differs from selected installation"));
                }
                directory(&destination)?;
                directory(&destination.join("tls"))?;
                publish(&destination.join("tls/certificate.der"), &der)?;
                publish(&destination.join("tls/private-key.der"), &key)?;
                backup_restore::restore_backup_to_redb(&source, &destination.join("archive"))?;
                record.save(&destination)?;
                self.perform(Action::Open(destination))?;
                Ok("Backup restored into NEW physical installation; selected original identity and trust retained".into())
            }
            mutation => {
                self.mutate(mutation)?;
                self.refresh()?;
                Ok(self.snapshot.warning.clone().unwrap_or_else(|| "Account change committed through authenticated administration API. Credential creation is local to this OS account; remote enrollment is unavailable.".into()))
            }
        }
    }
    fn finish_prepared(&self, root: &Path) -> Result<(), Error> {
        // Only a previously journaled console-owned NEW setup may complete.
        // Arbitrary stores without this trusted intent never enter bootstrap.
        let (record, der, _) = Installation::load_record(root, "prepared.json")?;
        let secret = self
            .credentials
            .get(&record.key(&der, &record.administrator)?)
            .map_err(|_| invalid("interrupted enrollment credential storage unavailable"))?
            .ok_or(invalid("interrupted enrollment has no captured credential; preserve installation"))?;
        let seed = root.join("seed");
        if !seed.join("managed-principals.json").try_exists()? {
            bootstrap::finalize_enrollment(
                &seed,
                &bootstrap::EnrollmentReceipt { administrator: record.administrator.clone(), server_id: record.server_id.clone() },
                secret.expose(),
            )?;
        }
        let backup = root.join("seed-backup");
        if !backup.try_exists()? {
            Store::open(&seed)?.backup(&backup)?;
        }
        if backup_restore::verify_backup(&backup)?.server_id != record.server_id {
            return Err(invalid("interrupted seed backup identity mismatch"));
        }
        let archive = root.join("archive");
        let restored_new = !archive.try_exists()?;
        if restored_new {
            backup_restore::restore_backup_to_redb(&backup, &archive)?;
        }
        path_check(&archive.join("managed/metadata.redb"))?;
        if !archive.join("managed/metadata.redb").is_file() {
            return Err(invalid("interrupted restore; preserve installation and restore to a NEW location"));
        }
        // Only an archive restored NEW in this recovery may be initialized.
        // Existing archives must already contain the policy promised by the
        // captured intent. A partial initialization fence remains an error.
        {
            let mut store = Store::open(&archive)?;
            if restored_new && let Some(policy) = &record.stream_policy {
                store.initialize_streaming(policy.clone())?;
            }
        }
        record.verify_saved_policy(root)?;
        record.save(root)?;
        Ok(())
    }
    fn start_reserved(&mut self, listener: TcpListener) -> Result<(), Error> {
        let root = self.root()?.to_owned();
        let (record, der, key) = Installation::load(&root)?;
        if listener.local_addr()?.port() != record.port {
            return Err(invalid("reserved port mismatch"));
        }
        let secret = self
            .credentials
            .get(&record.key(&der, &record.administrator)?)
            .map_err(|_| invalid("native credential storage unavailable"))?
            .ok_or(invalid("administrator credential missing"))?;
        let config = HttpsConfig::from_der(listener.local_addr()?, vec![der.clone()], key)?;
        let server = HttpsServer::start_loopback_with_listener(Store::open(&root.join("archive"))?, config, listener)?;
        let verification = (|| {
            let client = Client::https_with_ca(&record.origin(), AuthToken::parse(secret.expose().into())?, &der)?.bind_server(&record.server_id)?;
            self.verify(&record, &client.capabilities()?)?;
            if let Some(policy) = &record.stream_policy {
                let capabilities = client.transfer_capabilities()?.ok_or(invalid("binary transfer capabilities unavailable for new installation"))?;
                if !capabilities.binary_transfer_v1 || capabilities.limits.as_ref() != Some(policy) {
                    return Err(invalid("binary transfer capabilities differ from new installation policy"));
                }
            }
            Ok::<Client, Error>(client)
        })();
        let client = match verification {
            Ok(client) => client,
            Err(error) => {
                if let Err(shutdown_error) = server.shutdown() {
                    eprintln!("Candidate console service shutdown failed: {shutdown_error}");
                }
                return Err(error);
            }
        };
        self.running = Some(server);
        self.client = Some(client);
        self.installation = Some(record);
        if let Err(error) = self.refresh() {
            if let Err(stop_error) = self.stop() {
                eprintln!("Owned console service shutdown failed: {stop_error}");
            }
            return Err(error);
        }
        Ok(())
    }
    fn verify(&self, record: &Installation, caps: &Capabilities) -> Result<(), Error> {
        if caps.server_id != record.server_id
            || caps.principal.id != record.administrator
            || caps.principal.role != Role::Administrator
            || caps.metadata_backend != "redb"
            || !caps.features.users_admin_v1
            || !caps.features.audit_read_v1
        {
            return Err(invalid("server identity, administrator or transactional capabilities mismatch"));
        }
        Ok(())
    }
    fn refresh(&mut self) -> Result<(), Error> {
        self.snapshot.verified = false;
        self.snapshot.permissions.clear();
        let record = self.installation.as_ref().ok_or(invalid("installation missing"))?;
        let caps = self.client()?.capabilities()?;
        self.verify(record, &caps)?;
        let (revision, users) = match self.client()?.admin(AdminRequest::ListUsers {})? {
            AdminResponse::Users { revision, users } => (revision, users),
            _ => return Err(invalid("unexpected users response")),
        };
        self.snapshot.running = true;
        self.snapshot.root = self.root()?.display().to_string();
        self.snapshot.origin = record.origin();
        self.snapshot.server_id = caps.server_id;
        self.snapshot.administrator = caps.principal.id;
        self.snapshot.backend = caps.metadata_backend;
        self.snapshot.permissions = caps.permissions;
        self.snapshot.revision = revision;
        self.snapshot.users = users;
        self.snapshot.pending = self.load_pending_at(self.root()?)?.is_some();
        self.snapshot.verified = true;
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Error> {
        self.client = None;
        self.snapshot.running = false;
        self.snapshot.verified = false;
        self.snapshot.permissions.clear();
        if let Some(server) = self.running.take() {
            server.shutdown()?;
        }
        Ok(())
    }
    fn mutate(&mut self, action: Action) -> Result<(), Error> {
        if !self.snapshot.verified {
            return Err(invalid("refresh authenticated administrator authority before making account changes"));
        }
        self.client()?;
        self.require_no_pending()?;
        let revision = self.snapshot.revision;
        let request_id = AuthToken::generate()?;
        let request = match action {
            Action::Role { id, role } => AdminRequest::SetRole { request_id, expected_revision: revision, id, role },
            Action::Enabled { id, enabled } => AdminRequest::SetEnabled { request_id, expected_revision: revision, id, enabled },
            Action::CreateUser { id, role } => {
                let verifier = self.capture(&id)?;
                AdminRequest::CreateUser { request_id, expected_revision: revision, id, role, credential_sha256: verifier }
            }
            Action::Reset { id } => {
                let verifier = self.capture(&id)?;
                AdminRequest::ReplaceCredential { request_id, expected_revision: revision, id, credential_sha256: verifier }
            }
            _ => return Err(invalid("unsupported account action")),
        };
        let record = self.installation.as_ref().ok_or(invalid("installation missing"))?;
        let pending = Pending { version: 1, server_id: record.server_id.clone(), administrator: record.administrator.clone(), request };
        publish(&self.root()?.join("pending-admin.json"), &serde_json::to_vec(&pending)?)?;
        self.snapshot.pending = true;
        self.retry()
    }
    fn load_pending_at(&self, root: &Path) -> Result<Option<Pending>, Error> {
        let path = root.join("pending-admin.json");
        path_check(&path)?;
        if !path.try_exists()? {
            return Ok(None);
        }
        let pending: Pending = serde_json::from_slice(&read(&path, 64 * 1024)?)?;
        let (record, _, _) = Installation::load(root)?;
        if pending.version != 1 || pending.server_id != record.server_id || pending.administrator != record.administrator {
            return Err(invalid("pending administration identity mismatch"));
        }
        if matches!(pending.request, AdminRequest::ListUsers {} | AdminRequest::ListAudit { .. }) {
            return Err(invalid("invalid pending administration intent"));
        }
        Ok(Some(pending))
    }
    fn require_no_pending(&self) -> Result<(), Error> {
        if self.load_pending_at(self.root()?)?.is_some() {
            return Err(invalid("resolve pending administration request using Retry first"));
        }
        Ok(())
    }
    fn clear_pending(&mut self) -> Result<(), Error> {
        let root = self.root()?;
        fs::remove_file(root.join("pending-admin.json"))?;
        #[cfg(unix)]
        fs::File::open(root)?.sync_all()?;
        self.snapshot.pending = false;
        Ok(())
    }
    fn retry(&mut self) -> Result<(), Error> {
        let pending = self.load_pending_at(self.root()?)?.ok_or(invalid("no pending administration request"))?;
        let response = match self.client()?.admin(pending.request.clone()) {
            Ok(response) => response,
            // Validation/conflict responses are definitive for this request.
            // Authentication/authorization failures can precede replay lookup
            // after a successful mutation and must retain the exact journal.
            Err(Error::Server(code))
                if [
                    "invalid_request",
                    "self_lockout",
                    "last_administrator",
                    "conflict",
                    "principal_exists",
                    "duplicate_credential",
                    "idempotency_conflict",
                    "not_found",
                    "quota",
                ]
                .contains(&code.as_str()) =>
            {
                self.clear_pending()?;
                return Err(Error::Server(code));
            }
            Err(error) => return Err(error),
        };
        match response {
            AdminResponse::UserChanged { revision: receipt_revision, user } => {
                let account = match &pending.request {
                    AdminRequest::CreateUser { id, credential_sha256, .. } | AdminRequest::ReplaceCredential { id, credential_sha256, .. } => {
                        Some((id, credential_sha256))
                    }
                    _ => None,
                };
                if let Some((id, verifier)) = account {
                    if user.id != *id {
                        return Err(invalid("pending administration receipt target mismatch"));
                    }
                    let (current_revision, users) = match self.client()?.admin(AdminRequest::ListUsers {})? {
                        AdminResponse::Users { revision, users } => (revision, users),
                        _ => return Err(invalid("unexpected pending reconciliation response")),
                    };
                    if current_revision != receipt_revision || !users.iter().any(|entry| entry.id == *id) {
                        self.clear_pending()?;
                        self.snapshot.warning = Some("Warning: pending request acknowledged but superseded by a later administration revision. The existing local credential was preserved; versioned capture retained for recovery.".into());
                        return Ok(());
                    }
                    let (record, der, _) = Installation::load(self.root()?)?;
                    let secret = self
                        .credentials
                        .get(&record.key(&der, &format!("capture-{verifier}"))?)
                        .map_err(|_| invalid("pending credential capture unavailable"))?
                        .ok_or(invalid("pending credential capture missing"))?;
                    if hash(secret.expose().as_bytes()) != *verifier {
                        return Err(invalid("pending credential capture integrity"));
                    }
                    self.credentials
                        .set(&record.key(&der, id)?, &secret)
                        .map_err(|_| invalid("account committed; versioned credential retained, active local slot publication failed"))?;
                }
                self.clear_pending()?;
                Ok(())
            }
            _ => Err(invalid("unexpected account mutation response")),
        }
    }
    fn capture(&self, id: &str) -> Result<String, Error> {
        let (record, der, _) = Installation::load(self.root()?)?;
        // Never overwrite an existing captured account before a possibly rejected
        // mutation. Versioned credential sink retains prior capture for recovery.
        let secret = BearerSecret::parse(AuthToken::generate()?).map_err(|_| invalid("credential generation failed"))?;
        let verifier = hash(secret.expose().as_bytes());
        record.key(&der, id)?;
        let staging = format!("capture-{verifier}");
        self.credentials.set(&record.key(&der, &staging)?, &secret).map_err(|_| invalid("private credential capture failed"))?;
        Ok(verifier)
    }
}

/// Injected only by tests/proof; ordinary launch always selects OsCredentialStore.
#[derive(Default)]
pub struct MemoryCredentials(std::cell::RefCell<std::collections::BTreeMap<CredentialKey, String>>);
impl CredentialStore for MemoryCredentials {
    fn get(&self, key: &CredentialKey) -> Result<Option<BearerSecret>, crate::pdm_credentials::CredentialError> {
        self.0.borrow().get(key).cloned().map(BearerSecret::parse).transpose()
    }
    fn set(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), crate::pdm_credentials::CredentialError> {
        self.0.borrow_mut().insert(key.clone(), secret.expose().into());
        Ok(())
    }
    fn delete(&self, key: &CredentialKey) -> Result<(), crate::pdm_credentials::CredentialError> {
        self.0.borrow_mut().remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn new_root() -> Result<PathBuf, Error> {
        Ok(std::env::temp_dir().join(format!("solidcraft-console-test-{}", AuthToken::generate()?)))
    }
    #[test]
    fn new_default_installation_negotiates_binary_transfers() -> Result<(), Error> {
        let root = new_root()?;
        let mut service = Service::new(MemoryCredentials::default());
        service.perform(Action::Create { root: root.clone(), administrator: "operator".into(), port: 0 })?;
        let capabilities = service.client()?.transfer_capabilities()?.ok_or(Error::Integrity)?;
        assert!(capabilities.binary_transfer_v1);
        let policy = capabilities.limits.ok_or(Error::Integrity)?;
        assert_eq!(policy.max_file_bytes, 512 * 1024 * 1024);
        assert_eq!(policy.max_store_bytes, 20 * 1024 * 1024 * 1024);
        service.perform(Action::Stop)?;
        drop(service);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn new_custom_stream_policy_is_durable_and_reports_precise_file_limit() -> Result<(), Error> {
        use solidcraft_pdm::{
            stream_io::StreamPolicy,
            transfers::{TransferInput, TransferTarget},
        };
        let root = new_root()?;
        let policy = StreamPolicy { version: 1, max_file_bytes: 2 * 1024 * 1024, max_store_bytes: 3 * 1024 * 1024 * 1024 };
        let mut service = Service::new(MemoryCredentials::default());
        service.perform(Action::CreateConfigured { root: root.clone(), administrator: "operator".into(), port: 0, stream_policy: policy.clone() })?;
        let capabilities = service.client()?.transfer_capabilities()?.ok_or(Error::Integrity)?;
        assert!(capabilities.binary_transfer_v1);
        assert_eq!(capabilities.limits, Some(policy.clone()));
        let disk: StreamPolicy = serde_json::from_slice(&read(&root.join("archive/managed/stream-policy.json"), 1024)?)?;
        assert_eq!(disk, policy);
        let input = TransferInput {
            server_id: capabilities.server_id,
            recovery_epoch: capabilities.recovery_epoch,
            request_id: "oversized-policy-test".into(),
            target: TransferTarget::NewOnly { logical_path: "oversized.bin".into() },
            total_bytes: policy.max_file_bytes + 1,
            sha256: "a".repeat(64),
            dependencies: Vec::new(),
            comment: String::new(),
        };
        assert!(
            matches!(service.client()?.begin_transfer(input), Err(Error::FileTooLarge { actual, max }) if actual == policy.max_file_bytes + 1 && max == policy.max_file_bytes)
        );
        service.perform(Action::Stop)?;
        service.perform(Action::Start)?;
        assert_eq!(service.client()?.transfer_capabilities()?.ok_or(Error::Integrity)?.limits, Some(policy));
        service.perform(Action::Stop)?;
        drop(service);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn invalid_new_stream_policy_creates_no_root_or_authority() -> Result<(), Error> {
        use solidcraft_pdm::stream_io::{HARD_FILE_BYTES, HARD_STORE_BYTES, StreamPolicy};
        let mut service = Service::new(MemoryCredentials::default());
        for policy in [
            StreamPolicy { version: 1, max_file_bytes: 0, max_store_bytes: 1 },
            StreamPolicy { version: 2, max_file_bytes: 1, max_store_bytes: 1 },
            StreamPolicy { version: 1, max_file_bytes: HARD_FILE_BYTES + 1, max_store_bytes: HARD_STORE_BYTES },
            StreamPolicy { version: 1, max_file_bytes: 2, max_store_bytes: 1 },
            StreamPolicy { version: 1, max_file_bytes: 1, max_store_bytes: HARD_STORE_BYTES + 1 },
        ] {
            let root = new_root()?;
            assert!(
                service
                    .perform(Action::CreateConfigured { root: root.clone(), administrator: "operator".into(), port: 0, stream_policy: policy })
                    .is_err()
            );
            assert!(!root.exists());
            assert!(service.credentials.0.borrow().is_empty());
        }
        Ok(())
    }
    #[test]
    fn existing_prepared_archive_missing_stream_policy_is_not_silently_upgraded() -> Result<(), Error> {
        let root = new_root()?;
        let mut service = Service::new(MemoryCredentials::default());
        service.perform(Action::Create { root: root.clone(), administrator: "operator".into(), port: 0 })?;
        service.perform(Action::Stop)?;
        let prepared = read(&root.join("prepared.json"), 16 * 1024)?;
        fs::remove_file(root.join("console.json"))?;
        fs::rename(root.join("archive/managed/stream-policy.json"), root.join("archive/managed/policy-held-for-test"))?;
        assert!(service.perform(Action::Open(root.clone())).is_err());
        assert!(!root.join("console.json").exists());
        assert!(!root.join("archive/managed/stream-policy.json").exists());
        assert_eq!(prepared, read(&root.join("prepared.json"), 16 * 1024)?);
        assert!(!service.snapshot.running);
        drop(service);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn real_https_lifecycle_accounts_backup_restore_and_trust_rejection() -> Result<(), Error> {
        let root = new_root()?;
        let backup = new_root()?;
        let restored = new_root()?;
        let mut service = Service::new(MemoryCredentials::default());
        service.perform(Action::Create { root: root.clone(), administrator: "operator".into(), port: 0 })?;
        assert!(service.snapshot.running);
        assert_eq!(service.snapshot.backend, "redb");
        assert_eq!(service.snapshot.administrator, "operator");
        service.perform(Action::CreateUser { id: "reviewer".into(), role: Role::Viewer })?;
        let (record, der, _) = Installation::load(&root)?;
        let captured = service.credentials.get(&record.key(&der, "reviewer")?).map_err(|_| Error::Integrity)?.ok_or(Error::Integrity)?;
        let viewer = Client::https_with_ca(&record.origin(), AuthToken::parse(captured.expose().into())?, &der)?.bind_server(&record.server_id)?;
        assert_eq!(viewer.capabilities()?.principal.role, Role::Viewer);
        assert!(viewer.admin(AdminRequest::ListUsers {}).is_err());
        // Simulate a lost successful HTTPS reply. The durable request and
        // versioned credential capture exist BEFORE the server mutation.
        let verifier = service.capture("reviewer")?;
        let pending = Pending {
            version: 1,
            server_id: record.server_id.clone(),
            administrator: record.administrator.clone(),
            request: AdminRequest::ReplaceCredential {
                request_id: AuthToken::generate()?,
                expected_revision: service.snapshot.revision,
                id: "reviewer".into(),
                credential_sha256: verifier,
            },
        };
        publish(&root.join("pending-admin.json"), &serde_json::to_vec(&pending)?)?;
        service.snapshot.pending = true;
        let _response_lost_to_caller = service.client()?.admin(pending.request)?;
        assert!(service.perform(Action::Role { id: "reviewer".into(), role: Role::Contributor }).is_err());
        service.perform(Action::Stop)?;
        // Restart reloads the durable intent instead of generating a new secret
        // or request ID. Retry completes canonical publication exactly once.
        service.perform(Action::Start)?;
        assert!(service.snapshot.pending);
        service.perform(Action::Retry)?;
        assert!(!service.snapshot.pending);
        assert!(viewer.capabilities().is_err());
        let replacement = service.credentials.get(&record.key(&der, "reviewer")?).map_err(|_| Error::Integrity)?.ok_or(Error::Integrity)?;
        let replaced_viewer =
            Client::https_with_ca(&record.origin(), AuthToken::parse(replacement.expose().into())?, &der)?.bind_server(&record.server_id)?;
        assert_eq!(replaced_viewer.capabilities()?.principal.role, Role::Viewer);
        service.perform(Action::Enabled { id: "reviewer".into(), enabled: false })?;
        assert!(replaced_viewer.capabilities().is_err());
        assert!(service.perform(Action::Reset { id: "operator".into() }).is_err());
        // A rejected own-reset must not replace the acting administrator capture.
        service.perform(Action::Refresh)?;
        service.perform(Action::Audit { more: false })?;
        assert!(service.snapshot.audit.iter().any(|event| event.operation == "user.create"));
        assert!(service.perform(Action::Backup(backup.clone())).is_err());
        service.perform(Action::Stop)?;
        service.perform(Action::Backup(backup.clone()))?;
        service.perform(Action::Restore { source: backup.clone(), destination: restored.clone() })?;
        service.perform(Action::Start)?;
        assert!(service.snapshot.users.iter().any(|user| user.id == "reviewer" && !user.enabled && user.permissions.is_empty()));
        service.perform(Action::Stop)?;
        // Opening an arbitrary existing directory never bootstraps it.
        assert!(service.perform(Action::Open(backup.clone())).is_err());
        assert!(!backup.join("archive").exists());
        fs::write(restored.join("tls/certificate.der"), b"corrupt")?;
        assert!(service.perform(Action::Open(restored.clone())).is_err());
        drop(service);
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(backup)?;
        fs::remove_dir_all(restored)?;
        Ok(())
    }
    #[test]
    fn old_reset_receipt_preserves_newer_capture_and_forbidden_retry_retains_intent() -> Result<(), Error> {
        let root = new_root()?;
        let mut service = Service::new(MemoryCredentials::default());
        service.perform(Action::Create { root: root.clone(), administrator: "operator".into(), port: 0 })?;
        service.perform(Action::CreateUser { id: "other-admin".into(), role: Role::Administrator })?;
        service.perform(Action::CreateUser { id: "reviewer".into(), role: Role::Viewer })?;
        let (record, der, _) = Installation::load(&root)?;
        let other_secret = service.credentials.get(&record.key(&der, "other-admin")?).map_err(|_| Error::Integrity)?.ok_or(Error::Integrity)?;
        let other = Client::https_with_ca(&record.origin(), AuthToken::parse(other_secret.expose().into())?, &der)?.bind_server(&record.server_id)?;
        let verifier_a = service.capture("reviewer")?;
        let pending_a = Pending {
            version: 1,
            server_id: record.server_id.clone(),
            administrator: record.administrator.clone(),
            request: AdminRequest::ReplaceCredential {
                request_id: AuthToken::generate()?,
                expected_revision: service.snapshot.revision,
                id: "reviewer".into(),
                credential_sha256: verifier_a.clone(),
            },
        };
        publish(&root.join("pending-admin.json"), &serde_json::to_vec(&pending_a)?)?;
        service.snapshot.pending = true;
        let revision_a = match service.client()?.admin(pending_a.request)? {
            AdminResponse::UserChanged { revision, .. } => revision,
            _ => return Err(Error::Integrity),
        };
        // Another administrator replaces A with B and publishes B locally before
        // this console receives the historic idempotent receipt for A.
        let verifier_b = service.capture("reviewer")?;
        let response_b = other.admin(AdminRequest::ReplaceCredential {
            request_id: AuthToken::generate()?,
            expected_revision: revision_a,
            id: "reviewer".into(),
            credential_sha256: verifier_b.clone(),
        })?;
        let revision_b = match response_b {
            AdminResponse::UserChanged { revision, .. } => revision,
            _ => return Err(Error::Integrity),
        };
        let secret_b =
            service.credentials.get(&record.key(&der, &format!("capture-{verifier_b}"))?).map_err(|_| Error::Integrity)?.ok_or(Error::Integrity)?;
        service.credentials.set(&record.key(&der, "reviewer")?, &secret_b).map_err(|_| Error::Integrity)?;
        let warning = service.perform(Action::Retry)?;
        assert!(warning.contains("superseded"));
        assert!(!root.join("pending-admin.json").exists());
        let canonical = service.credentials.get(&record.key(&der, "reviewer")?).map_err(|_| Error::Integrity)?.ok_or(Error::Integrity)?;
        assert_eq!(canonical.expose(), secret_b.expose());
        assert!(service.credentials.get(&record.key(&der, &format!("capture-{verifier_a}"))?).map_err(|_| Error::Integrity)?.is_some());
        let verifier_c = service.capture("reviewer")?;
        let pending_c = Pending {
            version: 1,
            server_id: record.server_id.clone(),
            administrator: record.administrator.clone(),
            request: AdminRequest::ReplaceCredential {
                request_id: AuthToken::generate()?,
                expected_revision: revision_b,
                id: "reviewer".into(),
                credential_sha256: verifier_c.clone(),
            },
        };
        let intent_bytes = serde_json::to_vec(&pending_c)?;
        publish(&root.join("pending-admin.json"), &intent_bytes)?;
        service.snapshot.pending = true;
        let revision_c = match service.client()?.admin(pending_c.request)? {
            AdminResponse::UserChanged { revision, .. } => revision,
            _ => return Err(Error::Integrity),
        };
        other.admin(AdminRequest::SetRole {
            request_id: AuthToken::generate()?,
            expected_revision: revision_c,
            id: "operator".into(),
            role: Role::Contributor,
        })?;
        // Forbidden here is the preliminary capability check, not proof that C
        // failed: the acknowledged state already contains C's credential.
        assert!(service.perform(Action::Retry).is_err());
        assert_eq!(read(&root.join("pending-admin.json"), 64 * 1024)?, intent_bytes);
        assert!(service.credentials.get(&record.key(&der, &format!("capture-{verifier_c}"))?).map_err(|_| Error::Integrity)?.is_some());
        let canonical_after_denial =
            service.credentials.get(&record.key(&der, "reviewer")?).map_err(|_| Error::Integrity)?.ok_or(Error::Integrity)?;
        assert_eq!(canonical_after_denial.expose(), secret_b.expose());
        assert!(!service.snapshot.verified);
        assert!(service.snapshot.pending);
        service.perform(Action::Stop)?;
        drop(service);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn captured_prepared_enrollment_resumes_same_identity_without_reset() -> Result<(), Error> {
        for stream_policy in [None, Some(default_stream_policy())] {
            let root = new_root()?;
            directory(&root)?;
            directory(&root.join("tls"))?;
            directory(&root.join("seed"))?;
            let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).map_err(|_| Error::Integrity)?;
            let der = certificate.cert.der().to_vec();
            publish(&root.join("tls/certificate.der"), &der)?;
            publish(&root.join("tls/private-key.der"), &certificate.signing_key.serialize_der())?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            let mut service = Service::new(MemoryCredentials::default());
            let captured = bootstrap::initialize_to(&root.join("seed"), "operator", |receipt, bearer| {
                let record = Installation {
                    version: 1,
                    server_id: receipt.server_id.clone(),
                    administrator: receipt.administrator.clone(),
                    port,
                    certificate_sha256: hash(&der),
                    stream_policy: stream_policy.clone(),
                };
                publish(&root.join("prepared.json"), &serde_json::to_vec(&record)?)?;
                let secret = BearerSecret::parse(bearer.into()).map_err(|_| Error::Integrity)?;
                service.credentials.set(&record.key(&der, "operator")?, &secret).map_err(|_| Error::Integrity)?;
                Err(invalid("injected interruption after durable capture"))
            });
            assert!(captured.is_err());
            assert!(!root.join("seed/managed-principals.json").exists());
            let (prepared, _, _) = Installation::load_record(&root, "prepared.json")?;
            drop(listener);
            service.perform(Action::Open(root.clone()))?;
            service.perform(Action::Start)?;
            assert_eq!(service.snapshot.server_id, prepared.server_id);
            assert!(service.snapshot.verified);
            assert_eq!(service.snapshot.administrator, "operator");
            let capabilities = service.client()?.transfer_capabilities()?.ok_or(Error::Integrity)?;
            assert_eq!(capabilities.binary_transfer_v1, stream_policy.is_some());
            assert_eq!(capabilities.limits, stream_policy);
            service.perform(Action::Stop)?;
            drop(service);
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }
    #[test]
    fn external_revocation_clears_verified_authority_but_keeps_owned_stop() -> Result<(), Error> {
        let root = new_root()?;
        let mut service = Service::new(MemoryCredentials::default());
        service.perform(Action::Create { root: root.clone(), administrator: "operator".into(), port: 0 })?;
        service.perform(Action::CreateUser { id: "other-admin".into(), role: Role::Administrator })?;
        let (record, der, _) = Installation::load(&root)?;
        let secret = service.credentials.get(&record.key(&der, "other-admin")?).map_err(|_| Error::Integrity)?.ok_or(Error::Integrity)?;
        let other = Client::https_with_ca(&record.origin(), AuthToken::parse(secret.expose().into())?, &der)?.bind_server(&record.server_id)?;
        other.admin(AdminRequest::SetEnabled {
            request_id: AuthToken::generate()?,
            expected_revision: service.snapshot.revision,
            id: "operator".into(),
            enabled: false,
        })?;
        assert!(service.perform(Action::Refresh).is_err());
        assert!(service.snapshot.running);
        assert!(!service.snapshot.verified);
        assert!(service.snapshot.permissions.is_empty());
        assert!(service.perform(Action::CreateUser { id: "blocked".into(), role: Role::Viewer }).is_err());
        service.perform(Action::Stop)?;
        assert!(!service.snapshot.running);
        assert!(!service.snapshot.verified);
        drop(service);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn failed_private_sink_publishes_no_authority() -> Result<(), Error> {
        struct Failing;
        impl CredentialStore for Failing {
            fn get(&self, _: &CredentialKey) -> Result<Option<BearerSecret>, crate::pdm_credentials::CredentialError> {
                Ok(None)
            }
            fn set(&self, _: &CredentialKey, _: &BearerSecret) -> Result<(), crate::pdm_credentials::CredentialError> {
                Err(crate::pdm_credentials::CredentialError::Unavailable)
            }
            fn delete(&self, _: &CredentialKey) -> Result<(), crate::pdm_credentials::CredentialError> {
                Ok(())
            }
        }
        let root = new_root()?;
        let mut service = Service::new(Failing);
        assert!(service.perform(Action::Create { root: root.clone(), administrator: "operator".into(), port: 0 }).is_err());
        assert!(!root.join("seed/managed-principals.json").exists());
        assert!(root.join("prepared.json").is_file());
        assert!(!root.join("archive").exists());
        assert!(!service.snapshot.running);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
