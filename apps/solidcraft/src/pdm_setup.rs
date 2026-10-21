//! Guided private loopback installation. Never adds machine-wide certificate
//! trust, binds public interfaces, stores a bearer on disk, or resets an archive.
//! The parent directory must already be private to the installing account on
//! Windows. Unix installation directories/files are created as 0700/0600.
#![cfg(not(target_arch = "wasm32"))]
use crate::{
    pdm_credentials::CredentialStore,
    pdm_login::{self, Profile, Trust},
    pdm_profiles::ProfileDirectory,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Store,
    bootstrap::EnrollmentReceipt,
    http_server::{HttpsConfig, HttpsServer},
    managed::Role,
    stream_io::StreamPolicy,
};
use std::{
    fmt, fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Component, Path, PathBuf},
};

const MAX_JSON: usize = 384 * 1024;
const MAX_CA: usize = 64 * 1024;
const MAX_KEY: usize = 16 * 1024;

fn new_installation_policy() -> StreamPolicy {
    StreamPolicy { version: 1, max_file_bytes: 512 * 1024 * 1024, max_store_bytes: 20 * 1024 * 1024 * 1024 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupError {
    Invalid,
    Interrupted,
    Busy,
    Credentials,
    Metadata,
    Service,
}
impl fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "Invalid private local PDM installation",
            Self::Interrupted => "Incomplete local PDM setup; preserve installation data",
            Self::Busy => "Local PDM installation or its reserved port is already in use",
            Self::Credentials => "Local PDM setup credential unavailable",
            Self::Metadata => "Local PDM setup metadata could not be persisted",
            Self::Service => "Local PDM service identity verification failed",
        })
    }
}
impl std::error::Error for SetupError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    version: u32,
    installation_id: String,
    administrator: String,
    port: u16,
    certificate_sha256: String,
    /// A persisted new-installation intent. Missing in existing legacy setups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stream_policy: Option<StreamPolicy>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    installation_id: String,
    administrator: String,
    server_id: String,
    profile_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u32,
    installation_id: String,
    profile_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetupStatus {
    Prepared,
    EnrollmentCaptured,
    /// A prior verification receipt exists. This is public journal state only;
    /// current service identity/role still require fresh HTTPS authentication.
    VerificationRecorded,
}

/// This owns the server and installation lock. Dropping it shuts down only its
/// own server. No setup result is active before fresh HTTPS Admin verification.
pub struct RunningLocalSetup {
    pub profile: Profile,
    pub receipt: EnrollmentReceipt,
    pub profile_id: String,
    server: HttpsServer,
    _installation_lock: fs::File,
}
impl RunningLocalSetup {
    pub fn address(&self) -> SocketAddr {
        self.server.address()
    }
}
impl fmt::Debug for RunningLocalSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RunningLocalSetup").field("profile_id", &self.profile_id).field("address", &self.address()).finish()
    }
}

#[derive(Debug)]
pub struct LocalSetup {
    root: PathBuf,
}
impl LocalSetup {
    /// Pure constructor. Setup is deliberately limited to an absolute dedicated
    /// root whose parent already exists; never select an existing user's archive.
    pub fn new(root: PathBuf) -> Result<Self, SetupError> {
        if !root.is_absolute() || root.components().any(|part| matches!(part, Component::ParentDir)) {
            return Err(SetupError::Invalid);
        }
        Ok(Self { root })
    }
    pub fn begin(&self, administrator: &str, credentials: &impl CredentialStore) -> Result<RunningLocalSetup, SetupError> {
        validate_administrator(administrator)?;
        check_path(&self.root)?;
        // Bind first and retain this very listener through TLS service startup.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| SetupError::Busy)?;
        let port = listener.local_addr().map_err(|_| SetupError::Service)?.port();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).map_err(|_| SetupError::Service)?;
        let der = certificate.cert.der().to_vec();
        let private_key = certificate.signing_key.serialize_der();
        Trust::certificate_der(&der).map_err(|_| SetupError::Invalid)?;
        // Validate key/certificate before any disk or enrollment side effects.
        HttpsConfig::from_der((Ipv4Addr::LOCALHOST, port).into(), vec![der.clone()], private_key.clone()).map_err(|_| SetupError::Invalid)?;
        private_directory(&self.root, false)?;
        let lock = installation_lock(&self.root)?;
        private_directory(&self.root.join("setup"), false)?;
        private_directory(&self.root.join("tls"), false)?;
        let prepared = Prepared {
            version: 1,
            installation_id: AuthToken::generate().map_err(|_| SetupError::Service)?,
            administrator: administrator.into(),
            port,
            certificate_sha256: hash(&der),
            stream_policy: Some(new_installation_policy()),
        };
        publish(&self.root.join("tls/ca.der"), &der)?;
        publish(&self.root.join("tls/server-key.der"), &private_key)?;
        // This completion record is published only after both TLS files are
        // durable. Earlier crashes preserve an incomplete root for inspection;
        // they cannot be silently recovered by generating replacement trust.
        publish_json(&self.root.join("setup/prepared.json"), &prepared)?;
        self.enroll_and_start(&prepared, listener, lock, credentials)
    }

    /// Resume uses exactly the recorded port/trust. Occupied ports, changed TLS,
    /// partial registries and missing captured secrets are errors, never resets.
    pub fn resume(&self, credentials: &impl CredentialStore) -> Result<RunningLocalSetup, SetupError> {
        if !exists(&self.root.join("setup/prepared.json"))? {
            return Err(SetupError::Interrupted);
        }
        validate_layout(&self.root)?;
        let lock = installation_lock(&self.root)?;
        let prepared = self.prepared()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, prepared.port)).map_err(|_| SetupError::Busy)?;
        self.tls(&prepared)?;
        let intent_path = self.root.join("setup/enrollment.json");
        if !exists(&intent_path)? {
            if exists(&self.root.join("archive/managed-principals.json"))? || exists(&self.root.join("setup/ready.json"))? {
                return Err(SetupError::Interrupted);
            }
            // No committed intent: retry the credential capture transaction. The
            // archive's existing stable identity is retained by initialize_to.
            return self.enroll_and_start(&prepared, listener, lock, credentials);
        }
        let (enrollment, profile) = self.enrollment(&prepared)?;
        if exists(&self.root.join("setup/ready.json"))? {
            if !exists(&self.root.join("archive/managed-principals.json"))? {
                return Err(SetupError::Interrupted);
            }
            let ready: Ready = read_json(&self.root.join("setup/ready.json"))?;
            if ready.version != 1 || ready.installation_id != prepared.installation_id || ready.profile_id != enrollment.profile_id {
                return Err(SetupError::Interrupted);
            }
        }
        let receipt = EnrollmentReceipt { administrator: enrollment.administrator, server_id: enrollment.server_id };
        let captured = pdm_login::captured_user_credential(&profile, credentials).map_err(|_| SetupError::Credentials)?;
        if !exists(&self.root.join("archive/managed-principals.json"))? {
            // PHASE 2 service helper: checks actual stable store identity, empty
            // archive and absent registry under the OS writer lock; never resets.
            solidcraft_pdm::bootstrap::finalize_enrollment(&self.root.join("archive"), &receipt, captured.expose())
                .map_err(|_| SetupError::Interrupted)?;
        }
        self.prepare_streaming(&prepared, &receipt)?;
        self.start_verified(&prepared, receipt, profile, enrollment.profile_id, listener, lock, credentials)
    }

    /// Public metadata status only. No keyring lookup or live authority check is
    /// performed; a recorded verification never means a currently active login.
    pub fn inspect(&self) -> Result<SetupStatus, SetupError> {
        if !exists(&self.root.join("setup/prepared.json"))? {
            return Err(SetupError::Interrupted);
        }
        validate_layout(&self.root)?;
        let prepared = self.prepared()?;
        self.tls(&prepared)?;
        if !exists(&self.root.join("setup/enrollment.json"))? {
            if exists(&self.root.join("setup/ready.json"))? || exists(&self.root.join("archive/managed-principals.json"))? {
                return Err(SetupError::Interrupted);
            }
            return Ok(SetupStatus::Prepared);
        }
        let (enrollment, _) = self.enrollment(&prepared)?;
        if exists(&self.root.join("setup/ready.json"))? {
            if !exists(&self.root.join("archive/managed-principals.json"))? {
                return Err(SetupError::Interrupted);
            }
            let ready: Ready = read_json(&self.root.join("setup/ready.json"))?;
            if ready.version != 1 || ready.installation_id != prepared.installation_id || ready.profile_id != enrollment.profile_id {
                return Err(SetupError::Interrupted);
            }
            return Ok(SetupStatus::VerificationRecorded);
        }
        Ok(SetupStatus::EnrollmentCaptured)
    }

    fn prepared(&self) -> Result<Prepared, SetupError> {
        let prepared: Prepared = read_json(&self.root.join("setup/prepared.json"))?;
        if prepared.version != 1 || !id(&prepared.installation_id) || !id(&prepared.certificate_sha256) || prepared.port == 0 {
            return Err(SetupError::Invalid);
        }
        validate_administrator(&prepared.administrator)?;
        if let Some(policy) = &prepared.stream_policy {
            policy.validate().map_err(|_| SetupError::Invalid)?;
        }
        Ok(prepared)
    }
    fn tls(&self, prepared: &Prepared) -> Result<HttpsConfig, SetupError> {
        let der = read(&self.root.join("tls/ca.der"), MAX_CA)?;
        if hash(&der) != prepared.certificate_sha256 {
            return Err(SetupError::Interrupted);
        }
        Trust::certificate_der(&der).map_err(|_| SetupError::Interrupted)?;
        HttpsConfig::from_der((Ipv4Addr::LOCALHOST, prepared.port).into(), vec![der], read(&self.root.join("tls/server-key.der"), MAX_KEY)?)
            .map_err(|_| SetupError::Interrupted)
    }
    fn profile(&self, prepared: &Prepared, server_id: &str) -> Result<Profile, SetupError> {
        let der = read(&self.root.join("tls/ca.der"), MAX_CA)?;
        if hash(&der) != prepared.certificate_sha256 {
            return Err(SetupError::Interrupted);
        }
        let value = serde_json::json!({"target":{"origin":format!("https://127.0.0.1:{}",prepared.port),"tunnel":null,"server_id":server_id,
            "trust":{"kind":"certificate","certificate_der":der}},"principal_id":prepared.administrator});
        Profile::from_json(&serde_json::to_vec(&value).map_err(|_| SetupError::Invalid)?).map_err(|_| SetupError::Invalid)
    }
    fn enrollment(&self, prepared: &Prepared) -> Result<(Enrollment, Profile), SetupError> {
        let enrollment: Enrollment = read_json(&self.root.join("setup/enrollment.json"))?;
        if enrollment.version != 1
            || enrollment.installation_id != prepared.installation_id
            || enrollment.administrator != prepared.administrator
            || !id(&enrollment.server_id)
            || !id(&enrollment.profile_id)
        {
            return Err(SetupError::Invalid);
        }
        let profiles = ProfileDirectory::new(self.root.join("profiles")).map_err(|_| SetupError::Invalid)?;
        let saved = profiles.load(&enrollment.profile_id).map_err(|_| SetupError::Interrupted)?;
        let expected = self.profile(prepared, &enrollment.server_id)?;
        if ProfileDirectory::profile_id(&saved).map_err(|_| SetupError::Invalid)?
            != ProfileDirectory::profile_id(&expected).map_err(|_| SetupError::Invalid)?
        {
            return Err(SetupError::Interrupted);
        }
        Ok((enrollment, saved))
    }
    fn enroll_and_start(
        &self,
        prepared: &Prepared,
        listener: TcpListener,
        lock: fs::File,
        credentials: &impl CredentialStore,
    ) -> Result<RunningLocalSetup, SetupError> {
        let der = read(&self.root.join("tls/ca.der"), MAX_CA)?;
        if hash(&der) != prepared.certificate_sha256 {
            return Err(SetupError::Interrupted);
        }
        let origin = format!("https://127.0.0.1:{}", prepared.port);
        let profiles = ProfileDirectory::new(self.root.join("profiles")).map_err(|_| SetupError::Invalid)?;
        let mut profile_id = None;
        let (receipt, profile) = pdm_login::enroll_local_with_hook(
            &self.root.join("archive"),
            &prepared.administrator,
            &origin,
            Trust::certificate_der(&der).map_err(|_| SetupError::Invalid)?,
            credentials,
            |receipt, profile| {
                let id = profiles.install_new(profile.clone()).map_err(|_| pdm_login::LoginError::EnrollmentFailed)?;
                publish_json(
                    &self.root.join("setup/enrollment.json"),
                    &Enrollment {
                        version: 1,
                        installation_id: prepared.installation_id.clone(),
                        administrator: receipt.administrator.clone(),
                        server_id: receipt.server_id.clone(),
                        profile_id: id.clone(),
                    },
                )
                .map_err(|_| pdm_login::LoginError::EnrollmentFailed)?;
                profile_id = Some(id);
                Ok(())
            },
        )
        .map_err(|error| {
            if matches!(error, pdm_login::LoginError::CredentialUnavailable) { SetupError::Credentials } else { SetupError::Interrupted }
        })?;
        self.prepare_streaming(prepared, &receipt)?;
        self.start_verified(prepared, receipt, profile, profile_id.ok_or(SetupError::Interrupted)?, listener, lock, credentials)
    }
    /// Complete only the persisted fresh enrollment. Ordinary legacy startup
    /// never opts into conversion, and an installed archive never reinitializes.
    fn prepare_streaming(&self, prepared: &Prepared, receipt: &EnrollmentReceipt) -> Result<(), SetupError> {
        let Some(policy) = &prepared.stream_policy else {
            return Ok(());
        };
        let policy_path = self.root.join("archive/managed/stream-policy.json");
        if exists(&policy_path)? {
            let installed: StreamPolicy = read_json(&policy_path)?;
            return if installed == *policy { Ok(()) } else { Err(SetupError::Interrupted) };
        }
        if exists(&self.root.join("setup/ready.json"))? {
            return Err(SetupError::Interrupted);
        }
        let mut store = Store::open(&self.root.join("archive")).map_err(|_| SetupError::Interrupted)?;
        store.initialize_enrolled_streaming(receipt, policy.clone()).map_err(|_| SetupError::Interrupted)?;
        let installed: StreamPolicy = read_json(&policy_path)?;
        if installed != *policy {
            return Err(SetupError::Interrupted);
        }
        Ok(())
    }

    fn start_verified(
        &self,
        prepared: &Prepared,
        receipt: EnrollmentReceipt,
        profile: Profile,
        profile_id: String,
        listener: TcpListener,
        lock: fs::File,
        credentials: &impl CredentialStore,
    ) -> Result<RunningLocalSetup, SetupError> {
        let store = Store::open(&self.root.join("archive")).map_err(|_| SetupError::Interrupted)?;
        let server = HttpsServer::start_loopback_with_listener(store, self.tls(prepared)?, listener).map_err(|_| SetupError::Service)?;
        // The returned role is read fresh from configured server authority.
        let session = pdm_login::resume(profile.clone(), credentials).map_err(|_| SetupError::Service)?;
        if session.identity.principal.role != Role::Administrator
            || session.identity.principal.id != receipt.administrator
            || session.identity.server_id != receipt.server_id
        {
            return Err(SetupError::Service);
        }
        let ready = Ready { version: 1, installation_id: prepared.installation_id.clone(), profile_id: profile_id.clone() };
        publish_json(&self.root.join("setup/ready.json"), &ready)?;
        Ok(RunningLocalSetup { profile, receipt, profile_id, server, _installation_lock: lock })
    }
}

fn validate_administrator(value: &str) -> Result<(), SetupError> {
    if value.is_empty()
        || value.len() > 64
        || value == "owner"
        || !value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(SetupError::Invalid);
    }
    Ok(())
}
fn id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn exists(path: &Path) -> Result<bool, SetupError> {
    check_path(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SetupError::Invalid),
    }
}
fn check_path(path: &Path) -> Result<(), SetupError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(SetupError::Invalid);
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(SetupError::Invalid);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(SetupError::Invalid),
        }
    }
    Ok(())
}
fn private_directory(path: &Path, allow_existing: bool) -> Result<(), SetupError> {
    check_path(path)?;
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if allow_existing && error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(SetupError::Invalid),
    }
}
fn installation_lock(root: &Path) -> Result<fs::File, SetupError> {
    check_path(&root.join("setup.lock"))?;
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(root.join("setup.lock")).map_err(|_| SetupError::Invalid)?;
    lock.try_lock().map_err(|_| SetupError::Busy)?;
    Ok(lock)
}
fn validate_layout(root: &Path) -> Result<(), SetupError> {
    check_path(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(root).map_err(|_| SetupError::Invalid)?.permissions().mode() & 0o077 != 0 {
            return Err(SetupError::Invalid);
        }
    }
    validate_entries(root, &["setup", "tls", "profiles", "archive", "setup.lock"], 5, MAX_JSON)?;
    validate_entries(&root.join("setup"), &["prepared.json", "enrollment.json", "ready.json"], 8, MAX_JSON)?;
    validate_entries(&root.join("tls"), &["ca.der", "server-key.der"], 6, MAX_CA)?;
    Ok(())
}
fn validate_entries(root: &Path, allowed: &[&str], max_entries: usize, max_bytes: usize) -> Result<(), SetupError> {
    check_path(root)?;
    let mut count = 0usize;
    for entry in fs::read_dir(root).map_err(|_| SetupError::Interrupted)? {
        count += 1;
        if count > max_entries {
            return Err(SetupError::Invalid);
        }
        let entry = entry.map_err(|_| SetupError::Invalid)?;
        check_path(&entry.path())?;
        let name = entry.file_name().into_string().map_err(|_| SetupError::Invalid)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| SetupError::Invalid)?;
        if !allowed.contains(&name.as_str()) {
            if !name.strip_prefix(".setup-").and_then(|name| name.strip_suffix(".pending")).is_some_and(id)
                || !metadata.is_file()
                || metadata.len() > max_bytes as u64
            {
                return Err(SetupError::Invalid);
            }
        } else if metadata.is_file() && metadata.len() > max_bytes as u64 {
            return Err(SetupError::Invalid);
        }
    }
    Ok(())
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, SetupError> {
    check_path(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| SetupError::Interrupted)?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(SetupError::Invalid);
    }
    let mut bytes = Vec::new();
    fs::File::open(path).map_err(|_| SetupError::Interrupted)?.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| SetupError::Interrupted)?;
    if bytes.len() > limit {
        return Err(SetupError::Invalid);
    }
    Ok(bytes)
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, SetupError> {
    serde_json::from_slice(&read(path, MAX_JSON)?).map_err(|_| SetupError::Invalid)
}
fn publish_json(path: &Path, value: &impl Serialize) -> Result<(), SetupError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SetupError::Metadata)?;
    if bytes.len() > MAX_JSON {
        return Err(SetupError::Metadata);
    }
    publish(path, &bytes)
}
fn publish(path: &Path, bytes: &[u8]) -> Result<(), SetupError> {
    check_path(path)?;
    if exists(path)? {
        if read(path, MAX_JSON)? == bytes {
            return Ok(());
        }
        return Err(SetupError::Interrupted);
    }
    let parent = path.parent().ok_or(SetupError::Invalid)?;
    let random = AuthToken::generate().map_err(|_| SetupError::Metadata)?;
    let staging = parent.join(format!(".setup-{random}.pending"));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staging).map_err(|_| SetupError::Metadata)?;
    file.write_all(bytes).map_err(|_| SetupError::Metadata)?;
    file.sync_all().map_err(|_| SetupError::Metadata)?;
    drop(file);
    match fs::hard_link(&staging, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && read(path, MAX_JSON)? == bytes => {}
        Err(_) => return Err(SetupError::Metadata),
    }
    #[cfg(unix)]
    fs::File::open(parent).and_then(|directory| directory.sync_all()).map_err(|_| SetupError::Metadata)?;
    fs::remove_file(staging).map_err(|_| SetupError::Metadata)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdm_credentials::{BearerSecret, CredentialError, CredentialKey};
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
    };
    #[derive(Default)]
    struct Memory {
        values: RefCell<BTreeMap<CredentialKey, String>>,
        fail_capture: Cell<bool>,
        reads: Cell<usize>,
        writes: Cell<usize>,
    }
    impl CredentialStore for Memory {
        fn get(&self, key: &CredentialKey) -> Result<Option<BearerSecret>, CredentialError> {
            self.reads.set(self.reads.get() + 1);
            self.values.borrow().get(key).cloned().map(BearerSecret::parse).transpose()
        }
        fn set(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError> {
            if self.fail_capture.get() {
                return Err(CredentialError::Unavailable);
            }
            self.values.borrow_mut().insert(key.clone(), secret.expose().into());
            self.writes.set(self.writes.get() + 1);
            Ok(())
        }
        fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError> {
            self.values.borrow_mut().remove(key);
            Ok(())
        }
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self(std::env::temp_dir().join(format!("solidcraft-local-setup-{}", AuthToken::generate()?))))
        }
        fn setup(&self) -> Result<LocalSetup, SetupError> {
            LocalSetup::new(self.0.clone())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Reproduce an installation journal written before streaming was supported.
    /// The failed capture leaves generation one and no credential registry.
    fn begin_legacy_fixture(setup: &LocalSetup, credentials: &Memory) -> Result<RunningLocalSetup, Box<dyn std::error::Error>> {
        credentials.fail_capture.set(true);
        assert!(matches!(setup.begin("admin", credentials), Err(SetupError::Credentials)));
        credentials.fail_capture.set(false);
        let prepared_path = setup.root.join("setup/prepared.json");
        let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&prepared_path)?)?;
        record.as_object_mut().ok_or("missing legacy prepared object")?.remove("stream_policy");
        fs::write(&prepared_path, serde_json::to_vec(&record)?)?;
        assert!(setup.prepared()?.stream_policy.is_none());
        Ok(setup.resume(credentials)?)
    }

    #[test]
    fn original_tls_setup_verifies_admin_and_preserves_no_bearer_on_disk() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        assert!(!root.0.try_exists()?);
        let credentials = Memory::default();
        let running = setup.begin("admin", &credentials)?;
        assert!(running.address().ip().is_loopback());
        assert_eq!(running.profile.principal_id(), "admin");
        assert_eq!(setup.inspect()?, SetupStatus::VerificationRecorded);
        assert_eq!(credentials.writes.get(), 1);
        assert!(matches!(setup.resume(&credentials), Err(SetupError::Busy)));
        let profile_json = serde_json::to_vec(&running.profile)?;
        for bearer in credentials.values.borrow().values() {
            assert!(!String::from_utf8_lossy(&profile_json).contains(bearer));
            for name in ["prepared.json", "enrollment.json", "ready.json"] {
                assert!(!String::from_utf8_lossy(&fs::read(root.0.join("setup").join(name))?).contains(bearer));
            }
            assert!(!String::from_utf8_lossy(&fs::read(root.0.join("archive/managed-principals.json"))?).contains(bearer));
        }
        let origin = running.profile.origin().to_owned();
        let server_id = running.receipt.server_id.clone();
        drop(running);
        let resumed = setup.resume(&credentials)?;
        assert_eq!(resumed.profile.origin(), origin);
        assert_eq!(resumed.receipt.server_id, server_id);
        assert_eq!(credentials.writes.get(), 1);
        Ok(())
    }

    #[test]
    fn failed_capture_retries_prepared_install_without_replacing_tls() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        let credentials = Memory::default();
        credentials.fail_capture.set(true);
        assert!(matches!(setup.begin("admin", &credentials), Err(SetupError::Credentials)));
        assert_eq!(setup.inspect()?, SetupStatus::Prepared);
        assert!(!root.0.join("archive/managed-principals.json").try_exists()?);
        let before = fs::read(root.0.join("tls/ca.der"))?;
        credentials.fail_capture.set(false);
        let running = setup.resume(&credentials)?;
        assert_eq!(fs::read(root.0.join("tls/ca.der"))?, before);
        assert_eq!(running.profile.principal_id(), "admin");
        Ok(())
    }

    #[test]
    fn incomplete_tls_or_prepared_publication_never_enrolls_or_replaces_data() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        let credentials = Memory::default();
        private_directory(&root.0, false)?;
        private_directory(&root.0.join("setup"), false)?;
        private_directory(&root.0.join("tls"), false)?;
        // Crash before the prepared completion record. Preserve even a partial
        // TLS file instead of generating new trust or creating an administrator.
        publish(&root.0.join("tls/ca.der"), b"incomplete-tls")?;
        assert!(matches!(setup.inspect(), Err(SetupError::Interrupted)));
        assert!(matches!(setup.resume(&credentials), Err(SetupError::Interrupted)));
        assert_eq!(fs::read(root.0.join("tls/ca.der"))?, b"incomplete-tls");
        assert!(!root.0.join("archive").try_exists()?);
        assert_eq!(credentials.reads.get(), 0);
        assert_eq!(credentials.writes.get(), 0);

        // A damaged installation with an otherwise valid prepared record and a
        // missing private key is also rejected before credential capture.
        let missing_key = Temp::new()?;
        let missing_setup = missing_key.setup()?;
        private_directory(&missing_key.0, false)?;
        private_directory(&missing_key.0.join("setup"), false)?;
        private_directory(&missing_key.0.join("tls"), false)?;
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
        let der = certificate.cert.der().to_vec();
        publish(&missing_key.0.join("tls/ca.der"), &der)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let prepared = Prepared {
            version: 1,
            installation_id: AuthToken::generate()?,
            administrator: "admin".into(),
            port: listener.local_addr()?.port(),
            certificate_sha256: hash(&der),
            stream_policy: None,
        };
        drop(listener);
        publish_json(&missing_key.0.join("setup/prepared.json"), &prepared)?;
        assert!(matches!(missing_setup.inspect(), Err(SetupError::Interrupted)));
        assert!(matches!(missing_setup.resume(&credentials), Err(SetupError::Interrupted)));
        assert_eq!(fs::read(missing_key.0.join("tls/ca.der"))?, der);
        assert!(!missing_key.0.join("archive").try_exists()?);
        assert_eq!(credentials.reads.get(), 0);
        assert_eq!(credentials.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn captured_intent_finalizes_same_bearer_without_regeneration() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        let credentials = Memory::default();
        credentials.fail_capture.set(true);
        assert!(setup.begin("admin", &credentials).is_err());
        credentials.fail_capture.set(false);
        let prepared = setup.prepared()?;
        // Crash boundary: trusted sink durably captures metadata but returns an
        // error before initialize_to can reserve/publish the principal registry.
        let profiles = ProfileDirectory::new(root.0.join("profiles"))?;
        let der = read(&root.0.join("tls/ca.der"), MAX_CA)?;
        let origin = format!("https://127.0.0.1:{}", prepared.port);
        let failed = pdm_login::enroll_local_with_hook(
            &root.0.join("archive"),
            "admin",
            &origin,
            Trust::certificate_der(&der)?,
            &credentials,
            |receipt, profile| {
                let profile_id = profiles.install_new(profile.clone()).map_err(|_| pdm_login::LoginError::EnrollmentFailed)?;
                publish_json(
                    &root.0.join("setup/enrollment.json"),
                    &Enrollment {
                        version: 1,
                        installation_id: prepared.installation_id.clone(),
                        administrator: receipt.administrator.clone(),
                        server_id: receipt.server_id.clone(),
                        profile_id,
                    },
                )
                .map_err(|_| pdm_login::LoginError::EnrollmentFailed)?;
                Err(pdm_login::LoginError::EnrollmentFailed)
            },
        );
        assert!(failed.is_err());
        assert_eq!(setup.inspect()?, SetupStatus::EnrollmentCaptured);
        assert!(!root.0.join("archive/managed-principals.json").try_exists()?);
        let before = credentials.values.borrow().clone();
        let running = setup.resume(&credentials)?;
        assert_eq!(*credentials.values.borrow(), before);
        assert_eq!(credentials.writes.get(), 1);
        assert_eq!(running.profile.principal_id(), "admin");
        Ok(())
    }

    #[test]
    fn altered_trust_partial_registry_and_occupied_port_are_preserved() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        let credentials = Memory::default();
        let running = begin_legacy_fixture(&setup, &credentials)?;
        let port = running.address().port();
        drop(running);
        let occupying = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
        let reads = credentials.reads.get();
        assert!(matches!(setup.resume(&credentials), Err(SetupError::Busy)));
        assert_eq!(credentials.reads.get(), reads);
        drop(occupying);
        let original_ca = fs::read(root.0.join("tls/ca.der"))?;
        let changed = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
        fs::write(root.0.join("tls/ca.der"), changed.cert.der())?;
        assert!(setup.resume(&credentials).is_err());
        assert_eq!(credentials.reads.get(), reads);
        fs::write(root.0.join("tls/ca.der"), original_ca)?;
        fs::write(root.0.join("archive/managed-principals.json"), b"[")?;
        assert!(setup.resume(&credentials).is_err());
        assert_eq!(fs::read(root.0.join("archive/managed-principals.json"))?, b"[");
        assert!(setup.begin("other-admin", &credentials).is_err());
        Ok(())
    }

    #[test]
    fn recorded_verification_does_not_bypass_missing_credential_or_current_role() -> Result<(), Box<dyn std::error::Error>> {
        for remove_credential in [true, false] {
            let root = Temp::new()?;
            let setup = root.setup()?;
            let credentials = Memory::default();
            let running = begin_legacy_fixture(&setup, &credentials)?;
            let address = running.address();
            drop(running);
            let registry_path = root.0.join("archive/managed-principals.json");
            if remove_credential {
                credentials.values.borrow_mut().clear();
            } else {
                let mut registry: Vec<solidcraft_pdm::managed::PrincipalCredential> = serde_json::from_slice(&fs::read(&registry_path)?)?;
                let administrator = registry.first_mut().ok_or("missing administrator")?;
                administrator.principal.role = Role::Contributor;
                fs::write(&registry_path, serde_json::to_vec(&registry)?)?;
            }
            let preserved = ["setup/ready.json", "tls/ca.der", "tls/server-key.der", "archive/managed-principals.json"]
                .into_iter()
                .map(|name| Ok((name, fs::read(root.0.join(name))?)))
                .collect::<Result<Vec<_>, std::io::Error>>()?;
            assert_eq!(setup.inspect()?, SetupStatus::VerificationRecorded);
            assert!(setup.resume(&credentials).is_err());
            for (name, bytes) in preserved {
                assert_eq!(fs::read(root.0.join(name))?, bytes);
            }
            // A rejected fresh login must shut down only its own server and
            // release both locks, allowing explicit operator recovery later.
            let _port = TcpListener::bind(address)?;
            let _installation = installation_lock(&root.0)?;
            let _store = Store::open(&root.0.join("archive"))?;
            assert_eq!(credentials.writes.get(), 1);
        }
        Ok(())
    }

    #[test]
    fn enrollment_administrator_mismatch_is_rejected_before_credential_lookup() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        let credentials = Memory::default();
        let running = setup.begin("admin", &credentials)?;
        drop(running);
        let reads = credentials.reads.get();
        let registry_before = fs::read(root.0.join("archive/managed-principals.json"))?;
        let intent_path = root.0.join("setup/enrollment.json");
        let mut intent: Enrollment = read_json(&intent_path)?;
        intent.administrator = "different-admin".into();
        fs::write(&intent_path, serde_json::to_vec(&intent)?)?;
        assert!(matches!(setup.resume(&credentials), Err(SetupError::Invalid)));
        assert_eq!(credentials.reads.get(), reads);
        assert_eq!(fs::read(root.0.join("archive/managed-principals.json"))?, registry_before);
        Ok(())
    }
    #[test]
    fn new_installation_negotiates_namespace_and_streaming_with_exact_limits_after_resume() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        let credentials = Memory::default();
        let running = setup.begin("admin", &credentials)?;
        let expected = StreamPolicy { version: 1, max_file_bytes: 512 * 1024 * 1024, max_store_bytes: 20 * 1024 * 1024 * 1024 };
        assert_eq!(setup.prepared()?.stream_policy, Some(expected.clone()));
        let server_id = running.receipt.server_id.clone();
        let session = pdm_login::resume(running.profile.clone(), &credentials)?;
        assert_eq!(session.client.capabilities()?.metadata_backend, "redb");
        let namespace = session.client.namespace_capabilities()?.ok_or("missing namespace capabilities")?;
        assert!(namespace.supported && namespace.can_mutate && namespace.stable_materialization_paths);
        let transfer = session.client.transfer_capabilities()?.ok_or("missing transfer capabilities")?;
        assert!(transfer.binary_transfer_v1 && transfer.can_upload);
        assert_eq!(transfer.limits, Some(expected.clone()));
        assert!(transfer.recovery_epoch > 0);
        let policy_bytes = fs::read(root.0.join("archive/managed/stream-policy.json"))?;
        drop(session);
        drop(running);
        let resumed = setup.resume(&credentials)?;
        assert_eq!(resumed.receipt.server_id, server_id);
        let session = pdm_login::resume(resumed.profile.clone(), &credentials)?;
        assert_eq!(session.client.transfer_capabilities()?.ok_or("missing resumed transfer capabilities")?.limits, Some(expected));
        assert!(session.client.namespace_capabilities()?.ok_or("missing resumed namespace capabilities")?.supported);
        assert_eq!(fs::read(root.0.join("archive/managed/stream-policy.json"))?, policy_bytes);
        assert_eq!(credentials.writes.get(), 1);
        Ok(())
    }

    #[test]
    fn legacy_prepared_record_without_policy_resumes_without_conversion() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        let credentials = Memory::default();
        credentials.fail_capture.set(true);
        assert!(matches!(setup.begin("admin", &credentials), Err(SetupError::Credentials)));
        let prepared_path = root.0.join("setup/prepared.json");
        let mut old_record: serde_json::Value = serde_json::from_slice(&fs::read(&prepared_path)?)?;
        old_record.as_object_mut().ok_or("missing prepared object")?.remove("stream_policy");
        fs::write(&prepared_path, serde_json::to_vec(&old_record)?)?;
        assert!(setup.prepared()?.stream_policy.is_none());
        let metadata_path = root.0.join("archive/managed/generations/1/state.json");
        let original = fs::read(&metadata_path)?;
        credentials.fail_capture.set(false);
        let running = setup.resume(&credentials)?;
        let server_id = running.receipt.server_id.clone();
        let session = pdm_login::resume(running.profile.clone(), &credentials)?;
        assert_eq!(session.client.capabilities()?.metadata_backend, "json_generations");
        assert!(!session.client.namespace_capabilities()?.ok_or("missing legacy namespace negotiation")?.supported);
        assert!(!session.client.transfer_capabilities()?.ok_or("missing legacy transfer negotiation")?.binary_transfer_v1);
        assert!(!root.0.join("archive/managed/stream-policy.json").try_exists()?);
        assert!(!root.0.join("archive/managed/metadata.redb").try_exists()?);
        assert_eq!(fs::read(&metadata_path)?, original);
        drop(session);
        drop(running);
        let resumed = setup.resume(&credentials)?;
        assert_eq!(resumed.receipt.server_id, server_id);
        assert_eq!(fs::read(&metadata_path)?, original);
        assert!(!root.0.join("archive/managed/stream-policy.json").try_exists()?);
        assert_eq!(credentials.writes.get(), 1);
        Ok(())
    }

    #[test]
    fn ready_streaming_installation_never_recreates_missing_policy() -> Result<(), Box<dyn std::error::Error>> {
        let root = Temp::new()?;
        let setup = root.setup()?;
        let credentials = Memory::default();
        let running = setup.begin("admin", &credentials)?;
        drop(running);
        let policy_path = root.0.join("archive/managed/stream-policy.json");
        fs::remove_file(&policy_path)?;
        let preserved = ["setup/prepared.json", "setup/enrollment.json", "setup/ready.json", "archive/managed-principals.json"]
            .into_iter()
            .map(|name| Ok((name, fs::read(root.0.join(name))?)))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        assert!(matches!(setup.resume(&credentials), Err(SetupError::Interrupted)));
        assert!(!policy_path.try_exists()?);
        for (name, bytes) in preserved {
            assert_eq!(fs::read(root.0.join(name))?, bytes);
        }
        assert_eq!(credentials.writes.get(), 1);
        Ok(())
    }
    #[test]
    fn transactional_ready_receipt_never_bypasses_current_database_role_or_credential() -> Result<(), Box<dyn std::error::Error>> {
        use solidcraft_pdm::{
            administration::{AdminRequest, AdminResponse},
            client::Client,
        };
        for change in ["role", "disabled", "credential"] {
            let root = Temp::new()?;
            let setup = root.setup()?;
            let credentials = Memory::default();
            let running = setup.begin("admin", &credentials)?;
            let installer = pdm_login::resume(running.profile.clone(), &credentials)?;
            assert_eq!(installer.client.capabilities()?.metadata_backend, "redb");
            let AdminResponse::Users { revision, .. } = installer.client.admin(AdminRequest::ListUsers {})? else {
                return Err("missing database users response".into());
            };
            let second_bearer = AuthToken::generate()?;
            let AdminResponse::UserChanged { revision, user } = installer.client.admin(AdminRequest::CreateUser {
                request_id: AuthToken::generate()?,
                expected_revision: revision,
                id: "second-admin".into(),
                role: Role::Administrator,
                credential_sha256: hash(second_bearer.as_bytes()),
            })?
            else {
                return Err("missing second administrator creation response".into());
            };
            assert_eq!(user.id, "second-admin");
            assert_eq!(user.role, Role::Administrator);
            let ca = read(&root.0.join("tls/ca.der"), MAX_CA)?;
            let second =
                Client::https_with_ca(running.profile.origin(), AuthToken::parse(second_bearer)?, &ca)?.bind_server(&running.receipt.server_id)?;
            assert_eq!(second.authenticated_identity()?.principal.id, "second-admin");
            let seed_path = root.0.join("archive/managed-principals.json");
            let old_seed = fs::read(&seed_path)?;
            let request_id = AuthToken::generate()?;
            let mutation = match change {
                "role" => AdminRequest::SetRole { request_id, expected_revision: revision, id: "admin".into(), role: Role::Contributor },
                "disabled" => AdminRequest::SetEnabled { request_id, expected_revision: revision, id: "admin".into(), enabled: false },
                _ => AdminRequest::ReplaceCredential {
                    request_id,
                    expected_revision: revision,
                    id: "admin".into(),
                    credential_sha256: hash(AuthToken::generate()?.as_bytes()),
                },
            };
            let AdminResponse::UserChanged { user, .. } = second.admin(mutation)? else {
                return Err("missing database revocation response".into());
            };
            assert_eq!(user.id, "admin");
            if change == "role" {
                assert_eq!(user.role, Role::Contributor);
                assert_eq!(installer.client.authenticated_identity()?.principal.role, Role::Contributor);
            } else {
                if change == "disabled" {
                    assert!(!user.enabled);
                }
                assert!(matches!(installer.client.authenticated_identity(), Err(solidcraft_pdm::Error::Server(code)) if code == "unauthorized"));
            }
            // The JSON seed deliberately still advertises the original account.
            // Only the authenticated database mutation establishes current authority.
            assert_eq!(fs::read(&seed_path)?, old_seed);
            let ready = fs::read(root.0.join("setup/ready.json"))?;
            let address = running.address();
            drop(installer);
            drop(second);
            drop(running);
            assert_eq!(setup.inspect()?, SetupStatus::VerificationRecorded);
            assert!(matches!(setup.resume(&credentials), Err(SetupError::Service)), "{change} must be checked against fresh database authority");
            assert_eq!(fs::read(root.0.join("setup/ready.json"))?, ready);
            assert_eq!(fs::read(&seed_path)?, old_seed);
            assert_eq!(credentials.writes.get(), 1);
            let _port = TcpListener::bind(address)?;
            let _installation = installation_lock(&root.0)?;
            let _store = Store::open(&root.0.join("archive"))?;
        }
        Ok(())
    }
}
