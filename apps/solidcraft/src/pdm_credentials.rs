//! Native worker-only PDM credential boundary. Construction never accesses the OS.
//! User and connector bearers have distinct slots; storage-provider credentials
//! must use a separate namespace. Callers obtain principal identity from authentication.
#![cfg(not(target_arch = "wasm32"))]
use sha2::{Digest, Sha256};
use std::{fmt, net::IpAddr};

const SERVICE: &str = "SolidCraft PDM";
static CAPTURE_SERIALIZER: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    User,
    Connector,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialError {
    InvalidIdentity,
    InvalidSecret,
    Unavailable,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "Invalid PDM credential identity",
            Self::InvalidSecret => "Invalid PDM bearer credential",
            Self::Unavailable => "PDM credential storage unavailable",
        })
    }
}
impl std::error::Error for CredentialError {}

/// Validated public identity only; never include a token in this key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialKey {
    account: String,
}

/// Validated transport scope. Trust or route changes require a new login rather
/// than retrieving a bearer established under another trust decision.
#[derive(Clone, Debug)]
pub struct CredentialContext {
    trust: String,
    tunnel: Option<String>,
}
impl CredentialContext {
    pub fn platform(tunnel: Option<&str>) -> Result<Self, CredentialError> {
        Self::validated("platform".into(), tunnel)
    }
    pub fn certificate_der(der: &[u8], tunnel: Option<&str>) -> Result<Self, CredentialError> {
        if der.is_empty() || der.len() > 64 * 1024 {
            return Err(CredentialError::InvalidIdentity);
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(der.to_vec())).map_err(|_| CredentialError::InvalidIdentity)?;
        Self::validated(format!("ca-sha256:{:x}", Sha256::digest(der)), tunnel)
    }
    fn validated(trust: String, tunnel: Option<&str>) -> Result<Self, CredentialError> {
        if tunnel
            .is_some_and(|id| id.is_empty() || id.len() > 64 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
        {
            return Err(CredentialError::InvalidIdentity);
        }
        Ok(Self { trust, tunnel: tunnel.map(str::to_owned) })
    }
}

impl CredentialKey {
    /// Low-level unscoped slot. Native login/resume must use `new_scoped`.
    pub fn new(origin: &str, server_id: &str, principal_id: &str, purpose: Purpose) -> Result<Self, CredentialError> {
        let origin = normalized_origin(origin)?;
        if !hex64(server_id)
            || server_id.bytes().any(|byte| byte.is_ascii_uppercase())
            || principal_id.is_empty()
            || principal_id.len() > 128
            || principal_id.chars().any(char::is_control)
        {
            return Err(CredentialError::InvalidIdentity);
        }
        let mut hash = Sha256::new();
        for field in [
            "solidcraft-pdm-keyring-v1",
            match purpose {
                Purpose::User => "user",
                Purpose::Connector => "connector",
            },
            &origin,
            server_id,
            principal_id,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        Ok(Self { account: format!("v1-{:x}", hash.finalize()) })
    }

    pub fn new_scoped(
        origin: &str,
        server_id: &str,
        principal_id: &str,
        purpose: Purpose,
        context: &CredentialContext,
    ) -> Result<Self, CredentialError> {
        let base = Self::new(origin, server_id, principal_id, purpose)?;
        let mut hash = Sha256::new();
        for field in [
            "solidcraft-pdm-keyring-v2",
            &base.account,
            &context.trust,
            if context.tunnel.is_some() { "relay" } else { "direct" },
            context.tunnel.as_deref().unwrap_or_default(),
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        Ok(Self { account: format!("v2-{:x}", hash.finalize()) })
    }
}

pub(crate) fn normalized_origin(origin: &str) -> Result<String, CredentialError> {
    let invalid = CredentialError::InvalidIdentity;
    if origin.len() > 2048
        || !origin.is_ascii()
        || origin.bytes().any(|byte| byte.is_ascii_whitespace())
        || origin.contains(['%', '@', '?', '#', '\\'])
    {
        return Err(invalid);
    }
    let (scheme, authority) = origin.split_once("://").ok_or(invalid)?;
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid);
    }
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty() || authority.contains('/') {
        return Err(invalid);
    }
    let (host, port) = if authority.starts_with('[') {
        let closing = authority.find(']').ok_or(invalid)?;
        let address: IpAddr = authority.get(1..closing).ok_or(invalid)?.parse().map_err(|_| invalid)?;
        if !address.is_ipv6() {
            return Err(invalid);
        }
        let suffix = authority.get(closing + 1..).ok_or(invalid)?;
        (format!("[{address}]"), if suffix.is_empty() { None } else { Some(suffix.strip_prefix(':').ok_or(invalid)?) })
    } else {
        let (host, port) = authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port)));
        if host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(invalid);
        }
        // Ambiguous numeric IPv4 spellings must not create alternate slots.
        let numeric_suffix = host
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()) || label.to_ascii_lowercase().starts_with("0x"));
        if numeric_suffix && host.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(invalid);
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        None => None,
        Some(value) => {
            let parsed: u16 = value.parse().map_err(|_| invalid)?;
            if parsed == 0 || parsed.to_string() != value {
                return Err(invalid);
            }
            (parsed != 443).then_some(parsed)
        }
    };
    Ok(match port {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
}

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub struct BearerSecret(String);
impl BearerSecret {
    pub fn parse(value: String) -> Result<Self, CredentialError> {
        if !hex64(&value) {
            return Err(CredentialError::InvalidSecret);
        }
        Ok(Self(value))
    }
    /// Borrow only for an authenticated request or a credential persistence sink.
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for BearerSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerSecret([redacted])")
    }
}

pub trait CredentialStore {
    fn get(&self, key: &CredentialKey) -> Result<Option<BearerSecret>, CredentialError>;
    fn set(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError>;
    fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError>;
    /// Non-replacing capture. Injected stores serialize within this process;
    /// the OS implementation additionally serializes across client processes.
    fn capture_new(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError> {
        let _guard = CAPTURE_SERIALIZER.lock().map_err(|_| CredentialError::Unavailable)?;
        match self.get(key)? {
            Some(existing) if existing.expose() == secret.expose() => Ok(()),
            Some(_) => Err(CredentialError::Unavailable),
            None => self.set(key, secret),
        }
    }
}

fn guard_lock_path(path: &std::path::Path) -> Result<(), CredentialError> {
    if !path.is_absolute() || path.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
        return Err(CredentialError::Unavailable);
    }
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(CredentialError::Unavailable);
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(CredentialError::Unavailable);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CredentialError::Unavailable),
        }
    }
    Ok(())
}
fn lock_at(home: &std::path::Path, key: &CredentialKey) -> Result<std::fs::File, CredentialError> {
    guard_lock_path(home)?;
    if !std::fs::symlink_metadata(home).map_err(|_| CredentialError::Unavailable)?.is_dir() {
        return Err(CredentialError::Unavailable);
    }
    let root = home.join(".solidcraft-pdm-credential-locks");
    guard_lock_path(&root)?;
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(CredentialError::Unavailable),
    }
    let metadata = std::fs::symlink_metadata(&root).map_err(|_| CredentialError::Unavailable)?;
    if !metadata.is_dir() {
        return Err(CredentialError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(CredentialError::Unavailable);
        }
    }
    // The stable directory is under USERPROFILE/HOME, never redirected app-data
    // or an isolated client settings root. Windows inherits the user home's
    // private parent ACL; this module does not claim to inspect Windows DACLs.
    let path = root.join(format!("{}.lock", key.account));
    guard_lock_path(&path)?;
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && (!metadata.is_file() || metadata.len() != 0)
    {
        return Err(CredentialError::Unavailable);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(|_| CredentialError::Unavailable)?;
    guard_lock_path(&path)?;
    let metadata = file.metadata().map_err(|_| CredentialError::Unavailable)?;
    if !metadata.is_file() || metadata.len() != 0 {
        return Err(CredentialError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(CredentialError::Unavailable);
        }
    }
    file.lock().map_err(|_| CredentialError::Unavailable)?;
    Ok(file)
}
fn scoped_lock(key: &CredentialKey) -> Result<std::fs::File, CredentialError> {
    #[cfg(windows)]
    let variable = "USERPROFILE";
    #[cfg(not(windows))]
    let variable = "HOME";
    let home = std::env::var_os(variable).map(std::path::PathBuf::from).ok_or(CredentialError::Unavailable)?;
    lock_at(&home, key)
}

pub struct OsCredentialStore;
impl OsCredentialStore {
    fn entry(key: &CredentialKey) -> Result<keyring::Entry, CredentialError> {
        if !cfg!(any(target_os = "windows", target_os = "macos", target_os = "linux")) {
            return Err(CredentialError::Unavailable);
        }
        keyring::Entry::new(SERVICE, &key.account).map_err(|_| CredentialError::Unavailable)
    }
}
impl CredentialStore for OsCredentialStore {
    fn capture_new(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError> {
        let _lock = scoped_lock(key)?;
        let entry = Self::entry(key)?;
        match entry.get_password() {
            Ok(value) => {
                let existing = BearerSecret::parse(value)?;
                if existing.expose() == secret.expose() { Ok(()) } else { Err(CredentialError::Unavailable) }
            }
            Err(keyring::Error::NoEntry) => entry.set_password(secret.expose()).map_err(|_| CredentialError::Unavailable),
            Err(_) => Err(CredentialError::Unavailable),
        }
    }
    fn get(&self, key: &CredentialKey) -> Result<Option<BearerSecret>, CredentialError> {
        match Self::entry(key)?.get_password() {
            Ok(value) => BearerSecret::parse(value).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(CredentialError::Unavailable),
        }
    }
    fn set(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError> {
        let _lock = scoped_lock(key)?;
        Self::entry(key)?.set_password(secret.expose()).map_err(|_| CredentialError::Unavailable)
    }
    fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        let _lock = scoped_lock(key)?;
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(CredentialError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::BTreeMap};
    #[derive(Default)]
    struct MemoryStore {
        values: RefCell<BTreeMap<String, String>>,
    }
    impl CredentialStore for MemoryStore {
        fn get(&self, key: &CredentialKey) -> Result<Option<BearerSecret>, CredentialError> {
            self.values.borrow().get(&key.account).cloned().map(BearerSecret::parse).transpose()
        }
        fn set(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError> {
            self.values.borrow_mut().insert(key.account.clone(), secret.expose().into());
            Ok(())
        }
        fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError> {
            self.values.borrow_mut().remove(&key.account);
            Ok(())
        }
    }
    fn key(origin: &str, principal: &str, purpose: Purpose) -> Result<CredentialKey, CredentialError> {
        CredentialKey::new(origin, &"a".repeat(64), principal, purpose)
    }
    #[test]
    fn paired_import_concurrent_capture_preserves_one_winner_and_exact_repeat() {
        use std::sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicUsize, Ordering},
        };
        #[derive(Default)]
        struct Shared {
            values: Mutex<BTreeMap<String, String>>,
            writes: AtomicUsize,
        }
        impl CredentialStore for Shared {
            fn get(&self, key: &CredentialKey) -> Result<Option<BearerSecret>, CredentialError> {
                self.values.lock().map_err(|_| CredentialError::Unavailable)?.get(&key.account).cloned().map(BearerSecret::parse).transpose()
            }
            fn set(&self, key: &CredentialKey, secret: &BearerSecret) -> Result<(), CredentialError> {
                self.values.lock().map_err(|_| CredentialError::Unavailable)?.insert(key.account.clone(), secret.expose().into());
                self.writes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn delete(&self, key: &CredentialKey) -> Result<(), CredentialError> {
                self.values.lock().map_err(|_| CredentialError::Unavailable)?.remove(&key.account);
                Ok(())
            }
        }
        let store = Arc::new(Shared::default());
        let barrier = Arc::new(Barrier::new(16));
        let key = key("https://example.com", "concurrent-import", Purpose::User).unwrap();
        let workers: Vec<_> = (0..16)
            .map(|n| {
                let store = store.clone();
                let barrier = barrier.clone();
                let key = key.clone();
                std::thread::spawn(move || {
                    let secret = BearerSecret::parse(format!("{n:064x}")).unwrap();
                    barrier.wait();
                    store.capture_new(&key, &secret).is_ok()
                })
            })
            .collect();
        let accepted = workers.into_iter().map(|worker| usize::from(worker.join().unwrap())).sum::<usize>();
        assert_eq!(accepted, 1);
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
        let winner = store.get(&key).unwrap().unwrap();
        store.capture_new(&key, &winner).unwrap();
        assert_eq!(store.writes.load(Ordering::SeqCst), 1, "exact repeat never rewrites custody");
    }

    #[test]
    fn paired_import_scoped_file_lock_serializes_distinct_handles_and_stores_no_secret() {
        use std::{sync::mpsc, time::Duration};
        let home = std::env::temp_dir().join(format!("solidcraft-credential-lock-test-{}", solidcraft_pdm::AuthToken::generate().unwrap()));
        std::fs::create_dir(&home).unwrap();
        let key = key("https://example.com", "cross-process-lock", Purpose::User).unwrap();
        let first = lock_at(&home, &key).unwrap();
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_home = home.clone();
        let worker_key = key.clone();
        let worker = std::thread::spawn(move || {
            start_tx.send(()).unwrap();
            let lock = lock_at(&worker_home, &worker_key);
            done_tx.send(lock.map(|file| file.metadata().unwrap().len())).unwrap();
        });
        start_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err(), "a second independent handle cannot enter the same slot mutation");
        drop(first);
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap(), 0);
        worker.join().unwrap();
        let path = home.join(".solidcraft-pdm-credential-locks").join(format!("{}.lock", key.account));
        assert!(std::fs::read(&path).unwrap().is_empty());
        std::fs::write(&path, b"unexpected metadata").unwrap();
        assert!(lock_at(&home, &key).is_err(), "unexpected content never becomes a secret custody file");
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn normalized_identity_and_purpose_isolation() -> Result<(), CredentialError> {
        let original = key("https://example.com", "admin", Purpose::User)?;
        assert_eq!(original, key("HTTPS://EXAMPLE.COM:443/", "admin", Purpose::User)?);
        for alternative in [
            key("https://example.com:444", "admin", Purpose::User)?,
            key("https://other.com", "admin", Purpose::User)?,
            key("https://example.com", "other", Purpose::User)?,
            key("https://example.com", "admin", Purpose::Connector)?,
            CredentialKey::new("https://example.com", &"b".repeat(64), "admin", Purpose::User)?,
        ] {
            assert_ne!(original, alternative);
        }
        assert_eq!(key("https://[::1]:443", "admin", Purpose::User)?, key("https://[0:0:0:0:0:0:0:1]", "admin", Purpose::User)?);
        Ok(())
    }
    #[test]
    fn reject_ambiguous_or_non_origin_addresses() {
        for origin in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com?x",
            "https://example.com/#x",
            "https://example.com/path",
            "https://example.com//",
            "https://exa%6dple.com",
            "https://example.com:0443",
            "https://example.com:0",
            "https://example.com.",
            "https://127.1",
            "https://127.000.0.1",
            "https://0x7f000001",
            "https://127.0.0.0x1",
            "https://example.com\\other",
            "https://example.com\n",
        ] {
            assert!(key(origin, "admin", Purpose::User).is_err());
        }
    }

    #[test]
    fn invalid_public_identity_cannot_select_a_slot() {
        for server in ["", "a", &"A".repeat(64), &"g".repeat(64)] {
            assert!(CredentialKey::new("https://example.com", server, "admin", Purpose::User).is_err());
        }
        for principal in ["", "admin\n", &"a".repeat(129)] {
            assert!(key("https://example.com", principal, Purpose::User).is_err());
        }
    }
    #[test]
    fn roundtrip_delete_and_corrupt_storage_fail_closed() -> Result<(), CredentialError> {
        let store = MemoryStore::default();
        let user = key("https://example.com", "admin", Purpose::User)?;
        let connector = key("https://example.com", "admin", Purpose::Connector)?;
        assert!(store.get(&user)?.is_none());
        let secret = BearerSecret::parse("c".repeat(64))?;
        store.set(&user, &secret)?;
        assert_eq!(store.get(&user)?.ok_or(CredentialError::Unavailable)?.expose(), secret.expose());
        assert!(store.get(&connector)?.is_none());
        store.values.borrow_mut().insert(user.account.clone(), "corrupt-sensitive-data".into());
        assert!(matches!(store.get(&user), Err(CredentialError::InvalidSecret)));
        store.delete(&user)?;
        store.delete(&user)?;
        assert!(store.get(&user)?.is_none());
        Ok(())
    }
    #[test]
    fn secrets_and_errors_are_redacted() -> Result<(), CredentialError> {
        let secret = BearerSecret::parse("d".repeat(64))?;
        assert_eq!(format!("{secret:?}"), "BearerSecret([redacted])");
        for value in ["", "private-sensitive-value", &"z".repeat(64)] {
            let error = BearerSecret::parse(value.into()).err().ok_or(CredentialError::Unavailable)?;
            assert_eq!(error.to_string(), "Invalid PDM bearer credential");
            assert_eq!(format!("{error:?}"), "InvalidSecret");
        }
        assert_eq!(CredentialError::Unavailable.to_string(), "PDM credential storage unavailable");
        Ok(())
    }
}
