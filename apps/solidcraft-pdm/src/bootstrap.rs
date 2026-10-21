//! Local first-administrator enrollment for a new, privately owned store.
//!
//! This is not a password or remote login protocol. The installer must capture the
//! returned bearer secret directly into native credential storage, never a log,
//! command-line argument or file. Secure transports must disable the legacy
//! loopback owner fallback and authenticate configured principals exclusively.
use crate::{
    Error, Store,
    managed::{Principal, PrincipalCredential, Role},
};
use std::{
    fs,
    io::Write,
    path::{Component, Path},
};

/// Deliberately neither serializable nor clonable. Consume once into a keyring.
pub struct EnrollmentSecret(String);

impl std::fmt::Debug for EnrollmentSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EnrollmentSecret([redacted])")
    }
}

impl EnrollmentSecret {
    pub fn into_bearer(self) -> String {
        self.0
    }
}

/// Safe to display; this contains no authentication material.
#[derive(Debug, PartialEq, Eq)]
pub struct EnrollmentReceipt {
    pub administrator: String,
    pub server_id: String,
}

fn validate_root(root: &Path) -> Result<(), Error> {
    if !root.is_absolute() || root.components().any(|component| matches!(component, Component::ParentDir)) {
        return Err(Error::Invalid("bootstrap requires an absolute store path without parent traversal"));
    }
    crate::reject_symlink_ancestors(root)?;
    // Junctions and other reparse points are not necessarily classified as symlinks.
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        for ancestor in root.ancestors() {
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.file_attributes() & 0x400 != 0 => return Err(Error::Invalid("reparse store path")),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

/// Initialize once, while holding the same OS writer lock used by the service.
///
/// The directory must be privately owned by the installing account. Static path
/// validation does not protect against concurrent tampering by that host account.
/// A partial credential registry is deliberately retained after any failure:
/// reopening then fails closed rather than reverting to an unconfigured account.
/// Never retry enrollment by removing that registry or resetting an existing store.
/// Native installers should use [`initialize_to`] to persist the credential before
/// authority is published; this compatibility API transfers capture to its caller.
pub fn initialize(root: &Path, administrator: &str) -> Result<(EnrollmentReceipt, EnrollmentSecret), Error> {
    initialize_with_sink(root, administrator, |_, _| Ok(()))
}

/// Enroll through a trusted native credential sink before publishing authority.
///
/// The sink must durably capture the borrowed secret into private OS credential
/// storage and must never log it. It runs while the store writer lock is held.
/// A sink error leaves no principal registry and permits a later enrollment retry.
/// Once the sink succeeds, keep its credential even if publication fails: it may
/// be needed to recover an interrupted registry. This ordering prevents a crash
/// between registry publication and the installer's initial credential capture.
/// This function returns only the public receipt, never authentication material.
pub fn initialize_to(
    root: &Path,
    administrator: &str,
    sink: impl FnOnce(&EnrollmentReceipt, &str) -> Result<(), Error>,
) -> Result<EnrollmentReceipt, Error> {
    let (receipt, _) = initialize_with_sink(root, administrator, sink)?;
    Ok(receipt)
}

fn initialize_with_sink(
    root: &Path,
    administrator: &str,
    sink: impl FnOnce(&EnrollmentReceipt, &str) -> Result<(), Error>,
) -> Result<(EnrollmentReceipt, EnrollmentSecret), Error> {
    if !crate::valid_id(administrator) || administrator == "owner" {
        return Err(Error::Invalid("administrator ID"));
    }
    validate_root(root)?;
    validate_root(&root.join("writer.lock"))?;
    let registry = root.join("managed-principals.json");
    validate_root(&registry)?;
    match fs::symlink_metadata(&registry) {
        Ok(_) => return Err(Error::Invalid("principal registry already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let store = Store::open(root)?;
    // Check again under the lock; another installer may have finished meanwhile.
    match fs::symlink_metadata(&registry) {
        Ok(_) => return Err(Error::Invalid("principal registry already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let catalog = store.managed.catalog();
    if !catalog.entries.is_empty() || !store.list(None)?.is_empty() {
        return Err(Error::Invalid("bootstrap requires a store without documents"));
    }
    let secret = EnrollmentSecret(crate::AuthToken::generate()?);
    let credentials = [PrincipalCredential {
        principal: Principal { id: administrator.into(), role: Role::Administrator },
        token_sha256: crate::digest(secret.0.as_bytes()),
    }];
    let bytes = serde_json::to_vec(&credentials)?;
    let receipt = EnrollmentReceipt { administrator: administrator.into(), server_id: catalog.server_id };
    sink(&receipt, &secret.0)?;
    publish_registry(root, &bytes)?;
    Ok((receipt, secret))
}

/// Finish an interrupted trusted native installation using its already captured
/// credential. `expected` must come from the installer's immutable validated
/// enrollment intent, never a request body or caller-selected account label.
///
/// The server identity is checked against existing durable metadata. Before its
/// first registry exists the archive has no administrator identity to compare;
/// account binding is therefore the trusted installer's journal responsibility.
/// No network route may expose this function. Existing or partial registries
/// always refuse publication, and a failed attempt never rotates any credential.
pub fn finalize_enrollment(root: &Path, expected: &EnrollmentReceipt, bearer: &str) -> Result<(), Error> {
    if !crate::valid_id(&expected.administrator)
        || expected.administrator == "owner"
        || expected.server_id.len() != 64
        || !expected.server_id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Invalid("enrollment receipt"));
    }
    // This validates the random-bearer format, not a password or an entropy test.
    if bearer.len() != 64 || !bearer.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Invalid("enrollment credential"));
    }
    validate_root(root)?;
    if !fs::symlink_metadata(root)?.is_dir() {
        return Err(Error::Invalid("existing enrollment store required"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut private_ancestor = false;
        for ancestor in root.ancestors() {
            if fs::metadata(ancestor)?.permissions().mode() & 0o077 == 0 {
                private_ancestor = true;
                break;
            }
        }
        if !private_ancestor {
            return Err(Error::Invalid("private enrollment directory required"));
        }
    }
    for relative in ["managed", "managed/blobs", "managed/generations"] {
        let path = root.join(relative);
        validate_root(&path)?;
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(Error::Invalid("existing enrollment metadata required"));
        }
    }
    for relative in ["writer.lock", "managed/generations/1/state.json"] {
        let path = root.join(relative);
        validate_root(&path)?;
        if !fs::symlink_metadata(path)?.is_file() {
            return Err(Error::Invalid("existing enrollment metadata required"));
        }
    }
    let registry = root.join("managed-principals.json");
    registry_absent(&registry)?;
    let store = Store::open(root)?;
    registry_absent(&registry)?;
    let catalog = store.managed.catalog();
    if catalog.server_id != expected.server_id {
        return Err(Error::Invalid("enrollment server identity mismatch"));
    }
    if !catalog.entries.is_empty() || !store.list(None)?.is_empty() {
        return Err(Error::Invalid("enrollment requires a store without documents"));
    }
    let bytes = serde_json::to_vec(&[PrincipalCredential {
        principal: Principal { id: expected.administrator.clone(), role: Role::Administrator },
        token_sha256: crate::digest(bearer.as_bytes()),
    }])?;
    publish_registry(root, &bytes)
}

fn registry_absent(registry: &Path) -> Result<(), Error> {
    validate_root(registry)?;
    match fs::symlink_metadata(registry) {
        Ok(_) => Err(Error::Invalid("principal registry already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn publish_registry(root: &Path, bytes: &[u8]) -> Result<(), Error> {
    // Reserve the final name before writing anything. A crash or I/O failure
    // cannot leave a missing registry that would reactivate legacy fallback.
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(root.join("managed-principals.json"))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRoot(std::path::PathBuf);
    impl TestRoot {
        fn new() -> Result<Self, Error> {
            Ok(Self(std::env::temp_dir().join(format!("solidcraft-bootstrap-{}", crate::AuthToken::generate()?))))
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn captured_enrollment() -> Result<(TestRoot, EnrollmentReceipt, String), Error> {
        let root = TestRoot::new()?;
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(&root.0)?;
        let mut captured = None;
        let result = initialize_to(&root.0, "admin", |receipt, bearer| {
            captured =
                Some((EnrollmentReceipt { administrator: receipt.administrator.clone(), server_id: receipt.server_id.clone() }, bearer.to_owned()));
            Err(Error::Invalid("test interrupted after capture"))
        });
        assert!(result.is_err());
        let (receipt, bearer) = captured.ok_or(Error::Invalid("test capture missing"))?;
        Ok((root, receipt, bearer))
    }

    #[test]
    fn finalize_publishes_captured_credential_once_without_rotating_it() -> Result<(), Error> {
        let (root, receipt, bearer) = captured_enrollment()?;
        finalize_enrollment(&root.0, &receipt, &bearer)?;
        let bytes = fs::read(root.0.join("managed-principals.json"))?;
        assert!(!String::from_utf8_lossy(&bytes).contains(&bearer));
        let store = Store::open(&root.0)?;
        assert_eq!(store.managed.catalog().server_id, receipt.server_id);
        assert_eq!(store.managed.authenticate(&bearer), Some(Principal { id: "admin".into(), role: Role::Administrator }));
        drop(store);
        assert!(finalize_enrollment(&root.0, &receipt, &bearer).is_err());
        assert_eq!(fs::read(root.0.join("managed-principals.json"))?, bytes);
        Ok(())
    }

    #[test]
    fn finalize_rejects_invalid_receipt_credential_missing_store_and_busy_writer() -> Result<(), Error> {
        let (root, receipt, bearer) = captured_enrollment()?;
        let state_path = root.0.join("managed/generations/1/state.json");
        let before = fs::read(&state_path)?;
        let missing = TestRoot::new()?;
        assert!(finalize_enrollment(&missing.0, &receipt, &bearer).is_err());
        assert!(!missing.0.try_exists()?);
        let wrong_server = EnrollmentReceipt {
            administrator: "admin".into(),
            server_id: if receipt.server_id == "0".repeat(64) { "1".repeat(64) } else { "0".repeat(64) },
        };
        assert!(finalize_enrollment(&root.0, &wrong_server, &bearer).is_err());
        for administrator in ["", "owner", "Admin", "../admin"] {
            let invalid = EnrollmentReceipt { administrator: administrator.into(), server_id: receipt.server_id.clone() };
            assert!(finalize_enrollment(&root.0, &invalid, &bearer).is_err());
        }
        for invalid in ["", "secret-sensitive", &"z".repeat(64)] {
            let error = finalize_enrollment(&root.0, &receipt, invalid).err().ok_or(Error::Integrity)?;
            assert!(!format!("{error:?}").contains("secret-sensitive"));
        }
        let running = Store::open(&root.0)?;
        assert!(finalize_enrollment(&root.0, &receipt, &bearer).is_err());
        drop(running);
        assert!(!root.0.join("managed-principals.json").try_exists()?);
        assert_eq!(fs::read(state_path)?, before);
        Ok(())
    }

    #[test]
    fn finalize_refuses_partial_registry_and_existing_managed_or_legacy_documents() -> Result<(), Error> {
        let (root, receipt, bearer) = captured_enrollment()?;
        let registry = root.0.join("managed-principals.json");
        fs::write(&registry, b"[")?;
        assert!(finalize_enrollment(&root.0, &receipt, &bearer).is_err());
        assert_eq!(fs::read(&registry)?, b"[");
        for managed in [true, false] {
            let (documents, receipt, bearer) = captured_enrollment()?;
            let mut store = Store::open(&documents.0)?;
            if managed {
                store.managed.create(&Principal { id: "existing".into(), role: Role::Administrator }, "existing.solidcraft".into())?;
            } else {
                assert!(matches!(
                    store.execute(crate::Request::CheckIn {
                        document: "legacy".into(),
                        parent: None,
                        content: b"legacy-data".to_vec(),
                        dependencies: Vec::new()
                    }),
                    crate::Response::CheckedIn { .. }
                ));
            }
            let before = serde_json::to_vec(&store.list(None)?)?;
            drop(store);
            assert!(finalize_enrollment(&documents.0, &receipt, &bearer).is_err());
            assert!(!documents.0.join("managed-principals.json").try_exists()?);
            assert_eq!(serde_json::to_vec(&Store::open(&documents.0)?.list(None)?)?, before);
        }
        Ok(())
    }

    #[test]
    fn enrollment_reopens_with_hashed_administrator() -> Result<(), Error> {
        let root = TestRoot::new()?;
        let (receipt, secret) = initialize(&root.0, "first-admin")?;
        let bearer = secret.into_bearer();
        let bytes = fs::read(root.0.join("managed-principals.json"))?;
        assert!(!String::from_utf8_lossy(&bytes).contains(&bearer));
        let credentials: Vec<PrincipalCredential> = serde_json::from_slice(&bytes)?;
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].token_sha256, crate::digest(bearer.as_bytes()));
        assert_eq!(credentials[0].principal.role, Role::Administrator);
        let reopened = Store::open(&root.0)?;
        assert_eq!(reopened.managed.catalog().server_id, receipt.server_id);
        assert_eq!(reopened.managed.authenticate(&bearer), Some(Principal { id: receipt.administrator, role: Role::Administrator }));
        assert_eq!(reopened.managed.authenticate(&"0".repeat(64)), None);
        Ok(())
    }

    #[test]
    fn failed_credential_capture_allows_retry_without_publishing_authority() -> Result<(), Error> {
        let root = TestRoot::new()?;
        let failed = initialize_to(&root.0, "admin", |_, _| Err(Error::Invalid("credential storage unavailable")));
        assert!(failed.is_err());
        assert!(!root.0.join("managed-principals.json").try_exists()?);
        let mut captured = None;
        let receipt = initialize_to(&root.0, "admin", |receipt, secret| {
            assert_eq!(receipt.administrator, "admin");
            assert!(!root.0.join("managed-principals.json").try_exists()?);
            assert!(Store::open(&root.0).is_err());
            captured = Some(secret.to_owned());
            Ok(())
        })?;
        let captured = captured.ok_or(Error::Invalid("test credential capture missing"))?;
        let mut reopened = Store::open(&root.0)?;
        let principal = reopened.managed.authenticate(&captured).ok_or(Error::Forbidden)?;
        assert_eq!(principal, Principal { id: receipt.administrator, role: Role::Administrator });
        let created = reopened.managed.create(&principal, "Parts/captured.solidcraft".into())?;
        assert_eq!(created.logical_path, "Parts/captured.solidcraft");
        assert_eq!(reopened.managed.catalog().server_id, receipt.server_id);
        assert!(!String::from_utf8_lossy(&fs::read(root.0.join("managed-principals.json"))?).contains(&captured));
        Ok(())
    }

    #[test]
    fn rejected_existing_state_never_calls_credential_sink() -> Result<(), Error> {
        let root = TestRoot::new()?;
        let mut existing = Store::open(&root.0)?;
        existing.managed.create(&Principal { id: "existing-admin".into(), role: Role::Administrator }, "existing.solidcraft".into())?;
        drop(existing);
        let mut called = false;
        assert!(
            initialize_to(&root.0, "admin", |_, _| {
                called = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!called);
        assert!(!root.0.join("managed-principals.json").try_exists()?);
        let partial = TestRoot::new()?;
        drop(Store::open(&partial.0)?);
        fs::write(partial.0.join("managed-principals.json"), b"[")?;
        assert!(
            initialize_to(&partial.0, "admin", |_, _| {
                called = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!called);
        assert_eq!(fs::read(partial.0.join("managed-principals.json"))?, b"[");
        Ok(())
    }

    #[test]
    fn publication_failure_keeps_captured_credential_and_partial_registry() -> Result<(), Error> {
        let root = TestRoot::new()?;
        let mut captured = None;
        let result = initialize_to(&root.0, "admin", |_, secret| {
            captured = Some(secret.to_owned());
            // Simulate interrupted publication after the credential was captured.
            fs::write(root.0.join("managed-principals.json"), b"[")?;
            Ok(())
        });
        assert!(result.is_err());
        assert!(captured.is_some_and(|secret| secret.len() == 64));
        assert!(Store::open(&root.0).is_err());
        assert_eq!(fs::read(root.0.join("managed-principals.json"))?, b"[");
        Ok(())
    }

    #[test]
    fn existing_registry_is_never_reset() -> Result<(), Error> {
        let root = TestRoot::new()?;
        let _ = initialize(&root.0, "admin")?;
        let registry = root.0.join("managed-principals.json");
        let before = fs::read(&registry)?;
        assert!(initialize(&root.0, "other-admin").is_err());
        assert_eq!(fs::read(&registry)?, before);
        fs::write(&registry, b"[")?;
        assert!(initialize(&root.0, "admin").is_err());
        assert!(Store::open(&root.0).is_err());
        assert_eq!(fs::read(registry)?, b"[");
        Ok(())
    }

    #[test]
    fn interrupted_empty_registry_is_not_an_unconfigured_store() -> Result<(), Error> {
        let root = TestRoot::new()?;
        drop(Store::open(&root.0)?);
        let registry = root.0.join("managed-principals.json");
        fs::File::create(&registry)?.sync_all()?;
        assert!(initialize(&root.0, "admin").is_err());
        assert!(Store::open(&root.0).is_err());
        assert!(fs::read(registry)?.is_empty());
        Ok(())
    }

    #[test]
    fn running_store_prevents_enrollment() -> Result<(), Error> {
        let root = TestRoot::new()?;
        let running = Store::open(&root.0)?;
        assert!(initialize(&root.0, "admin").is_err());
        assert!(!root.0.join("managed-principals.json").try_exists()?);
        drop(running);
        assert!(initialize(&root.0, "admin").is_ok());
        Ok(())
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = EnrollmentSecret("never-display-this".into());
        assert_eq!(format!("{secret:?}"), "EnrollmentSecret([redacted])");
    }

    #[test]
    fn existing_documents_prevent_first_enrollment() -> Result<(), Error> {
        let root = TestRoot::new()?;
        let mut existing = Store::open(&root.0)?;
        existing.managed.create(&Principal { id: "existing-admin".into(), role: Role::Administrator }, "Parts/example.solidcraft".into())?;
        drop(existing);
        assert!(initialize(&root.0, "admin").is_err());
        assert!(!root.0.join("managed-principals.json").try_exists()?);
        assert_eq!(Store::open(&root.0)?.managed.catalog().entries.len(), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn linked_store_is_rejected() -> Result<(), Error> {
        let root = TestRoot::new()?;
        fs::create_dir(&root.0)?;
        let target = root.0.join("target");
        fs::create_dir(&target)?;
        let link = root.0.join("linked");
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(initialize(&link, "admin").is_err());
        assert!(!target.join("managed-principals.json").try_exists()?);
        Ok(())
    }

    #[test]
    fn bad_inputs_do_not_create_store() -> Result<(), Error> {
        let root = TestRoot::new()?;
        for administrator in ["", "owner", "Admin", "has space", "../admin", "line\nbreak"] {
            assert!(initialize(&root.0, administrator).is_err());
        }
        assert!(!root.0.try_exists()?);
        assert!(initialize(&root.0, &"a".repeat(65)).is_err());
        assert!(initialize(Path::new("relative-store"), "admin").is_err());
        Ok(())
    }
}
