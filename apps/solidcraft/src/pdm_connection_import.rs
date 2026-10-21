//! Explicit local descriptor import. No window, enrollment, plaintext custody or implicit retarget.
use crate::{
    pdm_connections::{ConnectionDirectory, ConnectionState},
    pdm_credentials::{BearerSecret, CredentialStore},
    pdm_login::{self, LoginTarget, Trust},
    pdm_profiles::ProfileDirectory,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    version: u32,
    label: String,
    origin: String,
    server_id: String,
    expected_principal: String,
    certificate_der_file: PathBuf,
    bearer_file: PathBuf,
    working_folder: PathBuf,
}
#[derive(Debug)]
pub(crate) struct ImportError(&'static str);
impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ImportError {}
fn invalid() -> ImportError {
    ImportError("ui.pdm_error_invalid")
}
fn metadata() -> ImportError {
    ImportError("ui.pdm_error_metadata")
}
fn conflict() -> ImportError {
    ImportError("ui.pdm_error_attach")
}
#[derive(Serialize)]
pub(crate) struct Receipt {
    pub connection_id: String,
    pub workspace: String,
    pub server: String,
    pub account: String,
}

fn guard(path: &Path) -> Result<(), ImportError> {
    if path.to_str().is_none_or(|s| s.len() > 4096) {
        return Err(invalid());
    }
    crate::pdm_connections::guard_workspace_path(path).map_err(|_| invalid())
}
fn permissions(path: &Path, secret: bool) -> Result<(), ImportError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(path).map_err(|_| metadata())?.mode();
        if mode & 0o022 != 0 || (secret && mode & 0o077 != 0) {
            return Err(invalid());
        }
    }
    #[cfg(windows)]
    {
        // Explicit local bootstrap requires an installer/fixture-owned private
        // parent, as ProfileDirectory does. The native standard library does not
        // inspect DACLs; callers verify private Windows parents out of band.
        let _ = (path, secret);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, secret);
        return Err(invalid());
    }
    Ok(())
}
fn read(path: &Path, limit: usize, secret: bool) -> Result<Vec<u8>, ImportError> {
    guard(path)?;
    let info = fs::symlink_metadata(path).map_err(|_| metadata())?;
    if !info.is_file() || info.len() > limit as u64 {
        return Err(invalid());
    }
    permissions(path, secret)?;
    let file = fs::File::open(path).map_err(|_| metadata())?;
    if !file.metadata().map_err(|_| metadata())?.is_file() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| metadata())?;
    if bytes.len() > limit {
        return Err(invalid());
    }
    Ok(bytes)
}
fn descriptor(path: &Path) -> Result<Descriptor, ImportError> {
    let d: Descriptor = serde_json::from_slice(&read(path, 32 * 1024, false)?).map_err(|_| invalid())?;
    if d.version != 1
        || d.label.trim().is_empty()
        || d.label.len() > 128
        || d.label.chars().any(char::is_control)
        || d.origin.len() > 2048
        || d.server_id.len() != 64
        || !d.server_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || d.expected_principal.is_empty()
        || d.expected_principal.len() > 128
        || d.expected_principal.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    guard(&d.certificate_der_file)?;
    guard(&d.bearer_file)?;
    guard(&d.working_folder)?;
    Ok(d)
}
fn path_key(path: &Path) -> Result<String, ImportError> {
    Ok(solidcraft_engine::pdm::cached_path_key(fs::canonicalize(path).map_err(|_| metadata())?.to_str().ok_or_else(invalid)?))
}
fn overlap(a: &Path, b: &Path) -> Result<bool, ImportError> {
    let key = |p: &Path| fs::canonicalize(p).ok().unwrap_or_else(|| p.to_path_buf());
    let a = key(a);
    let b = key(b);
    let a = solidcraft_engine::pdm::cached_path_key(a.to_str().ok_or_else(invalid)?);
    let b = solidcraft_engine::pdm::cached_path_key(b.to_str().ok_or_else(invalid)?);
    Ok(a == b || a.starts_with(&(b.clone() + "/")) || b.starts_with(&(a + "/")))
}
pub(crate) fn import_file(path: &Path, settings: &Path, credentials: &impl CredentialStore, protected: &[PathBuf]) -> Result<Receipt, ImportError> {
    let d = descriptor(path)?;
    guard(settings)?;
    for ancestor in settings.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                permissions(ancestor, false)?;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(metadata()),
        }
    }
    let folder = fs::canonicalize(&d.working_folder).map_err(|_| ImportError("ui.pdm_error_working_folder_missing"))?;
    if !fs::symlink_metadata(&folder).map_err(|_| metadata())?.is_dir() {
        return Err(ImportError("ui.pdm_error_working_folder_unavailable"));
    }
    permissions(&folder, false)?;
    for boundary in std::iter::once(settings).chain(protected.iter().map(PathBuf::as_path)) {
        guard(boundary)?;
        if overlap(&folder, boundary)? {
            return Err(invalid());
        }
    }
    for input in [&d.bearer_file, &d.certificate_der_file] {
        if let Some(parent) = input.parent()
            && overlap(&folder, parent)?
        {
            return Err(invalid());
        }
    }
    let trust = Trust::certificate_der(&read(&d.certificate_der_file, 64 * 1024, false)?).map_err(|_| invalid())?;
    let raw = read(&d.bearer_file, 128, true)?;
    let secret = BearerSecret::parse(std::str::from_utf8(&raw).map_err(|_| invalid())?.trim().into()).map_err(|_| invalid())?;
    let target = LoginTarget::direct(&d.origin, &d.server_id, trust).map_err(|_| invalid())?;
    let session = pdm_login::authenticate_expected(target, &secret, &d.expected_principal).map_err(login_error)?;
    let directory = ConnectionDirectory::new(settings.join("pdm-connections")).map_err(|_| metadata())?;
    let profile_id = ProfileDirectory::profile_id(&session.profile).map_err(|_| metadata())?;
    let rows = directory.list().map_err(|_| metadata())?;
    for row in rows {
        if matches!(&row.state,ConnectionState::SavedProfileUnverified{profile_id:existing} if *existing==profile_id) {
            let preference = directory.workspace_preference(&row.connection_id).map_err(|_| metadata())?.ok_or_else(conflict)?;
            if row.label != d.label || path_key(Path::new(&preference.path))? != path_key(&folder)? || preference.server != session.identity.server_id
            {
                return Err(conflict());
            }
            read(&folder.join(".solidcraft-pdm").join("lock"), 0, false)?;
            let workspace = solidcraft_pdm::managed_workspace::Workspace::open(&folder, &session.identity.server_id).map_err(|_| conflict())?;
            if workspace.manifest().workspace_id != preference.workspace {
                return Err(conflict());
            }
            pdm_login::capture_new(&session, &secret, credentials).map_err(login_error)?;
            return Ok(Receipt {
                connection_id: row.connection_id,
                workspace: preference.workspace,
                server: session.identity.server_id,
                account: session.identity.principal.id,
            });
        }
    }
    if fs::read_dir(&folder).map_err(|_| metadata())?.next().transpose().map_err(|_| metadata())?.is_some() {
        return Err(conflict());
    }
    // No keyring capture precedes verified identity and destination validation.
    pdm_login::capture_new(&session, &secret, credentials).map_err(login_error)?;
    directory.prepare_import_parent().map_err(|_| metadata())?;
    let profiles = ProfileDirectory::new(directory.imported_profiles_path()).map_err(|_| metadata())?;
    let profile_id = profiles.install_new(session.profile).map_err(|_| metadata())?;
    guard(&folder)?;
    if fs::read_dir(&folder).map_err(|_| metadata())?.next().transpose().map_err(|_| metadata())?.is_some() {
        return Err(conflict());
    }
    let workspace = solidcraft_pdm::managed_workspace::Workspace::create(&folder, &session.identity.server_id).map_err(|_| conflict())?;
    let workspace_id = workspace.manifest().workspace_id.clone();
    drop(workspace);
    let connection_id =
        directory.record_saved_profile_at(&d.label, &profile_id, &folder, &workspace_id, &session.identity.server_id).map_err(|_| metadata())?;
    Ok(Receipt { connection_id, workspace: workspace_id, server: session.identity.server_id, account: session.identity.principal.id })
}
fn login_error(error: pdm_login::LoginError) -> ImportError {
    use pdm_login::LoginError;
    ImportError(match error {
        LoginError::AuthenticationFailed => "ui.pdm_error_authentication",
        LoginError::ConnectionUnavailable => "ui.pdm_error_connection_unavailable",
        LoginError::IdentityMismatch => "ui.pdm_error_identity_mismatch",
        LoginError::CredentialMissing => "ui.pdm_error_credential_missing",
        LoginError::CredentialUnavailable => "ui.pdm_error_credential_unavailable",
        LoginError::InvalidProfile => "ui.pdm_error_invalid",
        _ => "ui.pdm_error_attach",
    })
}
