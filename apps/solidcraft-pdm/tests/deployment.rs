//! Disposable packaging rehearsal; no real secrets, keyring or public listener.
use solidcraft_pdm::{
    AuthToken, Store, bootstrap,
    client::Client,
    deployment::{DeploymentConfig, start_loopback_rehearsal},
    managed::ManagedCheckIn,
};
use std::{fs, path::PathBuf};
use std::{
    io::{BufRead, Read, Write},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const CA: &[u8] = include_bytes!("fixtures/pdm-https/ca.der");
const CERT: &[u8] = include_bytes!("fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("fixtures/pdm-https/server-key.der");
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("pdm-deployment-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn config(root: &Temp) -> DeploymentConfig {
    fs::write(root.0.join("server.der"), CERT).unwrap();
    fs::write(root.0.join("key.der"), KEY).unwrap();
    DeploymentConfig {
        store: root.0.join("store"),
        bind: "127.0.0.1:0".parse().unwrap(),
        certificate_chain: vec![root.0.join("server.der")],
        private_key: root.0.join("key.der"),
    }
}
fn enroll(config: &DeploymentConfig) -> (String, String) {
    let mut bearer = String::new();
    let receipt = bootstrap::initialize_to(&config.store, "admin", |_, secret| {
        bearer = secret.into();
        Ok(())
    })
    .unwrap();
    (receipt.server_id, bearer)
}

#[test]
fn explicit_redb_restore_uses_a_new_destination_and_preserves_identity() {
    let root = Temp::new();
    let config = config(&root);
    let (id, bearer) = enroll(&config);
    let backup = root.0.join("backup");
    Store::open(&config.store).unwrap().backup(&backup).unwrap();
    let destination = root.0.join("database-store");
    let output = Command::new(env!("CARGO_BIN_EXE_solidcraft-pdm")).args(["restore-redb"]).arg(&backup).arg(&destination).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(destination.join("managed/metadata.redb").is_file());
    assert!(!config.store.join("managed/metadata.redb").exists());
    let mut migrated_config = config;
    migrated_config.store = destination.clone();
    let server = start_loopback_rehearsal(migrated_config).unwrap();
    let client = Client::https_with_ca(&format!("https://127.0.0.1:{}", server.receipt().address.port()), AuthToken::parse(bearer).unwrap(), CA)
        .unwrap()
        .bind_server(&id)
        .unwrap();
    assert_eq!(client.managed_catalog().unwrap().server_id, id);
    server.shutdown().unwrap();
    let retry = Command::new(env!("CARGO_BIN_EXE_solidcraft-pdm")).arg("restore-redb").arg(&backup).arg(&destination).output().unwrap();
    assert!(!retry.status.success());
    assert!(solidcraft_pdm::backup_restore::verify_backup(&backup).is_ok());
}

#[test]
fn failed_redb_conversion_keeps_the_entire_restore_fenced() {
    let root = Temp::new();
    let config = config(&root);
    enroll(&config);
    let registry = config.store.join("managed-principals.json");
    let mut accounts: Vec<solidcraft_pdm::managed::PrincipalCredential> = serde_json::from_slice(&fs::read(&registry).unwrap()).unwrap();
    // Legacy validation accepts differently cased hashes; the new adapter
    // rejects this ambiguous normalized duplicate before database publication.
    let mut duplicate = accounts.first().unwrap().clone();
    duplicate.principal.id = "other-admin".into();
    duplicate.token_sha256 = duplicate.token_sha256.to_ascii_uppercase();
    accounts.push(duplicate);
    fs::write(registry, serde_json::to_vec(&accounts).unwrap()).unwrap();
    let backup = root.0.join("backup");
    Store::open(&config.store).unwrap().backup(&backup).unwrap();
    let destination = root.0.join("failed-import");
    assert!(solidcraft_pdm::backup_restore::restore_backup_to_redb(&backup, &destination).is_err());
    assert!(destination.join("restore.pending").is_file());
    assert!(!destination.join("managed/metadata.redb").exists());
    assert!(Store::open(&destination).is_err());
    assert!(Store::open(&config.store).is_ok());
    assert!(solidcraft_pdm::backup_restore::verify_backup(&backup).is_ok());
}

#[test]
fn redb_https_preserves_checkout_receipts_roles_audit_and_logical_backup() {
    let root = Temp::new();
    let config = config(&root);
    let (id, bearer) = enroll(&config);
    let viewer_token = AuthToken::generate().unwrap();
    let registry_path = config.store.join("managed-principals.json");
    let mut registry: Vec<solidcraft_pdm::managed::PrincipalCredential> = serde_json::from_slice(&fs::read(&registry_path).unwrap()).unwrap();
    use sha2::{Digest, Sha256};
    registry.push(solidcraft_pdm::managed::PrincipalCredential {
        principal: solidcraft_pdm::managed::Principal { id: "reader".into(), role: solidcraft_pdm::managed::Role::Viewer },
        token_sha256: format!("{:x}", Sha256::digest(viewer_token.as_bytes())),
    });
    fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
    let backup = root.0.join("seed-backup");
    Store::open(&config.store).unwrap().backup(&backup).unwrap();
    let destination = root.0.join("database-store");
    let output = Command::new(env!("CARGO_BIN_EXE_solidcraft-pdm")).arg("restore-redb").arg(&backup).arg(&destination).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let mut db_config = config;
    db_config.store = destination.clone();
    let server = start_loopback_rehearsal(DeploymentConfig {
        store: destination.clone(),
        bind: db_config.bind,
        certificate_chain: db_config.certificate_chain.clone(),
        private_key: db_config.private_key.clone(),
    })
    .unwrap();
    let connect = |port, token: &str| {
        Client::https_with_ca(&format!("https://127.0.0.1:{port}"), AuthToken::parse(token.into()).unwrap(), CA).unwrap().bind_server(&id).unwrap()
    };
    let client = connect(server.receipt().address.port(), &bearer);
    let viewer = connect(server.receipt().address.port(), &viewer_token);
    assert!(viewer.managed_create("denied.solidcraft".into()).is_err());
    assert!(viewer.managed_catalog().unwrap().entries.is_empty());
    let part = client.managed_create("parts/toy.solidcraft".into()).unwrap();
    let grant = client.managed_checkout(part.document.clone(), "ws".into(), "machine".into()).unwrap();
    server.shutdown().unwrap();
    // The database, not a later edited JSON registry, is authoritative after import.
    registry.last_mut().unwrap().principal.role = solidcraft_pdm::managed::Role::Administrator;
    fs::write(destination.join("managed-principals.json"), serde_json::to_vec(&registry).unwrap()).unwrap();
    let server = start_loopback_rehearsal(DeploymentConfig {
        store: destination.clone(),
        bind: db_config.bind,
        certificate_chain: db_config.certificate_chain.clone(),
        private_key: db_config.private_key.clone(),
    })
    .unwrap();
    let client = connect(server.receipt().address.port(), &bearer);
    let viewer = connect(server.receipt().address.port(), &viewer_token);
    assert!(viewer.managed_create("still-denied.solidcraft".into()).is_err());
    let resumed = client.managed_resume_checkout(part.document.clone(), "ws".into(), "machine".into()).unwrap();
    assert_eq!(resumed.token, grant.token);
    let input = ManagedCheckIn {
        document: part.document.clone(),
        workspace: "ws".into(),
        machine: "machine".into(),
        checkout_token: grant.token,
        request_id: "database-first".into(),
        parent: None,
        content: b"version one".to_vec(),
        dependencies: vec![],
        comment: "database test".into(),
    };
    let version = client.managed_check_in(input.clone()).unwrap();
    assert_eq!(client.managed_check_in(input.clone()).unwrap(), version);
    server.shutdown().unwrap();
    let db_backup = root.0.join("db-backup");
    Store::open(&destination).unwrap().backup(&db_backup).unwrap();
    let image_path = db_backup.join("data/managed/metadata-snapshot.json");
    let image: serde_json::Value = serde_json::from_slice(&fs::read(&image_path).unwrap()).unwrap();
    assert_eq!(image["audit"].as_array().unwrap().len(), 4);
    assert_eq!(image["audit"][3]["operation"], "check_in");
    assert_eq!(image["audit"][3]["actor"], "admin");
    assert!(!serde_json::to_string(&image["audit"]).unwrap().contains(&bearer));
    let restored = root.0.join("restored");
    solidcraft_pdm::backup_restore::restore_backup(&db_backup, &restored).unwrap();
    assert!(restored.join("managed/metadata.redb").exists());
    db_config.store = restored;
    let server = start_loopback_rehearsal(db_config).unwrap();
    let client = connect(server.receipt().address.port(), &bearer);
    assert_eq!(client.managed_check_in(input).unwrap(), version);
    assert_eq!(client.download(&version.version.reference).unwrap().1, b"version one");
    assert_eq!(client.managed_history(part.document).unwrap().len(), 1);
    server.shutdown().unwrap();
}
#[test]
fn enrolled_service_rehearsal_publishes_and_reopens_the_same_identity_and_content() {
    let root = Temp::new();
    let config = config(&root);
    let (id, bearer) = enroll(&config);
    let path = root.0.join("deployment.json");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let server = start_loopback_rehearsal(DeploymentConfig::load(&path).unwrap()).unwrap();
    assert_eq!(server.receipt().server_id, id);
    let receipt = serde_json::to_string(server.receipt()).unwrap();
    assert!(!receipt.contains(&bearer));
    assert!(Store::open(&config.store).is_err());
    let client =
        Client::https_with_ca(&format!("https://127.0.0.1:{}", server.receipt().address.port()), AuthToken::parse(bearer.clone()).unwrap(), CA)
            .unwrap()
            .bind_server(&id)
            .unwrap();
    let entry = client.managed_create("parts/toy.solidcraft".into()).unwrap();
    let grant = client.managed_checkout(entry.document.clone(), "test-workspace".into(), "test-machine".into()).unwrap();
    let version = client
        .managed_check_in(ManagedCheckIn {
            document: entry.document.clone(),
            workspace: "test-workspace".into(),
            machine: "test-machine".into(),
            checkout_token: grant.token,
            request_id: "deployment-initial".into(),
            parent: None,
            content: b"original toy bytes".to_vec(),
            dependencies: vec![],
            comment: "Packaging rehearsal".into(),
        })
        .unwrap();
    server.shutdown().unwrap();
    let server = start_loopback_rehearsal(config).unwrap();
    assert_eq!(server.receipt().server_id, id);
    let client = Client::https_with_ca(&format!("https://127.0.0.1:{}", server.receipt().address.port()), AuthToken::parse(bearer).unwrap(), CA)
        .unwrap()
        .bind_server(&id)
        .unwrap();
    let (_, bytes) = client.download(&version.version.reference).unwrap();
    assert_eq!(bytes, b"original toy bytes");
    assert!(client.managed_catalog().unwrap().entries.iter().all(|entry| entry.checkout.is_none()));
    server.shutdown().unwrap();
}
#[test]
fn invalid_configuration_never_creates_a_store_or_accepts_embedded_secrets() {
    let root = Temp::new();
    let mut config = config(&root);
    config.bind = "0.0.0.0:443".parse().unwrap();
    assert!(start_loopback_rehearsal(config).is_err());
    assert!(!root.0.join("store").exists());
    let path = root.0.join("config.json");
    let config = config_for_invalid(&root);
    let mut value = serde_json::to_value(&config).unwrap();
    value.as_object_mut().unwrap().insert("token".into(), serde_json::json!("not-allowed"));
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(DeploymentConfig::load(&path).is_err());
    fs::write(&path, vec![b' '; 64 * 1024 + 1]).unwrap();
    assert!(DeploymentConfig::load(&path).is_err());
    assert!(DeploymentConfig::load(&root.0.join("missing.json")).is_err());
    assert!(start_loopback_rehearsal(config_for_invalid(&root)).is_err());
    assert!(!root.0.join("store").exists());
}
fn config_for_invalid(root: &Temp) -> DeploymentConfig {
    config(root)
}
#[test]
fn unconfigured_store_bad_tls_parent_paths_and_occupied_ports_fail_closed() {
    let root = Temp::new();
    let mut config = config(&root);
    fs::create_dir(&config.store).unwrap();
    assert!(start_loopback_rehearsal(config_for_invalid(&root)).is_err());
    assert!(!config.store.join("writer.lock").exists());
    config.private_key = root.0.join("missing/../key.der");
    assert!(start_loopback_rehearsal(config).is_err());
    let config = config_for_invalid(&root);
    let _ = enroll(&config);
    fs::write(&config.private_key, b"invalid PKCS8").unwrap();
    assert!(start_loopback_rehearsal(config).is_err());
    assert!(Store::open(&root.0.join("store")).is_ok());
    let mut config = config_for_invalid(&root);
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config.bind = occupied.local_addr().unwrap();
    assert!(start_loopback_rehearsal(config).is_err());
    assert!(Store::open(&root.0.join("store")).is_ok());
}
#[cfg(unix)]
#[test]
fn symlink_certificate_is_rejected() {
    let root = Temp::new();
    let mut config = config(&root);
    let _ = enroll(&config);
    let link = root.0.join("linked.der");
    std::os::unix::fs::symlink(&config.certificate_chain[0], &link).unwrap();
    config.certificate_chain = vec![link];
    assert!(start_loopback_rehearsal(config).is_err());
}
#[cfg(windows)]
#[test]
fn reparse_certificate_parent_is_rejected() {
    use std::os::windows::fs::symlink_dir;
    let root = Temp::new();
    let mut config = config(&root);
    let _ = enroll(&config);
    let link = root.0.join("linked");
    // Creating symlinks needs Developer Mode or privilege on Windows. A junction
    // test belongs in the native installer gate when this host cannot create one.
    if symlink_dir(&root.0, &link).is_err() {
        return;
    }
    config.certificate_chain = vec![link.join("server.der")];
    assert!(start_loopback_rehearsal(config).is_err());
    fs::remove_dir(link).unwrap();
}

struct OwnChild(Child);
impl OwnChild {
    fn wait_bounded(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "owned rehearsal child did not stop before its deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn spawn_rehearsal(path: &std::path::Path) -> OwnChild {
    OwnChild(
        Command::new(env!("CARGO_BIN_EXE_solidcraft-pdm"))
            .arg("rehearse-https")
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
#[test]
fn real_cli_reports_readiness_serves_https_and_releases_its_store_on_shutdown() {
    let root = Temp::new();
    let config = config(&root);
    let (server_id, bearer) = enroll(&config);
    let path = root.0.join("deployment.json");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut child = spawn_rehearsal(&path);
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout).take(1025).read_line(&mut line).map(|_| line);
        let _ = send.send(result);
    });
    let line = match receive.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(line)) => line,
        _ => {
            drop(child);
            reader.join().unwrap();
            panic!("owned rehearsal child failed readiness");
        }
    };
    reader.join().unwrap();
    assert!(line.len() <= 1024 && line.ends_with('\n'));
    assert!(!line.contains(&bearer));
    let receipt: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(receipt.get("server_id").and_then(|v| v.as_str()), Some(server_id.as_str()));
    let address: std::net::SocketAddr = receipt.get("address").and_then(|v| v.as_str()).unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    let client = Client::https_with_ca(&format!("https://127.0.0.1:{}", address.port()), AuthToken::parse(bearer).unwrap(), CA)
        .unwrap()
        .bind_server(&server_id)
        .unwrap();
    assert_eq!(client.managed_catalog().unwrap().server_id, server_id);
    let entry = client.managed_create("cli/toy.solidcraft".into()).unwrap();
    assert_eq!(entry.logical_path, "cli/toy.solidcraft");
    let grant = client.managed_checkout(entry.document.clone(), "cli-workspace".into(), "cli-machine".into()).unwrap();
    let version = client
        .managed_check_in(ManagedCheckIn {
            document: entry.document,
            workspace: "cli-workspace".into(),
            machine: "cli-machine".into(),
            checkout_token: grant.token,
            request_id: "cli-publish".into(),
            parent: None,
            content: b"disposable CLI toy".to_vec(),
            dependencies: vec![],
            comment: "CLI service rehearsal".into(),
        })
        .unwrap();
    assert_eq!(client.download(&version.version.reference).unwrap().1, b"disposable CLI toy");
    child.0.stdin.as_mut().unwrap().write_all(b"shutdown\n").unwrap();
    child.0.stdin.as_mut().unwrap().flush().unwrap();
    assert!(child.wait_bounded().success());
    assert!(Store::open(&config.store).is_ok());
}
#[test]
fn real_cli_rejects_public_address_without_creating_a_store() {
    let root = Temp::new();
    let mut config = config(&root);
    config.bind = "0.0.0.0:443".parse().unwrap();
    let path = root.0.join("deployment.json");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut child = spawn_rehearsal(&path);
    drop(child.0.stdin.take());
    assert!(!child.wait_bounded().success());
    assert!(!config.store.exists());
}
