//! Explicit remote-mode configuration, exercised only on owned loopback listeners.
use solidcraft_pdm::{
    AuthToken, Store, bootstrap,
    client::Client,
    deployment::{DeploymentConfig, start_explicit_remote, start_loopback_rehearsal},
};
#[cfg(unix)]
use std::time::Instant;
use std::{
    fs,
    io::{BufRead, Read},
    net::{Ipv4Addr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
const CA: &[u8] = include_bytes!("fixtures/pdm-https/ca.der");
const CERT: &[u8] = include_bytes!("fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("fixtures/pdm-https/server-key.der");
struct Fixture {
    root: PathBuf,
    config: PathBuf,
    store: PathBuf,
    id: String,
    bearer: String,
}
impl Fixture {
    fn new(enroll: bool) -> Self {
        let root = std::env::temp_dir().join(format!("pdm-remote-mode-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("server.der"), CERT).unwrap();
        fs::write(root.join("key.der"), KEY).unwrap();
        let store = root.join("archive");
        let mut bearer = String::new();
        let id = if enroll {
            bootstrap::initialize_to(&store, "remote-admin", |_, secret| {
                bearer = secret.into();
                Ok(())
            })
            .unwrap()
            .server_id
        } else {
            String::new()
        };
        let reserve = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let bind = reserve.local_addr().unwrap();
        drop(reserve);
        let configuration =
            DeploymentConfig { store: store.clone(), bind, certificate_chain: vec![root.join("server.der")], private_key: root.join("key.der") };
        let config = root.join("deployment.json");
        fs::write(&config, serde_json::to_vec(&configuration).unwrap()).unwrap();
        Self { root, config, store, id, bearer }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn non_loopback_configuration_requires_explicit_remote_loader_and_start_path() {
    let f = Fixture::new(false);
    let mut config: DeploymentConfig = serde_json::from_slice(&fs::read(&f.config).unwrap()).unwrap();
    // A documentation-only address: validation never binds it or creates a store.
    config.bind = "192.0.2.10:443".parse().unwrap();
    fs::write(&f.config, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(DeploymentConfig::load(&f.config).is_err());
    assert!(DeploymentConfig::load_explicit_remote(&f.config).is_ok());
    assert!(start_loopback_rehearsal(config).is_err());
    assert!(!f.store.exists());
    let mut config = DeploymentConfig::load_explicit_remote(&f.config).unwrap();
    config.bind = "127.0.0.1:0".parse().unwrap();
    fs::write(&f.config, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(DeploymentConfig::load(&f.config).is_ok(), "legacy ephemeral loopback remains supported");
    assert!(DeploymentConfig::load_explicit_remote(&f.config).is_err());
    assert!(start_explicit_remote(config).is_err());
    assert!(!f.store.exists());
}

#[test]
fn explicit_remote_start_requires_existing_enrollment_and_pinned_tls() {
    let f = Fixture::new(false);
    assert!(start_explicit_remote(DeploymentConfig::load_explicit_remote(&f.config).unwrap()).is_err());
    assert!(!f.store.exists());
    let f = Fixture::new(true);
    let server = start_explicit_remote(DeploymentConfig::load_explicit_remote(&f.config).unwrap()).unwrap();
    assert_eq!(server.receipt().server_id, f.id);
    assert!(server.receipt().address.ip().is_loopback());
    let origin = format!("https://{}", server.receipt().address);
    let client = Client::https_with_ca(&origin, AuthToken::parse(f.bearer.clone()).unwrap(), CA).unwrap().bind_server(&f.id).unwrap();
    assert_eq!(client.authenticated_identity().unwrap().principal.id, "remote-admin");
    let unknown = Client::https_with_ca(&origin, AuthToken::parse(AuthToken::generate().unwrap()).unwrap(), CA).unwrap();
    assert!(unknown.authenticated_identity().is_err());
    let untrusted = Client::https(&origin, AuthToken::parse(f.bearer.clone()).unwrap()).unwrap();
    assert!(untrusted.authenticated_identity().is_err());
    server.shutdown().unwrap();
    assert!(Store::open(&f.store).is_ok());
}

#[test]
fn explicit_remote_rejects_bad_tls_and_unknown_config_fields_without_creating_archive() {
    let f = Fixture::new(false);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&f.config).unwrap()).unwrap();
    value["token"] = serde_json::json!("not-a-supported-configuration-field");
    fs::write(&f.config, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(DeploymentConfig::load_explicit_remote(&f.config).is_err());
    assert!(!f.store.exists());
    let f = Fixture::new(true);
    fs::write(f.root.join("key.der"), b"invalid TLS key").unwrap();
    assert!(start_explicit_remote(DeploymentConfig::load_explicit_remote(&f.config).unwrap()).is_err());
    assert!(Store::open(&f.store).is_ok());
}

struct OwnChild(Child);
impl Drop for OwnChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn spawn_remote(f: &Fixture) -> OwnChild {
    let mut child = OwnChild(
        Command::new(env!("CARGO_BIN_EXE_solidcraft-pdm"))
            .arg("serve-https-remote")
            .arg(&f.config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout).take(4097).read_line(&mut line).map(|_| line);
        let _ = send.send(result);
    });
    let line = match receive.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(line)) => line,
        _ => {
            drop(child);
            reader.join().unwrap();
            panic!("owned remote-mode child failed readiness");
        }
    };
    reader.join().unwrap();
    assert!(line.ends_with('\n') && line.len() <= 4096);
    assert!(!line.contains(&f.bearer));
    let receipt: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(receipt["server_id"], f.id);
    child
}

#[test]
fn explicit_remote_cli_stays_alive_when_stdin_is_closed() {
    let f = Fixture::new(true);
    let mut child = spawn_remote(&f);
    std::thread::sleep(Duration::from_millis(150));
    assert!(child.0.try_wait().unwrap().is_none(), "stdin EOF stopped the remote service");
}

#[cfg(unix)]
#[test]
fn explicit_remote_cli_sigterm_and_sigint_shutdown_release_owned_archive() {
    let f = Fixture::new(true);
    for signal in ["-TERM", "-INT"] {
        let mut child = spawn_remote(&f);
        assert!(Command::new("kill").args([signal, &child.0.id().to_string()]).status().unwrap().success());
        let deadline = Instant::now() + Duration::from_secs(8);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "signal did not gracefully stop the owned child");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "remote service exited through default signal termination instead of graceful shutdown");
        assert!(Store::open(&f.store).is_ok());
    }
}
