use super::*;
use solidcraft_pdm::{
    managed::{Principal, Role},
    stream_io::StreamPolicy,
    transfer_source::SourceInfo,
};

fn capabilities() -> TransferCapabilities {
    TransferCapabilities {
        protocol: solidcraft_pdm::transfers::PROTOCOL.into(),
        server_id: "a".repeat(64),
        recovery_epoch: 7,
        principal: Principal { id: "contributor".into(), role: Role::Contributor },
        binary_transfer_v1: true,
        can_upload: true,
        limits: Some(StreamPolicy { version: 1, max_file_bytes: 8 * 1024 * 1024, max_store_bytes: 64 * 1024 * 1024 }),
        chunk_bytes: solidcraft_pdm::transfers::CHUNK_BYTES,
    }
}

struct SourceFixture(PathBuf);
impl SourceFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("solidcraft-native-transfer-{}", AuthToken::generate().unwrap()));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for SourceFixture {
    fn drop(&mut self) {
        fn writable_files(root: &Path) {
            if let Ok(entries) = fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(metadata) = fs::symlink_metadata(&path) {
                        if metadata.is_dir() && !metadata.file_type().is_symlink() {
                            writable_files(&path);
                        } else if metadata.is_file() && metadata.permissions().readonly() {
                            let mut permissions = metadata.permissions();
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                permissions.set_mode(permissions.mode() | 0o200);
                            }
                            #[cfg(not(unix))]
                            permissions.set_readonly(false);
                            let _ = fs::set_permissions(&path, permissions);
                        }
                    }
                }
            }
        }
        writable_files(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_copy_store(source: &Path, destination: &Path, depth: usize) {
    assert!(depth < 32, "private fixture store is too deep");
    crate::pdm_connections::guard_workspace_path(source).expect("unsafe fixture store path");
    fs::create_dir(destination).expect("could not create owned store directory");
    for (index, entry) in fs::read_dir(source).expect("fixture store unavailable").enumerate() {
        assert!(index < 16_384, "private fixture store has too many entries");
        let entry = entry.expect("fixture store entry unavailable");
        let source = entry.path();
        crate::pdm_connections::guard_workspace_path(&source).expect("unsafe fixture store entry");
        let metadata = fs::symlink_metadata(&source).expect("fixture store metadata unavailable");
        let destination = destination.join(entry.file_name());
        if metadata.is_dir() {
            fixture_copy_store(&source, &destination, depth + 1);
        } else {
            assert!(metadata.is_file(), "fixture store contains an irregular file");
            fs::copy(source, destination).expect("could not copy owned fixture store file");
        }
    }
}

struct FixtureProcess(std::process::Child);
impl Drop for FixtureProcess {
    fn drop(&mut self) {
        if let Some(mut input) = self.0.stdin.take() {
            let _ = input.write_all(b"shutdown\n");
        }
        for _ in 0..300 {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Only this test's owned child is eligible for forced shutdown.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureReady {
    server_id: String,
    address: std::net::SocketAddr,
}

fn frozen_fixture_server(fixture: &Path, owned: &Path) -> (FixtureProcess, FixtureReady) {
    use sha2::Digest;
    use std::io::{BufRead, Read};
    let binary = std::env::var_os("PDM_STREAM_SERVER_BIN").expect("PDM_STREAM_SERVER_BIN must identify the frozen private server");
    let mut executable = fs::File::open(&binary).expect("frozen server binary unavailable");
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = executable.read(&mut buffer).expect("could not verify frozen server binary");
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    assert_eq!(
        format!("{:X}", digest.finalize()),
        "F08A695F74A29A760F229B095CCA1CDE4E2B50DEEACEAFE80E12EFE20817537B",
        "server fixture binary changed"
    );
    let mut config =
        solidcraft_pdm::deployment::DeploymentConfig::load(&fixture.join("deployment.json")).expect("private deployment configuration unavailable");
    let store = owned.join("store");
    fixture_copy_store(&config.store, &store, 0);
    config.store = store;
    config.bind = "127.0.0.1:0".parse().unwrap();
    let configuration = owned.join("deployment.json");
    fs::write(&configuration, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut command = std::process::Command::new(binary);
    command
        .arg("rehearse-https")
        .arg(configuration)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut process = FixtureProcess(command.spawn().expect("could not start the owned frozen server"));
    let output = process.0.stdout.take().expect("owned server stdout unavailable");
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = Vec::new();
        let result = std::io::BufReader::new(output).take(4097).read_until(b'\n', &mut line).map(|_| line);
        let _ = send.send(result);
    });
    let line = receive
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("owned server did not become ready")
        .expect("owned server readiness unavailable");
    assert!(line.len() <= 4096 && line.last() == Some(&b'\n'), "invalid bounded server readiness");
    let ready: FixtureReady = serde_json::from_slice(&line).expect("invalid private readiness receipt");
    assert!(ready.address.ip().is_loopback() && ready.address.port() != 0);
    let descriptor: serde_json::Value = serde_json::from_slice(&fs::read(fixture.join("paired-descriptor.json")).unwrap()).unwrap();
    assert_eq!(descriptor["server_id"].as_str(), Some(ready.server_id.as_str()));
    (process, ready)
}

fn native_fixture_action(host: &mut Host, task: ManagedTask) -> ManagedState {
    fn never_launch(_: &Path) -> Result<(), String> {
        Err("This test must not launch an associated application".into())
    }
    let (outcome, opened) = host
        .execute_single_with_opener(task, None, never_launch)
        .unwrap_or_else(|failure| panic!("native stream fixture action failed: {}", failure.message));
    assert!(opened.is_none(), "opaque actions must not create a CAD editor");
    let Outcome::Managed { state, .. } = outcome else { panic!("expected managed fixture state") };
    state
}

#[test]
#[ignore = "requires PDM_STREAM_FIXTURE_DIR and PDM_STREAM_SERVER_BIN for the frozen private 11865ae8 fixture; copies its store and never opens user applications"]
fn native_stream_frozen_private_fixture_full_workflow() {
    use std::io::Read;
    let fixture =
        PathBuf::from(std::env::var_os("PDM_STREAM_FIXTURE_DIR").expect("PDM_STREAM_FIXTURE_DIR is required, never silently skip this test"));
    let owned = SourceFixture::new();
    let (_server, ready) = frozen_fixture_server(&fixture, &owned.0);
    let mut raw = String::new();
    fs::File::open(fixture.join("paired-author.bearer"))
        .expect("private author credential unavailable")
        .take(129)
        .read_to_string(&mut raw)
        .expect("private author credential unreadable");
    assert!(raw.len() <= 128, "private author credential exceeds its bound");
    let token = AuthToken::parse(raw.trim().into()).expect("private author credential invalid");
    let ca = fs::read(fixture.join("tls/certificate.der")).expect("private fixture certificate unavailable");
    let client = Client::https_with_ca(&format!("https://{}", ready.address), token, &ca)
        .expect("could not create private TLS client")
        .bind_server(&ready.server_id)
        .expect("could not pin private fixture server");
    assert_eq!(client.authenticated_identity().unwrap().principal.id, "paired-author");
    let caps = client.transfer_capabilities().unwrap().expect("frozen fixture must advertise binary transfers");
    assert!(caps.binary_transfer_v1 && caps.can_upload);
    let mut host = Host::prepare_connection(client.clone(), &owned.0.join("author"), ready.address.port(), Some("paired-author"))
        .unwrap_or_else(|_| panic!("could not prepare owned author workspace"))
        .host;
    let source = owned.0.join("large.ipt");
    let initial = vec![0x51; 2 * 1024 * 1024 + 97];
    fs::write(&source, &initial).unwrap();
    let workspace = host.workspace().unwrap().manifest().workspace_id.clone();
    let import = || ManagedTask::ImportNew {
        source_path: source.to_string_lossy().into_owned(),
        folder: "NativeStreamProof".into(),
        expected_workspace: workspace.clone(),
    };
    native_fixture_action(&mut host, import());
    let entry = client
        .managed_catalog()
        .unwrap()
        .entries
        .into_iter()
        .find(|entry| entry.logical_path == "NativeStreamProof/large.ipt")
        .expect("imported fixture attachment missing");
    let document = entry.document;
    assert_eq!(entry.head, Some(1));
    assert!(entry.checkout.is_none());
    native_fixture_action(&mut host, import());
    assert_eq!(client.managed_history(document.clone()).unwrap().len(), 1, "exact import retry must not create a version");
    let physical = host.workspace().unwrap().path(&document).unwrap();
    assert_eq!(hash(&fs::read(&physical).unwrap()), hash(&initial));
    assert!(fs::metadata(&physical).unwrap().permissions().readonly());
    assert_eq!(fs::read(&source).unwrap(), initial, "import source remains unchanged");

    let mut consumer = Host::prepare_connection(client.clone(), &owned.0.join("consumer"), ready.address.port(), Some("paired-author"))
        .unwrap_or_else(|_| panic!("could not prepare owned consumer workspace"))
        .host;
    native_fixture_action(&mut consumer, ManagedTask::GetLatest { document: Some(document.clone()), path: None });
    assert_eq!(consumer.workspace().unwrap().local_sha256(&document).unwrap(), hash(&initial));
    native_fixture_action(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
    let changed = vec![0x52; initial.len() + 19];
    fs::write(&physical, &changed).unwrap();
    let archive = || {
        let placeholder = Session::default();
        ManagedTask::Archive {
            path: physical.to_string_lossy().into_owned(),
            logical_path: None,
            saved: placeholder.doc,
            visibility: Box::new(placeholder.visibility),
        }
    };
    native_fixture_action(&mut host, archive());
    let history = client.managed_history(document.clone()).unwrap();
    assert_eq!(history.len(), 2);
    assert!(history.iter().any(|version| version.version.reference.version == 2 && version.version.sha256 == hash(&changed)));
    assert!(history.iter().all(|version| version.version.dependencies.is_empty()));
    let placeholder = Session::default();
    native_fixture_action(
        &mut host,
        ManagedTask::ReconcileArchive {
            path: physical.to_string_lossy().into_owned(),
            logical_path: None,
            saved: placeholder.doc,
            visibility: Box::new(placeholder.visibility),
        },
    );
    assert_eq!(client.managed_history(document.clone()).unwrap().len(), 2, "completed receipt reconciliation must not publish");
    native_fixture_action(&mut host, ManagedTask::Checkout { document: Some(document.clone()), path: None });
    let dirty = vec![0x53; changed.len() + 23];
    fs::write(&physical, &dirty).unwrap();
    let generation = host.workspace().unwrap().manifest().generation;
    native_fixture_action(&mut host, ManagedTask::CancelCheckout { document: Some(document.clone()), path: None });
    assert_eq!(host.workspace().unwrap().local_sha256(&document).unwrap(), hash(&changed));
    assert_eq!(hash(&fs::read(host.root.as_ref().unwrap().join(format!(".solidcraft-pdm/backup-{generation}"))).unwrap()), hash(&dirty));
    assert!(fs::metadata(&physical).unwrap().permissions().readonly());
    assert_eq!(client.managed_history(document.clone()).unwrap().len(), 2);

    let metadata = client.managed_metadata(document.clone()).unwrap();
    let rename = || ManagedTask::Rename {
        document: document.clone(),
        logical_path: "Renamed/large-current.ipt".into(),
        expected_head: metadata.entry.head,
        expected_revision: metadata.revision,
        expected_epoch: 0,
    };
    native_fixture_action(&mut host, rename());
    native_fixture_action(&mut host, rename());
    let renamed = client.managed_metadata(document.clone()).unwrap();
    assert_eq!(renamed.entry.document, document);
    assert_eq!(renamed.entry.logical_path, "Renamed/large-current.ipt");
    assert_eq!(renamed.materialization_path, metadata.materialization_path);
    assert_eq!(renamed.revision, metadata.revision + 1, "exact namespace retry increments once");
    assert_eq!(host.workspace().unwrap().path(&document).unwrap(), physical);
    assert_eq!(hash(&fs::read(&physical).unwrap()), hash(&changed));
    let deletion = || ManagedTask::Delete {
        document: document.clone(),
        expected_head: renamed.entry.head,
        expected_revision: renamed.revision,
        expected_epoch: 0,
    };
    let deleted = native_fixture_action(&mut host, deletion());
    assert!(!deleted.catalog.iter().any(|entry| entry.document == document));
    native_fixture_action(&mut host, deletion());
    assert!(client.managed_metadata(document.clone()).unwrap().tombstoned);
    assert_eq!(hash(&fs::read(&physical).unwrap()), hash(&changed), "namespace deletion preserves local bytes");
    assert_eq!(fs::read(&source).unwrap(), initial);
}

#[test]
fn native_stream_upload_rejects_changed_intended_source_before_contacting_server() {
    let fixture = SourceFixture::new();
    let original = vec![0x41; 2 * 1024 * 1024 + 97];
    let original_path = fixture.0.join("original.ipt");
    let current_path = fixture.0.join("working.ipt");
    fs::write(&original_path, &original).unwrap();
    fs::write(&current_path, &original).unwrap();
    let caps = capabilities();
    let expected = {
        let verified = FileSource::open(&current_path, caps.limits.as_ref().unwrap().max_file_bytes, &AtomicBool::new(false)).unwrap();
        SourceInfo { bytes: verified.info().bytes, sha256: verified.info().sha256.clone() }
    };
    let client = Client::new(0, AuthToken::parse("b".repeat(64)).unwrap());
    // Same length catches the digest boundary; another length catches size binding.
    for changed in [vec![0x42; original.len()], vec![0x43; original.len() + 13]] {
        fs::write(&current_path, &changed).unwrap();
        let error = upload(
            &client,
            &caps,
            &current_path,
            TransferTarget::NewOnly { logical_path: "Imports/working.ipt".into() },
            Vec::new(),
            "working-folder",
            &expected,
        )
        .unwrap_err();
        assert_eq!(error.message, "The intended source changed before transfer; nothing was published");
        assert!(!error.disconnect);
        assert_eq!(fs::read(&original_path).unwrap(), original);
        assert_eq!(fs::read(&current_path).unwrap(), changed);
    }
}

#[test]
fn native_stream_publication_receipt_binds_identity_and_payload_without_checkout_secret() {
    let caps = capabilities();
    let make_target = |secret: &str, workspace: &str, parent| TransferTarget::CheckIn {
        document: "managed-part".into(),
        workspace: workspace.into(),
        machine: "desktop".into(),
        checkout_token: secret.into(),
        parent,
    };
    let first_secret = "c".repeat(64);
    let renewed_secret = "d".repeat(64);
    let sha = hash(b"exact saved file");
    let target = make_target(&first_secret, "working-folder", Some(1));
    let receipt = publication_id(&caps, "working-folder", &target, 2_097_249, &sha, &[]).unwrap();
    let renewed = make_target(&renewed_secret, "working-folder", Some(1));
    assert_eq!(receipt, publication_id(&caps, "working-folder", &renewed, 2_097_249, &sha, &[]).unwrap());
    assert_eq!(receipt.len(), 64);
    assert!(receipt.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_ne!(receipt, first_secret);
    assert_ne!(receipt, renewed_secret);

    let changed_parent = make_target(&first_secret, "working-folder", Some(2));
    assert_ne!(receipt, publication_id(&caps, "working-folder", &changed_parent, 2_097_249, &sha, &[]).unwrap());
    let changed_workspace = make_target(&first_secret, "another-folder", Some(1));
    assert_ne!(receipt, publication_id(&caps, "another-folder", &changed_workspace, 2_097_249, &sha, &[]).unwrap());
    let mut changed_account = caps.clone();
    changed_account.principal.id = "another-contributor".into();
    assert_ne!(receipt, publication_id(&changed_account, "working-folder", &target, 2_097_249, &sha, &[]).unwrap());
    assert_ne!(receipt, publication_id(&caps, "working-folder", &target, 2_097_249, &hash(b"different file"), &[]).unwrap());
    assert_ne!(receipt, publication_id(&caps, "working-folder", &target, 2_097_250, &sha, &[]).unwrap());
}
