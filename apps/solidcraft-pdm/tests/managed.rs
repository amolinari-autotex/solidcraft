use solidcraft_pdm::{
    Request, Response, Store, VersionRef,
    managed::{CatalogEntry, CheckoutGrant, ManagedCheckIn, ManagedVersion, Principal, Role},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("solidcraft-managed-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn user(id: &str) -> Principal {
    Principal { id: id.into(), role: Role::Contributor }
}
fn create(store: &mut Store, owner: &Principal, path: &str) -> CatalogEntry {
    match store.execute_as(Request::ManagedCreate { logical_path: path.into() }, owner) {
        Response::ManagedDocument { entry } => entry,
        other => panic!("{other:?}"),
    }
}
fn checkout(store: &mut Store, owner: &Principal, document: &str, workspace: &str) -> CheckoutGrant {
    match store.execute_as(Request::ManagedCheckout { document: document.into(), workspace: workspace.into(), machine: "machine-a".into() }, owner) {
        Response::ManagedCheckout { grant } => grant,
        other => panic!("{other:?}"),
    }
}
fn resume(store: &mut Store, owner: &Principal, document: &str, workspace: &str) -> CheckoutGrant {
    match store
        .execute_as(Request::ManagedResumeCheckout { document: document.into(), workspace: workspace.into(), machine: "machine-a".into() }, owner)
    {
        Response::ManagedCheckout { grant } => grant,
        other => panic!("{other:?}"),
    }
}
fn input(grant: &CheckoutGrant, request: &str) -> ManagedCheckIn {
    ManagedCheckIn {
        document: grant.entry.document.clone(),
        workspace: grant.entry.checkout.as_ref().unwrap().workspace.clone(),
        machine: "machine-a".into(),
        checkout_token: grant.token.clone(),
        request_id: request.into(),
        parent: grant.entry.head,
        content: b"public toy design".to_vec(),
        dependencies: vec![],
        comment: "Initial toy version".into(),
    }
}
fn committed(response: Response) -> ManagedVersion {
    match response {
        Response::ManagedCheckedIn { version } => version,
        other => panic!("{other:?}"),
    }
}
fn error(response: Response, code: &str) {
    assert!(matches!(response, Response::Error { code: actual } if actual == code));
}

#[test]
fn checkout_is_exclusive_persistent_and_catalog_does_not_disclose_grant() {
    let temp = Temp::new();
    let owner = user("alice");
    let mut store = Store::open(&temp.0).unwrap();
    let entry = create(&mut store, &owner, "parts/widget.solidcraft");
    assert_ne!(entry.document, entry.logical_path);
    let grant = checkout(&mut store, &owner, &entry.document, "workspace-a");
    error(
        store.execute_as(
            Request::ManagedCheckout { document: entry.document.clone(), workspace: "workspace-a".into(), machine: "machine-a".into() },
            &owner,
        ),
        "conflict",
    );
    assert_eq!(grant, resume(&mut store, &owner, &entry.document, "workspace-a"));
    for (principal, workspace) in [(user("bob"), "workspace-a"), (owner.clone(), "workspace-b")] {
        error(
            store.execute_as(
                Request::ManagedCheckout { document: entry.document.clone(), workspace: workspace.into(), machine: "machine-a".into() },
                &principal,
            ),
            "conflict",
        );
    }
    let catalog = store.execute_as(Request::ManagedCatalog, &owner);
    assert!(!serde_json::to_string(&catalog).unwrap().contains(&grant.token));
    let server_id = match catalog {
        Response::ManagedCatalog { catalog } => catalog.server_id,
        _ => panic!(),
    };
    drop(store);
    let mut store = Store::open(&temp.0).unwrap();
    error(
        store.execute_as(
            Request::ManagedCheckout { document: entry.document.clone(), workspace: "workspace-a".into(), machine: "machine-a".into() },
            &owner,
        ),
        "conflict",
    );
    assert_eq!(grant, resume(&mut store, &owner, &entry.document, "workspace-a"));
    match store.execute_as(Request::ManagedCatalog, &owner) {
        Response::ManagedCatalog { catalog } => assert_eq!(server_id, catalog.server_id),
        _ => panic!(),
    }
}

#[test]
fn owner_workspace_machine_token_and_cas_are_all_required() {
    let temp = Temp::new();
    let alice = user("alice");
    let mut store = Store::open(&temp.0).unwrap();
    let entry = create(&mut store, &alice, "part.solidcraft");
    let grant = checkout(&mut store, &alice, &entry.document, "ws");
    let request = input(&grant, "commit-a");
    assert!(!format!("{grant:?}").contains(&grant.token));
    assert!(!format!("{request:?}").contains(&grant.token));
    error(store.execute_as(Request::ManagedCheckIn { input: request.clone() }, &user("bob")), "forbidden");
    for field in ["workspace", "machine", "token"] {
        let mut bad = request.clone();
        match field {
            "workspace" => bad.workspace = "other".into(),
            "machine" => bad.machine = "other".into(),
            _ => bad.checkout_token = "wrong".into(),
        }
        error(store.execute_as(Request::ManagedCheckIn { input: bad }, &alice), "forbidden");
    }
    let mut stale = request.clone();
    stale.parent = Some(1);
    error(store.execute_as(Request::ManagedCheckIn { input: stale }, &alice), "conflict");
    let version = committed(store.execute_as(Request::ManagedCheckIn { input: request }, &alice));
    assert_eq!(version.author, "alice");
    assert_eq!(version.version.reference.version, 1);
    assert!(checkout(&mut store, &user("bob"), &entry.document, "bob-ws").entry.checkout.is_some());
}

#[cfg(unix)]
#[test]
fn store_rejects_existing_symlink_roots_and_managed_storage_directories() {
    let temp = Temp::new();
    let external = Temp::new();
    std::os::unix::fs::symlink(&external.0, temp.0.join("linked")).unwrap();
    assert!(Store::open(&temp.0.join("linked")).is_err());
    assert!(Store::open(&temp.0.join("linked/subdirectory")).is_err());
    std::os::unix::fs::symlink(&external.0, temp.0.join("managed")).unwrap();
    assert!(Store::open(&temp.0).is_err());
    assert!(!external.0.join("blobs").exists());
}

#[test]
fn lost_ack_retry_is_identical_after_restart_and_does_not_unlock_new_checkout() {
    let temp = Temp::new();
    let alice = user("alice");
    let mut store = Store::open(&temp.0).unwrap();
    let entry = create(&mut store, &alice, "part.solidcraft");
    let grant = checkout(&mut store, &alice, &entry.document, "ws");
    let request = input(&grant, "receipt-a");
    let version = committed(store.execute_as(Request::ManagedCheckIn { input: request.clone() }, &alice));
    drop(store);
    let mut store = Store::open(&temp.0).unwrap();
    let bob_grant = checkout(&mut store, &user("bob"), &entry.document, "bob-ws");
    assert_eq!(bob_grant.entry.head_checked_in_unix_ms, Some(version.checked_in_unix_ms));
    assert_eq!(bob_grant.entry.head_author.as_deref(), Some(version.author.as_str()));
    assert_eq!(version, committed(store.execute_as(Request::ManagedCheckIn { input: request.clone() }, &alice)));
    let mut without_secret = request.clone();
    without_secret.checkout_token.clear();
    assert_eq!(version, committed(store.execute_as(Request::ManagedCheckIn { input: without_secret }, &alice)));
    assert_eq!(bob_grant, resume(&mut store, &user("bob"), &entry.document, "bob-ws"));
    let mut changed = request;
    changed.content.push(1);
    error(store.execute_as(Request::ManagedCheckIn { input: changed }, &alice), "conflict");
    assert_eq!(store.download(&version.version.reference).unwrap().1, b"public toy design");
    match store.execute_as(Request::ManagedHistory { document: entry.document }, &alice) {
        Response::ManagedHistory { versions } => assert_eq!(versions, vec![version]),
        _ => panic!(),
    }
}

#[test]
fn older_catalog_entries_without_optional_head_metadata_remain_readable() {
    let entry: CatalogEntry = serde_json::from_value(serde_json::json!({
        "document":"m-example", "logical_path":"toy.solidcraft", "head":null, "checkout":null
    }))
    .unwrap();
    assert_eq!(entry.head_checked_in_unix_ms, None);
    assert_eq!(entry.head_author, None);
}

#[test]
fn redb_import_preserves_pinned_graph_and_independent_future_heads() {
    let temp = Temp::new();
    let alice = user("alice");
    let source = temp.0.join("source");
    let mut store = Store::open(&source).unwrap();
    let part = create(&mut store, &alice, "parts/widget.solidcraft");
    let grant = checkout(&mut store, &alice, &part.document, "ws");
    let part_v1 = committed(store.execute_as(Request::ManagedCheckIn { input: input(&grant, "part-v1") }, &alice));
    let assembly = create(&mut store, &alice, "assembly.solidcraft");
    let grant = checkout(&mut store, &alice, &assembly.document, "ws");
    let mut assembly_input = input(&grant, "assembly-v1");
    assembly_input.dependencies = vec![part_v1.version.reference.clone()];
    let assembly_v1 = committed(store.execute_as(Request::ManagedCheckIn { input: assembly_input }, &alice));
    let backup = temp.0.join("backup");
    store.backup(&backup).unwrap();
    drop(store);
    let target = temp.0.join("database");
    solidcraft_pdm::backup_restore::restore_backup_to_redb(&backup, &target).unwrap();
    let mut store = Store::open(&target).unwrap();
    let grant = checkout(&mut store, &alice, &part.document, "ws");
    let mut next = input(&grant, "part-v2");
    next.content = b"changed part".to_vec();
    let part_v2 = committed(store.execute_as(Request::ManagedCheckIn { input: next }, &alice));
    assert_eq!(part_v2.version.reference.version, 2);
    drop(store);
    let mut store = Store::open(&target).unwrap();
    let (version, _) = store.download(&assembly_v1.version.reference).unwrap();
    assert_eq!(version.dependencies, vec![part_v1.version.reference.clone()]);
    assert_eq!(store.download(&part_v1.version.reference).unwrap().1, b"public toy design");
    assert!(matches!(store.execute_as(Request::WhereUsed { reference: part_v1.version.reference }, &alice),
        Response::WhereUsed { versions } if versions == vec![assembly_v1.version.reference]));
    drop(store);
    assert!(!source.join("managed/metadata.redb").exists());
    assert!(solidcraft_pdm::backup_restore::verify_backup(&backup).is_ok());
}

#[test]
fn managed_writes_cannot_bypass_checkout_through_legacy_api_or_viewer_role() {
    let temp = Temp::new();
    let alice = user("alice");
    let mut store = Store::open(&temp.0).unwrap();
    let viewer = Principal { id: "reader".into(), role: Role::Viewer };
    error(store.execute_as(Request::ManagedCreate { logical_path: "x.solidcraft".into() }, &viewer), "forbidden");
    let entry = create(&mut store, &alice, "part.solidcraft");
    assert!(matches!(store.check_in(entry.document.clone(), None, vec![], vec![]), Err(solidcraft_pdm::Error::Forbidden)));
    error(
        store.execute_as(Request::CheckIn { document: entry.document.clone(), parent: None, content: vec![], dependencies: vec![] }, &alice),
        "forbidden",
    );
    let grant = checkout(&mut store, &alice, &entry.document, "ws");
    error(store.execute_as(Request::ManagedCheckIn { input: input(&grant, "receipt-a") }, &viewer), "forbidden");
    error(
        store.execute_as(
            Request::ManagedCancelCheckout {
                document: entry.document.clone(),
                workspace: "ws".into(),
                machine: "machine-a".into(),
                checkout_token: grant.token.clone(),
            },
            &user("bob"),
        ),
        "forbidden",
    );
    assert!(matches!(
        store.execute_as(
            Request::ManagedCancelCheckout {
                document: entry.document,
                workspace: "ws".into(),
                machine: "machine-a".into(),
                checkout_token: grant.token
            },
            &alice
        ),
        Response::ManagedDocument { .. }
    ));
}

#[test]
fn logical_paths_are_portable_unique_and_never_server_paths() {
    let temp = Temp::new();
    let alice = user("alice");
    let mut store = Store::open(&temp.0).unwrap();
    for path in ["../x", "/x", "x//y", "x/./y", "x\\y", "C:/x", "CON.solidcraft", "x/NUL", "x.", "x ", "x\n"] {
        error(store.execute_as(Request::ManagedCreate { logical_path: path.into() }, &alice), "invalid_request");
    }
    let entry = create(&mut store, &alice, "parts/gear.solidcraft");
    assert_eq!(entry, create(&mut store, &alice, "parts/gear.solidcraft"));
    error(store.execute_as(Request::ManagedCreate { logical_path: "Parts/Gear.solidcraft".into() }, &alice), "conflict");
    assert!(!temp.0.join("parts").exists());
}

#[test]
fn import_new_reserves_a_path_exclusively_without_touching_existing_content() {
    let temp = Temp::new();
    let alice = user("alice");
    let mut store = Store::open(&temp.0).unwrap();
    let request = || serde_json::from_value::<Request>(serde_json::json!({"operation":"managed_create_new","logical_path":"parts/import.txt"}));
    assert!(request().is_ok(), "new-only import reservation must be supported");
    let entry = match store.execute_as(request().unwrap(), &alice) {
        Response::ManagedDocument { entry } => entry,
        other => panic!("{other:?}"),
    };
    let grant = checkout(&mut store, &alice, &entry.document, "ws");
    let published = committed(store.execute_as(Request::ManagedCheckIn { input: input(&grant, "import-first") }, &alice));
    error(store.execute_as(request().unwrap(), &alice), "conflict");
    let folded = serde_json::from_value::<Request>(serde_json::json!({"operation":"managed_create_new","logical_path":"Parts/Import.txt"})).unwrap();
    error(store.execute_as(folded, &alice), "conflict");
    let history = match store.execute_as(Request::ManagedHistory { document: entry.document.clone() }, &alice) {
        Response::ManagedHistory { versions } => versions,
        other => panic!("{other:?}"),
    };
    assert_eq!(history.len(), 1);
    assert_eq!(history[0], published);
    assert_eq!(create(&mut store, &alice, "parts/import.txt").checkout, None);
    let viewer = Principal { id: "reader".into(), role: Role::Viewer };
    let denied = serde_json::from_value::<Request>(serde_json::json!({"operation":"managed_create_new","logical_path":"denied.txt"})).unwrap();
    error(store.execute_as(denied, &viewer), "forbidden");
}

#[test]
fn graph_download_list_and_where_used_include_managed_versions() {
    let temp = Temp::new();
    let alice = user("alice");
    let mut store = Store::open(&temp.0).unwrap();
    let part = create(&mut store, &alice, "part.solidcraft");
    let grant = checkout(&mut store, &alice, &part.document, "ws");
    let p1 = committed(store.execute_as(Request::ManagedCheckIn { input: input(&grant, "part-one") }, &alice));
    let assembly = create(&mut store, &alice, "assembly.solidcraft");
    let grant = checkout(&mut store, &alice, &assembly.document, "ws");
    let mut request = input(&grant, "assembly-one");
    request.dependencies = vec![p1.version.reference.clone()];
    let a1 = committed(store.execute_as(Request::ManagedCheckIn { input: request }, &alice));
    let grant = checkout(&mut store, &alice, &part.document, "ws");
    committed(store.execute_as(Request::ManagedCheckIn { input: input(&grant, "part-two") }, &alice));
    assert_eq!(store.where_used(&p1.version.reference).unwrap(), vec![a1.version.reference.clone()]);
    assert_eq!(store.list(Some(&part.document)).unwrap().len(), 2);
    assert_eq!(store.download(&VersionRef { document: assembly.document, version: 1 }).unwrap().0.dependencies, vec![p1.version.reference]);
}

#[test]
fn metadata_failure_preserves_checkout_and_retry_publishes_once() {
    let temp = Temp::new();
    let alice = user("alice");
    let mut store = Store::open(&temp.0).unwrap();
    let entry = create(&mut store, &alice, "part.solidcraft");
    let grant = checkout(&mut store, &alice, &entry.document, "ws");
    // Inject failure before the metadata generation can publish, after blob publication.
    fs::write(temp.0.join("managed/generations/pending"), b"block staging").unwrap();
    let request = input(&grant, "retry-a");
    error(store.execute_as(Request::ManagedCheckIn { input: request.clone() }, &alice), "storage_error");
    assert_eq!(grant, resume(&mut store, &alice, &entry.document, "ws"));
    fs::remove_file(temp.0.join("managed/generations/pending")).unwrap();
    let version = committed(store.execute_as(Request::ManagedCheckIn { input: request.clone() }, &alice));
    assert_eq!(version, committed(store.execute_as(Request::ManagedCheckIn { input: request }, &alice)));
    assert_eq!(store.list(Some(&entry.document)).unwrap().len(), 1);
}

#[test]
fn server_configuration_selects_principals_and_roles_over_authenticated_tcp() {
    use sha2::{Digest, Sha256};
    use solidcraft_pdm::{AuthToken, bind_loopback, client::Client, serve_connection};
    let temp = Temp::new();
    let alice_secret = AuthToken::generate().unwrap();
    let viewer_secret = AuthToken::generate().unwrap();
    let credentials = vec![
        solidcraft_pdm::managed::PrincipalCredential {
            principal: user("alice"),
            token_sha256: format!("{:x}", Sha256::digest(alice_secret.as_bytes())),
        },
        solidcraft_pdm::managed::PrincipalCredential {
            principal: Principal { id: "reader".into(), role: Role::Viewer },
            token_sha256: format!("{:x}", Sha256::digest(viewer_secret.as_bytes())),
        },
    ];
    fs::write(temp.0.join("managed-principals.json"), serde_json::to_vec(&credentials).unwrap()).unwrap();
    let mut store = Store::open(&temp.0).unwrap();
    let listener = bind_loopback(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let owner_secret = AuthToken::parse(AuthToken::generate().unwrap()).unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..6 {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(&mut store, stream, &owner_secret).unwrap();
        }
    });
    let alice = Client::new(port, AuthToken::parse(alice_secret).unwrap());
    let viewer = Client::new(port, AuthToken::parse(viewer_secret).unwrap());
    let entry = alice.managed_create("toy.solidcraft".into()).unwrap();
    assert!(
        matches!(viewer.managed_checkout(entry.document.clone(), "ws".into(), "machine-a".into()), Err(solidcraft_pdm::Error::Server(code)) if code == "forbidden")
    );
    let grant = alice.managed_checkout(entry.document, "ws".into(), "machine-a".into()).unwrap();
    assert_eq!(grant.entry.checkout.as_ref().unwrap().owner, "alice");
    let catalog = viewer.managed_catalog().unwrap();
    assert!(!serde_json::to_string(&catalog).unwrap().contains(&grant.token));
    let version = alice.managed_check_in(input(&grant, "network-receipt")).unwrap();
    assert_eq!(version.author, "alice");
    let bogus = Client::new(port, AuthToken::parse(AuthToken::generate().unwrap()).unwrap());
    assert!(matches!(bogus.managed_catalog(), Err(solidcraft_pdm::Error::Server(code)) if code == "unauthorized"));
    server.join().unwrap();
}
