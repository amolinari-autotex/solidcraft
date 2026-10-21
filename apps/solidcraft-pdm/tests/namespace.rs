use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Request, Response, Store, backup_restore,
    managed::{Principal, Role},
};
struct Root(std::path::PathBuf, String);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> (Root, Store) {
    let root = Root(std::env::temp_dir().join(format!("namespace-{}", AuthToken::generate().unwrap())), AuthToken::generate().unwrap().to_string());
    std::fs::create_dir(&root.0).unwrap();
    let seed = root.0.join("seed");
    std::fs::create_dir(&seed).unwrap();
    std::fs::write(
        seed.join("managed-principals.json"),
        serde_json::to_vec(
            &json!([{"principal":{"id":"alice","role":"contributor"},"token_sha256":format!("{:x}",Sha256::digest(root.1.as_bytes()))}]),
        )
        .unwrap(),
    )
    .unwrap();
    Store::open(&seed).unwrap().backup(&root.0.join("backup")).unwrap();
    backup_restore::restore_backup_to_redb(&root.0.join("backup"), &root.0.join("db")).unwrap();
    let store = Store::open(&root.0.join("db")).unwrap();
    (root, store)
}
fn user() -> Principal {
    Principal { id: "alice".into(), role: Role::Contributor }
}
fn call(store: &mut Store, req: Value, principal: &Principal) -> Value {
    serde_json::to_value(store.execute_as(serde_json::from_value(req).unwrap(), principal)).unwrap()
}
fn create(store: &mut Store, path: &str) -> String {
    match store.execute_as(Request::ManagedCreate { logical_path: path.into() }, &user()) {
        Response::ManagedDocument { entry } => entry.document,
        _ => panic!("create failed"),
    }
}
#[test]
fn rename_tombstone_cas_retry_role_lease_and_restart() {
    let (root, mut store) = fixture();
    let id = create(&mut store, "parts/a.txt");
    let rename = json!({"operation":"managed_namespace","input":{"document":id,"request_id":"rename-one","expected_head":null,"expected_revision":0,"action":{"operation":"rename","logical_path":"parts/b.txt"}}});
    let viewer = Principal { id: "reader".into(), role: Role::Viewer };
    assert_eq!(call(&mut store, rename.clone(), &viewer)["code"], "forbidden");
    let changed = call(&mut store, rename.clone(), &user());
    assert_eq!(changed["metadata"]["revision"], 1);
    assert_eq!(changed["metadata"]["entry"]["document"], id);
    assert_eq!(changed["metadata"]["materialization_path"], "parts/a.txt");
    assert_eq!(call(&mut store, rename.clone(), &user()), changed);
    let mut stale = rename.clone();
    stale["input"]["request_id"] = json!("stale");
    assert_eq!(call(&mut store, stale, &user())["code"], "conflict");
    let del = json!({"operation":"managed_namespace","input":{"document":id,"request_id":"delete-one","expected_head":null,"expected_revision":1,"action":{"operation":"tombstone"}}});
    let grant = store.execute_as(Request::ManagedCheckout { document: id.clone(), workspace: "ws".into(), machine: "pc".into() }, &user());
    assert_eq!(call(&mut store, del.clone(), &user())["code"], "conflict");
    let token = match grant {
        Response::ManagedCheckout { grant } => grant.token,
        _ => panic!("checkout"),
    };
    store.execute_as(
        Request::ManagedCancelCheckout { document: id.clone(), workspace: "ws".into(), machine: "pc".into(), checkout_token: token },
        &user(),
    );
    let deleted = call(&mut store, del.clone(), &user());
    assert_eq!(deleted["metadata"]["tombstoned"], true);
    drop(store);
    let mut store = Store::open(&root.0.join("db")).unwrap();
    assert_eq!(call(&mut store, del, &user()), deleted);
    assert_eq!(call(&mut store, json!({"operation":"managed_catalog"}), &user())["catalog"]["entries"].as_array().unwrap().len(), 0);
    assert_eq!(call(&mut store, json!({"operation":"managed_checkout","document":id,"workspace":"ws","machine":"pc"}), &user())["code"], "not_found");
    assert_eq!(call(&mut store, json!({"operation":"managed_create","logical_path":"parts/b.txt"}), &user())["code"], "conflict");
    assert_eq!(call(&mut store, json!({"operation":"managed_create_new","logical_path":"parts/a.txt"}), &user())["code"], "conflict");
    let backup = root.0.join("namespace-backup");
    store.backup(&backup).unwrap();
    let image: Value = serde_json::from_slice(&std::fs::read(backup.join("data/managed/metadata-snapshot.json")).unwrap()).unwrap();
    assert_eq!(image["audit"].as_array().unwrap().last().unwrap()["subject"], id);
    let restored = root.0.join("restored");
    backup_restore::restore_backup_to_redb(&backup, &restored).unwrap();
    let mut copy = Store::open(&restored).unwrap();
    assert_eq!(call(&mut copy, json!({"operation":"managed_metadata","document":id}), &user())["metadata"]["tombstoned"], true);
}
#[test]
fn rename_collision_traversal_and_referenced_delete_preserve_history() {
    let (_root, mut store) = fixture();
    let part = create(&mut store, "parts/a.txt");
    create(&mut store, "parts/b.txt");
    let mutation = |path: &str, request: &str| json!({"operation":"managed_namespace","input":{"document":part,"request_id":request,"expected_head":null,"expected_revision":0,"action":{"operation":"rename","logical_path":path}}});
    assert_eq!(call(&mut store, mutation("Parts/B.txt", "collision"), &user())["code"], "conflict");
    assert_eq!(call(&mut store, mutation("../a", "traversal"), &user())["code"], "invalid_request");
    let publish = |store: &mut Store, doc: &str, parent: Option<u64>, deps: Vec<Value>, request: &str| {
        let grant = call(store, json!({"operation":"managed_checkout","document":doc,"workspace":"ws","machine":"pc"}), &user());
        call(
            store,
            json!({"operation":"managed_check_in","input":{"document":doc,"workspace":"ws","machine":"pc","checkout_token":grant["grant"]["token"],"request_id":request,"parent":parent,"content":[1,2,3],"dependencies":deps,"comment":"toy"}}),
            &user(),
        )
    };
    assert_eq!(publish(&mut store, &part, None, vec![], "part-v1")["result"], "managed_checked_in");
    let assembly = create(&mut store, "asm.txt");
    publish(&mut store, &assembly, None, vec![json!({"document":part,"version":1})], "asm-v1");
    let deleted = call(
        &mut store,
        json!({"operation":"managed_namespace","input":{"document":part,"request_id":"delete-part","expected_head":1,"expected_revision":0,"action":{"operation":"tombstone"}}}),
        &user(),
    );
    assert_eq!(deleted["code"], "referenced");
    assert_eq!(call(&mut store, json!({"operation":"managed_history","document":part}), &user())["versions"].as_array().unwrap().len(), 1);
}

#[test]
fn pinned_https_namespace_helpers_preserve_references_and_report_conflicts() {
    use solidcraft_pdm::{
        client::Client,
        http_server::{HttpsConfig, HttpsServer},
        managed::{ManagedCheckIn, NamespaceAction, NamespaceMutation},
    };
    let (root, store) = fixture();
    let server = HttpsServer::start(
        store,
        HttpsConfig::from_der(
            "127.0.0.1:0".parse().unwrap(),
            vec![include_bytes!("fixtures/pdm-https/server.der").to_vec()],
            include_bytes!("fixtures/pdm-https/server-key.der").to_vec(),
        )
        .unwrap(),
    )
    .unwrap();
    let client = Client::https_with_ca(
        &format!("https://{}", server.address()),
        AuthToken::parse(root.1.clone()).unwrap(),
        include_bytes!("fixtures/pdm-https/ca.der"),
    )
    .unwrap();
    let caps = client.namespace_capabilities().unwrap().unwrap();
    assert!(caps.supported && caps.can_mutate);
    assert_eq!(caps.principal.id, "alice");
    let publish = |document: String, deps: Vec<solidcraft_pdm::VersionRef>| {
        let grant = client.managed_checkout(document.clone(), "ws".into(), "pc".into()).unwrap();
        client
            .managed_check_in(ManagedCheckIn {
                document,
                workspace: "ws".into(),
                machine: "pc".into(),
                checkout_token: grant.token,
                request_id: AuthToken::generate().unwrap().to_string(),
                parent: None,
                content: if deps.is_empty() { vec![1, 2, 3] } else { b"part.txt".to_vec() },
                dependencies: deps,
                comment: "toy".into(),
            })
            .unwrap()
    };
    let part = client.managed_create("part.txt".into()).unwrap();
    let v1 = publish(part.document.clone(), vec![]);
    let assembly = client.managed_create("assembly.txt".into()).unwrap();
    let a1 = publish(assembly.document.clone(), vec![v1.version.reference.clone()]);
    let input = NamespaceMutation {
        document: part.document.clone(),
        request_id: "rename-over-tls".into(),
        expected_head: Some(1),
        expected_revision: 0,
        action: NamespaceAction::Rename { logical_path: "renamed.txt".into() },
    };
    let changed = client.managed_namespace(input.clone()).unwrap();
    assert_eq!(changed.entry.document, part.document);
    assert_eq!(changed.materialization_path, "part.txt");
    let namespace = client.namespace_catalog().unwrap();
    let displayed = namespace.iter().find(|m| m.entry.document == part.document).unwrap();
    assert_eq!(displayed.entry.logical_path, "renamed.txt");
    assert_eq!(displayed.materialization_path, "part.txt");
    let legacy = client.managed_catalog().unwrap();
    let fresh = root.0.join("fresh-workspace");
    std::fs::create_dir(&fresh).unwrap();
    for entry in &legacy.entries {
        if let Some(version) = entry.head {
            let bytes = client.download(&solidcraft_pdm::VersionRef { document: entry.document.clone(), version }).unwrap().1;
            let path = fresh.join(&entry.logical_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(path).unwrap();
            file.write_all(&bytes).unwrap();
        }
    }
    let dependency = std::fs::read_to_string(fresh.join("assembly.txt")).unwrap();
    assert_eq!(std::fs::read(fresh.join(dependency)).unwrap(), vec![1, 2, 3]);
    assert!(!fresh.join("renamed.txt").exists());
    assert_eq!(legacy.entries.iter().find(|e| e.document == part.document).unwrap().logical_path, "part.txt");
    assert_eq!(client.managed_create("part.txt".into()).unwrap().document, part.document);
    assert!(matches!(client.managed_create_new("PART.TXT".into()),Err(solidcraft_pdm::Error::Server(code)) if code=="conflict"));
    let legacy_grant = client.managed_checkout(part.document.clone(), "legacy-ws".into(), "legacy-pc".into()).unwrap();
    assert_eq!(legacy_grant.entry.logical_path, "part.txt");
    assert_eq!(client.managed_resume_checkout(part.document.clone(), "legacy-ws".into(), "legacy-pc".into()).unwrap().entry.logical_path, "part.txt");
    client.managed_cancel_checkout(part.document.clone(), "legacy-ws".into(), "legacy-pc".into(), legacy_grant.token).unwrap();
    assert_eq!(changed.revision, 1);
    assert_eq!(client.managed_namespace(input).unwrap(), changed);
    assert_eq!(client.download(&a1.version.reference).unwrap().0.dependencies, vec![v1.version.reference.clone()]);
    assert!(
        matches!(client.managed_namespace(NamespaceMutation {document:part.document.clone(),request_id:"delete-referenced".into(),expected_head:Some(1),expected_revision:1,action:NamespaceAction::Tombstone}),Err(solidcraft_pdm::Error::Server(code)) if code=="referenced")
    );
    let tomb = client
        .managed_namespace(NamespaceMutation {
            document: assembly.document.clone(),
            request_id: "delete-assembly".into(),
            expected_head: Some(1),
            expected_revision: 0,
            action: NamespaceAction::Tombstone,
        })
        .unwrap();
    assert!(tomb.tombstoned);
    assert_eq!(client.download(&a1.version.reference).unwrap().1, b"part.txt");
    assert_eq!(client.managed_metadata(assembly.document).unwrap(), tomb);
    let bad = Client::https_with_ca(
        &format!("https://{}", server.address()),
        AuthToken::parse(AuthToken::generate().unwrap()).unwrap(),
        include_bytes!("fixtures/pdm-https/ca.der"),
    )
    .unwrap();
    assert!(bad.namespace_capabilities().is_err());
    server.shutdown().unwrap();
    let store = Store::open(&root.0.join("db")).unwrap();
    let backup = root.0.join("graph-backup");
    store.backup(&backup).unwrap();
    drop(store);
    let restored = root.0.join("graph-restored");
    backup_restore::restore_backup_to_redb(&backup, &restored).unwrap();
    let mut restored = Store::open(&restored).unwrap();
    let metadata = call(&mut restored, json!({"operation":"managed_metadata","document":part.document}), &user());
    assert_eq!(metadata["metadata"]["entry"]["logical_path"], "renamed.txt");
    assert_eq!(metadata["metadata"]["materialization_path"], "part.txt");
}
