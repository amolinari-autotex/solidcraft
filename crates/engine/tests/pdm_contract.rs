// PDM public API contract. Additive pilot; the original unit test remains unchanged.
use serde_json::json;
use solidcraft_engine::{
    Session,
    pdm::{Outcome, Task},
};

#[test]
fn current_assembly_links_refresh_nested_parts_without_saving_intermediate_files() {
    let root = std::env::temp_dir().join(format!("solidcraft-current-links-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let leaf_path = root.join("leaf.solidcraft");
    let child_path = root.join("child.solidcraft");
    let mut leaf = Session::default();
    leaf.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    leaf.execute("file.save", &json!({"path":leaf_path})).unwrap();
    let mut child = Session::default();
    child.execute("component.insert_design", &json!({"path":leaf_path})).unwrap();
    child.execute("file.save", &json!({"path":child_path})).unwrap();
    let original = std::fs::read(&child_path).unwrap();
    let mut assembly = Session::default();
    assembly.execute("component.insert_design", &json!({"path":child_path})).unwrap();
    assert_eq!(assembly.world_state().bodies.len(), 1);
    leaf.execute("solid.box", &json!({"length":5,"width":6,"height":7})).unwrap();
    leaf.execute("file.save", &json!({"path":leaf_path})).unwrap();
    assembly.execute("component.update_links", &json!({"recursive":true})).unwrap();
    assert_eq!(assembly.world_state().bodies.len(), 2, "the current grandchild must replace cached nested geometry");
    assert_eq!(std::fs::read(&child_path).unwrap(), original, "derived refresh must not save the child assembly");
    leaf.execute("component.insert_design", &json!({"path":child_path})).unwrap();
    leaf.execute("file.save", &json!({"path":leaf_path})).unwrap();
    let before = assembly.doc.clone();
    assert!(assembly.execute("component.update_links", &json!({"recursive":true})).is_err(), "nested cycles must be rejected");
    assert_eq!(assembly.doc, before, "failed refresh must preserve the loaded assembly");
    std::fs::remove_dir_all(root).unwrap();
}

fn connected() -> Session {
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    let request = session.execute("pdm.connect", &json!({"port":48231})).unwrap()["request"].as_u64().unwrap();
    assert!(matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Connect { port: 48231 }));
    session.pdm.finish(request, Ok(Outcome::Connected { port: 48231, versions: vec![] })).unwrap();
    session
}

#[test]
fn credentials_and_unknown_parameters_are_refused_before_command_recording() {
    let mut session = connected();
    let secret = "credential-must-not-be-recorded";
    for (command, params) in [
        ("pdm.connect", json!({"port":48231,"token":secret})),
        ("pdm.status", json!({"credential":secret})),
        ("pdm.check_in", json!({"document":"part","dependencies":[{"document":"base","version":1,"token":secret}]})),
    ] {
        let error = session.execute(command, &params).unwrap_err().to_string();
        assert!(!error.contains(secret), "credentials must stay out of command errors");
        assert!(session.pdm.take_job().unwrap().is_none());
    }
    assert!(!serde_json::to_string(&session.pdm.status().unwrap()).unwrap().contains(secret));
    assert!(!session.scratch().pdm.status().unwrap().available);
}

#[test]
fn user8_reference_working_open_is_explicit_validated_and_never_checkout() {
    let mut session = connected();
    let mut state = solidcraft_engine::pdm::ManagedState::default();
    state.server_id = Some("server".into());
    state.workspace = Some("workspace".into());
    state.root = Some("Working".into());
    state.catalog.push(solidcraft_engine::pdm::CatalogEntry {
        document: "part".into(),
        logical_path: "part.solidcraft".into(),
        head: Some(2),
        checkout: None,
        head_checked_in_unix_ms: None,
        head_author: None,
    });
    let refresh = session.pdm.enqueue(Task::Refresh).unwrap();
    session.pdm.finish(refresh, Ok(Outcome::Managed { port: 48231, state })).unwrap();
    session
        .execute("pdm.open_referenced", &json!({"document":"part"}))
        .expect("reference normal-open is a supported command distinct from archived Retrieve and retargeting Open");
    let job = session.pdm.take_job().unwrap().unwrap();
    assert!(matches!(job.task, Task::Managed(_)));
    assert!(!matches!(
        job.task,
        Task::Managed(
            solidcraft_engine::pdm::ManagedTask::Open { .. }
                | solidcraft_engine::pdm::ManagedTask::Checkout { .. }
                | solidcraft_engine::pdm::ManagedTask::CheckoutPreservingMemory { .. }
        )
    ));
    session.pdm.finish(job.id, Ok(Outcome::Listed(vec![]))).unwrap();
    for params in [json!({"document":"part","token":"never-record-this"}), json!({"document":"part","version":1}), json!({"document":"../part"})] {
        assert!(session.execute("pdm.open_referenced", &params).is_err());
        assert!(session.pdm.take_job().unwrap().is_none());
    }
}

#[test]
fn import_new_command_requires_captured_workspace_and_refuses_private_or_traversal_params() {
    let mut session = connected();
    let state = solidcraft_engine::pdm::ManagedState { root: Some("Working".into()), workspace: Some("workspace-a".into()), ..Default::default() };
    let id = session.pdm.enqueue(Task::Refresh).unwrap();
    session.pdm.finish(id, Ok(Outcome::Managed { port: 48231, state })).unwrap();
    for params in [
        json!({"source_path":"C:/source/manual.pdf","folder":"../escape","expected_workspace":"workspace-a"}),
        json!({"source_path":"C:/source/manual.pdf","folder":"Parts","expected_workspace":"stale-workspace"}),
        json!({"source_path":"C:/source/manual.pdf","folder":"Parts","expected_workspace":"workspace-a","token":"not-accepted"}),
    ] {
        assert!(session.execute("pdm.import_new", &params).is_err());
        assert!(session.pdm.take_job().unwrap().is_none());
    }
    session.execute("pdm.import_new", &json!({"source_path":"C:/source/manual.pdf","folder":"Parts","expected_workspace":"workspace-a"})).unwrap();
    assert!(matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Managed(_)));
}

#[test]
fn admin_read_is_explicit_readonly_and_rejects_mutation_or_credential_parameters() {
    let mut session = connected();
    assert!(session.pdm.take_job().unwrap().is_none(), "ordinary connection must not probe administration");
    session.execute("pdm.admin.read", &json!({})).expect("explicit read-only administration request is supported");
    let job = session.pdm.take_job().unwrap().unwrap();
    assert!(matches!(job.task, Task::Managed(_)));
    assert!(!session.pdm.status().unwrap().blocking, "metadata reads must not block document editing");
    session.pdm.finish(job.id, Ok(Outcome::Listed(vec![]))).unwrap();
    for params in [json!({"operation":"create_user"}), json!({"token":"never-display-me"}), json!({"id":"admin","enabled":false})] {
        assert!(session.execute("pdm.admin.read", &params).is_err());
        assert!(session.pdm.take_job().unwrap().is_none());
    }
}

#[test]
fn admin_snapshot_is_bounded_and_cannot_cross_an_authenticated_account_or_disconnect() {
    use solidcraft_engine::pdm::{ActiveConnection, AdminPrincipal, AdminReadStatus, AdminState, AdminUser, ManagedState};
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    let mut connection = ActiveConnection {
        id: "a".repeat(64),
        label: "Archive".into(),
        origin: "https://localhost:48231".into(),
        server_id: "server".into(),
        account: "alice".into(),
        role: "Administrator".into(),
    };
    let state =
        ManagedState { server_id: Some("server".into()), root: Some("Working".into()), workspace: Some("workspace".into()), ..Default::default() };
    let connect = session.execute("pdm.connect", &json!({"port":48231})).unwrap()["request"].as_u64().unwrap();
    session.pdm.take_job().unwrap().unwrap();
    session
        .pdm
        .finish(connect, Ok(Outcome::ManagedConnected { port: 48231, state: state.clone(), connections: vec![], connection: connection.clone() }))
        .unwrap();
    let snapshot = AdminState {
        server_id: Some("server".into()),
        metadata_backend: Some("redb".into()),
        principal: Some(AdminPrincipal { id: "alice".into(), role: "administrator".into(), permissions: vec!["users.manage".into()] }),
        users_status: AdminReadStatus::Available,
        users: vec![AdminUser { id: "private-alice-user".into(), role: "viewer".into(), enabled: true }],
        ..Default::default()
    };
    let request = session.execute("pdm.admin.read", &json!({})).unwrap()["request"].as_u64().unwrap();
    session.pdm.take_job().unwrap().unwrap();
    session.pdm.finish(request, Ok(Outcome::Administration(snapshot.clone()))).unwrap();
    assert_eq!(session.pdm.status().unwrap().administration.unwrap().users.len(), 1);
    let disconnect = session.execute("pdm.disconnect", &json!({})).unwrap()["request"].as_u64().unwrap();
    session.pdm.take_job().unwrap().unwrap();
    session.pdm.finish(disconnect, Ok(Outcome::Disconnected)).unwrap();
    assert!(session.pdm.status().unwrap().administration.is_none());
    connection.account = "bob".into();
    let connect = session.execute("pdm.connect", &json!({"port":48231})).unwrap()["request"].as_u64().unwrap();
    session.pdm.take_job().unwrap().unwrap();
    session.pdm.finish(connect, Ok(Outcome::ManagedConnected { port: 48231, state, connections: vec![], connection })).unwrap();
    let request = session.execute("pdm.admin.read", &json!({})).unwrap()["request"].as_u64().unwrap();
    session.pdm.take_job().unwrap().unwrap();
    assert!(session.pdm.finish(request, Ok(Outcome::Administration(snapshot.clone()))).is_err());
    assert!(session.pdm.status().unwrap().administration.is_none());
    let mut oversized = snapshot;
    oversized.principal.as_mut().unwrap().id = "bob".into();
    oversized.users = vec![AdminUser { id: "account".into(), role: "viewer".into(), enabled: true }; 65];
    let request = session.execute("pdm.admin.read", &json!({})).unwrap()["request"].as_u64().unwrap();
    session.pdm.take_job().unwrap().unwrap();
    assert!(session.pdm.finish(request, Ok(Outcome::Administration(oversized))).is_err());
    assert!(session.pdm.status().unwrap().administration.is_none());
    assert_eq!(session.pdm.status().unwrap().connection.unwrap().account, "bob");
}
