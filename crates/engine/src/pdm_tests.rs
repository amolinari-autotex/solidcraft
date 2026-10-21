use super::*;
use crate::Session;
use serde_json::json;

#[test]
fn first_archive_blocks_concurrent_edits_and_save_before_manifest_registration() {
    let mut session = connected();
    let folder = std::env::temp_dir().join(format!("solidcraft-first-archive-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let path = folder.join("first.solidcraft");
    session.execute("file.save", &json!({"path":path})).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let request = session.execute("pdm.archive", &json!({})).unwrap()["request"].as_u64().unwrap();
    assert!(session.pdm.managed_for_path(path.to_str().unwrap()).is_none());
    assert!(session.pdm.blocks_path(path.to_str().unwrap()));
    assert!(session.execute("file.save", &json!({})).is_err());
    assert!(session.execute("assembly.bom", &json!({"path":path,"format":"json"})).is_err());
    assert!(session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    session.pdm.finish(request, Err(Failure { message: "offline".into(), disconnect: false })).unwrap();
    assert!(!session.pdm.blocks_path(path.to_str().unwrap()));
    session.execute("file.save", &json!({})).unwrap();
    std::fs::remove_dir_all(folder).unwrap();
}

#[test]
fn managed_save_guard_is_independent_of_os_readonly_and_allows_a_separate_copy() {
    let mut session = Session::default();
    let folder = std::env::temp_dir().join(format!("solidcraft-managed-save-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let path = folder.join("managed.solidcraft");
    session.execute("file.save", &json!({"path":path})).unwrap();
    session.pdm.set_available(true).unwrap();
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session
        .pdm
        .finish(
            id,
            Ok(Outcome::Managed {
                port: 48231,
                state: ManagedState {
                    local: vec![LocalEntry {
                        document: "doc".into(),
                        path: path.to_string_lossy().into_owned(),
                        relative_path: "managed.solidcraft".into(),
                        base_version: 1,
                        sha256: "ab".repeat(32),
                        checked_out: false,
                        modified: false,
                        present: true,
                    }],
                    ..ManagedState::default()
                },
            }),
        )
        .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    assert!(session.execute("file.save", &json!({})).is_err());
    assert!(session.execute("file.save_as", &json!({"path":folder.join(".").join("managed.solidcraft")})).is_err());
    assert!(session.execute("file.export", &json!({"path":folder.join(".").join("managed.solidcraft"),"format":"design"})).is_err());
    assert!(session.execute("file.export", &json!({"path":path,"format":"urdf"})).is_err());
    assert!(session.execute("assembly.bom", &json!({"path":folder.join(".").join("managed.solidcraft"),"format":"json"})).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    session.execute("assembly.bom", &json!({"path":folder.join("parts.csv")})).unwrap();
    session.execute("file.save_as", &json!({"path":folder.join("copy.solidcraft")})).unwrap();
    session.execute("file.save", &json!({})).unwrap();
    std::fs::remove_dir_all(folder).unwrap();
}

#[test]
fn historical_guard_survives_edits_but_save_as_detaches_the_copy() {
    let mut session = Session::default();
    let folder = std::env::temp_dir().join(format!("solidcraft-history-save-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    session.execute("file.save", &json!({"path":folder.join("history.solidcraft")})).unwrap();
    session.pdm_read_only = true;
    let bytes = std::fs::read(folder.join("history.solidcraft")).unwrap();
    session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    assert!(session.execute("file.save", &json!({})).is_err());
    assert!(session.execute("file.save_as", &json!({"path":folder.join(".").join("history.solidcraft")})).is_err());
    assert!(session.execute("assembly.bom", &json!({"path":folder.join(".").join("history.solidcraft"),"format":"json"})).is_err());
    assert_eq!(std::fs::read(folder.join("history.solidcraft")).unwrap(), bytes);
    session.execute("assembly.bom", &json!({"path":folder.join("historical-parts.csv")})).unwrap();
    assert!(session.pdm_read_only);
    session.execute("file.save_as", &json!({"path":folder.join("copy.solidcraft")})).unwrap();
    assert!(!session.pdm_read_only);
    session.execute("file.save", &json!({})).unwrap();
    std::fs::remove_dir_all(folder).unwrap();
}

fn connected() -> Session {
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    let request = session.execute("pdm.connect", &json!({"port":48231})).unwrap()["request"].as_u64().unwrap();
    assert!(matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Connect { port: 48231 }));
    session.pdm.finish(request, Ok(Outcome::Connected { port: 48231, versions: vec![] })).unwrap();
    session
}

fn managed_snapshot(path: &str, workspace: &str, checked_out: bool) -> ManagedState {
    ManagedState {
        server_id: Some("server".into()),
        workspace: Some(workspace.into()),
        local: vec![LocalEntry {
            document: "part".into(),
            path: path.into(),
            relative_path: "part.solidcraft".into(),
            base_version: 1,
            sha256: "ab".repeat(32),
            checked_out,
            modified: false,
            present: true,
        }],
        ..ManagedState::default()
    }
}

fn apply_managed(runtime: &Runtime, managed: ManagedState, refresh: bool) -> Result<(), String> {
    let connected = runtime.status()?.port.is_some();
    let task = if refresh && connected {
        Task::Refresh
    } else {
        if connected {
            // Workspace-switch fixtures must model the explicit disconnect,
            // preserving the protection ledger before a new native connection.
            let id = runtime.enqueue(Task::Disconnect)?;
            runtime.finish(id, Ok(Outcome::Disconnected))?;
        }
        Task::Connect { port: 48231 }
    };
    let id = runtime.enqueue(task)?;
    runtime.finish(
        id,
        Ok(if refresh { Outcome::ManagedRefreshed { port: 48231, state: managed } } else { Outcome::Managed { port: 48231, state: managed } }),
    )
}

#[test]
fn inactive_workspace_paths_stay_protected_and_verified_reconnection_restores_checkout() {
    let mut session = connected();
    let folder = std::env::temp_dir().join(format!("solidcraft-workspace-switch-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let path = folder.join("part.solidcraft");
    session.execute("file.save", &json!({"path":path})).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let path = path.to_str().unwrap();
    let inactive_tab = session.pdm.clone();
    apply_managed(&session.pdm, managed_snapshot(path, "a", false), false).unwrap();
    assert!(inactive_tab.may_save(path).is_err());
    let id = session.pdm.enqueue(Task::Disconnect).unwrap();
    session.pdm.finish(id, Ok(Outcome::Disconnected)).unwrap();
    assert!(inactive_tab.may_save(path).is_err());
    for refresh in [false, true] {
        apply_managed(&session.pdm, managed_snapshot("another.solidcraft", "b", false), refresh).unwrap();
        assert!(!inactive_tab.managed_for_path(path).unwrap().checked_out);
        assert!(session.execute("file.save", &json!({})).is_err());
        let alias = folder.join(".").join("part.solidcraft");
        assert!(session.execute("file.save_as", &json!({"path":alias})).is_err());
        assert!(session.execute("file.export", &json!({"path":alias,"format":"design"})).is_err());
        assert!(session.execute("assembly.bom", &json!({"path":alias,"format":"json"})).is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    apply_managed(&session.pdm, managed_snapshot(path, "a", true), false).unwrap();
    session.pdm.may_save(path).unwrap();
    // Switching away preserves the server reservation, but requires verified
    // reconnection before this application's inactive workspace can save again.
    apply_managed(&session.pdm, managed_snapshot("another.solidcraft", "b", false), false).unwrap();
    assert!(inactive_tab.may_save(path).is_err());
    apply_managed(&session.pdm, managed_snapshot(path, "a", true), true).unwrap();
    assert!(inactive_tab.managed_for_path(path).unwrap().checked_out);
    session.execute("file.save", &json!({})).unwrap();
    apply_managed(&session.pdm, managed_snapshot(path, "a", false), true).unwrap();
    assert!(inactive_tab.may_save(path).is_err());
    session.execute("file.save_as", &json!({"path":folder.join("separate.solidcraft")})).unwrap();
    std::fs::remove_dir_all(folder).unwrap();
}

#[test]
fn historical_destinations_remain_readonly_for_other_tabs_and_workspaces() {
    let runtime = connected().pdm;
    let mut snapshot = managed_snapshot("working.solidcraft", "a", true);
    snapshot.historical_paths = vec!["snapshot/root.solidcraft".into(), "snapshot/component.solidcraft".into()];
    apply_managed(&runtime, snapshot, false).unwrap();
    runtime.may_save("working.solidcraft").unwrap();
    apply_managed(&runtime, managed_snapshot("other.solidcraft", "b", false), true).unwrap();
    for path in ["snapshot/root.solidcraft", "snapshot/component.solidcraft"] {
        assert!(runtime.may_save(path).is_err());
    }
    runtime.may_save("independent.solidcraft").unwrap();
}

#[test]
fn conflicting_workspace_path_and_protection_overflow_fail_closed() {
    let runtime = connected().pdm;
    apply_managed(&runtime, managed_snapshot("part.solidcraft", "a", false), false).unwrap();
    assert!(apply_managed(&runtime, managed_snapshot("part.solidcraft", "b", true), false).is_err());
    assert!(runtime.status().unwrap().busy.is_none());
    assert!(runtime.status().unwrap().error.is_some());
    assert!(runtime.may_save("part.solidcraft").is_err());
    assert!(runtime.enqueue(Task::Connect { port: 48231 }).is_err());
    let runtime = connected().pdm;
    let snapshot = ManagedState {
        historical_paths: (0..MAX_PROTECTED_PATHS + 1).map(|n| format!("snapshot/{n}.solidcraft")).collect(),
        ..ManagedState::default()
    };
    assert!(apply_managed(&runtime, snapshot, false).is_err());
    assert!(runtime.may_save("snapshot/0.solidcraft").is_err());
    assert!(runtime.may_save("unregistered.solidcraft").is_err());
}

#[test]
fn historical_ledger_retains_original_paths_for_save_time_resolution() {
    let runtime = connected().pdm;
    let path = r"\\?\UNC\server\share\history\part.solidcraft";
    let snapshot = ManagedState { historical_paths: vec![path.into()], ..ManagedState::default() };
    apply_managed(&runtime, snapshot, false).unwrap();
    assert_eq!(runtime.0.lock().unwrap().historical_paths.get(&cached_path_key(path)).unwrap(), path);
    if cfg!(target_os = "windows") {
        assert_eq!(cached_path_key(path), cached_path_key(r"\\server\share\history\part.solidcraft"));
        assert_eq!(cached_path_key(r"\\?\unc\server\share\history\part.solidcraft"), cached_path_key(path));
    }
}

#[test]
fn urdf_export_checks_every_mesh_before_writing_any_target() {
    let mut session = connected();
    for name in ["A", "B"] {
        session.execute("component.activate", &json!({"component":"root"})).unwrap();
        session.execute("component.create", &json!({"name":name})).unwrap();
        session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    }
    let folder = std::env::temp_dir().join(format!("solidcraft-pdm-urdf-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let package =
        solidcraft_io::urdf(&session.doc, &session.doc.painted(&session.model.state()), "robot", &solidcraft_io::UrdfOptions::default()).unwrap();
    assert!(package.meshes.len() >= 2);
    let first = folder.join(&package.meshes.first().unwrap().0);
    let last = folder.join(&package.meshes.last().unwrap().0);
    std::fs::write(&first, b"existing first mesh").unwrap();
    std::fs::write(&last, b"protected last mesh").unwrap();
    let destination = folder.join("robot.urdf");
    apply_managed(&session.pdm, managed_snapshot(last.to_str().unwrap(), "a", false), false).unwrap();
    for historical in [false, true] {
        if historical {
            session.pdm = Runtime::default();
            session.pdm_read_only = true;
            session.path = Some(last.to_string_lossy().into_owned());
        }
        let error = session.execute("file.export", &json!({"path":destination,"format":"urdf"})).unwrap_err().to_string();
        assert!(error.contains(if historical { "Historical copies are read-only" } else { "Extract this managed design" }), "{error}");
        assert_eq!(std::fs::read(&first).unwrap(), b"existing first mesh");
        assert_eq!(std::fs::read(&last).unwrap(), b"protected last mesh");
        assert!(!destination.exists());
    }
    let separate = folder.join("separate");
    std::fs::create_dir(&separate).unwrap();
    session.execute("file.export", &json!({"path":separate.join("robot.urdf"),"format":"urdf"})).unwrap();
    assert!(separate.join("robot.urdf").exists());
    assert_eq!(std::fs::read(&last).unwrap(), b"protected last mesh");
    std::fs::remove_dir_all(folder).unwrap();
}

#[test]
fn host_availability_ports_and_single_job_guards_are_enforced_without_design_edits() {
    let mut session = Session::default();
    assert!(session.execute("pdm.connect", &json!({"port":48231})).is_err());
    session.pdm.set_available(true).unwrap();
    for port in [json!(0), json!(65536), json!(1.5), json!("bad")] {
        assert!(session.execute("pdm.connect", &json!({"port":port})).is_err());
    }
    let doc = session.doc.clone();
    let revision = session.revision;
    let id = session.execute("pdm.connect", &json!({"port":48231})).unwrap()["request"].as_u64().unwrap();
    assert!(session.execute("pdm.connect", &json!({"port":48232})).is_err());
    assert!(session.execute("pdm.disconnect", &json!({})).is_err());
    assert!(session.pdm.finish(id + 1, Ok(Outcome::Disconnected)).is_err());
    assert_eq!(session.pdm.status().unwrap().busy, Some(id));
    session.pdm.finish(id, Err(Failure { message: "Service unavailable".into(), disconnect: true })).unwrap();
    assert!(session.pdm.status().unwrap().port.is_none());
    assert_eq!(*session.doc, *doc);
    assert_eq!(session.revision, revision);
    assert!(session.undo.is_empty());
    assert!(!session.is_dirty());
}

#[test]
fn check_in_requires_saved_unchanged_design_and_retains_explicit_base_and_dependencies() {
    let mut session = connected();
    assert!(session.execute("pdm.check_in", &json!({"document":"part"})).is_err());
    session.path = Some("saved.solidcraft".into());
    session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    assert!(session.execute("pdm.check_in", &json!({"document":"part"})).is_err());
    session.mark_saved();
    session.execute("pdm.check_in", &json!({"document":"assembly","parent":4,"dependencies":[{"document":"part","version":2}]})).unwrap();
    let job = session.pdm.take_job().unwrap().unwrap();
    match job.task {
        Task::CheckIn { document, parent, path, dependencies, saved, .. } => {
            assert_eq!(document, "assembly");
            assert_eq!(parent, Some(4));
            assert_eq!(path, "saved.solidcraft");
            assert_eq!(dependencies, vec![Reference { document: "part".into(), version: 2 }]);
            assert_eq!(*saved, *session.doc);
        }
        other => panic!("unexpected task {other:?}"),
    }
    session.pdm.finish(job.id, Err(Failure { message: "Version conflict".into(), disconnect: false })).unwrap();
    assert_eq!(session.pdm.status().unwrap().port, Some(48231));
    assert!(session.pdm.status().unwrap().error.is_some());
    assert!(!session.is_dirty());
}

#[test]
fn retrieval_validates_refs_and_only_requests_a_new_working_copy() {
    let mut session = connected();
    let before = session.doc.clone();
    for document in ["../escape", "UPPER", "a/b", ""] {
        assert!(session.execute("pdm.retrieve", &json!({"document":document,"version":1})).is_err());
    }
    assert!(session.execute("pdm.retrieve", &json!({"document":"part","version":0})).is_err());
    session.execute("pdm.retrieve", &json!({"document":"part","version":1})).unwrap();
    assert!(matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Retrieve { reference: Reference { version: 1, .. }, open: true }));
    assert_eq!(*session.doc, *before);
    assert!(session.path.is_none());
}

#[test]
fn active_edits_and_bad_parent_or_dependency_metadata_are_refused() {
    let mut session = connected();
    session.path = Some("saved.solidcraft".into());
    session.active_sketch = Some(7);
    assert!(session.execute("pdm.check_in", &json!({"document":"part"})).is_err());
    session.active_sketch = None;
    for params in [
        json!({"document":"part","parent":0}),
        json!({"document":"part","parent":"bad"}),
        json!({"document":"part","dependencies":[{"document":"../escape","version":1}]}),
    ] {
        assert!(session.execute("pdm.check_in", &params).is_err());
    }
    assert!(session.pdm.take_job().unwrap().is_none());
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
        assert!(!error.contains(secret));
        assert!(session.pdm.take_job().unwrap().is_none());
    }
    assert!(!serde_json::to_string(&session.pdm.status().unwrap()).unwrap().contains(secret));
    assert!(!session.scratch().pdm.status().unwrap().available);
}

#[test]
fn restore_in_flight_blocks_edits_and_outputs_in_every_editor_for_its_workspace() {
    let mut session = connected();
    let folder = std::env::temp_dir().join(format!("solidcraft-pdm-restore-inflight-{}", std::process::id()));
    std::fs::create_dir(&folder).unwrap();
    let path = folder.join("part.solidcraft");
    session.execute("file.save", &json!({"path":path})).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut state = managed_snapshot(path.to_str().unwrap(), "a", false);
    state.local[0].base_version = 2;
    state.catalog.push(CatalogEntry {
        document: "part".into(),
        logical_path: "part.solidcraft".into(),
        head: Some(2),
        checkout: None,
        head_checked_in_unix_ms: None,
        head_author: None,
    });
    apply_managed(&session.pdm, state, false).unwrap();
    let mut second_editor = Session { path: Some(path.to_string_lossy().into_owned()), pdm: session.pdm.clone(), ..Default::default() };
    second_editor.mark_saved();
    let id = session.execute("pdm.restore_version", &json!({"document":"part","version":1,"restore":true})).unwrap()["request"].as_u64().unwrap();
    assert!(session.pdm.status().unwrap().blocking);
    for editor in [&mut session, &mut second_editor] {
        let doc = editor.doc.clone();
        let error = editor.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap_err().to_string();
        assert!(error.contains("Wait for the managed operation"));
        assert_eq!(*editor.doc, *doc);
        assert!(editor.execute("file.save", &json!({})).is_err());
        assert!(editor.execute("parameters.export", &json!({"path":path,"format":"json"})).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    session.pdm.finish(id, Err(Failure { message: "Restore did not change the working copy".into(), disconnect: false })).unwrap();
    assert!(!session.pdm.status().unwrap().blocking);
    second_editor.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(folder).unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn hardlink_destinations_cannot_truncate_historical_or_inactive_managed_files() {
    let folder = std::env::temp_dir().join(format!("solidcraft-pdm-hardlinks-{}", std::process::id()));
    std::fs::create_dir(&folder).unwrap();
    let original = folder.join("protected.solidcraft");
    let alias = folder.join("report.json");
    let bytes = b"protected original bytes";
    std::fs::write(&original, bytes).unwrap();
    std::fs::hard_link(&original, &alias).unwrap();
    assert_ne!(std::fs::canonicalize(&original).unwrap(), std::fs::canonicalize(&alias).unwrap());
    assert!(same_file_path(original.to_str().unwrap(), alias.to_str().unwrap()));
    for protection in 0..3 {
        let mut session = connected();
        match protection {
            0 => {
                let state = ManagedState { historical_paths: vec![original.to_string_lossy().into_owned()], ..ManagedState::default() };
                apply_managed(&session.pdm, state, false).unwrap();
                apply_managed(&session.pdm, managed_snapshot("other.solidcraft", "b", true), false).unwrap();
            }
            1 => {
                apply_managed(&session.pdm, managed_snapshot(original.to_str().unwrap(), "a", false), false).unwrap();
                apply_managed(&session.pdm, managed_snapshot("other.solidcraft", "b", true), false).unwrap();
            }
            _ => {
                session.pdm_read_only = true;
                session.path = Some(original.to_string_lossy().into_owned());
            }
        }
        for (command, params) in [
            ("parameters.export", json!({"path":alias,"format":"json"})),
            ("timeline.export_script", json!({"path":alias})),
            ("assembly.bom", json!({"path":alias,"format":"json"})),
            ("file.save_as", json!({"path":alias})),
        ] {
            let error = session.execute(command, &params).unwrap_err().to_string();
            assert!(
                error.contains(if protection == 1 { "Extract this managed design" } else { "Historical copies are read-only" }),
                "{command}: {error}"
            );
            assert_eq!(std::fs::read(&original).unwrap(), bytes);
            assert_eq!(std::fs::read(&alias).unwrap(), bytes);
        }
        session.execute("parameters.export", &json!({"path":folder.join(format!("separate-{protection}.json")),"format":"json"})).unwrap();
        assert_eq!(std::fs::read(&original).unwrap(), bytes);
    }
    std::fs::remove_dir_all(folder).unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn busy_managed_destinations_block_existing_hardlinks_until_completion() {
    let folder = std::env::temp_dir().join(format!("solidcraft-pdm-busy-hardlinks-{}", std::process::id()));
    std::fs::create_dir(&folder).unwrap();
    let original = folder.join("working.solidcraft");
    let alias = folder.join("alias.solidcraft");
    std::fs::write(&original, b"unchanged").unwrap();
    std::fs::hard_link(&original, &alias).unwrap();
    let runtime = connected().pdm;
    let mut state = managed_snapshot(original.to_str().unwrap(), "a", true);
    state.catalog.push(CatalogEntry {
        document: "part".into(),
        logical_path: "working.solidcraft".into(),
        head: Some(1),
        checkout: Some(Checkout {
            owner: "alice".into(),
            workspace: "a".into(),
            machine: "desktop".into(),
            checked_out_unix_ms: 1,
            base_version: Some(1),
        }),
        head_checked_in_unix_ms: None,
        head_author: None,
    });
    apply_managed(&runtime, state, false).unwrap();
    runtime.may_save(alias.to_str().unwrap()).unwrap();
    let id = runtime.enqueue(Task::Managed(ManagedTask::CancelCheckout { document: Some("part".into()), path: None })).unwrap();
    assert!(runtime.may_save(alias.to_str().unwrap()).unwrap_err().contains("Wait for the managed operation"));
    assert_eq!(std::fs::read(&original).unwrap(), b"unchanged");
    runtime.finish(id, Err(Failure { message: "No local replacement".into(), disconnect: false })).unwrap();
    runtime.may_save(alias.to_str().unwrap()).unwrap();
    std::fs::remove_dir_all(folder).unwrap();
}

#[test]
fn guided_public_requests_validate_before_queue_and_preserve_the_design() {
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    let before = session.doc.clone();
    let secret = "do-not-record-credentials";
    for (command, parameters) in [
        ("pdm.setup.create", json!({"label":"Archive","administrator":"admin","token":secret})),
        ("pdm.setup.create", json!({"label":"Archive\nOther","administrator":"admin"})),
        ("pdm.setup.create", json!({"label":"Archive","administrator":"owner"})),
        ("pdm.setup.create", json!({"label":"Archive","administrator":"ADMIN"})),
        ("pdm.connection.open", json!({"connection_id":"../escape"})),
        ("pdm.connection.open", json!({"connection_id":"A".repeat(64)})),
        ("pdm.connection.recover", json!({"connection_id":"a".repeat(64)})),
        ("pdm.connections", json!({"credential":secret})),
        ("pdm.workspace.change", json!({"connection_id":"a".repeat(64),"path":"relative","expected_workspace":"workspace-a"})),
        (
            "pdm.workspace.change",
            json!({"connection_id":"a".repeat(64),"path":std::env::temp_dir(),"expected_workspace":"workspace-a","token":secret}),
        ),
    ] {
        let error = session.execute(command, &parameters).unwrap_err().to_string();
        assert!(!error.contains(secret));
        assert!(session.pdm.status().unwrap().busy.is_none());
        assert!(session.pdm.take_job().unwrap().is_none());
        assert_eq!(*session.doc, *before);
        assert!(session.undo.is_empty());
    }
    session.execute("pdm.setup.create", &json!({"label":"Archive","administrator":"admin"})).unwrap();
    assert!(
        matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Managed(ManagedTask::CreateLocal {label,administrator}) if label=="Archive" && administrator=="admin")
    );
    assert_eq!(*session.doc, *before);
}

#[test]
fn working_folder_change_binds_current_connection_and_blocks_file_io_until_completion() {
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    let active = ActiveConnection {
        id: "a".repeat(64),
        label: "Archive".into(),
        origin: "https://localhost:1".into(),
        server_id: "server".into(),
        account: "viewer".into(),
        role: "Viewer".into(),
    };
    let state = ManagedState {
        workspace: Some("workspace-a".into()),
        root: Some(std::env::temp_dir().join("old-pdm-workspace").to_string_lossy().into_owned()),
        server_id: Some("server".into()),
        ..Default::default()
    };
    let request = session.pdm.enqueue(Task::Connect { port: 1 }).unwrap();
    session
        .pdm
        .finish(request, Ok(Outcome::ManagedConnected { port: 1, state: state.clone(), connections: vec![], connection: active.clone() }))
        .unwrap();
    let before = session.doc.clone();
    for (id, workspace) in [("b".repeat(64), "workspace-a"), (active.id.clone(), "workspace-b")] {
        assert!(
            session
                .execute(
                    "pdm.workspace.change",
                    &json!({"connection_id":id,"path":std::env::temp_dir().join("new-pdm-workspace"),"expected_workspace":workspace})
                )
                .is_err()
        );
        assert!(session.pdm.status().unwrap().busy.is_none());
    }
    let request = session
        .execute(
            "pdm.workspace.change",
            &json!({"connection_id":active.id,"path":std::env::temp_dir().join("new-pdm-workspace"),"expected_workspace":"workspace-a"}),
        )
        .unwrap()["request"]
        .as_u64()
        .unwrap();
    assert!(
        matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Managed(ManagedTask::ChangeWorkspace {expected_workspace,..}) if expected_workspace=="workspace-a")
    );
    assert!(session.pdm.status().unwrap().blocking);
    assert!(session.pdm.blocks_path(std::env::temp_dir().join("ordinary.solidcraft").to_str().unwrap()));
    assert_eq!(*session.doc, *before);
    session.pdm.finish(request, Err(Failure { message: "destination refused".into(), disconnect: false })).unwrap();
    assert!(!session.pdm.blocks_path(std::env::temp_dir().join("ordinary.solidcraft").to_str().unwrap()));
    assert_eq!(session.pdm.status().unwrap().managed.workspace, state.workspace);
    assert_eq!(session.pdm.status().unwrap().connection, Some(active));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn working_folder_change_rejects_managed_and_historical_filesystem_aliases() {
    for historical in [false, true] {
        let temp = EpochTemp::new(if historical { "settings-history-alias" } else { "settings-managed-alias" });
        let original = temp.0.join("original.solidcraft");
        let alias = temp.0.join("outside-alias.solidcraft");
        let mut session = Session::default();
        session.execute("file.save", &json!({"path":original})).unwrap();
        std::fs::hard_link(&original, &alias).unwrap();
        session.execute("doc.open", &json!({"path":alias})).unwrap();
        session.pdm.set_available(true).unwrap();
        let mut state = managed_snapshot(original.to_str().unwrap(), "workspace-a", false);
        state.root = Some(temp.0.join("working").to_string_lossy().into_owned());
        if historical {
            state.local.clear();
            state.historical_paths.push(original.to_string_lossy().into_owned());
        }
        let active = ActiveConnection {
            id: "a".repeat(64),
            label: "Archive".into(),
            origin: "https://localhost:1".into(),
            server_id: "server".into(),
            account: "viewer".into(),
            role: "Viewer".into(),
        };
        let request = session.pdm.enqueue(Task::Connect { port: 1 }).unwrap();
        session.pdm.finish(request, Ok(Outcome::ManagedConnected { port: 1, state, connections: vec![], connection: active })).unwrap();
        assert!(!session.pdm_read_only);
        let memory = session.doc.clone();
        let error = session
            .execute(
                "pdm.workspace.change",
                &json!({
                    "connection_id":"a".repeat(64), "path":temp.0.join("new-working"), "expected_workspace":"workspace-a"
                }),
            )
            .unwrap_err();
        assert!(error.to_string().contains("Close managed documents"), "{error}");
        assert!(session.pdm.status().unwrap().busy.is_none());
        assert_eq!(*session.doc, *memory);
    }
}

#[test]
fn saved_inventory_never_establishes_or_replaces_authenticated_identity() {
    let runtime = Runtime::default();
    runtime.set_available(true).unwrap();
    let rows = vec![ConnectionSummary {
        id: "a".repeat(64),
        label: "Unverified label".into(),
        kind: ConnectionKind::Saved,
        stage: ConnectionStage::SavedUnverified,
    }];
    let id = runtime.enqueue(Task::Managed(ManagedTask::ListConnections)).unwrap();
    runtime.finish(id, Ok(Outcome::Connections(rows.clone()))).unwrap();
    assert!(runtime.status().unwrap().connection.is_none());
    assert!(runtime.status().unwrap().port.is_none());
    let active = ActiveConnection {
        id: "a".repeat(64),
        label: "Verified archive".into(),
        origin: "https://localhost:48231".into(),
        server_id: "server".into(),
        account: "actual-account".into(),
        role: "Viewer".into(),
    };
    let id = runtime.enqueue(Task::Managed(ManagedTask::OpenConnection { connection_id: active.id.clone() })).unwrap();
    runtime
        .finish(
            id,
            Ok(Outcome::ManagedConnected {
                port: 48231,
                state: managed_snapshot("managed.solidcraft", "a", false),
                connections: rows.clone(),
                connection: active.clone(),
            }),
        )
        .unwrap();
    let id = runtime.enqueue(Task::Managed(ManagedTask::ListConnections)).unwrap();
    runtime.finish(id, Ok(Outcome::Connections(rows))).unwrap();
    assert_eq!(runtime.status().unwrap().connection, Some(active.clone()));
    assert_eq!(runtime.enqueue(Task::Managed(ManagedTask::OpenConnection { connection_id: "b".repeat(64) })).unwrap_err(), "ui.pdm_connected");
    assert!(runtime.take_job().unwrap().is_none());
    assert_eq!(runtime.status().unwrap().connection, Some(active));
    apply_managed(&runtime, managed_snapshot("other.solidcraft", "b", false), true).unwrap();
    assert!(runtime.status().unwrap().connection.is_none(), "a new workspace snapshot must not inherit verified identity");
    assert!(runtime.may_save("managed.solidcraft").is_err());
}

#[test]
fn scoped_recovery_rejects_unsaved_active_work_before_queueing() {
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    let before = session.doc.clone();
    assert!(session.execute("pdm.connection.recover", &json!({"connection_id":"a".repeat(64),"restore":true})).is_err());
    assert!(session.pdm.take_job().unwrap().is_none());
    assert_eq!(*session.doc, *before);
}

#[test]
fn opaque_connection_recovery_blocks_registered_saved_editors_until_native_completion() {
    let mut session = connected();
    session.path = Some("known-workspace/part.solidcraft".into());
    session.mark_saved();
    apply_managed(&session.pdm, managed_snapshot("known-workspace/part.solidcraft", "workspace", true), false).unwrap();
    let before = session.doc.clone();
    let id = session.execute("pdm.connection.recover", &json!({"connection_id":"a".repeat(64),"restore":true})).unwrap()["request"].as_u64().unwrap();
    assert!(session.pdm.blocks_path(session.path.as_deref().unwrap()));
    assert!(session.pdm.may_save("another-destination.json").is_err());
    assert!(session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).is_err());
    assert_eq!(*session.doc, *before);
    session.pdm.finish(id, Err(Failure { message: "Recovery root unavailable; no files changed".into(), disconnect: false })).unwrap();
    assert!(!session.pdm.blocks_path(session.path.as_deref().unwrap()));
    session.pdm.may_save("another-destination.json").unwrap();
    assert!(session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap_err().to_string().contains("Reopen"));
    assert_eq!(*session.doc, *before);
}

struct EpochTemp(std::path::PathBuf);
impl EpochTemp {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("solidcraft-recovery-epoch-{label}-{}-{sequence}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}
impl Drop for EpochTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn epoch_editor(path: &std::path::Path) -> Session {
    let mut session = connected();
    session.execute("solid.box", &json!({"length":10,"width":20,"height":3})).unwrap();
    session.execute("file.save", &json!({"path":path})).unwrap();
    let request = session.pdm.enqueue(Task::Refresh).unwrap();
    session
        .pdm
        .finish(request, Ok(Outcome::ManagedRefreshed { port: 48231, state: managed_snapshot(path.to_str().unwrap(), "workspace", true) }))
        .unwrap();
    session
}

#[test]
fn recovery_success_failure_and_refresh_never_authorize_stale_clean_editor() {
    for guided in [false, true] {
        for success in [false, true] {
            let temp = EpochTemp::new("outcomes");
            let path = temp.0.join("part.solidcraft");
            let mut editor = epoch_editor(&path);
            assert!(!editor.is_dirty());
            let old_doc = editor.doc.clone();
            let task = if guided {
                ManagedTask::RecoverConnection { connection_id: "a".repeat(64) }
            } else {
                ManagedTask::Recover { port: 48231, root: temp.0.to_string_lossy().into_owned() }
            };
            let request = editor.pdm.enqueue(Task::Managed(task)).unwrap();
            assert_eq!(editor.pdm.recovery_epoch().unwrap(), 1);
            assert!(editor.pdm.begin_pdm_reload().is_err());
            // Native recovery replaces bytes while the clean editor still holds B.
            let recovered = Session::default();
            let recovered_bytes = solidcraft_io::write_design(&recovered.doc);
            std::fs::write(&path, &recovered_bytes).unwrap();
            let state = managed_snapshot(path.to_str().unwrap(), "workspace", true);
            let result = if success {
                Ok(Outcome::ManagedRefreshed { port: 48231, state })
            } else {
                Err(Failure { message: "recovery interrupted".into(), disconnect: false })
            };
            editor.pdm.finish(request, result).unwrap();
            let refresh = editor.pdm.enqueue(Task::Refresh).unwrap();
            editor
                .pdm
                .finish(refresh, Ok(Outcome::ManagedRefreshed { port: 48231, state: managed_snapshot(path.to_str().unwrap(), "workspace", true) }))
                .unwrap();
            assert_eq!(editor.pdm.recovery_epoch().unwrap(), 1);
            assert!(editor.pdm.managed_for_path(path.to_str().unwrap()).unwrap().checked_out);
            assert!(editor.execute("solid.box", &json!({"length":1,"width":2,"height":3})).is_err());
            assert!(editor.execute("file.save", &json!({})).is_err());
            assert!(editor.execute("assembly.bom", &json!({"path":path,"format":"json"})).is_err());
            assert!(editor.execute("pdm.archive", &json!({})).is_err());
            assert!(editor.execute("pdm.check_in", &json!({"document":"part"})).is_err());
            assert_eq!(*editor.doc, *old_doc);
            assert_eq!(std::fs::read(&path).unwrap(), recovered_bytes);
            assert!(!editor.is_dirty());
            assert!(editor.pdm.status().unwrap().busy.is_none());
            assert!(editor.pdm.take_job().unwrap().is_none());
            editor.execute("doc.open", &json!({"path":path})).unwrap();
            assert!(editor.doc.features.is_empty(), "verified reopen must load recovered A, not retain stale B");
            assert!(editor.check_pdm_reopen().is_ok());
        }
    }
}

#[test]
fn verified_reload_refreshes_only_that_editor_not_another_tab_or_copy() {
    let temp = EpochTemp::new("two-editors");
    let path = temp.0.join("part.solidcraft");
    let mut first = epoch_editor(&path);
    let mut second = Session { pdm: first.pdm.clone(), ..Default::default() };
    second.execute("doc.open", &json!({"path":path})).unwrap();
    let request = first.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
    first.pdm.finish(request, Err(Failure { message: "recovery failed".into(), disconnect: false })).unwrap();
    first.execute("doc.open", &json!({"path":path})).unwrap();
    assert_eq!(first.pdm_recovery_epoch, 1);
    assert!(first.check_pdm_reopen().is_ok());
    assert!(second.check_pdm_reopen().is_err());
    let before = std::fs::read(&path).unwrap();
    let old_epoch = second.pdm_recovery_epoch;
    assert!(second.execute("file.save_as", &json!({"path":temp.0.join("missing").join("copy.solidcraft")})).is_err());
    assert_eq!(second.pdm_recovery_epoch, old_epoch);
    assert_eq!(second.path.as_deref(), path.to_str());
    let copy = temp.0.join("copy.solidcraft");
    second.execute("file.save_as", &json!({"path":copy})).unwrap();
    assert_eq!(second.pdm_recovery_epoch, 1);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(second.check_pdm_reopen().is_ok());
    // A third cached editor remains stale even after both other editors proceed.
    let mut third = Session { path: Some(path.to_string_lossy().into_owned()), pdm: first.pdm.clone(), ..Default::default() };
    assert!(third.execute("file.save", &json!({})).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn recovery_between_read_start_and_stamp_cannot_authorize_cached_bytes() {
    let temp = EpochTemp::new("async-race");
    let path = temp.0.join("part.solidcraft");
    let mut editor = epoch_editor(&path);
    let captured = editor.pdm.begin_pdm_reload().unwrap();
    let request = editor.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
    assert!(editor.mark_pdm_reloaded_from(captured).is_err());
    editor.pdm.finish(request, Err(Failure { message: "failed".into(), disconnect: false })).unwrap();
    assert!(editor.mark_pdm_reloaded_from(captured).is_err());
    assert_eq!(editor.pdm_recovery_epoch, 0);
    assert!(editor.check_pdm_reopen().is_err());
    editor.execute("doc.open", &json!({"path":path})).unwrap();
    assert_eq!(editor.pdm_recovery_epoch, 1);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn stale_editor_cannot_export_over_a_native_hardlink_alias() {
    let temp = EpochTemp::new("hardlink");
    let path = temp.0.join("part.solidcraft");
    let alias = temp.0.join("alias.solidcraft");
    let mut editor = epoch_editor(&path);
    std::fs::hard_link(&path, &alias).unwrap();
    let before = std::fs::read(&path).unwrap();
    let request = editor.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
    editor.pdm.finish(request, Err(Failure { message: "failed".into(), disconnect: false })).unwrap();
    assert!(editor.execute("file.save", &json!({"path":alias})).is_err());
    assert!(editor.execute("assembly.bom", &json!({"path":alias,"format":"json"})).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read(&alias).unwrap(), before);
}

#[test]
fn unnamed_editor_is_editable_and_stamps_epoch_only_after_new_file_success() {
    let temp = EpochTemp::new("unnamed");
    let mut editor = connected();
    let request = editor.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
    editor.pdm.finish(request, Err(Failure { message: "failed".into(), disconnect: false })).unwrap();
    editor.execute("solid.box", &json!({"length":1,"width":2,"height":3})).unwrap();
    assert_eq!(editor.pdm_recovery_epoch, 0);
    assert!(editor.execute("file.save", &json!({"path":temp.0.join("missing").join("first.solidcraft")})).is_err());
    assert_eq!(editor.pdm_recovery_epoch, 0);
    assert!(editor.path.is_none());
    editor.execute("file.save", &json!({"path":temp.0.join("first.solidcraft")})).unwrap();
    assert_eq!(editor.pdm_recovery_epoch, 1);
    assert!(editor.check_pdm_reopen().is_ok());
}

#[test]
fn recovery_epoch_exhaustion_and_poison_fail_closed_for_saved_editors() {
    let temp = EpochTemp::new("failed-protection");
    let path = temp.0.join("part.solidcraft");
    let mut editor = epoch_editor(&path);
    editor.pdm.0.lock().unwrap().recovery_epoch = u64::MAX;
    editor.pdm_recovery_epoch = u64::MAX;
    let bytes = std::fs::read(&path).unwrap();
    assert!(editor.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).is_err());
    assert_eq!(editor.pdm.0.lock().unwrap().recovery_epoch, u64::MAX);
    assert!(editor.execute("file.save", &json!({})).is_err());
    assert!(editor.execute("solid.box", &json!({"length":1,"width":2,"height":3})).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let runtime = Runtime::default();
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _state = runtime.0.lock().unwrap();
        panic!("test-only PDM runtime poisoning");
    }));
    assert!(poisoned.is_err());
    assert!(runtime.requires_reopen(0, Some(path.to_str().unwrap())));
    assert!(runtime.begin_pdm_reload().is_err());
}

fn policy_status() -> Status {
    Status {
        available: true,
        port: Some(48231),
        connection: Some(ActiveConnection {
            id: "a".repeat(64),
            label: "Toy".into(),
            origin: "https://localhost".into(),
            server_id: "server".into(),
            account: "alice".into(),
            role: "Contributor".into(),
        }),
        managed: ManagedState {
            catalog: vec![CatalogEntry {
                document: "part".into(),
                logical_path: "part.solidcraft".into(),
                head: Some(2),
                checkout: None,
                head_checked_in_unix_ms: None,
                head_author: None,
            }],
            ..managed_snapshot("/workspace/part.solidcraft", "a", false)
        },
        ..Status::default()
    }
}

#[test]
fn namespace_policy_requires_negotiated_metadata_role_and_no_checkout() {
    let mut status = policy_status();
    assert_eq!(status.action_unavailable("pdm.rename", Some("part"), None, false, false, None), Some("ui.pdm_namespace_unavailable"));
    status.managed.namespace = NamespaceState {
        supported: true,
        can_mutate: true,
        entries: vec![NamespaceEntry { document: "part".into(), materialization_path: "part.solidcraft".into(), revision: 3, tombstoned: false }],
    };
    assert_eq!(status.action_unavailable("pdm.rename", Some("part"), None, true, false, None), None);
    status.managed.catalog[0].checkout =
        Some(Checkout { owner: "alice".into(), workspace: "a".into(), machine: "machine".into(), checked_out_unix_ms: 1, base_version: Some(2) });
    assert!(status.action_unavailable("pdm.delete", Some("part"), None, false, false, None).is_some());
    status.managed.catalog[0].checkout = None;
    status.connection.as_mut().unwrap().role = "Viewer".into();
    assert_eq!(status.action_unavailable("pdm.delete", Some("part"), None, false, false, None), Some("ui.pdm_reason_viewer"));
    status.connection = None;
    assert!(status.action_unavailable("pdm.rename", Some("part"), None, false, false, None).is_some());
}

#[test]
fn renamed_design_uses_immutable_locator_for_attachment_classification() {
    let mut status = policy_status();
    status.managed.catalog[0].logical_path = "renamed.txt".into();
    status.managed.namespace.entries =
        vec![NamespaceEntry { document: "part".into(), materialization_path: "part.solidcraft".into(), revision: 1, tombstoned: false }];
    assert_eq!(status.attachment_path(Some("part")), None);
    status.managed.namespace.entries[0].materialization_path = "original.txt".into();
    status.managed.catalog[0].logical_path = "renamed.solidcraft".into();
    assert!(status.attachment_path(Some("part")).is_some());
}

#[test]
fn action_policy_requires_verified_checkout_here_and_distinguishes_other_reservations() {
    let mut status = policy_status();
    status.managed.local[0].base_version = 2;
    let path = Some("/workspace/part.solidcraft");
    let action = |status: &Status, command| status.action_unavailable(command, Some("part"), path, false, false, Some(1));
    assert_eq!(status.document_state(Some("part"), path, false), "ui.pdm_state_archived");
    assert_eq!(action(&status, "pdm.archive"), Some("ui.pdm_reason_checkout_required"));
    assert_eq!(action(&status, "pdm.checkout"), None);
    assert_eq!(action(&status, "pdm.cancel_checkout"), Some("ui.pdm_reason_checkout_required"));
    assert_eq!(action(&status, "pdm.get_latest"), Some("ui.pdm_reason_up_to_date"));
    assert_eq!(action(&status, "pdm.restore_version"), None);
    status.managed.catalog[0].checkout =
        Some(Checkout { owner: "alice".into(), workspace: "a".into(), machine: "desktop".into(), checked_out_unix_ms: 1, base_version: Some(2) });
    assert_eq!(action(&status, "pdm.archive"), Some("ui.pdm_reason_checked_out_elsewhere"));
    status.managed.local[0].checked_out = true;
    assert_eq!(action(&status, "pdm.archive"), None);
    assert_eq!(action(&status, "pdm.cancel_checkout"), None);
    assert_eq!(action(&status, "pdm.checkout"), Some("ui.pdm_reason_checked_out_here"));
    assert_eq!(status.document_state(Some("part"), path, true), "ui.pdm_state_modified");
    status.managed.catalog[0].checkout.as_mut().unwrap().workspace = "other-device".into();
    assert_eq!(action(&status, "pdm.archive"), Some("ui.pdm_reason_checked_out_elsewhere"));
    status.managed.catalog[0].checkout.as_mut().unwrap().owner = "bob".into();
    assert_eq!(action(&status, "pdm.cancel_checkout"), Some("ui.pdm_reason_checked_out_other"));
    assert_eq!(status.document_state(Some("part"), path, false), "ui.pdm_state_checked_out_other");
}

#[test]
fn action_policy_covers_busy_offline_dirty_stale_initial_archive_and_selection_mismatch() {
    let mut status = policy_status();
    assert_eq!(status.action_unavailable("pdm.archive", None, Some("/workspace/new.solidcraft"), false, false, None), None);
    assert_eq!(
        status.action_unavailable("pdm.archive", Some("part"), Some("/workspace/new.solidcraft"), false, false, None),
        Some("ui.pdm_reason_open_selected")
    );
    assert_eq!(status.action_unavailable("pdm.checkout", None, None, false, false, None), Some("ui.pdm_reason_select_document"));
    assert_eq!(status.action_unavailable("pdm.checkout", Some("part"), None, true, false, None), Some("ui.pdm_reason_open_selected"));
    assert_eq!(status.action_unavailable("pdm.restore_version", Some("part"), None, false, false, Some(1)), Some("ui.pdm_reason_stale_base"));
    assert_eq!(status.document_state(Some("part"), None, false), "ui.pdm_state_outdated");
    status.connection.as_mut().unwrap().role = "Viewer".into();
    assert_eq!(status.action_unavailable("pdm.checkout", Some("part"), None, false, false, None), Some("ui.pdm_reason_viewer"));
    status.busy = Some(3);
    assert_eq!(status.action_unavailable("pdm.checkout", Some("part"), None, false, false, None), Some("ui.pdm_reason_busy"));
    assert_eq!(status.document_state(Some("part"), None, false), "ui.pdm_state_busy");
    status.busy = None;
    status.port = None;
    assert_eq!(status.action_unavailable("pdm.checkout", Some("part"), None, false, false, None), Some("ui.pdm_reason_disconnected"));
}

#[test]
fn action_policy_checks_working_folder_and_native_dependency_update_flags() {
    let mut status = policy_status();
    status.managed.root = Some("/workspace".into());
    status.managed.local[0].base_version = 2;
    assert_eq!(
        status.action_unavailable("pdm.archive", None, Some("/outside/new.solidcraft"), false, false, None),
        Some("ui.pdm_reason_working_folder")
    );
    assert_eq!(
        status.action_unavailable("pdm.archive", None, Some("/workspace-other/new.solidcraft"), false, false, None),
        Some("ui.pdm_reason_working_folder")
    );
    assert_eq!(status.action_unavailable("pdm.archive", None, Some("/workspace/new.solidcraft"), false, false, None), None);
    status.managed.dependency_updates.push("part".into());
    assert_eq!(status.action_unavailable("pdm.get_latest", Some("part"), None, false, false, None), None);
    assert_eq!(status.document_state(Some("part"), None, false), "ui.pdm_state_outdated");
}

#[test]
fn managed_action_queue_rejects_duplicates_and_archive_without_checkout() {
    let session = connected();
    let snapshot = policy_status().managed;
    apply_managed(&session.pdm, snapshot, false).unwrap();
    let task = Task::Managed(ManagedTask::Checkout { document: Some("part".into()), path: None });
    let id = session.pdm.enqueue(task.clone()).unwrap();
    assert!(session.pdm.enqueue(task.clone()).is_err());
    session.pdm.finish(id, Err(Failure { message: "offline".into(), disconnect: false })).unwrap();
    assert!(session.pdm.status().unwrap().managed.catalog[0].checkout.is_none());
    assert_eq!(session.pdm.enqueue(task.clone()).unwrap_err(), "ui.pdm_reason_refresh_required");
    let inventory = session.pdm.enqueue(Task::Managed(ManagedTask::ListConnections)).unwrap();
    session.pdm.finish(inventory, Ok(Outcome::Connections(vec![]))).unwrap();
    assert_eq!(session.pdm.enqueue(task.clone()).unwrap_err(), "ui.pdm_reason_refresh_required", "saved metadata is not fresh server authority");
    let refresh = session.pdm.enqueue(Task::Refresh).unwrap();
    session.pdm.finish(refresh, Ok(Outcome::ManagedRefreshed { port: 48231, state: policy_status().managed })).unwrap();
    let id = session.pdm.enqueue(task).unwrap();
    session.pdm.finish(id, Ok(Outcome::Managed { port: 48231, state: policy_status().managed })).unwrap();
    let archive = Task::Managed(ManagedTask::Archive {
        path: "/workspace/part.solidcraft".into(),
        logical_path: None,
        saved: session.doc.clone(),
        visibility: Box::new(session.visibility.clone()),
    });
    assert_eq!(session.pdm.enqueue(archive).unwrap_err(), "ui.pdm_reason_checkout_required");
    assert!(session.pdm.take_job().unwrap().is_none());
}

#[test]
fn receipt_only_reconciliation_can_queue_after_reconnect_but_never_ordinary_archive() {
    let mut session = connected();
    let path = "/workspace/part.solidcraft";
    let mut state = policy_status().managed;
    state.local[0].checked_out = false;
    apply_managed(&session.pdm, state, false).unwrap();
    session.path = Some(path.into());
    session.mark_saved();
    assert!(session.execute("pdm.archive", &json!({})).is_err());
    assert!(session.pdm.take_job().unwrap().is_none());
    let id = session.execute("pdm.archive", &json!({"reconcile":true})).unwrap()["request"].as_u64().unwrap();
    assert!(matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Managed(ManagedTask::ReconcileArchive { .. })));
    session.pdm.finish(id, Err(Failure { message: "No matching receipt".into(), disconnect: false })).unwrap();
    assert!(session.execute("pdm.archive", &json!({})).is_err());
    let id = session.execute("pdm.archive", &json!({"reconcile":true})).unwrap()["request"].as_u64().unwrap();
    session.pdm.finish(id, Err(Failure { message: "Still no matching receipt".into(), disconnect: false })).unwrap();
    assert!(session.execute("pdm.archive", &json!({"document":"other","reconcile":true})).is_err());
    assert!(session.execute("pdm.archive", &json!({"reconcile":"yes"})).is_err());
}

#[test]
fn native_incomplete_checkout_proof_allows_release_only_and_never_publication() {
    let mut status = policy_status();
    status.managed.local.clear();
    status.managed.catalog[0].checkout =
        Some(Checkout { owner: "alice".into(), workspace: "a".into(), machine: "desktop".into(), checked_out_unix_ms: 1, base_version: Some(2) });
    assert_eq!(status.action_unavailable("pdm.cancel_checkout", Some("part"), None, false, false, None), Some("ui.pdm_reason_checked_out_elsewhere"));
    status.managed.recoverable_checkouts.push("part".into());
    assert_eq!(status.document_state(Some("part"), None, false), "ui.pdm_state_checkout_incomplete");
    assert_eq!(status.action_unavailable("pdm.cancel_checkout", Some("part"), None, false, false, None), None);
    assert!(status.action_unavailable("pdm.archive", Some("part"), Some("/workspace/part.solidcraft"), false, false, None).is_some());
    assert!(status.action_unavailable("pdm.checkout", Some("part"), None, false, false, None).is_some());
    status.managed.catalog[0].checkout.as_mut().unwrap().owner = "bob".into();
    assert_eq!(status.action_unavailable("pdm.cancel_checkout", Some("part"), None, false, false, None), Some("ui.pdm_reason_checked_out_other"));
    status.managed.catalog[0].checkout.as_mut().unwrap().owner = "alice".into();
    status.managed.catalog[0].checkout.as_mut().unwrap().workspace = "other-device".into();
    assert_eq!(status.action_unavailable("pdm.cancel_checkout", Some("part"), None, false, false, None), Some("ui.pdm_reason_checked_out_elsewhere"));
}

fn feedback_connection_session(guided: bool) -> Session {
    let session = Session::default();
    session.pdm.set_available(true).unwrap();
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    let outcome = if guided {
        let status = policy_status();
        Outcome::ManagedConnected { port: 48231, state: status.managed, connections: vec![], connection: status.connection.unwrap() }
    } else {
        Outcome::Connected { port: 48231, versions: vec![] }
    };
    session.pdm.finish(id, Ok(outcome)).unwrap();
    session
}

#[test]
fn feedback_connection_shared_policy_disables_connected_and_pending_connection_actions() {
    let mut status = Status { available: true, ..Default::default() };
    for command in ["pdm.connect", "pdm.connection.open", "pdm.setup.create"] {
        assert_eq!(status.action_unavailable(command, None, None, false, false, None), None);
    }
    status.busy = Some(1);
    assert_eq!(status.action_unavailable("pdm.connect", None, None, false, false, None), Some("ui.pdm_reason_busy"));
    status.busy = None;
    status.port = Some(48231);
    for command in ["pdm.connect", "pdm.connection.open", "pdm.setup.create"] {
        assert_eq!(status.action_unavailable(command, None, None, false, false, None), Some("ui.pdm_connected"));
    }
    assert_eq!(status.action_unavailable("pdm.disconnect", None, None, false, false, None), None);
    assert_eq!(status.action_unavailable("pdm.connections", None, None, false, false, None), None);
    assert_eq!(status.action_unavailable("pdm.connection.recover", None, None, false, false, None), None);
    assert_eq!(status.action_unavailable("pdm.recover_workspace", None, None, false, false, None), None);
}

#[test]
fn feedback_connection_runtime_rejects_repeated_connection_mutations_after_native_confirmation() {
    for guided in [false, true] {
        for task in [
            Task::Connect { port: 48232 },
            Task::Managed(ManagedTask::Connect { port: 48232, root: Some("/workspace".into()) }),
            Task::Managed(ManagedTask::OpenConnection { connection_id: "a".repeat(64) }),
            Task::Managed(ManagedTask::CreateLocal { label: "Another archive".into(), administrator: "admin".into() }),
        ] {
            let session = feedback_connection_session(guided);
            assert_eq!(session.pdm.enqueue(task).unwrap_err(), "ui.pdm_connected");
            assert!(session.pdm.take_job().unwrap().is_none());
            let status = session.pdm.status().unwrap();
            assert_eq!(status.port, Some(48231));
            assert!(status.busy.is_none());
        }
    }
}

#[test]
fn feedback_connection_command_handlers_cannot_queue_a_second_connection() {
    for guided in [false, true] {
        for (command, params) in [
            ("pdm.connect", json!({"port":48232})),
            ("pdm.connect", json!({"port":48232,"root":"/workspace"})),
            ("pdm.connection.open", json!({"connection_id":"a".repeat(64)})),
            ("pdm.setup.create", json!({"label":"Another archive","administrator":"admin"})),
        ] {
            let mut session = feedback_connection_session(guided);
            assert!(session.execute(command, &params).is_err(), "{command}");
            assert!(session.pdm.take_job().unwrap().is_none());
            assert!(session.pdm.status().unwrap().busy.is_none());
        }
    }
}

#[test]
fn feedback_connection_pending_and_real_disconnection_control_reconnect_availability() {
    let session = Session::default();
    session.pdm.set_available(true).unwrap();
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    assert!(session.pdm.enqueue(Task::Connect { port: 48231 }).is_err());
    session.pdm.finish(id, Err(Failure { message: "Service unavailable".into(), disconnect: true })).unwrap();
    assert!(session.pdm.status().unwrap().port.is_none());
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session.pdm.finish(id, Ok(Outcome::Connected { port: 48231, versions: vec![] })).unwrap();
    let id = session.pdm.enqueue(Task::Refresh).unwrap();
    session.pdm.finish(id, Err(Failure { message: "Metadata request failed".into(), disconnect: false })).unwrap();
    let status = session.pdm.status().unwrap();
    assert_eq!(status.port, Some(48231));
    assert_eq!(status.action_unavailable("pdm.connect", None, None, false, false, None), Some("ui.pdm_connected"));
    assert_eq!(status.action_unavailable("pdm.disconnect", None, None, false, false, None), None);
    let id = session.pdm.enqueue(Task::Refresh).unwrap();
    session.pdm.finish(id, Err(Failure { message: "Connection closed".into(), disconnect: true })).unwrap();
    assert!(session.pdm.status().unwrap().port.is_none());
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session.pdm.finish(id, Ok(Outcome::Connected { port: 48231, versions: vec![] })).unwrap();
}

#[test]
fn feedback_connection_disconnect_keeps_dirty_design_and_existing_checkout_protection() {
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    let mut state = managed_snapshot("/workspace/owned.solidcraft", "a", true);
    state.local.push(LocalEntry {
        document: "archived".into(),
        path: "/workspace/archived.solidcraft".into(),
        relative_path: "archived.solidcraft".into(),
        base_version: 1,
        sha256: "ab".repeat(32),
        checked_out: false,
        modified: false,
        present: true,
    });
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session.pdm.finish(id, Ok(Outcome::Managed { port: 48231, state })).unwrap();
    session.execute("solid.box", &json!({"length":1,"width":2,"height":3})).unwrap();
    let dirty = session.doc.clone();
    assert!(session.is_dirty());
    let id = session.execute("pdm.disconnect", &json!({})).unwrap()["request"].as_u64().unwrap();
    assert!(matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Disconnect));
    session.pdm.finish(id, Ok(Outcome::Disconnected)).unwrap();
    assert_eq!(*session.doc, *dirty);
    assert!(session.is_dirty());
    assert!(session.pdm.managed_for_path("/workspace/owned.solidcraft").unwrap().checked_out);
    assert!(session.pdm.may_save("/workspace/owned.solidcraft").is_ok());
    assert!(session.pdm.may_save("/workspace/archived.solidcraft").is_err());
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session.pdm.finish(id, Ok(Outcome::Connected { port: 48231, versions: vec![] })).unwrap();
    let id = session.pdm.enqueue(Task::Managed(ManagedTask::ListConnections)).unwrap();
    session.pdm.finish(id, Ok(Outcome::Connections(vec![]))).unwrap();
    let id = session.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
    session.pdm.finish(id, Err(Failure { message: "Explicit recovery not performed in this fixture".into(), disconnect: false })).unwrap();
}

fn autosave_status(checked_out: bool) -> Status {
    let mut status = policy_status();
    status.managed.local[0].base_version = 2;
    status.managed.local[0].checked_out = checked_out;
    if checked_out {
        status.managed.catalog[0].checkout =
            Some(Checkout { owner: "alice".into(), workspace: "a".into(), machine: "desktop".into(), checked_out_unix_ms: 1, base_version: Some(2) });
    }
    status
}

#[test]
fn autosave_archive_policy_allows_dirty_owned_working_copy_but_never_wrong_target() {
    let status = autosave_status(true);
    assert_eq!(status.action_unavailable("pdm.archive", Some("part"), Some("/workspace/part.solidcraft"), true, false, None), None);
    assert!(status.action_unavailable("pdm.archive", Some("part"), Some("/workspace/other.solidcraft"), true, false, None).is_some());
    assert!(status.action_unavailable("pdm.archive", Some("part"), Some("/workspace/part.solidcraft"), true, true, None).is_some());
    assert!(status.action_unavailable("pdm.archive", Some("part"), None, true, false, None).is_some());
}

#[test]
fn autosave_archive_raw_handler_refuses_unsaved_memory_without_queueing_saved_disk_bytes() {
    let temp = EpochTemp::new("archive-memory");
    let path = temp.0.join("part.solidcraft");
    let mut session = Session::default();
    session.execute("file.save", &json!({"path":path})).unwrap();
    let before = std::fs::read(&path).unwrap();
    session.pdm.set_available(true).unwrap();
    let mut status = autosave_status(true);
    status.managed.local[0].path = path.to_string_lossy().into_owned();
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session.pdm.finish(id, Ok(Outcome::Managed { port: 48231, state: status.managed })).unwrap();
    session.execute("solid.box", &json!({"length":4,"width":5,"height":6})).unwrap();
    let memory = session.doc.clone();
    assert!(session.execute("pdm.archive", &json!({"document":"part"})).is_err());
    assert!(session.pdm.take_job().unwrap().is_none());
    assert_eq!(*session.doc, *memory);
    assert!(session.is_dirty());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn autosave_checkout_policy_preserves_dirty_memory_only_at_the_current_matching_base() {
    let mut status = autosave_status(false);
    let path = Some("/workspace/part.solidcraft");
    assert_eq!(status.action_unavailable("pdm.checkout", Some("part"), path, true, false, None), None);
    assert!(status.action_unavailable("pdm.checkout", Some("part"), Some("/workspace/other.solidcraft"), true, false, None).is_some());
    status.managed.local[0].modified = true;
    assert_eq!(status.action_unavailable("pdm.checkout", Some("part"), path, true, false, None), Some("ui.pdm_reason_modified"));
    status.managed.local[0].modified = false;
    status.managed.local[0].base_version = 1;
    assert_eq!(status.action_unavailable("pdm.checkout", Some("part"), path, true, false, None), Some("ui.pdm_reason_stale_base"));
    status.managed.local[0].base_version = 2;
    status.managed.catalog[0].checkout =
        Some(Checkout { owner: "bob".into(), workspace: "b".into(), machine: "desktop".into(), checked_out_unix_ms: 1, base_version: Some(2) });
    assert_eq!(status.action_unavailable("pdm.checkout", Some("part"), path, true, false, None), Some("ui.pdm_reason_checked_out_other"));
}

#[test]
fn discard_checkout_dirty_owned_copy_requires_explicit_acknowledgement_before_queue() {
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    let status = autosave_status(true);
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session.pdm.finish(id, Ok(Outcome::Managed { port: 48231, state: status.managed })).unwrap();
    session.path = Some("/workspace/part.solidcraft".into());
    session.execute("solid.box", &json!({"length":4,"width":5,"height":6})).unwrap();
    let memory = session.doc.clone();
    assert!(session.execute("pdm.cancel_checkout", &json!({"document":"part"})).is_err());
    assert!(session.pdm.take_job().unwrap().is_none());
    assert_eq!(
        session.pdm.status().unwrap().action_unavailable("pdm.cancel_checkout", Some("part"), session.path.as_deref(), true, false, None),
        None
    );
    let id = session.execute("pdm.cancel_checkout", &json!({"document":"part","discard":true})).unwrap()["request"].as_u64().unwrap();
    assert!(
        matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Managed(ManagedTask::CancelCheckout { document: Some(document), .. }) if document == "part")
    );
    assert_eq!(*session.doc, *memory, "RAM remains intact until the explicitly confirmed native operation succeeds");
    assert!(session.is_dirty());
    session.pdm.finish(id, Err(Failure { message: "Offline; checkout was not released".into(), disconnect: false })).unwrap();
    assert_eq!(*session.doc, *memory);
    assert!(session.is_dirty());
    let id = session.execute("pdm.cancel_checkout", &json!({"document":"part","discard":true})).unwrap()["request"].as_u64().unwrap();
    session.pdm.finish(id, Err(Failure { message: "Server still unavailable; no completion".into(), disconnect: false })).unwrap();
    assert_eq!(*session.doc, *memory);
}

fn autosave_editor_with_status(status: Status) -> Session {
    let mut session = Session::default();
    session.pdm.set_available(true).unwrap();
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session
        .pdm
        .finish(id, Ok(Outcome::ManagedConnected { port: 48231, state: status.managed, connections: vec![], connection: status.connection.unwrap() }))
        .unwrap();
    session.path = Some("/workspace/part.solidcraft".into());
    session.execute("solid.box", &json!({"length":4,"width":5,"height":6})).unwrap();
    session
}

#[test]
fn autosave_checkout_handler_queues_exact_base_without_replacing_or_saving_unsaved_memory() {
    let mut session = autosave_editor_with_status(autosave_status(false));
    let memory = session.doc.clone();
    let id = session.execute("pdm.checkout", &json!({"document":"part"})).unwrap()["request"].as_u64().unwrap();
    assert!(
        matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Managed(ManagedTask::CheckoutPreservingMemory { document, path, expected_base: 2 }) if document == "part" && path == "/workspace/part.solidcraft")
    );
    assert!(session.pdm.blocks_path("/workspace/part.solidcraft"));
    assert!(session.pdm.may_save("/workspace/part.solidcraft").is_err());
    assert!(session.execute("solid.box", &json!({"length":1,"width":1,"height":1})).is_err());
    assert_eq!(*session.doc, *memory);
    assert!(session.is_dirty());
    session.pdm.finish(id, Err(Failure { message: "Checkout was not confirmed".into(), disconnect: false })).unwrap();
    assert_eq!(*session.doc, *memory);
    assert!(session.is_dirty());
}

#[test]
fn autosave_checkout_handler_rejects_stale_other_owner_missing_and_offline_targets() {
    for case in ["stale", "owner", "missing", "disk", "path", "offline"] {
        let mut status = autosave_status(false);
        match case {
            "stale" => status.managed.local[0].base_version = 1,
            "owner" => {
                status.managed.catalog[0].checkout = Some(Checkout {
                    owner: "bob".into(),
                    workspace: "b".into(),
                    machine: "other".into(),
                    checked_out_unix_ms: 1,
                    base_version: Some(2),
                })
            }
            "missing" => status.managed.local[0].present = false,
            "disk" => status.managed.local[0].modified = true,
            _ => {}
        }
        let mut session = autosave_editor_with_status(status);
        if case == "path" {
            session.path = Some("/workspace/other.solidcraft".into());
        }
        if case == "offline" {
            let id = session.pdm.enqueue(Task::Refresh).unwrap();
            session.pdm.finish(id, Err(Failure { message: "Connection closed".into(), disconnect: true })).unwrap();
        }
        let memory = session.doc.clone();
        assert!(session.execute("pdm.checkout", &json!({"document":"part"})).is_err(), "{case}");
        assert!(session.pdm.take_job().unwrap().is_none());
        assert_eq!(*session.doc, *memory);
        assert!(session.is_dirty());
    }
}

#[test]
fn autosave_checkout_preserving_memory_runtime_cannot_bypass_expected_base_or_recovery_fence() {
    let mut session = autosave_editor_with_status(autosave_status(false));
    assert!(
        session
            .pdm
            .enqueue(Task::Managed(ManagedTask::CheckoutPreservingMemory {
                document: "part".into(),
                path: "/workspace/part.solidcraft".into(),
                expected_base: 1
            }))
            .is_err()
    );
    assert!(session.pdm.take_job().unwrap().is_none());
    let id = session.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
    session.pdm.finish(id, Ok(Outcome::ManagedRefreshed { port: 48231, state: autosave_status(false).managed })).unwrap();
    assert!(session.check_pdm_reopen().is_err());
    assert!(session.execute("pdm.checkout", &json!({"document":"part"})).is_err());
    assert!(session.pdm.take_job().unwrap().is_none());
}

#[test]
fn discard_checkout_policy_allows_owned_retry_but_never_other_owner_or_disconnected_discard() {
    let mut status = autosave_status(true);
    status.error = Some("Previous server response was not confirmed".into());
    assert_eq!(status.action_unavailable("pdm.cancel_checkout", Some("part"), Some("/workspace/part.solidcraft"), true, false, None), None);
    assert_eq!(status.action_unavailable("pdm.cancel_checkout", Some("part"), Some("/workspace/other.solidcraft"), true, false, None), None);
    status.managed.catalog[0].checkout.as_mut().unwrap().owner = "bob".into();
    assert_eq!(
        status.action_unavailable("pdm.cancel_checkout", Some("part"), Some("/workspace/part.solidcraft"), true, false, None),
        Some("ui.pdm_reason_checked_out_other")
    );
    status.managed.catalog[0].checkout.as_mut().unwrap().owner = "alice".into();
    status.port = None;
    assert_eq!(
        status.action_unavailable("pdm.cancel_checkout", Some("part"), Some("/workspace/part.solidcraft"), true, false, None),
        Some("ui.pdm_reason_disconnected")
    );
}

#[test]
fn discard_checkout_explicit_selected_document_keeps_unrelated_active_dirty_memory() {
    let mut session = autosave_editor_with_status(autosave_status(true));
    session.path = Some("/workspace/other.solidcraft".into());
    let active_memory = session.doc.clone();
    assert!(session.is_dirty());
    assert_eq!(
        session.pdm.status().unwrap().action_unavailable("pdm.cancel_checkout", Some("part"), session.path.as_deref(), true, false, None),
        None
    );
    let id = session.execute("pdm.cancel_checkout", &json!({"document":"part","discard":true})).unwrap()["request"].as_u64().unwrap();
    assert!(
        matches!(session.pdm.take_job().unwrap().unwrap().task, Task::Managed(ManagedTask::CancelCheckout { document: Some(document), path: Some(path) }) if document == "part" && path == "/workspace/part.solidcraft")
    );
    assert_eq!(session.path.as_deref(), Some("/workspace/other.solidcraft"));
    assert_eq!(*session.doc, *active_memory);
    assert!(session.is_dirty());
    session.pdm.finish(id, Ok(Outcome::Managed { port: 48231, state: autosave_status(false).managed })).unwrap();
    assert_eq!(*session.doc, *active_memory);
    assert_eq!(session.path.as_deref(), Some("/workspace/other.solidcraft"));
    assert!(session.is_dirty());
}

#[test]
fn opt_in_ordinary_saved_editor_survives_recovery_of_managed_files_in_the_same_folder() {
    for success in [false, true] {
        let temp = EpochTemp::new("ordinary-opt-in");
        let managed_path = temp.0.join("managed.solidcraft");
        let ordinary_path = temp.0.join("ordinary.solidcraft");
        let managed = epoch_editor(&managed_path);
        let mut ordinary = Session { pdm: managed.pdm.clone(), ..Default::default() };
        ordinary.execute("file.save", &json!({"path":ordinary_path})).unwrap();
        let old_epoch = ordinary.pdm_recovery_epoch;
        let captured = ordinary.pdm.begin_pdm_reload().unwrap();
        let mut ordinary_candidate = Session::new(solidcraft_io::read_design(&std::fs::read(&ordinary_path).unwrap()).unwrap());
        ordinary_candidate.path = ordinary.path.clone();
        ordinary_candidate.pdm = ordinary.pdm.clone();
        let id = managed.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
        // Until opaque native preflight identifies the affected paths, repair
        // intentionally serializes file IO. This is temporary, not opt-in state.
        assert!(managed.pdm.blocks_path(managed_path.to_str().unwrap()));
        assert!(ordinary.pdm.blocks_path(ordinary_path.to_str().unwrap()));
        assert!(ordinary_candidate.mark_pdm_reloaded_from(captured).is_err());
        let result = if success {
            Ok(Outcome::ManagedRefreshed { port: 48231, state: managed_snapshot(managed_path.to_str().unwrap(), "workspace", true) })
        } else {
            Err(Failure { message: "Managed recovery did not complete".into(), disconnect: false })
        };
        managed.pdm.finish(id, result).unwrap();
        assert!(managed.check_pdm_reopen().is_err());
        assert!(ordinary.check_pdm_reopen().is_ok());
        assert!(ordinary_candidate.mark_pdm_reloaded_from(captured).is_ok(), "unrelated completed recovery must not invalidate ordinary file IO");
        ordinary.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
        ordinary.execute("file.save", &json!({})).unwrap();
        assert_eq!(ordinary.pdm_recovery_epoch, old_epoch, "ordinary editing does not need a PDM reload stamp");
        assert_eq!(solidcraft_io::read_design(&std::fs::read(&ordinary_path).unwrap()).unwrap(), *ordinary.doc);
        assert!(ordinary.pdm.managed_for_path(ordinary_path.to_str().unwrap()).is_none());
        assert!(!ordinary.pdm_read_only);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn opt_in_managed_and_historical_hardlink_aliases_keep_recovery_fences() {
    let temp = EpochTemp::new("scoped-aliases");
    let managed_path = temp.0.join("managed.solidcraft");
    let alias_path = temp.0.join("alias.solidcraft");
    let history_path = temp.0.join("history.solidcraft");
    let managed = epoch_editor(&managed_path);
    std::fs::hard_link(&managed_path, &alias_path).unwrap();
    let mut alias = Session { pdm: managed.pdm.clone(), ..Default::default() };
    alias.execute("doc.open", &json!({"path":alias_path})).unwrap();
    let mut historical = Session::default();
    historical.execute("file.save", &json!({"path":history_path})).unwrap();
    historical.pdm = managed.pdm.clone();
    let mut state = managed_snapshot(managed_path.to_str().unwrap(), "workspace", true);
    state.historical_paths.push(history_path.to_string_lossy().into_owned());
    let refresh = managed.pdm.enqueue(Task::Refresh).unwrap();
    managed.pdm.finish(refresh, Ok(Outcome::ManagedRefreshed { port: 48231, state })).unwrap();
    let captured = managed.pdm.begin_pdm_reload().unwrap();
    let id = managed.pdm.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
    assert!(managed.pdm.blocks_path(alias_path.to_str().unwrap()));
    assert!(managed.pdm.blocks_path(history_path.to_str().unwrap()));
    assert!(alias.mark_pdm_reloaded_from(captured).is_err());
    assert!(historical.mark_pdm_reloaded_from(captured).is_err());
    assert!(managed.pdm.may_save(alias_path.to_str().unwrap()).is_err());
    managed.pdm.finish(id, Err(Failure { message: "Recovery interrupted".into(), disconnect: false })).unwrap();
    assert!(alias.check_pdm_reopen().is_err());
    assert!(historical.check_pdm_reopen().is_err());
    assert!(alias.execute("file.save", &json!({})).is_err());
    assert!(historical.execute("file.save", &json!({})).is_err());
}

fn disconnect_private_metadata() -> (Session, ManagedState, ActiveConnection) {
    let session = Session::default();
    session.pdm.set_available(true).unwrap();
    let mut status = autosave_status(true);
    let reference = Reference { document: "part".into(), version: 1 };
    status.managed.history.push(ManagedVersion {
        version: Version { reference: reference.clone(), parent: None, sha256: "ab".repeat(32), dependencies: vec![] },
        author: "alice".into(),
        checked_in_unix_ms: 1,
        comment: "Private Alice history".into(),
        request_id: "alice-history".into(),
    });
    status.managed.where_used.push(Reference { document: "alice-parent".into(), version: 2 });
    status.managed.preview = Some(Preview { reference, sha256: "ab".repeat(32), png: vec![1, 2, 3] });
    status.managed.dependency_updates.push("part".into());
    status.managed.recoverable_checkouts.push("incomplete".into());
    let connection = status.connection.unwrap();
    let id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    session
        .pdm
        .finish(
            id,
            Ok(Outcome::ManagedConnected {
                port: 48231,
                state: status.managed.clone(),
                connections: vec![ConnectionSummary {
                    id: connection.id.clone(),
                    label: connection.label.clone(),
                    kind: ConnectionKind::Saved,
                    stage: ConnectionStage::SavedUnverified,
                }],
                connection: connection.clone(),
            }),
        )
        .unwrap();
    (session, status.managed, connection)
}

#[test]
fn disconnect_success_and_transport_loss_remove_remote_metadata_but_preserve_local_protection() {
    for transport_loss in [false, true] {
        let (mut session, before, _) = disconnect_private_metadata();
        session.execute("solid.box", &json!({"length":1,"width":2,"height":3})).unwrap();
        let document = session.doc.clone();
        let id = session.pdm.enqueue(if transport_loss { Task::Refresh } else { Task::Disconnect }).unwrap();
        session
            .pdm
            .finish(
                id,
                if transport_loss { Err(Failure { message: "Authentication lost".into(), disconnect: true }) } else { Ok(Outcome::Disconnected) },
            )
            .unwrap();
        let status = session.pdm.status().unwrap();
        assert!(status.port.is_none() && status.connection.is_none());
        assert!(status.managed.catalog.is_empty(), "remote catalog must not remain browseable after disconnect");
        assert!(status.managed.history.is_empty() && status.managed.where_used.is_empty() && status.managed.preview.is_none());
        assert!(status.managed.dependency_updates.is_empty() && status.managed.recoverable_checkouts.is_empty());
        assert!(status.versions.is_empty() && status.retrieved.is_none());
        assert_eq!(status.connections.len(), 1, "saved connection metadata must survive; it conveys no authenticated authority");
        assert_eq!(*session.doc, *document);
        assert!(session.is_dirty());
        let path = &before.local[0].path;
        assert!(session.pdm.is_managed_or_historical_path(path));
        assert!(session.pdm.managed_for_path(path).unwrap().checked_out, "legitimate local checkout/save protection survives disconnect");
        assert!(session.pdm.may_save(path).is_ok());
        for command in [
            "pdm.checkout",
            "pdm.archive",
            "pdm.cancel_checkout",
            "pdm.get_latest",
            "pdm.open_document",
            "pdm.open_archived",
            "pdm.restore_version",
            "pdm.history",
            "pdm.preview",
        ] {
            assert_eq!(
                status.action_unavailable(command, Some("part"), Some(path), false, false, Some(1)),
                Some("ui.pdm_reason_disconnected"),
                "{command}"
            );
        }
        assert!(session.pdm.enqueue(Task::Managed(ManagedTask::History { document: "part".into() })).is_err());
    }
}

#[test]
fn disconnect_late_old_account_result_cannot_replace_a_pending_or_connected_new_account() {
    let (session, old_state, old_connection) = disconnect_private_metadata();
    let old_id = session.pdm.enqueue(Task::Refresh).unwrap();
    session.pdm.take_job().unwrap().unwrap();
    session.pdm.finish(old_id, Err(Failure { message: "User A connection lost".into(), disconnect: true })).unwrap();
    let new_id = session.pdm.enqueue(Task::Connect { port: 48231 }).unwrap();
    let old_result = || Outcome::ManagedConnected { port: 48231, state: old_state.clone(), connections: vec![], connection: old_connection.clone() };
    assert!(session.pdm.finish(old_id, Ok(old_result())).is_err());
    assert_eq!(session.pdm.status().unwrap().busy, Some(new_id));
    let mut new_connection = old_connection.clone();
    new_connection.account = "bob".into();
    new_connection.role = "Viewer".into();
    let mut state = old_state.clone();
    state.catalog.clear();
    state.local.clear();
    state.history.clear();
    state.where_used.clear();
    state.preview = None;
    state.recoverable_checkouts.clear();
    state.dependency_updates.clear();
    session.pdm.finish(new_id, Ok(Outcome::ManagedConnected { port: 48231, state, connections: vec![], connection: new_connection })).unwrap();
    let snapshot = serde_json::to_value(session.pdm.status().unwrap()).unwrap();
    assert!(session.pdm.finish(old_id, Ok(old_result())).is_err());
    assert_eq!(serde_json::to_value(session.pdm.status().unwrap()).unwrap(), snapshot);
    assert_eq!(session.pdm.status().unwrap().connection.unwrap().account, "bob");
    assert!(!session.pdm.managed_for_path(&old_state.local[0].path).unwrap().checked_out);
    assert!(session.pdm.may_save(&old_state.local[0].path).is_err());
}

#[test]
fn disconnect_fresh_account_identity_never_inherits_previous_principals_detail_metadata() {
    let (session, mut state, mut connection) = disconnect_private_metadata();
    connection.account = "bob".into();
    connection.role = "Viewer".into();
    state.local.iter_mut().for_each(|entry| entry.checked_out = false);
    state.catalog.clear();
    state.history.clear();
    state.where_used.clear();
    state.preview = None;
    state.recoverable_checkouts.clear();
    state.dependency_updates.clear();
    let id = session.pdm.enqueue(Task::Refresh).unwrap();
    session.pdm.finish(id, Ok(Outcome::ManagedConnected { port: 48231, state, connections: vec![], connection })).unwrap();
    let status = session.pdm.status().unwrap();
    assert_eq!(status.connection.unwrap().account, "bob");
    assert!(
        status.managed.history.is_empty() && status.managed.where_used.is_empty() && status.managed.preview.is_none(),
        "same server/workspace is insufficient when the authenticated account changed"
    );
}

#[test]
fn disconnect_protection_ledger_failure_also_removes_previous_remote_metadata() {
    let (session, mut state, _) = disconnect_private_metadata();
    state.local[0].path = "x".repeat(MAX_PROTECTED_PATH_BYTES + 1);
    let id = session.pdm.enqueue(Task::Refresh).unwrap();
    assert!(session.pdm.finish(id, Ok(Outcome::ManagedRefreshed { port: 48231, state })).is_err());
    let status = session.pdm.status().unwrap();
    assert!(status.port.is_none() && status.connection.is_none());
    assert!(
        status.managed.catalog.is_empty()
            && status.managed.history.is_empty()
            && status.managed.where_used.is_empty()
            && status.managed.preview.is_none(),
        "fail-closed ledger rejection also invalidates remote display state"
    );
    assert!(session.pdm.is_managed_or_historical_path("/workspace/part.solidcraft"));
    assert!(session.pdm.may_save("/workspace/part.solidcraft").is_err());
    assert!(status.error.is_some());
}

#[test]
fn disconnect_same_account_new_connection_identity_does_not_inherit_old_private_metadata() {
    let (session, mut state, mut connection) = disconnect_private_metadata();
    connection.id = "b".repeat(64);
    state.history.clear();
    state.where_used.clear();
    state.preview = None;
    let id = session.pdm.enqueue(Task::Refresh).unwrap();
    session.pdm.finish(id, Ok(Outcome::ManagedConnected { port: 48231, state, connections: vec![], connection })).unwrap();
    let status = session.pdm.status().unwrap();
    assert_eq!(status.connection.unwrap().id, "b".repeat(64));
    assert!(status.managed.history.is_empty() && status.managed.where_used.is_empty() && status.managed.preview.is_none());
}
