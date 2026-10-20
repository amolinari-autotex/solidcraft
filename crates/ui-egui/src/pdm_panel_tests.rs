use crate::{
    pdm_panel::{Completion, Start},
    scenario::Harness,
};
use serde_json::json;
use solidcraft_engine::{
    Session,
    pdm::{Failure, ManagedTask, Outcome, Reference, Retrieved, Task, Version},
};
use std::sync::{Arc, Mutex, mpsc};

fn version() -> Version {
    Version {
        reference: Reference { document: "part".into(), version: 1 },
        parent: None,
        sha256: "00".repeat(32),
        dependencies: vec![Reference { document: "base".into(), version: 3 }],
    }
}
fn backend(held: Option<Arc<Mutex<Option<mpsc::Sender<Completion>>>>>) -> Start {
    Arc::new(move |job| {
        let (send, receive) = mpsc::channel();
        if let Some(held) = &held {
            *held.lock().unwrap() = Some(send);
            return receive;
        }
        let (outcome, open) = match job.task {
            Task::Managed(ManagedTask::Connect { port, .. }) => (Outcome::Connected { port, versions: vec![version()] }, None),
            Task::Managed(ManagedTask::History { .. }) => (Outcome::Listed(vec![version()]), None),
            Task::Managed(_) => (Outcome::Listed(vec![version()]), None),
            Task::Connect { port } => (Outcome::Connected { port, versions: vec![version()] }, None),
            Task::Disconnect => (Outcome::Disconnected, None),
            Task::Refresh => (Outcome::Managed { port: 48231, state: Default::default() }, None),
            Task::CheckIn { .. } => (Outcome::CheckedIn(Version { reference: Reference { document: "part".into(), version: 2 }, ..version() }), None),
            Task::Retrieve { reference, open } => {
                let mut session = Session::default();
                session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
                session.mark_saved();
                session.path = Some("new-private-copy.solidcraft".into());
                (
                    Outcome::Retrieved(Retrieved { reference, path: "new-private-copy.solidcraft".into(), versions: vec![version()] }),
                    open.then(|| Box::new(session)),
                )
            }
        };
        send.send(Completion { result: Ok(outcome), open }).unwrap();
        receive
    })
}
fn app() -> Harness {
    let mut h = Harness::new();
    h.app.services.pdm = Some(backend(None));
    h.app.start("pdm.panel");
    h.frames(3);
    h.step(&json!({"click":{"handle":"pdm:advanced"}})).unwrap();
    h.frames(3);
    h
}
fn connect(h: &mut Harness) {
    h.step(&json!({"click":{"handle":"pdm:connect"}})).unwrap();
    h.frames(5);
    h.app.pdm.open = false;
    h.app.pdm.document = "part".into();
    h.frames(2);
    assert_eq!(h.app.pdm.runtime.status().unwrap().port, Some(48231));
}

#[test]
fn actual_panel_connects_lists_pinned_dependencies_and_disconnects() {
    let mut h = app();
    connect(&mut h);
    h.step(&json!({"click":{"handle":"pdm:version:part:1"}})).unwrap();
    h.frames(2);
    assert_eq!(h.app.pdm.selected, Some(Reference { document: "part".into(), version: 1 }));
    h.app.pdm.detail_tab = 1;
    h.frames(2);
    assert!(h.widget("base · v3").is_some());
    h.app.pdm.open = true;
    // Reopening inventories saved connections before actions become available.
    h.frames(5);
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_none());
    h.step(&json!({"click":{"handle":"pdm:disconnect"}})).unwrap();
    h.frames(4);
    assert!(h.app.pdm.runtime.status().unwrap().port.is_none());
}

#[test]
fn retrieval_opens_a_new_tab_and_preserves_dirty_active_design_and_undo() {
    let mut h = app();
    connect(&mut h);
    h.app.run("solid.box", json!({"length":10,"width":20,"height":3})).unwrap();
    let before = h.app.session.doc.clone();
    let undo = h.app.session.undo.len();
    let active = h.app.docs.active;
    assert!(h.app.session.is_dirty());
    h.app.run("pdm.retrieve", json!({"document":"part","version":1})).unwrap();
    h.frames(5);
    assert_eq!(h.app.session.path.as_deref(), Some("new-private-copy.solidcraft"));
    assert!(!h.app.session.is_dirty());
    crate::documents::switch(&mut h.app, active);
    h.frames(2);
    assert_eq!(*h.app.session.doc, *before);
    assert_eq!(h.app.session.undo.len(), undo);
    assert!(h.app.session.is_dirty());
}

#[test]
fn full_tab_limit_never_replaces_dirty_design_on_retrieval() {
    let mut h = app();
    connect(&mut h);
    for _ in 1..crate::documents::MAX_OPEN {
        crate::documents::open_tab(&mut h.app, Session::default()).unwrap();
    }
    h.app.run("solid.box", json!({"length":10,"width":20,"height":3})).unwrap();
    let before = h.app.session.doc.clone();
    h.app.run("pdm.retrieve", json!({"document":"part","version":1})).unwrap();
    h.frames(5);
    assert_eq!(*h.app.session.doc, *before);
    assert!(h.app.session.is_dirty());
    assert_eq!(h.app.docs.count(), crate::documents::MAX_OPEN);
    assert!(h.app.pdm.runtime.status().unwrap().retrieved.is_some());
}

#[test]
fn completed_retrieval_waits_for_a_modelling_dialog_started_during_download() {
    let mut h = app();
    connect(&mut h);
    h.app.run("solid.box", json!({"length":10,"width":20,"height":3})).unwrap();
    let before = h.app.session.doc.clone();
    let active = h.app.docs.active;
    let held = Arc::new(Mutex::new(None));
    h.app.services.pdm = Some(backend(Some(held.clone())));
    h.app.run("pdm.retrieve", json!({"document":"part","version":1})).unwrap();
    h.frames(2);
    h.app.start("solid.box");
    assert!(h.app.dialog.is_some());
    h.app.start("pdm.panel");
    assert!(h.app.dialog.is_some());
    let mut loaded = Session::default();
    loaded.path = Some("new-private-copy.solidcraft".into());
    held.lock()
        .unwrap()
        .take()
        .unwrap()
        .send(Completion {
            result: Ok(Outcome::Retrieved(Retrieved {
                reference: version().reference,
                path: "new-private-copy.solidcraft".into(),
                versions: vec![version()],
            })),
            open: Some(Box::new(loaded)),
        })
        .unwrap();
    h.frames(4);
    assert_eq!(h.app.docs.active, active);
    assert!(h.app.dialog.is_some());
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_some());
    assert_eq!(*h.app.session.doc, *before);
    crate::dialogs::cancel(&mut h.app);
    h.frames(4);
    assert_eq!(h.app.session.path.as_deref(), Some("new-private-copy.solidcraft"));
    crate::documents::switch(&mut h.app, active);
    assert_eq!(*h.app.session.doc, *before);
    assert!(h.app.session.is_dirty());
}

#[test]
fn saved_check_in_uses_engine_guards_and_async_failure_keeps_the_document() {
    let mut h = app();
    connect(&mut h);
    h.app.run("solid.box", json!({"length":10,"width":20,"height":3})).unwrap();
    assert!(h.app.run("pdm.check_in", json!({"document":"part"})).is_err());
    h.app.run("file.save", json!({"path":h.dir.join("saved.solidcraft")})).unwrap();
    h.app.pdm.document = "part".into();
    h.app.pdm.parent = "1".into();
    h.frames(2);
    h.app.run("pdm.check_in", json!({"document":"part","parent":1})).unwrap();
    h.frames(5);
    assert_eq!(h.app.pdm.parent, "2");
    let before = h.app.session.doc.clone();
    let held = Arc::new(Mutex::new(None));
    h.app.services.pdm = Some(backend(Some(held.clone())));
    h.app.run("pdm.refresh", json!({})).unwrap();
    h.frames(2);
    assert!(h.app.run("pdm.disconnect", json!({})).is_err());
    held.lock()
        .unwrap()
        .take()
        .unwrap()
        .send(Completion { result: Err(Failure { message: "Local service unavailable".into(), disconnect: true }), open: None })
        .unwrap();
    h.frames(4);
    assert!(h.app.pdm.runtime.status().unwrap().port.is_none());
    assert_eq!(*h.app.session.doc, *before);
    assert!(!h.app.session.is_dirty());
    let prefs = serde_json::to_string(&h.app.prefs()).unwrap();
    assert!(!prefs.contains("SOLIDCRAFT_PDM_TOKEN"));
    assert!(!prefs.contains("pdm"));
}

#[test]
fn stale_worker_completion_cannot_open_a_tab_or_change_the_active_design() {
    let mut h = app();
    connect(&mut h);
    h.app.run("solid.box", json!({"length":10,"width":20,"height":3})).unwrap();
    let before = h.app.session.doc.clone();
    let count = h.app.docs.count();
    let held = Arc::new(Mutex::new(None));
    h.app.services.pdm = Some(backend(Some(held.clone())));
    h.app.run("pdm.retrieve", json!({"document":"part","version":1})).unwrap();
    h.frames(2);
    let id = h.app.pdm.runtime.status().unwrap().busy.unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::Disconnected)).unwrap();
    held.lock()
        .unwrap()
        .take()
        .unwrap()
        .send(Completion {
            result: Ok(Outcome::Retrieved(Retrieved { reference: version().reference, path: "stale-copy.solidcraft".into(), versions: vec![] })),
            open: Some(Box::new(Session::default())),
        })
        .unwrap();
    h.frames(4);
    assert_eq!(h.app.docs.count(), count);
    assert_eq!(*h.app.session.doc, *before);
    assert!(h.app.session.is_dirty());
    assert!(h.app.pdm.runtime.status().unwrap().retrieved.is_none());
}

#[test]
fn managed_reload_reuses_the_existing_tab_and_refuses_dirty_work() {
    let mut h = Harness::new();
    h.app.session.path = Some("managed.solidcraft".into());
    h.app.session.mark_saved();
    let count = h.app.docs.count();
    let mut replacement = Session::default();
    replacement.path = Some("managed.solidcraft".into());
    replacement.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    replacement.mark_saved();
    crate::documents::apply_managed(&mut h.app, replacement).unwrap();
    assert_eq!(h.app.docs.count(), count);
    assert_eq!(h.app.session.world_state().bodies.len(), 1);
    h.app.session.execute("solid.box", &json!({"length":5,"width":6,"height":7})).unwrap();
    let before = h.app.session.doc.clone();
    let mut replacement = Session::default();
    replacement.path = Some("managed.solidcraft".into());
    replacement.mark_saved();
    assert!(crate::documents::apply_managed(&mut h.app, replacement).is_err());
    assert_eq!(*h.app.session.doc, *before);
    assert!(h.app.session.is_dirty());
}

#[test]
fn managed_readonly_interactive_edit_prompts_before_starting_a_tool() {
    use solidcraft_engine::pdm::{LocalEntry, ManagedState};
    let mut h = Harness::new();
    h.app.pdm.runtime.set_available(true).unwrap();
    h.app.session.path = Some("managed.solidcraft".into());
    h.app.session.mark_saved();
    let id = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
    h.app
        .pdm
        .runtime
        .finish(
            id,
            Ok(Outcome::Managed {
                port: 48231,
                state: ManagedState {
                    local: vec![LocalEntry {
                        document: "part".into(),
                        path: "managed.solidcraft".into(),
                        relative_path: "managed.solidcraft".into(),
                        base_version: 1,
                        sha256: "00".repeat(32),
                        checked_out: false,
                        modified: false,
                        present: true,
                    }],
                    ..Default::default()
                },
            }),
        )
        .unwrap();
    h.app.start("solid.box");
    assert_eq!(h.app.pdm.pending_edit.as_deref(), Some("solid.box"));
    assert!(h.app.dialog.is_none());
    assert!(!h.app.session.is_dirty());
    assert!(h.app.pdm.runtime.may_save("managed.solidcraft").is_err());
}

#[test]
fn historical_snapshot_edit_prompts_and_cannot_be_checked_out_in_place() {
    let mut h = Harness::new();
    h.app.session.path = Some("history/snapshot.solidcraft".into());
    h.app.session.pdm_read_only = true;
    h.app.session.mark_saved();
    h.app.start("solid.box");
    assert_eq!(h.app.pdm.pending_edit.as_deref(), Some("solid.box"));
    assert!(h.app.dialog.is_none());
}

#[test]
fn workspace_switcher_opens_docked_archive_and_preserves_the_design() {
    let mut h = Harness::new();
    h.app.run("solid.box", json!({"length":10,"width":20,"height":3})).unwrap();
    let before = h.app.session.doc.clone();
    let undo = h.app.session.undo.len();
    h.frames(3);
    let at = crate::scenario::rect_of("workspace_switcher").unwrap().center();
    h.step(&json!({"click":[at.x,at.y]})).unwrap();
    h.step(&json!({"click":{"handle":"menu:ui.workspace.pdm"}})).unwrap();
    assert!(h.app.pdm.workspace_active);
    assert!(!h.app.pdm.open, "the main browser is docked, not a floating window");
    assert!(h.widget("Archive folders").is_some());
    assert!(crate::scenario::rect_of("toolbar_tab:PDM").is_some());
    let at = crate::scenario::rect_of("workspace_switcher").unwrap().center();
    h.step(&json!({"click":[at.x,at.y]})).unwrap();
    h.step(&json!({"click":{"handle":"menu:ui.workspace.design"}})).unwrap();
    assert!(!h.app.pdm.workspace_active);
    assert_eq!(*h.app.session.doc, *before);
    assert_eq!(h.app.session.undo.len(), undo);
}

#[test]
fn local_recovery_requires_a_root_and_explicit_confirmation() {
    let mut h = app();
    h.step(&json!({"click":{"handle":"pdm:recover_workspace"}})).unwrap();
    assert!(!h.app.pdm.recovery_confirmation);
    h.app.pdm.root = h.dir.to_string_lossy().to_string();
    h.frames(2);
    h.step(&json!({"click":{"handle":"pdm:recover_workspace"}})).unwrap();
    assert!(h.app.pdm.recovery_confirmation);
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_none(), "opening confirmation does not queue recovery");
    h.step(&json!({"widget":"Cancel"})).unwrap();
    assert!(!h.app.pdm.recovery_confirmation);
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_none());
}

#[cfg(target_os = "windows")]
#[test]
fn extended_windows_managed_path_reuses_tab_and_detects_unsaved_editor() {
    use solidcraft_engine::pdm::{LocalEntry, ManagedState};
    let mut h = Harness::new();
    h.app.session.path = Some(r"C:\Work\part.solidcraft".into());
    h.app.session.mark_saved();
    let count = h.app.docs.count();
    let mut replacement = Session::default();
    replacement.path = Some(r"\\?\c:\work\part.solidcraft".into());
    replacement.mark_saved();
    crate::documents::apply_managed(&mut h.app, replacement).unwrap();
    assert_eq!(h.app.docs.count(), count);
    h.app.session.path = Some(r"C:\Work\part.solidcraft".into());
    h.app.session.execute("solid.box", &json!({"length":2,"width":3,"height":4})).unwrap();
    h.app.pdm.runtime.set_available(true).unwrap();
    let id = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
    h.app
        .pdm
        .runtime
        .finish(
            id,
            Ok(Outcome::Managed {
                port: 48231,
                state: ManagedState {
                    local: vec![LocalEntry {
                        document: "part".into(),
                        path: r"\\?\c:\work\part.solidcraft".into(),
                        relative_path: "part.solidcraft".into(),
                        base_version: 1,
                        sha256: "00".repeat(32),
                        checked_out: true,
                        modified: false,
                        present: true,
                    }],
                    ..Default::default()
                },
            }),
        )
        .unwrap();
    assert!(crate::documents::managed_target_dirty(&h.app, Some("part")));
    assert!(h.app.run("pdm.get_latest", json!({"document":"part"})).is_err());
}

#[test]
fn metadata_refresh_keeps_explicit_temporary_ram_edit_permission() {
    let mut h = app();
    connect(&mut h);
    let key = solidcraft_engine::pdm::cached_path_key("managed.solidcraft");
    h.app.pdm.ram_paths.insert(key.clone());
    h.app.run("pdm.refresh", json!({})).unwrap();
    h.frames(5);
    assert!(h.app.pdm.ram_paths.contains(&key));
}

#[test]
fn restore_version_confirmation_captures_selection_and_cancel_queues_nothing() {
    use solidcraft_engine::pdm::{LocalEntry, ManagedState};
    let mut h = app();
    connect(&mut h);
    let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
    h.app
        .pdm
        .runtime
        .finish(
            id,
            Ok(Outcome::Managed {
                port: 48231,
                state: ManagedState {
                    catalog: vec![solidcraft_engine::pdm::CatalogEntry {
                        document: "part".into(),
                        logical_path: "part.solidcraft".into(),
                        head: Some(2),
                        checkout: None,
                        head_checked_in_unix_ms: None,
                        head_author: None,
                    }],
                    local: vec![LocalEntry {
                        document: "part".into(),
                        path: "part.solidcraft".into(),
                        relative_path: "part.solidcraft".into(),
                        base_version: 2,
                        sha256: "00".repeat(32),
                        checked_out: false,
                        modified: false,
                        present: true,
                    }],
                    ..Default::default()
                },
            }),
        )
        .unwrap();
    h.app.pdm.selected = Some(version().reference);
    h.frames(8);
    h.step(&json!({"click":{"handle":"pdm:restore_version"}})).unwrap();
    assert_eq!(h.app.pdm.restore_confirmation, Some(version().reference));
    assert!(h.widget("part.solidcraft · v1").is_some(), "confirmation identifies the readable captured file and version");
    assert!(h.widget("part - v1").is_none(), "opaque identity belongs only in the hover details");
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_none());
    h.step(&json!({"widget":"Cancel"})).unwrap();
    assert!(h.app.pdm.restore_confirmation.is_none());
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_none());

    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    h.app.services.pdm = Some(Arc::new(move |job| {
        captured.lock().unwrap().push(job.task);
        let (_send, receive) = mpsc::channel();
        receive
    }));
    h.step(&json!({"click":{"handle":"pdm:restore_version"}})).unwrap();
    h.app.pdm.selected = Some(Reference { document: "different".into(), version: 9 });
    h.step(&json!({"click":{"handle":"pdm:restore_version_confirm"}})).unwrap();
    h.frames(2);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(matches!(&requests[0], Task::Managed(ManagedTask::Restore { reference }) if *reference == version().reference));
    assert!(h.app.pdm.restore_confirmation.is_none());
}

use solidcraft_engine::pdm::{ActiveConnection, ConnectionKind, ConnectionStage, ConnectionSummary, ManagedState};

fn guided_recent() -> Vec<ConnectionSummary> {
    vec![
        ConnectionSummary {
            id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            label: "Saved archive label".into(),
            kind: ConnectionKind::Local,
            stage: ConnectionStage::SavedUnverified,
        },
        ConnectionSummary {
            id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            label: "Interrupted archive".into(),
            kind: ConnectionKind::Local,
            stage: ConnectionStage::Pending,
        },
    ]
}
fn guided_worker(requests: Arc<Mutex<Vec<ManagedTask>>>, recent: Vec<ConnectionSummary>) -> Start {
    Arc::new(move |job| {
        let (send, receive) = mpsc::channel();
        let Task::Managed(task) = job.task else {
            send.send(Completion { result: Err(Failure { message: "Unexpected test request".into(), disconnect: false }), open: None }).unwrap();
            return receive;
        };
        requests.lock().unwrap().push(task.clone());
        let result = match task {
            ManagedTask::ListConnections => Ok(Outcome::Connections(recent.clone())),
            ManagedTask::OpenConnection { connection_id } | ManagedTask::RecoverConnection { connection_id } => Ok(Outcome::ManagedConnected {
                port: 48231,
                state: ManagedState {
                    root: Some("C:/PDM proof/Working".into()),
                    server_id: Some("server-real".into()),
                    workspace: Some("verified-workspace".into()),
                    ..Default::default()
                },
                connections: recent.clone(),
                connection: ActiveConnection {
                    id: connection_id,
                    label: "Verified archive".into(),
                    origin: "https://localhost:48231".into(),
                    server_id: "server-real".into(),
                    account: "authenticated-admin".into(),
                    role: "Administrator".into(),
                },
            }),
            ManagedTask::CreateLocal { .. } => Err(Failure { message: "Setup fixture stopped before native work".into(), disconnect: false }),
            _ => Err(Failure { message: "Unexpected guided action".into(), disconnect: false }),
        };
        send.send(Completion { result, open: None }).unwrap();
        receive
    })
}
fn guided_app(recent: Vec<ConnectionSummary>) -> (Harness, Arc<Mutex<Vec<ManagedTask>>>) {
    let mut h = Harness::new();
    let requests = Arc::new(Mutex::new(Vec::new()));
    h.app.services.pdm = Some(guided_worker(requests.clone(), recent));
    h.app.start("pdm.panel");
    h.frames(5);
    (h, requests)
}

#[test]
fn guided_empty_state_lists_once_and_has_no_fabricated_verified_identity() {
    let (mut h, requests) = guided_app(Vec::new());
    assert!(h.widget("Create a local archive to get started.").is_some());
    assert!(h.widget("Create Local Archive").is_some());
    assert!(h.app.pdm.runtime.status().unwrap().connection.is_none());
    h.frames(5);
    assert_eq!(requests.lock().unwrap().iter().filter(|task| matches!(task, ManagedTask::ListConnections)).count(), 1);
    assert!(!requests.lock().unwrap().iter().any(|task| matches!(task, ManagedTask::CreateLocal { .. } | ManagedTask::OpenConnection { .. })));
}

#[test]
fn guided_create_sends_only_public_label_and_administrator_to_worker() {
    let (mut h, requests) = guided_app(Vec::new());
    h.app.pdm.guided.label = "Fixture archive".into();
    h.app.pdm.guided.administrator = "fixture_admin".into();
    h.frames(2);
    h.step(&json!({"click":{"handle":"pdm:setup_create"}})).unwrap();
    h.frames(3);
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|task| matches!(task,ManagedTask::CreateLocal {label,administrator} if label=="Fixture archive" && administrator=="fixture_admin"))
    );
    assert!(h.app.pdm.runtime.status().unwrap().connection.is_none());
    assert!(h.app.session.path.is_none());
}

#[test]
fn guided_existing_open_displays_only_fresh_authenticated_metadata() {
    let (mut h, requests) = guided_app(guided_recent());
    assert!(h.widget("Saved archive label").is_some());
    assert!(h.widget("Not connected").is_some());
    assert!(h.widget("authenticated-admin").is_none());
    assert!(h.app.pdm.runtime.status().unwrap().connection.is_none());
    h.step(&json!({"click":{"handle":"pdm:connection:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}})).unwrap();
    h.frames(4);
    assert!(requests.lock().unwrap().iter().any(|task|matches!(task,ManagedTask::OpenConnection {connection_id} if connection_id=="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
    assert!(h.widget("authenticated-admin").is_some());
    assert!(h.widget("Administrator").is_some());
    assert!(h.widget("https://localhost:48231").is_some());
    assert!(h.widget("C:/PDM proof/Working").is_some());
    assert!(h.widget("Connected").is_some());
    assert!(h.widget("Not connected").is_none());
}

#[test]
fn guided_busy_state_disables_setup_and_connection_open() {
    let (mut h, requests) = guided_app(guided_recent());
    h.app.pdm.guided.label = "Fixture archive".into();
    h.frames(2);
    let held = Arc::new(Mutex::new(Vec::<mpsc::Sender<Completion>>::new()));
    let retained = held.clone();
    let observed = requests.clone();
    h.app.services.pdm = Some(Arc::new(move |job| {
        let (send, receive) = mpsc::channel();
        if let Task::Managed(task) = job.task {
            observed.lock().unwrap().push(task);
        }
        retained.lock().unwrap().push(send);
        receive
    }));
    h.app.run("pdm.connections", json!({})).unwrap();
    h.frames(2);
    let before = requests.lock().unwrap().len();
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_some());
    h.step(&json!({"click":{"handle":"pdm:setup_create"}})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:connection:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), before);
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_some());
    assert_eq!(held.lock().unwrap().len(), 1);
}

#[test]
fn guided_pending_row_resumes_existing_installation_without_creating_another() {
    let (mut h, requests) = guided_app(guided_recent());
    assert!(h.widget("Setup incomplete").is_some());
    h.step(&json!({"click":{"handle":"pdm:connection:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}})).unwrap();
    h.frames(4);
    assert!(requests.lock().unwrap().iter().any(|task|matches!(task,ManagedTask::OpenConnection {connection_id} if connection_id=="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")));
    assert!(!requests.lock().unwrap().iter().any(|task| matches!(task, ManagedTask::CreateLocal { .. })));
}

#[test]
fn guided_recovery_requires_confirmation_and_scopes_the_existing_connection() {
    let (mut h, requests) = guided_app(guided_recent());
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    h.step(&json!({"click":{"handle":format!("pdm:connection_recover:{id}")}})).unwrap();
    h.frames(2);
    assert!(h.app.pdm.guided.pending_recovery.is_some());
    assert!(!requests.lock().unwrap().iter().any(|task| matches!(task, ManagedTask::RecoverConnection { .. })));
    h.step(&json!({"click":{"handle":"pdm:connection_recover_confirm"}})).unwrap();
    h.frames(4);
    assert!(requests.lock().unwrap().iter().any(|task| matches!(task,ManagedTask::RecoverConnection {connection_id} if connection_id==id)));
    assert!(!requests.lock().unwrap().iter().any(|task| matches!(task, ManagedTask::CreateLocal { .. })));
}

#[test]
fn guided_recovery_cancel_and_dirty_editor_never_queue_native_recovery() {
    let (mut h, requests) = guided_app(guided_recent());
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    h.step(&json!({"click":{"handle":format!("pdm:connection_recover:{id}")}})).unwrap();
    h.frames(2);
    h.step(&json!({"click":{"handle":"pdm:connection_recover_cancel"}})).unwrap();
    h.frames(2);
    assert!(h.app.pdm.guided.pending_recovery.is_none());
    h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
    h.frames(2);
    h.step(&json!({"click":{"handle":format!("pdm:connection_recover:{id}")}})).unwrap();
    h.frames(2);
    assert!(h.app.pdm.guided.pending_recovery.is_none());
    assert!(!requests.lock().unwrap().iter().any(|task| matches!(task, ManagedTask::RecoverConnection { .. })));
}

#[test]
fn restore_completion_clears_temporary_ram_permission_and_reuses_its_editor() {
    use solidcraft_engine::pdm::{LocalEntry, ManagedState};
    let mut h = app();
    connect(&mut h);
    h.app.session.path = Some("part.solidcraft".into());
    h.app.session.mark_saved();
    let state = |base_version| ManagedState {
        catalog: vec![solidcraft_engine::pdm::CatalogEntry {
            document: "part".into(),
            logical_path: "part.solidcraft".into(),
            head: Some(base_version),
            checkout: None,
            head_checked_in_unix_ms: None,
            head_author: None,
        }],
        local: vec![LocalEntry {
            document: "part".into(),
            path: "part.solidcraft".into(),
            relative_path: "part.solidcraft".into(),
            base_version,
            sha256: "00".repeat(32),
            checked_out: false,
            modified: false,
            present: true,
        }],
        ..Default::default()
    };
    let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state: state(2) })).unwrap();
    let key = solidcraft_engine::pdm::cached_path_key("part.solidcraft");
    h.app.pdm.ram_paths.insert(key.clone());
    let held = Arc::new(Mutex::new(None));
    h.app.services.pdm = Some(backend(Some(held.clone())));
    let count = h.app.docs.count();
    h.app.run("pdm.restore_version", json!({"document":"part","version":1,"restore":true})).unwrap();
    h.frames(3);
    assert!(h.app.pdm.runtime.status().unwrap().blocking);
    assert!(h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).is_err());
    let mut restored = Session::default();
    restored.path = Some("part.solidcraft".into());
    restored.mark_saved();
    held.lock()
        .unwrap()
        .take()
        .unwrap()
        .send(Completion { result: Ok(Outcome::Managed { port: 48231, state: state(3) }), open: Some(Box::new(restored)) })
        .unwrap();
    h.frames(5);
    assert!(!h.app.pdm.runtime.status().unwrap().blocking);
    assert!(!h.app.pdm.ram_paths.contains(&key));
    assert_eq!(h.app.docs.count(), count);
    assert_eq!(h.app.session.path.as_deref(), Some("part.solidcraft"));
    assert!(!h.app.session.is_dirty());
    assert_eq!(h.app.pdm.runtime.status().unwrap().managed.local.first().unwrap().base_version, 3);
}

#[test]
fn switching_authenticated_connections_clears_old_archive_actions_and_ram_permissions() {
    let (mut h, _) = guided_app(guided_recent());
    let id = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
    h.app
        .pdm
        .runtime
        .finish(
            id,
            Ok(Outcome::Managed {
                port: 48231,
                state: ManagedState { server_id: Some("old-server".into()), workspace: Some("old-workspace".into()), ..Default::default() },
            }),
        )
        .unwrap();
    h.app.pdm.document = "old-document".into();
    h.app.pdm.parent = "9".into();
    h.app.pdm.folder = "Old folder".into();
    h.app.pdm.logical_path = "Old folder/part.solidcraft".into();
    h.app.pdm.selected = Some(Reference { document: "old-document".into(), version: 9 });
    h.app.pdm.dependencies = vec![Reference { document: "old-part".into(), version: 4 }];
    h.app.pdm.restore_confirmation = h.app.pdm.selected.clone();
    h.app.pdm.pending_edit = Some("solid.box".into());
    h.app.pdm.ram_paths.insert("old/part.solidcraft".into());
    h.app.pdm.guided.pending_recovery = Some(("c".repeat(64), "Old connection".into()));
    let disconnected = h.app.pdm.runtime.enqueue(Task::Disconnect).unwrap();
    h.app.pdm.runtime.finish(disconnected, Ok(Outcome::Disconnected)).unwrap();
    h.app.run("pdm.connection.open", json!({"connection_id":"a".repeat(64)})).unwrap();
    h.frames(5);
    assert_eq!(h.app.pdm.runtime.status().unwrap().connection.unwrap().account, "authenticated-admin");
    assert!(h.app.pdm.document.is_empty());
    assert!(h.app.pdm.parent.is_empty());
    assert!(h.app.pdm.folder.is_empty());
    assert!(h.app.pdm.logical_path.is_empty());
    assert!(h.app.pdm.selected.is_none());
    assert!(h.app.pdm.dependencies.is_empty());
    assert!(h.app.pdm.restore_confirmation.is_none());
    assert!(h.app.pdm.pending_edit.is_none());
    assert!(h.app.pdm.ram_paths.is_empty());
    assert!(h.app.pdm.guided.pending_recovery.is_none());
}

fn epoch_managed_state(path: &std::path::Path) -> solidcraft_engine::pdm::ManagedState {
    use solidcraft_engine::pdm::{LocalEntry, ManagedState};
    ManagedState {
        server_id: Some("epoch-server".into()),
        workspace: Some("epoch-workspace".into()),
        local: vec![LocalEntry {
            document: "part".into(),
            path: path.to_string_lossy().into_owned(),
            relative_path: "part.solidcraft".into(),
            base_version: 1,
            sha256: "ab".repeat(32),
            checked_out: true,
            modified: false,
            present: true,
        }],
        ..Default::default()
    }
}
fn epoch_connected(h: &mut Harness, path: &std::path::Path) {
    h.app.pdm.runtime.set_available(true).unwrap();
    let task = if h.app.pdm.runtime.status().unwrap().port.is_some() { Task::Refresh } else { Task::Connect { port: 48231 } };
    let request = h.app.pdm.runtime.enqueue(task).unwrap();
    h.app.pdm.runtime.finish(request, Ok(Outcome::Managed { port: 48231, state: epoch_managed_state(path) })).unwrap();
}
fn epoch_recover(h: &mut Harness, path: &std::path::Path, failed: bool) {
    h.app.pdm.runtime.set_available(true).unwrap();
    let request = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
    let mut disk = Session::default();
    disk.execute("solid.box", &json!({"length":7,"width":8,"height":9})).unwrap();
    disk.execute("file.save", &json!({"path":path})).unwrap();
    let result = if failed {
        Err(Failure { message: "Reply lost after disk restoration".into(), disconnect: false })
    } else {
        Ok(Outcome::Managed { port: 48231, state: epoch_managed_state(path) })
    };
    h.app.pdm.runtime.finish(request, result).unwrap();
}
fn epoch_read_fresh(h: &Harness, path: &std::path::Path) -> Session {
    let receipt = h.app.pdm.runtime.begin_pdm_reload().unwrap();
    let mut fresh = Session::default();
    fresh.execute("doc.open", &json!({"path":path})).unwrap();
    crate::documents::bind_fresh_pdm_load(&h.app, &mut fresh, receipt).unwrap();
    fresh
}

#[test]
fn pdm_recovery_epoch_success_and_failure_keep_clean_cached_editor_fenced() {
    for failed in [false, true] {
        let mut h = Harness::new();
        let path = h.dir.join("part.solidcraft");
        h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
        h.app.run("file.save", json!({"path":path})).unwrap();
        epoch_connected(&mut h, &path);
        let old = h.app.session.doc.clone();
        epoch_recover(&mut h, &path, failed);
        let disk = std::fs::read(&path).unwrap();
        assert!(h.app.session.check_pdm_reopen().is_err());
        assert!(h.app.run("file.save", json!({})).is_err());
        h.app.start("solid.box");
        assert!(h.app.dialog.is_none());
        assert!(h.app.pdm.pending_edit.is_none());
        assert!(h.app.status.as_ref().is_some_and(|(text, _, _)| text.contains("Reopen")));
        assert_eq!(*h.app.session.doc, *old);
        let fresh = epoch_read_fresh(&h, &path);
        let expected = fresh.doc.clone();
        crate::documents::apply_managed(&mut h.app, fresh).unwrap();
        assert!(h.app.session.check_pdm_reopen().is_ok());
        assert_eq!(*h.app.session.doc, *expected);
        assert_eq!(std::fs::read(&path).unwrap(), disk);
    }
}

#[test]
fn pdm_recovery_epoch_reopening_one_tab_does_not_bless_another_same_path() {
    let mut h = Harness::new();
    let path = h.dir.join("part.solidcraft");
    h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
    h.app.run("file.save", json!({"path":path})).unwrap();
    epoch_connected(&mut h, &path);
    let original = h.app.docs.active;
    let duplicate = epoch_read_fresh(&h, &path);
    crate::documents::open_tab(&mut h.app, duplicate).unwrap();
    epoch_recover(&mut h, &path, false);
    let fresh = epoch_read_fresh(&h, &path);
    crate::documents::apply_managed(&mut h.app, fresh).unwrap();
    assert!(h.app.session.check_pdm_reopen().is_ok());
    crate::documents::switch(&mut h.app, original);
    assert!(h.app.session.check_pdm_reopen().is_err());
    assert!(h.app.run("file.save", json!({})).is_err());
    h.app.session.mark_unsaved();
    let before = h.app.session.doc.clone();
    let fresh = epoch_read_fresh(&h, &path);
    assert!(crate::documents::apply_managed(&mut h.app, fresh).is_err());
    assert_eq!(*h.app.session.doc, *before);
    assert!(h.app.session.is_dirty());
}

#[test]
fn pdm_recovery_epoch_cached_adoption_never_renews_its_receipt() {
    let mut h = Harness::new();
    let path = h.dir.join("part.solidcraft");
    h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
    h.app.run("file.save", json!({"path":path})).unwrap();
    epoch_connected(&mut h, &path);
    let cached = epoch_read_fresh(&h, &path);
    epoch_recover(&mut h, &path, true);
    crate::documents::adopt(&mut h.app, cached);
    assert!(h.app.session.check_pdm_reopen().is_err());
}

fn explorer_state(checked_out: bool) -> ManagedState {
    use solidcraft_engine::pdm::{CatalogEntry, Checkout, LocalEntry};
    let catalog = ["part", "other"]
        .into_iter()
        .map(|document| CatalogEntry {
            document: document.into(),
            logical_path: format!("Projects/{document}.solidcraft"),
            head: Some(2),
            checkout: (checked_out && document == "part").then(|| Checkout {
                owner: "tester".into(),
                workspace: "workspace-a".into(),
                machine: "test-device".into(),
                checked_out_unix_ms: 0,
                base_version: Some(2),
            }),
            head_checked_in_unix_ms: Some(0),
            head_author: Some("tester".into()),
        })
        .collect();
    let local = ["part", "other"]
        .into_iter()
        .map(|document| LocalEntry {
            document: document.into(),
            path: format!("Working/{document}.solidcraft"),
            relative_path: format!("Projects/{document}.solidcraft"),
            base_version: 2,
            sha256: "00".repeat(32),
            checked_out: checked_out && document == "part",
            modified: false,
            present: true,
        })
        .collect();
    ManagedState {
        server_id: Some("test-server".into()),
        workspace: Some("workspace-a".into()),
        root: Some("Working".into()),
        catalog,
        local,
        ..Default::default()
    }
}

type ExplorerRequests = Arc<Mutex<Vec<Task>>>;
type ExplorerCompletions = Arc<Mutex<Vec<mpsc::Sender<Completion>>>>;

fn explorer(checked_out: bool) -> (Harness, ExplorerRequests, ExplorerCompletions) {
    let mut h = Harness::new();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let held = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let retained = held.clone();
    h.app.services.pdm = Some(Arc::new(move |job| {
        let (send, receive) = mpsc::channel();
        if matches!(&job.task, Task::Managed(ManagedTask::History { .. } | ManagedTask::Preview { .. })) {
            send.send(Completion { result: Ok(Outcome::Listed(Vec::new())), open: None }).unwrap();
        } else {
            observed.lock().unwrap().push(job.task);
            retained.lock().unwrap().push(send);
        }
        receive
    }));
    h.app.pdm.runtime.set_available(true).unwrap();
    let id = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
    h.app
        .pdm
        .runtime
        .finish(
            id,
            Ok(Outcome::ManagedConnected {
                port: 48231,
                state: explorer_state(checked_out),
                connections: Vec::new(),
                connection: ActiveConnection {
                    id: "a".repeat(64),
                    label: "Test archive".into(),
                    origin: "https://localhost:48231".into(),
                    server_id: "test-server".into(),
                    account: "tester".into(),
                    role: "Editor".into(),
                },
            }),
        )
        .unwrap();
    h.app.session.path = Some("Working/part.solidcraft".into());
    h.app.session.mark_saved();
    crate::pdm_panel::enter(&mut h.app).unwrap();
    h.app.pdm.document = "part".into();
    h.app.pdm.folder = "Projects".into();
    h.frames(3);
    (h, requests, held)
}

fn complete_explorer(h: &mut Harness, held: &ExplorerCompletions, result: Result<Outcome, Failure>) {
    held.lock().unwrap().remove(0).send(Completion { result, open: None }).unwrap();
    h.frames(4);
}

#[test]
fn explorer_checkout_is_single_flight_and_archive_requires_confirmed_checkout() {
    let (mut h, requests, held) = explorer(false);
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive"), Some("ui.pdm_reason_checkout_required"));
    h.step(&json!({"click":{"handle":"pdm:archive"}})).unwrap();
    h.frames(2);
    assert!(requests.lock().unwrap().is_empty());
    h.step(&json!({"click":{"handle":"pdm:checkout"}})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:checkout"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Checkout{document:Some(document),..})if document=="part"));
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive"), Some("ui.pdm_reason_busy"));
    complete_explorer(&mut h, &held, Ok(Outcome::ManagedRefreshed { port: 48231, state: explorer_state(true) }));
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.checkout"), Some("ui.pdm_reason_checked_out_here"));
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive"), None);
    assert!(h.widget("Check Out completed for Projects/part.solidcraft.").is_some());
    h.step(&json!({"click":{"handle":"pdm:checkout"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    h.step(&json!({"click":{"handle":"pdm:archive"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert!(matches!(&requests.lock().unwrap()[1],Task::Managed(ManagedTask::Archive{path,..})if path=="Working/part.solidcraft"));
    complete_explorer(&mut h, &held, Ok(Outcome::ManagedRefreshed { port: 48231, state: explorer_state(false) }));
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive"), Some("ui.pdm_reason_checkout_required"));
    assert!(h.widget("Check In completed for Projects/part.solidcraft.").is_some());
}

#[test]
fn explorer_completion_keeps_selection_folder_and_target_feedback_through_refresh() {
    let (mut h, requests, held) = explorer(false);
    h.step(&json!({"click":{"handle":"pdm:checkout"}})).unwrap();
    h.frames(2);
    h.app.pdm.document = "other".into();
    complete_explorer(&mut h, &held, Ok(Outcome::ManagedRefreshed { port: 48231, state: explorer_state(true) }));
    assert_eq!(h.app.pdm.document, "other");
    assert_eq!(h.app.pdm.folder, "Projects");
    assert!(h.widget("Check Out completed for Projects/part.solidcraft.").is_some());
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive"), Some("ui.pdm_reason_open_selected"));
    h.app.run("pdm.refresh", json!({})).unwrap();
    h.frames(2);
    complete_explorer(&mut h, &held, Ok(Outcome::ManagedRefreshed { port: 48231, state: explorer_state(true) }));
    assert!(h.widget("Check Out completed for Projects/part.solidcraft.").is_some());
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[test]
fn explorer_offline_failure_stays_visible_and_blocks_actions_without_fake_success() {
    let (mut h, requests, held) = explorer(false);
    h.step(&json!({"click":{"handle":"pdm:checkout"}})).unwrap();
    h.frames(2);
    complete_explorer(&mut h, &held, Err(Failure { message: "Archive is offline; reconnect and retry".into(), disconnect: true }));
    assert!(h.app.pdm.runtime.status().unwrap().port.is_none());
    assert!(h.widget("Check Out failed for Projects/part.solidcraft: Archive is offline; reconnect and retry").is_some());
    h.step(&json!({"click":{"handle":"pdm:checkout"}})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:archive"}})).unwrap();
    h.frames(3);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(h.widget("Check Out failed for Projects/part.solidcraft: Archive is offline; reconnect and retry").is_some());
}

#[test]
fn explorer_undo_checkout_confirmation_keeps_captured_document_after_selection_switch() {
    let (mut h, requests, held) = explorer(true);
    h.step(&json!({"click":{"handle":"pdm:cancel_checkout"}})).unwrap();
    h.frames(2);
    assert!(h.app.pdm.cancel_confirmation);
    assert!(requests.lock().unwrap().is_empty());
    h.app.pdm.document = "other".into();
    h.step(&json!({"click":{"handle":"pdm:cancel_checkout_confirm"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::CancelCheckout{document:Some(document),..})if document=="part"));
    complete_explorer(&mut h, &held, Ok(Outcome::ManagedRefreshed { port: 48231, state: explorer_state(false) }));
    assert_eq!(h.app.pdm.document, "other");
}

#[test]
fn explorer_no_selection_cannot_operate_active_managed_file_but_initial_archive_is_explicit() {
    let (mut h, requests, _held) = explorer(true);
    h.app.pdm.document.clear();
    h.frames(2);
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.checkout"), Some("ui.pdm_reason_select_document"));
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive"), Some("ui.pdm_reason_select_document"));
    h.step(&json!({"click":{"handle":"pdm:archive"}})).unwrap();
    h.frames(2);
    assert!(requests.lock().unwrap().is_empty());
    h.app.session.path = Some("Working/new-design.solidcraft".into());
    h.app.session.mark_saved();
    h.frames(2);
    assert!(h.widget("Initial Check In").is_some());
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive"), None);
    h.step(&json!({"click":{"handle":"pdm:archive"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Archive{path,..})if path=="Working/new-design.solidcraft"));
}

#[test]
fn explorer_sorting_preserves_selection_and_folder_navigation_clears_file_targets() {
    let (mut h, requests, _held) = explorer(false);
    h.app.pdm.selected = Some(Reference { document: "part".into(), version: 1 });
    h.step(&json!({"click":{"handle":"pdm:sort:0"}})).unwrap();
    assert_eq!(h.app.pdm.document, "part");
    assert_eq!(h.app.pdm.selected, Some(Reference { document: "part".into(), version: 1 }));
    for navigation in ["pdm:folder:root", "pdm:folder:Projects", "pdm:breadcrumb:Projects", "pdm:breadcrumb:root"] {
        h.app.pdm.document = "part".into();
        h.app.pdm.selected = Some(Reference { document: "part".into(), version: 1 });
        h.frames(2);
        h.step(&json!({"click":{"handle":navigation}})).unwrap();
        h.frames(2);
        assert!(h.app.pdm.document.is_empty() && h.app.pdm.selected.is_none(), "{navigation} retained a stale file target");
        assert!(crate::scenario::handles("pdm:version:").is_empty());
        for command in ["pdm.checkout", "pdm.archive", "pdm.open_document", "pdm.open_archived", "pdm.restore_version"] {
            assert!(crate::pdm_panel::command_unavailable(&h.app, command).is_some(), "{navigation} enabled {command}");
        }
    }
    assert!(h.app.pdm.folder.is_empty());
    h.app.session.path = Some("Working/New.solidcraft".into());
    h.app.session.mark_saved();
    assert!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive").is_some(), "root navigation must not publish an unrelated editor");
    h.step(&json!({"click":{"handle":"pdm:folder:Projects"}})).unwrap();
    h.frames(2);
    // Text itself remains clickable; it never becomes generic text selection.
    h.step(&json!({"widget":"other.solidcraft"})).unwrap();
    h.frames(3);
    assert_eq!(h.app.pdm.document, "other");
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn explorer_menu_command_info_matches_ribbon_policy_and_waits_for_native_file_operations() {
    let (mut h, _requests, _held) = explorer(false);
    let archive = solidcraft_engine::find_command("pdm.archive").unwrap();
    let checkout = solidcraft_engine::find_command("pdm.checkout").unwrap();
    for command in [archive, checkout] {
        let reason = crate::pdm_panel::command_unavailable(&h.app, command.id);
        let info = h.app.command_info(command);
        assert_eq!(info.enabled, reason.is_none());
        assert_eq!(info.disabled_reason, reason.map(|reason| h.app.tr(reason).to_string()));
    }
    h.app.services.pick_open = Some(Box::new(|_| Box::pin(std::future::pending())));
    h.app.pick_open(|_, _| {});
    assert!(h.app.file_picker_busy());
    for command in [archive, checkout] {
        let info = h.app.command_info(command);
        assert!(!info.enabled);
        assert_eq!(crate::pdm_panel::command_unavailable(&h.app, command.id), Some("ui.pdm_reason_busy"));
        assert_eq!(info.disabled_reason.as_deref(), Some(h.app.tr("ui.pdm_reason_busy")));
    }
}

#[test]
fn explorer_failed_archive_offers_receipt_verification_without_repeating_publication() {
    let (mut h, requests, held) = explorer(true);
    h.step(&json!({"click":{"handle":"pdm:archive"}})).unwrap();
    h.frames(2);
    complete_explorer(&mut h, &held, Err(Failure { message: "Publication reply was lost; verify the result".into(), disconnect: false }));
    assert!(h.widget("Verify Check-In Result").is_some());
    h.step(&json!({"click":{"handle":"pdm:reconcile_archive"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Archive{path,..})if path=="Working/part.solidcraft"));
    assert!(matches!(&requests.lock().unwrap()[1],Task::Managed(ManagedTask::ReconcileArchive{path,..})if path=="Working/part.solidcraft"));
    complete_explorer(&mut h, &held, Ok(Outcome::ManagedRefreshed { port: 48231, state: explorer_state(false) }));
    assert!(h.widget("Check In completed for Projects/part.solidcraft.").is_some());
    assert!(h.widget("Verify Check-In Result").is_none());
}

#[test]
fn explorer_table_rows_keep_allocated_height_below_header_in_wide_and_narrow_windows() {
    let (mut h, _requests, _held) = explorer(false);
    for width in [1600, 860] {
        h.call("ui.resize", json!({"width":width,"height":1000}));
        h.frames(3);
        let header = crate::scenario::handle_at("pdm:sort:0").unwrap();
        let other = crate::scenario::handle_at("pdm:file:other").unwrap();
        let part = crate::scenario::handle_at("pdm:file:part").unwrap();
        assert!(other.y - header.y >= 31.0, "first row overlaps header: {header:?} {other:?}");
        assert!(part.y - other.y >= 31.0, "allocated row height lost: {other:?} {part:?}");
        assert!(part.y < 1000.0, "rows remain inside the explorer");
    }
}

#[test]
fn explorer_palette_start_routes_checkout_to_selected_row_instead_of_another_active_editor() {
    let (mut h, requests, _held) = explorer(false);
    h.app.pdm.document = "other".into();
    assert_eq!(h.app.session.path.as_deref(), Some("Working/part.solidcraft"));
    h.app.start("pdm.checkout");
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Checkout{document:Some(document),..})if document=="other"));
    assert_eq!(h.app.session.path.as_deref(), Some("Working/part.solidcraft"));
}

#[test]
fn explorer_where_used_never_shows_completed_metadata_for_a_different_selection() {
    let (mut h, _requests, _held) = explorer(false);
    h.app.pdm.detail_tab = 2;
    let mut initial = explorer_state(false);
    initial.where_used = vec![Reference { document: "parent_a".into(), version: 1 }];
    // Metadata jobs return Managed, whereas periodic ManagedRefreshed deliberately
    // preserves the previous history/where-used snapshot in Runtime::finish.
    h.app.services.pdm = Some(Arc::new(move |job| {
        assert!(matches!(job.task,Task::Managed(ManagedTask::History {ref document}) if document=="part"));
        let (send, receive) = mpsc::channel();
        send.send(Completion { result: Ok(Outcome::Managed { port: 48231, state: initial.clone() }), open: None }).unwrap();
        receive
    }));
    h.app.run("pdm.history", json!({"document":"part"})).unwrap();
    h.frames(4);
    assert!(h.widget("parent_a · v1").is_some());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let held = Arc::new(Mutex::new(Vec::new()));
    let retained = held.clone();
    h.app.services.pdm = Some(Arc::new(move |job| {
        let (send, receive) = mpsc::channel();
        observed.lock().unwrap().push(job.task);
        retained.lock().unwrap().push(send);
        receive
    }));
    h.app.run("pdm.history", json!({"document":"part"})).unwrap();
    h.frames(2);
    h.step(&json!({"click":{"handle":"pdm:file:other"}})).unwrap();
    h.frames(2);
    assert_eq!(h.app.pdm.document, "other");
    assert!(h.widget("parent_a · v1").is_none());
    let mut stale = explorer_state(false);
    stale.where_used = vec![Reference { document: "parent_a".into(), version: 1 }];
    h.frames(20); // Single-click metadata begins after the physical double-click interval.
    complete_explorer(&mut h, &held, Ok(Outcome::Managed { port: 48231, state: stale }));
    assert_eq!(h.app.pdm.document, "other");
    assert!(h.widget("parent_a · v1").is_none());
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert!(matches!(&requests.lock().unwrap()[1],Task::Managed(ManagedTask::History{document})if document=="other"));
    let mut current = explorer_state(false);
    current.where_used = vec![Reference { document: "parent_b".into(), version: 2 }];
    complete_explorer(&mut h, &held, Ok(Outcome::Managed { port: 48231, state: current }));
    assert!(h.widget("parent_b · v2").is_some());
    assert!(h.widget("parent_a · v1").is_none());
}

#[test]
fn explorer_incomplete_checkout_release_requires_verified_native_proof_and_never_enables_archive() {
    let (mut h, requests, held) = explorer(false);
    let mut incomplete = explorer_state(true);
    incomplete.local.retain(|entry| entry.document != "part");
    incomplete.recoverable_checkouts = vec!["part".into()];
    let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::ManagedRefreshed { port: 48231, state: incomplete.clone() })).unwrap();
    h.frames(3);
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.cancel_checkout"), None);
    assert!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive").is_some());
    assert_eq!(h.app.pdm.runtime.status().unwrap().document_state(Some("part"), None, false), "ui.pdm_state_checkout_incomplete");
    h.step(&json!({"click":{"handle":"pdm:cancel_checkout"}})).unwrap();
    h.frames(2);
    assert!(h.widget("Release this verified incomplete checkout? No local file will be replaced.").is_some());
    assert!(h.widget(h.app.tr("ui.pdm_discard_confirm")).is_none());
    h.step(&json!({"click":{"handle":"pdm:cancel_checkout_confirm"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::CancelCheckout{document:Some(document),..})if document=="part"));
    incomplete.recoverable_checkouts.clear();
    complete_explorer(&mut h, &held, Ok(Outcome::ManagedRefreshed { port: 48231, state: incomplete }));
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.cancel_checkout"), Some("ui.pdm_reason_checked_out_elsewhere"));
    assert!(crate::pdm_panel::command_unavailable(&h.app, "pdm.archive").is_some());
    h.step(&json!({"click":{"handle":"pdm:cancel_checkout"}})).unwrap();
    h.frames(2);
    assert!(!h.app.pdm.cancel_confirmation);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn explorer_compact_details_keep_actions_above_footer_and_scroll_to_later_history_rows() {
    use solidcraft_engine::pdm::{ManagedVersion, Preview};
    let (mut h, _requests, held) = explorer(false);
    let long_path = "Working/Very long archive folder/Another nested folder/Initial.solidcraft";
    h.app.session.path = Some(long_path.into());
    h.app.session.mark_saved();
    h.app.pdm.document.clear();
    h.app.run("pdm.archive", json!({})).unwrap();
    h.frames(2);
    let mut state = explorer_state(false);
    state.catalog.iter_mut().find(|entry| entry.document == "part").unwrap().head = Some(3);
    state.local.iter_mut().find(|entry| entry.document == "part").unwrap().base_version = 3;
    state.history = (1..=3)
        .map(|number| ManagedVersion {
            version: Version {
                reference: Reference { document: "part".into(), version: number },
                parent: (number > 1).then_some(number - 1),
                sha256: "00".repeat(32),
                dependencies: Vec::new(),
            },
            author: "Test author".into(),
            checked_in_unix_ms: 0,
            comment: format!("Test version {number}"),
            request_id: format!("history-{number}"),
        })
        .collect();
    let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(240, 150, image::Rgba([60, 90, 120, 255])));
    let mut png = std::io::Cursor::new(Vec::new());
    image.write_to(&mut png, image::ImageFormat::Png).unwrap();
    state.preview = Some(Preview { reference: Reference { document: "part".into(), version: 3 }, sha256: "00".repeat(32), png: png.into_inner() });
    h.app.pdm.document = "part".into();
    h.app.pdm.selected = Some(Reference { document: "part".into(), version: 3 });
    complete_explorer(&mut h, &held, Ok(Outcome::Managed { port: 48231, state }));
    h.app.preferences.language = "it".into();
    h.frames(8);
    for (index, width) in [860, 960].into_iter().enumerate() {
        h.call("ui.resize", json!({"width":width,"height":512}));
        h.frames(4);
        let pane = crate::scenario::rect_of("pdm_details_pane").unwrap();
        let footer = crate::scenario::rect_of("pdm_footer").unwrap();
        let actions = crate::scenario::rect_of("pdm_detail_actions").unwrap();
        assert!(pane.bottom() <= footer.top(), "details crossed footer: {pane:?} {footer:?}");
        for command in ["pdm.open_archived", "pdm.restore_version"] {
            let button = crate::scenario::rect_of(&format!("pdm_action_button:{command}")).unwrap();
            // egui rounds widget edges to physical pixels; only containment in
            // the reserved action row gets this subpixel allowance. The footer
            // boundary below remains strict.
            assert!(actions.expand(0.5).contains_rect(button), "action escaped reserved row at {width}: {button:?} {actions:?}");
            assert!(button.bottom() <= footer.top(), "action crossed persistent footer: {button:?} {footer:?}");
        }
        let notice = crate::scenario::rect_of("pdm_notice").unwrap();
        assert!(footer.contains_rect(notice), "notice escaped footer: {notice:?} {footer:?}");
        assert!(notice.height() < 24.0, "success notice wrapped at {width}: {notice:?}");
        let scroll = crate::scenario::rect_of("pdm_details_scroll").unwrap();
        assert!(scroll.height() >= 64.0, "history must initially show a readable full thumbnail row: {scroll:?}");
        if index > 0 {
            h.call("ui.scroll", json!({"x":scroll.center().x,"y":scroll.center().y,"delta":300}));
            h.frames(12);
        }
        let scroll = crate::scenario::rect_of("pdm_details_scroll").unwrap();
        let first_label = crate::scenario::rect_of("pdm_history_version:part:3").unwrap();
        let first_thumbnail = crate::scenario::rect_of("pdm_history_thumbnail:part:3").unwrap();
        assert!(scroll.expand(0.5).contains_rect(first_label), "initial version text clipped at {width}: {first_label:?} {scroll:?}");
        assert!(scroll.expand(0.5).contains_rect(first_thumbnail), "initial real thumbnail clipped at {width}: {first_thumbnail:?} {scroll:?}");
        h.call("ui.scroll", json!({"x":scroll.center().x,"y":scroll.center().y,"delta":-300}));
        h.frames(12);
        let last = crate::scenario::handle_at("pdm:version:part:1").unwrap();
        let scroll = crate::scenario::rect_of("pdm_details_scroll").unwrap();
        assert!(scroll.contains(last), "later history row unreachable by wheel at {width}: {last:?} {scroll:?}");
        h.step(&json!({"click":{"handle":"pdm:version:part:1"}})).unwrap();
        h.frames(3);
        assert_eq!(h.app.pdm.selected, Some(Reference { document: "part".into(), version: 1 }));
    }
    let locale = crate::i18n::Locale::for_language("it");
    let notice = locale.format("ui.pdm_operation_succeeded", &[("action", locale.text("ui.pdm_archive")), ("file", "Initial.solidcraft")]);
    assert!(h.widget(&notice).is_some());
}

fn click_catalog_frame(h: &mut Harness, name: &str) -> bool {
    // run_ui can discard/repeat a pass after navigation changes layout. Observe
    // the actual input in its first pass, before a later pass consumes the flag.
    let double = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = double.clone();
    h.ctx.on_begin_pass(
        "pdm physical click",
        Arc::new(move |ui| {
            if ui.input(|input| input.pointer.button_double_clicked(egui::PointerButton::Primary)) {
                observed.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }),
    );
    let pos = crate::scenario::handle_at(name).unwrap();
    h.app.synthetic.push(egui::Event::PointerMoved(pos));
    h.frame();
    h.app.synthetic.extend([true, false].map(|pressed| egui::Event::PointerButton {
        pos,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    }));
    h.frames(2);
    double.load(std::sync::atomic::Ordering::Relaxed)
}

fn feedback_folder_fixture() -> (Harness, ExplorerRequests, ExplorerCompletions) {
    use solidcraft_engine::pdm::{CatalogEntry, ManagedVersion};
    let (mut h, requests, held) = explorer(false);
    let mut state = explorer_state(false);
    state.catalog = vec![
        ("part", "Projects/Root.solidcraft", 2),
        ("other", "Projects/Parts/Pin.solidcraft", 2),
        ("deep", "Projects/Parts/Nested/Child.solidcraft", 1),
        ("sibling", "Projects/Other/Sibling.solidcraft", 1),
        ("outside", "Elsewhere/Foreign.solidcraft", 1),
    ]
    .into_iter()
    .map(|(document, path, head)| CatalogEntry {
        document: document.into(),
        logical_path: path.into(),
        head: Some(head),
        checkout: None,
        head_checked_in_unix_ms: Some(0),
        head_author: Some("tester".into()),
    })
    .collect();
    for local in &mut state.local {
        let path = if local.document == "part" { "Projects/Root.solidcraft" } else { "Projects/Parts/Pin.solidcraft" };
        local.relative_path = path.into();
        local.path = format!("Working/{path}");
    }
    state.history = vec![ManagedVersion {
        version: Version {
            reference: Reference { document: "part".into(), version: 1 },
            parent: None,
            sha256: "00".repeat(32),
            dependencies: Vec::new(),
        },
        author: "tester".into(),
        checked_in_unix_ms: 0,
        comment: "Initial version".into(),
        request_id: "initial-history".into(),
    }];
    let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: "part".into() })).unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state })).unwrap();
    h.app.session.path = Some("Working/Projects/Root.solidcraft".into());
    h.app.session.mark_saved();
    h.app.pdm.selected = Some(Reference { document: "part".into(), version: 1 });
    h.frames(8);
    (h, requests, held)
}

// Break caught: deriving only file rows (or flattening descendant documents)
// makes a populated archive folder appear empty or leaks files from deeper levels.
#[test]
fn feedback_folder_list_shows_immediate_subfolders_before_immediate_files() {
    let (mut h, _requests, _held) = feedback_folder_fixture();
    let other = crate::scenario::handle_at("pdm:folder_row:Projects/Other");
    let parts = crate::scenario::handle_at("pdm:folder_row:Projects/Parts");
    assert!(other.is_some() && parts.is_some(), "the central current-folder list must expose both immediate subfolders");
    let root = crate::scenario::handle_at("pdm:file:part").unwrap();
    assert!(other.unwrap().y < parts.unwrap().y && parts.unwrap().y < root.y, "folders sort before the immediate Root file");
    for document in ["other", "deep", "sibling", "outside"] {
        assert!(
            crate::scenario::handle_at(&format!("pdm:file:{document}")).is_none(),
            "descendant/foreign file {document} was flattened into Projects"
        );
    }
    assert!(crate::scenario::handle_at("pdm:folder_row:Projects/Parts/Nested").is_none());
    h.step(&json!({"click":{"handle":"pdm:sort:0"}})).unwrap();
    h.frames(2);
    let parts = crate::scenario::handle_at("pdm:folder_row:Projects/Parts").unwrap();
    let other = crate::scenario::handle_at("pdm:folder_row:Projects/Other").unwrap();
    let root = crate::scenario::handle_at("pdm:file:part").unwrap();
    assert!(parts.y < other.y && other.y < root.y, "descending names must keep folders grouped before files");
}

// Breaks caught: retaining a document/version target on a folder selection,
// or treating a folder double click as a file operation instead of navigation.
#[test]
fn feedback_folder_selection_clears_file_targets_and_double_click_navigates() {
    let (mut h, requests, _held) = feedback_folder_fixture();
    assert_eq!(crate::pdm_panel::command_unavailable(&h.app, "pdm.restore_version"), None);
    assert!(crate::scenario::handle_at("pdm:version:part:1").is_some());
    h.step(&json!({"click":{"handle":"pdm:folder_row:Projects/Parts"}})).unwrap();
    h.frames(3);
    assert_eq!(h.app.pdm.folder, "Projects", "a single click selects the folder without entering it");
    assert!(h.app.pdm.document.is_empty() && h.app.pdm.selected.is_none());
    assert!(h.app.pdm.restore_confirmation.is_none());
    assert!(crate::scenario::handles("pdm:version:").is_empty(), "folders have no file version history");
    for command in
        ["pdm.open_document", "pdm.checkout", "pdm.archive", "pdm.cancel_checkout", "pdm.get_latest", "pdm.open_archived", "pdm.restore_version"]
    {
        assert!(crate::pdm_panel::command_unavailable(&h.app, command).is_some(), "folder selection enabled {command}");
    }
    h.app.session.path = Some("Working/New.solidcraft".into());
    h.app.session.mark_saved();
    h.frames(2);
    assert!(
        crate::pdm_panel::command_unavailable(&h.app, "pdm.archive").is_some(),
        "a folder selection must not publish an unrelated unmanaged active editor"
    );
    h.step(&json!({"click":{"handle":"pdm:search"}})).unwrap();
    h.step(&json!({"text":"Parts"})).unwrap();
    h.frames(2);
    let search_at = crate::scenario::handle_at("pdm:search").unwrap();
    assert!(h.output.accesskit_update.as_ref().unwrap().nodes.iter().any(|(_, node)| node.value() == Some("Parts")
        && node.bounds().is_some_and(|bounds| f64::from(search_at.x) >= bounds.x0
            && f64::from(search_at.x) <= bounds.x1
            && f64::from(search_at.y) >= bounds.y0
            && f64::from(search_at.y) <= bounds.y1)));
    assert!(crate::scenario::handle_at("pdm:file:other").is_none(), "search stays within the current folder rather than flattening descendants");
    // Search's focus click is a separate gesture. egui prioritizes a triple
    // click when last_last_click_time is within twice the double-click window,
    // so finish that window before sending the folder's two physical clicks.
    let search_gesture_frames = h.ctx.options(|options| (options.input_options.max_double_click_delay * 2.0 * 60.0).ceil() as usize + 1);
    h.frames(search_gesture_frames);
    click_catalog_frame(&mut h, "pdm:folder_row:Projects/Parts");
    let double = click_catalog_frame(&mut h, "pdm:folder_row:Projects/Parts");
    assert!(double, "the input stream must contain a physical second click within the egui interval");
    h.frames(3);
    assert_eq!(h.app.pdm.folder, "Projects/Parts");
    assert!(h.app.pdm.document.is_empty() && h.app.pdm.selected.is_none());
    assert!(crate::scenario::handle_at("pdm:file:other").is_some());
    assert!(crate::scenario::handle_at("pdm:folder_row:Projects/Parts/Nested").is_some());
    assert!(crate::scenario::handle_at("pdm:file:deep").is_none());
    assert!(
        crate::scenario::handle_at("pdm:folder:Projects/Parts/Nested").is_some(),
        "entering a folder must reveal its children in the synchronized tree"
    );
    assert!(h.widget("Parts").is_some(), "the breadcrumb must include the entered folder");
    let search_at = crate::scenario::handle_at("pdm:search").unwrap();
    assert!(
        !h.output.accesskit_update.as_ref().unwrap().nodes.iter().any(|(_, node)| node.value() == Some("Parts")
            && node.bounds().is_some_and(|bounds| f64::from(search_at.x) >= bounds.x0
                && f64::from(search_at.x) <= bounds.x1
                && f64::from(search_at.y) >= bounds.y0
                && f64::from(search_at.y) <= bounds.y1)),
        "entering a folder clears the old folder's search filter"
    );
    assert!(requests.lock().unwrap().is_empty(), "folder navigation must not enqueue a file mutation");
}

// Break caught: a connected toolbar presents a second Connect operation rather
// than the explicit Disconnect action, or a repeated click queues duplicates.
#[test]
fn feedback_connection_connected_toolbar_disables_connect_and_disconnects_once() {
    let (mut h, requests, held) = explorer(false);
    let connect = solidcraft_engine::find_command("pdm.connect").unwrap();
    let info = h.app.command_info(connect);
    assert!(!info.enabled, "Connect must be disabled for the current verified connection");
    assert_eq!(info.disabled_reason.as_deref(), Some(h.app.tr("ui.pdm_connected")));
    h.step(&json!({"click":{"handle":"pdm:connect_settings"}})).unwrap();
    h.frames(2);
    assert!(!h.app.pdm.open, "disabled Connect must not open a second connection flow");
    h.step(&json!({"click":{"handle":"pdm:disconnect_toolbar"}})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:disconnect_toolbar"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0], Task::Disconnect));
    complete_explorer(&mut h, &held, Err(Failure { message: "Disconnect was not confirmed".into(), disconnect: false }));
    assert_eq!(h.app.pdm.runtime.status().unwrap().port, Some(48231));
    assert!(!h.app.command_info(connect).enabled, "a failed disconnect cannot enable Connect");
    h.step(&json!({"click":{"handle":"pdm:disconnect_toolbar"}})).unwrap();
    h.frames(2);
    complete_explorer(&mut h, &held, Ok(Outcome::Disconnected));
    assert!(h.app.pdm.runtime.status().unwrap().port.is_none());
    assert!(h.app.command_info(connect).enabled);
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[test]
fn feedback_connection_disconnected_error_and_busy_keep_connect_single_flight() {
    let (mut h, requests, held) = explorer(false);
    let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
    h.app.pdm.runtime.finish(id, Err(Failure { message: "The server connection was lost".into(), disconnect: true })).unwrap();
    h.frames(2);
    let connect = solidcraft_engine::find_command("pdm.connect").unwrap();
    assert!(h.app.command_info(connect).enabled, "an actual disconnect permits a fresh connection");
    h.step(&json!({"click":{"handle":"pdm:connect_settings"}})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:connect_settings"}})).unwrap();
    h.frames(3);
    assert!(h.app.pdm.open);
    assert_eq!(requests.lock().unwrap().len(), 1, "the manager must inventory connections once despite repeated Connect clicks");
    assert!(matches!(&requests.lock().unwrap()[0], Task::Managed(ManagedTask::ListConnections)));
    assert!(!h.app.command_info(connect).enabled, "pending connection work disables Connect across command surfaces");
    h.app.pdm.workspace_active = false;
    h.app.ui.tab = "PDM".into();
    h.frames(2);
    assert!(!h.app.command_info(connect).enabled, "the CAD PDM ribbon uses the same busy policy");
    complete_explorer(&mut h, &held, Err(Failure { message: "The inventory request failed".into(), disconnect: true }));
    assert!(h.app.command_info(connect).enabled, "a failed disconnected request may be retried");
}

// Break caught: icons stay beside labels or only the icon is clickable, losing
// the requested full vertical button interaction and readable original artwork.
#[test]
fn feedback_toolbar_places_original_icons_above_labels_with_one_hit_area() {
    let (mut h, requests, _held) = explorer(false);
    let button = crate::scenario::rect_of("pdm_action_button:pdm.checkout").unwrap();
    let icon = crate::scenario::rect_of("pdm_action:pdm.checkout").unwrap();
    assert!((icon.center().x - button.center().x).abs() < 1.0, "the action icon must be centered above its label");
    let label = crate::scenario::rect_of("pdm_action_label:pdm.checkout").unwrap();
    assert!(icon.bottom() <= label.top(), "icon and label are vertical, not overlaid or side by side");
    assert!(icon.height() > label.height() * 1.5, "the icon remains readable artwork rather than a text-sized glyph");
    assert!(button.contains_rect(icon) && button.contains_rect(label));
    h.step(&json!({"click":[button.center().x,button.bottom()-3.0]})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1, "the lower label/button region must be clickable");
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Checkout{document:Some(document),..})if document=="part"));
}

#[test]
fn feedback_file_double_click_waits_for_open_then_activates_existing_tab_in_design() {
    let (mut h, requests, held) = explorer(false);
    let original = h.app.docs.active;
    let mut other = Session::default();
    other.path = Some("Working/other.solidcraft".into());
    other.mark_saved();
    crate::documents::open_tab(&mut h.app, other).unwrap();
    let existing = h.app.docs.active;
    crate::documents::switch(&mut h.app, original);
    crate::pdm_panel::enter(&mut h.app).unwrap();
    h.frames(3);
    let count = h.app.docs.count();
    click_catalog_frame(&mut h, "pdm:file:other");
    h.frames(2);
    assert!(h.app.pdm.runtime.status().unwrap().busy.is_none(), "first-click metadata must leave the physical double-click interval free");
    click_catalog_frame(&mut h, "pdm:file:other");
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1, "a file double click must enqueue one working-copy open");
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Open{document})if document=="other"));
    assert!(h.app.pdm.workspace_active, "pending IO must leave the archive workspace visible");
    assert_eq!(h.app.docs.active, original);
    assert_eq!(h.app.session.path.as_deref(), Some("Working/part.solidcraft"));
    // Repeated clicks, including a different row, cannot queue another job or
    // redirect the load already in flight to the newly selected file.
    h.step(&json!({"click":{"handle":"pdm:file:other"},"double":true})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:file:part"},"double":true})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(h.app.pdm.document, "part");
    assert!(h.app.pdm.workspace_active);
    let mut loaded = Session::default();
    loaded.path = Some("Working/other.solidcraft".into());
    loaded.mark_saved();
    held.lock()
        .unwrap()
        .remove(0)
        .send(Completion { result: Ok(Outcome::Managed { port: 48231, state: explorer_state(false) }), open: Some(Box::new(loaded)) })
        .unwrap();
    h.frames(5);
    assert!(!h.app.pdm.workspace_active, "DESIGN is entered only after a successful working-copy load");
    assert_eq!(h.app.docs.active, existing, "opening a known working path activates its existing tab");
    assert_eq!(h.app.docs.count(), count, "double click must not duplicate an existing working-copy tab");
    assert_eq!(h.app.session.path.as_deref(), Some("Working/other.solidcraft"));
    assert_eq!(requests.lock().unwrap().len(), 1, "opening must not acquire a checkout or publish anything");
}

#[test]
fn feedback_file_double_click_failure_keeps_the_archive_and_current_document() {
    let (mut h, requests, held) = explorer(false);
    let active = h.app.docs.active;
    let count = h.app.docs.count();
    let before = h.app.session.doc.clone();
    h.step(&json!({"click":{"handle":"pdm:file:other"},"double":true})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Open{document})if document=="other"));
    assert!(h.app.pdm.workspace_active);
    complete_explorer(&mut h, &held, Err(Failure { message: "Working copy could not be opened".into(), disconnect: false }));
    assert!(h.app.pdm.workspace_active);
    assert_eq!(h.app.docs.active, active);
    assert_eq!(h.app.docs.count(), count);
    assert_eq!(h.app.session.path.as_deref(), Some("Working/part.solidcraft"));
    assert_eq!(*h.app.session.doc, *before);
    assert!(h.widget("Open Working Copy failed for Projects/other.solidcraft: Working copy could not be opened").is_some());
}

#[test]
fn feedback_history_sorts_numeric_versions_newest_first_and_keeps_reference_selection() {
    use solidcraft_engine::pdm::ManagedVersion;
    let (mut h, requests, _held) = explorer(false);
    let mut state = explorer_state(false);
    state.catalog.iter_mut().find(|entry| entry.document == "part").unwrap().head = Some(10);
    state.local.iter_mut().find(|entry| entry.document == "part").unwrap().base_version = 10;
    state.history = [(1, 300), (2, 200), (10, 100)]
        .into_iter()
        .map(|(number, date)| ManagedVersion {
            version: Version {
                reference: Reference { document: "part".into(), version: number },
                parent: None,
                sha256: "00".repeat(32),
                dependencies: Vec::new(),
            },
            author: "tester".into(),
            checked_in_unix_ms: date,
            comment: format!("Version {number}"),
            request_id: format!("version-{number}"),
        })
        .collect();
    let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: "part".into() })).unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state: state.clone() })).unwrap();
    h.app.pdm.selected = Some(Reference { document: "part".into(), version: 2 });
    h.frames(8);
    let v10 = crate::scenario::handle_at("pdm:version:part:10").unwrap();
    let v2 = crate::scenario::handle_at("pdm:version:part:2").unwrap();
    let v1 = crate::scenario::handle_at("pdm:version:part:1").unwrap();
    assert!(v10.y < v2.y && v2.y < v1.y, "history order must follow numeric version, not insertion order, timestamp, or lexical text");
    state.catalog.iter_mut().find(|entry| entry.document == "part").unwrap().head = Some(11);
    state.local.iter_mut().find(|entry| entry.document == "part").unwrap().base_version = 11;
    state.history.push(ManagedVersion {
        version: Version {
            reference: Reference { document: "part".into(), version: 11 },
            parent: Some(10),
            sha256: "00".repeat(32),
            dependencies: Vec::new(),
        },
        author: "tester".into(),
        checked_in_unix_ms: 50,
        comment: "Latest version".into(),
        request_id: "version-11".into(),
    });
    let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: "part".into() })).unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state })).unwrap();
    h.frames(6);
    assert!(crate::scenario::handle_at("pdm:version:part:11").unwrap().y < crate::scenario::handle_at("pdm:version:part:10").unwrap().y);
    assert_eq!(
        h.app.pdm.selected,
        Some(Reference { document: "part".into(), version: 2 }),
        "inserting a head must not shift the selected version identity"
    );
    h.step(&json!({"click":{"handle":"pdm:restore_version"}})).unwrap();
    h.frames(2);
    assert_eq!(h.app.pdm.restore_confirmation, Some(Reference { document: "part".into(), version: 2 }));
    h.step(&json!({"widget":"Cancel"})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:open_archived"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(
        matches!(&requests.lock().unwrap()[0],Task::Retrieve{reference,open:true}if reference.document=="part" && reference.version==2),
        "captured request: {:?}",
        requests.lock().unwrap()
    );
}

fn dirty_archive_fixture() -> (Harness, ExplorerRequests, ExplorerCompletions, std::path::PathBuf) {
    let (mut h, requests, held) = explorer(true);
    let path = h.dir.join("part.solidcraft");
    h.app.run("file.save", json!({"path":path})).unwrap();
    let mut state = explorer_state(true);
    state.root = Some(h.dir.to_string_lossy().into_owned());
    state.local.iter_mut().find(|entry| entry.document == "part").unwrap().path = path.to_string_lossy().into_owned();
    let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::ManagedRefreshed { port: 48231, state })).unwrap();
    h.app.session.doc_mut().name = "Unsaved owned design".into();
    (h, requests, held, path)
}

#[test]
fn autosave_archive_saves_exact_active_memory_before_one_captured_publication() {
    let (mut h, requests, _held, path) = dirty_archive_fixture();
    let before = std::fs::read(&path).unwrap();
    h.app.run("pdm.archive", json!({"document":"part"})).unwrap();
    assert!(h.app.saving.is_some(), "dirty Check In must start an asynchronous save");
    assert!(requests.lock().unwrap().is_empty(), "publication cannot precede save completion");
    assert!(h.app.run("pdm.archive", json!({"document":"part"})).is_err());
    assert!(h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).is_err());
    assert!(h.app.run("pdm.cancel_checkout", json!({"document":"part","discard":true})).is_err(), "discard cannot race an in-flight save writer");
    h.app.pdm.document = "other".into();
    crate::save_job::tick(&mut h.app, true);
    h.frames(2);
    assert!(!h.app.session.is_dirty());
    let bytes = std::fs::read(&path).unwrap();
    assert_ne!(bytes, before);
    let saved = solidcraft_engine::io::read_design(&bytes).unwrap();
    assert_eq!(saved.name, "Unsaved owned design");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        matches!(&requests[0],Task::Managed(ManagedTask::Archive{path:target,saved,..}) if target==path.to_str().unwrap() && saved.name=="Unsaved owned design")
    );
}

#[test]
fn autosave_failure_preserves_unsaved_editor_and_never_publishes() {
    let (mut h, requests, _held, path) = dirty_archive_fixture();
    let before = std::fs::read(&path).unwrap();
    let bad = h.dir.join("missing").join("part.solidcraft");
    let mut state = explorer_state(true);
    state.root = Some(h.dir.to_string_lossy().into_owned());
    state.local.iter_mut().find(|entry| entry.document == "part").unwrap().path = bad.to_string_lossy().into_owned();
    let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::ManagedRefreshed { port: 48231, state })).unwrap();
    h.app.session.path = Some(bad.to_string_lossy().into_owned());
    h.app.run("pdm.archive", json!({"document":"part"})).unwrap();
    crate::save_job::tick(&mut h.app, true);
    h.frames(2);
    assert!(requests.lock().unwrap().is_empty());
    assert!(h.app.session.is_dirty());
    assert_eq!(h.app.session.doc.name, "Unsaved owned design");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!bad.exists());
    assert!(h.app.status.as_ref().is_some_and(|(_, _, error)| *error));
}

#[test]
fn autosave_stale_completion_never_marks_new_memory_saved_or_publishes_it() {
    let (mut h, requests, _held, _path) = dirty_archive_fixture();
    h.app.run("pdm.archive", json!({"document":"part"})).unwrap();
    // Simulate a replaced editor behind the normal busy guard. It must not be
    // adopted as the worker's saved document or published under its receipt.
    h.app.session.doc_mut().name = "Newer editor memory".into();
    crate::save_job::tick(&mut h.app, true);
    h.frames(2);
    assert_eq!(h.app.session.doc.name, "Newer editor memory");
    assert!(h.app.session.is_dirty());
    assert!(requests.lock().unwrap().is_empty());
    assert!(h.app.status.as_ref().is_some_and(|(_, _, error)| *error));
}

#[test]
fn discard_dirty_owned_checkout_requires_confirmation_then_replaces_only_acknowledged_memory() {
    let (mut h, requests, held, path) = dirty_archive_fixture();
    let before = h.app.session.doc.clone();
    assert!(h.app.command_info(solidcraft_engine::find_command("pdm.cancel_checkout").unwrap()).enabled);
    assert!(h.app.run("pdm.cancel_checkout", json!({"document":"part"})).is_err());
    h.app.start("pdm.cancel_checkout");
    h.frames(2);
    assert!(h.app.pdm.cancel_confirmation);
    h.step(&json!({"widget":"Cancel"})).unwrap();
    assert_eq!(*h.app.session.doc, *before);
    assert!(h.app.session.is_dirty());
    assert!(requests.lock().unwrap().is_empty());
    h.app.start("pdm.cancel_checkout");
    h.frames(2);
    h.step(&json!({"click":{"handle":"pdm:cancel_checkout_confirm"}})).unwrap();
    assert_eq!(*h.app.session.doc, *before, "confirmation alone must not claim disk restoration");
    assert!(h.app.session.is_dirty());
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::CancelCheckout{document:Some(document),..})if document=="part"));
    let mut restored = Session::default();
    restored.path = Some(path.to_string_lossy().into_owned());
    restored.doc_mut().name = "Archived head".into();
    restored.mark_saved();
    let mut state = explorer_state(false);
    state.root = Some(h.dir.to_string_lossy().into_owned());
    state.local.iter_mut().find(|entry| entry.document == "part").unwrap().path = path.to_string_lossy().into_owned();
    held.lock().unwrap().remove(0).send(Completion { result: Ok(Outcome::Managed { port: 48231, state }), open: Some(Box::new(restored)) }).unwrap();
    h.frames(4);
    assert_eq!(h.app.session.doc.name, "Archived head");
    assert!(!h.app.session.is_dirty());
}

#[test]
fn discard_failure_keeps_unsaved_ram_and_does_not_claim_a_released_checkout() {
    let (mut h, requests, held, _path) = dirty_archive_fixture();
    let before = h.app.session.doc.clone();
    h.app.run("pdm.cancel_checkout", json!({"document":"part","discard":true})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    complete_explorer(&mut h, &held, Err(Failure { message: "Server is offline".into(), disconnect: true }));
    assert_eq!(*h.app.session.doc, *before);
    assert!(h.app.session.is_dirty());
    assert!(h.app.pdm.runtime.status().unwrap().managed.local.iter().any(|entry| entry.document == "part" && entry.checked_out));
    assert!(
        h.widget("Undo Checkout failed for Projects/part.solidcraft: Server is offline").is_some(),
        "the persistent PDM footer must report the failed discard"
    );
}

#[test]
fn discard_stale_acknowledgement_cannot_replace_newer_editor_memory() {
    let (mut h, _requests, held, path) = dirty_archive_fixture();
    h.app.run("pdm.cancel_checkout", json!({"document":"part","discard":true})).unwrap();
    h.frames(2);
    h.app.session.doc_mut().name = "Newer unacknowledged edits".into();
    let mut loaded = Session::default();
    loaded.path = Some(path.to_string_lossy().into_owned());
    loaded.mark_saved();
    let mut state = explorer_state(false);
    state.root = Some(h.dir.to_string_lossy().into_owned());
    state.local.iter_mut().find(|entry| entry.document == "part").unwrap().path = path.to_string_lossy().into_owned();
    held.lock().unwrap().remove(0).send(Completion { result: Ok(Outcome::Managed { port: 48231, state }), open: Some(Box::new(loaded)) }).unwrap();
    h.frames(4);
    assert_eq!(h.app.session.doc.name, "Newer unacknowledged edits");
    assert!(h.app.session.is_dirty());
    assert!(h.app.status.as_ref().is_some_and(|(_, _, error)| *error));
}

#[test]
fn context_menu_file_actions_capture_the_right_clicked_row_and_shared_policy() {
    let (mut h, requests, _held) = explorer(false);
    h.step(&json!({"click":{"handle":"pdm:file:other"},"button":"right"})).unwrap();
    h.frames(2);
    assert_eq!(h.app.pdm.document, "other");
    let node = solidcraft_engine::find_command("pdm.archive").unwrap();
    assert!(!h.app.command_info(node).enabled, "another active editor cannot archive the right-clicked file");
    h.step(&json!({"click":{"handle":"pdm:context_open"}})).unwrap();
    h.frames(2);
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Open{document})if document=="other"));
}

#[test]
fn context_menu_working_folder_only_reveals_an_existing_file_within_the_verified_root() {
    let (mut h, _requests, _held, path) = dirty_archive_fixture();
    let shown = Arc::new(Mutex::new(Vec::new()));
    let observed = shown.clone();
    h.app.services.show_in_folder = Some(Box::new(move |path| observed.lock().unwrap().push(path.to_string())));
    h.frames(2);
    h.step(&json!({"click":{"handle":"pdm:file:part"},"button":"right"})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:context_working_folder"}})).unwrap();
    assert_eq!(*shown.lock().unwrap(), vec![std::fs::canonicalize(&path).unwrap().to_string_lossy().into_owned()]);
    let mut state = explorer_state(true);
    state.root = Some(h.dir.join("another-root").to_string_lossy().into_owned());
    state.local.iter_mut().find(|entry| entry.document == "part").unwrap().path = path.to_string_lossy().into_owned();
    let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
    h.app.pdm.runtime.finish(id, Ok(Outcome::ManagedRefreshed { port: 48231, state })).unwrap();
    h.frames(2);
    h.step(&json!({"click":{"handle":"pdm:file:part"},"button":"right"})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:context_working_folder"}})).unwrap();
    assert_eq!(shown.lock().unwrap().len(), 1, "an outside or missing working root cannot launch Explorer");
}

#[test]
fn context_menu_go_to_folder_clears_search_and_keeps_the_right_clicked_file_selected() {
    let (mut h, _requests, _held) = explorer(false);
    h.step(&json!({"click":{"handle":"pdm:search"}})).unwrap();
    h.step(&json!({"text":"other"})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:file:other"},"button":"right"})).unwrap();
    h.step(&json!({"click":{"handle":"pdm:context_folder"}})).unwrap();
    h.frames(2);
    assert_eq!(h.app.pdm.folder, "Projects");
    assert_eq!(h.app.pdm.document, "other");
    assert!(crate::scenario::handle_at("pdm:file:part").is_some(), "clearing the filter must reveal the immediate sibling again");
}

#[test]
fn autosave_invalid_archive_parameters_never_start_a_save_or_publication() {
    let (mut h, requests, _held, path) = dirty_archive_fixture();
    let before = std::fs::read(&path).unwrap();
    for params in [json!({"document":"part","token":"synthetic-test-field"}), json!({"document":12}), json!({"document":"part","reconcile":"true"})] {
        assert!(h.app.run("pdm.archive", params).is_err());
        assert!(h.app.saving.is_none());
        assert!(requests.lock().unwrap().is_empty());
        assert!(h.app.session.is_dirty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn opt_in_clean_preferences_leave_pdm_dormant_during_ordinary_edit_save_and_open() {
    let mut h = Harness::new();
    h.app.preferences = crate::prefs::Prefs::default();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    h.app.services.pdm = Some(Arc::new(move |job| {
        observed.lock().unwrap().push(job.task);
        let (send, receive) = mpsc::channel();
        send.send(Completion { result: Err(Failure { message: "Unexpected PDM activation".into(), disconnect: true }), open: None }).unwrap();
        receive
    }));
    h.app.home.show(h.app.session.revision);
    h.frames(40);
    assert!(!h.app.pdm.tab_open() && !h.app.pdm.open && !h.app.pdm.workspace_active);
    assert!(crate::scenario::handle_at("tab:pdm").is_none());
    h.app.home.open = false;
    h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
    let path = h.dir.join("ordinary.solidcraft");
    h.app.run("file.save", json!({"path":path})).unwrap();
    h.app.run("solid.sphere", json!({"diameter":2})).unwrap();
    h.app.run("file.save", json!({})).unwrap();
    let before = h.app.session.doc.clone();
    h.app.open_path_async(path.to_str().unwrap());
    h.settle();
    h.frames(20);
    assert_eq!(*h.app.session.doc, *before);
    assert_eq!(h.app.session.path.as_deref(), path.to_str());
    assert!(!h.app.session.is_dirty());
    assert!(requests.lock().unwrap().is_empty(), "ordinary work must not inventory, connect, or request any PDM operation");
    assert!(!h.app.pdm.tab_open() && !h.app.pdm.open && !h.app.pdm.workspace_active);
    assert!(crate::scenario::handle_at("tab:pdm").is_none());
    assert!(h.app.pdm.pending_edit.is_none() && h.app.pdm.ram_paths.is_empty());
    let status = h.app.pdm.runtime.status().unwrap();
    assert!(status.port.is_none() && status.connection.is_none() && status.busy.is_none());
    assert!(
        status.managed.server_id.is_none()
            && status.managed.workspace.is_none()
            && status.managed.local.is_empty()
            && status.managed.catalog.is_empty()
    );
    assert!(!h.app.pdm.runtime.blocks_path(path.to_str().unwrap()));
    assert!(h.app.pdm.runtime.managed_for_path(path.to_str().unwrap()).is_none());
    assert!(h.app.session.check_pdm_reopen().is_ok());
}
