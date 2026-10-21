//! Save and Save As off the window's thread (#3044): writing a large design (and the model a
//! save keeps with it) takes long enough that the window must keep drawing meanwhile. The
//! command runs on a copy of the session on a worker; the design waits for it like it waits for
//! a file picker, and the outcome is taken up as running the command here would have left it.

use serde_json::Value;
use solidcraft_engine::Session;

use crate::SolveApp;

/// A save being written on a worker thread.
pub struct Saving {
    command: &'static str,
    stamp: crate::documents::EditorStamp,
    archive: Option<Value>,
    done: std::sync::mpsc::Receiver<(Session, Result<Value, String>)>,
    graph: Option<GraphSaving>,
}

struct GraphSaving {
    params: Value,
    done: std::sync::mpsc::Receiver<GraphResult>,
}
struct GraphResult {
    saved: Vec<(crate::documents::EditorStamp, Session)>,
    result: Result<(), String>,
}

pub(crate) fn archive_graph(app: &mut SolveApp, params: Value, graph: crate::documents::ArchiveGraph) -> Result<Value, String> {
    let stamp = crate::documents::EditorStamp::active(app)?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("save-linked-designs".into())
        .spawn(move || {
            let mut saved = Vec::new();
            let result = (|| {
                for mut node in graph.nodes {
                    if !node.save {
                        continue;
                    }
                    if !node.session.doc.links.is_empty() {
                        node.session.execute("component.update_links", &serde_json::json!({"recursive":true})).map_err(|error| error.to_string())?;
                    }
                    node.session.execute("file.save", &serde_json::json!({})).map_err(|error| error.to_string())?;
                    if let Some(stamp) = node.stamp {
                        saved.push((stamp, node.session));
                    }
                }
                Ok(())
            })();
            let _ = sender.send(GraphResult { saved, result });
        })
        .map_err(|_| "The linked-design save worker could not start")?;
    let (_, unused) = std::sync::mpsc::channel();
    app.saving = Some(Saving { command: "file.save", stamp, archive: None, done: unused, graph: Some(GraphSaving { params, done: receiver }) });
    Ok(serde_json::json!({"saving":true,"pending":true}))
}

/// Run `file.save` or `file.save_as` with `params`. On the desktop it runs on a worker and is
/// taken up by [`tick`] (true: it is under way); in the browser, or when no thread can start, it
/// runs here and is finished on return (false).
pub fn start(app: &mut SolveApp, command: &'static str, params: Value) -> bool {
    start_with(app, command, params, None).unwrap_or(false)
}

pub(crate) fn archive(app: &mut SolveApp, params: Value) -> Result<Value, String> {
    let pending = start_with(app, "file.save", serde_json::json!({}), Some(params))?;
    Ok(serde_json::json!({"saving":pending,"pending":pending}))
}

fn start_with(app: &mut SolveApp, command: &'static str, params: Value, archive: Option<Value>) -> Result<bool, String> {
    #[cfg(not(target_arch = "wasm32"))]
    if app.saving.is_none() && app.file_picker.is_none() && !app.file_load.busy() {
        let stamp = crate::documents::EditorStamp::active(app)?;
        let mut copy = app.session.scratch();
        // The copy has no file: the command saves to this session's (and names the design after it).
        copy.path.clone_from(&app.session.path);
        // Scratch sessions intentionally detach host authority. A save worker is
        // still this editor: keep the shared ledger and its exact load stamp.
        copy.pdm = app.pdm.runtime.clone();
        copy.pdm_read_only = app.session.pdm_read_only;
        copy.pdm_recovery_epoch = app.session.pdm_recovery_epoch;
        let (tx, rx) = std::sync::mpsc::channel();
        let given = params.clone();
        let job = std::thread::Builder::new().name("save".into()).spawn(move || {
            let r = copy.execute(command, &given).map_err(|e| e.to_string());
            let _ = tx.send((copy, r));
        });
        if job.is_ok() {
            app.saving = Some(Saving { command, done: rx, stamp, archive, graph: None });
            return Ok(true);
        }
        // No thread to write on: save here, as before.
    }
    app.run(command, params)?;
    if let Some(params) = archive {
        app.run("pdm.archive", params)?;
    }
    Ok(false)
}

/// Take up a finished save (`wait`: wait for a running one).
pub fn tick(app: &mut SolveApp, wait: bool) {
    let Some(saving) = app.saving.as_ref() else { return };
    if let Some(graph) = &saving.graph {
        let outcome = if wait {
            graph.done.recv().ok()
        } else {
            match graph.done.try_recv() {
                Ok(outcome) => Some(outcome),
                Err(std::sync::mpsc::TryRecvError::Empty) => return,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
            }
        };
        let Some(Saving { graph: Some(graph), stamp, .. }) = app.saving.take() else { return };
        let result = (|| {
            if !stamp.matches_active(app) {
                return Err("The editor changed while saving linked designs; archive was not started".to_string());
            }
            let outcome = outcome.ok_or("The linked-design save worker stopped")?;
            for (stamp, session) in outcome.saved {
                crate::documents::apply_archive_save(app, &stamp, &session)?;
            }
            outcome.result?;
            app.run("pdm.archive", graph.params.clone()).map(|_| ())
        })();
        if let Err(error) = result {
            crate::pdm_panel::archive_save_failed(app, &graph.params, error);
        }
        return;
    }
    let outcome = if wait {
        saving.done.recv().ok()
    } else {
        match saving.done.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
        }
    };
    let Some(Saving { command, stamp, archive, .. }) = app.saving.take() else { return };
    let r = match outcome {
        Some((_, Ok(_))) if !stamp.matches_active(app) => Err("The editor changed while saving; check in was not started".into()),
        Some((copy, Ok(v))) => {
            app.session.adopt_save(&copy);
            app.session.pdm_read_only = copy.pdm_read_only;
            app.session.pdm_recovery_epoch = copy.pdm_recovery_epoch;
            Ok(v)
        }
        Some((_, Err(e))) => Err(e),
        None => Err(format!("{command}: the save stopped")),
    };
    app.finish_command(command, &r);
    if let Some(params) = archive {
        let result = match &r {
            Ok(_) => app.run("pdm.archive", params.clone()).map(|_| ()),
            Err(error) => Err(error.clone()),
        };
        if let Err(error) = result {
            crate::pdm_panel::archive_save_failed(app, &params, error);
        }
    }
    crate::documents::saved_for_close(app);
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use solidcraft_engine::Session;

    /// #3044: Save writes on a worker while the window keeps drawing; the design waits (commands
    /// are refused) until the save is taken up, which leaves it saved under its file, in the
    /// recent files, with the command echoed, as a save run here does.
    #[test]
    fn save_writes_on_a_worker_and_is_taken_up_like_a_save_here() {
        let mut h = crate::scenario::Harness::new();
        h.app.run("solid.box", json!({"length": 10, "width": 10, "height": 10})).unwrap();
        let path = h.dir.join("Plate.solidcraft");
        assert!(super::start(&mut h.app, "file.save_as", json!({"path": path.to_string_lossy()})), "under way on a worker");
        assert!(h.app.file_picker_busy() && h.app.run("solid.sphere", json!({"diameter": 4})).is_err(), "the design waits for it");
        h.frame();
        h.settle();
        assert!(h.app.saving.is_none() && !h.app.session.is_dirty());
        assert_eq!(h.app.session.path.as_deref(), path.to_str());
        assert_eq!(h.app.session.doc.name, "Plate");
        assert!(h.app.home.recent.iter().any(|r| r.as_str() == path.to_str().unwrap()), "{:?}", h.app.home.recent);
        assert!(h.app.session.log.iter().any(|l| l.contains("Save As")), "{:?}", h.app.session.log);
        // A failing save reports why, and leaves the changes unsaved.
        h.app.run("solid.sphere", json!({"diameter": 4})).unwrap();
        let bad = h.dir.join("missing").join("x.solidcraft");
        super::start(&mut h.app, "file.save_as", json!({"path": bad.to_string_lossy()}));
        super::tick(&mut h.app, true);
        assert!(h.app.session.is_dirty() && h.app.status.as_ref().is_some_and(|(_, _, error)| *error));
    }
    fn managed(path: &std::path::Path, checked_out: bool) -> solidcraft_engine::pdm::ManagedState {
        use solidcraft_engine::pdm::{CatalogEntry, Checkout, LocalEntry, ManagedState};
        ManagedState {
            server_id: Some("save-server".into()),
            workspace: Some("workspace-a".into()),
            catalog: vec![CatalogEntry {
                document: "part".into(),
                logical_path: "part.solidcraft".into(),
                head: Some(1),
                checkout: checked_out.then(|| Checkout {
                    owner: "alice".into(),
                    workspace: "workspace-a".into(),
                    machine: "desktop".into(),
                    checked_out_unix_ms: 1,
                    base_version: Some(1),
                }),
                head_checked_in_unix_ms: None,
                head_author: None,
            }],
            local: vec![LocalEntry {
                document: "part".into(),
                path: path.to_string_lossy().into_owned(),
                relative_path: "part.solidcraft".into(),
                base_version: 1,
                sha256: "ab".repeat(32),
                checked_out,
                modified: false,
                present: true,
            }],
            ..Default::default()
        }
    }
    fn connect(h: &mut crate::scenario::Harness, state: solidcraft_engine::pdm::ManagedState) {
        use solidcraft_engine::pdm::{Outcome, Task};
        h.app.pdm.runtime.set_available(true).unwrap();
        if h.app.pdm.runtime.status().unwrap().port.is_some() {
            // Reconnect fixtures follow the same explicit disconnect as users,
            // while the runtime retains the protected destination ledger.
            let id = h.app.pdm.runtime.enqueue(Task::Disconnect).unwrap();
            h.app.pdm.runtime.finish(id, Ok(Outcome::Disconnected)).unwrap();
        }
        let id = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
        h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state })).unwrap();
        h.app.session.pdm = h.app.pdm.runtime.clone();
    }
    #[test]
    fn background_save_preserves_managed_historical_and_inactive_workspace_guards() {
        for protection in 0..3 {
            let mut h = crate::scenario::Harness::new();
            let path = h.dir.join("part.solidcraft");
            h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
            h.app.run("file.save", json!({"path":path})).unwrap();
            let before = std::fs::read(&path).unwrap();
            match protection {
                0 => connect(&mut h, managed(&path, false)),
                1 => {
                    connect(
                        &mut h,
                        solidcraft_engine::pdm::ManagedState { historical_paths: vec![path.to_string_lossy().into_owned()], ..Default::default() },
                    );
                    h.app.session.pdm_read_only = true;
                }
                _ => {
                    connect(&mut h, managed(&path, true));
                    connect(
                        &mut h,
                        solidcraft_engine::pdm::ManagedState {
                            server_id: Some("save-server".into()),
                            workspace: Some("workspace-b".into()),
                            ..Default::default()
                        },
                    );
                }
            }
            h.app.session.doc_mut().name = "unsaved changes".into();
            for command in ["file.save", "file.save_as"] {
                let params = if command == "file.save" { json!({}) } else { json!({"path":path}) };
                assert!(super::start(&mut h.app, command, params));
                super::tick(&mut h.app, true);
                assert_eq!(std::fs::read(&path).unwrap(), before, "protection {protection}");
                assert!(h.app.session.is_dirty());
                assert!(h.app.status.as_ref().is_some_and(|(_, _, error)| *error));
            }
            let separate = h.dir.join("separate.solidcraft");
            assert!(super::start(&mut h.app, "file.save_as", json!({"path":separate})));
            super::tick(&mut h.app, true);
            assert!(separate.exists());
            assert_eq!(h.app.session.path.as_deref(), separate.to_str());
            assert!(!h.app.session.pdm_read_only);
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(super::start(&mut h.app, "file.save_as", json!({"path":path})));
            super::tick(&mut h.app, true);
            assert!(h.app.status.as_ref().is_some_and(|(_, _, error)| *error));
            assert_eq!(h.app.session.path.as_deref(), separate.to_str());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
    #[test]
    fn background_save_preserves_original_recovery_fence_and_detaches_a_separate_copy() {
        use solidcraft_engine::pdm::{Failure, ManagedTask, Task};
        let mut h = crate::scenario::Harness::new();
        let path = h.dir.join("part.solidcraft");
        h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
        h.app.run("file.save", json!({"path":path})).unwrap();
        connect(&mut h, managed(&path, true));
        h.app.session.doc_mut().name = "owned changes".into();
        assert!(super::start(&mut h.app, "file.save", json!({})));
        super::tick(&mut h.app, true);
        assert!(!h.app.session.is_dirty());
        let before = std::fs::read(&path).unwrap();
        let loaded_epoch = h.app.session.pdm_recovery_epoch;
        let mut original_editor = Session::default();
        original_editor.pdm = h.app.pdm.runtime.clone();
        original_editor.execute("doc.open", &json!({"path":path})).unwrap();
        assert_eq!(original_editor.pdm_recovery_epoch, loaded_epoch);
        let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::RecoverConnection { connection_id: "a".repeat(64) })).unwrap();
        h.app.pdm.runtime.finish(id, Err(Failure { message: "Recovery reply lost".into(), disconnect: false })).unwrap();
        assert_ne!(h.app.pdm.runtime.recovery_epoch().unwrap(), loaded_epoch);
        assert!(h.app.session.check_pdm_reopen().is_err());
        assert!(super::start(&mut h.app, "file.save", json!({})));
        super::tick(&mut h.app, true);
        assert!(h.app.status.as_ref().is_some_and(|(_, _, error)| *error));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(h.app.session.pdm_recovery_epoch, loaded_epoch);
        let separate = h.dir.join("recovery-copy.solidcraft");
        assert!(super::start(&mut h.app, "file.save_as", json!({"path":separate})));
        super::tick(&mut h.app, true);
        assert!(separate.exists());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(h.app.session.pdm_recovery_epoch, h.app.pdm.runtime.recovery_epoch().unwrap());
        assert!(h.app.session.check_pdm_reopen().is_ok(), "successful separate SaveAs establishes the new copy at its captured epoch");
        assert_eq!(original_editor.pdm_recovery_epoch, loaded_epoch);
        assert!(original_editor.check_pdm_reopen().is_err());
        assert!(original_editor.execute("file.save", &json!({})).is_err());
        assert!(original_editor.execute("file.save_as", &json!({"path":path})).is_err());
        h.app.run("solid.box", json!({"length":1,"width":1,"height":1})).unwrap();
        assert!(super::start(&mut h.app, "file.save", json!({})));
        super::tick(&mut h.app, true);
        assert!(!h.app.session.is_dirty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(solidcraft_engine::io::read_design(&std::fs::read(&separate).unwrap()).unwrap(), *h.app.session.doc);
        // A fresh server snapshot makes the original archived again. Detaching a
        // copy never discards that destination's managed write protection.
        connect(&mut h, managed(&path, false));
        assert!(super::start(&mut h.app, "file.save_as", json!({"path":path})));
        super::tick(&mut h.app, true);
        assert!(h.app.status.as_ref().is_some_and(|(_, _, error)| *error));
        assert_eq!(h.app.session.path.as_deref(), separate.to_str());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(original_editor.check_pdm_reopen().is_err());
        assert!(original_editor.execute("file.save", &json!({})).is_err());
    }
}
