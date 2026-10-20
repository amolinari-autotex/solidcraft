//! Local PDM commands enqueue work for the host; no command accepts a credential.
use super::CommandSpec;
use crate::{
    EngineError, Result, Session,
    pdm::{ManagedTask, Reference, Task, valid_connection, valid_document},
};
use serde_json::{Value, json};

pub static COMMANDS: &[CommandSpec] = &[
    CommandSpec::new("pdm.connections", "Saved PDM Connections", connections).icon("list").noundo().doc_only().params("none; public saved connection metadata, without authentication"),
    CommandSpec::new("pdm.setup.create", "Create Local PDM Archive", create_local).icon("new").noundo().doc_only().params("label,administrator; private local setup and fresh native authentication"),
    CommandSpec::new("pdm.connection.open", "Open PDM Connection", open_connection).icon("open").noundo().doc_only().params("connection_id; freshly authenticate an existing native connection"),
    CommandSpec::new("pdm.connection.recover", "Recover PDM Connection", recover_connection).icon("restore").noundo().doc_only().params("connection_id,restore:true; explicit scoped workspace recovery after fresh native authentication"),
    CommandSpec::new("pdm.restore_version", "Restore as New Version", restore_version).icon("restore").noundo().doc_only().params("document,version,restore:true; publish historical content as a new head version and restore the clean normal working copy"),
    CommandSpec::new("pdm.recover_workspace", "Recover Interrupted Local Update", recover_workspace).icon("restore").noundo().doc_only().params("port,root,restore:true; explicitly recover an interrupted local update after server verification, preserving recovery copies"),
    CommandSpec::new("pdm.preview", "Preview", preview).icon("render_image").noundo().doc_only().params("document,version; retrieves the embedded thumbnail for that exact version, if available"),
    CommandSpec::new("pdm.archive", "Check In", archive).at("PDM", "WORKSPACE").icon("save").noundo().doc_only().params("document?: selected identity guard; logical_path?: workspace-relative path; reconcile:true only reconciles an existing authenticated publication receipt and never publishes"),
    CommandSpec::new("pdm.checkout", "Check Out", checkout).at("PDM", "WORKSPACE").icon("open").noundo().doc_only().params("document?: selected stable identity; otherwise active managed design"),
    CommandSpec::new("pdm.cancel_checkout", "Undo Checkout", cancel_checkout).at("PDM", "WORKSPACE").icon("undo").noundo().doc_only().params("document?: selected stable identity; discard:true explicitly restores archived content, preserving a recovery copy"),
    CommandSpec::new("pdm.get_latest", "Get Latest", get_latest).at("PDM", "WORKSPACE").icon("update").noundo().doc_only().params("document?: selected stable identity; refuses unsaved local edits"),
    CommandSpec::new("pdm.open_document", "Open Working Copy", open_document).at("PDM", "ARCHIVE").icon("open").noundo().doc_only().params("document: selected stable identity; opens its normal workspace path"),
    CommandSpec::new("pdm.open_archived", "Open as Archived", retrieve).at("PDM", "ARCHIVE").icon("open").noundo().doc_only().params("document,version; opens a separate read-only historical snapshot"),
    CommandSpec::new("pdm.history", "Document versions", history).icon("list").noundo().doc_only().params("document: stable identity; loads version history and where-used metadata"),
    CommandSpec::new("pdm.panel", "Local PDM", status).icon("library").noundo().doc_only().params("none; programmatic calls return status, only interactive start opens the panel"),
    CommandSpec::new("pdm.status", "Local PDM Status", status).icon("library").noundo().doc_only().params("none; host-only connection/job/version state, never credentials"),
    CommandSpec::new("pdm.connect", "Connect Local PDM", connect).icon("library").noundo().doc_only().params("port: local TCP port; credential comes from the native host, never params"),
    CommandSpec::new("pdm.disconnect", "Disconnect Local PDM", disconnect).icon("library").noundo().doc_only().params("none; refused while an operation is running"),
    CommandSpec::new("pdm.refresh", "Refresh PDM Versions", refresh).icon("library").noundo().doc_only().params("none; list exact document versions"),
    CommandSpec::new("pdm.check_in", "Check In Saved Design", check_in).icon("save").noundo().doc_only().params("document: lowercase identifier; parent?: exact expected latest version (omit for creation); dependencies?: [{document,version}]; active design must already be saved and unchanged"),
    CommandSpec::new("pdm.retrieve", "Retrieve PDM Working Copy", retrieve).icon("open").noundo().doc_only().params("document, version; open?: bool (default true); create a NEW private working copy and optionally open a NEW tab; never replace current design"),
];
fn err(message: impl Into<String>) -> EngineError {
    EngineError::Other(message.into())
}
/// Validate the entire supported parameter shape BEFORE the engine records a command.
/// In particular, accidental token/credential fields must never enter the crash journal.
pub(crate) fn validate_params(id: &str, p: &Value) -> Result<()> {
    let keys: &[&str] = match id {
        "pdm.setup.create" => &["label", "administrator"],
        "pdm.connection.open" => &["connection_id"],
        "pdm.connection.recover" => &["connection_id", "restore"],
        "pdm.connect" => &["port", "root"],
        "pdm.recover_workspace" => &["port", "root", "restore"],
        "pdm.archive" => &["logical_path", "document", "reconcile"],
        "pdm.checkout" | "pdm.get_latest" => &["document"],
        "pdm.cancel_checkout" => &["document", "discard"],
        "pdm.open_document" | "pdm.history" => &["document"],
        "pdm.check_in" => &["document", "parent", "dependencies"],
        "pdm.retrieve" | "pdm.open_archived" => &["document", "version", "open"],
        "pdm.preview" => &["document", "version"],
        "pdm.restore_version" => &["document", "version", "restore"],
        _ => &[],
    };
    if !p.is_null() && !p.is_object() {
        return Err(err("Invalid local PDM parameters; credentials belong only to the native host"));
    }
    if p.as_object().is_some_and(|p| p.keys().any(|key| !keys.contains(&key.as_str()))) {
        return Err(err("Unsupported local PDM parameter; credentials belong only to the native host"));
    }
    match id {
        "pdm.setup.create" => {
            let label = p.get("label").and_then(Value::as_str).ok_or_else(|| err("An archive name is required"))?;
            let administrator = p.get("administrator").and_then(Value::as_str).ok_or_else(|| err("An administrator identifier is required"))?;
            if label.trim().is_empty()
                || label.len() > 128
                || label.chars().any(char::is_control)
                || !valid_document(administrator)
                || administrator == "owner"
            {
                return Err(err("Invalid archive name or administrator identifier"));
            }
        }
        "pdm.connection.open" | "pdm.connection.recover" => {
            connection_id(p)?;
            if id == "pdm.connection.recover" && p.get("restore").and_then(Value::as_bool) != Some(true) {
                return Err(err("Recovery requires explicit restore:true"));
            }
        }
        "pdm.connect" | "pdm.recover_workspace" => {
            if p.get("port").and_then(Value::as_u64).filter(|v| *v > 0 && *v <= u16::MAX as u64).is_none() {
                return Err(err("A valid local PDM port is required"));
            }
            if p.get("root").is_some_and(|v| !v.is_string() || v.as_str().is_some_and(|s| s.is_empty() || s.len() > 4096)) {
                return Err(err("A valid working folder is required"));
            }
            if id == "pdm.recover_workspace"
                && (p.get("root").and_then(Value::as_str).is_none() || p.get("restore").and_then(Value::as_bool) != Some(true))
            {
                return Err(err("Recovery requires an explicit root and restore:true"));
            }
        }
        "pdm.check_in" => {
            document(p)?;
            if p.get("parent").is_some_and(|v| !v.is_null() && v.as_u64().filter(|v| *v > 0).is_none()) {
                return Err(err("Expected parent must be a positive version"));
            }
            if let Some(value) = p.get("dependencies") {
                let dependencies: Vec<Reference> = serde_json::from_value(value.clone()).map_err(|_| err("Invalid PDM dependencies"))?;
                if dependencies.len() > 256 {
                    return Err(err("Too many PDM dependencies"));
                }
                for reference in dependencies {
                    reference.validate().map_err(err)?;
                }
            }
        }
        "pdm.retrieve" | "pdm.open_archived" | "pdm.preview" | "pdm.restore_version" => {
            document(p)?;
            if p.get("version").and_then(Value::as_u64).filter(|v| *v > 0).is_none() {
                return Err(err("A positive PDM version is required"));
            }
            if id == "pdm.restore_version" && p.get("restore").and_then(Value::as_bool) != Some(true) {
                return Err(err("Restore requires explicit restore:true; a new head version will be published"));
            }
            if p.get("open").is_some_and(|v| !v.is_boolean()) {
                return Err(err("open must be boolean"));
            }
        }
        "pdm.checkout" | "pdm.get_latest" | "pdm.cancel_checkout" => {
            if p.get("document").is_some() {
                document(p)?;
            }
            if id == "pdm.cancel_checkout" && p.get("discard").and_then(Value::as_bool) != Some(true) {
                return Err(err("Undo Check Out requires explicit discard:true; local edits will be restored from the archive"));
            }
        }
        "pdm.open_document" | "pdm.history" => {
            document(p)?;
        }
        "pdm.archive" => {
            if p.get("logical_path").is_some_and(|v| v.as_str().is_none_or(|s| s.is_empty() || s.len() > 1024)) {
                return Err(err("Invalid logical archive path"));
            }
            if p.get("document").is_some() {
                document(p)?;
            }
            if p.get("reconcile").is_some_and(|value| !value.is_boolean()) {
                return Err(err("reconcile must be boolean"));
            }
        }
        _ => {}
    }
    Ok(())
}
fn enqueue(s: &Session, task: Task) -> Result<Value> {
    Ok(json!({"queued":true,"request":s.pdm.enqueue(task).map_err(err)?}))
}
fn status(s: &mut Session, _: &Value) -> Result<Value> {
    serde_json::to_value(s.pdm.status().map_err(err)?).map_err(|_| err("Local PDM status unavailable"))
}
fn connections(s: &mut Session, _: &Value) -> Result<Value> {
    enqueue(s, Task::Managed(ManagedTask::ListConnections))
}
fn create_local(s: &mut Session, p: &Value) -> Result<Value> {
    let label = p.get("label").and_then(Value::as_str).ok_or_else(|| err("An archive name is required"))?.trim().into();
    let administrator = p.get("administrator").and_then(Value::as_str).ok_or_else(|| err("An administrator identifier is required"))?.into();
    enqueue(s, Task::Managed(ManagedTask::CreateLocal { label, administrator }))
}
fn connection_id(p: &Value) -> Result<String> {
    p.get("connection_id")
        .and_then(Value::as_str)
        .filter(|id| valid_connection(id))
        .map(str::to_owned)
        .ok_or_else(|| err("Invalid PDM connection identifier"))
}
fn open_connection(s: &mut Session, p: &Value) -> Result<Value> {
    enqueue(s, Task::Managed(ManagedTask::OpenConnection { connection_id: connection_id(p)? }))
}
fn recover_connection(s: &mut Session, p: &Value) -> Result<Value> {
    if s.is_dirty() || s.active_sketch.is_some() || !s.pending_moves.is_empty() {
        return Err(err("Finish and save current edits before recovering the working folder"));
    }
    enqueue(s, Task::Managed(ManagedTask::RecoverConnection { connection_id: connection_id(p)? }))
}
fn connect(s: &mut Session, p: &Value) -> Result<Value> {
    let port = p
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p > 0)
        .ok_or_else(|| err("A valid local PDM port is required"))?;
    // Existing script callers retain their old connection task. The native adapter
    // initializes managed state for both forms; an explicit root is host-only.
    match p.get("root").and_then(Value::as_str) {
        Some(root) => enqueue(s, Task::Managed(ManagedTask::Connect { port, root: Some(root.into()) })),
        None => enqueue(s, Task::Connect { port }),
    }
}

fn saved_path(s: &Session) -> Result<String> {
    s.check_pdm_reopen()?;
    if s.is_dirty() || s.active_sketch.is_some() || !s.pending_moves.is_empty() {
        return Err(err("Finish edits and save the active design first"));
    }
    s.path.clone().filter(|p| solidcraft_io::is_design_path(p)).ok_or_else(|| err("Save a native design in the working folder first"))
}
fn archive(s: &mut Session, p: &Value) -> Result<Value> {
    let selected = p.get("document").map(|_| document(p)).transpose()?;
    let reconcile = p.get("reconcile").and_then(Value::as_bool) == Some(true);
    if reconcile {
        let mut status = s.pdm.status().map_err(err)?;
        status.error = None; // Receipt-only verification never creates new authority.
        if let Some(reason) = status.action_unavailable("pdm.archive", selected.as_deref(), s.path.as_deref(), s.is_dirty(), s.pdm_read_only, None)
            && !matches!(
                reason,
                "ui.pdm_reason_checkout_required"
                    | "ui.pdm_reason_stale_base"
                    | "ui.pdm_reason_checked_out_here"
                    | "ui.pdm_reason_checked_out_elsewhere"
                    | "ui.pdm_reason_checked_out_other"
            )
        {
            return Err(err(reason));
        }
    } else {
        policy(s, "pdm.archive", selected.as_deref(), None)?;
    }
    let path = saved_path(s)?;
    let logical_path = p.get("logical_path").and_then(Value::as_str).map(str::to_string);
    let saved = s.doc.clone();
    let visibility = Box::new(s.visibility.clone());
    enqueue(
        s,
        Task::Managed(if reconcile {
            ManagedTask::ReconcileArchive { path, logical_path, saved, visibility }
        } else {
            ManagedTask::Archive { path, logical_path, saved, visibility }
        }),
    )
}
fn policy(s: &Session, command: &str, document: Option<&str>, version: Option<u64>) -> Result<()> {
    let status = s.pdm.status().map_err(err)?;
    if let Some(reason) = status.action_unavailable(
        command,
        document,
        s.path.as_deref(),
        s.is_dirty() || s.active_sketch.is_some() || !s.pending_moves.is_empty(),
        s.pdm_read_only,
        version,
    ) && (command != "pdm.restore_version"
        || !matches!(
            reason,
            "ui.pdm_reason_stale_base" | "ui.pdm_reason_checked_out_here" | "ui.pdm_reason_checked_out_elsewhere" | "ui.pdm_reason_checked_out_other"
        ))
    {
        return Err(err(reason));
    }
    Ok(())
}
fn target(s: &Session, p: &Value) -> Result<(Option<String>, Option<String>)> {
    if s.is_dirty() || s.active_sketch.is_some() || !s.pending_moves.is_empty() {
        return Err(err("Finish and save or explicitly discard current edits before replacing a managed copy"));
    }
    let document = p.get("document").map(|_| document(p)).transpose()?;
    if document.is_none() && s.path.is_none() {
        return Err(err("Select an archived document first"));
    }
    Ok((document, s.path.clone()))
}
fn checkout(s: &mut Session, p: &Value) -> Result<Value> {
    let (document, path) = target(s, p)?;
    policy(s, "pdm.checkout", document.as_deref(), None)?;
    enqueue(s, Task::Managed(ManagedTask::Checkout { document, path }))
}
fn cancel_checkout(s: &mut Session, p: &Value) -> Result<Value> {
    // Preserve unsaved RAM separately before any destructive disk operation.
    if s.is_dirty() || s.active_sketch.is_some() || !s.pending_moves.is_empty() {
        return Err(err("Save or Save As current edits before undoing checkout; archived bytes will replace the local copy"));
    }
    let document = p.get("document").map(|_| document(p)).transpose()?;
    policy(s, "pdm.cancel_checkout", document.as_deref(), None)?;
    enqueue(s, Task::Managed(ManagedTask::CancelCheckout { document, path: s.path.clone() }))
}
fn get_latest(s: &mut Session, p: &Value) -> Result<Value> {
    let (document, path) = target(s, p)?;
    policy(s, "pdm.get_latest", document.as_deref(), None)?;
    enqueue(s, Task::Managed(ManagedTask::GetLatest { document, path }))
}
fn open_document(s: &mut Session, p: &Value) -> Result<Value> {
    enqueue(s, Task::Managed(ManagedTask::Open { document: document(p)? }))
}
fn history(s: &mut Session, p: &Value) -> Result<Value> {
    enqueue(s, Task::Managed(ManagedTask::History { document: document(p)? }))
}
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    enqueue(
        s,
        Task::Managed(ManagedTask::Preview {
            reference: Reference {
                document: document(p)?,
                version: p.get("version").and_then(Value::as_u64).filter(|v| *v > 0).ok_or_else(|| err("A positive version is required"))?,
            },
        }),
    )
}
fn restore_version(s: &mut Session, p: &Value) -> Result<Value> {
    target(s, p)?;
    policy(s, "pdm.restore_version", Some(&document(p)?), p.get("version").and_then(Value::as_u64))?;
    if p.get("restore").and_then(Value::as_bool) != Some(true) {
        return Err(err("Restore requires explicit restore:true"));
    }
    enqueue(
        s,
        Task::Managed(ManagedTask::Restore {
            reference: Reference {
                document: document(p)?,
                version: p.get("version").and_then(Value::as_u64).filter(|v| *v > 0).ok_or_else(|| err("A positive version is required"))?,
            },
        }),
    )
}
fn recover_workspace(s: &mut Session, p: &Value) -> Result<Value> {
    let port = p.get("port").and_then(Value::as_u64).and_then(|v| u16::try_from(v).ok()).ok_or_else(|| err("Invalid recovery port"))?;
    let root = p.get("root").and_then(Value::as_str).ok_or_else(|| err("Explicit recovery folder required"))?;
    enqueue(s, Task::Managed(ManagedTask::Recover { port, root: root.into() }))
}
fn disconnect(s: &mut Session, _: &Value) -> Result<Value> {
    enqueue(s, Task::Disconnect)
}
fn refresh(s: &mut Session, _: &Value) -> Result<Value> {
    enqueue(s, Task::Refresh)
}
fn document(p: &Value) -> Result<String> {
    let document = p
        .get("document")
        .and_then(Value::as_str)
        .filter(|id| valid_document(id))
        .ok_or_else(|| err("A valid PDM document identifier is required"))?;
    Ok(document.into())
}
fn check_in(s: &mut Session, p: &Value) -> Result<Value> {
    s.check_pdm_reopen()?;
    if s.active_sketch.is_some() || !s.pending_moves.is_empty() {
        return Err(err("Finish active edits before checking in the saved design"));
    }
    if s.is_dirty() {
        return Err(err("Save the active design before checking it in"));
    }
    let path = s.path.clone().filter(|p| solidcraft_io::is_design_path(p)).ok_or_else(|| err("Save the active design as a SolidCraft file first"))?;
    let document = document(p)?;
    let parent = match p.get("parent").filter(|v| !v.is_null()) {
        Some(value) => Some(value.as_u64().filter(|v| *v > 0).ok_or_else(|| err("Expected parent must be a positive version"))?),
        None => None,
    };
    let dependencies: Vec<Reference> = match p.get("dependencies") {
        Some(value) => serde_json::from_value(value.clone()).map_err(|_| err("Invalid PDM dependencies"))?,
        None => Vec::new(),
    };
    if dependencies.len() > 256 {
        return Err(err("Too many PDM dependencies"));
    }
    for dependency in &dependencies {
        dependency.validate().map_err(err)?;
    }
    enqueue(s, Task::CheckIn { document, parent, path, dependencies, saved: s.doc.clone(), visibility: Box::new(s.visibility.clone()) })
}
fn retrieve(s: &mut Session, p: &Value) -> Result<Value> {
    let reference = Reference {
        document: document(p)?,
        version: p.get("version").and_then(Value::as_u64).filter(|v| *v > 0).ok_or_else(|| err("A positive PDM version is required"))?,
    };
    let open = match p.get("open") {
        Some(v) => v.as_bool().ok_or_else(|| err("open must be boolean"))?,
        None => true,
    };
    enqueue(s, Task::Retrieve { reference, open })
}

#[cfg(test)]
mod restore_tests {
    use super::*;
    #[test]
    fn restore_requires_strict_explicit_confirmation_before_enqueueing() {
        for params in [
            json!({"document":"part","version":1}),
            json!({"document":"part","version":1,"restore":false}),
            json!({"document":"part","version":0,"restore":true}),
            json!({"document":"part","version":1,"restore":true,"token":"secret"}),
            json!({"document":"part","version":1,"restore":true,"open":true}),
        ] {
            assert!(validate_params("pdm.restore_version", &params).is_err());
        }
        assert!(validate_params("pdm.restore_version", &json!({"document":"part","version":1,"restore":true})).is_ok());
        let mut session = Session::default();
        session.execute("solid.box", &json!({"length":1,"width":1,"height":1})).unwrap();
        assert!(restore_version(&mut session, &json!({"document":"part","version":1,"restore":true})).is_err());
    }
}
