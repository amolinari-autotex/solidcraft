//! Local PDM commands enqueue work for the host; no command accepts a credential.
use super::CommandSpec;
use crate::{
    EngineError, Result, Session,
    pdm::{ManagedTask, Reference, Task, valid_connection, valid_document},
};
use serde_json::{Value, json};

pub static COMMANDS: &[CommandSpec] = &[
    CommandSpec::new("pdm.rename", "Rename Archived File", rename).icon("rename").noundo().doc_only().params("document,logical_path,expected_head,expected_revision,expected_epoch; change the display path while preserving the immutable working-file locator"),
    CommandSpec::new("pdm.delete", "Delete Archived File", delete).icon("delete").noundo().doc_only().params("document,expected_head,expected_revision,expected_epoch,confirm:true; tombstone an unreferenced file without removing bytes or history"),
    CommandSpec::new("pdm.admin", "PDM Administration", status).icon("settings").noundo().doc_only().params("none; explicit read-only administration page, programmatic calls return public status"),
    CommandSpec::new("pdm.admin.read", "Refresh Administration", admin_read).icon("update").noundo().doc_only().params("none; negotiate authenticated server capabilities and read only permitted public users/audit metadata"),
    CommandSpec::new("pdm.import_new", "Import New File", import_new).icon("import").noundo().doc_only().params("source_path,folder,expected_workspace; copy a new file into the selected working folder and publish without replacing existing local or archived content"),
    CommandSpec::new("pdm.connections", "Saved PDM Connections", connections).icon("list").noundo().doc_only().params("none; public saved connection metadata, without authentication"),
    CommandSpec::new("pdm.settings", "PDM Client Settings", status).icon("settings").noundo().doc_only().params("none; interactive client settings page, programmatic calls return public status"),
    CommandSpec::new("pdm.workspace.change", "Change Local Working Folder", change_workspace).icon("folder").noundo().doc_only().params("connection_id,path,expected_workspace; switch to a new empty client folder after fresh native authentication, without moving files"),
    CommandSpec::new("pdm.setup.create", "Create Local PDM Archive", create_local).icon("new").noundo().doc_only().params("label,administrator; private local setup and fresh native authentication"),
    CommandSpec::new("pdm.connection.open", "Open PDM Connection", open_connection).icon("open").noundo().doc_only().params("connection_id; freshly authenticate an existing native connection"),
    CommandSpec::new("pdm.connection.recover", "Recover PDM Connection", recover_connection).icon("restore").noundo().doc_only().params("connection_id,restore:true; explicit scoped workspace recovery after fresh native authentication"),
    CommandSpec::new("pdm.restore_version", "Restore as New Version", restore_version).icon("restore").noundo().doc_only().params("document,version,restore:true; publish historical content as a new head version and restore the clean normal working copy"),
    CommandSpec::new("pdm.recover_workspace", "Recover Interrupted Local Update", recover_workspace).icon("restore").noundo().doc_only().params("port,root,restore:true; explicitly recover an interrupted local update after server verification, preserving recovery copies"),
    CommandSpec::new("pdm.preview", "Preview", preview).icon("render_image").noundo().doc_only().params("document,version; retrieves the embedded thumbnail for that exact version, if available"),
    CommandSpec::new("pdm.archive", "Check In", archive).at("PDM", "WORKSPACE").icon("pdm_checkin").noundo().doc_only().params("document?: selected identity guard; logical_path?: workspace-relative path; reconcile:true only reconciles an existing authenticated publication receipt and never publishes"),
    CommandSpec::new("pdm.checkout", "Check Out", checkout).at("PDM", "WORKSPACE").icon("pdm_checkout").noundo().doc_only().params("document?: selected stable identity; otherwise active managed design"),
    CommandSpec::new("pdm.cancel_checkout", "Undo Checkout", cancel_checkout).at("PDM", "WORKSPACE").icon("undo").noundo().doc_only().params("document?: selected stable identity; discard:true explicitly discards unsaved RAM and restores archived content, preserving a recovery copy"),
    CommandSpec::new("pdm.get_latest", "Download Latest", get_latest).at("PDM", "WORKSPACE").icon("import").noundo().doc_only().params("document?: selected stable identity; refuses unsaved local edits"),
    CommandSpec::new("pdm.open_document", "Open Working Copy", open_document).at("PDM", "ARCHIVE").icon("open").noundo().doc_only().params("document: selected stable identity; opens its normal workspace path"),
    CommandSpec::new("pdm.open_referenced", "Open Working Copy", open_referenced).icon("open").noundo().doc_only().params("document: stable reference target; opens its normal working copy without retargeting saved component references or checking it out"),
    CommandSpec::new("pdm.open_archived", "Open as Archived", retrieve).at("PDM", "ARCHIVE").icon("open").noundo().doc_only().params("document,version; opens a separate read-only historical snapshot"),
    CommandSpec::new("pdm.history", "Document versions", history).icon("list").noundo().doc_only().params("document: stable identity; loads version history and where-used metadata"),
    CommandSpec::new("pdm.panel", "PDM", status).icon("ws_pdm").noundo().doc_only().params("none; programmatic calls return status, only interactive start opens the panel"),
    CommandSpec::new("pdm.status", "PDM Status", status).icon("library").noundo().doc_only().params("none; host-only connection/job/version state, never credentials"),
    CommandSpec::new("pdm.connect", "Connect PDM", connect).icon("pdm_connect").noundo().doc_only().params("port: local TCP port; credential comes from the native host, never params"),
    CommandSpec::new("pdm.disconnect", "Disconnect PDM", disconnect).icon("pdm_disconnect").noundo().doc_only().params("none; refused while an operation is running"),
    CommandSpec::new("pdm.refresh", "Refresh PDM Versions", refresh).icon("update").noundo().doc_only().params("none; list exact document versions"),
    CommandSpec::new("pdm.check_in", "Check In Saved Design", check_in).icon("pdm_checkin").noundo().doc_only().params("document: lowercase identifier; parent?: exact expected latest version (omit for creation); dependencies?: [{document,version}]; active design must already be saved and unchanged"),
    CommandSpec::new("pdm.retrieve", "Retrieve PDM Working Copy", retrieve).icon("open").noundo().doc_only().params("document, version; open?: bool (default true); create a NEW private working copy and optionally open a NEW tab; never replace current design"),
];
fn err(message: impl Into<String>) -> EngineError {
    EngineError::Other(message.into())
}
/// Validate the entire supported parameter shape BEFORE the engine records a command.
/// In particular, accidental token/credential fields must never enter the crash journal.
pub fn validate_params(id: &str, p: &Value) -> Result<()> {
    let keys: &[&str] = match id {
        "pdm.rename" => &["document", "logical_path", "expected_head", "expected_revision", "expected_epoch"],
        "pdm.delete" => &["document", "expected_head", "expected_revision", "expected_epoch", "confirm"],
        "pdm.import_new" => &["source_path", "folder", "expected_workspace"],
        "pdm.setup.create" => &["label", "administrator"],
        "pdm.connection.open" => &["connection_id"],
        "pdm.workspace.change" => &["connection_id", "path", "expected_workspace"],
        "pdm.connection.recover" => &["connection_id", "restore"],
        "pdm.connect" => &["port", "root"],
        "pdm.recover_workspace" => &["port", "root", "restore"],
        "pdm.archive" => &["logical_path", "document", "reconcile"],
        "pdm.checkout" | "pdm.get_latest" => &["document"],
        "pdm.cancel_checkout" => &["document", "discard"],
        "pdm.open_document" | "pdm.open_referenced" | "pdm.history" => &["document"],
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
        "pdm.rename" | "pdm.delete" => {
            document(p)?;
            if p.get("expected_head").is_none_or(|value| !value.is_null() && value.as_u64().is_none_or(|head| head == 0))
                || p.get("expected_revision").and_then(Value::as_u64).is_none_or(|revision| revision == u64::MAX)
                || p.get("expected_epoch").and_then(Value::as_u64).is_none()
            {
                return Err(err("A captured namespace head, revision and authenticated session are required"));
            }
            if id == "pdm.rename" && p.get("logical_path").and_then(Value::as_str).is_none_or(|path| !crate::pdm::valid_namespace_path(path)) {
                return Err(err("ui.pdm_namespace_invalid_name"));
            }
            if id == "pdm.delete" && p.get("confirm").and_then(Value::as_bool) != Some(true) {
                return Err(err("Logical deletion requires explicit confirm:true"));
            }
        }
        "pdm.workspace.change" => {
            connection_id(p)?;
            if p.get("path").and_then(Value::as_str).is_none_or(|path| !crate::pdm::valid_workspace_path(path))
                || p.get("expected_workspace").and_then(Value::as_str).is_none_or(|id| !valid_document(id))
            {
                return Err(err("A valid absolute client folder and current workspace identity are required"));
            }
        }
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
        "pdm.import_new" => {
            let source = p.get("source_path").and_then(Value::as_str).ok_or_else(|| err("An import source is required"))?;
            let folder = p.get("folder").and_then(Value::as_str).ok_or_else(|| err("An import folder is required"))?;
            let workspace = p.get("expected_workspace").and_then(Value::as_str).ok_or_else(|| err("A captured workspace is required"))?;
            if source.is_empty()
                || source.len() > 4096
                || source.chars().any(char::is_control)
                || !valid_document(workspace)
                || folder.len() > 240
                || folder.contains(['\\', ':'])
                || folder.chars().any(char::is_control)
                || (!folder.is_empty()
                    && folder.split('/').any(|part| part.is_empty() || part == "." || part == ".." || part.eq_ignore_ascii_case(".solidcraft-pdm")))
            {
                return Err(err("Invalid new-file import path or workspace"));
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
        "pdm.open_document" | "pdm.open_referenced" | "pdm.history" => {
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
fn change_workspace(s: &mut Session, p: &Value) -> Result<Value> {
    let path = p
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| crate::pdm::valid_workspace_path(path))
        .ok_or_else(|| err("A valid absolute client folder is required"))?;
    let expected_workspace = p
        .get("expected_workspace")
        .and_then(Value::as_str)
        .filter(|id| valid_document(id))
        .ok_or_else(|| err("A current workspace identity is required"))?;
    let current = s.pdm.status().map_err(err)?;
    if s.pdm_read_only
        || s.path.as_ref().is_some_and(|path| {
            let key = crate::pdm::cached_path_key(path);
            s.pdm.is_managed_or_historical_path(path)
                || current.managed.root.as_ref().is_some_and(|root| {
                    let root = crate::pdm::cached_path_key(root);
                    key == root || key.starts_with(&format!("{}/", root.trim_end_matches('/')))
                })
        })
    {
        return Err(err("Close managed documents before changing the client working folder"));
    }
    enqueue(
        s,
        Task::Managed(ManagedTask::ChangeWorkspace {
            connection_id: connection_id(p)?,
            path: path.into(),
            expected_workspace: expected_workspace.into(),
        }),
    )
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
    if !reconcile {
        let status = s.pdm.status().map_err(err)?;
        if let Some(path) = status.attachment_path(selected.as_deref()) {
            if let Some(reason) = status.action_unavailable("pdm.archive", selected.as_deref(), Some(path), false, false, None) {
                return Err(err(reason));
            }
            return enqueue(
                s,
                Task::Managed(ManagedTask::Archive {
                    path: path.into(),
                    logical_path: None,
                    saved: s.doc.clone(),
                    visibility: Box::new(s.visibility.clone()),
                }),
            );
        }
    }
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
    let document = p.get("document").map(|_| document(p)).transpose()?;
    if let Some(path) = s.pdm.status().map_err(err)?.attachment_path(document.as_deref()) {
        return Ok((document, Some(path.into())));
    }
    if s.is_dirty() || s.active_sketch.is_some() || !s.pending_moves.is_empty() {
        return Err(err("Finish and save or explicitly discard current edits before replacing a managed copy"));
    }
    if document.is_none() && s.path.is_none() {
        return Err(err("Select an archived document first"));
    }
    Ok((document, s.path.clone()))
}
fn checkout(s: &mut Session, p: &Value) -> Result<Value> {
    if s.active_sketch.is_some() || !s.pending_moves.is_empty() {
        return Err(err("Finish active sketch or move operations before checking out this design"));
    }
    let document = p.get("document").map(|_| document(p)).transpose()?;
    policy(s, "pdm.checkout", document.as_deref(), None)?;
    if s.is_dirty() && s.pdm.status().map_err(err)?.attachment_path(document.as_deref()).is_none() {
        s.check_pdm_reopen()?;
        let path = s.path.clone().ok_or_else(|| err("Open the selected working copy before checking out unsaved edits"))?;
        let status = s.pdm.status().map_err(err)?;
        let local = status
            .managed
            .local
            .iter()
            .find(|local| {
                crate::pdm::cached_path_key(&local.path) == crate::pdm::cached_path_key(&path)
                    && document.as_ref().is_none_or(|document| *document == local.document)
            })
            .ok_or_else(|| err("Open the selected working copy before checking out unsaved edits"))?;
        return enqueue(
            s,
            Task::Managed(ManagedTask::CheckoutPreservingMemory { document: local.document.clone(), path, expected_base: local.base_version }),
        );
    }
    let (document, path) = target(s, p)?;
    enqueue(s, Task::Managed(ManagedTask::Checkout { document, path }))
}
fn cancel_checkout(s: &mut Session, p: &Value) -> Result<Value> {
    // Explicit discard acknowledges both unsaved RAM and local disk edits.
    if p.get("discard").and_then(Value::as_bool) != Some(true) {
        return Err(err("Undo Checkout requires explicit discard:true before unsaved edits can be discarded"));
    }
    if s.active_sketch.is_some() || !s.pending_moves.is_empty() {
        return Err(err("Finish active sketch or move operations before undoing checkout"));
    }
    let document = p.get("document").map(|_| document(p)).transpose()?;
    policy(s, "pdm.cancel_checkout", document.as_deref(), None)?;
    let path = if let Some(document) = &document {
        s.pdm.status().map_err(err)?.managed.local.iter().find(|local| local.document == *document).map(|local| local.path.clone())
    } else {
        s.path.clone()
    };
    enqueue(s, Task::Managed(ManagedTask::CancelCheckout { document, path }))
}
fn get_latest(s: &mut Session, p: &Value) -> Result<Value> {
    let (document, path) = target(s, p)?;
    policy(s, "pdm.get_latest", document.as_deref(), None)?;
    enqueue(s, Task::Managed(ManagedTask::GetLatest { document, path }))
}
fn admin_read(s: &mut Session, _: &Value) -> Result<Value> {
    policy(s, "pdm.admin.read", None, None)?;
    enqueue(s, Task::Managed(ManagedTask::AdministrationRead))
}
fn import_new(s: &mut Session, p: &Value) -> Result<Value> {
    policy(s, "pdm.import_new", None, None)?;
    enqueue(
        s,
        Task::Managed(ManagedTask::ImportNew {
            source_path: p["source_path"].as_str().ok_or_else(|| err("An import source is required"))?.into(),
            folder: p["folder"].as_str().ok_or_else(|| err("An import folder is required"))?.into(),
            expected_workspace: p["expected_workspace"].as_str().ok_or_else(|| err("A captured workspace is required"))?.into(),
        }),
    )
}
fn open_document(s: &mut Session, p: &Value) -> Result<Value> {
    enqueue(s, Task::Managed(ManagedTask::Open { document: document(p)? }))
}
fn open_referenced(s: &mut Session, p: &Value) -> Result<Value> {
    let document = document(p)?;
    policy(s, "pdm.open_referenced", Some(&document), None)?;
    enqueue(s, Task::Managed(ManagedTask::OpenReferenced { document }))
}
fn history(s: &mut Session, p: &Value) -> Result<Value> {
    enqueue(s, Task::Managed(ManagedTask::History { document: document(p)? }))
}
fn rename(s: &mut Session, p: &Value) -> Result<Value> {
    enqueue(
        s,
        Task::Managed(ManagedTask::Rename {
            document: document(p)?,
            logical_path: p.get("logical_path").and_then(Value::as_str).ok_or_else(|| err("ui.pdm_namespace_invalid_name"))?.into(),
            expected_head: p.get("expected_head").and_then(Value::as_u64),
            expected_revision: p.get("expected_revision").and_then(Value::as_u64).ok_or_else(|| err("ui.pdm_namespace_stale"))?,
            expected_epoch: p.get("expected_epoch").and_then(Value::as_u64).ok_or_else(|| err("ui.pdm_namespace_stale"))?,
        }),
    )
}
fn delete(s: &mut Session, p: &Value) -> Result<Value> {
    enqueue(
        s,
        Task::Managed(ManagedTask::Delete {
            document: document(p)?,
            expected_head: p.get("expected_head").and_then(Value::as_u64),
            expected_revision: p.get("expected_revision").and_then(Value::as_u64).ok_or_else(|| err("ui.pdm_namespace_stale"))?,
            expected_epoch: p.get("expected_epoch").and_then(Value::as_u64).ok_or_else(|| err("ui.pdm_namespace_stale"))?,
        }),
    )
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
