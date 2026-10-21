//! Exact immutable reference navigation; no working-copy or assembly-link edits.
use super::{BrowserContext, Notice, Reference};
use crate::{SolveApp, documents};
use serde_json::json;
use solidcraft_engine::pdm::{ManagedVersion, Outcome, Preview, Status, WhereUsedEntry};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Section {
    Uses,
    WhereUsed,
}
impl Section {
    fn name(self) -> &'static str {
        match self {
            Self::Uses => "uses",
            Self::WhereUsed => "where_used",
        }
    }
}

#[derive(Default)]
pub(super) struct State {
    selected: Option<(Section, Reference)>,
    pending: Option<Pending>,
}

pub(super) struct Pending {
    id: u64,
    reference: Reference,
    context: BrowserContext,
    cached: Option<(String, documents::EditorStamp)>,
    source_document: String,
    source_version: Option<Reference>,
    history: Vec<ManagedVersion>,
    where_used: Vec<Reference>,
    where_used_details: Vec<WhereUsedEntry>,
    preview: Option<Preview>,
}
impl Pending {
    pub(super) fn current(&self, app: &SolveApp) -> bool {
        app.pdm.runtime.status().ok().and_then(|status| BrowserContext::current(&status)).as_ref() == Some(&self.context)
    }
    pub(super) fn cached(&self) -> bool {
        self.cached.is_some()
    }
    pub(super) fn preserve_details(&self, app: &SolveApp, result: &mut Result<Outcome, solidcraft_engine::pdm::Failure>) {
        // Native reference authorization returns fresh catalog/local authority,
        // but its focused child metadata must not replace the source panel's
        // exact parent context. Do not restore it after a selection/auth change.
        if !self.current(app) || self.source_document != app.pdm.document || self.source_version != app.pdm.selected {
            return;
        }
        if let Ok(Outcome::Managed { port, state }) = result
            && *port == self.context.port
            && state.server_id == self.context.server
            && state.workspace == self.context.workspace
        {
            state.history = self.history.clone();
            state.where_used = self.where_used.clone();
            state.where_used_details = self.where_used_details.clone();
            state.preview = self.preview.clone();
        }
    }
}

pub(super) fn take_request(app: &mut SolveApp, id: u64) -> Option<Pending> {
    if app.pdm.references.pending.as_ref().is_some_and(|pending| pending.id == id) { app.pdm.references.pending.take() } else { None }
}

pub(super) fn context_reference(app: &SolveApp, status: &Status) -> Option<Reference> {
    app.pdm.selected.as_ref().filter(|reference| reference.document == app.pdm.document).cloned().or_else(|| {
        status
            .managed
            .catalog
            .iter()
            .find(|entry| entry.document == app.pdm.document)
            .and_then(|entry| entry.head.map(|version| Reference { document: entry.document.clone(), version }))
    })
}

pub(super) fn missing_metadata(app: &mut SolveApp, ui: &mut egui::Ui, status: &Status) {
    if app.pdm.document.is_empty() {
        ui.label(app.tr("ui.pdm_select_file"));
        return;
    }
    let reason = if status.busy.is_some() { "ui.pdm_busy" } else { status.error.as_deref().unwrap_or("ui.pdm_reference_unavailable") };
    ui.add(egui::Label::new(app.tr(reason)).wrap());
    let available = !app.file_picker_busy()
        && !app.file_load.busy()
        && status.action_unavailable("pdm.history", Some(&app.pdm.document), None, false, false, None).is_none();
    let retry = ui.add_enabled(available, egui::Button::new(app.tr("ui.pdm_refresh")));
    super::handle("references_retry", &retry);
    if retry.clicked() {
        super::dispatch(app, "pdm.history", json!({"document":app.pdm.document}));
    }
}

pub(super) fn rows(app: &mut SolveApp, ui: &mut egui::Ui, status: &Status, section: Section, values: &[Reference]) {
    let historical = app.pdm.selected.as_ref().is_some_and(|reference| reference.document == app.pdm.document);
    let mut current = Vec::new();
    let mut missing = false;
    if !historical {
        let mut documents = std::collections::BTreeSet::new();
        for reference in values {
            if !documents.insert(reference.document.as_str()) {
                continue;
            }
            if let Some(version) = status.managed.catalog.iter().find(|entry| entry.document == reference.document).and_then(|entry| entry.head) {
                current.push(Reference { document: reference.document.clone(), version });
            } else {
                missing = true;
            }
        }
    }
    let values = if historical { values } else { &current };
    if missing {
        ui.label(app.tr("ui.pdm_reference_unavailable"));
    }
    if values.is_empty() && !missing {
        ui.label(app.tr("ui.pdm_no_dependencies"));
    }
    for reference in values {
        let selected =
            app.pdm.references.selected.as_ref().is_some_and(|(selected_section, selected)| *selected_section == section && selected == reference);
        let reason = if app.file_picker_busy() || app.file_load.busy() || app.pdm.references.pending.is_some() {
            Some("ui.pdm_reason_busy")
        } else {
            status.action_unavailable("pdm.open_referenced", Some(&reference.document), None, false, false, None)
        };
        // The explicit link opens on a single click; the remaining full row
        // selects on one click and opens on a physical double click.
        let row = ui.horizontal(|ui| {
            let link = ui.add_enabled(reason.is_none(), egui::Link::new(super::reference_label(reference, &status.managed.catalog)));
            let hit = ui.allocate_response(egui::vec2(ui.available_width().max(28.0), link.rect.height().max(24.0)), egui::Sense::click());
            super::handle(&format!("reference_link:{}:{}:{}", section.name(), reference.document, reference.version), &link);
            super::handle(&format!("reference:{}:{}:{}", section.name(), reference.document, reference.version), &hit);
            if let Some(reason) = reason {
                link.clone().on_disabled_hover_text(app.tr(reason));
            }
            (link.clicked(), reason.is_none() && hit.clicked(), reason.is_none() && hit.double_clicked())
        });
        if selected {
            ui.painter().rect_stroke(row.response.rect, 0.0, ui.visuals().selection.stroke, egui::StrokeKind::Inside);
        }
        if row.inner.0 || row.inner.1 {
            app.pdm.references.selected = Some((section, reference.clone()));
        }
        if row.inner.0 || row.inner.2 {
            open(app, reference.clone());
        }
        if historical && section == Section::WhereUsed {
            for entry in status.managed.where_used_details.iter().filter(|entry| entry.parent == *reference) {
                ui.horizontal(|ui| {
                    ui.label(app.tr("ui.pdm_reference_used_version"));
                    ui.label(super::reference_label(&entry.used, &status.managed.catalog));
                });
            }
        }
    }
}

fn unavailable(app: &SolveApp, status: &Status, reference: &Reference) -> Option<&'static str> {
    if app.file_picker_busy() || app.file_load.busy() || app.pdm.references.pending.is_some() {
        return Some("ui.pdm_reason_busy");
    }
    status.action_unavailable("pdm.open_archived", Some(&reference.document), None, false, false, Some(reference.version))
}

fn fail(app: &mut SolveApp, reference: &Reference, action: &'static str, error: String) {
    let file = app
        .pdm
        .runtime
        .status()
        .ok()
        .map(|status| super::reference_label(reference, &status.managed.catalog))
        .unwrap_or_else(|| reference.document.clone());
    app.pdm.notice = Some(Notice { action, file, path: None, error: Some(error.clone()) });
    app.set_status(app.tr(&error).to_string(), true);
}

fn open(app: &mut SolveApp, reference: Reference) {
    if let Err(error) = app.run("pdm.open_referenced", json!({"document":reference.document})) {
        fail(app, &reference, "ui.pdm_open_document", error);
    }
}

fn capture(
    app: &mut SolveApp,
    id: u64,
    reference: Reference,
    context: BrowserContext,
    status: Status,
    cached: Option<(String, documents::EditorStamp)>,
) {
    app.pdm.pending_notice = Some((id, "ui.pdm_open_archived", super::reference_label(&reference, &status.managed.catalog), None));
    app.pdm.references.pending = Some(Pending {
        id,
        reference,
        context,
        cached,
        source_document: app.pdm.document.clone(),
        source_version: app.pdm.selected.clone(),
        history: status.managed.history,
        where_used: status.managed.where_used,
        where_used_details: status.managed.where_used_details,
        preview: status.managed.preview,
    });
}

/// One route for reference links, history actions and programmatic archived
/// opens. The legacy mutable private-copy protocol keeps its existing path.
pub(super) fn run_historical(app: &mut SolveApp, command: &str, params: &serde_json::Value) -> Option<Result<serde_json::Value, String>> {
    if !matches!(command, "pdm.open_archived" | "pdm.retrieve") || params.get("open").and_then(serde_json::Value::as_bool) == Some(false) {
        return None;
    }
    let status = match app.pdm.runtime.status() {
        Ok(status) => status,
        Err(error) => return Some(Err(error)),
    };
    let context = BrowserContext::current(&status)?;
    let server = context.server.clone()?;
    Some((|| {
        solidcraft_engine::cmd::validate_pdm_params(command, params).map_err(|error| error.to_string())?;
        let reference = Reference {
            document: params.get("document").and_then(serde_json::Value::as_str).ok_or("ui.pdm_reference_unavailable")?.into(),
            version: params.get("version").and_then(serde_json::Value::as_u64).ok_or("ui.pdm_reference_unavailable")?,
        };
        reference.validate()?;
        if let Some(reason) = unavailable(app, &status, &reference) {
            return Err(reason.into());
        }
        let cached = documents::registered_historical(app, &server, &reference)?;
        let result = if cached.is_some() {
            app.session.execute("pdm.preview", &json!({"document":reference.document,"version":reference.version}))
        } else {
            app.session.execute(command, params)
        }
        .map_err(|error| error.to_string())?;
        let id = result.get("request").and_then(serde_json::Value::as_u64).ok_or("ui.pdm_reference_open_failed")?;
        capture(app, id, reference, context, status, cached);
        Ok(result)
    })())
}

/// Trusted Runtime jobs may originate outside SolveApp::run as well. Record
/// their exact native request before dispatch, never infer it from a filename.
pub(super) fn capture_job(app: &mut SolveApp, job: &solidcraft_engine::pdm::Job) {
    if app.pdm.references.pending.is_some() {
        return;
    }
    let reference = match &job.task {
        solidcraft_engine::pdm::Task::Retrieve { reference, open: true }
        | solidcraft_engine::pdm::Task::Managed(solidcraft_engine::pdm::ManagedTask::OpenArchived { reference }) => reference.clone(),
        _ => return,
    };
    let Ok(status) = app.pdm.runtime.status() else { return };
    let Some(context) = BrowserContext::current(&status).filter(|context| context.server.is_some()) else { return };
    capture(app, job.id, reference, context, status, None);
}

/// Called only after Runtime accepted the captured request and any loaded
/// Session was applied successfully. Cache hits never renew a disk-load receipt.
pub(super) fn complete(app: &mut SolveApp, request: Pending, loaded_path: Option<&str>) -> Result<(), String> {
    if !request.current(app) {
        return Err("ui.pdm_reason_disconnected".into());
    }
    let path = if let Some((path, stamp)) = request.cached {
        documents::activate_authorized_historical(app, &path, &stamp)?;
        path
    } else {
        let path = loaded_path.ok_or("ui.pdm_reference_open_failed")?.to_owned();
        documents::activate_managed_path(app, &path);
        if app.session.path.as_deref() != Some(path.as_str()) || !app.session.pdm_read_only || app.session.is_dirty() {
            return Err("ui.pdm_reference_open_failed".into());
        }
        documents::register_historical(app, request.context.server.as_deref().ok_or("ui.pdm_reference_unavailable")?, request.reference, &path)?;
        path
    };
    // Both directions open a pinned historical tab. Do not call Get Latest,
    // Checkout, or write any active assembly/component link.
    super::leave(app);
    let _ = crate::render_workspace::enter(app, false);
    app.ui.tab = "SOLID".into();
    app.pdm.notice =
        Some(Notice { action: "ui.pdm_open_archived", file: path.rsplit(['/', '\\']).next().unwrap_or(&path).into(), path: Some(path), error: None });
    Ok(())
}
