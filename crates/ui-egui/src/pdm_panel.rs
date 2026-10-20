//! Thin local PDM window. Credentials remain exclusively in the host service.
use crate::{SolveApp, documents, theme::Tokens};
use serde_json::json;
use solidcraft_engine::{
    Session,
    pdm::{CatalogEntry, Failure, Job, ManagedTask, Outcome, Preview, Reference, Runtime, Status, Task, cached_path_key},
};
use std::sync::{
    Arc,
    mpsc::{Receiver, TryRecvError},
};

#[path = "pdm_guided_panel.rs"]
mod guided;

pub struct Completion {
    pub result: Result<Outcome, Failure>,
    /// A separately loaded design; managed loads reuse their existing editor.
    pub open: Option<Box<Session>>,
}
pub type Start = Arc<dyn Fn(Job) -> Receiver<Completion> + Send + Sync>;

/// A single bounded decoded preview. Invalid content is cached too, avoiding repeated
/// decode work on every frame. Its identity includes the immutable version and hash.
#[derive(Default)]
struct PreviewCache {
    key: Option<(Reference, String)>,
    texture: Option<egui::TextureHandle>,
    recent: std::collections::VecDeque<((Reference, String), egui::TextureHandle)>,
}
impl PreviewCache {
    fn update(&mut self, ctx: &egui::Context, preview: Option<&Preview>) {
        let key = preview.map(|p| (p.reference.clone(), p.sha256.clone()));
        if self.key == key {
            return;
        }
        self.key = key.clone();
        if let Some((_, texture)) = self.recent.iter().find(|(entry, _)| Some(entry) == key.as_ref()) {
            self.texture = Some(texture.clone());
            return;
        }
        self.texture = preview
            .filter(|p| p.png.len() <= 512 * 1024)
            .and_then(|p| crate::home::decode_thumbnail(p.png.clone()))
            .map(|image| ctx.load_texture("pdm-native-preview", image, egui::TextureOptions::LINEAR));
        if let (Some(key), Some(texture)) = (key, &self.texture) {
            self.recent.push_front((key, texture.clone()));
            self.recent.truncate(16);
        }
    }
}

#[derive(Clone)]
struct ActionTarget {
    document: Option<String>,
    path: Option<String>,
    label: String,
}

struct Notice {
    action: &'static str,
    file: String,
    path: Option<String>,
    error: Option<String>,
}

pub struct Panel {
    pub guided: guided::GuidedState,
    pub open: bool,
    pub workspace_active: bool,
    return_tab: Option<String>,
    tab_open: bool,
    pub(crate) discard_ack: Option<(u64, documents::EditorStamp)>,
    cancel_editor: Option<documents::EditorStamp>,
    pub root: String,
    pub logical_path: String,
    pub folder: String,
    pub detail_tab: usize,
    pub cancel_confirmation: bool,
    cancel_target: Option<ActionTarget>,
    search: String,
    selected_folder: Option<String>,
    expanded: std::collections::BTreeSet<String>,
    tree_width: f32,
    details_height: f32,
    details_visible: bool,
    column_widths: [f32; 6],
    sort_column: usize,
    sort_descending: bool,
    notice: Option<Notice>,
    pending_notice: Option<(u64, &'static str, String, Option<ActionTarget>)>,
    reconcile_target: Option<ActionTarget>,
    preview_requested: std::collections::BTreeSet<(String, u64, String)>,
    history_requested: Option<String>,
    metadata_not_before: f64,
    detail_context: Option<(String, Option<u64>)>,
    pending_detail_context: Option<(u64, String, Option<u64>)>,
    pub recovery_confirmation: bool,
    pub restore_confirmation: Option<Reference>,
    pub pending_edit: Option<String>,
    pub pending_edit_path: Option<String>,
    resume_edit: Option<(String, String)>,
    pub ram_paths: std::collections::BTreeSet<String>,
    preview_cache: PreviewCache,
    reset_ram_on_completion: bool,
    last_activity: web_time::Instant,
    refresh_delay: std::time::Duration,
    pub runtime: Runtime,
    pub port: String,
    pub document: String,
    pub parent: String,
    pub selected: Option<Reference>,
    pub dependencies: Vec<Reference>,
    pending: Option<(u64, Receiver<Completion>)>,
    ready: Option<(u64, Completion)>,
    pending_open_epoch: Option<u64>,
    working_open_job: Option<u64>,
}

impl Panel {
    /// The dedicated browser tab exists only after explicit entry in this run.
    pub(crate) fn tab_open(&self) -> bool {
        self.tab_open
    }
}

impl Default for Panel {
    fn default() -> Self {
        Self {
            guided: guided::GuidedState::default(),
            open: false,
            workspace_active: false,
            return_tab: None,
            tab_open: false,
            discard_ack: None,
            cancel_editor: None,
            root: String::new(),
            logical_path: String::new(),
            folder: String::new(),
            detail_tab: 0,
            cancel_confirmation: false,
            cancel_target: None,
            search: String::new(),
            selected_folder: None,
            expanded: Default::default(),
            tree_width: 214.0,
            details_height: 238.0,
            details_visible: true,
            column_widths: [240.0, 160.0, 188.0, 160.0, 136.0, 180.0],
            sort_column: 0,
            sort_descending: false,
            notice: None,
            pending_notice: None,
            reconcile_target: None,
            preview_requested: Default::default(),
            history_requested: None,
            metadata_not_before: 0.0,
            detail_context: None,
            pending_detail_context: None,
            recovery_confirmation: false,
            restore_confirmation: None,
            pending_edit: None,
            pending_edit_path: None,
            resume_edit: None,
            ram_paths: Default::default(),
            preview_cache: PreviewCache::default(),
            reset_ram_on_completion: false,
            last_activity: web_time::Instant::now(),
            refresh_delay: std::time::Duration::from_secs(10),
            runtime: Runtime::default(),
            port: "48231".into(),
            document: String::new(),
            parent: String::new(),
            selected: None,
            dependencies: Vec::new(),
            pending: None,
            ready: None,
            pending_open_epoch: None,
            working_open_job: None,
        }
    }
}

pub fn tick(app: &mut SolveApp, ctx: &egui::Context) {
    app.session.pdm = app.pdm.runtime.clone();
    let _ = app.pdm.runtime.set_available(app.services.pdm.is_some());
    if app.pdm.ready.is_none()
        && let Some((id, receiver)) = app.pdm.pending.as_ref()
    {
        match receiver.try_recv() {
            Ok(completion) => {
                app.pdm.ready = Some((*id, completion));
                app.pdm.pending = None;
            }
            Err(TryRecvError::Disconnected) => {
                app.pdm.ready =
                    Some((*id, Completion { result: Err(Failure { message: "Local PDM worker stopped".into(), disconnect: true }), open: None }));
                app.pdm.pending = None;
            }
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(50));
            }
        }
    }
    // Opening must wait for other file operations, never replace their active design.
    let can_open = !app.file_picker_busy()
        && !app.file_load.busy()
        && app.docs.closing.is_none()
        && app.docs.quitting.is_none()
        && app.dialog.is_none()
        && app.params.is_none()
        && app.design_properties.is_none()
        && app.tree.capture_prompt.is_none()
        && app.tool.is_none()
        && app.applying.is_none()
        && app.deferred.is_none();
    let needs_open = app.pdm.ready.as_ref().is_some_and(|(_, completion)| completion.open.is_some());
    if (can_open || !needs_open)
        && let Some((id, mut completion)) = app.pdm.ready.take()
    {
        let working_open = app.pdm.working_open_job.take() == Some(id);
        let discard_stamp = app.pdm.discard_ack.take().filter(|(request, _)| *request == id).map(|(_, stamp)| stamp);
        let next_parent = match &completion.result {
            Ok(Outcome::CheckedIn(version)) if app.pdm.document == version.reference.document => Some(version.reference.version),
            _ => None,
        };
        let previous = app.pdm.runtime.status().ok();
        let context_changed = match (&previous, &completion.result) {
            (
                Some(previous),
                Ok(Outcome::Managed { port, state } | Outcome::ManagedRefreshed { port, state } | Outcome::ManagedConnected { port, state, .. }),
            ) => previous.port != Some(*port) || previous.managed.server_id != state.server_id || previous.managed.workspace != state.workspace,
            _ => false,
        };
        let managed = matches!(&completion.result, Ok(Outcome::Managed { .. } | Outcome::ManagedConnected { .. }));
        let success = completion.result.is_ok();
        let completion_error = completion.result.as_ref().err().map(|failure| failure.message.clone());
        let accepted = match app.pdm.runtime.finish(id, completion.result) {
            Ok(()) => true,
            Err(error) => {
                app.set_status(error, true);
                false
            }
        };
        if let Some((request, document, version)) = app.pdm.pending_detail_context.take()
            && request == id
            && accepted
            && success
        {
            app.pdm.detail_context = Some((document, version));
        }
        if let Some((notice_id, action, file, target)) = app.pdm.pending_notice.take()
            && notice_id == id
        {
            if action == "ui.pdm_archive" {
                app.pdm.reconcile_target = if accepted && success { None } else { target.clone() };
            }
            app.pdm.notice = Some(Notice {
                action,
                file,
                path: target.as_ref().and_then(|target| target.path.clone()),
                error: if accepted { completion_error } else { Some("The operation result is stale; refresh the archive and retry".into()) },
            });
        }
        app.pdm.last_activity = web_time::Instant::now();
        app.pdm.refresh_delay =
            if success { std::time::Duration::from_secs(10) } else { (app.pdm.refresh_delay * 2).min(std::time::Duration::from_secs(60)) };
        if accepted && success && context_changed {
            app.pdm.document.clear();
            app.pdm.parent.clear();
            app.pdm.logical_path.clear();
            app.pdm.folder.clear();
            app.pdm.selected_folder = None;
            app.pdm.detail_tab = 0;
            app.pdm.selected = None;
            app.pdm.dependencies.clear();
            app.pdm.restore_confirmation = None;
            app.pdm.guided.pending_recovery = None;
            app.pdm.cancel_confirmation = false;
            app.pdm.cancel_target = None;
            app.pdm.reconcile_target = None;
            app.pdm.recovery_confirmation = false;
            app.pdm.pending_edit = None;
            app.pdm.pending_edit_path = None;
            app.pdm.resume_edit = None;
            app.pdm.ram_paths.clear();
            app.pdm.preview_cache = PreviewCache::default();
            app.pdm.preview_requested.clear();
            app.pdm.history_requested = None;
            app.pdm.detail_context = None;
            app.pdm.pending_detail_context = None;
            app.pdm.search.clear();
            app.pdm.expanded.clear();
        }
        if accepted && success && managed && app.pdm.reset_ram_on_completion {
            app.pdm.ram_paths.clear();
        }
        if accepted && let Some(parent) = next_parent {
            app.pdm.parent = parent.to_string();
        }
        if accepted
            && success
            && let Some(mut session) = completion.open.take()
        {
            let loaded_path = session.path.clone();
            let applied = app
                .pdm
                .pending_open_epoch
                .take()
                .ok_or_else(|| "Reopen this design from disk after workspace recovery".to_string())
                .and_then(|epoch| documents::bind_fresh_pdm_load(app, &mut session, epoch))
                .and_then(|()| {
                    if let Some(stamp) = discard_stamp.as_ref() {
                        documents::apply_acknowledged_discard(app, *session, stamp)
                    } else {
                        documents::apply_managed(app, *session)
                    }
                });
            if let Err(error) = applied {
                let message = format!("PDM copy was saved but could not open: {error}");
                if let Some(notice) = app.pdm.notice.as_mut() {
                    notice.error = Some(message.clone());
                }
                app.set_status(message, true);
            } else if working_open {
                if let Some(path) = loaded_path {
                    documents::activate_managed_path(app, &path);
                }
                leave(app);
                let _ = crate::render_workspace::enter(app, false);
                app.ui.tab = if app.session.active_sketch.is_some() { "SKETCH".into() } else { "SOLID".into() };
            }
        }
    }
    if app.pdm.resume_edit.is_some()
        && app.pdm.pending.is_none()
        && app.pdm.ready.is_none()
        && app.pdm.runtime.status().is_ok_and(|s| s.busy.is_none())
    {
        let permitted = app.session.path.as_ref().is_some_and(|p| app.pdm.runtime.managed_for_path(p).is_some_and(|e| e.checked_out));
        if let Some((path, command)) = app.pdm.resume_edit.take()
            && permitted
            && app.session.path.as_ref().is_some_and(|current| cached_path_key(current) == path)
        {
            app.start(&command);
        }
    }
    if app.pdm.pending.is_none() && app.pdm.ready.is_none() {
        match app.pdm.runtime.take_job() {
            Ok(Some(job)) => {
                let id = job.id;
                app.pdm.working_open_job = matches!(&job.task, Task::Managed(ManagedTask::Open { .. })).then_some(id);
                app.pdm.pending_detail_context = match &job.task {
                    Task::Managed(ManagedTask::History { document }) => Some((id, document.clone(), None)),
                    Task::Managed(ManagedTask::Preview { reference }) => Some((id, reference.document.clone(), Some(reference.version))),
                    _ => None,
                };
                if let Some((action, document, path)) = task_notice(&job.task) {
                    let file = target_label(app, document, path);
                    let target = (action == "ui.pdm_archive").then(|| ActionTarget {
                        document: document.map(str::to_owned).or_else(|| {
                            app.pdm.runtime.status().ok().and_then(|status| {
                                status
                                    .managed
                                    .local
                                    .iter()
                                    .find(|entry| path.is_some_and(|path| cached_path_key(path) == cached_path_key(&entry.path)))
                                    .map(|entry| entry.document.clone())
                            })
                        }),
                        path: path.map(str::to_owned),
                        label: file.clone(),
                    });
                    app.pdm.pending_notice = Some((id, action, file, target));
                }
                // Recovery restores disk but must not bless an old editor. Normal
                // native load jobs are serialized by this same Runtime.
                app.pdm.pending_open_epoch =
                    if matches!(&job.task, Task::Managed(ManagedTask::Recover { .. } | ManagedTask::RecoverConnection { .. })) {
                        None
                    } else {
                        app.pdm.runtime.begin_pdm_reload().ok()
                    };
                app.pdm.reset_ram_on_completion = matches!(
                    &job.task,
                    Task::Managed(
                        ManagedTask::CreateLocal { .. }
                            | ManagedTask::OpenConnection { .. }
                            | ManagedTask::RecoverConnection { .. }
                            | ManagedTask::Restore { .. }
                            | ManagedTask::Connect { .. }
                            | ManagedTask::Recover { .. }
                            | ManagedTask::Archive { .. }
                            | ManagedTask::ReconcileArchive { .. }
                            | ManagedTask::Checkout { .. }
                            | ManagedTask::CheckoutPreservingMemory { .. }
                            | ManagedTask::CancelCheckout { .. }
                            | ManagedTask::GetLatest { .. }
                            | ManagedTask::Open { .. }
                    )
                );
                if app.pdm.reset_ram_on_completion {
                    app.pdm.detail_context = None;
                }
                if let Some(start) = &app.services.pdm {
                    app.pdm.pending = Some((id, start(job)));
                    ctx.request_repaint();
                } else {
                    let _ = app.pdm.runtime.finish(id, Err(Failure { message: "Local PDM is unavailable in this host".into(), disconnect: true }));
                }
            }
            Err(error) => app.set_status(error, true),
            Ok(None) => {}
        }
    }
    if let Ok(status) = app.pdm.runtime.status()
        && status.port.is_some()
        && status.available
    {
        let remaining = app.pdm.refresh_delay.saturating_sub(app.pdm.last_activity.elapsed());
        if remaining.is_zero()
            && !app.file_picker_busy()
            && !app.file_load.busy()
            && status.busy.is_none()
            && app.pdm.pending.is_none()
            && app.pdm.ready.is_none()
            && !app.pdm.cancel_confirmation
            && app.pdm.restore_confirmation.is_none()
            && !app.pdm.recovery_confirmation
            && app.pdm.pending_edit.is_none()
        {
            app.pdm.last_activity = web_time::Instant::now();
            if let Err(error) = app.run("pdm.refresh", json!({})) {
                app.set_status(error, true);
            }
            ctx.request_repaint();
        } else {
            ctx.request_repaint_after(remaining.max(std::time::Duration::from_millis(50)));
        }
    }
}

fn handle(name: &str, response: &egui::Response) {
    crate::scenario::publish_handle(&format!("pdm:{name}"), response.rect.center());
}

/// Gregorian UTC display, bounded to four-digit years and without platform time APIs.
fn utc_time(milliseconds: u64) -> String {
    if milliseconds > 253_402_300_799_999 {
        return "—".into();
    }
    let seconds = milliseconds / 1000;
    let days = seconds / 86_400;
    let year_start = |year: u64| {
        let previous = year - 1;
        365 * (year - 1970) + previous / 4 - previous / 100 + previous / 400 - 477
    };
    let (mut low, mut high) = (1970_u64, 10_000_u64);
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if year_start(middle) <= days {
            low = middle;
        } else {
            high = middle;
        }
    }
    let year = low;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let lengths = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut day = days - year_start(year);
    for (month, length) in lengths.into_iter().enumerate() {
        if day < length {
            return format!("{year:04}-{:02}-{:02} {:02}:{:02} UTC", month + 1, day + 1, seconds % 86_400 / 3600, seconds % 3600 / 60);
        }
        day -= length;
    }
    "—".into()
}

fn reference_label(reference: &Reference, catalog: &[solidcraft_engine::pdm::CatalogEntry]) -> String {
    let name = catalog.iter().find(|entry| entry.document == reference.document).map(|entry| entry.logical_path.as_str());
    let fallback: String = reference.document.chars().take(12).collect();
    format!("{} · v{}", name.unwrap_or(&fallback), reference.version)
}

/// Enter the archive browser without changing the active document.
pub fn enter(app: &mut SolveApp) -> Result<(), String> {
    if app.tool.is_some() || app.dialog.is_some() || app.session.active_sketch.is_some() || app.file_load.busy() {
        return Err("Finish the current operation before entering PDM".into());
    }
    if !app.pdm.workspace_active {
        app.pdm.return_tab = Some(app.ui.tab.clone());
    }
    app.pdm.tab_open = true;
    app.pdm.workspace_active = true;
    app.pdm.open = false;
    app.ui.tab = "PDM".into();
    app.home.open = false;
    Ok(())
}

/// Return to the existing editor workspace without changing its document or view.
pub(crate) fn leave(app: &mut SolveApp) {
    if app.pdm.workspace_active {
        app.pdm.workspace_active = false;
        if let Some(tab) = app.pdm.return_tab.take() {
            app.ui.tab = tab;
        }
    }
}

pub(crate) fn archive_save_failed(app: &mut SolveApp, params: &serde_json::Value, error: String) {
    let file = target_label(app, params.get("document").and_then(serde_json::Value::as_str), app.session.path.as_deref());
    app.pdm.notice = Some(Notice { action: "ui.pdm_archive", file, path: app.session.path.clone(), error: Some(error.clone()) });
    app.set_status(error, true);
}

fn action_key(id: &str) -> &'static str {
    match id {
        "pdm.disconnect" => "ui.pdm_disconnect",
        "pdm.checkout" => "ui.pdm_checkout",
        "pdm.archive" | "pdm.check_in" => "ui.pdm_archive",
        "pdm.cancel_checkout" => "ui.pdm_cancel_checkout",
        "pdm.get_latest" => "ui.pdm_get_latest",
        "pdm.open_document" => "ui.pdm_open_document",
        "pdm.open_archived" | "pdm.retrieve" => "ui.pdm_open_archived",
        "pdm.restore_version" => "ui.pdm_restore_version",
        "pdm.setup.create" => "cmd.pdm_setup_create",
        "pdm.recover_workspace" | "pdm.connection.recover" => "ui.pdm_recover_workspace",
        _ => "ui.pdm_connect",
    }
}

/// Only user-visible operations replace the persistent result. Background metadata
/// refreshes, preview requests and inventories never erase the last useful feedback.
fn task_notice(task: &Task) -> Option<(&'static str, Option<&str>, Option<&str>)> {
    let (command, document, path) = match task {
        Task::Managed(task) => match task {
            ManagedTask::CheckoutPreservingMemory { document, path, .. } => ("pdm.checkout", Some(document.as_str()), Some(path.as_str())),
            ManagedTask::Checkout { document, path } => ("pdm.checkout", document.as_deref(), path.as_deref()),
            ManagedTask::CancelCheckout { document, path } => ("pdm.cancel_checkout", document.as_deref(), path.as_deref()),
            ManagedTask::GetLatest { document, path } => ("pdm.get_latest", document.as_deref(), path.as_deref()),
            ManagedTask::Archive { path, .. } | ManagedTask::ReconcileArchive { path, .. } => ("pdm.archive", None, Some(path.as_str())),
            ManagedTask::Open { document } => ("pdm.open_document", Some(document.as_str()), None),
            ManagedTask::OpenArchived { reference } => ("pdm.open_archived", Some(reference.document.as_str()), None),
            ManagedTask::Restore { reference } => ("pdm.restore_version", Some(reference.document.as_str()), None),
            ManagedTask::CreateLocal { label, .. } => ("pdm.setup.create", None, Some(label.as_str())),
            ManagedTask::OpenConnection { .. } | ManagedTask::Connect { .. } => ("pdm.connect", None, None),
            ManagedTask::Recover { .. } | ManagedTask::RecoverConnection { .. } => ("pdm.recover_workspace", None, None),
            _ => return None,
        },
        Task::CheckIn { document, path, .. } => ("pdm.check_in", Some(document.as_str()), Some(path.as_str())),
        Task::Retrieve { reference, .. } => ("pdm.retrieve", Some(reference.document.as_str()), None),
        Task::Connect { .. } => ("pdm.connect", None, None),
        Task::Disconnect => ("pdm.disconnect", None, None),
        _ => return None,
    };
    Some((action_key(command), document, path))
}

fn target_label(app: &SolveApp, document: Option<&str>, path: Option<&str>) -> String {
    app.pdm
        .runtime
        .status()
        .ok()
        .and_then(|status| {
            let document = document.or_else(|| {
                path.and_then(|path| {
                    status
                        .managed
                        .local
                        .iter()
                        .find(|entry| cached_path_key(&entry.path) == cached_path_key(path))
                        .map(|entry| entry.document.as_str())
                })
            });
            status.managed.catalog.iter().find(|entry| Some(entry.document.as_str()) == document).map(|entry| entry.logical_path.clone())
        })
        .or_else(|| path.and_then(|path| path.rsplit(['/', '\\']).find(|part| !part.is_empty()).map(str::to_owned)))
        .unwrap_or_else(|| app.tr("ui.pdm_selected_file").to_string())
}

fn dispatch(app: &mut SolveApp, id: &str, params: serde_json::Value) {
    let file = target_label(app, params.get("document").and_then(serde_json::Value::as_str), app.session.path.as_deref());
    if let Err(error) = app.run(id, params) {
        if !matches!(id, "pdm.preview" | "pdm.history" | "pdm.refresh") {
            app.pdm.notice = Some(Notice { action: action_key(id), file, path: app.session.path.clone(), error: Some(error.clone()) });
        }
        app.set_status(error, true);
    }
}

fn active_target(app: &SolveApp, status: &Status, selected: bool) -> ActionTarget {
    let path = app.session.path.clone();
    let document = if selected {
        (!app.pdm.document.is_empty()).then(|| app.pdm.document.clone())
    } else {
        path.as_ref()
            .and_then(|path| status.managed.local.iter().find(|entry| cached_path_key(&entry.path) == cached_path_key(path)))
            .map(|entry| entry.document.clone())
    };
    let label = target_label(app, document.as_deref(), path.as_deref());
    ActionTarget { document, path, label }
}

fn unavailable(app: &SolveApp, status: &Status, id: &str, target: &ActionTarget, version: Option<u64>) -> Option<&'static str> {
    if app.file_picker_busy() || app.file_load.busy() {
        return Some("ui.pdm_reason_busy");
    }
    if matches!(id, "pdm.connect" | "pdm.disconnect") {
        return status.action_unavailable(id, None, None, false, false, None);
    }
    if app.pdm.workspace_active && app.pdm.selected_folder.is_some() && id != "pdm.refresh" {
        return Some("ui.pdm_reason_select_document");
    }
    let unmanaged_initial = id == "pdm.archive"
        && target.path.as_ref().is_some_and(|path| !status.managed.local.iter().any(|entry| cached_path_key(&entry.path) == cached_path_key(path)));
    if app.pdm.workspace_active && target.document.is_none() && id != "pdm.refresh" && !unmanaged_initial {
        return Some("ui.pdm_reason_select_document");
    }
    let dirty = app.session.is_dirty() || documents::managed_target_dirty(app, target.document.as_deref());
    status.action_unavailable(id, target.document.as_deref(), target.path.as_deref(), dirty, app.session.pdm_read_only, version)
}

/// Generic command surfaces share the explorer's exact target and reason.
pub(crate) fn command_unavailable(app: &SolveApp, command: &str) -> Option<&'static str> {
    if !matches!(
        command,
        "pdm.panel"
            | "pdm.connect"
            | "pdm.disconnect"
            | "pdm.checkout"
            | "pdm.archive"
            | "pdm.cancel_checkout"
            | "pdm.get_latest"
            | "pdm.open_document"
            | "pdm.open_archived"
            | "pdm.restore_version"
            | "pdm.refresh"
    ) {
        return None;
    }
    let Ok(status) = app.pdm.runtime.status() else {
        return Some("ui.pdm_reason_unavailable");
    };
    if command == "pdm.panel" {
        return (status.busy.is_some() || app.file_picker_busy() || app.file_load.busy()).then_some("ui.pdm_reason_busy");
    }
    let target = active_target(app, &status, app.pdm.workspace_active);
    let version = app
        .pdm
        .selected
        .as_ref()
        .filter(|reference| Some(reference.document.as_str()) == target.document.as_deref())
        .map(|reference| reference.version);
    unavailable(app, &status, command, &target, version)
}

/// Interactive command surfaces route through the same captured explorer target.
/// Returning false leaves the remaining setup commands with their guided host flow.
pub(crate) fn start_action(app: &mut SolveApp, command: &str) -> bool {
    if !matches!(
        command,
        "pdm.connect"
            | "pdm.disconnect"
            | "pdm.checkout"
            | "pdm.archive"
            | "pdm.cancel_checkout"
            | "pdm.get_latest"
            | "pdm.open_document"
            | "pdm.open_archived"
            | "pdm.restore_version"
            | "pdm.refresh"
    ) {
        return false;
    }
    let Ok(status) = app.pdm.runtime.status() else {
        return true;
    };
    let target = active_target(app, &status, app.pdm.workspace_active);
    let reference = app.pdm.selected.as_ref().filter(|reference| Some(reference.document.as_str()) == target.document.as_deref()).cloned();
    start_target_action(app, command, target, reference)
}

fn start_target_action(app: &mut SolveApp, command: &str, target: ActionTarget, reference: Option<Reference>) -> bool {
    let Ok(status) = app.pdm.runtime.status() else { return true };
    if let Some(reason) = unavailable(app, &status, command, &target, reference.as_ref().map(|reference| reference.version)) {
        let error = app.tr(reason).to_string();
        app.pdm.notice = Some(Notice { action: action_key(command), file: target.label, path: target.path.clone(), error: Some(reason.into()) });
        app.set_status(error, true);
        return true;
    }
    match command {
        "pdm.connect" => app.pdm.open = true,
        "pdm.disconnect" => dispatch(app, command, json!({})),
        "pdm.cancel_checkout" => {
            app.pdm.cancel_editor = documents::managed_editor_stamp(app, target.document.as_deref());
            app.pdm.cancel_target = Some(target);
            app.pdm.cancel_confirmation = true;
        }
        "pdm.restore_version" => {
            app.pdm.restore_confirmation = reference;
        }
        "pdm.open_archived" => {
            if let Some(reference) = reference {
                dispatch(app, command, json!({"document":reference.document,"version":reference.version}));
            }
        }
        _ => {
            let params =
                target.document.as_ref().filter(|_| command != "pdm.refresh").map_or_else(|| json!({}), |document| json!({"document":document}));
            dispatch(app, command, params);
        }
    }
    true
}

/// The label remains an accessible egui widget; the original icon is painted into
/// its reserved leading space and follows the existing light/dark icon palette.
fn action_button(app: &SolveApp, ui: &mut egui::Ui, id: &str, key: &str, icon: &str, reason: Option<&str>, name: &str) -> bool {
    let text = format!("     {}", app.tr(key));
    let response = ui.add_enabled(reason.is_none(), egui::Button::new(text).min_size(egui::vec2(0.0, 30.0)));
    let rect = egui::Rect::from_center_size(egui::pos2(response.rect.left() + 15.0, response.rect.center().y), egui::vec2(20.0, 20.0));
    crate::icons::paint_icon(ui.painter(), rect, icon, if reason.is_none() { 1.0 } else { 0.4 });
    handle(name, &response);
    crate::scenario::publish_rect(&format!("pdm_action_button:{id}"), response.rect);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, reason.is_none(), app.tr(key)));
    let clicked = response.clicked();
    let help = reason.map_or_else(|| app.tr(key), |reason| app.tr(reason));
    response.on_disabled_hover_text(help).on_hover_text(help);
    crate::scenario::publish_rect(&format!("pdm_action:{id}"), rect);
    clicked
}

/// In modelling this targets only the active editor. The dedicated workspace
/// passes a selected-row target; publication additionally verifies its saved path.
pub fn actions(app: &mut SolveApp, ui: &mut egui::Ui) {
    toolbar(app, ui, app.pdm.workspace_active);
}

fn ribbon_button(app: &SolveApp, ui: &mut egui::Ui, id: &str, key: &str, icon: &str, reason: Option<&str>, name: &str, help: &str) -> bool {
    let font = egui::FontId::proportional(12.0);
    let color = ui.visuals().text_color().gamma_multiply(if reason.is_none() { 1.0 } else { 0.4 });
    let label = ui.painter().layout_no_wrap(app.tr(key).to_string(), font, color);
    let size = egui::vec2((label.size().x + 12.0).max(70.0), 54.0);
    let response = ui.add_enabled(reason.is_none(), egui::Button::new("").min_size(size));
    let icon_rect = egui::Rect::from_center_size(egui::pos2(response.rect.center().x, response.rect.top() + 19.0), egui::vec2(30.0, 30.0));
    crate::icons::paint_icon(ui.painter(), icon_rect, icon, if reason.is_none() { 1.0 } else { 0.4 });
    let label_rect = egui::Rect::from_center_size(egui::pos2(response.rect.center().x, response.rect.top() + 43.0), label.size());
    ui.painter().galley(label_rect.min, label, color);
    handle(name, &response);
    crate::scenario::publish_rect(&format!("pdm_action_button:{id}"), response.rect);
    crate::scenario::publish_rect(&format!("pdm_action:{id}"), icon_rect);
    crate::scenario::publish_rect(&format!("pdm_action_label:{id}"), label_rect);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, reason.is_none(), app.tr(key)));
    let clicked = response.clicked();
    let help = reason.map_or_else(|| format!("{}\n{help}", app.tr(key)), |reason| app.tr(reason).to_string());
    response.on_hover_text(&help).on_disabled_hover_text(help);
    clicked
}

fn toolbar(app: &mut SolveApp, ui: &mut egui::Ui, selected: bool) {
    let Ok(status) = app.pdm.runtime.status() else { return };
    let target = active_target(app, &status, selected);
    let help = format!("{}: {}", app.tr(if selected { "ui.pdm_selected_file" } else { "ui.pdm_active_file" }), target.label);
    let mut action = None;
    egui::ScrollArea::horizontal().id_salt(("pdm_toolbar", selected)).max_height(62.0).show(ui, |ui| {
        ui.horizontal(|ui| {
            let connection =
                status.connection.as_ref().map_or_else(String::new, |connection| format!("{} · {}", connection.label, connection.account));
            if ribbon_button(
                app,
                ui,
                "pdm.connect",
                "ui.pdm_connect",
                "library",
                unavailable(app, &status, "pdm.connect", &target, None),
                "connect_settings",
                &connection,
            ) {
                action = Some("pdm.connect");
            }
            if status.port.is_some()
                && ribbon_button(
                    app,
                    ui,
                    "pdm.disconnect",
                    "ui.pdm_disconnect",
                    "library",
                    unavailable(app, &status, "pdm.disconnect", &target, None),
                    "disconnect_toolbar",
                    &connection,
                )
            {
                action = Some("pdm.disconnect");
            }
            ui.separator();
            for (id, key, icon, name) in [
                ("pdm.open_document", "ui.pdm_open_document", "open", "open_document"),
                ("pdm.checkout", "ui.pdm_checkout", "open", "checkout"),
                ("pdm.archive", "ui.pdm_archive", "save", "archive"),
                ("pdm.cancel_checkout", "ui.pdm_cancel_checkout", "undo", "cancel_checkout"),
            ] {
                let initial = id == "pdm.archive"
                    && target.document.is_none()
                    && (!selected || app.pdm.selected_folder.is_none())
                    && target
                        .path
                        .as_ref()
                        .is_some_and(|path| !status.managed.local.iter().any(|entry| cached_path_key(&entry.path) == cached_path_key(path)));
                let key = if initial { "ui.pdm_archive_initial" } else { key };
                if ribbon_button(app, ui, id, key, icon, unavailable(app, &status, id, &target, None), name, &help) {
                    action = Some(id);
                }
            }
            ui.separator();
            for (id, key, icon, name) in
                [("pdm.get_latest", "ui.pdm_get_latest", "update", "get_latest"), ("pdm.refresh", "ui.pdm_refresh", "update", "refresh")]
            {
                if ribbon_button(app, ui, id, key, icon, unavailable(app, &status, id, &target, None), name, &help) {
                    action = Some(id);
                }
            }
            if selected && ribbon_button(app, ui, "pdm.details", "ui.pdm_details", "library", None, "details", &help) {
                app.pdm.details_visible = !app.pdm.details_visible;
            }
        });
    });
    if let Some(id) = action {
        start_action(app, id);
    }
}

fn folder_icon(ui: &egui::Ui, rect: egui::Rect, name: &str) {
    crate::icons::paint_icon(ui.painter(), rect, name, 1.0);
}

fn clear_file_selection(app: &mut SolveApp) {
    app.pdm.document.clear();
    app.pdm.parent.clear();
    app.pdm.logical_path.clear();
    app.pdm.selected = None;
    app.pdm.dependencies.clear();
    app.pdm.restore_confirmation = None;
    app.pdm.cancel_confirmation = false;
    app.pdm.cancel_target = None;
    app.pdm.history_requested = None;
    app.pdm.detail_context = None;
    app.pdm.preview_requested.clear();
}

fn navigate_folder(app: &mut SolveApp, folder: String) {
    clear_file_selection(app);
    let parts: Vec<_> = folder.split('/').filter(|part| !part.is_empty()).collect();
    for n in 1..=parts.len() {
        app.pdm.expanded.insert(parts[..n].join("/"));
    }
    app.pdm.selected_folder = Some(folder.clone());
    app.pdm.folder = folder;
    app.pdm.search.clear();
}

fn folder_tree(app: &mut SolveApp, ui: &mut egui::Ui, catalog: &[CatalogEntry]) {
    ui.strong(app.tr("ui.pdm_folders"));
    ui.separator();
    let mut folders = std::collections::BTreeSet::new();
    for entry in catalog {
        let mut parent = String::new();
        let parts: Vec<_> = entry.logical_path.split('/').collect();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(part);
            folders.insert(parent.clone());
        }
    }
    egui::ScrollArea::both().id_salt("pdm_folder_tree").show(ui, |ui| {
        let root = ui.selectable_label(app.pdm.folder.is_empty(), format!("      {}", app.tr("ui.pdm_title")));
        folder_icon(ui, egui::Rect::from_center_size(root.rect.left_center() + egui::vec2(12.0, 0.0), egui::vec2(19.0, 19.0)), "folder");
        handle("folder:root", &root);
        if root.clicked() {
            navigate_folder(app, String::new());
        }
        for folder in &folders {
            let parts: Vec<_> = folder.split('/').collect();
            let ancestors: Vec<_> = (1..parts.len()).map(|n| parts[..n].join("/")).collect();
            if ancestors.iter().any(|parent| !app.pdm.expanded.contains(parent)) {
                continue;
            }
            let has_children = folders.iter().any(|child| child.rsplit_once('/').is_some_and(|(parent, _)| parent == folder));
            ui.horizontal(|ui| {
                ui.add_space((parts.len().saturating_sub(1) as f32) * 15.0);
                if has_children {
                    let open = app.pdm.expanded.contains(folder);
                    let toggle = ui.small_button(if open { "▾" } else { "▸" });
                    handle(&format!("folder_expand:{folder}"), &toggle);
                    if toggle.clicked() {
                        if open {
                            app.pdm.expanded.remove(folder);
                        } else {
                            app.pdm.expanded.insert(folder.clone());
                        }
                    }
                } else {
                    ui.add_space(18.0);
                }
                let response = ui.selectable_label(app.pdm.folder == *folder, format!("      {}", parts.last().copied().unwrap_or(folder)));
                folder_icon(ui, egui::Rect::from_center_size(response.rect.left_center() + egui::vec2(12.0, 0.0), egui::vec2(19.0, 19.0)), "folder");
                handle(&format!("folder:{folder}"), &response);
                if response.clicked() {
                    navigate_folder(app, folder.clone());
                }
            });
        }
    });
}

fn cell(ui: &mut egui::Ui, rect: egui::Rect, text: impl Into<egui::WidgetText>, color: egui::Color32) {
    // The table row has already advanced the parent cursor. A scope would move
    // that cursor back to the shorter label and make adjacent rows overlap.
    let mut child =
        ui.new_child(egui::UiBuilder::new().max_rect(rect.shrink2(egui::vec2(8.0, 3.0))).layout(egui::Layout::left_to_right(egui::Align::Center)));
    child.style_mut().visuals.override_text_color = Some(color);
    // Rows own click/selection: text selection must not intercept a click on
    // a filename or a longer busy-state label inside that row.
    child.add(egui::Label::new(text).truncate().selectable(false));
}

enum CatalogClick {
    File(String, bool),
    Folder(String, bool),
}

fn file_table(app: &mut SolveApp, ui: &mut egui::Ui, status: &Status, compact: bool) -> Option<CatalogClick> {
    let t = Tokens::get();
    let search = app.pdm.search.to_lowercase();
    let mut entries: Vec<_> = status
        .managed
        .catalog
        .iter()
        .filter(|entry| {
            let parent = entry.logical_path.rsplit_once('/').map_or("", |(parent, _)| parent);
            parent == app.pdm.folder && entry.logical_path.rsplit('/').next().unwrap_or_default().to_lowercase().contains(&search)
        })
        .collect();
    entries.sort_by(|a, b| {
        let order = match app.pdm.sort_column {
            2 => status.document_state(Some(&a.document), None, false).cmp(status.document_state(Some(&b.document), None, false)),
            3 => a.checkout.as_ref().map(|v| &v.owner).cmp(&b.checkout.as_ref().map(|v| &v.owner)),
            4 => a.head.cmp(&b.head),
            5 => a.head_checked_in_unix_ms.cmp(&b.head_checked_in_unix_ms),
            _ => a.logical_path.to_lowercase().cmp(&b.logical_path.to_lowercase()),
        };
        if app.pdm.sort_descending { order.reverse() } else { order }
    });
    let prefix = if app.pdm.folder.is_empty() { String::new() } else { format!("{}/", app.pdm.folder) };
    let mut folders: Vec<_> = status
        .managed
        .catalog
        .iter()
        .filter_map(|entry| {
            let tail = entry.logical_path.strip_prefix(&prefix)?;
            let (name, _) = tail.split_once('/')?;
            name.to_lowercase().contains(&search).then(|| format!("{prefix}{name}"))
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    folders.sort_by_key(|folder| folder.to_lowercase());
    if app.pdm.sort_descending {
        folders.reverse();
    }
    let mut selected = None;
    egui::ScrollArea::both().id_salt(("pdm_catalog", app.pdm.folder.clone())).auto_shrink([false, false]).show(ui, |ui| {
        let width: f32 = app.pdm.column_widths.iter().sum();
        let (header, _) = ui.allocate_exact_size(egui::vec2(width, if compact { 28.0 } else { 32.0 }), egui::Sense::hover());
        ui.painter().rect_filled(header, 0.0, t.panel_header);
        let mut x = header.left();
        for (column, key) in
            ["ui.pdm_file", "ui.pdm_description", "ui.pdm_local_status", "ui.pdm_checked_out_by", "ui.pdm_local_server", "ui.pdm_checked_in"]
                .into_iter()
                .enumerate()
        {
            let w = app.pdm.column_widths.get(column).copied().unwrap_or(120.0);
            let rect = egui::Rect::from_min_size(egui::pos2(x, header.top()), egui::vec2(w, header.height()));
            let response = ui.interact(rect.shrink2(egui::vec2(4.0, 0.0)), ui.id().with(("pdm_sort", column)), egui::Sense::click());
            let arrow = if app.pdm.sort_column == column { if app.pdm.sort_descending { " ↓" } else { " ↑" } } else { "" };
            cell(ui, rect, egui::RichText::new(format!("{}{arrow}", app.tr(key))).strong(), t.text);
            handle(&format!("sort:{column}"), &response);
            if response.clicked() {
                if app.pdm.sort_column == column {
                    app.pdm.sort_descending = !app.pdm.sort_descending;
                } else {
                    app.pdm.sort_column = column;
                    app.pdm.sort_descending = false;
                }
            }
            let splitter = egui::Rect::from_center_size(egui::pos2(rect.right(), rect.center().y), egui::vec2(6.0, rect.height()));
            let resize =
                ui.interact(splitter, ui.id().with(("pdm_column", column)), egui::Sense::drag()).on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
            if resize.dragged()
                && let Some(pointer) = resize.interact_pointer_pos()
                && let Some(column_width) = app.pdm.column_widths.get_mut(column)
            {
                *column_width = (pointer.x - x).clamp(88.0, 600.0);
            }
            ui.painter().line_segment([rect.right_top(), rect.right_bottom()], egui::Stroke::new(1.0, t.border));
            x += w;
        }
        if entries.is_empty() && folders.is_empty() {
            ui.add_space(28.0);
            ui.label(egui::RichText::new(app.tr(if status.port.is_none() { "ui.pdm_connect_hint" } else { "ui.pdm_no_files" })).color(t.text_dim));
        }
        for folder in &folders {
            let (row, _) = ui.allocate_exact_size(egui::vec2(width, if compact { 28.0 } else { 31.0 }), egui::Sense::hover());
            let response = ui.interact(row, ui.id().with(("pdm_folder", folder)), egui::Sense::click());
            if app.pdm.selected_folder.as_ref() == Some(folder) || response.hovered() {
                ui.painter().rect_filled(row, 0.0, t.hover);
            }
            folder_icon(ui, egui::Rect::from_center_size(row.left_center() + egui::vec2(18.0, 0.0), egui::vec2(21.0, 21.0)), "folder");
            let name_rect =
                egui::Rect::from_min_max(row.min + egui::vec2(27.0, 0.0), egui::pos2(row.left() + app.pdm.column_widths[0], row.bottom()));
            cell(ui, name_rect, folder.rsplit('/').next().unwrap_or(folder), t.text);
            handle(&format!("folder_row:{folder}"), &response);
            if response.clicked() {
                selected = Some(CatalogClick::Folder(folder.clone(), response.double_clicked()));
            }
        }
        for (index, entry) in entries.iter().enumerate() {
            let document = &entry.document;
            let (row, _) = ui.allocate_exact_size(egui::vec2(width, if compact { 28.0 } else { 31.0 }), egui::Sense::hover());
            let response = ui.interact(row, ui.id().with(("pdm_file", document)), egui::Sense::click());
            let is_selected = app.pdm.document == *document;
            let fill = if is_selected {
                t.accent_soft
            } else if response.hovered() {
                t.hover
            } else if index % 2 == 0 {
                t.panel
            } else {
                t.subheading_bg
            };
            ui.painter().rect_filled(row, 0.0, fill);
            handle(&format!("file:{document}"), &response);
            if response.clicked() {
                selected = Some(CatalogClick::File(document.clone(), response.double_clicked()));
            }
            let local = status.managed.local.iter().find(|local| local.document == *document);
            let dirty = documents::managed_target_dirty(app, Some(document));
            let state = status.document_state(Some(document), local.map(|local| local.path.as_str()), dirty);
            let color = if matches!(
                state,
                "ui.pdm_state_modified" | "ui.pdm_state_outdated" | "ui.pdm_state_checked_out_elsewhere" | "ui.pdm_state_checked_out_other"
            ) {
                t.warning
            } else if state == "ui.pdm_state_error" {
                t.error
            } else {
                t.text
            };
            let values = [
                entry.logical_path.rsplit('/').next().unwrap_or(&entry.logical_path).to_string(),
                "—".to_string(),
                format!("●  {}", app.tr(state)),
                entry.checkout.as_ref().map_or_else(|| "—".into(), |lock| format!("{} · {}", lock.owner, lock.machine)),
                format!(
                    "{} / {}",
                    local.filter(|local| local.present).map_or_else(|| "—".into(), |local| format!("v{}", local.base_version)),
                    entry.head.map_or_else(|| "—".into(), |head| format!("v{head}"))
                ),
                entry.head_checked_in_unix_ms.map_or_else(|| "—".into(), utc_time),
            ];
            let mut x = row.left();
            for (column, value) in values.iter().enumerate() {
                let w = app.pdm.column_widths.get(column).copied().unwrap_or(120.0);
                let rect = egui::Rect::from_min_size(egui::pos2(x, row.top()), egui::vec2(w, row.height()));
                if column == 0 {
                    folder_icon(ui, egui::Rect::from_center_size(rect.left_center() + egui::vec2(18.0, 0.0), egui::vec2(21.0, 21.0)), "box");
                    cell(ui, egui::Rect::from_min_max(rect.min + egui::vec2(27.0, 0.0), rect.max), value.as_str(), t.text);
                } else {
                    cell(ui, rect, value.as_str(), if column == 2 { color } else { t.text });
                }
                x += w;
            }
            if response.secondary_clicked() {
                selected = Some(CatalogClick::File(document.clone(), false));
            }
            response.clone().context_menu(|ui| file_context_menu(app, ui, status, entry));
            response.on_hover_text(&entry.logical_path);
        }
    });
    selected
}

fn local_working_file(status: &Status, document: &str) -> Option<std::path::PathBuf> {
    status.port?;
    let root = std::fs::canonicalize(status.managed.root.as_ref()?).ok()?;
    let local = status.managed.local.iter().find(|entry| entry.document == document && entry.present)?;
    let file = std::fs::canonicalize(&local.path).ok()?;
    let parent = file.parent()?;
    (root.is_dir() && file.is_file() && parent.is_dir() && parent.starts_with(root)).then_some(file)
}

fn file_context_menu(app: &mut SolveApp, ui: &mut egui::Ui, status: &Status, entry: &CatalogEntry) {
    let target = ActionTarget { document: Some(entry.document.clone()), path: app.session.path.clone(), label: entry.logical_path.clone() };
    for (id, key, icon, name) in [
        ("pdm.open_document", "ui.open", "open", "context_open"),
        ("pdm.archive", "ui.pdm_archive", "save", "context_archive"),
        ("pdm.get_latest", "ui.pdm_load", "update", "context_load"),
        ("pdm.checkout", "ui.pdm_checkout", "open", "context_checkout"),
        ("pdm.cancel_checkout", "ui.pdm_cancel_checkout", "undo", "context_cancel_checkout"),
    ] {
        let reason = unavailable(app, status, id, &target, None);
        if action_button(app, ui, &format!("context:{id}"), key, icon, reason, name) {
            start_target_action(app, id, target.clone(), None);
            ui.close();
        }
    }
    ui.separator();
    if action_button(app, ui, "context:folder", "ui.pdm_go_to_folder", "folder", None, "context_folder") {
        let folder = entry.logical_path.rsplit_once('/').map_or("", |(parent, _)| parent).to_string();
        navigate_folder(app, folder);
        app.pdm.selected_folder = None;
        app.pdm.document = entry.document.clone();
        app.pdm.metadata_not_before = ui.input(|input| input.time) + ui.ctx().options(|options| options.input_options.max_double_click_delay);
        ui.close();
    }
    let file = local_working_file(status, &entry.document);
    let reason = (file.is_none() || app.services.show_in_folder.is_none()).then_some("ui.pdm_reason_working_folder");
    if action_button(app, ui, "context:working_folder", "ui.pdm_go_to_working_folder", "folder", reason, "context_working_folder") {
        if let (Some(file), Some(show)) = (file, app.services.show_in_folder.as_ref()) {
            show(&file.to_string_lossy());
        }
        ui.close();
    }
}

fn detail_context_matches(app: &SolveApp) -> bool {
    let expected = app.pdm.selected.as_ref().filter(|reference| reference.document == app.pdm.document).map(|reference| reference.version);
    app.pdm.detail_context.as_ref().is_some_and(|(document, version)| document == &app.pdm.document && *version == expected)
}

fn details(app: &mut SolveApp, ui: &mut egui::Ui, status: &Status) -> Option<(&'static str, serde_json::Value)> {
    let t = Tokens::get();
    let mut action = None;
    let bounds = ui.available_rect_before_wrap();
    crate::scenario::publish_rect("pdm_details_pane", bounds);
    let compact = bounds.height() < 180.0;
    if compact {
        ui.spacing_mut().item_spacing.y = 2.0;
    }
    let font = egui::TextStyle::Button.resolve(ui.style());
    let button_width = ["ui.pdm_open_archived", "ui.pdm_restore_version"]
        .into_iter()
        .map(|key| ui.painter().layout_no_wrap(format!("     {}", app.tr(key)), font.clone(), t.text).size().x + ui.spacing().button_padding.x * 2.0)
        .sum::<f32>()
        + ui.spacing().item_spacing.x;
    let action_height = if compact && button_width + 12.0 <= bounds.width() { 34.0 } else { 42.0 };
    let actions_rect = egui::Rect::from_min_max(egui::pos2(bounds.left(), (bounds.bottom() - action_height).max(bounds.top())), bounds.max);
    crate::scenario::publish_rect("pdm_detail_actions", actions_rect);
    ui.horizontal(|ui| {
        for (index, key) in ["ui.pdm_versions", "ui.pdm_uses", "ui.pdm_where_used", "ui.pdm_preview"].iter().enumerate() {
            let label = app.tr(key).to_string();
            ui.selectable_value(&mut app.pdm.detail_tab, index, label);
        }
    });
    ui.separator();
    app.pdm.preview_cache.update(ui.ctx(), status.managed.preview.as_ref());
    let mut versions: Vec<_> =
        if status.managed.history.is_empty() { status.versions.clone() } else { status.managed.history.iter().map(|v| v.version.clone()).collect() };
    versions.sort_by_key(|version| std::cmp::Reverse(version.reference.version));
    let body_gap = if compact { 2.0 } else { 4.0 };
    let body_rect = egui::Rect::from_min_max(ui.cursor().min, egui::pos2(bounds.right(), (actions_rect.top() - body_gap).max(ui.cursor().min.y)));
    let height = body_rect.height();
    let mut body_ui = ui.new_child(egui::UiBuilder::new().max_rect(body_rect));
    body_ui.set_clip_rect(body_rect.intersect(ui.clip_rect()));
    body_ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
    let scrolled = egui::ScrollArea::both().id_salt("pdm_details").max_height(height).min_scrolled_height(0.0).auto_shrink([false, false]).show(
        &mut body_ui,
        |ui| match app.pdm.detail_tab {
            0 => {
                if versions.iter().all(|version| version.reference.document != app.pdm.document) {
                    ui.label(app.tr("ui.pdm_no_history"));
                }
                egui::Grid::new("pdm_history_table").striped(true).min_col_width(76.0).spacing(egui::vec2(18.0, 8.0)).show(ui, |ui| {
                    for key in
                        ["ui.pdm_preview", "ui.pdm_server_version", "ui.pdm_local_status", "ui.pdm_author", "ui.pdm_checked_in", "ui.pdm_description"]
                    {
                        ui.strong(app.tr(key));
                    }
                    ui.end_row();
                    for version in versions.iter().filter(|version| version.reference.document == app.pdm.document) {
                        let reference = &version.reference;
                        if let Some((_, texture)) =
                            app.pdm.preview_cache.recent.iter().find(|((cached, sha), _)| cached == reference && sha == &version.sha256)
                        {
                            let response = ui.add(egui::Image::new((texture.id(), texture.size_vec2())).fit_to_exact_size(egui::vec2(64.0, 40.0)));
                            crate::scenario::publish_rect(
                                &format!("pdm_history_thumbnail:{}:{}", reference.document, reference.version),
                                response.rect,
                            );
                        } else {
                            ui.label(egui::RichText::new("—").color(t.text_dim)).on_hover_text(app.tr("ui.pdm_preview_unavailable"));
                        }
                        let response = ui.selectable_label(app.pdm.selected.as_ref() == Some(reference), format!("v{}", reference.version));
                        handle(&format!("version:{}:{}", reference.document, reference.version), &response);
                        crate::scenario::publish_rect(&format!("pdm_history_version:{}:{}", reference.document, reference.version), response.rect);
                        if response.clicked() {
                            app.pdm.selected = Some(reference.clone());
                            action = Some(("pdm.preview", json!({"document":reference.document,"version":reference.version})));
                        }
                        let copy = status
                            .managed
                            .local
                            .iter()
                            .find(|local| local.document == reference.document && local.present && local.base_version == reference.version);
                        ui.label(app.tr(if copy.is_some() { "ui.pdm_current" } else { "ui.pdm_absent" }));
                        let metadata = status.managed.history.iter().find(|item| item.version.reference == *reference);
                        ui.label(metadata.map_or("—", |item| item.author.as_str()));
                        ui.label(metadata.map_or_else(|| "—".into(), |item| utc_time(item.checked_in_unix_ms)));
                        ui.label(metadata.map_or("—", |item| item.comment.as_str()));
                        ui.end_row();
                    }
                });
            }
            1 => {
                let dependencies = versions
                    .iter()
                    .find(|version| app.pdm.selected.as_ref() == Some(&version.reference))
                    .map(|version| version.dependencies.as_slice())
                    .unwrap_or(&[]);
                if dependencies.is_empty() {
                    ui.label(app.tr("ui.pdm_no_dependencies"));
                }
                for reference in dependencies {
                    ui.label(reference_label(reference, &status.managed.catalog));
                }
            }
            2 => {
                if detail_context_matches(app) {
                    if status.managed.where_used.is_empty() {
                        ui.label(app.tr("ui.pdm_no_dependencies"));
                    }
                    for reference in &status.managed.where_used {
                        ui.label(reference_label(reference, &status.managed.catalog));
                    }
                } else if let Some(error) = &status.error {
                    ui.colored_label(t.error, app.tr(error));
                } else if app.pdm.document.is_empty() {
                    ui.label(app.tr("ui.pdm_select_file"));
                } else {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(app.tr("ui.pdm_busy"));
                    });
                }
            }
            _ => {
                let selected = app.pdm.selected.as_ref();
                let texture = selected.and_then(|reference| {
                    app.pdm.preview_cache.recent.iter().find(|((cached, _), _)| cached == reference).map(|(_, texture)| texture)
                });
                if let Some(texture) = texture {
                    ui.add(egui::Image::new((texture.id(), texture.size_vec2())).max_size(egui::vec2(ui.available_width(), height)));
                } else {
                    ui.label(app.tr("ui.pdm_preview_unavailable"));
                }
            }
        },
    );
    crate::scenario::publish_rect("pdm_details_scroll", scrolled.inner_rect);
    let target = active_target(app, status, true);
    let reference = app.pdm.selected.as_ref().filter(|reference| reference.document == app.pdm.document).cloned();
    let mut actions_ui = ui.new_child(egui::UiBuilder::new().max_rect(actions_rect));
    actions_ui.set_clip_rect(actions_rect.intersect(ui.clip_rect()));
    egui::ScrollArea::horizontal().id_salt("pdm_details_action_scroll").max_height(actions_rect.height()).show(&mut actions_ui, |ui| {
        ui.horizontal(|ui| {
            let reason = unavailable(app, status, "pdm.open_archived", &target, reference.as_ref().map(|reference| reference.version));
            if action_button(app, ui, "pdm.open_archived", "ui.pdm_open_archived", "open", reason, "open_archived")
                && let Some(reference) = &reference
            {
                action = Some(("pdm.open_archived", json!({"document":reference.document,"version":reference.version})));
            }
            let reason = unavailable(app, status, "pdm.restore_version", &target, reference.as_ref().map(|reference| reference.version));
            if action_button(app, ui, "pdm.restore_version", "ui.pdm_restore_version", "restore", reason, "restore_version") {
                app.pdm.restore_confirmation = reference;
            }
        });
    });
    ui.advance_cursor_after_rect(bounds);
    action
}

fn status_bar(app: &mut SolveApp, ui: &mut egui::Ui, status: &Status) {
    let t = Tokens::get();
    ui.separator();
    egui::ScrollArea::horizontal().id_salt("pdm_footer_identity").max_height(ui.text_style_height(&egui::TextStyle::Body) + 6.0).show(ui, |ui| {
        ui.horizontal(|ui| {
            let online = status.port.is_some() && status.available;
            ui.colored_label(
                if online { t.accent } else { t.warning },
                format!("● {}", app.tr(if online { "ui.pdm_connection_online" } else { "ui.pdm_connection_offline" })),
            );
            if let Some(connection) = &status.connection {
                ui.separator();
                ui.label(&connection.label);
                ui.label(&connection.account);
                ui.label(&connection.role);
            }
            let count = if app.pdm.document.is_empty() { "0" } else { "1" };
            ui.separator();
            ui.label(crate::i18n::format("ui.pdm_selection_count", &[("count", count)]));
            if status.busy.is_some() || app.saving.is_some() {
                ui.spinner();
                ui.label(app.tr(if app.saving.is_some() { "ui.pdm_saving" } else { "ui.pdm_busy" }));
            }
        });
    });
    if let Some(notice) = &app.pdm.notice {
        let action = app.tr(notice.action);
        let key = if notice.error.is_some() { "ui.pdm_operation_failed" } else { "ui.pdm_operation_succeeded" };
        let error = notice.error.as_deref().map(|error| app.tr(error)).unwrap_or_default();
        let message = crate::i18n::format(key, &[("action", action), ("file", &notice.file), ("error", error)]);
        let color = if notice.error.is_some() { t.error } else { t.text };
        let tooltip = notice.path.as_ref().map_or_else(|| message.clone(), |path| format!("{message}\n{path}"));
        let response = ui.add(egui::Label::new(egui::RichText::new(message).color(color)).truncate()).on_hover_text(tooltip);
        crate::scenario::publish_rect("pdm_notice", response.rect);
        if notice.action == "ui.pdm_archive"
            && notice.error.is_some()
            && let Some(target) = app.pdm.reconcile_target.clone()
        {
            let reason = if status.busy.is_some() || app.file_picker_busy() || app.file_load.busy() {
                Some("ui.pdm_reason_busy")
            } else if status.port.is_none() || !status.available {
                Some("ui.pdm_reason_disconnected")
            } else if target
                .path
                .as_ref()
                .zip(app.session.path.as_ref())
                .is_none_or(|(original, current)| cached_path_key(original) != cached_path_key(current))
            {
                Some("ui.pdm_reason_open_selected")
            } else if app.session.is_dirty() {
                Some("ui.pdm_reason_save_first")
            } else {
                None
            };
            let response = ui
                .add_enabled(reason.is_none(), egui::Button::new(app.tr("ui.pdm_reconcile_archive")))
                .on_hover_text(app.tr("ui.pdm_reconcile_archive_hint"));
            let response = if let Some(reason) = reason { response.on_disabled_hover_text(app.tr(reason)) } else { response };
            handle("reconcile_archive", &response);
            if response.clicked() {
                let mut params = json!({"reconcile":true});
                if let Some(document) = target.document {
                    params["document"] = json!(document);
                }
                dispatch(app, "pdm.archive", params);
            }
        }
    } else if let Some(error) = &status.error {
        ui.add(egui::Label::new(egui::RichText::new(app.tr(error)).color(t.error)).truncate()).on_hover_text(app.tr(error));
    }
}

pub fn workspace(app: &mut SolveApp, ui: &mut egui::Ui) {
    let Ok(status) = app.pdm.runtime.status() else {
        return;
    };
    let t = Tokens::get();
    let compact = ui.available_height() < 440.0;
    egui::Frame::new().fill(t.panel).inner_margin(if compact { 8.0 } else { 12.0 }).show(ui, |ui| {
        ui.set_min_size(ui.available_size());
        let archive_label = status.managed.root.as_deref().map(|root| {
            status
                .connection
                .as_ref()
                .map(|connection| connection.label.as_str())
                .unwrap_or_else(|| root.rsplit(['/', '\\']).find(|part| !part.is_empty()).unwrap_or(root))
        });
        if !compact {
            ui.horizontal(|ui| {
                ui.heading(app.tr("ui.pdm_title"));
                if let Some(label) = archive_label {
                    ui.label(egui::RichText::new(label).color(t.text_dim)).on_hover_text(status.managed.root.as_deref().unwrap_or_default());
                }
            });
        }
        ui.horizontal(|ui| {
            // The archive identity shares the navigation row in short windows,
            // leaving room for a complete history thumbnail instead of a second
            // heading row. The full identity/path remains available on hover.
            if compact {
                ui.strong(app.tr("ui.pdm_title"));
                if let Some(label) = archive_label {
                    let help = format!("{label}\n{}", status.managed.root.as_deref().unwrap_or_default());
                    ui.add_sized(
                        egui::vec2(140.0, ui.text_style_height(&egui::TextStyle::Body)),
                        egui::Label::new(egui::RichText::new(label).color(t.text_dim)).truncate(),
                    )
                    .on_hover_text(help);
                }
                ui.separator();
            }
            let root = ui.selectable_label(app.pdm.folder.is_empty(), "/");
            handle("breadcrumb:root", &root);
            if root.clicked() {
                navigate_folder(app, String::new());
            }
            let mut path = String::new();
            for part in app.pdm.folder.clone().split('/') {
                if part.is_empty() {
                    continue;
                }
                if !path.is_empty() {
                    path.push('/');
                }
                path.push_str(part);
                ui.label("›");
                let response = ui.link(part);
                handle(&format!("breadcrumb:{path}"), &response);
                if response.clicked() {
                    navigate_folder(app, path.clone());
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let response =
                    ui.add(egui::TextEdit::singleline(&mut app.pdm.search).hint_text(crate::i18n::tr("ui.pdm_search")).desired_width(240.0));
                handle("search", &response);
            });
        });
        ui.separator();
        let line = ui.text_style_height(&egui::TextStyle::Body);
        let spacing = ui.spacing().item_spacing.y;
        let status_height = line
            + spacing * 2.0
            + if compact { 6.0 } else { 10.0 }
            + if app.pdm.notice.is_some() || status.error.is_some() { line + spacing } else { 0.0 }
            + if app.pdm.reconcile_target.is_some() { 32.0 + spacing } else { 0.0 };
        let remaining = ui.available_height();
        let content_height = (remaining - status_height).max(0.0);
        let available = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), content_height));
        let footer =
            egui::Rect::from_min_max(egui::pos2(available.left(), available.bottom()), egui::pos2(available.right(), available.top() + remaining));
        crate::scenario::publish_rect("pdm_footer", footer);
        let tree_width = app.pdm.tree_width.clamp(150.0, (available.width() * 0.4).max(150.0));
        let tree = egui::Rect::from_min_max(available.min, egui::pos2(available.left() + tree_width, available.bottom()));
        let splitter = egui::Rect::from_min_max(egui::pos2(tree.right() + 3.0, available.top()), egui::pos2(tree.right() + 9.0, available.bottom()));
        let right = egui::Rect::from_min_max(egui::pos2(splitter.right() + 7.0, available.top()), available.max);
        ui.scope_builder(egui::UiBuilder::new().max_rect(tree), |ui| folder_tree(app, ui, &status.managed.catalog));
        ui.painter().line_segment([splitter.center_top(), splitter.center_bottom()], egui::Stroke::new(1.0, t.border));
        let resize =
            ui.interact(splitter, ui.id().with("pdm_tree_splitter"), egui::Sense::drag()).on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
        if resize.dragged()
            && let Some(pointer) = resize.interact_pointer_pos()
        {
            app.pdm.tree_width = (pointer.x - available.left()).clamp(150.0, (available.width() * 0.4).max(150.0));
        }
        let mut action = None;
        ui.scope_builder(egui::UiBuilder::new().max_rect(right), |ui| {
            ui.set_clip_rect(right.intersect(ui.clip_rect()));
            let selection = status.managed.catalog.iter().find(|entry| entry.document == app.pdm.document);
            ui.horizontal(|ui| {
                ui.strong(selection.map_or_else(|| app.tr("ui.pdm_select_file"), |entry| entry.logical_path.as_str()));
                if let Some(entry) = selection {
                    ui.label(
                        egui::RichText::new(app.tr(status.document_state(
                            Some(&entry.document),
                            None,
                            documents::managed_target_dirty(app, Some(&entry.document)),
                        )))
                        .color(t.text_dim),
                    );
                }
            });
            ui.separator();
            let remaining = ui.available_height();
            let min_table = if compact { 28.0 + 28.0 } else { 32.0 + 31.0 } + ui.spacing().item_spacing.y;
            let divider_height = if compact { 6.0 } else { 8.0 };
            let maximum_details = (remaining - min_table - divider_height).max(0.0);
            let details_height = if app.pdm.details_visible { app.pdm.details_height.max(96.0).min(maximum_details) } else { 0.0 };
            let table_height = (remaining - details_height - if app.pdm.details_visible { divider_height } else { 0.0 }).max(0.0);
            let table = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), table_height));
            ui.scope_builder(egui::UiBuilder::new().id_salt("pdm_file_table").max_rect(table), |ui| {
                ui.set_clip_rect(table.intersect(ui.clip_rect()));
                if let Some(clicked) = file_table(app, ui, &status, compact) {
                    clear_file_selection(app);
                    match clicked {
                        CatalogClick::File(document, open) => {
                            app.pdm.selected_folder = None;
                            app.pdm.document = document;
                            // A first click must not start background IO before a
                            // physical second click can request the working copy.
                            let delay = ui.ctx().options(|options| options.input_options.max_double_click_delay);
                            app.pdm.metadata_not_before = ui.input(|input| input.time) + delay;
                            ui.ctx().request_repaint_after(std::time::Duration::from_secs_f64(delay));
                            if open {
                                start_action(app, "pdm.open_document");
                            }
                        }
                        CatalogClick::Folder(folder, enter) => {
                            app.pdm.selected_folder = Some(folder.clone());
                            if enter {
                                navigate_folder(app, folder);
                            }
                        }
                    }
                }
            });
            if app.pdm.details_visible {
                let splitter = egui::Rect::from_min_size(egui::pos2(table.left(), table.bottom()), egui::vec2(table.width(), divider_height));
                let response = ui
                    .interact(splitter, ui.id().with("pdm_details_splitter"), egui::Sense::drag())
                    .on_hover_cursor(egui::CursorIcon::ResizeVertical);
                ui.painter().line_segment([splitter.left_center(), splitter.right_center()], egui::Stroke::new(1.0, t.border));
                if response.dragged()
                    && let Some(pointer) = response.interact_pointer_pos()
                {
                    app.pdm.details_height = (right.bottom() - pointer.y).max(0.0).min(maximum_details);
                }
                let details_rect = egui::Rect::from_min_max(egui::pos2(right.left(), splitter.bottom()), right.max);
                ui.scope_builder(egui::UiBuilder::new().max_rect(details_rect), |ui| {
                    ui.set_clip_rect(details_rect.intersect(ui.clip_rect()));
                    if let Some(detail_action) = details(app, ui, &status) {
                        action = Some(detail_action);
                    }
                });
            }
        });
        ui.scope_builder(egui::UiBuilder::new().max_rect(footer), |ui| {
            ui.set_clip_rect(footer.intersect(ui.clip_rect()));
            status_bar(app, ui, &status);
        });
        let metadata_idle = ui.input(|input| input.time) >= app.pdm.metadata_not_before
            && app.pdm.runtime.status().is_ok_and(|current| current.busy.is_none())
            && !app.pdm.cancel_confirmation
            && app.pdm.restore_confirmation.is_none()
            && !app.pdm.recovery_confirmation
            && !app.pdm.open
            && !app.file_picker_busy()
            && !app.file_load.busy();
        if action.is_none()
            && metadata_idle
            && status.busy.is_none()
            && status.available
            && status.port.is_some()
            && !app.file_picker_busy()
            && !app.file_load.busy()
            && !app.pdm.document.is_empty()
            && app.pdm.history_requested.as_deref() != Some(app.pdm.document.as_str())
            && status.managed.catalog.iter().any(|entry| entry.document == app.pdm.document)
        {
            app.pdm.history_requested = Some(app.pdm.document.clone());
            action = Some(("pdm.history", json!({"document":app.pdm.document})));
        }
        if action.is_none()
            && metadata_idle
            && status.busy.is_none()
            && status.port.is_some()
            && status.available
            && status.error.is_none()
            && app.pdm.detail_tab == 2
            && !app.pdm.document.is_empty()
            && !detail_context_matches(app)
        {
            action = Some(if let Some(reference) = app.pdm.selected.as_ref().filter(|reference| reference.document == app.pdm.document) {
                ("pdm.preview", json!({"document":reference.document,"version":reference.version}))
            } else {
                ("pdm.history", json!({"document":app.pdm.document}))
            });
        }
        if action.is_none() && metadata_idle && status.busy.is_none() && app.pdm.details_visible && app.pdm.detail_tab == 0 {
            // Request at most one immutable thumbnail per frame/job, bounded to
            // the first sixteen history rows. A missing image is remembered too.
            let mut versions: Vec<_> = if status.managed.history.is_empty() {
                status.versions.clone()
            } else {
                status.managed.history.iter().map(|item| item.version.clone()).collect()
            };
            versions.sort_by_key(|version| std::cmp::Reverse(version.reference.version));
            for version in versions.iter().filter(|version| version.reference.document == app.pdm.document).take(16) {
                let identity = (version.reference.document.clone(), version.reference.version, version.sha256.clone());
                if status
                    .action_unavailable("pdm.preview", Some(&version.reference.document), None, false, false, Some(version.reference.version))
                    .is_none()
                    && !app.pdm.preview_cache.recent.iter().any(|((reference, sha), _)| reference == &version.reference && sha == &version.sha256)
                    && {
                        if app.pdm.preview_requested.len() >= 256 {
                            app.pdm.preview_requested.clear();
                        }
                        app.pdm.preview_requested.insert(identity)
                    }
                {
                    action = Some(("pdm.preview", json!({"document":version.reference.document,"version":version.reference.version})));
                    break;
                }
            }
        }
        if let Some((id, params)) = action {
            dispatch(app, id, params);
        }
    });
}

pub fn show(app: &mut SolveApp, ctx: &egui::Context) {
    guided::connection_window(app, ctx);
    if let Some(reference) = app.pdm.restore_confirmation.clone() {
        egui::Modal::new(egui::Id::new("pdm_restore_version_confirmation")).show(ctx, |ui| {
            ui.heading(app.tr("ui.pdm_restore_version"));
            ui.label(app.tr("ui.pdm_restore_version_warning"));
            let status = app.pdm.runtime.status().ok();
            let target = ActionTarget {
                document: Some(reference.document.clone()),
                path: app.session.path.clone(),
                label: target_label(app, Some(&reference.document), None),
            };
            ui.label(format!("{} · v{}", target.label, reference.version)).on_hover_text(&reference.document);
            let reason = status.as_ref().and_then(|status| unavailable(app, status, "pdm.restore_version", &target, Some(reference.version)));
            let response = ui.add_enabled(status.is_some() && reason.is_none(), egui::Button::new(app.tr("ui.pdm_restore_version_confirm")));
            let response = if let Some(reason) = reason { response.on_disabled_hover_text(app.tr(reason)) } else { response };
            handle("restore_version_confirm", &response);
            if response.clicked() {
                app.pdm.restore_confirmation = None;
                dispatch(app, "pdm.restore_version", json!({"document":reference.document,"version":reference.version,"restore":true}));
            }
            if ui.button(app.tr("ui.cancel")).clicked() {
                app.pdm.restore_confirmation = None;
            }
        });
    }
    if app.pdm.recovery_confirmation {
        egui::Modal::new(egui::Id::new("pdm_recover_confirmation")).show(ctx, |ui| {
            ui.heading(app.tr("ui.pdm_recover_workspace"));
            ui.label(app.tr("ui.pdm_recover_warning"));
            ui.label(format!("127.0.0.1:{}", app.pdm.port));
            ui.label(&app.pdm.root);
            if ui.button(app.tr("ui.pdm_recover_confirm")).clicked() {
                app.pdm.recovery_confirmation = false;
                dispatch(app, "pdm.recover_workspace", json!({"port":app.pdm.port.parse::<u16>().ok(),"root":app.pdm.root,"restore":true}));
            }
            if ui.button(app.tr("ui.cancel")).clicked() {
                app.pdm.recovery_confirmation = false;
            }
        });
    }
    if app.pdm.pending_edit.is_some() && app.pdm.pending_edit_path != app.session.path.as_ref().map(|path| cached_path_key(path)) {
        app.pdm.pending_edit = None;
    }
    if let Some(command) = app.pdm.pending_edit.clone() {
        egui::Modal::new(egui::Id::new("pdm_readonly_confirmation")).show(ctx, |ui| {
            ui.heading(app.tr("ui.pdm_readonly_title"));
            ui.label(app.tr("ui.pdm_readonly_hint"));
            let status = app.pdm.runtime.status().ok();
            let reason = status.as_ref().and_then(|status| unavailable(app, status, "pdm.checkout", &active_target(app, status, false), None));
            let response = ui.add_enabled(status.is_some() && reason.is_none(), egui::Button::new(app.tr("ui.pdm_checkout")));
            let response = if let Some(reason) = reason { response.on_disabled_hover_text(app.tr(reason)) } else { response };
            if response.clicked() {
                app.pdm.pending_edit = None;
                app.pdm.resume_edit = app.session.path.as_ref().map(|path| (cached_path_key(path), command.clone()));
                dispatch(app, "pdm.checkout", json!({}));
            }
            if ui.button(app.tr("ui.pdm_edit_ram")).clicked() {
                if let Some(path) = &app.session.path {
                    app.pdm.ram_paths.insert(cached_path_key(path));
                }
                app.pdm.pending_edit = None;
                app.start(&command);
            }
            if ui.button(app.tr("ui.cancel")).clicked() {
                app.pdm.pending_edit = None;
            }
        });
    }
    if app.pdm.cancel_confirmation {
        let status = app.pdm.runtime.status().ok();
        let target = app.pdm.cancel_target.clone().or_else(|| status.as_ref().map(|status| active_target(app, status, app.pdm.workspace_active)));
        let stale_consent = app.pdm.cancel_editor.as_ref().is_some_and(|stamp| !stamp.matches(app));
        let incomplete = status
            .as_ref()
            .zip(target.as_ref())
            .is_some_and(|(status, target)| target.document.as_ref().is_some_and(|document| status.managed.recoverable_checkouts.contains(document)));
        egui::Modal::new(egui::Id::new("pdm_undo_confirmation")).show(ctx, |ui| {
            ui.heading(app.tr("ui.pdm_cancel_checkout"));
            ui.label(app.tr(if incomplete { "ui.pdm_release_incomplete_warning" } else { "ui.pdm_discard_warning" }));
            if let Some(target) = &target {
                ui.label(&target.label);
            }
            let reason =
                status.as_ref().zip(target.as_ref()).and_then(|(status, target)| unavailable(app, status, "pdm.cancel_checkout", target, None));
            let response = ui.add_enabled(
                status.is_some() && target.is_some() && reason.is_none() && !stale_consent,
                egui::Button::new(app.tr(if incomplete { "ui.pdm_cancel_checkout" } else { "ui.pdm_discard_confirm" })),
            );
            let response = if let Some(reason) = reason { response.on_disabled_hover_text(app.tr(reason)) } else { response };
            handle("cancel_checkout_confirm", &response);
            if response.clicked() {
                app.pdm.cancel_editor = None;
                app.pdm.cancel_confirmation = false;
                app.pdm.cancel_target = None;
                let mut params = json!({"discard":true});
                if let Some(document) = target.as_ref().and_then(|target| target.document.as_ref()) {
                    params["document"] = json!(document);
                }
                dispatch(app, "pdm.cancel_checkout", params);
            }
            let cancel = ui.button(app.tr("ui.cancel"));
            handle("cancel_checkout_cancel", &cancel);
            if cancel.clicked() {
                app.pdm.cancel_confirmation = false;
                app.pdm.cancel_target = None;
                app.pdm.cancel_editor = None;
            }
        });
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;

    fn preview() -> Preview {
        let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(240, 150, image::Rgba([20, 80, 160, 255])));
        let mut output = std::io::Cursor::new(Vec::new());
        image.write_to(&mut output, image::ImageFormat::Png).unwrap();
        Preview { reference: Reference { document: "part".into(), version: 1 }, sha256: "00".repeat(32), png: output.into_inner() }
    }

    #[test]
    fn utc_times_are_readable_and_bound_input() {
        assert_eq!(utc_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_time(951_782_400_000), "2000-02-29 00:00 UTC");
        assert_eq!(utc_time(4_107_542_400_000), "2100-03-01 00:00 UTC");
        assert_eq!(utc_time(253_402_300_799_999), "9999-12-31 23:59 UTC");
        assert_eq!(utc_time(u64::MAX), "—");
    }

    #[test]
    fn native_preview_cache_reuses_exact_identity_and_clears_stale_images() {
        let ctx = egui::Context::default();
        let mut cache = PreviewCache::default();
        let mut preview = preview();
        cache.update(&ctx, Some(&preview));
        let first = cache.texture.as_ref().unwrap().id();
        assert_eq!(cache.texture.as_ref().unwrap().size(), [240, 150]);
        cache.update(&ctx, Some(&preview));
        assert_eq!(cache.texture.as_ref().unwrap().id(), first);
        preview.reference.version = 2;
        cache.update(&ctx, Some(&preview));
        assert_ne!(cache.texture.as_ref().unwrap().id(), first);
        cache.update(&ctx, None);
        assert!(cache.texture.is_none());
    }

    #[test]
    fn malformed_or_oversized_preview_never_keeps_a_previous_texture() {
        let ctx = egui::Context::default();
        let mut cache = PreviewCache::default();
        let mut preview = preview();
        cache.update(&ctx, Some(&preview));
        preview.reference.version = 2;
        preview.png = vec![0; 24];
        cache.update(&ctx, Some(&preview));
        assert!(cache.texture.is_none());
        let rejected = cache.key.clone();
        cache.update(&ctx, Some(&preview));
        assert_eq!(cache.key, rejected);
        preview.reference.version = 3;
        preview.png = vec![0; 512 * 1024 + 1];
        cache.update(&ctx, Some(&preview));
        assert!(cache.texture.is_none());
    }
    #[test]
    fn synchronous_policy_failure_notice_renders_italian_reason_instead_of_message_id() {
        let mut h = crate::scenario::Harness::new();
        h.app.preferences.language = "it".into();
        h.app.session.path = Some("unmanaged.solidcraft".into());
        h.app.session.mark_saved();
        super::enter(&mut h.app).unwrap();
        super::dispatch(&mut h.app, "pdm.checkout", json!({}));
        h.frames(3);
        let locale = crate::i18n::Locale::for_language("it");
        let message = locale.format(
            "ui.pdm_operation_failed",
            &[("action", locale.text("ui.pdm_checkout")), ("file", "unmanaged.solidcraft"), ("error", locale.text("ui.pdm_reason_disconnected"))],
        );
        assert!(h.widget(&message).is_some(), "{message}");
        assert!(h.widget("ui.pdm_reason_disconnected").is_none());
        assert!(h.app.pdm.notice.as_ref().is_some_and(|notice| notice.error.as_deref() == Some("ui.pdm_reason_disconnected")));
    }

    #[test]
    fn native_preview_cache_bounds_history_and_reuses_loaded_version_after_selection_changes() {
        let ctx = egui::Context::default();
        let mut cache = PreviewCache::default();
        let mut image = preview();
        cache.update(&ctx, Some(&image));
        let first = cache.texture.as_ref().unwrap().id();
        image.reference.version = 2;
        cache.update(&ctx, Some(&image));
        image.reference.version = 1;
        cache.update(&ctx, Some(&image));
        assert_eq!(cache.texture.as_ref().unwrap().id(), first);
        for version in 3..=20 {
            image.reference.version = version;
            cache.update(&ctx, Some(&image));
        }
        assert_eq!(cache.recent.len(), 16);
        assert!(cache.recent.iter().all(|((reference, _), _)| reference.version > 2));
        cache.update(&ctx, None);
        assert!(cache.texture.is_none());
    }
}
