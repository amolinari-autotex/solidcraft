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

#[path = "pdm_admin_panel.rs"]
mod administration;
#[path = "pdm_guided_panel.rs"]
mod guided;
#[path = "pdm_references_panel.rs"]
mod references;
#[path = "pdm_settings_panel.rs"]
mod settings;

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

#[derive(Clone)]
struct NamespaceDialog {
    target: ActionTarget,
    context: BrowserContext,
    head: Option<u64>,
    revision: u64,
    name: String,
    delete: bool,
}

struct Notice {
    action: &'static str,
    file: String,
    path: Option<String>,
    error: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
struct BrowserContext {
    authentication_epoch: u64,
    port: u16,
    connection: Option<solidcraft_engine::pdm::ActiveConnection>,
    server: Option<String>,
    workspace: Option<String>,
}
impl BrowserContext {
    fn current(status: &Status) -> Option<Self> {
        if !status.available {
            return None;
        }
        Some(Self {
            authentication_epoch: status.authentication_epoch,
            port: status.port?,
            connection: status.connection.clone(),
            server: status.managed.server_id.clone(),
            workspace: status.managed.workspace.clone(),
        })
    }
}

pub struct Panel {
    pub guided: guided::GuidedState,
    pub settings: settings::State,
    pub settings_open: bool,
    pub admin_open: bool,
    browser_context: Option<BrowserContext>,
    references: references::State,
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
    namespace_dialog: Option<NamespaceDialog>,
    search: String,
    selected_folder: Option<String>,
    expanded: std::collections::BTreeSet<String>,
    root_expanded: bool,
    tree_width: f32,
    details_height: f32,
    details_visible: bool,
    column_widths: [f32; 7],
    sort_column: usize,
    sort_descending: bool,
    notice: Option<Notice>,
    row_operation: Option<(u64, String)>,
    pending_notice: Option<(u64, &'static str, String, Option<ActionTarget>)>,
    reconcile_target: Option<ActionTarget>,
    preview_requested: std::collections::BTreeSet<(String, u64, String)>,
    history_requested: Option<String>,
    metadata_not_before: f64,
    detail_context: Option<(String, Option<u64>)>,
    pending_detail_context: Option<(u64, String, Option<u64>)>,
    metadata_job: Option<(u64, BrowserContext)>,
    pub recovery_confirmation: bool,
    pub restore_confirmation: Option<Reference>,
    pub pending_edit: Option<String>,
    pub pending_edit_path: Option<String>,
    resume_edit: Option<(String, String)>,
    pub ram_paths: std::collections::BTreeSet<String>,
    preview_cache: PreviewCache,
    reset_ram_on_completion: bool,
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
            settings: settings::State::default(),
            settings_open: false,
            admin_open: false,
            browser_context: None,
            references: references::State::default(),
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
            namespace_dialog: None,
            search: String::new(),
            selected_folder: None,
            expanded: Default::default(),
            root_expanded: true,
            tree_width: 214.0,
            details_height: 238.0,
            details_visible: true,
            column_widths: [240.0, 160.0, 188.0, 160.0, 160.0, 136.0, 180.0],
            sort_column: 0,
            sort_descending: false,
            notice: None,
            pending_notice: None,
            row_operation: None,
            reconcile_target: None,
            preview_requested: Default::default(),
            history_requested: None,
            metadata_not_before: 0.0,
            detail_context: None,
            pending_detail_context: None,
            metadata_job: None,
            recovery_confirmation: false,
            restore_confirmation: None,
            pending_edit: None,
            pending_edit_path: None,
            resume_edit: None,
            ram_paths: Default::default(),
            preview_cache: PreviewCache::default(),
            reset_ram_on_completion: false,
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

fn sync_browser_context(app: &mut SolveApp, status: &Status) {
    let current = BrowserContext::current(status);
    if app.pdm.browser_context == current {
        return;
    }
    app.pdm.browser_context = current;
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
    app.pdm.namespace_dialog = None;
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
    app.pdm.cancel_editor = None;
    app.pdm.discard_ack = None;
    app.pdm.references = references::State::default();
    app.pdm.admin_open = false;
    app.pdm.notice = None;
    settings::invalidate_picker(app);
}

fn failure_text(app: &SolveApp, message: &str) -> String {
    if message.len() <= 2048
        && let Ok(solidcraft_engine::pdm::FileFailure::FileSizeLimit { filename, actual_bytes, limit_bytes }) = serde_json::from_str(message)
    {
        if filename.is_empty() || filename.len() > 1024 || filename.chars().any(|c| c.is_control() || matches!(c, '/' | '\\')) {
            return app.tr("ui.pdm_error_invalid").into();
        }
        return crate::i18n::Locale::for_language(&app.preferences.language).format(
            "ui.pdm_error_file_size_limit",
            &[("file", &filename), ("actual", &actual_bytes.to_string()), ("limit", &limit_bytes.to_string())],
        );
    }
    app.tr(message).into()
}

pub fn tick(app: &mut SolveApp, ctx: &egui::Context) {
    app.session.pdm = app.pdm.runtime.clone();
    let _ = app.pdm.runtime.set_available(app.services.pdm.is_some());
    if let Ok(status) = app.pdm.runtime.status() {
        sync_browser_context(app, &status);
        if !admin_visible(&status) {
            app.pdm.admin_open = false;
        }
    }
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
    // Drop obsolete replies before publishing status/notice or touching any
    // editor. A newer Runtime job may already be queued: remove only this ID's
    // UI intent, leaving its busy token, job and feedback intact.
    if let Some((id, _)) = app.pdm.ready.as_ref()
        && app.pdm.runtime.status().is_ok_and(|status| status.busy != Some(*id))
    {
        let id = *id;
        app.pdm.ready = None;
        if app.pdm.working_open_job == Some(id) {
            app.pdm.working_open_job = None;
        }
        if app.pdm.discard_ack.as_ref().is_some_and(|(request, _)| *request == id) {
            app.pdm.discard_ack = None;
        }
        if app.pdm.pending_notice.as_ref().is_some_and(|(request, _, _, _)| *request == id) {
            app.pdm.pending_notice = None;
        }
        if app.pdm.pending_detail_context.as_ref().is_some_and(|(request, _, _)| *request == id) {
            app.pdm.pending_detail_context = None;
        }
        let _ = references::take_request(app, id);
        app.pdm.pending_open_epoch = None;
        guided::connection_completed(app, id, false);
        ctx.request_repaint();
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
        let refresh_existing_only = app.pdm.pending_notice.as_ref().is_some_and(|(request, action, _, _)| {
            *request == id && matches!(*action, "ui.pdm_checkout" | "ui.pdm_cancel_checkout" | "ui.pdm_get_latest")
        });
        if refresh_existing_only
            && completion.open.as_ref().and_then(|session| session.path.as_deref()).is_some_and(|path| !documents::managed_path_is_open(app, path))
        {
            completion.open = None;
        }
        let archive_completed = app.pdm.pending_notice.as_ref().is_some_and(|(request, action, _, _)| *request == id && *action == "ui.pdm_archive");
        let discard_stamp = app.pdm.discard_ack.take().filter(|(request, _)| *request == id).map(|(_, stamp)| stamp);
        let next_parent = match &completion.result {
            Ok(Outcome::CheckedIn(version)) if app.pdm.document == version.reference.document => Some(version.reference.version),
            _ => None,
        };
        if app.pdm.metadata_job.as_ref().is_some_and(|(request, _)| *request == id)
            && let Some((_, context)) = app.pdm.metadata_job.take()
        {
            match app.pdm.runtime.status() {
                Ok(current) if BrowserContext::current(&current).as_ref() == Some(&context) => {
                    if let Ok(Outcome::Managed { port, state }) = &mut completion.result {
                        if current.port != Some(*port) || current.managed.server_id != state.server_id || current.managed.workspace != state.workspace
                        {
                            completion.result = Err(Failure { message: "Stale file details; select the file again".into(), disconnect: false });
                        } else {
                            // Metadata never replaces the browser inventory or local-file snapshot.
                            let mut cached = current.managed;
                            if app
                                .pdm
                                .pending_detail_context
                                .as_ref()
                                .is_some_and(|(request, document, _)| *request == id && *document == app.pdm.document)
                            {
                                cached.history = std::mem::take(&mut state.history);
                                cached.where_used = std::mem::take(&mut state.where_used);
                                cached.where_used_details = std::mem::take(&mut state.where_used_details);
                                cached.preview = state.preview.take();
                            }
                            *state = cached;
                        }
                    }
                }
                _ => completion.result = Err(Failure { message: "Stale file details; reconnect explicitly".into(), disconnect: false }),
            }
        }
        let reference_request = references::take_request(app, id);
        if let Some(request) = &reference_request {
            request.preserve_details(app, &mut completion.result);
        }
        if reference_request.is_none()
            && let Some((request, document, Some(version))) = app.pdm.pending_detail_context.as_ref()
            && *request == id
            && *document == app.pdm.document
            && !app.pdm.selected.as_ref().is_some_and(|selected| selected.document == *document && selected.version == *version)
            && let Ok(current) = app.pdm.runtime.status()
            && let Ok(Outcome::Managed { state, .. }) = &mut completion.result
        {
            state.where_used = current.managed.where_used;
            state.where_used_details = current.managed.where_used_details;
        }
        let managed = matches!(&completion.result, Ok(Outcome::Managed { .. } | Outcome::ManagedConnected { .. }));
        let success = completion.result.is_ok();
        let guided_authenticated = matches!(&completion.result, Ok(Outcome::ManagedConnected { .. }));
        let completion_error = completion.result.as_ref().err().map(|failure| failure.message.clone());
        let accepted = match app.pdm.runtime.finish(id, completion.result) {
            Ok(()) => true,
            Err(error) => {
                app.set_status(error, true);
                false
            }
        };
        if let Ok(status) = app.pdm.runtime.status() {
            sync_browser_context(app, &status);
        }
        if accepted && let Some(error) = &completion_error {
            app.set_status(failure_text(app, error), true);
        }
        let reference_current = reference_request.as_ref().is_none_or(|request| request.current(app));
        guided::connection_completed(app, id, accepted && guided_authenticated);
        if let Some((request, document, version)) = app.pdm.pending_detail_context.take()
            && request == id
            && accepted
            && success
            && reference_request.is_none()
            && (version.is_none()
                || app.pdm.selected.as_ref().is_some_and(|selected| selected.document == document && Some(selected.version) == version))
        {
            app.pdm.detail_context = Some((document, version));
        }
        if let Some((notice_id, action, file, target)) = app.pdm.pending_notice.take()
            && notice_id == id
        {
            if accepted && success && matches!(action, "ui.pdm_rename" | "ui.pdm_delete") {
                if action == "ui.pdm_delete" && target.as_ref().and_then(|target| target.document.as_deref()) == Some(app.pdm.document.as_str()) {
                    clear_file_selection(app);
                }
                app.pdm.preview_cache = PreviewCache::default();
                app.pdm.preview_requested.clear();
                app.pdm.history_requested = None;
                app.pdm.detail_context = None;
                app.pdm.pending_detail_context = None;
                app.pdm.selected = None;
            }
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
        if accepted && success && managed && app.pdm.reset_ram_on_completion {
            app.pdm.ram_paths.clear();
        }
        if accepted && let Some(parent) = next_parent {
            app.pdm.parent = parent.to_string();
        }
        let mut reference_loaded_path = None;
        if accepted
            && success
            && reference_current
            && let Some(mut session) = completion.open.take()
        {
            let loaded_path = session.path.clone();
            let historical_kind =
                if reference_request.is_some() && !session.pdm_read_only { Err("ui.pdm_reference_open_failed".to_string()) } else { Ok(()) };
            let applied = historical_kind.and_then(|()| {
                app.pdm
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
                    })
            });
            if let Err(error) = applied {
                let message =
                    if reference_request.is_some() { app.tr(&error).to_string() } else { format!("PDM copy was saved but could not open: {error}") };
                if let Some(notice) = app.pdm.notice.as_mut() {
                    notice.error = Some(message.clone());
                }
                app.set_status(message, true);
            } else {
                if reference_request.is_some() {
                    reference_loaded_path = loaded_path.clone();
                }
                if working_open {
                    if let Some(path) = loaded_path {
                        documents::activate_managed_path(app, &path);
                        if let Ok(status) = app.pdm.runtime.status()
                            && let Some(local) = status.managed.local.iter().find(|entry| cached_path_key(&entry.path) == cached_path_key(&path))
                            && let Some(entry) = status.managed.catalog.iter().find(|entry| entry.document == local.document)
                        {
                            app.pdm.document = entry.document.clone();
                            app.pdm.folder = entry.logical_path.rsplit_once('/').map_or("", |(folder, _)| folder).into();
                            app.pdm.selected = None;
                            app.pdm.selected_folder = None;
                            app.pdm.history_requested = None;
                            app.pdm.detail_context = None;
                        }
                    }
                    leave(app);
                    let _ = crate::render_workspace::enter(app, false);
                    app.ui.tab = if app.session.active_sketch.is_some() { "SKETCH".into() } else { "MODEL".into() };
                }
            }
        }
        if let Some(request) = reference_request
            && accepted
            && success
            && reference_current
            && (request.cached() || reference_loaded_path.is_some())
            && let Err(error) = references::complete(app, request, reference_loaded_path.as_deref())
        {
            if let Some(notice) = app.pdm.notice.as_mut() {
                notice.error = Some(error.clone());
            }
            app.set_status(app.tr(&error).to_string(), true);
        }
        if archive_completed && accepted && success {
            let warnings = documents::refresh_linked_assemblies(app);
            if !warnings.is_empty() {
                app.set_status(warnings.join("\n"), true);
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
                let row_document = task_notice(&job.task).and_then(|(_, document, path)| {
                    document.map(str::to_owned).or_else(|| {
                        let status = app.pdm.runtime.status().ok()?;
                        status
                            .managed
                            .local
                            .iter()
                            .find(|entry| path.is_some_and(|path| cached_path_key(path) == cached_path_key(&entry.path)))
                            .map(|entry| entry.document.clone())
                    })
                });
                app.pdm.row_operation = row_document.map(|document| (id, document));
                references::capture_job(app, &job);
                app.pdm.working_open_job =
                    matches!(&job.task, Task::Managed(ManagedTask::Open { .. } | ManagedTask::OpenReferenced { .. })).then_some(id);
                if matches!(&job.task, Task::Managed(ManagedTask::ImportNew { .. })) {
                    app.pdm.detail_context = None;
                    app.pdm.history_requested = None;
                }
                app.pdm.metadata_job = if matches!(&job.task, Task::Managed(ManagedTask::History { .. } | ManagedTask::Preview { .. })) {
                    app.pdm.runtime.status().ok().and_then(|status| BrowserContext::current(&status)).map(|context| (id, context))
                } else {
                    None
                };
                app.pdm.pending_detail_context = match &job.task {
                    Task::Managed(ManagedTask::History { document }) => Some((id, document.clone(), None)),
                    Task::Managed(ManagedTask::Preview { reference }) => Some((id, reference.document.clone(), Some(reference.version))),
                    _ => None,
                };
                if let Some((action, document, path)) = task_notice(&job.task)
                    && !app.pdm.pending_notice.as_ref().is_some_and(|(request, _, _, _)| *request == id)
                {
                    let file = target_label(app, document, path);
                    let target = matches!(action, "ui.pdm_archive" | "ui.pdm_rename" | "ui.pdm_delete").then(|| ActionTarget {
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
                            | ManagedTask::OpenReferenced { .. }
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
    // Refresh explicitly or after an operation; idle polling interrupts the browser.
}

fn handle(name: &str, response: &egui::Response) {
    crate::scenario::publish_handle(&format!("pdm:{name}"), response.rect.center());
}

/// Display archive timestamps in the OS/browser timezone, including historical DST.
fn local_time(milliseconds: u64) -> String {
    use chrono::TimeZone;
    let Some(milliseconds) = i64::try_from(milliseconds).ok().filter(|value| *value <= 253_402_300_799_999) else { return "—".into() };
    let local = std::panic::catch_unwind(|| chrono::Local.timestamp_millis_opt(milliseconds).single()).ok().flatten();
    local.map_or_else(
        || format!("{} ({})", utc_time(milliseconds as u64), crate::i18n::tr("ui.pdm_local_time_unavailable")),
        |time| time.format("%Y-%m-%d %H:%M").to_string(),
    )
}

/// Explicit UTC fallback when local timezone conversion is unavailable.
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
    if let Ok(status) = app.pdm.runtime.status() {
        sync_browser_context(app, &status);
    }
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
    settings::invalidate_picker(app);
    if app.pdm.workspace_active {
        app.pdm.workspace_active = false;
        if let Some(tab) = app.pdm.return_tab.take() {
            app.ui.tab = tab;
        }
    }
}

pub(crate) fn run_historical(app: &mut SolveApp, command: &str, params: &serde_json::Value) -> Option<Result<serde_json::Value, String>> {
    references::run_historical(app, command, params)
}

pub(crate) fn archive_save_failed(app: &mut SolveApp, params: &serde_json::Value, error: String) {
    let file = target_label(app, params.get("document").and_then(serde_json::Value::as_str), app.session.path.as_deref());
    app.pdm.notice = Some(Notice { action: "ui.pdm_archive", file, path: app.session.path.clone(), error: Some(error.clone()) });
    app.set_status(error, true);
}

fn action_key(id: &str) -> &'static str {
    match id {
        "pdm.rename" => "ui.pdm_rename",
        "pdm.delete" => "ui.pdm_delete",
        "pdm.admin.read" => "cmd.pdm_admin_read",
        "pdm.import_new" => "cmd.pdm_import_new",
        "pdm.disconnect" => "ui.pdm_disconnect",
        "pdm.checkout" => "ui.pdm_checkout",
        "pdm.archive" | "pdm.check_in" => "ui.pdm_archive",
        "pdm.cancel_checkout" => "ui.pdm_cancel_checkout",
        "pdm.get_latest" => "ui.pdm_get_latest",
        "pdm.open_document" | "pdm.open_referenced" => "ui.pdm_open_document",
        "pdm.open_archived" | "pdm.retrieve" => "ui.pdm_open_archived",
        "pdm.restore_version" => "ui.pdm_restore_version",
        "pdm.setup.create" => "cmd.pdm_setup_create",
        "pdm.workspace.change" => "cmd.pdm_workspace_change",
        "pdm.recover_workspace" | "pdm.connection.recover" => "ui.pdm_recover_workspace",
        _ => "ui.pdm_connect",
    }
}

/// Only user-visible operations replace the persistent result. Background metadata
/// refreshes, preview requests and inventories never erase the last useful feedback.
fn task_notice(task: &Task) -> Option<(&'static str, Option<&str>, Option<&str>)> {
    let (command, document, path) = match task {
        Task::Managed(task) => match task {
            ManagedTask::Rename { document, .. } => ("pdm.rename", Some(document.as_str()), None),
            ManagedTask::Delete { document, .. } => ("pdm.delete", Some(document.as_str()), None),
            ManagedTask::AdministrationRead => ("pdm.admin.read", None, None),
            ManagedTask::ImportNew { source_path, .. } => ("pdm.import_new", None, Some(source_path.as_str())),
            ManagedTask::CheckoutPreservingMemory { document, path, .. } => ("pdm.checkout", Some(document.as_str()), Some(path.as_str())),
            ManagedTask::Checkout { document, path } => ("pdm.checkout", document.as_deref(), path.as_deref()),
            ManagedTask::CancelCheckout { document, path } => ("pdm.cancel_checkout", document.as_deref(), path.as_deref()),
            ManagedTask::GetLatest { document, path } => ("pdm.get_latest", document.as_deref(), path.as_deref()),
            ManagedTask::Archive { path, .. } | ManagedTask::ReconcileArchive { path, .. } => ("pdm.archive", None, Some(path.as_str())),
            ManagedTask::Open { document } | ManagedTask::OpenReferenced { document } => ("pdm.open_document", Some(document.as_str()), None),
            ManagedTask::OpenArchived { reference } => ("pdm.open_archived", Some(reference.document.as_str()), None),
            ManagedTask::Restore { reference } => ("pdm.restore_version", Some(reference.document.as_str()), None),
            ManagedTask::CreateLocal { label, .. } => ("pdm.setup.create", None, Some(label.as_str())),
            ManagedTask::ChangeWorkspace { path, .. } => ("pdm.workspace.change", None, Some(path.as_str())),
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
    let path = if id == "pdm.import_new" {
        params.get("source_path").and_then(serde_json::Value::as_str).map(str::to_owned)
    } else if id == "pdm.workspace.change" {
        params.get("path").and_then(serde_json::Value::as_str).map(str::to_owned)
    } else {
        app.session.path.clone()
    };
    let file = target_label(app, params.get("document").and_then(serde_json::Value::as_str), path.as_deref());
    if let Err(error) = app.run(id, params) {
        if !matches!(id, "pdm.preview" | "pdm.history" | "pdm.refresh") {
            app.pdm.notice = Some(Notice { action: action_key(id), file, path, error: Some(error.clone()) });
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
    let path = status.attachment_path(document.as_deref()).map(str::to_owned).or(path);
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

fn admin_visible(status: &Status) -> bool {
    use solidcraft_engine::pdm::AdminReadStatus::{Forbidden, Unauthorized};
    status.available
        && status.port.is_some()
        && status.connection.as_ref().is_some_and(|connection| connection.role.eq_ignore_ascii_case("administrator"))
        && status.administration.as_ref().is_none_or(|admin| {
            admin.server_id.as_ref() == status.managed.server_id.as_ref()
                && admin.principal.as_ref().is_some_and(|principal| principal.role == "administrator")
                && !matches!(admin.users_status, Forbidden | Unauthorized)
                && !matches!(admin.audit_status, Forbidden | Unauthorized)
        })
}

pub(crate) fn command_visible(app: &SolveApp, command: &str) -> bool {
    !matches!(command, "pdm.admin" | "pdm.admin.read") || app.pdm.runtime.status().is_ok_and(|status| admin_visible(&status))
}

/// Generic command surfaces share the explorer's exact target and reason.
pub(crate) fn command_unavailable(app: &SolveApp, command: &str) -> Option<&'static str> {
    if matches!(command, "pdm.admin" | "pdm.admin.read") {
        if !command_visible(app, command) {
            return Some("ui.pdm_admin_forbidden");
        }
        let Ok(status) = app.pdm.runtime.status() else { return Some("ui.pdm_reason_unavailable") };
        if app.file_picker_busy() || app.file_load.busy() {
            return Some("ui.pdm_reason_busy");
        }
        return status.action_unavailable(command, None, None, false, false, None);
    }
    if matches!(command, "pdm.settings" | "pdm.workspace.change") {
        let Ok(status) = app.pdm.runtime.status() else { return Some("ui.pdm_reason_unavailable") };
        if status.busy.is_some() || app.file_picker_busy() || app.file_load.busy() {
            return Some("ui.pdm_reason_busy");
        }
        if !status.available {
            return Some("ui.pdm_reason_unavailable");
        }
        if command == "pdm.workspace.change" {
            if documents::any_managed_open(app) {
                return Some("ui.pdm_workspace_close_editors");
            }
            return status.action_unavailable(command, None, None, false, false, None);
        }
        return None;
    }
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
            | "pdm.open_referenced"
            | "pdm.open_archived"
            | "pdm.restore_version"
            | "pdm.rename"
            | "pdm.delete"
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
    if command == "pdm.admin" {
        if let Err(error) = administration::open(app) {
            app.set_status(error, true);
        }
        return true;
    }
    if matches!(command, "pdm.settings" | "pdm.workspace.change") {
        app.pdm.admin_open = false;
        if let Err(error) = settings::open(app) {
            app.set_status(error, true);
        }
        return true;
    }
    if !matches!(
        command,
        "pdm.connect"
            | "pdm.disconnect"
            | "pdm.checkout"
            | "pdm.archive"
            | "pdm.cancel_checkout"
            | "pdm.get_latest"
            | "pdm.open_document"
            | "pdm.open_referenced"
            | "pdm.open_archived"
            | "pdm.restore_version"
            | "pdm.rename"
            | "pdm.delete"
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
        "pdm.rename" | "pdm.delete" => {
            if let Some(context) = BrowserContext::current(&status)
                && let Some(remote) = status.managed.catalog.iter().find(|entry| Some(entry.document.as_str()) == target.document.as_deref())
                && let Some(metadata) = status.managed.namespace.entries.iter().find(|entry| entry.document == remote.document && !entry.tombstoned)
            {
                let name = remote.logical_path.rsplit('/').next().unwrap_or_default().to_owned();
                app.pdm.namespace_dialog =
                    Some(NamespaceDialog { target, context, head: remote.head, revision: metadata.revision, name, delete: command == "pdm.delete" });
            }
        }
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
    let font = egui::TextStyle::Button.resolve(ui.style());
    let opacity = if reason.is_none() { 1.0 } else { 0.4 };
    let color = ui.visuals().text_color().gamma_multiply(opacity);
    let label = ui.painter().layout_no_wrap(app.tr(key).to_owned(), font, color);
    let padding = ui.spacing().button_padding;
    let icon_column = 24.0;
    let gap = 8.0;
    let size = egui::vec2(padding.x * 2.0 + icon_column + gap + label.size().x, (padding.y * 2.0 + label.size().y).max(30.0));
    let response = ui.add_enabled(reason.is_none(), egui::Button::new("").min_size(size));
    let rect = egui::Rect::from_center_size(
        egui::pos2(response.rect.left() + padding.x + icon_column / 2.0, response.rect.center().y),
        egui::vec2(20.0, 20.0),
    );
    let label_rect = egui::Rect::from_min_size(
        egui::pos2(response.rect.left() + padding.x + icon_column + gap, response.rect.center().y - label.size().y / 2.0),
        label.size(),
    );
    crate::icons::paint_icon(ui.painter(), rect, icon, opacity);
    ui.painter().galley(label_rect.min, label, color);
    crate::scenario::publish_rect(&format!("pdm_action_label:{id}"), label_rect);
    handle(name, &response);
    crate::scenario::publish_rect(&format!("pdm_action_button:{id}"), response.rect);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, reason.is_none(), app.tr(key)));
    let clicked = response.clicked();
    let help = reason.map_or_else(|| app.tr(if id == "context:pdm.get_latest" { "ui.pdm_get_latest_hint" } else { key }), |reason| app.tr(reason));
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
    let hint = match id {
        "pdm.get_latest" => app.tr("ui.pdm_get_latest_hint"),
        "pdm.refresh" => app.tr("ui.pdm_refresh_hint"),
        _ => help,
    };
    let help = reason.map_or_else(|| format!("{}\n{hint}", app.tr(key)), |reason| app.tr(reason).to_string());
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
            let connected = status.port.is_some();
            let (id, key, icon, name) = if connected {
                ("pdm.disconnect", "ui.pdm_disconnect", "pdm_disconnect", "disconnect_toolbar")
            } else {
                ("pdm.connect", "ui.pdm_connect", "pdm_connect", "connect_settings")
            };
            if ribbon_button(app, ui, id, key, icon, unavailable(app, &status, id, &target, None), name, &connection) {
                action = Some(id);
            }
            ui.separator();
            for (id, key, icon, name) in [
                ("pdm.open_document", "ui.pdm_open_document", "open", "open_document"),
                ("pdm.checkout", "ui.pdm_checkout", "pdm_checkout", "checkout"),
                ("pdm.archive", "ui.pdm_archive", "pdm_checkin", "archive"),
                ("pdm.cancel_checkout", "ui.pdm_cancel_checkout", "undo", "cancel_checkout"),
            ] {
                if !selected && id == "pdm.open_document" {
                    continue;
                }
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
                [("pdm.get_latest", "ui.pdm_get_latest", "import", "get_latest"), ("pdm.refresh", "ui.pdm_refresh", "update", "refresh")]
            {
                if !selected && id == "pdm.get_latest" {
                    continue;
                }
                if ribbon_button(app, ui, id, key, icon, unavailable(app, &status, id, &target, None), name, &help) {
                    action = Some(id);
                }
            }
            if selected && ribbon_button(app, ui, "pdm.details", "ui.pdm_details", "pdm_details", None, "details", &help) {
                app.pdm.details_visible = !app.pdm.details_visible;
            }
            if selected
                && ribbon_button(app, ui, "pdm.settings", "cmd.pdm_settings", "settings", command_unavailable(app, "pdm.settings"), "settings", "")
            {
                action = Some("pdm.settings");
            }
            if selected
                && admin_visible(&status)
                && ribbon_button(app, ui, "pdm.admin", "cmd.pdm_admin", "settings", command_unavailable(app, "pdm.admin"), "admin", "")
            {
                action = Some("pdm.admin");
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
    if !folder.is_empty() {
        app.pdm.root_expanded = true;
    }
    let parts: Vec<_> = folder.split('/').filter(|part| !part.is_empty()).collect();
    for n in 1..=parts.len() {
        app.pdm.expanded.insert(parts[..n].join("/"));
    }
    app.pdm.selected_folder = Some(folder.clone());
    app.pdm.folder = folder;
    app.pdm.search.clear();
}

fn folder_tree_row(ui: &mut egui::Ui, folder: &str, label: &str, depth: usize, selected: bool, branch: Option<bool>, width: f32) -> (bool, bool) {
    let t = Tokens::get();
    let color = if selected { ui.visuals().selection.stroke.color } else { t.text };
    let text = ui.painter().layout_no_wrap(label.to_string(), egui::TextStyle::Body.resolve(ui.style()), color);
    let indent = depth as f32 * 15.0;
    let row_width = width.max(indent + 18.0 + 19.0 + 6.0 + text.size().x + 4.0);
    let (row, _) = ui.allocate_exact_size(egui::vec2(row_width, ui.spacing().interact_size.y.max(text.size().y + 6.0)), egui::Sense::hover());
    // Every row reserves the same expander slot, including leaves. Font metrics,
    // button padding and item spacing therefore cannot shift sibling folders.
    let expander = egui::Rect::from_min_size(row.min + egui::vec2(indent, 0.0), egui::vec2(18.0, row.height()));
    let body = egui::Rect::from_min_max(egui::pos2(expander.right(), row.top()), row.max);
    let response = ui.interact(body, ui.id().with(("pdm_tree_folder", folder)), egui::Sense::click());
    if selected || ui.rect_contains_pointer(row) {
        ui.painter().rect_filled(row, 2.0, if selected { ui.visuals().selection.bg_fill } else { t.hover });
    }
    let mut toggled = false;
    if let Some(open) = branch {
        let toggle = ui.interact(expander, ui.id().with(("pdm_tree_expander", folder)), egui::Sense::click());
        ui.painter().text(
            expander.center(),
            egui::Align2::CENTER_CENTER,
            if open { "▾" } else { "▸" },
            egui::TextStyle::Body.resolve(ui.style()),
            color,
        );
        handle(&format!("folder_expand:{folder}"), &toggle);
        toggled = toggle.clicked();
    }
    let icon = egui::Rect::from_center_size(egui::pos2(body.left() + 9.5, row.center().y), egui::vec2(19.0, 19.0));
    let label_rect = egui::Rect::from_min_size(egui::pos2(icon.right() + 6.0, row.center().y - text.size().y * 0.5), text.size());
    folder_icon(ui, icon, "folder");
    ui.painter().galley(label_rect.min, text, color);
    handle(&format!("folder:{folder}"), &response);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
    for (name, rect) in [("row", row), ("icon", icon), ("label", label_rect), ("expander", expander)] {
        crate::scenario::publish_rect(&format!("pdm_tree_{name}:{folder}"), rect);
    }
    (response.clicked(), toggled)
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
    let width = ui.available_width();
    egui::ScrollArea::both().id_salt("pdm_folder_tree").auto_shrink([false, false]).show(ui, |ui| {
        // A leading slash cannot be a logical folder path. Keep the archive
        // root's widget and scenario identities separate from a folder "root".
        let (clicked, toggled) = folder_tree_row(
            ui,
            "/",
            app.tr("ui.pdm_title"),
            0,
            app.pdm.folder.is_empty(),
            (!folders.is_empty()).then_some(app.pdm.root_expanded),
            width,
        );
        if toggled {
            app.pdm.root_expanded = !app.pdm.root_expanded;
        }
        if clicked {
            navigate_folder(app, String::new());
        }
        if !app.pdm.root_expanded {
            return;
        }
        for folder in &folders {
            let parts: Vec<_> = folder.split('/').collect();
            let ancestors: Vec<_> = (1..parts.len()).map(|n| parts[..n].join("/")).collect();
            if ancestors.iter().any(|parent| !app.pdm.expanded.contains(parent)) {
                continue;
            }
            let has_children = folders.iter().any(|child| child.rsplit_once('/').is_some_and(|(parent, _)| parent == folder));
            let open = app.pdm.expanded.contains(folder);
            let (clicked, toggled) = folder_tree_row(
                ui,
                folder,
                parts.last().copied().unwrap_or(folder),
                parts.len(),
                app.pdm.folder == *folder,
                has_children.then_some(open),
                width,
            );
            if toggled {
                if open {
                    app.pdm.expanded.remove(folder);
                } else {
                    app.pdm.expanded.insert(folder.clone());
                }
            }
            if clicked {
                navigate_folder(app, folder.clone());
            }
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

fn repository_state_label(app: &SolveApp, status: &Status, entry: &CatalogEntry, dirty: bool) -> String {
    if !status.available || status.port.is_none() {
        return app.tr("ui.pdm_state_disconnected").into();
    }
    if app.pdm.row_operation.as_ref().is_some_and(|(request, document)| status.busy == Some(*request) && *document == entry.document) {
        return app.tr("ui.pdm_state_busy").into();
    }
    let local = status.managed.local.iter().find(|local| local.document == entry.document);
    let mut labels = Vec::new();
    if let Some(checkout) = &entry.checkout {
        let mine = status.connection.as_ref().is_some_and(|connection| connection.account == checkout.owner);
        labels.push(app.tr(if mine { "ui.pdm_state_checked_out_me" } else { "ui.pdm_state_checked_out_someone_else" }));
    }
    let modified = dirty || local.is_some_and(|local| local.present && local.modified);
    if modified {
        labels.push(app.tr("ui.pdm_state_modified"));
    }
    if let Some(local) = local.filter(|local| local.present) {
        let version = match entry.head.filter(|head| *head > 0).zip((local.base_version > 0).then_some(local.base_version)) {
            Some((head, base)) if head > base => Some("ui.pdm_state_server_newer"),
            Some((head, base)) if head < base => Some("ui.pdm_state_local_newer"),
            Some(_) if status.managed.dependency_updates.contains(&entry.document) => Some("ui.pdm_state_outdated"),
            Some(_) if !modified => Some("ui.pdm_state_up_to_date"),
            Some(_) => None,
            None => Some("ui.pdm_state_version_unknown"),
        };
        if let Some(key) = version {
            labels.push(app.tr(key));
        }
    } else {
        labels.push(app.tr("ui.pdm_state_not_local"));
    }
    labels.join(" · ")
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
            2 => repository_state_label(app, status, a, documents::managed_target_dirty(app, Some(&a.document))).cmp(&repository_state_label(
                app,
                status,
                b,
                documents::managed_target_dirty(app, Some(&b.document)),
            )),
            3 => a.checkout.as_ref().map(|v| &v.owner).cmp(&b.checkout.as_ref().map(|v| &v.owner)),
            4 => a.head_author.cmp(&b.head_author),
            5 => a.head.cmp(&b.head),
            6 => a.head_checked_in_unix_ms.cmp(&b.head_checked_in_unix_ms),
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
        for (column, key) in [
            "ui.pdm_file",
            "ui.pdm_description",
            "ui.pdm_repository_status",
            "ui.pdm_checked_out_by",
            "ui.pdm_checked_in_by",
            "ui.pdm_local_server",
            "ui.pdm_checked_in",
        ]
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
            let color = if dirty
                || local.is_none_or(|local| !local.present || local.modified || Some(local.base_version) != entry.head)
                || entry.checkout.is_some()
                || status.managed.dependency_updates.contains(document)
            {
                t.warning
            } else {
                t.text
            };
            let values = [
                entry.logical_path.rsplit('/').next().unwrap_or(&entry.logical_path).to_string(),
                "—".to_string(),
                format!("●  {}", repository_state_label(app, status, entry, dirty)),
                entry.checkout.as_ref().map_or_else(|| "—".into(), |lock| format!("{} · {}", lock.owner, lock.machine)),
                entry.head_author.clone().unwrap_or_else(|| "—".into()),
                format!(
                    "{} / {}",
                    local.filter(|local| local.present).map_or_else(|| "—".into(), |local| format!("v{}", local.base_version)),
                    entry.head.map_or_else(|| "—".into(), |head| format!("v{head}"))
                ),
                entry.head_checked_in_unix_ms.map_or_else(|| "—".into(), local_time),
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
        ("pdm.archive", "ui.pdm_archive", "pdm_checkin", "context_archive"),
        ("pdm.get_latest", "ui.pdm_load", "import", "context_load"),
        ("pdm.checkout", "ui.pdm_checkout", "pdm_checkout", "context_checkout"),
        ("pdm.cancel_checkout", "ui.pdm_cancel_checkout", "undo", "context_cancel_checkout"),
    ] {
        let reason = unavailable(app, status, id, &target, None);
        if action_button(app, ui, &format!("context:{id}"), key, icon, reason, name) {
            start_target_action(app, id, target.clone(), None);
            ui.close();
        }
    }
    ui.separator();
    for (command, key, icon, name) in
        [("pdm.rename", "ui.pdm_rename", "rename", "context_rename"), ("pdm.delete", "ui.pdm_delete", "delete", "context_delete")]
    {
        let reason = unavailable(app, status, command, &target, None);
        if action_button(app, ui, &format!("context:{command}"), key, icon, reason, name) {
            start_target_action(app, command, target.clone(), None);
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

fn detail_context_matches(app: &SolveApp, _status: &Status) -> bool {
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
    let button_width = ["ui.pdm_restore_version"]
        .into_iter()
        .map(|key| ui.painter().layout_no_wrap(app.tr(key).to_owned(), font.clone(), t.text).size().x + 32.0 + ui.spacing().button_padding.x * 2.0)
        .sum::<f32>()
        + ui.spacing().item_spacing.x;
    let action_height = if compact && button_width + 12.0 <= bounds.width() { 34.0 } else { 42.0 };
    let actions_rect = egui::Rect::from_min_max(egui::pos2(bounds.left(), (bounds.bottom() - action_height).max(bounds.top())), bounds.max);
    crate::scenario::publish_rect("pdm_detail_actions", actions_rect);
    ui.horizontal(|ui| {
        for (index, key) in ["ui.pdm_versions", "ui.pdm_uses", "ui.pdm_where_used", "ui.pdm_preview"].iter().enumerate() {
            let label = app.tr(key).to_string();
            let response = ui.selectable_value(&mut app.pdm.detail_tab, index, label);
            handle(&format!("detail_tab:{}", ["history", "uses", "where_used", "preview"][index]), &response);
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
                let history_width = ui.available_width();
                egui::Grid::new("pdm_history_table").striped(true).min_col_width(76.0).spacing(egui::vec2(18.0, 8.0)).show(ui, |ui| {
                    for key in
                        ["ui.pdm_preview", "ui.pdm_server_version", "ui.pdm_local_status", "ui.pdm_author", "ui.pdm_checked_in", "ui.pdm_description"]
                    {
                        ui.strong(app.tr(key));
                    }
                    ui.end_row();
                    for version in versions.iter().filter(|version| version.reference.document == app.pdm.document) {
                        let reference = &version.reference;
                        let selected = app.pdm.selected.as_ref() == Some(reference);
                        let background = ui.painter().add(egui::Shape::Noop);
                        let mut row = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(history_width, 0.0));
                        let mut cell_rect = |column, rect: egui::Rect| {
                            row = row.union(rect);
                            crate::scenario::publish_rect(&format!("pdm_history_cell:{}:{}:{column}", reference.document, reference.version), rect);
                        };
                        let thumbnail = if let Some((_, texture)) =
                            app.pdm.preview_cache.recent.iter().find(|((cached, sha), _)| cached == reference && sha == &version.sha256)
                        {
                            ui.add(egui::Image::new((texture.id(), texture.size_vec2())).fit_to_exact_size(egui::vec2(64.0, 40.0)))
                        } else {
                            ui.label(egui::RichText::new("—").color(t.text_dim)).on_hover_text(app.tr("ui.pdm_preview_unavailable"))
                        };
                        cell_rect(0, thumbnail.rect);
                        crate::scenario::publish_rect(&format!("pdm_history_thumbnail:{}:{}", reference.document, reference.version), thumbnail.rect);
                        let response = ui.selectable_label(selected, format!("v{}", reference.version));
                        cell_rect(1, response.rect);
                        handle(&format!("version:{}:{}", reference.document, reference.version), &response);
                        crate::scenario::publish_rect(&format!("pdm_history_version:{}:{}", reference.document, reference.version), response.rect);
                        let copy = status
                            .managed
                            .local
                            .iter()
                            .find(|local| local.document == reference.document && local.present && local.base_version == reference.version);
                        cell_rect(2, ui.label(app.tr(if copy.is_some() { "ui.pdm_current" } else { "ui.pdm_absent" })).rect);
                        let metadata = status.managed.history.iter().find(|item| item.version.reference == *reference);
                        cell_rect(3, ui.label(metadata.map_or("—", |item| item.author.as_str())).rect);
                        cell_rect(4, ui.label(metadata.map_or_else(|| "—".into(), |item| local_time(item.checked_in_unix_ms))).rect);
                        cell_rect(5, ui.label(metadata.map_or("—", |item| item.comment.as_str())).rect);
                        let hit = row.intersect(ui.clip_rect());
                        if hit.is_positive() {
                            let row_response =
                                ui.interact(hit, ui.id().with(("pdm_history_row", &reference.document, reference.version)), egui::Sense::click());
                            if selected || row_response.hovered() {
                                ui.painter().set(background, egui::Shape::rect_filled(row, 0.0, if selected { t.accent_soft } else { t.hover }));
                            }
                            row_response.widget_info(|| {
                                egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, selected, format!("v{}", reference.version))
                            });
                            crate::scenario::publish_rect(&format!("pdm_history_row_hit:{}:{}", reference.document, reference.version), hit);
                            if response.clicked() || row_response.clicked() {
                                app.pdm.selected = Some(reference.clone());
                                if status.busy.is_none() {
                                    action = Some(("pdm.preview", json!({"document":reference.document,"version":reference.version})));
                                }
                            }
                        }
                        crate::scenario::publish_rect(&format!("pdm_history_row:{}:{}", reference.document, reference.version), row);
                        ui.end_row();
                    }
                });
            }
            1 => {
                let context = references::context_reference(app, status);
                if let Some(reference) = &context {
                    let key = if app.pdm.selected.as_ref() == Some(reference) {
                        "ui.pdm_reference_version_context"
                    } else {
                        "ui.pdm_reference_file_context"
                    };
                    ui.label(format!("{}: {}", app.tr(key), reference_label(reference, &status.managed.catalog)));
                }
                if let Some(version) = versions.iter().find(|version| context.as_ref() == Some(&version.reference)) {
                    references::rows(app, ui, status, references::Section::Uses, &version.dependencies);
                } else {
                    references::missing_metadata(app, ui, status);
                }
            }
            2 => {
                if detail_context_matches(app, status) {
                    if let Some(reference) = app.pdm.selected.as_ref().filter(|reference| reference.document == app.pdm.document) {
                        ui.label(format!("{}: {}", app.tr("ui.pdm_reference_version_context"), reference_label(reference, &status.managed.catalog)));
                    } else {
                        let name = status
                            .managed
                            .catalog
                            .iter()
                            .find(|entry| entry.document == app.pdm.document)
                            .map_or(app.pdm.document.as_str(), |entry| entry.logical_path.as_str());
                        ui.label(format!("{}: {name}", app.tr("ui.pdm_reference_file_context")));
                    }
                    references::rows(app, ui, status, references::Section::WhereUsed, &status.managed.where_used);
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
                let selected = references::context_reference(app, status);
                let texture = selected.as_ref().and_then(|reference| {
                    app.pdm.preview_cache.recent.iter().find(|((cached, _), _)| cached == reference).map(|(_, texture)| texture)
                });
                if let Some(texture) = texture {
                    let response = ui.add(egui::Image::new((texture.id(), texture.size_vec2())).max_size(egui::vec2(ui.available_width(), height)));
                    handle("preview_image", &response);
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
            let reason = unavailable(app, status, "pdm.restore_version", &target, reference.as_ref().map(|reference| reference.version));
            if action_button(app, ui, "pdm.restore_version", "ui.pdm_restore_version", "restore", reason, "restore_version") {
                app.pdm.restore_confirmation = reference;
            }
        });
    });
    ui.advance_cursor_after_rect(bounds);
    action
}

fn metadata_loading(app: &SolveApp, status: &Status) -> bool {
    app.pdm.metadata_job.as_ref().is_some_and(|(request, _)| status.busy == Some(*request))
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
            if (status.busy.is_some() && !metadata_loading(app, status)) || app.saving.is_some() {
                ui.spinner();
                ui.label(app.tr(if app.saving.is_some() { "ui.pdm_saving" } else { "ui.pdm_busy" }));
            }
        });
    });
    if let Some(notice) = &app.pdm.notice {
        let action = app.tr(notice.action);
        let key = if notice.error.is_some() { "ui.pdm_operation_failed" } else { "ui.pdm_operation_succeeded" };
        let error = notice.error.as_deref().map(|error| failure_text(app, error)).unwrap_or_default();
        let message = crate::i18n::format(key, &[("action", action), ("file", &notice.file), ("error", &error)]);
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
        let message = failure_text(app, error);
        ui.add(egui::Label::new(egui::RichText::new(&message).color(t.error)).truncate()).on_hover_text(message);
    }
}

/// Consume browser drops before the ordinary design open/insert fallback.
/// Native authority owns copying, exclusive creation and publication.
pub(crate) fn drop_path(app: &mut SolveApp, path: &str) -> bool {
    if !app.pdm.workspace_active {
        return false;
    }
    let status = match app.pdm.runtime.status() {
        Ok(status) => status,
        Err(error) => {
            app.set_status(error, true);
            return true;
        }
    };
    let reason = if app.pdm.settings_open || app.pdm.admin_open || app.file_picker_busy() || app.file_load.busy() {
        Some("ui.pdm_reason_busy")
    } else {
        status.action_unavailable("pdm.import_new", None, None, false, false, None)
    };
    if let Some(reason) = reason {
        let file = target_label(app, None, Some(path));
        app.pdm.notice = Some(Notice { action: "cmd.pdm_import_new", file, path: Some(path.into()), error: Some(reason.into()) });
        app.set_status(app.tr(reason).to_string(), true);
        return true;
    }
    dispatch(app, "pdm.import_new", json!({"source_path":path,"folder":app.pdm.folder,"expected_workspace":status.managed.workspace}));
    true
}

pub fn workspace(app: &mut SolveApp, ui: &mut egui::Ui) {
    if app.pdm.admin_open {
        administration::show(app, ui);
        return;
    }
    if app.pdm.settings_open {
        settings::show(app, ui);
        return;
    }
    let Ok(mut status) = app.pdm.runtime.status() else {
        return;
    };
    if status.port.is_none() || !status.available {
        status.managed.catalog.clear();
        status.managed.history.clear();
        status.managed.where_used.clear();
        status.managed.where_used_details.clear();
        status.managed.preview = None;
        status.versions.clear();
    }
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
                        egui::RichText::new(repository_state_label(app, &status, entry, documents::managed_target_dirty(app, Some(&entry.document))))
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
                    match clicked {
                        CatalogClick::File(document, open) => {
                            if app.pdm.document != document || app.pdm.selected_folder.is_some() {
                                clear_file_selection(app);
                                app.pdm.selected_folder = None;
                                app.pdm.document = document;
                                // Let a physical second click request the working copy first.
                                let delay = ui.ctx().options(|options| options.input_options.max_double_click_delay);
                                app.pdm.metadata_not_before = ui.input(|input| input.time) + delay;
                                ui.ctx().request_repaint_after(std::time::Duration::from_secs_f64(delay));
                            }
                            if open {
                                start_action(app, "pdm.open_document");
                            }
                        }
                        CatalogClick::Folder(folder, enter) => {
                            clear_file_selection(app);
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
            && app.pdm.namespace_dialog.is_none()
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
            action = Some(if app.pdm.detail_tab == 2 {
                app.pdm.selected.as_ref().filter(|reference| reference.document == app.pdm.document).map_or_else(
                    || ("pdm.history", json!({"document":app.pdm.document})),
                    |reference| ("pdm.preview", json!({"document":reference.document,"version":reference.version})),
                )
            } else {
                ("pdm.history", json!({"document":app.pdm.document}))
            });
        }
        if action.is_none()
            && metadata_idle
            && status.busy.is_none()
            && status.port.is_some()
            && status.available
            && status.error.is_none()
            && app.pdm.detail_tab == 2
            && !app.pdm.document.is_empty()
            && !detail_context_matches(app, &status)
        {
            action = Some(if let Some(reference) = app.pdm.selected.as_ref().filter(|reference| reference.document == app.pdm.document) {
                ("pdm.preview", json!({"document":reference.document,"version":reference.version}))
            } else {
                ("pdm.history", json!({"document":app.pdm.document}))
            });
        }
        if action.is_none()
            && metadata_idle
            && status.busy.is_none()
            && app.pdm.details_visible
            && app.pdm.detail_tab == 3
            && let Some(reference) = references::context_reference(app, &status)
            && status.action_unavailable("pdm.preview", Some(&reference.document), None, false, false, Some(reference.version)).is_none()
            && !app.pdm.preview_cache.recent.iter().any(|((cached, _), _)| cached == &reference)
        {
            let sha = status
                .managed
                .history
                .iter()
                .map(|item| &item.version)
                .chain(status.versions.iter())
                .find(|version| version.reference == reference)
                .map_or_else(String::new, |version| version.sha256.clone());
            if app.pdm.preview_requested.len() >= 256 {
                app.pdm.preview_requested.clear();
            }
            if app.pdm.preview_requested.insert((reference.document.clone(), reference.version, sha)) {
                action = Some(("pdm.preview", json!({"document":reference.document,"version":reference.version})));
            }
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

fn namespace_dialog_reason(status: &Status, dialog: &NamespaceDialog) -> Option<&'static str> {
    if BrowserContext::current(status).as_ref() != Some(&dialog.context)
        || !status.managed.catalog.iter().any(|entry| Some(entry.document.as_str()) == dialog.target.document.as_deref() && entry.head == dialog.head)
        || !status
            .managed
            .namespace
            .entries
            .iter()
            .any(|entry| Some(entry.document.as_str()) == dialog.target.document.as_deref() && entry.revision == dialog.revision && !entry.tombstoned)
    {
        return Some("ui.pdm_namespace_stale");
    }
    status.action_unavailable(if dialog.delete { "pdm.delete" } else { "pdm.rename" }, dialog.target.document.as_deref(), None, false, false, None)
}

fn namespace_logical_path(dialog: &NamespaceDialog) -> Option<String> {
    if dialog.name.contains(['/', '\\']) {
        return None;
    }
    let path = dialog.target.label.rsplit_once('/').map_or_else(|| dialog.name.clone(), |(parent, _)| format!("{parent}/{}", dialog.name));
    solidcraft_engine::pdm::valid_namespace_path(&path).then_some(path)
}

fn show_namespace_dialog(app: &mut SolveApp, ctx: &egui::Context) {
    let Some(mut dialog) = app.pdm.namespace_dialog.clone() else { return };
    let mut close = false;
    let mut submit = false;
    egui::Modal::new(egui::Id::new("pdm_namespace_confirmation")).show(ctx, |ui| {
        ui.heading(app.tr(if dialog.delete { "ui.pdm_delete" } else { "ui.pdm_rename" }));
        ui.label(&dialog.target.label);
        ui.label(app.tr(if dialog.delete { "ui.pdm_delete_warning" } else { "ui.pdm_rename_warning" }));
        if !dialog.delete {
            ui.label(app.tr("ui.pdm_namespace_name"));
            let response = ui.text_edit_singleline(&mut dialog.name);
            handle("namespace_name", &response);
        }
        let status = app.pdm.runtime.status().ok();
        let reason = status
            .as_ref()
            .map_or(Some("ui.pdm_namespace_stale"), |status| namespace_dialog_reason(status, &dialog))
            .or_else(|| (!dialog.delete && namespace_logical_path(&dialog).is_none()).then_some("ui.pdm_namespace_invalid_name"));
        if let Some(reason) = reason {
            ui.label(app.tr(reason));
        }
        ui.horizontal(|ui| {
            let response = ui.add_enabled(
                reason.is_none(),
                egui::Button::new(app.tr(if dialog.delete { "ui.pdm_delete_confirm" } else { "ui.pdm_rename_confirm" })),
            );
            handle("namespace_confirm", &response);
            submit = response.clicked();
            let response = ui.button(app.tr("ui.cancel"));
            handle("namespace_cancel", &response);
            close = response.clicked();
        });
    });
    app.pdm.namespace_dialog = if close || submit { None } else { Some(dialog.clone()) };
    if submit {
        let mut params = json!({"document":dialog.target.document,"expected_head":dialog.head,"expected_revision":dialog.revision,"expected_epoch":dialog.context.authentication_epoch});
        if dialog.delete {
            params["confirm"] = json!(true);
            dispatch(app, "pdm.delete", params);
        } else if let Some(path) = namespace_logical_path(&dialog) {
            params["logical_path"] = json!(path);
            dispatch(app, "pdm.rename", params);
        }
    }
}

pub fn show(app: &mut SolveApp, ctx: &egui::Context) {
    guided::connection_window(app, ctx);
    show_namespace_dialog(app, ctx);
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
            let cancel = ui.button(app.tr("ui.cancel"));
            handle("recover_workspace_cancel", &cancel);
            if cancel.clicked() {
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
    fn user_preview_defaults_to_current_file_head_and_keeps_an_explicit_pin() {
        use crate::pdm_panel_tests::{complete_explorer, reference_interaction_fixture};
        let (mut h, requests, held, mut state) = reference_interaction_fixture();
        h.app.pdm.detail_tab = 3;
        assert!(h.app.pdm.selected.is_none());
        h.frames(3);
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "opening Preview directly must request the current file head without first selecting a history row"
        );
        assert!(
            matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Preview {reference}) if reference.document == "part" && reference.version == 2)
        );
        let mut image = preview();
        image.reference = Reference { document: "part".into(), version: 2 };
        state.preview = Some(image);
        complete_explorer(&mut h, &held, Ok(Outcome::Managed { port: 48231, state: state.clone() }));
        assert!(h.app.pdm.selected.is_none(), "default preview must not create an explicit historical pin");
        assert!(crate::scenario::handle_at("pdm:preview_image").is_some(), "actual decoded native image is rendered for the default head");
        assert_eq!(requests.lock().unwrap().len(), 1, "a decoded preview must be reused without repeated requests");
        requests.lock().unwrap().clear();
        h.app.pdm.selected = Some(Reference { document: "part".into(), version: 1 });
        h.frames(3);
        assert!(
            matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Preview {reference}) if reference.document == "part" && reference.version == 1)
        );
        assert!(crate::scenario::handle_at("pdm:preview_image").is_none(), "never show head image under an uncached historical pin");
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

#[cfg(test)]
mod disconnect_regressions {
    use super::*;
    use crate::pdm_panel_tests::{complete_explorer, dirty_archive_fixture, explorer, version};

    #[test]
    fn disconnect_explorer_hides_server_rows_and_clears_detail_targets_without_touching_dirty_local_design() {
        use solidcraft_engine::pdm::{ManagedVersion, Preview};
        for transport_loss in [false, true] {
            let (mut h, requests, held, path) = dirty_archive_fixture();
            let mut state = h.app.pdm.runtime.status().unwrap().managed;
            let reference = Reference { document: "part".into(), version: 1 };
            state.history = vec![ManagedVersion {
                version: version(),
                author: "tester".into(),
                checked_in_unix_ms: 0,
                comment: "Private disconnected history".into(),
                request_id: "disconnect-history".into(),
            }];
            state.where_used = vec![Reference { document: "private-parent".into(), version: 2 }];
            let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(240, 150, image::Rgba([20, 80, 120, 255])));
            let mut png = std::io::Cursor::new(Vec::new());
            image.write_to(&mut png, image::ImageFormat::Png).unwrap();
            state.preview = Some(Preview { reference: reference.clone(), sha256: "00".repeat(32), png: png.into_inner() });
            let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: "part".into() })).unwrap();
            h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state })).unwrap();
            h.app.pdm.document = "part".into();
            h.app.pdm.selected = Some(reference.clone());
            h.app.pdm.search = "part".into();
            h.app.pdm.history_requested = Some("part".into());
            h.app.pdm.detail_context = Some(("part".into(), Some(1)));
            h.frames(3);
            assert!(crate::scenario::handle_at("pdm:file:part").is_some());
            assert!(crate::scenario::handle_at("pdm:version:part:1").is_some());
            assert!(h.app.pdm.preview_cache.texture.is_some(), "precondition: a real preview is decoded before disconnect");
            let document = h.app.session.doc.clone();
            let bytes = std::fs::read(&path).unwrap();
            h.app.run(if transport_loss { "pdm.refresh" } else { "pdm.disconnect" }, json!({})).unwrap();
            h.frames(2);
            h.app.pdm.restore_confirmation = Some(reference);
            complete_explorer(
                &mut h,
                &held,
                if transport_loss { Err(Failure { message: "Authentication revoked".into(), disconnect: true }) } else { Ok(Outcome::Disconnected) },
            );
            assert!(crate::scenario::handles("pdm:file:").is_empty(), "disconnected server files must disappear, not remain clickable offline");
            assert!(crate::scenario::handles("pdm:version:").is_empty());
            assert!(crate::scenario::handle_at("pdm:folder:Projects").is_none());
            assert!(h.app.pdm.document.is_empty() && h.app.pdm.selected.is_none());
            assert!(h.app.pdm.folder.is_empty() && h.app.pdm.search.is_empty());
            assert!(h.app.pdm.restore_confirmation.is_none() && !h.app.pdm.cancel_confirmation);
            assert!(h.app.pdm.history_requested.is_none() && h.app.pdm.detail_context.is_none() && h.app.pdm.pending_detail_context.is_none());
            assert!(h.app.pdm.preview_cache.texture.is_none() && h.app.pdm.preview_cache.recent.is_empty());
            assert_eq!(*h.app.session.doc, *document);
            assert!(h.app.session.is_dirty());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(h.app.pdm.runtime.may_save(path.to_str().unwrap()).is_ok(), "disconnect does not discard a legitimate local checkout");
            for command in [
                "pdm.open_document",
                "pdm.open_archived",
                "pdm.checkout",
                "pdm.archive",
                "pdm.cancel_checkout",
                "pdm.get_latest",
                "pdm.restore_version",
            ] {
                assert!(crate::pdm_panel::command_unavailable(&h.app, command).is_some(), "disconnected action {command}");
                let params = match command {
                    "pdm.open_archived" => json!({"document":"part","version":1}),
                    "pdm.restore_version" => json!({"document":"part","version":1,"restore":true}),
                    "pdm.cancel_checkout" => json!({"document":"part","discard":true}),
                    _ => json!({"document":"part"}),
                };
                assert!(h.app.run(command, params).is_err());
            }
            h.frames(3);
            assert_eq!(requests.lock().unwrap().len(), 1, "no metadata/action request may follow disconnect");
        }
    }

    #[test]
    fn disconnect_late_open_from_previous_account_cannot_replace_editor_or_repopulate_new_account_catalog() {
        let (mut h, requests, held) = explorer(false);
        h.app.run("pdm.open_document", json!({"document":"other"})).unwrap();
        h.frames(2);
        assert_eq!(requests.lock().unwrap().len(), 1);
        let old_id = h.app.pdm.runtime.status().unwrap().busy.unwrap();
        let old_status = h.app.pdm.runtime.status().unwrap();
        // Simulate the connection being invalidated while native loading is still
        // held, then establish a different authenticated principal on the same host.
        h.app.pdm.runtime.finish(old_id, Err(Failure { message: "Account A disconnected".into(), disconnect: true })).unwrap();
        let connect = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
        let mut connection = old_status.connection.clone().unwrap();
        connection.account = "new-viewer".into();
        connection.role = "Viewer".into();
        let mut state = old_status.managed.clone();
        state.catalog.clear();
        state.local.clear();
        state.history.clear();
        state.where_used.clear();
        state.preview = None;
        h.app.pdm.runtime.finish(connect, Ok(Outcome::ManagedConnected { port: 48231, state, connections: vec![], connection })).unwrap();
        let document = h.app.session.doc.clone();
        let active = h.app.docs.active;
        let count = h.app.docs.count();
        let mut loaded = Session::default();
        loaded.path = Some("Working/other.solidcraft".into());
        loaded.doc_mut().name = "STALE PRIVATE ACCOUNT A".into();
        loaded.mark_saved();
        held.lock()
            .unwrap()
            .remove(0)
            .send(Completion { result: Ok(Outcome::Managed { port: 48231, state: old_status.managed }), open: Some(Box::new(loaded)) })
            .unwrap();
        h.frames(4);
        assert_eq!(h.app.pdm.runtime.status().unwrap().connection.unwrap().account, "new-viewer");
        assert!(h.app.pdm.runtime.status().unwrap().managed.catalog.is_empty());
        assert_eq!(*h.app.session.doc, *document);
        assert_eq!(h.app.docs.active, active);
        assert_eq!(h.app.docs.count(), count);
        assert!(h.app.pdm.notice.is_none(), "a rejected old-account result must not publish its captured file/path as a new-account notice");
        assert!(h.app.pdm.workspace_active, "a stale open must not switch into Design");
        assert!(crate::scenario::handles("pdm:file:").is_empty());
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn disconnect_same_host_new_principal_or_connection_clears_browser_identity_and_cached_details() {
        for change_account in [false, true] {
            let (mut h, _requests, held, _) = dirty_archive_fixture();
            let status = h.app.pdm.runtime.status().unwrap();
            h.app.pdm.document = "part".into();
            h.app.pdm.selected = Some(Reference { document: "part".into(), version: 1 });
            h.app.pdm.search = "private filter".into();
            h.app.pdm.detail_context = Some(("part".into(), Some(1)));
            h.app.pdm.preview_requested.insert(("part".into(), 1, "00".repeat(32)));
            h.app.run("pdm.refresh", json!({})).unwrap();
            h.frames(2);
            let mut connection = status.connection.unwrap();
            if change_account {
                connection.account = "new-account".into();
            } else {
                connection.id = "b".repeat(64);
            }
            let mut state = status.managed;
            state.local.iter_mut().for_each(|entry| entry.checked_out = false);
            state.catalog.clear();
            state.history.clear();
            state.where_used.clear();
            state.preview = None;
            complete_explorer(&mut h, &held, Ok(Outcome::ManagedConnected { port: 48231, state, connections: vec![], connection }));
            assert!(h.app.pdm.document.is_empty() && h.app.pdm.selected.is_none());
            assert!(h.app.pdm.folder.is_empty() && h.app.pdm.search.is_empty());
            assert!(h.app.pdm.detail_context.is_none() && h.app.pdm.preview_requested.is_empty());
        }
    }

    #[test]
    fn disconnect_deferred_ready_load_is_rejected_after_reauthentication_before_dialog_closes() {
        let (mut h, _requests, held) = explorer(false);
        h.app.run("pdm.open_document", json!({"document":"other"})).unwrap();
        h.frames(2);
        let old_status = h.app.pdm.runtime.status().unwrap();
        let old_id = old_status.busy.unwrap();
        h.app.params = Some(crate::params_dialog::ParamsDialog::new());
        let mut loaded = Session::default();
        loaded.path = Some("Working/other.solidcraft".into());
        loaded.mark_saved();
        held.lock()
            .unwrap()
            .remove(0)
            .send(Completion { result: Ok(Outcome::Managed { port: 48231, state: old_status.managed.clone() }), open: Some(Box::new(loaded)) })
            .unwrap();
        h.frames(2);
        assert!(
            h.app.pdm.ready.is_some() && h.app.pdm.pending.is_none(),
            "precondition: actual native reply waits in ready while the dialog is open"
        );
        let document = h.app.session.doc.clone();
        h.app.pdm.runtime.finish(old_id, Err(Failure { message: "Account changed while opening".into(), disconnect: true })).unwrap();
        let connect = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
        let mut connection = old_status.connection.unwrap();
        connection.id = "b".repeat(64);
        connection.account = "bob".into();
        let mut state = old_status.managed;
        state.catalog.clear();
        state.local.clear();
        state.history.clear();
        state.where_used.clear();
        state.preview = None;
        h.app.pdm.runtime.finish(connect, Ok(Outcome::ManagedConnected { port: 48231, state, connections: vec![], connection })).unwrap();
        h.app.params = None;
        h.frames(4);
        assert!(h.app.pdm.ready.is_none());
        assert!(h.app.pdm.notice.is_none(), "a deferred old-session result must not restore its captured file/path feedback after reauthentication");
        assert_eq!(*h.app.session.doc, *document);
        assert_eq!(h.app.session.path.as_deref(), Some("Working/part.solidcraft"));
        assert!(h.app.pdm.workspace_active);
        assert!(h.app.pdm.runtime.status().unwrap().managed.catalog.is_empty());
    }

    #[test]
    fn disconnect_editor_discard_consent_expires_for_same_host_new_account_or_connection() {
        for change_account in [false, true] {
            let (mut h, _requests, _held, path) = dirty_archive_fixture();
            let consent = documents::EditorStamp::active(&h.app).unwrap();
            assert!(consent.matches(&h.app));
            let status = h.app.pdm.runtime.status().unwrap();
            let mut connection = status.connection.unwrap();
            if change_account {
                connection.account = "bob".into();
            } else {
                connection.id = "b".repeat(64);
            }
            let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
            h.app
                .pdm
                .runtime
                .finish(id, Ok(Outcome::ManagedConnected { port: 48231, state: status.managed, connections: vec![], connection }))
                .unwrap();
            let document = h.app.session.doc.clone();
            assert!(!consent.matches(&h.app), "discard acknowledgement must bind the authenticated principal and connection");
            let mut loaded = Session::default();
            loaded.path = Some(path.to_string_lossy().into_owned());
            loaded.mark_saved();
            assert!(documents::apply_acknowledged_discard(&mut h.app, loaded, &consent).is_err());
            assert_eq!(*h.app.session.doc, *document);
            assert!(h.app.session.is_dirty());
        }
    }

    #[test]
    fn disconnect_same_account_reconnect_between_frames_expires_old_editor_consent() {
        let (mut h, _requests, _held, path) = dirty_archive_fixture();
        let consent = documents::EditorStamp::active(&h.app).unwrap();
        let status = h.app.pdm.runtime.status().unwrap();
        let id = h.app.pdm.runtime.enqueue(Task::Disconnect).unwrap();
        h.app.pdm.runtime.finish(id, Ok(Outcome::Disconnected)).unwrap();
        let id = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
        h.app
            .pdm
            .runtime
            .finish(
                id,
                Ok(Outcome::ManagedConnected {
                    port: 48231,
                    state: status.managed,
                    connections: status.connections,
                    connection: status.connection.unwrap(),
                }),
            )
            .unwrap();
        // No GUI frame observes the intermediate disconnected state.
        assert!(!consent.matches(&h.app), "an earlier session's discard consent cannot revive when the same principal reconnects");
        let memory = h.app.session.doc.clone();
        let mut loaded = Session::default();
        loaded.path = Some(path.to_string_lossy().into_owned());
        loaded.mark_saved();
        assert!(documents::apply_acknowledged_discard(&mut h.app, loaded, &consent).is_err());
        assert_eq!(*h.app.session.doc, *memory);
    }
}

#[cfg(test)]
mod historical_identity_tests {
    use super::*;
    use crate::pdm_panel_tests::{complete_explorer, reference_complete_historical_fixture, reference_interaction_fixture};
    use solidcraft_engine::pdm::Version;

    #[test]
    fn reference_common_history_action_and_links_reuse_the_same_verified_editor_but_not_a_reloaded_path() {
        let (mut h, requests, held, root) = reference_interaction_fixture();
        let original = h.app.docs.active;
        h.app.session.doc_mut().name = "Unsaved source assembly".into();
        let source = h.app.session.doc.clone();
        let pin = Reference { document: "base".into(), version: 3 };
        let mut target = root.clone();
        target.history = vec![solidcraft_engine::pdm::ManagedVersion {
            version: Version { reference: pin.clone(), parent: None, sha256: "00".repeat(32), dependencies: vec![] },
            author: "tester".into(),
            checked_in_unix_ms: 0,
            comment: String::new(),
            request_id: "ordinary-archived-origin".into(),
        }];
        h.app.pdm.document = "base".into();
        h.app.pdm.selected = Some(pin.clone());
        h.app.pdm.detail_tab = 1;
        h.app.pdm.history_requested = Some(h.app.pdm.document.clone());
        let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: "base".into() })).unwrap();
        h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state: target.clone() })).unwrap();
        h.frames(2);
        h.app.run("pdm.open_archived", json!({"document":"base","version":3})).unwrap();
        h.frames(2);
        assert!(matches!(&requests.lock().unwrap()[0],Task::Retrieve {reference,open:true} if *reference==pin));
        let path = h.dir.join("ordinary-base-v3.solidcraft").to_string_lossy().into_owned();
        reference_complete_historical_fixture(&mut h, &held, pin.clone(), &path, target.clone());
        let count = h.app.docs.count();
        for link in [true, false] {
            crate::documents::switch(&mut h.app, original);
            crate::pdm_panel::enter(&mut h.app).unwrap();
            assert_eq!(*h.app.session.doc, *source);
            assert!(h.app.session.is_dirty());
            let state = if link { root.clone() } else { target.clone() };
            h.app.pdm.document = if link { "part" } else { "base" }.into();
            h.app.pdm.selected = Some(if link { Reference { document: "part".into(), version: 2 } } else { pin.clone() });
            h.app.pdm.detail_tab = 1;
            h.app.pdm.history_requested = Some(h.app.pdm.document.clone());
            let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: h.app.pdm.document.clone() })).unwrap();
            h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state: state.clone() })).unwrap();
            h.frames(2);
            requests.lock().unwrap().clear();
            if link {
                h.app.run("pdm.open_archived", json!({"document":"base","version":3})).unwrap();
            } else {
                h.app.run("pdm.open_archived", json!({"document":"base","version":3})).unwrap();
            }
            h.frames(2);
            assert_eq!(requests.lock().unwrap().len(), 1);
            assert!(
                matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Preview {reference}) if *reference==pin),
                "both ordinary archived action and reference link must freshly authorize the SAME registered historical editor"
            );
            assert!(h.app.pdm.workspace_active);
            complete_explorer(&mut h, &held, Ok(Outcome::Managed { port: 48231, state }));
            assert!(!h.app.pdm.workspace_active);
            assert_eq!(h.app.docs.count(), count);
            assert_eq!(h.app.session.path.as_deref(), Some(path.as_str()));
        }
        // Replacing the editor's memory at the same readonly path is not proof that
        // the new Session still represents the previously registered exact pin.
        let mut unrelated = Session::default();
        unrelated.path = Some(path.clone());
        unrelated.pdm_read_only = true;
        unrelated.doc_mut().name = "Externally reloaded file".into();
        unrelated.mark_saved();
        crate::documents::apply_managed(&mut h.app, unrelated).unwrap();
        crate::documents::switch(&mut h.app, original);
        crate::pdm_panel::enter(&mut h.app).unwrap();
        h.app.pdm.document = "part".into();
        h.app.pdm.selected = Some(Reference { document: "part".into(), version: 2 });
        h.app.pdm.detail_tab = 1;
        h.app.pdm.history_requested = Some(h.app.pdm.document.clone());
        let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: "part".into() })).unwrap();
        h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state: root })).unwrap();
        h.frames(2);
        requests.lock().unwrap().clear();
        h.app.run("pdm.open_archived", json!({"document":"base","version":3})).unwrap();
        h.frames(2);
        assert!(
            matches!(&requests.lock().unwrap()[0],Task::Retrieve {reference,open:true} if *reference==pin),
            "a reloaded path must obtain a fresh native historical identity instead of inheriting the old editor's origin"
        );
    }

    #[test]
    fn reference_historical_identity_survives_sixteen_cache_entries_and_reconnect_but_refuses_dirty_target() {
        let (mut h, requests, held, mut root) = reference_interaction_fixture();
        root.catalog.iter_mut().find(|entry| entry.document == "base").unwrap().head = Some(20);
        let original = h.app.docs.active;
        let connection = h.app.pdm.runtime.status().unwrap().connection.unwrap();
        for version in 1..=18 {
            crate::documents::switch(&mut h.app, original);
            crate::pdm_panel::enter(&mut h.app).unwrap();
            h.app.pdm.document = "part".into();
            h.app.pdm.selected = Some(Reference { document: "part".into(), version: 2 });
            h.app.pdm.detail_tab = 1;
            h.app.pdm.history_requested = Some(h.app.pdm.document.clone());
            root.history.iter_mut().find(|entry| entry.version.reference.version == 2).unwrap().version.dependencies =
                vec![Reference { document: "base".into(), version }];
            let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: "part".into() })).unwrap();
            h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state: root.clone() })).unwrap();
            h.frames(2);
            requests.lock().unwrap().clear();
            h.app.run("pdm.open_archived", json!({"document":"base","version":version})).unwrap();
            h.frames(2);
            assert_eq!(requests.lock().unwrap().len(), 1);
            assert!(
                matches!(&requests.lock().unwrap()[0],Task::Retrieve {reference,open:true} if reference.document=="base" && reference.version==version)
            );
            let path = h.dir.join(format!("base-v{version}.solidcraft")).to_string_lossy().into_owned();
            reference_complete_historical_fixture(&mut h, &held, Reference { document: "base".into(), version }, &path, root.clone());
        }
        let first_path = h.dir.join("base-v1.solidcraft").to_string_lossy().into_owned();
        let count = h.app.docs.count();
        assert_eq!(count, 19);
        for reconnect in [false, true] {
            crate::documents::switch(&mut h.app, original);
            crate::pdm_panel::enter(&mut h.app).unwrap();
            if reconnect {
                h.app.run("pdm.disconnect", json!({})).unwrap();
                h.frames(2);
                complete_explorer(&mut h, &held, Ok(Outcome::Disconnected));
                h.app.run("pdm.connect", json!({"port":48231})).unwrap();
                h.frames(2);
                complete_explorer(
                    &mut h,
                    &held,
                    Ok(Outcome::ManagedConnected { port: 48231, state: root.clone(), connections: vec![], connection: connection.clone() }),
                );
            }
            h.app.pdm.document = "part".into();
            h.app.pdm.selected = Some(Reference { document: "part".into(), version: 2 });
            h.app.pdm.detail_tab = 1;
            h.app.pdm.history_requested = Some(h.app.pdm.document.clone());
            root.history.iter_mut().find(|entry| entry.version.reference.version == 2).unwrap().version.dependencies =
                vec![Reference { document: "base".into(), version: 1 }];
            let id = h.app.pdm.runtime.enqueue(Task::Managed(ManagedTask::History { document: "part".into() })).unwrap();
            h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state: root.clone() })).unwrap();
            h.frames(2);
            requests.lock().unwrap().clear();
            h.app.run("pdm.open_archived", json!({"document":"base","version":1})).unwrap();
            h.frames(2);
            assert_eq!(requests.lock().unwrap().len(), 1);
            assert!(
                matches!(&requests.lock().unwrap()[0],Task::Managed(ManagedTask::Preview {reference}) if reference.document=="base" && reference.version==1),
                "an open historical identity survives reference-cache eviction and login; it still needs current exact permission"
            );
            complete_explorer(&mut h, &held, Ok(Outcome::Managed { port: 48231, state: root.clone() }));
            assert_eq!(
                h.app.session.path.as_deref(),
                Some(first_path.as_str()),
                "reuse must activate the exact oldest snapshot despite tab insertion shifts"
            );
            assert_eq!(h.app.docs.count(), count);
            assert!(h.app.session.pdm_read_only);
        }
        let first = h.app.docs.active;
        h.app.session.doc_mut().name = "Unsaved historical memory".into();
        crate::documents::switch(&mut h.app, original);
        crate::pdm_panel::enter(&mut h.app).unwrap();
        h.app.pdm.detail_tab = 1;
        h.app.pdm.history_requested = Some(h.app.pdm.document.clone());
        h.frames(2);
        requests.lock().unwrap().clear();
        let error = h.app.run("pdm.open_archived", json!({"document":"base","version":1})).unwrap_err();
        assert_eq!(error, "ui.pdm_reason_modified", "the direct command must reject dirty historical memory before requesting a snapshot");
        h.frames(2);
        assert!(requests.lock().unwrap().is_empty(), "dirty historical memory must not be overwritten or bypassed by creating another tab");
        assert_eq!(h.app.docs.count(), count);
        assert!(h.app.pdm.workspace_active);
        crate::documents::switch(&mut h.app, first);
        assert_eq!(h.app.session.doc.name, "Unsaved historical memory");
        assert!(h.app.session.is_dirty());
    }
}
