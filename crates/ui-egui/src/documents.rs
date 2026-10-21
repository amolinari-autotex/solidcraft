//! Several open designs, as tabs in the application bar. The active design lives in the app as
//! always (`app.session`, `app.cam`…); the others wait here with their own session (undo,
//! selection), camera and per-design view state, and are swapped in when their tab is picked.
//! Closing a design with unsaved changes asks first, and so does quitting: one "save changes?"
//! per design with unsaved changes ([`request_quit`]).

use crate::ui_kit::{Container, Surface};
use egui::{FontId, Rect, Sense, pos2, vec2};
use serde_json::{Value, json};
use solidcraft_engine::Session;
use solidcraft_engine::render::Camera;

use crate::SolveApp;
use crate::theme::Tokens;
use crate::ui_kit;

/// Most designs open at once.
pub const MAX_OPEN: usize = 32;

/// A design that is not the active one: everything that belongs to it alone.
pub struct DocSlot {
    pub(crate) session: Session,
    pub(crate) autosave: Option<solidcraft_engine::recovery::Autosaver>,
    pub(crate) big_operation: bool,
    cam: Camera,
    pre_sketch_marker: Option<Option<usize>>,
    view: DocView,
    occurrence_move: Option<crate::browser::OccMove>,
}

/// The per-design part of the UI state (what is hidden, shown or locked).
#[derive(Clone, Debug, Default)]
struct DocView {
    render: crate::render_workspace::ViewState,
    hidden_profiles: Vec<u64>,
    shown_dims: Vec<u64>,
    locked_bodies: Vec<String>,
}

impl DocSlot {
    fn new(session: Session) -> DocSlot {
        DocSlot {
            session,
            autosave: None,
            big_operation: false,
            cam: Camera::default(),
            pre_sketch_marker: None,
            view: DocView::default(),
            occurrence_move: None,
        }
    }
}

/// The open designs: one slot per tab; the active tab's slot is empty (its design is in the app).
#[derive(Default)]
pub struct Documents {
    slots: Vec<Option<DocSlot>>,
    historical: Vec<HistoricalIdentity>,
    pub active: usize,
    /// A tab waiting for the answer to "save changes?".
    pub closing: Option<usize>,
    /// Quitting: the tabs answered so far with Don't Save (`None`: not quitting).
    pub quitting: Option<Vec<usize>>,
    /// The "save changes?" button the arrow keys have picked; Enter gives it.
    pub choice: Answer,
    /// Save As is answering a Close/Quit prompt.
    saving: bool,
    /// Close Other Tabs / Close All Tabs: the tabs still to close, in increasing order (the last
    /// is closed first, so the ones before it keep their places). One with unsaved changes asks
    /// first; Cancel stops the rest (#3055).
    pub batch: Option<Vec<usize>>,
}

// Local provenance is not permission: a fresh exact server authorization is
// required before activating this editor. Weak identity prevents a same-path
// reload from inheriting the previous native snapshot's exact Reference.
struct HistoricalIdentity {
    server: String,
    reference: solidcraft_engine::pdm::Reference,
    path: String,
    document: std::sync::Weak<solidcraft_engine::doc::Document>,
}

impl Documents {
    pub(crate) fn background_mut(&mut self) -> impl Iterator<Item = &mut DocSlot> {
        self.slots.iter_mut().filter_map(Option::as_mut)
    }

    /// Number of open designs (at least the active one).
    pub fn count(&self) -> usize {
        self.slots.len().max(1)
    }
}

fn take_view(app: &mut SolveApp) -> DocView {
    let u = &mut app.ui;
    DocView {
        render: std::mem::take(&mut app.render_workspace.view),
        hidden_profiles: std::mem::take(&mut u.hidden_profiles),
        shown_dims: std::mem::take(&mut u.shown_dims),
        locked_bodies: std::mem::take(&mut u.locked_bodies),
    }
}

fn put_view(app: &mut SolveApp, v: DocView) {
    app.render_workspace.view = v.render;
    crate::render_workspace::invalidate_scene(app);
    crate::render_workspace::sync_backend(app);
    let u = &mut app.ui;
    u.hidden_profiles = v.hidden_profiles;
    u.shown_dims = v.shown_dims;
    u.locked_bodies = v.locked_bodies;
}

/// Put `slot` into the app and return what was there.
fn swap_in(app: &mut SolveApp, slot: DocSlot) -> DocSlot {
    if crate::render_workspace::active(app) {
        let _ = crate::render_workspace::enter(app, false);
    }
    // Whatever was going on in the design leaves with it.
    crate::sketch_text_move::cancel_drag(app);
    crate::dialogs::cancel(app);
    crate::dim_view::cancel();
    app.tool = None;
    app.params = None;
    app.design_properties = None;
    app.bom = None;
    app.cancel_view_animation();
    app.viewport.orbit_free = None;
    app.preview.reset();
    app.viewport.hover = None;
    app.menu.props = None;
    crate::sketch_attachment_ui::clear(app);
    let out_rev = app.session.revision;
    let mut out = DocSlot {
        session: std::mem::replace(&mut app.session, slot.session),
        autosave: app.autosave.as_mut().and_then(|a| std::mem::replace(&mut a.active, slot.autosave)),
        big_operation: std::mem::replace(&mut app.big_operation, slot.big_operation),
        cam: std::mem::replace(&mut app.cam, slot.cam),
        pre_sketch_marker: std::mem::replace(&mut app.pre_sketch_marker, slot.pre_sketch_marker),
        view: take_view(app),
        occurrence_move: std::mem::replace(&mut app.tree.occurrence_move, slot.occurrence_move),
    };
    // Only the displayed design owns the process-wide crash replay journal.
    app.session.crash_journal = out.session.crash_journal;
    out.session.crash_journal = false;
    put_view(app, slot.view);
    // Preferences the session holds go with the user, not the tab (#680).
    app.session.auto_project = out.session.auto_project;
    // Views cache by revision: the incoming design must not look unchanged.
    app.session.invalidate_view(out_rev);
    app.ui.ribbon_context = None;
    app.ui.tab = "MODEL".into();
    crate::workspace::sync_context(app);
    out
}

/// Make tab `i` the active design.
pub fn switch(app: &mut SolveApp, i: usize) {
    if app.file_picker_busy() {
        return;
    }
    crate::pdm_panel::leave(app);
    app.home.open = false;
    if i == app.docs.active || i >= app.docs.slots.len() {
        return;
    }
    let Some(incoming) = app.docs.slots.get_mut(i).and_then(Option::take) else { return };
    let out = swap_in(app, incoming);
    let a = app.docs.active;
    if let Some(s) = app.docs.slots.get_mut(a) {
        *s = Some(out);
    }
    app.docs.active = i;
}

/// Open `session` in a new tab after the active one and switch to it (`fit`: frame its model).
pub fn open_tab(app: &mut SolveApp, mut session: Session) -> Result<(), String> {
    // Bind shared protection without renewing this session's reload receipt.
    session.pdm = app.pdm.runtime.clone();
    if app.docs.slots.is_empty() {
        app.docs.slots.push(None);
        app.docs.active = 0;
    }
    if app.docs.slots.len() >= MAX_OPEN {
        return Err(format!("at most {MAX_OPEN} designs can be open"));
    }
    let at = app.docs.active + 1;
    app.docs.slots.insert(at, Some(DocSlot::new(session)));
    switch(app, at);
    app.fit_view();
    Ok(())
}

/// Is the active design an untouched new one (it can be replaced instead of opening a tab)?
pub fn active_is_blank(app: &SolveApp) -> bool {
    let s = &app.session;
    s.path.is_none() && s.doc.features.is_empty() && s.doc.params.is_empty() && s.doc.components.is_empty() && !s.is_dirty()
}

/// Show `session` (a design built or read elsewhere): in place of a blank active design,
/// otherwise in a new tab.
pub fn adopt(app: &mut SolveApp, mut session: Session) {
    // Adoption may use an old cached sample or autosave, so never stamp here.
    session.pdm = app.pdm.runtime.clone();
    if active_is_blank(app) {
        let rev = app.session.revision;
        crate::dialogs::cancel(app);
        app.tool = None;
        app.menu.props = None;
        crate::sketch_attachment_ui::clear(app);
        app.session.replace_design(session);
        crate::render_workspace::reset_document(app);
        app.session.invalidate_view(rev);
        app.cam = Camera::default();
        app.fit_view();
    } else if let Err(e) = open_tab(app, session) {
        app.set_status(e, true);
    }
}

fn same_managed_path(candidate: Option<&String>, path: &str) -> bool {
    candidate.is_some_and(|candidate| solidcraft_engine::pdm::cached_path_key(candidate) == solidcraft_engine::pdm::cached_path_key(path))
}

/// Check every open editor before a managed transfer can touch its local path.
pub fn managed_target_dirty(app: &SolveApp, document: Option<&str>) -> bool {
    let path = if let Some(document) = document {
        app.pdm.runtime.status().ok().and_then(|s| s.managed.local.into_iter().find(|v| v.document == document).map(|v| v.path))
    } else {
        app.session.path.clone()
    };
    let Some(path) = path else { return false };
    (same_managed_path(app.session.path.as_ref(), &path) && app.session.is_dirty())
        || app.docs.slots.iter().flatten().any(|s| same_managed_path(s.session.path.as_ref(), &path) && s.session.is_dirty())
}

/// Only real native/IO load completions call this, with a receipt captured BEFORE
/// reading. Generic adoption and tab switching must never renew cached sessions.
pub(crate) fn bind_fresh_pdm_load(app: &SolveApp, session: &mut Session, expected_epoch: u64) -> Result<(), String> {
    session.pdm = app.pdm.runtime.clone();
    session.mark_pdm_reloaded_from(expected_epoch)
}

/// Refresh a managed path in its existing tab. Never discard an unsaved editor.
pub fn apply_managed(app: &mut SolveApp, mut session: Session) -> Result<(), String> {
    if app.docs.slots.is_empty() && active_is_blank(app) {
        adopt(app, session);
        return Ok(());
    }
    let Some(path) = session.path.as_ref() else { return open_tab(app, session) };
    if same_managed_path(app.session.path.as_ref(), path) {
        if app.session.is_dirty() {
            return Err("Managed refresh cannot replace unsaved changes".into());
        }
        session.pdm = app.pdm.runtime.clone();
        app.session.replace_design(session);
        crate::render_workspace::reset_document(app);
        app.preview.reset();
        return Ok(());
    }
    for slot in app.docs.slots.iter_mut().flatten() {
        if same_managed_path(slot.session.path.as_ref(), path) {
            if slot.session.is_dirty() {
                return Err("Managed refresh cannot replace unsaved changes in another tab".into());
            }
            session.pdm = app.pdm.runtime.clone();
            slot.session = session;
            return Ok(());
        }
    }
    open_tab(app, session)
}

/// Consent is bound to one editor, its exact memory, path and authority epoch.
#[derive(Clone)]
pub(crate) struct EditorStamp {
    index: usize,
    document: std::sync::Arc<solidcraft_engine::doc::Document>,
    revision: u64,
    visibility: solidcraft_engine::Visibility,
    path: Option<String>,
    load_epoch: u64,
    read_only: bool,
    runtime_epoch: u64,
    authentication_epoch: u64,
    context: (Option<u16>, Option<String>, Option<String>, Option<solidcraft_engine::pdm::ActiveConnection>),
}
impl EditorStamp {
    fn capture(app: &SolveApp, index: usize, session: &Session) -> Result<Self, String> {
        let status = app.pdm.runtime.status()?;
        Ok(Self {
            index,
            document: session.doc.clone(),
            revision: session.revision,
            visibility: session.visibility.clone(),
            path: session.path.clone(),
            load_epoch: session.pdm_recovery_epoch,
            read_only: session.pdm_read_only,
            runtime_epoch: app.pdm.runtime.recovery_epoch()?,
            authentication_epoch: status.authentication_epoch,
            context: (status.port, status.managed.server_id, status.managed.workspace, status.connection),
        })
    }
    pub(crate) fn active(app: &SolveApp) -> Result<Self, String> {
        Self::capture(app, app.docs.active, &app.session)
    }
    pub(crate) fn matches(&self, app: &SolveApp) -> bool {
        let session = if self.index == app.docs.active {
            Some(&app.session)
        } else {
            app.docs.slots.get(self.index).and_then(Option::as_ref).map(|slot| &slot.session)
        };
        session.is_some_and(|session| {
            std::sync::Arc::ptr_eq(&self.document, &session.doc)
                && self.revision == session.revision
                && self.visibility == session.visibility
                && self.path.as_ref().map(|p| solidcraft_engine::pdm::cached_path_key(p))
                    == session.path.as_ref().map(|p| solidcraft_engine::pdm::cached_path_key(p))
                && self.load_epoch == session.pdm_recovery_epoch
                && self.read_only == session.pdm_read_only
        }) && app.pdm.runtime.recovery_epoch().ok() == Some(self.runtime_epoch)
            && app.pdm.runtime.status().is_ok_and(|status| {
                self.authentication_epoch == status.authentication_epoch
                    && self.context == (status.port, status.managed.server_id, status.managed.workspace, status.connection)
            })
    }
    pub(crate) fn matches_active(&self, app: &SolveApp) -> bool {
        self.index == app.docs.active && self.matches(app)
    }
}

/// One bounded graph prepared before any local save or server publication.
/// Scratch sessions retain current RAM; their original editors stay in place.
pub(crate) struct ArchiveNode {
    pub(crate) session: Session,
    pub(crate) stamp: Option<EditorStamp>,
    pub(crate) save: bool,
}
pub(crate) struct ArchiveGraph {
    pub(crate) nodes: Vec<ArchiveNode>,
}
impl ArchiveGraph {
    pub(crate) fn needs_save(&self) -> bool {
        self.nodes.iter().any(|node| node.save)
    }
}

fn archive_path(path: &std::path::Path, root: &std::path::Path) -> Result<std::path::PathBuf, String> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| "A linked working file is missing or unavailable")?;
        if metadata.file_type().is_symlink() {
            return Err("Working-folder links are not allowed while archiving".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Working-folder reparse points are not allowed while archiving".into());
            }
        }
    }
    let path = std::fs::canonicalize(path).map_err(|_| "A linked working file is unavailable")?;
    if !path.starts_with(root) || !path.is_file() {
        return Err("Save every linked design inside the configured working folder before archiving".into());
    }
    Ok(path)
}

fn archive_editor<'a>(app: &'a SolveApp, path: &str) -> Result<Option<(usize, &'a Session)>, String> {
    let mut found = None;
    for (index, session) in std::iter::once((app.docs.active, &app.session))
        .chain(app.docs.slots.iter().enumerate().filter_map(|(index, slot)| slot.as_ref().map(|slot| (index, &slot.session))))
    {
        if session.path.as_deref().is_some_and(|candidate| solidcraft_engine::pdm::same_file_path(candidate, path)) {
            if found.is_some() {
                return Err("Close duplicate editors of this linked working file before archiving".into());
            }
            found = Some((index, session));
        }
    }
    Ok(found)
}

pub(crate) fn prepare_archive_graph(app: &SolveApp) -> Result<ArchiveGraph, String> {
    use std::io::Read;
    let status = app.pdm.runtime.status()?;
    let root = std::fs::canonicalize(status.managed.root.as_deref().ok_or("Choose a working folder before archiving")?)
        .map_err(|_| "The configured working folder is unavailable")?;
    let start = app.session.path.as_deref().ok_or("Save this design inside the working folder before archiving")?;
    let start = archive_path(std::path::Path::new(start), &root)?;
    let mut stack = vec![(start, false)];
    let mut visiting = std::collections::BTreeSet::new();
    let mut complete = std::collections::BTreeSet::new();
    let mut pending = std::collections::BTreeMap::new();
    let mut nodes = Vec::new();
    while let Some((path, finish)) = stack.pop() {
        let key = solidcraft_engine::pdm::cached_path_key(&path.to_string_lossy());
        if finish {
            visiting.remove(&key);
            complete.insert(key.clone());
            let (mut node, children): (ArchiveNode, Vec<String>) = pending.remove(&key).ok_or("Invalid linked design graph")?;
            if children.iter().any(|child| {
                nodes.iter().any(|node: &ArchiveNode| {
                    node.save && node.session.path.as_deref().is_some_and(|path| solidcraft_engine::pdm::cached_path_key(path) == *child)
                })
            }) {
                node.save = true;
            }
            if node.save {
                node.session.check_output_path(node.session.path.as_deref().ok_or("Missing working path")?).map_err(|error| error.to_string())?;
                let path = node.session.path.as_deref();
                let document = status
                    .managed
                    .local
                    .iter()
                    .find(|local| path.is_some_and(|path| solidcraft_engine::pdm::same_file_path(&local.path, path)))
                    .map(|local| local.document.as_str());
                if let Some(reason) = status.action_unavailable("pdm.archive", document, path, true, false, None) {
                    return Err(reason.into());
                }
            }
            nodes.push(node);
            continue;
        }
        if complete.contains(&key) {
            continue;
        }
        if !visiting.insert(key.clone()) {
            return Err("Linked design cycles must be resolved before archiving".into());
        }
        if complete.len().saturating_add(visiting.len()) > 256 {
            return Err("Managed assembly exceeds 256 linked designs".into());
        }
        let text = path.to_str().ok_or("Invalid linked working path")?;
        let (mut copy, stamp) = if let Some((index, editor)) = archive_editor(app, text)? {
            if editor.pdm_read_only || editor.active_sketch.is_some() || !editor.pending_moves.is_empty() {
                return Err("Finish linked editor operations and close historical copies before archiving".into());
            }
            editor.check_pdm_reopen().map_err(|error| error.to_string())?;
            let stamp = EditorStamp::capture(app, index, editor)?;
            let mut copy = editor.scratch();
            copy.path = Some(text.into());
            copy.pdm_recovery_epoch = editor.pdm_recovery_epoch;
            (copy, Some(stamp))
        } else {
            let mut bytes = Vec::new();
            std::fs::File::open(&path)
                .map_err(|_| "A linked design is unavailable")?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "A linked design cannot be read")?;
            if bytes.len() > 1024 * 1024 {
                return Err("A linked managed design exceeds the content limit".into());
            }
            let doc = solidcraft_engine::io::read_design(&bytes).map_err(|_| "A linked native design is invalid")?;
            let mut copy = Session::new(doc);
            copy.path = Some(text.into());
            copy.mark_saved();
            copy.pdm_recovery_epoch = app.pdm.runtime.begin_pdm_reload()?;
            (copy, None)
        };
        copy.pdm = app.pdm.runtime.clone();
        if app.pdm.runtime.is_managed_or_historical_path(text)
            && status.managed.historical_paths.iter().any(|historical| solidcraft_engine::pdm::same_file_path(historical, text))
        {
            return Err("Historical copies cannot be archived in place".into());
        }
        let local = status.managed.local.iter().find(|local| solidcraft_engine::pdm::same_file_path(&local.path, text));
        if local.is_none() && app.pdm.runtime.is_managed_or_historical_path(text) {
            return Err("A protected historical or other-workspace file cannot be archived here".into());
        }
        let remote = local.and_then(|local| status.managed.catalog.iter().find(|remote| remote.document == local.document)).or_else(|| {
            status.managed.catalog.iter().find(|remote| {
                let relative = path.strip_prefix(&root).ok().map(|path| path.to_string_lossy().replace('\\', "/"));
                relative.as_deref() == Some(remote.logical_path.as_str())
            })
        });
        if remote.is_some_and(|remote| {
            remote.checkout.as_ref().is_some_and(|checkout| {
                !local.is_some_and(|local| local.checked_out && Some(local.base_version) == remote.head)
                    || Some(checkout.workspace.as_str()) != status.managed.workspace.as_deref()
                    || status.connection.as_ref().is_some_and(|connection| connection.account != checkout.owner)
            })
        }) {
            return Err("A linked design is checked out by another working folder or account".into());
        }
        let mut children = Vec::new();
        for link in copy.doc.links.values() {
            let child = archive_path(&path.parent().ok_or("Missing working folder")?.join(&link.path), &root)?;
            children.push(solidcraft_engine::pdm::cached_path_key(&child.to_string_lossy()));
        }
        // Validate derived geometry against saved children now, before any save.
        // Dirty RAM children are saved first and refreshed once more on the worker.
        if !copy.doc.links.is_empty() {
            let authority = std::mem::take(&mut copy.pdm);
            let derived = copy.execute("component.update_links", &json!({"recursive":true}));
            copy.pdm = authority;
            derived.map_err(|error| error.to_string())?;
        }
        let save = copy.is_dirty();
        let child_paths: Vec<_> = copy.doc.links.values().map(|link| path.parent().unwrap_or(&root).join(&link.path)).collect();
        pending.insert(key, (ArchiveNode { session: copy, stamp, save }, children));
        stack.push((path, true));
        for child in child_paths.into_iter().rev() {
            stack.push((archive_path(&child, &root)?, false));
        }
    }
    Ok(ArchiveGraph { nodes })
}

pub(crate) fn apply_archive_save(app: &mut SolveApp, stamp: &EditorStamp, done: &Session) -> Result<(), String> {
    if !stamp.matches(app) {
        return Err("A linked editor changed while saving; archive was not started".into());
    }
    let session = if stamp.index == app.docs.active {
        &mut app.session
    } else {
        &mut app.docs.slots.get_mut(stamp.index).and_then(Option::as_mut).ok_or("A linked editor was closed while saving")?.session
    };
    adopt_derived_links(session, done);
    session.adopt_save(done);
    Ok(())
}

fn adopt_derived_links(session: &mut Session, done: &Session) {
    if *session.doc == *done.doc {
        return;
    }
    session.undo.push(solidcraft_engine::Snapshot {
        label: "Update Links".into(),
        doc: session.doc.clone(),
        active_sketch: session.active_sketch,
        pending_moves: session.pending_moves.clone(),
    });
    session.redo.clear();
    session.doc = done.doc.clone();
    session.refresh();
}

/// Refresh derived linked geometry in RAM only; do not acquire grants, save,
/// replace editors, or publish any containing assembly.
pub(crate) fn refresh_linked_assemblies(app: &mut SolveApp) -> Vec<String> {
    if app.tool.is_some() || app.dialog.is_some() || app.applying.is_some() || app.deferred.is_some() {
        return Vec::new();
    }
    let Ok(status) = app.pdm.runtime.status() else { return Vec::new() };
    if status.port.is_none() || status.blocking {
        return Vec::new();
    }
    let mut prepared = Vec::new();
    for (index, session) in std::iter::once((app.docs.active, &app.session))
        .chain(app.docs.slots.iter().enumerate().filter_map(|(index, slot)| slot.as_ref().map(|slot| (index, &slot.session))))
    {
        if session.pdm_read_only
            || session.doc.links.is_empty()
            || session.active_sketch.is_some()
            || !session.pending_moves.is_empty()
            || session.check_pdm_reopen().is_err()
            || session
                .path
                .as_deref()
                .is_none_or(|path| !status.managed.local.iter().any(|local| solidcraft_engine::pdm::same_file_path(&local.path, path)))
        {
            continue;
        }
        let Ok(stamp) = EditorStamp::capture(app, index, session) else { continue };
        let mut copy = session.scratch();
        copy.path = session.path.clone();
        // Detached authority is intentional for derived RAM geometry only.
        // No save/publication command is run on this scratch session.
        prepared.push((stamp, copy));
    }
    let mut errors = Vec::new();
    for (stamp, mut copy) in prepared {
        if let Err(error) = copy.execute("component.update_links", &json!({"recursive":true})) {
            errors.push(error.to_string());
            continue;
        }
        if !stamp.matches(app) {
            errors.push("A linked editor changed before its geometry refresh".into());
            continue;
        }
        let session = if stamp.index == app.docs.active {
            &mut app.session
        } else if let Some(Some(slot)) = app.docs.slots.get_mut(stamp.index) {
            &mut slot.session
        } else {
            continue;
        };
        adopt_derived_links(session, &copy);
    }
    errors
}

pub(crate) fn managed_editor_stamp(app: &SolveApp, document: Option<&str>) -> Option<EditorStamp> {
    let path = document.map_or_else(
        || app.session.path.clone(),
        |document| app.pdm.runtime.status().ok()?.managed.local.into_iter().find(|entry| entry.document == document).map(|entry| entry.path),
    )?;
    if same_managed_path(app.session.path.as_ref(), &path) {
        return EditorStamp::active(app).ok();
    }
    app.docs.slots.iter().enumerate().find_map(|(index, slot)| {
        slot.as_ref()
            .filter(|slot| same_managed_path(slot.session.path.as_ref(), &path))
            .and_then(|slot| EditorStamp::capture(app, index, &slot.session).ok())
    })
}

pub(crate) fn managed_path_is_open(app: &SolveApp, path: &str) -> bool {
    same_managed_path(app.session.path.as_ref(), path)
        || app.docs.slots.iter().flatten().any(|slot| same_managed_path(slot.session.path.as_ref(), path))
}

/// Only the exact editor covered by an explicit discard acknowledgement may be
/// replaced while dirty. Ordinary managed refresh never calls this boundary.
pub(crate) fn apply_acknowledged_discard(app: &mut SolveApp, mut session: Session, consent: &EditorStamp) -> Result<(), String> {
    if !consent.matches(app) || consent.path.as_deref().is_none_or(|path| !same_managed_path(session.path.as_ref(), path)) {
        return Err("The editor changed after discard was confirmed; reopen the restored working copy".into());
    }
    session.pdm = app.pdm.runtime.clone();
    if consent.index == app.docs.active {
        app.session.replace_design(session);
        crate::render_workspace::reset_document(app);
        app.preview.reset();
    } else if let Some(Some(slot)) = app.docs.slots.get_mut(consent.index) {
        slot.session = session;
    } else {
        return Err("The confirmed editor is no longer open".into());
    }
    Ok(())
}

/// Activate an already loaded managed path without opening a duplicate editor.
/// Call only after the native load was accepted and applied successfully.
pub(crate) fn activate_managed_path(app: &mut SolveApp, path: &str) {
    let index = app.docs.slots.iter().position(|slot| slot.as_ref().is_some_and(|slot| same_managed_path(slot.session.path.as_ref(), path)));
    if let Some(index) = index {
        switch(app, index);
    }
}

/// An immutable historical tab may be reused only after a fresh native
/// authorization, with the exact clean editor captured before that request.
fn historical_session<'a>(app: &'a SolveApp, path: &str) -> Option<&'a Session> {
    if same_managed_path(app.session.path.as_ref(), path) {
        return Some(&app.session);
    }
    app.docs.slots.iter().flatten().find(|slot| same_managed_path(slot.session.path.as_ref(), path)).map(|slot| &slot.session)
}

fn prune_historical(app: &mut SolveApp) {
    let entries = std::mem::take(&mut app.docs.historical);
    app.docs.historical = entries
        .into_iter()
        .filter(|entry| {
            historical_session(app, &entry.path).is_some_and(|session| {
                // Keep a changed dirty target only to refuse replacement/duplication.
                // A clean external reload has no native exact-reference provenance.
                session.is_dirty()
                    || (session.pdm_read_only && entry.document.upgrade().is_some_and(|doc| std::sync::Arc::ptr_eq(&doc, &session.doc)))
            })
        })
        .collect();
}

pub(crate) fn register_historical(app: &mut SolveApp, server: &str, reference: solidcraft_engine::pdm::Reference, path: &str) -> Result<(), String> {
    prune_historical(app);
    let session =
        historical_session(app, path).filter(|session| session.pdm_read_only && !session.is_dirty()).ok_or("ui.pdm_reference_open_failed")?;
    let document = std::sync::Arc::downgrade(&session.doc);
    app.docs.historical.retain(|entry| entry.path != path);
    if app.docs.historical.len() >= MAX_OPEN {
        return Err("ui.pdm_reference_unavailable".into());
    }
    app.docs.historical.push(HistoricalIdentity { server: server.into(), reference, path: path.into(), document });
    Ok(())
}

pub(crate) fn registered_historical(
    app: &mut SolveApp,
    server: &str,
    reference: &solidcraft_engine::pdm::Reference,
) -> Result<Option<(String, EditorStamp)>, String> {
    prune_historical(app);
    let Some(path) = app.docs.historical.iter().find(|entry| entry.server == server && entry.reference == *reference).map(|entry| entry.path.clone())
    else {
        return Ok(None);
    };
    let session = historical_session(app, &path).ok_or("ui.pdm_reference_unavailable")?;
    if session.is_dirty() {
        return Err("ui.pdm_reason_modified".into());
    }
    let stamp = historical_editor_stamp(app, &path).ok_or("ui.pdm_reference_unavailable")?;
    Ok(Some((path, stamp)))
}

pub(crate) fn historical_editor_stamp(app: &SolveApp, path: &str) -> Option<EditorStamp> {
    let eligible = |session: &Session| {
        same_managed_path(session.path.as_ref(), path) && session.pdm_read_only && !session.is_dirty() && session.check_pdm_reopen().is_ok()
    };
    if eligible(&app.session) {
        return EditorStamp::active(app).ok();
    }
    app.docs.slots.iter().enumerate().find_map(|(index, slot)| {
        slot.as_ref().filter(|slot| eligible(&slot.session)).and_then(|slot| EditorStamp::capture(app, index, &slot.session).ok())
    })
}

pub(crate) fn activate_authorized_historical(app: &mut SolveApp, path: &str, stamp: &EditorStamp) -> Result<(), String> {
    if !stamp.matches(app) || historical_editor_stamp(app, path).is_none() {
        return Err("ui.pdm_reference_unavailable".into());
    }
    activate_managed_path(app, path);
    if !same_managed_path(app.session.path.as_ref(), path) || !app.session.pdm_read_only || app.session.is_dirty() {
        return Err("ui.pdm_reference_unavailable".into());
    }
    Ok(())
}

/// A new, empty design in its own tab. One that is already empty keeps its tab and still
/// takes Units of new designs (#1205): a launch starts on that empty design, so returning
/// here used to leave it in millimetres.
pub fn new_design(app: &mut SolveApp) {
    if app.file_picker_busy() {
        return;
    }
    crate::pdm_panel::leave(app);
    app.home.open = false;
    if active_is_blank(app) {
        crate::prefs::apply_new_design(app);
        return;
    }
    if let Err(e) = open_tab(app, Session::default()) {
        app.set_status(e, true);
    } else {
        crate::prefs::apply_new_design(app);
    }
}

/// Create a new tab directly; the File view chooses units before using [`new_design`].
/// An untouched blank launch design is reused.
pub fn new_tab(app: &mut SolveApp) {
    if app.file_picker_busy() {
        return;
    }
    if app.home.open && active_is_blank(app) {
        new_design(app);
        return;
    }
    crate::pdm_panel::leave(app);
    app.home.open = false;
    if let Err(e) = open_tab(app, Session::default()) {
        app.set_status(e, true);
    } else {
        crate::prefs::apply_new_design(app);
    }
}

/// Before opening a file: a fresh tab unless the active design is blank. The empty design,
/// new or already showing, takes Units of new designs so a cancelled open is not millimetres
/// when the preference says otherwise.
pub fn prepare_open(app: &mut SolveApp) {
    if active_is_blank(app) {
        crate::prefs::apply_new_design(app);
        return;
    }
    if let Err(e) = open_tab(app, Session::default()) {
        app.set_status(e, true);
    } else {
        crate::prefs::apply_new_design(app);
    }
}

/// Close tab `i`: asks first when it has unsaved changes (`force`: close anyway).
pub fn close(app: &mut SolveApp, i: usize, force: bool) {
    if app.file_picker_busy() {
        return;
    }
    let n = app.docs.count();
    if i >= n {
        return;
    }
    if !force && dirty(app, i) {
        app.docs.closing = Some(i);
        return;
    }
    app.docs.closing = None;
    let browser = app.pdm.workspace_active;
    if n <= 1 {
        if browser {
            crate::pdm_panel::leave(app);
        }
        // The last design: a blank one takes its place.
        if let Some(a) = app.autosave.as_mut().and_then(|a| a.active.take()) {
            a.discard();
        }
        app.big_operation = false;
        crate::sketch_text_move::cancel_drag(app);
        let rev = app.session.revision;
        crate::dialogs::cancel(app);
        app.tool = None;
        app.session.replace_design(Session::default());
        app.session.revision = rev + 1;
        crate::prefs::apply_new_design(app);
        app.cam = Camera::default();
        app.fit_view();
        put_view(app, DocView::default());
        app.docs = Documents::default();
        if browser {
            app.ui.tab = "SOLID".into();
            if let Err(error) = crate::pdm_panel::enter(app) {
                app.set_status(error, true);
            }
        }
        app.home.open = !browser;
        return;
    }
    if i == app.docs.active {
        // Show a neighbour first, then drop this one.
        let next = if i + 1 < n { i + 1 } else { i - 1 };
        switch(app, next);
    }
    if let Some(slot) = app.docs.slots.remove(i)
        && let Some(a) = slot.autosave
    {
        a.discard();
    }
    if app.docs.active > i {
        app.docs.active -= 1;
    }
    if browser
        && !app.pdm.workspace_active
        && let Err(error) = crate::pdm_panel::enter(app)
    {
        app.set_status(error, true);
    }
}

/// Close the visible page. PDM is a reusable application tab, so leaving it
/// returns to Home without changing any document or server reservation.
pub fn close_active_tab(app: &mut SolveApp) {
    if app.file_picker_busy() || app.file_load.busy() {
        return;
    }
    if app.pdm.workspace_active {
        crate::pdm_panel::leave(app);
        app.home.show(app.session.revision);
    } else if !app.home.open {
        close(app, app.docs.active, false);
    }
}

/// Close several tabs (Close Other Tabs, Close All Tabs; #3055): each with unsaved changes asks
/// "save changes?" in turn, the others close; Cancel keeps the tabs not closed yet.
pub fn close_many(app: &mut SolveApp, mut tabs: Vec<usize>) {
    if app.file_picker_busy() || app.docs.quitting.is_some() || app.docs.closing.is_some() {
        return;
    }
    tabs.sort_unstable();
    tabs.dedup();
    app.docs.batch = Some(tabs);
    batch_step(app);
}

/// Close the next tab of [`close_many`]'s batch, or ask about it when it has unsaved changes.
fn batch_step(app: &mut SolveApp) {
    if app.docs.closing.is_some() || app.docs.quitting.is_some() {
        return;
    }
    let Some(mut left) = app.docs.batch.take() else { return };
    while let Some(i) = left.pop() {
        if i >= app.docs.count() {
            continue;
        }
        if dirty(app, i) {
            app.docs.closing = Some(i);
            app.docs.batch = Some(left);
            return;
        }
        close(app, i, true);
    }
}

/// Quit (the title bar's ×, File ▸ Quit, the window being closed): asks "save changes?" for each
/// design with unsaved changes, then sets `app.quit_requested` for the host to close the window.
/// Cancel, or a Save that didn't save, stays open.
pub fn request_quit(app: &mut SolveApp) {
    if app.file_picker_busy() {
        return;
    }
    if app.docs.quitting.is_none() {
        app.docs.quitting = Some(Vec::new());
    }
    quit_step(app);
}

/// Ask about the next design with unsaved changes, or quit when none is left.
fn quit_step(app: &mut SolveApp) {
    let Some(skip) = app.docs.quitting.clone() else { return };
    if app.docs.closing.is_some() {
        return;
    }
    match (0..app.docs.count()).find(|i| !skip.contains(i) && dirty(app, *i)) {
        Some(i) => {
            switch(app, i);
            app.docs.closing = Some(i);
        }
        None => {
            // Don't Save means discard: no recovery copy is kept for the next launch either.
            for i in skip {
                switch(app, i);
                app.session.mark_saved();
            }
            app.docs.quitting = None;
            app.quit_requested = true;
        }
    }
}

/// Is any open design unsaved (the web page asks before it is left)?
pub fn any_dirty(app: &SolveApp) -> bool {
    (0..app.docs.count()).any(|i| dirty(app, i))
}

/// Changing the client working directory requires all managed editors closed,
/// including inactive tabs and historical read-only copies. Ordinary documents
/// outside the PDM working directory retain their current editor state.
pub(crate) fn any_managed_open(app: &SolveApp) -> bool {
    let root = app.pdm.runtime.status().ok().and_then(|status| status.managed.root).map(|root| solidcraft_engine::pdm::cached_path_key(&root));
    let managed = |session: &Session| {
        session.pdm_read_only
            || session.path.as_ref().is_some_and(|path| {
                let key = solidcraft_engine::pdm::cached_path_key(path);
                app.pdm.runtime.managed_for_path(path).is_some()
                    || root.as_ref().is_some_and(|root| key == *root || key.starts_with(&format!("{}/", root.trim_end_matches('/'))))
            })
    };
    managed(&app.session) || app.docs.slots.iter().flatten().any(|slot| managed(&slot.session))
}

/// Resolve aliases only when submitting the change, never on ordinary UI frames.
pub(crate) fn any_managed_open_for_change(app: &SolveApp) -> bool {
    let protected = |session: &Session| session.path.as_deref().is_some_and(|path| app.pdm.runtime.is_managed_or_historical_path(path));
    any_managed_open(app) || protected(&app.session) || app.docs.slots.iter().flatten().any(|slot| protected(&slot.session))
}

fn dirty(app: &SolveApp, i: usize) -> bool {
    if i == app.docs.active || app.docs.slots.is_empty() {
        return app.session.is_dirty();
    }
    app.docs.slots.get(i).and_then(Option::as_ref).is_some_and(|s| s.session.is_dirty())
}

/// Tab names (with an unsaved-changes flag), in order.
pub fn tabs_info(app: &SolveApp) -> Vec<(String, bool)> {
    if app.docs.slots.is_empty() {
        return vec![(app.session.doc.name.clone(), app.session.is_dirty())];
    }
    app.docs
        .slots
        .iter()
        .map(|s| match s {
            Some(d) => (d.session.doc.name.clone(), d.session.is_dirty()),
            None => (app.session.doc.name.clone(), app.session.is_dirty()),
        })
        .collect()
}

/// The control channel's `ui.documents`: list, `new`, `switch`, `close` (by index; `force`
/// closes without asking), `close_others` (all but `index`), `close_all` or `quit`; `answer`:
/// save | dont_save | cancel answers "save changes?".
pub fn control(app: &mut SolveApp, p: &Value) -> Value {
    let i = p.get("index").and_then(Value::as_u64).map(|x| x as usize);
    match p.get("action").and_then(Value::as_str) {
        Some("new") => new_design(app),
        Some("switch") => switch(app, i.unwrap_or(app.docs.active)),
        Some("close") => close(app, i.unwrap_or(app.docs.active), p.get("force").and_then(Value::as_bool).unwrap_or(false)),
        Some("close_others") => {
            let keep = i.unwrap_or(app.docs.active);
            close_many(app, (0..app.docs.count()).filter(|k| *k != keep).collect());
        }
        Some("close_all") => close_many(app, (0..app.docs.count()).collect()),
        Some("quit") => request_quit(app),
        _ => {}
    }
    let answer = match p.get("answer").and_then(Value::as_str) {
        Some("save") => Some(Answer::Save),
        Some("dont_save") => Some(Answer::DontSave),
        Some("cancel") => Some(Answer::Cancel),
        _ => None,
    };
    if let Some(a) = answer {
        answer_prompt(app, a);
    }
    let tabs: Vec<Value> = tabs_info(app).into_iter().map(|(name, dirty)| json!({"name": name, "dirty": dirty})).collect();
    json!({"documents": tabs, "active": app.docs.active, "closing": app.docs.closing, "quitting": app.docs.quitting.is_some(), "batch": app.docs.batch})
}

/// The document tabs in the application bar, from `x0` to `x1`: click to switch, × to close,
/// + for a new design.
pub fn tabs(app: &mut SolveApp, ui: &mut egui::Ui, r: Rect, x0: f32, x1: f32) {
    let t = Tokens::get();
    let mut x0 = x0;
    if app.pdm.tab_open() {
        let label_width = ui.painter().layout_no_wrap(app.tr("ui.pdm_title").into(), FontId::proportional(t.font_button), t.app_bar_text).size().x;
        let tab_width = (label_width + 34.0).max(66.0);
        let pdm = Rect::from_min_size(pos2(x0, r.top() + 4.0), vec2(tab_width, r.height() - 8.0));
        let response = ui.interact(pdm, ui.id().with("pdm_tab"), Sense::click());
        tab_shape(ui.painter(), &t, pdm, app.pdm.workspace_active && !app.home.open, response.hovered());
        crate::icons::paint_on(
            ui.painter(),
            Rect::from_center_size(pos2(pdm.left() + 13.0, pdm.center().y), vec2(18.0, 18.0)),
            "ws_pdm",
            Some(true),
            1.0,
        );
        ui.painter().text(
            pos2(pdm.left() + 26.0, pdm.center().y),
            egui::Align2::LEFT_CENTER,
            app.tr("ui.pdm_title"),
            FontId::proportional(t.font_button),
            if app.pdm.workspace_active && !app.home.open { t.text } else { t.app_bar_text },
        );
        crate::scenario::publish_handle("tab:pdm", pdm.center());
        response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, !app.file_picker_busy(), app.tr("ui.pdm_title")));
        if response.clicked()
            && !app.file_picker_busy()
            && let Err(error) = crate::pdm_panel::enter(app)
        {
            app.set_status(error, true);
        }
        x0 += tab_width + 4.0;
    }
    // Home and PDM can be used before a real design exists. The startup session
    // remains internal; no dummy file or extra document tab is created.
    let info =
        if app.docs.slots.is_empty() && active_is_blank(app) && (app.home.open || app.pdm.workspace_active) { Vec::new() } else { tabs_info(app) };
    let n = info.len();
    let (first, shown, w) = layout(n, app.docs.active, x1 - x0);
    let mut x = x0;
    let mut pick: Option<usize> = None;
    let mut shut: Option<usize> = None;
    // Each tab fits its name (up to MAX_FIT) while all of them fit; otherwise they share the room.
    const MAX_FIT: f32 = 200.0;
    let natural: Vec<f32> = info
        .iter()
        .map(|(name, dirty)| {
            let shown_name = crate::i18n::Locale::for_language(&app.preferences.language).given_name(name);
            let label = format!("{shown_name}{}", if *dirty { " •" } else { "" });
            let text = ui.painter().layout_no_wrap(label, crate::fonts::semibold(crate::theme::Tokens::get().font_button), t.app_bar_text).size().x;
            (text + 40.0).clamp(72.0, MAX_FIT)
        })
        .collect();
    let fit_all = shown == n && natural.iter().sum::<f32>() <= x1 - x0 - 34.0;
    // A right-click on a tab opens its menu (#3055): the tab and where the menu opens.
    let menu_id = egui::Id::new("sc_doc_tab_menu");
    let mut menu: Option<(usize, egui::Pos2)> = ui.ctx().data(|d| d.get_temp(menu_id));
    for (i, (name, dirty)) in info.iter().enumerate().skip(first).take(shown) {
        let w = if fit_all { natural.get(i).copied().unwrap_or(w) } else { w };
        let tr = Rect::from_min_size(pos2(x, r.top() + 4.0), vec2(w - 2.0, r.height() - 8.0));
        let active = !app.home.open && !app.pdm.workspace_active && (i == app.docs.active || app.docs.slots.is_empty());
        let resp = ui.interact(tr, ui.id().with(("doc_tab", i)), Sense::click_and_drag());
        crate::scenario::publish_target(&format!("tab:design:{i}"), tr);
        // The tabs are part of the title bar: dragging one moves the window, a double click
        // maximizes it.
        if app.custom_titlebar || app.integrated_titlebar {
            if resp.drag_started_by(egui::PointerButton::Primary) {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
            } else if resp.double_clicked() {
                crate::titlebar::toggle_maximize(ui.ctx());
            }
        }
        tab_shape(ui.painter(), &t, tr, active, resp.hovered() || resp.has_focus());
        let ink = if active || resp.hovered() { t.app_bar_text } else { t.app_bar_text.gamma_multiply(0.7) };
        let name_display = crate::i18n::Locale::for_language(&app.preferences.language).given_name(name);
        let label = format!("{name_display}{}", if *dirty { " •" } else { "" });
        let font = if active {
            crate::fonts::semibold(crate::theme::Tokens::get().font_button)
        } else {
            FontId::proportional(crate::theme::Tokens::get().font_button)
        };
        let g = ui.painter().layout_no_wrap(label, font, ink);
        let text_w = (tr.width() - 30.0).max(10.0);
        let clip = Rect::from_min_size(tr.min, vec2(text_w + 10.0, tr.height()));
        ui.painter().with_clip_rect(clip).galley(pos2(tr.left() + 10.0, tr.center().y - g.size().y / 2.0), g, ink);
        // ×
        let xr = Rect::from_center_size(pos2(tr.right() - 13.0, tr.center().y), vec2(16.0, 16.0));
        let show_close = active || resp.hovered() || ui.rect_contains_pointer(tr);
        let xresp = ui.interact(xr, ui.id().with(("doc_close", i)), if show_close { Sense::click() } else { Sense::hover() });
        crate::scenario::publish_target(&format!("tab:close:{i}"), xr);
        if show_close && (xresp.hovered() || xresp.has_focus()) {
            ui.painter().rect_filled(xr, 3.0, t.app_bar_hover_strong);
        }
        if show_close {
            crate::icons::paint_app_bar(
                ui.painter(),
                Rect::from_center_size(xr.center(), vec2(14.0, 14.0)),
                "close",
                if xresp.hovered() || xresp.has_focus() { 1.0 } else { 0.55 },
            );
        }
        if resp.secondary_clicked() {
            menu = Some((i, ui.ctx().pointer_interact_pos().unwrap_or(tr.left_bottom())));
        }
        if xresp.on_hover_text("Close").clicked() {
            shut = Some(i);
        } else if resp.on_hover_text(name.as_str()).clicked() {
            pick = Some(i);
        }
        x += w;
    }
    // More tabs than fit: a chevron lists them all.
    if shown < n {
        let mr = Rect::from_center_size(pos2(x + 12.0, r.center().y), vec2(20.0, 22.0));
        let mresp = ui.interact(mr, ui.id().with("doc_more"), Sense::click());
        crate::scenario::publish_handle("tab:overflow", mr.center());
        if mresp.hovered() {
            ui.painter().rect_filled(mr, 4.0, t.app_bar_hover_button);
        }
        ui.painter().text(
            mr.center(),
            egui::Align2::CENTER_CENTER,
            format!("»{}", n - shown),
            FontId::proportional(crate::theme::Tokens::get().font_body),
            t.app_bar_text,
        );
        let id = egui::Id::new("sc_doc_more");
        if mresp.clone().on_hover_text(crate::i18n::tr_label("All open designs")).clicked() {
            ui.ctx().data_mut(|d| d.insert_temp(id, !d.get_temp::<bool>(id).unwrap_or(false)));
        }
        if ui.ctx().data(|d| d.get_temp::<bool>(id).unwrap_or(false)) {
            let resp = Container::new(ui.ctx(), Surface::Popup)
                .area(id.with("area"))
                .fixed_pos(pos2(mr.left(), r.bottom()))
                .order(egui::Order::Foreground)
                .show(ui.ctx(), |ui| {
                    crate::context_menu::menu_frame(ui, |ui| {
                        for (i, (name, dirty)) in info.iter().enumerate() {
                            let label = format!("{name}{}", if *dirty { " •" } else { "" });
                            if ui_kit::list_picker(ui, &format!("document:{i}"), &label, i == app.docs.active).clicked() {
                                pick = Some(i);
                            }
                        }
                    })
                });
            let pressed_outside = ui.ctx().input(|i| i.pointer.any_pressed()) && !resp.response.contains_pointer() && !mresp.contains_pointer();
            if pick.is_some() || pressed_outside {
                ui.ctx().data_mut(|d| d.insert_temp(id, false));
            }
        }
        x += 26.0;
    }
    // The tab's menu: close it, the others, or all of them.
    let mut many: Option<Vec<usize>> = None;
    if let Some((i, at)) = menu.filter(|(i, _)| *i < n) {
        let items = [("ui.closeTab", "Close"), ("ui.closeOtherTabs", "Close Other Tabs"), ("ui.closeAllTabs", "Close All Tabs")];
        let resp =
            Container::new(ui.ctx(), Surface::Popup).area(menu_id.with("area")).fixed_pos(at).order(egui::Order::Foreground).show(ui.ctx(), |ui| {
                crate::context_menu::menu_frame(ui, |ui| {
                    let mut chosen = None;
                    for (id, label) in items {
                        let mut item = crate::context_menu::Item::action(id, label, "");
                        item.enabled = id != "ui.closeOtherTabs" || n > 1;
                        let top = ui.cursor().top();
                        let row = crate::context_menu::list_row(ui, &item);
                        let rect = Rect::from_min_max(pos2(ui.min_rect().left(), top), pos2(ui.min_rect().right(), ui.cursor().top()));
                        crate::scenario::publish_handle(&format!("tab_menu:{id}"), rect.center());
                        if row.is_some() {
                            chosen = Some(id);
                        }
                    }
                    chosen
                })
            });
        match resp.inner {
            Some("ui.closeTab") => shut = Some(i),
            Some("ui.closeOtherTabs") => many = Some((0..n).filter(|k| *k != i).collect()),
            Some("ui.closeAllTabs") => many = Some((0..n).collect()),
            _ => {}
        }
        let pressed_outside = ui.ctx().input(|x| x.pointer.any_pressed()) && !resp.response.contains_pointer();
        menu = if resp.inner.is_some() || pressed_outside || ui.ctx().input(|x| x.key_pressed(egui::Key::Escape)) { None } else { Some((i, at)) };
    }
    ui.ctx().data_mut(|d| match menu {
        Some(m) => {
            d.insert_temp(menu_id, m);
        }
        None => {
            d.remove::<(usize, egui::Pos2)>(menu_id);
        }
    });
    // Choose a new design, open or sample from the File view before creating a tab.
    let pr = Rect::from_center_size(pos2(x + 14.0, r.center().y), vec2(22.0, 22.0));
    let presp = ui.interact(pr, ui.id().with("doc_new"), Sense::click());
    if presp.hovered() {
        ui.painter().rect_filled(pr, 4.0, t.app_bar_hover_button);
    }
    crate::icons::paint_app_bar(
        ui.painter(),
        Rect::from_center_size(pr.center(), vec2(16.0, 16.0)),
        "plus",
        if presp.hovered() { 1.0 } else { 0.55 },
    );
    // A file loading into the window keeps the tabs as they are (dragging still moves it).
    let idle = !app.file_load.busy();
    crate::scenario::publish_handle("tab:new", pr.center());
    if presp.on_hover_text(app.tr("ui.start_page")).clicked() && idle {
        app.home.show(app.session.revision);
    }
    match (shut, pick) {
        _ if !idle => {}
        _ if many.is_some() => close_many(app, many.unwrap_or_default()),
        (Some(i), _) => close(app, i, false),
        (None, Some(i)) => switch(app, i),
        (None, None) => {}
    }
}

/// Tabs are rounded chips on the bar; the active design has the stronger fill.
fn tab_shape(painter: &egui::Painter, t: &Tokens, r: Rect, active: bool, hovered: bool) {
    let fill = if active {
        t.app_bar_tab_active
    } else if hovered {
        t.app_bar_hover
    } else {
        egui::Color32::TRANSPARENT
    };
    painter.rect_filled(r, t.radius_md, fill);
}

/// Which tabs the strip shows in `room` points: (first, how many, tab width). Tabs shrink to
/// `MIN_TAB`; past that a window of tabs around the active one is shown and the rest go in the »
/// list.
pub fn layout(n: usize, active: usize, room: f32) -> (usize, usize, f32) {
    const MIN_TAB: f32 = 90.0;
    let n = n.max(1);
    let avail = (room - 34.0).max(MIN_TAB);
    if avail / n as f32 >= MIN_TAB {
        return (0, n, (avail / n as f32).min(220.0));
    }
    // Leave room for the » button.
    let fit = (((avail - 26.0) / MIN_TAB).floor() as usize).max(1);
    let first = active.saturating_sub(fit - 1).min(n - fit);
    (first, fit, MIN_TAB)
}

/// What "save changes?" was answered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Answer {
    #[default]
    Save,
    DontSave,
    Cancel,
}

/// The "save changes?" prompt for a tab being closed, or for each unsaved design when quitting.
pub fn prompt(app: &mut SolveApp, ctx: &egui::Context) {
    let _language = crate::i18n::scope(&app.preferences.language);
    quit_step(app);
    let Some(i) = app.docs.closing else { return };
    let name = tabs_info(app).get(i).map(|x| x.0.clone()).unwrap_or_default();
    let name_display = crate::i18n::tr_name(&name);
    let mut answer: Option<Answer> = None;
    // Left and Right move between the buttons as they are laid out (Save is picked first, at the
    // right); Enter gives the picked one.
    let order = [Answer::DontSave, Answer::Cancel, Answer::Save];
    let (left, right, enter) = ctx.input_mut(|x| {
        (
            x.consume_key(egui::Modifiers::NONE, egui::Key::ArrowLeft),
            x.consume_key(egui::Modifiers::NONE, egui::Key::ArrowRight),
            x.consume_key(egui::Modifiers::NONE, egui::Key::Enter),
        )
    });
    let at = order.iter().position(|a| *a == app.docs.choice).unwrap_or(order.len() - 1);
    let at = if left {
        at.saturating_sub(1)
    } else if right {
        (at + 1).min(order.len() - 1)
    } else {
        at
    };
    let choice = order.get(at).copied().unwrap_or_default();
    app.docs.choice = choice;
    if enter {
        answer = Some(choice);
    }
    let title = crate::i18n::format("document.save_changes", &[("name", &name_display)]);
    let (closed, action) = ui_kit::Confirm::new(egui::Id::new("sc_close_prompt"), "status_warning", &title)
        .tone(ui_kit::Tone::Warning)
        .actions(crate::i18n::tr("ui.save"), crate::i18n::tr("ui.cancel"), Some(crate::i18n::tr("ui.don_t_save")))
        .selected(match choice {
            Answer::Save => ui_kit::Action::Ok,
            Answer::DontSave => ui_kit::Action::Apply,
            Answer::Cancel => ui_kit::Action::Cancel,
        })
        .show(ctx, true, |ui| {
            ui_kit::text(ui, &crate::i18n::format("document.unsaved_changes", &[("name", &name_display)]), ui_kit::Text::Report("unsaved", false));
        });
    answer = match action {
        ui_kit::Action::Ok => Some(Answer::Save),
        ui_kit::Action::Apply => Some(Answer::DontSave),
        ui_kit::Action::Cancel => Some(Answer::Cancel),
        ui_kit::Action::None if closed => Some(Answer::Cancel),
        ui_kit::Action::None => answer,
    };
    if ctx.input(|x| x.key_pressed(egui::Key::Escape)) {
        answer = Some(Answer::Cancel);
        app.esc_handled = true;
    }
    if let Some(a) = answer {
        answer_prompt(app, a);
    }
}

/// Act on the "save changes?" answer (also the control channel's `ui.documents {answer}`).
pub fn answer_prompt(app: &mut SolveApp, answer: Answer) {
    if app.file_picker_busy() {
        return;
    }
    let Some(i) = app.docs.closing else { return };
    app.docs.choice = Answer::Save;
    match answer {
        Answer::Save => {
            switch(app, i);
            app.docs.saving = true;
            crate::toolbar::save(app);
            if !app.file_picker_busy() {
                saved_for_close(app);
            }
        }
        Answer::DontSave => {
            if let Some(skip) = app.docs.quitting.as_mut() {
                skip.push(i);
                app.docs.closing = None;
            } else {
                close(app, i, true);
            }
        }
        Answer::Cancel => {
            app.docs.closing = None;
            app.docs.quitting = None;
            app.docs.batch = None;
        }
    }
    quit_step(app);
    batch_step(app);
}

/// Resume Close/Quit only after Save As has answered and the write succeeded.
pub(crate) fn saved_for_close(app: &mut SolveApp) {
    if !std::mem::take(&mut app.docs.saving) || app.docs.closing.is_none() {
        return;
    }
    let saved = !app.session.is_dirty();
    app.docs.closing = None;
    if app.docs.quitting.is_some() {
        if !saved {
            app.docs.quitting = None;
        }
    } else if saved {
        close(app, app.docs.active, true);
    } else {
        // Save As cancelled: the tabs not closed yet stay.
        app.docs.batch = None;
    }
    quit_step(app);
    batch_step(app);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Services;
    use egui::Color32;

    #[test]
    fn pdm_tab_home_opens_one_browser_without_creating_a_design_file() {
        let mut h = crate::scenario::Harness::new();
        h.app.home.show(h.app.session.revision);
        h.frames(3);
        assert!(crate::scenario::handles("tab:pdm").is_empty(), "PDM does not occupy a document tab before explicit use");
        let original = h.app.session.doc.clone();
        let count = h.app.docs.count();
        h.step(&json!({"click":{"handle":"home:pdm"}})).unwrap();
        h.frames(3);
        assert!(h.app.pdm.workspace_active && !h.app.home.open);
        assert_eq!(h.app.docs.count(), count);
        assert_eq!(*h.app.session.doc, *original);
        assert!(h.app.session.path.is_none() && !h.app.session.is_dirty());
        for _ in 0..2 {
            h.step(&json!({"click":{"handle":"tab:pdm"}})).unwrap();
            h.frames(2);
        }
        assert_eq!(crate::scenario::handles("tab:pdm").len(), 1);
        assert_eq!(h.app.docs.count(), count);
        h.step(&json!({"click":{"handle":"tab:home"}})).unwrap();
        h.frames(2);
        assert!(h.app.home.open && !h.app.pdm.workspace_active);
        assert!(crate::scenario::handle_at("home:pdm").is_some());
    }

    #[test]
    fn pdm_tab_preserves_document_render_workspace_memory_and_browser_navigation() {
        let mut h = crate::scenario::Harness::new();
        h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
        h.app.ui.tab = "RENDER".into();
        h.app.cam.distance = 42.0;
        let original = h.app.session.doc.clone();
        let undo = h.app.session.undo.len();
        h.app.pdm.folder = "Projects".into();
        h.app.pdm.document = "part".into();
        crate::pdm_panel::enter(&mut h.app).unwrap();
        h.frames(2);
        h.step(&json!({"click":{"handle":"tab:design:0"}})).unwrap();
        h.frames(2);
        assert!(!h.app.pdm.workspace_active && !h.app.home.open);
        assert_eq!(h.app.ui.tab, "RENDER");
        assert_eq!(*h.app.session.doc, *original);
        assert_eq!(h.app.session.undo.len(), undo);
        assert_eq!(h.app.cam.distance, 42.0);
        assert!(h.app.session.is_dirty());
        h.step(&json!({"click":{"handle":"tab:pdm"}})).unwrap();
        h.frames(2);
        assert!(h.app.pdm.workspace_active);
        assert_eq!(h.app.pdm.folder, "Projects");
        assert_eq!(h.app.pdm.document, "part");
    }

    #[test]
    fn pdm_tab_first_native_working_load_does_not_create_a_dummy_document_tab() {
        let mut h = crate::scenario::Harness::new();
        h.app.home.show(h.app.session.revision);
        crate::pdm_panel::enter(&mut h.app).unwrap();
        let mut loaded = Session::default();
        loaded.path = Some("Working/part.solidcraft".into());
        loaded.mark_saved();
        apply_managed(&mut h.app, loaded).unwrap();
        assert_eq!(h.app.docs.count(), 1);
        assert_eq!(h.app.session.path.as_deref(), Some("Working/part.solidcraft"));
        assert!(!h.app.home.open);
    }

    #[test]
    fn pdm_tab_last_document_close_and_ctrl_w_preserve_the_connection() {
        use solidcraft_engine::pdm::{Outcome, Task};
        let mut h = crate::scenario::Harness::new();
        h.app.services.pdm = Some(std::sync::Arc::new(|_| std::sync::mpsc::channel().1));
        h.app.pdm.runtime.set_available(true).unwrap();
        let id = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
        h.app.pdm.runtime.finish(id, Ok(Outcome::Connected { port: 48231, versions: vec![] })).unwrap();
        h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
        crate::pdm_panel::enter(&mut h.app).unwrap();
        // Select a folder after entering the authenticated browser context.
        h.app.pdm.folder = "Projects".into();
        close(&mut h.app, 0, true);
        h.frames(2);
        assert!(h.app.pdm.workspace_active && !h.app.home.open);
        assert!(h.app.session.path.is_none() && h.app.session.doc.features.is_empty());
        assert_eq!(h.app.pdm.runtime.status().unwrap().port, Some(48231));
        h.step(&json!({"key":"W","cmd":true})).unwrap();
        h.frames(2);
        assert!(h.app.home.open && !h.app.pdm.workspace_active);
        assert_eq!(h.app.pdm.runtime.status().unwrap().port, Some(48231));
        h.step(&json!({"click":{"handle":"tab:pdm"}})).unwrap();
        h.frames(2);
        assert_eq!(h.app.pdm.folder, "Projects");
    }

    fn app() -> SolveApp {
        SolveApp::new(Session::default(), Services::default())
    }

    /// Each tab keeps its own design, undo, selection and camera; closing asks when there are
    /// unsaved changes; the last tab closing leaves a blank design.
    #[test]
    fn the_tab_strip_overflows_into_a_list_keeping_the_active_tab() {
        assert_eq!(layout(2, 0, 800.0), (0, 2, 220.0));
        let (first, shown, w) = layout(12, 11, 600.0);
        assert!(shown < 12 && w == 90.0);
        assert!((first..first + shown).contains(&11), "the active tab stays visible");
        assert!(shown as f32 * w + 26.0 + 34.0 <= 600.0 + 0.5);
        assert_eq!(layout(12, 0, 600.0).0, 0);
    }

    /// Active and hovered document tabs keep the bar's light text readable in both themes.
    #[test]
    fn title_bar_tabs_keep_their_text_readable_on_hover() {
        fn luminance(c: Color32) -> f32 {
            let c = egui::Rgba::from(c);
            0.2126 * c.r() + 0.7152 * c.g() + 0.0722 * c.b()
        }
        // egui blends premultiplied colours in gamma space.
        fn over(top: Color32, bottom: Color32) -> Color32 {
            let ch = |t: u8, b: u8| t.saturating_add(((u16::from(b) * u16::from(255 - top.a())) / 255) as u8);
            Color32::from_rgb(ch(top.r(), bottom.r()), ch(top.g(), bottom.g()), ch(top.b(), bottom.b()))
        }
        for t in [Tokens::light(), Tokens::dark()] {
            let r = Rect::from_min_size(pos2(10.0, 5.0), vec2(80.0, 30.0));
            for (active, hovered) in [(false, false), (false, true), (true, false)] {
                let ctx = crate::fonts::test_context();
                let mut out = ctx.run_ui(egui::RawInput::default(), |ui| tab_shape(ui.painter(), &t, r, active, hovered));
                out.textures_delta.clear();
                let rects: Vec<_> = out
                    .shapes
                    .iter()
                    .filter_map(|s| match &s.shape {
                        egui::Shape::Rect(rect) => Some((rect.clone(), s.clip_rect)),
                        _ => None,
                    })
                    .collect();
                let fill = rects.iter().find(|(rect, _)| rect.fill.a() > 0).map(|(rect, _)| rect.fill).unwrap_or_default();
                let bg = over(fill, t.app_bar);
                let (hi, lo) = (luminance(t.app_bar_text).max(luminance(bg)), luminance(t.app_bar_text).min(luminance(bg)));
                assert!((hi + 0.05) / (lo + 0.05) >= 4.5, "text on a tab (hovered: {hovered}) must stay readable: {bg:?} {t:?}");
                assert!(rects.iter().all(|(rect, _)| rect.stroke.width == 0.0), "tabs have no outline (active: {active})");
            }
        }
    }

    /// Four tabs: the first and third with a part (unsaved), the second and fourth blank.
    fn four_tabs() -> SolveApp {
        let mut a = app();
        a.run("solid.box", json!({"length": 10, "width": 10, "height": 10})).unwrap();
        open_tab(&mut a, Session::default()).unwrap();
        open_tab(&mut a, Session::default()).unwrap();
        a.run("solid.box", json!({"length": 5, "width": 5, "height": 5})).unwrap();
        open_tab(&mut a, Session::default()).unwrap();
        assert_eq!(a.docs.count(), 4);
        a
    }

    /// #3055: Close Other Tabs on the first tab closes the blank fourth, asks about the third
    /// (unsaved), and after Don't Save closes it and the blank second: the first is left, its
    /// part as it was.
    #[test]
    fn close_other_tabs_asks_about_unsaved_ones_and_keeps_the_tab() {
        let mut a = four_tabs();
        let v = control(&mut a, &json!({"action": "close_others", "index": 0}));
        assert_eq!(v["closing"], json!(2), "{v}");
        assert_eq!(a.docs.count(), 3, "the blank fourth closed without asking");
        let v = control(&mut a, &json!({"answer": "dont_save"}));
        assert_eq!(a.docs.count(), 1, "{v}");
        assert!(a.docs.closing.is_none() && a.docs.batch.is_none());
        let volume = a.run("inspect.measure", json!({})).unwrap()["total"]["volume_mm3"].as_f64().unwrap();
        assert!((volume - 1000.0).abs() < 1e-6, "the first tab's part: {volume}");
    }

    /// #3055: Close All Tabs, and Cancel at the first question: the tabs not closed yet stay.
    /// Close All Tabs on blank designs leaves one blank design.
    #[test]
    fn close_all_tabs_stops_at_cancel_and_ends_on_a_blank_design() {
        let mut a = four_tabs();
        control(&mut a, &json!({"action": "close_all"}));
        assert_eq!((a.docs.count(), a.docs.closing), (3, Some(2)));
        control(&mut a, &json!({"answer": "cancel"}));
        assert_eq!((a.docs.count(), a.docs.closing, a.docs.batch.clone()), (3, None, None), "Cancel keeps the rest");
        control(&mut a, &json!({"action": "close_all"}));
        control(&mut a, &json!({"answer": "dont_save"}));
        control(&mut a, &json!({"answer": "dont_save"}));
        assert_eq!(a.docs.count(), 1);
        assert!(active_is_blank(&a), "all closed: a blank design");
    }

    /// #3055: a right-click on a tab opens its menu; Close Other Tabs from it keeps that tab.
    #[test]
    fn a_tab_right_clicked_offers_close_others() {
        let mut h = crate::scenario::Harness::new();
        h.app.home.open = false;
        h.app.custom_titlebar = true;
        h.call("ui.resize", json!({"width": 1400, "height": 720}));
        open_tab(&mut h.app, Session::default()).unwrap();
        open_tab(&mut h.app, Session::default()).unwrap();
        assert_eq!(h.app.docs.count(), 3);
        h.frames(3);
        h.step(&json!({"click": {"handle": "tab:design:1"}, "button": "right"})).unwrap();
        h.frames(2);
        h.step(&json!({"click": {"handle": "tab_menu:ui.closeOtherTabs"}})).unwrap();
        h.frames(2);
        assert_eq!(h.app.docs.count(), 1);
    }

    #[test]
    fn tabs_keep_their_own_design() {
        let mut a = app();
        a.run("solid.box", json!({"length": 10, "width": 10, "height": 10})).unwrap();
        a.session.selection = vec![solidcraft_engine::Sel::Body { name: "Body1".into() }];
        a.cam.distance = 123.0;
        new_design(&mut a);
        assert_eq!(a.docs.count(), 2);
        assert_eq!(a.docs.active, 1);
        assert!(a.session.doc.features.is_empty() && a.session.selection.is_empty());
        a.run("solid.sphere", json!({"diameter": 8})).unwrap();
        a.run("solid.sphere", json!({"diameter": 4})).unwrap();
        switch(&mut a, 0);
        assert_eq!(a.session.doc.features.len(), 1);
        assert_eq!(a.session.selection.len(), 1);
        assert!((a.cam.distance - 123.0).abs() < 1e-9);
        a.run("edit.undo", json!({})).unwrap();
        assert!(a.session.doc.features.is_empty(), "undo is this design's");
        switch(&mut a, 1);
        assert_eq!(a.session.doc.features.len(), 2, "the other design kept its features");
        // Unsaved: closing asks, Don't Save closes.
        close(&mut a, 1, false);
        assert_eq!(a.docs.closing, Some(1));
        assert_eq!(a.docs.count(), 2);
        close(&mut a, 1, true);
        assert_eq!(a.docs.count(), 1);
        assert_eq!(a.docs.active, 0);
        close(&mut a, 0, true);
        assert!(active_is_blank(&a) && a.home.open);
    }

    /// Direct tab creation remains available, including reuse of an untouched launch design.
    #[test]
    fn direct_new_tab_reuses_the_launch_design_then_opens_a_tab_every_time() {
        let mut a = app();
        a.home.open = true;
        new_tab(&mut a);
        assert_eq!(a.docs.count(), 1, "the launch's blank design is used");
        assert!(!a.home.open);
        new_tab(&mut a);
        new_tab(&mut a);
        assert_eq!(a.docs.count(), 3);
        assert_eq!(a.docs.active, 2);
    }

    /// Quitting asks once per design with unsaved changes: Don't Save moves on (and keeps no
    /// recovery copy), Save saves and moves on, and the app quits after the last answer.
    #[test]
    fn quit_asks_about_each_unsaved_design_then_quits() {
        let mut a = app();
        request_quit(&mut a);
        assert!(a.quit_requested, "nothing unsaved: quits at once");

        let mut a = app();
        let file = std::env::temp_dir().join(format!("solidcraft-quit-save-{}.solidcraft", std::process::id()));
        let _ = std::fs::remove_file(&file);
        a.run("solid.box", json!({"length": 10, "width": 10, "height": 10})).unwrap();
        a.run("file.save_as", json!({"path": file.to_string_lossy()})).unwrap();
        a.run("solid.sphere", json!({"diameter": 4})).unwrap();
        new_design(&mut a);
        a.run("solid.sphere", json!({"diameter": 8})).unwrap();
        assert!(dirty(&a, 0) && dirty(&a, 1));

        request_quit(&mut a);
        assert!(!a.quit_requested);
        assert_eq!(a.docs.closing, Some(0), "the first unsaved design is asked about first");
        assert_eq!(a.docs.active, 0, "and shown");
        answer_prompt(&mut a, Answer::Save);
        crate::save_job::tick(&mut a, true);
        assert!(!dirty(&a, 0), "saved");
        assert_eq!(
            std::fs::read(&file).ok().and_then(|b| solidcraft_engine::io::read_design(&b).ok()).map(|d| d.features.len()),
            Some(2),
            "the file holds the change"
        );
        assert_eq!(a.docs.closing, Some(1), "then the next one");
        assert!(!a.quit_requested);
        answer_prompt(&mut a, Answer::DontSave);
        assert_eq!(a.docs.closing, None);
        assert!(a.quit_requested, "every design answered: quit");
        assert!(!any_dirty(&a), "Don't Save discards: nothing is kept for recovery");
        let _ = std::fs::remove_file(&file);
    }

    /// Cancel, Esc's answer, or a Save that saves nothing (a never-saved design whose Save As
    /// picker is cancelled) stay open with the changes.
    #[test]
    fn quit_cancelled_or_unsaved_stays_open() {
        let mut a = app();
        a.run("solid.box", json!({"length": 10, "width": 10, "height": 10})).unwrap();
        request_quit(&mut a);
        assert_eq!(a.docs.closing, Some(0));
        answer_prompt(&mut a, Answer::Cancel);
        assert!(!a.quit_requested && a.docs.closing.is_none() && a.docs.quitting.is_none());
        assert!(a.session.is_dirty(), "the changes are still there");

        // No Save As picker answer (the default services have none): not saved, so no quit.
        request_quit(&mut a);
        answer_prompt(&mut a, Answer::Save);
        assert!(!a.quit_requested && a.docs.quitting.is_none() && a.session.is_dirty());

        // A picked file: saved, then quit.
        let file = std::env::temp_dir().join(format!("solidcraft-quit-saveas-{}.solidcraft", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let to = file.to_string_lossy().to_string();
        a.services.pick_save = Some(Box::new(move |_: &str, _: &[&str], _initial_directory| Box::pin(std::future::ready(Some(to.clone())))));
        request_quit(&mut a);
        answer_prompt(&mut a, Answer::Save);
        assert!(!a.quit_requested && a.file_picker_busy());
        crate::file_picker::tick(&mut a, &crate::fonts::test_context());
        crate::save_job::tick(&mut a, true);
        assert!(a.quit_requested && file.exists());
        let _ = std::fs::remove_file(&file);
    }

    /// #680: "Project face edges into new sketches" is a preference: it holds in new tabs, in
    /// the tab switched to, in a design adopted over a blank one and after the last tab closes,
    /// and it is what the preferences file keeps.
    #[test]
    fn auto_project_follows_the_user_across_tabs() {
        let mut a = app();
        a.run("solid.box", json!({"length": 10, "width": 10, "height": 10})).unwrap();
        a.run("sketch.auto_project", json!({"value": false})).unwrap();
        new_design(&mut a);
        assert_eq!(a.docs.count(), 2);
        assert!(!a.session.auto_project, "a new tab");
        a.run("solid.box", json!({"length": 5, "width": 5, "height": 5})).unwrap();
        a.run("sketch.auto_project", json!({"value": true})).unwrap();
        switch(&mut a, 0);
        assert!(a.session.auto_project, "the tab switched to");
        a.run("sketch.auto_project", json!({"value": false})).unwrap();
        switch(&mut a, 1);
        assert!(!a.session.auto_project);
        let prefs: Value = serde_json::from_str(&a.prefs()).unwrap();
        assert_eq!(prefs["auto_project"], false);
        close(&mut a, 1, true);
        close(&mut a, 0, true);
        assert!(active_is_blank(&a) && !a.session.auto_project, "after the last tab closes");
        adopt(&mut a, Session::default());
        assert_eq!(a.docs.count(), 1);
        assert!(!a.session.auto_project, "a design adopted over a blank one");
    }

    /// #1205: Units of new designs apply to the empty design a launch shows, to New while that
    /// design is still empty, to `file.new`, and to the blank design left when the last tab closes.
    /// A design that already has features keeps its units.
    #[test]
    fn new_designs_use_the_preferred_units_including_a_blank_one() {
        let mut a = app();
        a.preferences.default_units = "in".into();
        assert_eq!(a.session.doc.units, "mm");
        // What a launch with no file does after reading preferences.
        crate::prefs::apply_new_design(&mut a);
        assert_eq!(a.session.doc.units, "in");
        assert!(!a.session.is_dirty());
        assert!(active_is_blank(&a));
        let tabs = a.docs.count();
        new_design(&mut a);
        assert_eq!(a.docs.count(), tabs, "New on an empty design does not open another tab");
        assert_eq!(a.session.doc.units, "in");
        assert!(!a.session.is_dirty());
        // Geometry already there is left alone. New then opens a tab in the preferred units.
        a.run("solid.box", json!({"length": 25.4, "width": 25.4, "height": 25.4})).unwrap();
        assert_eq!(a.session.doc.units, "in");
        a.preferences.default_units = "ft".into();
        new_design(&mut a);
        assert_eq!(a.docs.count(), tabs + 1);
        assert_eq!(a.session.doc.units, "ft");
        assert!(a.session.doc.features.is_empty());
        assert!(!a.session.is_dirty());
        a.run("file.new", json!({"name": "From command"})).unwrap();
        assert_eq!(a.session.doc.units, "ft");
        assert_eq!(a.session.doc.name, "From command");
        assert!(!a.session.is_dirty());
        // Closing every tab leaves a blank design in the preferred units.
        assert_eq!(a.docs.count(), 2);
        let active = a.docs.active;
        close(&mut a, active, true);
        assert_eq!(a.docs.count(), 1);
        assert!(!a.session.doc.features.is_empty(), "the other tab still has its part");
        close(&mut a, 0, true);
        assert!(active_is_blank(&a));
        assert_eq!(a.session.doc.units, "ft");
        assert!(!a.session.is_dirty());
    }

    /// A design built elsewhere replaces a blank one and gets a tab otherwise.
    #[test]
    fn adopt_reuses_a_blank_design() {
        let mut a = app();
        let mut s = Session::default();
        s.run_script(&solidcraft_engine::sample::script()).unwrap();
        adopt(&mut a, s);
        assert_eq!(a.docs.count(), 1);
        assert!(!a.session.doc.features.is_empty());
        adopt(&mut a, Session::default());
        assert_eq!(a.docs.count(), 2);
        let v = control(&mut a, &json!({"action": "switch", "index": 0}));
        assert_eq!(v["active"], 0);
        assert_eq!(v["documents"].as_array().map(Vec::len), Some(2));
    }

    fn ram_graph_fixture() -> (crate::scenario::Harness, std::path::PathBuf, std::path::PathBuf, solidcraft_engine::pdm::ManagedState) {
        use solidcraft_engine::pdm::{CatalogEntry, Checkout, LocalEntry, ManagedState, Outcome, Task};
        let mut h = crate::scenario::Harness::new();
        let root = h.dir.join("Working");
        std::fs::create_dir(&root).unwrap();
        let child = root.join("child.solidcraft");
        let assembly = root.join("assembly.solidcraft");
        h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
        h.app.run("file.save", json!({"path":child})).unwrap();
        open_tab(&mut h.app, Session::default()).unwrap();
        h.app.run("file.save", json!({"path":assembly})).unwrap();
        h.app.run("component.insert_design", json!({"path":child})).unwrap();
        h.app.run("file.save", json!({})).unwrap();
        let mut state = ManagedState {
            root: Some(root.to_string_lossy().into_owned()),
            server_id: Some("ram-server".into()),
            workspace: Some("ram-workspace".into()),
            ..Default::default()
        };
        for (id, path) in [("child", &child), ("assembly", &assembly)] {
            state.catalog.push(CatalogEntry {
                document: id.into(),
                logical_path: format!("{id}.solidcraft"),
                head: Some(1),
                checkout: Some(Checkout {
                    owner: "alice".into(),
                    workspace: "ram-workspace".into(),
                    machine: "desktop".into(),
                    checked_out_unix_ms: 1,
                    base_version: Some(1),
                }),
                head_checked_in_unix_ms: None,
                head_author: None,
            });
            state.local.push(LocalEntry {
                document: id.into(),
                path: path.to_string_lossy().into_owned(),
                relative_path: format!("{id}.solidcraft"),
                base_version: 1,
                sha256: "ab".repeat(32),
                checked_out: true,
                modified: false,
                present: true,
            });
        }
        let reply = state.clone();
        h.app.services.pdm = Some(std::sync::Arc::new(move |_| {
            let (send, receive) = std::sync::mpsc::channel();
            send.send(crate::pdm_panel::Completion { result: Ok(Outcome::Managed { port: 48231, state: reply.clone() }), open: None }).unwrap();
            receive
        }));
        h.app.pdm.runtime.set_available(true).unwrap();
        let id = h.app.pdm.runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
        h.app.pdm.runtime.finish(id, Ok(Outcome::Managed { port: 48231, state: state.clone() })).unwrap();
        h.app.session.pdm = h.app.pdm.runtime.clone();
        (h, child, assembly, state)
    }

    #[test]
    fn recursive_archive_saves_dirty_inactive_component_ram_before_root_publication() {
        let (mut h, child, assembly, _) = ram_graph_fixture();
        switch(&mut h.app, 0);
        h.app.session.doc_mut().name = "Unsaved component RAM".into();
        h.app.run("solid.box", json!({"length":1,"width":1,"height":1})).unwrap();
        switch(&mut h.app, 1);
        assert!(!h.app.session.is_dirty());
        h.app.run("pdm.archive", json!({"document":"assembly"})).unwrap();
        assert!(h.app.saving.is_some(), "a clean assembly still needs its open dirty component saved first");
        while h.app.saving.is_some() {
            crate::save_job::tick(&mut h.app, true);
        }
        h.frames(4);
        assert_eq!(solidcraft_engine::io::read_design(&std::fs::read(child).unwrap()).unwrap().name, "Unsaved component RAM");
        assert_eq!(solidcraft_engine::io::read_design(&std::fs::read(assembly).unwrap()).unwrap(), *h.app.session.doc);
        assert!(!h.app.session.is_dirty());
        assert!(!h.app.docs.slots[0].as_ref().unwrap().session.is_dirty());
    }

    #[test]
    fn recursive_archive_external_component_is_rejected_before_any_autosave() {
        let (mut h, child, assembly, _) = ram_graph_fixture();
        let external = h.dir.join("external.solidcraft");
        std::fs::copy(&child, &external).unwrap();
        h.app.session.doc_mut().links.values_mut().next().unwrap().path = "../external.solidcraft".into();
        h.app.session.doc_mut().name = "Unsaved assembly".into();
        let before = std::fs::read(&assembly).unwrap();
        assert!(h.app.run("pdm.archive", json!({"document":"assembly"})).is_err());
        assert!(h.app.saving.is_none());
        assert_eq!(std::fs::read(assembly).unwrap(), before);
        assert!(h.app.session.is_dirty());
    }

    #[test]
    fn recursive_archive_component_completion_refreshes_dirty_open_assembly_without_saving_it() {
        use solidcraft_engine::pdm::{Outcome, Task};
        let (mut h, child, assembly, mut state) = ram_graph_fixture();
        state.local.iter_mut().find(|entry| entry.document == "assembly").unwrap().checked_out = false;
        state.catalog.iter_mut().find(|entry| entry.document == "assembly").unwrap().checkout = None;
        let id = h.app.pdm.runtime.enqueue(Task::Refresh).unwrap();
        h.app.pdm.runtime.finish(id, Ok(Outcome::ManagedRefreshed { port: 48231, state: state.clone() })).unwrap();
        h.app.services.pdm = Some(std::sync::Arc::new(move |_| {
            let (send, receive) = std::sync::mpsc::channel();
            send.send(crate::pdm_panel::Completion { result: Ok(Outcome::Managed { port: 48231, state: state.clone() }), open: None }).unwrap();
            receive
        }));
        h.app.session.doc_mut().name = "Keep my unsaved assembly edits".into();
        let before = h.app.session.doc.clone();
        let undo = h.app.session.undo.len();
        let disk = std::fs::read(&assembly).unwrap();
        switch(&mut h.app, 0);
        h.app.run("solid.box", json!({"length":5,"width":6,"height":7})).unwrap();
        h.app.run("file.save", json!({})).unwrap();
        h.app.run("pdm.archive", json!({"document":"child"})).unwrap();
        while h.app.saving.is_some() {
            crate::save_job::tick(&mut h.app, true);
        }
        h.frames(4);
        let linked = &h.app.docs.slots[1].as_ref().unwrap().session;
        assert_eq!(linked.doc.name, "Keep my unsaved assembly edits");
        assert_ne!(*linked.doc, *before, "component completion must refresh cached linked geometry");
        assert!(linked.is_dirty());
        assert!(linked.undo.len() >= undo);
        assert_eq!(std::fs::read(assembly).unwrap(), disk, "derived refresh must not save or archive the parent");
        assert!(child.exists());
    }
}
