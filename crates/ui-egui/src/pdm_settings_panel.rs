//! Client settings inside the explicitly opened PDM tab.
//! Client folder association changes only after a successful native commit.
use crate::{SolveApp, documents, theme::Tokens};
use serde_json::json;
use solidcraft_engine::pdm::{ConnectionStage, Status};

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    authentication_epoch: u64,
    connection: String,
    account: String,
    server: String,
    workspace: String,
    root: String,
}
impl Identity {
    fn current(status: &Status) -> Option<Self> {
        status.port?;
        let connection = status.connection.as_ref()?;
        let server = status.managed.server_id.as_ref()?;
        if server != &connection.server_id {
            return None;
        }
        Some(Self {
            authentication_epoch: status.authentication_epoch,
            connection: connection.id.clone(),
            account: connection.account.clone(),
            server: server.clone(),
            workspace: status.managed.workspace.clone()?,
            root: status.managed.root.clone()?,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PickerTicket {
    identity: Identity,
    generation: u64,
}

#[derive(Default)]
pub struct State {
    pub(crate) candidate: String,
    identity: Option<Identity>,
    generation: u64,
    picker: Option<PickerTicket>,
}
impl State {
    fn invalidate_picker(&mut self) {
        self.picker = None;
        self.generation = self.generation.saturating_add(1);
    }
    fn sync(&mut self, status: &Status) {
        let current = Identity::current(status);
        if self.identity != current {
            self.invalidate_picker();
            self.identity = current;
            self.candidate.clear();
        }
    }
    fn ticket(&mut self, status: &Status) -> Option<PickerTicket> {
        self.sync(status);
        if self.generation == u64::MAX {
            return None;
        }
        self.invalidate_picker();
        let ticket = PickerTicket { identity: self.identity.clone()?, generation: self.generation };
        self.picker = Some(ticket.clone());
        Some(ticket)
    }
    fn accept_picker(&mut self, status: &Status, ticket: &PickerTicket, page_open: bool, path: Option<String>) {
        self.sync(status);
        if !page_open
            || self.picker.as_ref() != Some(ticket)
            || self.identity.as_ref() != Some(&ticket.identity)
            || self.generation != ticket.generation
        {
            return;
        }
        self.picker = None;
        if let Some(path) = path {
            self.candidate = path;
        }
    }
}

pub(super) fn open(app: &mut SolveApp) -> Result<(), String> {
    if !app.pdm.workspace_active {
        super::enter(app)?;
    }
    let status = app.pdm.runtime.status()?;
    app.pdm.settings.sync(&status);
    app.pdm.settings.invalidate_picker();
    app.pdm.settings_open = true;
    app.pdm.open = false;
    Ok(())
}

pub(super) fn invalidate_picker(app: &mut SolveApp) {
    app.pdm.settings.invalidate_picker();
}

pub(super) fn close(app: &mut SolveApp) {
    invalidate_picker(app);
    app.pdm.settings_open = false;
    // Keep the PDM tab, selected archive folder, documents and camera intact.
}

fn busy(app: &SolveApp, status: &Status) -> bool {
    app.file_picker_busy() || app.file_load.busy() || status.busy.is_some()
}

fn change_unavailable(app: &SolveApp, status: &Status) -> Option<&'static str> {
    if busy(app, status) {
        return Some("ui.pdm_reason_busy");
    }
    if !status.available {
        return Some("ui.pdm_reason_unavailable");
    }
    if Identity::current(status).is_none() {
        return Some("ui.pdm_reason_disconnected");
    }
    if documents::any_managed_open(app) {
        return Some("ui.pdm_workspace_close_editors");
    }
    if let Some(reason) = status.action_unavailable("pdm.workspace.change", None, Some(&app.pdm.settings.candidate), false, false, None) {
        return Some(reason);
    }
    if !std::path::Path::new(&app.pdm.settings.candidate).is_absolute() || app.pdm.settings.candidate.chars().any(char::is_control) {
        return Some("ui.pdm_workspace_empty_folder");
    }
    None
}

fn choose_folder(app: &mut SolveApp) {
    let Ok(status) = app.pdm.runtime.status() else {
        return;
    };
    if busy(app, &status) || !status.available || app.services.pick_folder.is_none() {
        return;
    }
    let Some(ticket) = app.pdm.settings.ticket(&status) else {
        return;
    };
    let initial = if std::path::Path::new(&app.pdm.settings.candidate).is_absolute() {
        app.pdm.settings.candidate.clone()
    } else {
        ticket.identity.root.clone()
    };
    app.pick_folder(Some(&initial), move |app, path| {
        let Ok(status) = app.pdm.runtime.status() else {
            return;
        };
        let page_open = app.pdm.settings_open && app.pdm.workspace_active;
        app.pdm.settings.accept_picker(&status, &ticket, page_open, path);
    });
}

fn apply(app: &mut SolveApp) {
    let Ok(status) = app.pdm.runtime.status() else {
        return;
    };
    app.pdm.settings.sync(&status);
    if let Some(reason) = change_unavailable(app, &status) {
        app.set_status(app.tr(reason).to_string(), true);
        return;
    }
    let Some(identity) = app.pdm.settings.identity.clone() else {
        return;
    };
    let path = app.pdm.settings.candidate.clone();
    // No optimistic root/input update. The native command owns empty-directory,
    // path integrity, grant, atomic-association and expected-workspace checks.
    super::dispatch(
        app,
        "pdm.workspace.change",
        json!({
            "connection_id":identity.connection, "path":path, "expected_workspace":identity.workspace
        }),
    );
}

fn section_title(app: &SolveApp, ui: &mut egui::Ui, key: &str, icon: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
        crate::icons::paint_icon(ui.painter(), rect, icon, 1.0);
        ui.strong(app.tr(key));
    });
}

pub(super) fn show(app: &mut SolveApp, ui: &mut egui::Ui) {
    let Ok(status) = app.pdm.runtime.status() else {
        return;
    };
    let status = &status;
    app.pdm.settings.sync(status);
    let t = Tokens::get();
    let idle = status.available && !busy(app, status);
    egui::Frame::new().fill(t.panel).inner_margin(16.0).show(ui, |ui| {
        ui.set_min_size(ui.available_size());
        ui.horizontal_wrapped(|ui| {
            let back = ui.add(egui::Button::new(app.tr("ui.back")).min_size(egui::vec2(0.0, 30.0)));
            super::handle("settings_back", &back);
            if back.clicked() {
                close(app);
            }
            ui.heading(app.tr("cmd.pdm_settings"));
        });
        ui.add_space(12.0);
        egui::ScrollArea::vertical().id_salt("pdm_client_settings").auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width(ui.available_width().min(760.0));
            ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);
            egui::Frame::group(ui.style()).inner_margin(12.0).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                section_title(app, ui, "ui.pdm_connected_archive", "library");
                if let Some(connection) = &status.connection {
                    ui.label(egui::RichText::new(&connection.label).size(18.0).strong());
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("{} · {}", connection.account, connection.role));
                        ui.label(egui::RichText::new(app.tr("ui.pdm_connected")).color(t.accent));
                    });
                    ui.add(egui::Label::new(&connection.origin).truncate().selectable(true)).on_hover_text(&connection.origin);
                } else {
                    ui.label(app.tr("ui.pdm_connection_offline"));
                }
            });
            ui.add_space(4.0);
            egui::Frame::group(ui.style()).inner_margin(12.0).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                section_title(app, ui, "ui.pdm_working_folder", "folder");
                ui.label(egui::RichText::new(app.tr("ui.pdm_current_folder")).color(t.text_dim));
                let root = status.managed.root.as_deref().unwrap_or("—");
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if super::action_button(
                            app,
                            ui,
                            "settings_copy_current",
                            "ui.copy",
                            "copy",
                            status.managed.root.is_none().then_some("ui.pdm_reason_disconnected"),
                            "settings_copy_current",
                        ) {
                            ui.ctx().copy_text(root.to_string());
                        }
                        let path = ui.add_sized(egui::vec2(ui.available_width(), 30.0), egui::Label::new(root).truncate().selectable(true));
                        path.on_hover_text(root);
                    })
                });
                ui.add_space(4.0);
                ui.label(app.tr("ui.pdm_new_folder"));
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let reason = if !status.available || app.services.pick_folder.is_none() {
                            Some("ui.pdm_reason_unavailable")
                        } else if busy(app, status) {
                            Some("ui.pdm_reason_busy")
                        } else if Identity::current(status).is_none() {
                            Some("ui.pdm_reason_disconnected")
                        } else {
                            None
                        };
                        if super::action_button(app, ui, "settings_choose_folder", "ui.pdm_choose_folder", "folder", reason, "settings_choose_folder")
                        {
                            choose_folder(app);
                        }
                        let hint = app.tr("ui.path").to_string();
                        let candidate = ui.add_enabled(
                            idle,
                            egui::TextEdit::singleline(&mut app.pdm.settings.candidate)
                                .hint_text(hint)
                                .desired_width(ui.available_width())
                                .min_size(egui::vec2(0.0, 30.0)),
                        );
                        super::handle("settings_candidate", &candidate);
                    })
                });
                ui.add(egui::Label::new(app.tr("ui.pdm_workspace_empty_folder")).wrap());
                let reason = change_unavailable(app, status);
                if super::action_button(app, ui, "settings_apply", "ui.apply", "save", reason, "settings_apply") {
                    apply(app);
                }
                if let Some(reason) = reason.filter(|reason| *reason != "ui.pdm_workspace_empty_folder") {
                    ui.add(egui::Label::new(egui::RichText::new(app.tr(reason)).color(t.text_dim)).wrap());
                }
                if let Some(error) = status.error.as_deref().or_else(|| {
                    app.pdm.notice.as_ref().filter(|notice| notice.action == "cmd.pdm_workspace_change").and_then(|notice| notice.error.as_deref())
                }) {
                    ui.add(egui::Label::new(egui::RichText::new(app.tr(error)).color(t.error)).wrap());
                }
            });
            ui.add_space(4.0);
            egui::Frame::group(ui.style()).inner_margin(12.0).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                section_title(app, ui, "ui.pdm_recent_connections", "library");
                ui.horizontal_wrapped(|ui| {
                    let reason = (!idle).then_some("ui.pdm_reason_busy");
                    if super::action_button(
                        app,
                        ui,
                        "settings_refresh_connections",
                        "ui.pdm_refresh_connections",
                        "update",
                        reason,
                        "settings_refresh_connections",
                    ) {
                        super::dispatch(app, "pdm.connections", json!({}));
                    }
                    if super::action_button(
                        app,
                        ui,
                        "settings_manage_connections",
                        "cmd.pdm_connections",
                        "settings",
                        reason,
                        "settings_manage_connections",
                    ) {
                        app.pdm.open = true;
                    }
                });
                if status.connections.is_empty() {
                    ui.label(app.tr("ui.pdm_no_connections"));
                }
                for connection in &status.connections {
                    let connected = status.connection.as_ref().is_some_and(|active| active.id == connection.id);
                    egui::Frame::new().fill(if connected { t.accent_soft } else { t.panel }).inner_margin(8.0).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            ui.strong(&connection.label);
                            let key = if connected {
                                "ui.pdm_connected"
                            } else {
                                match connection.stage {
                                    ConnectionStage::Pending => "ui.pdm_setup_incomplete",
                                    ConnectionStage::SavedUnverified => "ui.pdm_saved_unverified",
                                }
                            };
                            ui.label(egui::RichText::new(app.tr(key)).color(if connected { t.accent } else { t.text_dim }));
                        });
                    });
                }
            });
        });
    });
}

#[cfg(test)]
mod disconnect_regressions {
    use super::*;
    use solidcraft_engine::pdm::ActiveConnection;

    #[test]
    fn disconnect_settings_picker_rejects_a_different_authenticated_account_on_same_connection() {
        let mut status = Status {
            available: true,
            port: Some(48231),
            connection: Some(ActiveConnection {
                id: "a".repeat(64),
                label: "Archive".into(),
                origin: "https://localhost:48231".into(),
                server_id: "server".into(),
                account: "alice".into(),
                role: "administrator".into(),
            }),
            ..Default::default()
        };
        status.managed.server_id = Some("server".into());
        status.managed.workspace = Some("workspace".into());
        status.managed.root = Some("C:/Working".into());
        let mut state = State::default();
        state.sync(&status);
        state.candidate = "C:/Typed".into();
        let ticket = state.ticket(&status).unwrap();
        status.connection.as_mut().unwrap().account = "bob".into();
        state.accept_picker(&status, &ticket, true, Some("C:/LateAlicePicker".into()));
        assert!(state.candidate.is_empty(), "a late chooser result for the former principal must not populate the new principal's settings");
    }

    #[test]
    fn disconnect_same_account_reconnect_between_frames_rejects_an_old_folder_picker_ticket() {
        use solidcraft_engine::pdm::{ManagedState, Outcome, Runtime, Task};
        let runtime = Runtime::default();
        runtime.set_available(true).unwrap();
        let connection = ActiveConnection {
            id: "a".repeat(64),
            label: "Archive".into(),
            origin: "https://localhost:48231".into(),
            server_id: "server".into(),
            account: "alice".into(),
            role: "administrator".into(),
        };
        let managed = ManagedState {
            server_id: Some("server".into()),
            workspace: Some("workspace".into()),
            root: Some("C:/Working".into()),
            ..Default::default()
        };
        let connect = || Outcome::ManagedConnected { port: 48231, state: managed.clone(), connections: vec![], connection: connection.clone() };
        let id = runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
        runtime.finish(id, Ok(connect())).unwrap();
        let mut state = State::default();
        state.sync(&runtime.status().unwrap());
        state.candidate = "C:/Typed".into();
        let ticket = state.ticket(&runtime.status().unwrap()).unwrap();
        let id = runtime.enqueue(Task::Disconnect).unwrap();
        runtime.finish(id, Ok(Outcome::Disconnected)).unwrap();
        let id = runtime.enqueue(Task::Connect { port: 48231 }).unwrap();
        runtime.finish(id, Ok(connect())).unwrap();
        state.accept_picker(&runtime.status().unwrap(), &ticket, true, Some("C:/LateOldSession".into()));
        assert!(
            state.candidate.is_empty(),
            "an old native picker cannot bind into a new login session even with identical account and connection labels"
        );
    }
}
