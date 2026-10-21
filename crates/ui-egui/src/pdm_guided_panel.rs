//! Guided local setup and saved connection login; all side effects run in the native worker.
use crate::SolveApp;
use serde_json::json;
use solidcraft_engine::pdm::ConnectionStage;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Intent {
    #[default]
    Connect,
    Create,
    Diagnostics,
}

pub struct GuidedState {
    pub label: String,
    pub administrator: String,
    listing_requested: bool,
    intent: Intent,
    selected_connection: Option<String>,
    pending_connection_request: Option<u64>,
    pub pending_recovery: Option<(String, String)>,
}
impl Default for GuidedState {
    fn default() -> Self {
        Self {
            label: String::new(),
            administrator: "admin".into(),
            listing_requested: false,
            intent: Intent::default(),
            selected_connection: None,
            pending_connection_request: None,
            pending_recovery: None,
        }
    }
}

fn valid_form(label: &str, administrator: &str) -> bool {
    !label.trim().is_empty()
        && label.len() <= 128
        && !label.chars().any(char::is_control)
        && !administrator.is_empty()
        && administrator.len() <= 64
        && administrator != "owner"
        && administrator.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

fn diagnostics(
    app: &mut SolveApp,
    ui: &mut egui::Ui,
    status: &solidcraft_engine::pdm::Status,
    idle: bool,
    action: &mut Option<(&'static str, serde_json::Value)>,
) {
    ui.add(egui::Label::new(app.tr("ui.pdm_diagnostics_hint")).wrap());
    if let Some(recent) = status.connections.iter().find(|recent| app.pdm.guided.selected_connection.as_deref() == Some(recent.id.as_str())) {
        ui.strong(&recent.label);
        let response = ui.add_enabled(idle && !crate::documents::any_dirty(app), egui::Button::new(app.tr("ui.pdm_recover_connection")));
        super::handle(&format!("connection_recover:{}", recent.id), &response);
        if response.clicked() {
            app.pdm.guided.pending_recovery = Some((recent.id.clone(), recent.label.clone()));
        }
        ui.separator();
    }
    if !app.services.pdm_local_diagnostics {
        ui.add(egui::Label::new(app.tr("ui.pdm_legacy_not_configured")).wrap());
        return;
    }
    ui.strong(app.tr("ui.pdm_legacy_connection"));
    ui.add_enabled_ui(idle, |ui| {
        ui.label(app.tr("ui.pdm_port"));
        let response = ui.text_edit_singleline(&mut app.pdm.port);
        super::handle("port", &response);
        ui.label(app.tr("ui.pdm_working_folder"));
        let response = ui.text_edit_singleline(&mut app.pdm.root);
        super::handle("root", &response);
        let response = ui.button(app.tr("ui.pdm_connect"));
        super::handle("connect", &response);
        if response.clicked() {
            let mut params = json!({"port":app.pdm.port.parse::<u16>().ok()});
            if !app.pdm.root.trim().is_empty() {
                params["root"] = json!(app.pdm.root);
            }
            *action = Some(("pdm.connect", params));
        }
        let response = ui.add_enabled(!app.pdm.root.trim().is_empty(), egui::Button::new(app.tr("ui.pdm_recover_workspace")));
        super::handle("recover_workspace", &response);
        if response.clicked() {
            app.pdm.recovery_confirmation = true;
        }
    });
}

/// Only the request started by the still-open dialog may navigate after login.
pub(super) fn connection_completed(app: &mut SolveApp, request: u64, authenticated: bool) {
    if app.pdm.guided.pending_connection_request != Some(request) {
        return;
    }
    app.pdm.guided.pending_connection_request = None;
    if authenticated && app.pdm.open {
        if let Err(error) = super::enter(app) {
            app.set_status(error, true);
        } else {
            app.pdm.guided.listing_requested = false;
        }
    }
}

pub fn connection_window(app: &mut SolveApp, ctx: &egui::Context) {
    if !app.pdm.open {
        app.pdm.guided.listing_requested = false;
        app.pdm.guided.pending_recovery = None;
        app.pdm.guided.pending_connection_request = None;
        return;
    }
    // Exactly one asynchronous inventory request per opening. Wait for an earlier
    // job instead of dropping the request or starting a parallel native worker.
    let Ok(status) = app.pdm.runtime.status() else {
        return;
    };
    if !app.pdm.guided.listing_requested && status.available && status.busy.is_none() {
        app.pdm.guided.listing_requested = true;
        super::dispatch(app, "pdm.connections", json!({}));
    }
    let Ok(status) = app.pdm.runtime.status() else {
        return;
    };
    let idle = status.available && status.busy.is_none() && app.pdm.guided.pending_recovery.is_none();
    let disconnected = status.connection.is_none() && status.port.is_none();
    if !status.connections.iter().any(|recent| app.pdm.guided.selected_connection.as_deref() == Some(recent.id.as_str())) {
        app.pdm.guided.selected_connection = status.connections.first().map(|recent| recent.id.clone());
    }
    let mut open = true;
    let mut close = false;
    let mut action = None;
    let title = if !disconnected {
        "ui.pdm_connected_archive"
    } else {
        match app.pdm.guided.intent {
            Intent::Connect => "ui.pdm_connect_archive",
            Intent::Create => "ui.pdm_configure_local_service",
            Intent::Diagnostics => "ui.pdm_diagnostics",
        }
    };
    crate::frame::window(ctx, app.tr(title), crate::frame::Width::Normal).id(egui::Id::new("pdm_connection")).open(&mut open).show(ctx, |ui| {
        if status.busy.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(app.tr("ui.pdm_busy"));
            });
        }
        if let Some(error) = status.error.as_deref() {
            ui.add(egui::Label::new(egui::RichText::new(app.tr(error)).color(crate::theme::Tokens::get().error)).wrap());
        }
        // Only native-authenticated values are shown as the connected identity.
        if !disconnected {
            ui.label(app.tr("ui.pdm_connected"));
            if let Some(active) = &status.connection {
                ui.heading(&active.label);
                egui::Grid::new("pdm_verified_connection").show(ui, |ui| {
                    ui.label(app.tr("ui.pdm_account"));
                    ui.label(&active.account);
                    ui.end_row();
                    ui.label(app.tr("ui.pdm_role"));
                    ui.label(&active.role);
                    ui.end_row();
                    ui.label(app.tr("ui.pdm_address"));
                    ui.add(egui::Label::new(&active.origin).truncate().selectable(true)).on_hover_text(&active.origin);
                    ui.end_row();
                    if let Some(root) = status.managed.root.as_deref() {
                        ui.label(app.tr("ui.pdm_working_folder"));
                        ui.add(egui::Label::new(root).truncate().selectable(true)).on_hover_text(root);
                        ui.end_row();
                    }
                });
            } else {
                ui.heading(app.tr("ui.pdm_connected_archive"));
            }
            let response = ui.add_enabled(idle, egui::Button::new(app.tr("ui.pdm_disconnect")));
            super::handle("disconnect", &response);
            if response.clicked() {
                action = Some(("pdm.disconnect", json!({})));
            }
        } else {
            let connect_label = app.tr("ui.pdm_connect_archive").to_string();
            let create_label = app.tr("ui.pdm_configure_local_service").to_string();
            let diagnostics_label = app.tr("ui.pdm_diagnostics").to_string();
            let previous_intent = app.pdm.guided.intent;
            ui.add_enabled_ui(idle, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let response = ui.selectable_value(&mut app.pdm.guided.intent, Intent::Connect, connect_label);
                    super::handle("connection_mode_connect", &response);
                    let response = ui.selectable_value(&mut app.pdm.guided.intent, Intent::Create, create_label);
                    super::handle("connection_mode_create", &response);
                    if app.services.pdm_local_diagnostics || !status.connections.is_empty() {
                        let response = ui.selectable_value(&mut app.pdm.guided.intent, Intent::Diagnostics, diagnostics_label);
                        super::handle("diagnostics", &response);
                    }
                });
            });
            if previous_intent != app.pdm.guided.intent {
                app.pdm.guided.pending_recovery = None;
            }
            ui.separator();
            match app.pdm.guided.intent {
                Intent::Connect => {
                    ui.horizontal(|ui| {
                        ui.label(app.tr("ui.pdm_recent_connections"));
                        let response = ui.add_enabled(idle, egui::Button::new(app.tr("ui.pdm_refresh_connections")));
                        super::handle("connections_refresh", &response);
                        if response.clicked() {
                            action = Some(("pdm.connections", json!({})));
                        }
                    });
                    if status.connections.is_empty() && status.busy.is_none() {
                        ui.label(app.tr("ui.pdm_no_connections"));
                    }
                    egui::ScrollArea::vertical().id_salt("pdm_recent_connections").max_height(180.0).show(ui, |ui| {
                        for recent in &status.connections {
                            ui.horizontal_wrapped(|ui| {
                                let selected = app.pdm.guided.selected_connection.as_deref() == Some(recent.id.as_str());
                                let response = ui.selectable_label(selected, &recent.label);
                                super::handle(&format!("connection_select:{}", recent.id), &response);
                                if response.clicked() {
                                    app.pdm.guided.selected_connection = Some(recent.id.clone());
                                }
                                if matches!(recent.stage, ConnectionStage::Pending) {
                                    ui.label(app.tr("ui.pdm_setup_incomplete"));
                                }
                            });
                        }
                    });
                    if let Some(recent) =
                        status.connections.iter().find(|recent| app.pdm.guided.selected_connection.as_deref() == Some(recent.id.as_str()))
                    {
                        ui.label(app.tr("ui.pdm_saved_unverified"));
                        let key = if matches!(recent.stage, ConnectionStage::Pending) { "ui.pdm_resume_setup" } else { "ui.pdm_connect" };
                        let response = ui.add_enabled(idle, egui::Button::new(app.tr(key)));
                        super::handle(&format!("connection:{}", recent.id), &response);
                        if response.clicked() {
                            action = Some(("pdm.connection.open", json!({"connection_id":recent.id})));
                        }
                    }
                }
                Intent::Create => {
                    ui.add(egui::Label::new(app.tr("ui.pdm_local_service_hint")).wrap());
                    ui.add_enabled_ui(idle, |ui| {
                        ui.label(app.tr("ui.pdm_archive_name"));
                        let response = ui.text_edit_singleline(&mut app.pdm.guided.label);
                        super::handle("setup_label", &response);
                        ui.label(app.tr("ui.pdm_administrator"));
                        let response = ui.text_edit_singleline(&mut app.pdm.guided.administrator);
                        super::handle("setup_administrator", &response);
                        ui.small(app.tr("ui.pdm_admin_id_hint"));
                        let response = ui.add_enabled(
                            valid_form(&app.pdm.guided.label, &app.pdm.guided.administrator),
                            egui::Button::new(app.tr("ui.pdm_setup_local_service")),
                        );
                        super::handle("setup_create", &response);
                        if response.clicked() {
                            action =
                                Some(("pdm.setup.create", json!({"label":app.pdm.guided.label.trim(),"administrator":app.pdm.guided.administrator})));
                        }
                    });
                }
                Intent::Diagnostics => diagnostics(app, ui, &status, idle, &mut action),
            }
        }
        let response = ui.button(app.tr(if status.busy.is_some() || !disconnected { "ui.close" } else { "ui.cancel" }));
        super::handle("connection_close", &response);
        close = response.clicked();
    });
    open &= !close;
    app.pdm.open = open;
    if !open {
        app.pdm.guided.listing_requested = false;
        app.pdm.guided.pending_connection_request = None;
    }
    if let Some((id, params)) = action {
        let previous_request = app.pdm.runtime.status().ok().and_then(|status| status.busy);
        super::dispatch(app, id, params);
        if open && previous_request.is_none() && matches!(id, "pdm.connection.open" | "pdm.setup.create") {
            app.pdm.guided.pending_connection_request = app.pdm.runtime.status().ok().and_then(|status| status.busy);
        }
    }
    if open && let Some((connection_id, label)) = app.pdm.guided.pending_recovery.clone() {
        let mut confirm_open = true;
        crate::frame::window(ctx, app.tr("ui.pdm_recover_workspace"), crate::frame::Width::Normal)
            .id(egui::Id::new("pdm_guided_recovery"))
            .open(&mut confirm_open)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.strong(label);
                ui.add(egui::Label::new(app.tr("ui.pdm_recover_warning")).wrap());
                let dirty = crate::documents::any_dirty(app);
                if dirty {
                    ui.label(app.tr("ui.pdm_save_first"));
                }
                let response =
                    ui.add_enabled(status.available && status.busy.is_none() && !dirty, egui::Button::new(app.tr("ui.pdm_recover_confirm")));
                super::handle("connection_recover_confirm", &response);
                if response.clicked() {
                    app.pdm.guided.pending_recovery = None;
                    super::dispatch(app, "pdm.connection.recover", json!({"connection_id":connection_id,"restore":true}));
                }
                let response = ui.button(app.tr("ui.cancel"));
                super::handle("connection_recover_cancel", &response);
                if response.clicked() {
                    app.pdm.guided.pending_recovery = None;
                }
            });
        if !confirm_open {
            app.pdm.guided.pending_recovery = None;
        }
    }
}

#[cfg(test)]
mod form_tests {
    use super::*;
    #[test]
    fn public_setup_form_accepts_only_bounded_display_label_and_account_id() {
        assert!(valid_form("My archive", "admin"));
        assert!(!valid_form(" ", "admin"));
        assert!(!valid_form("Archive", "owner"));
        assert!(!valid_form("Archive", "Admin user"));
        assert!(!valid_form(&"x".repeat(129), "admin"));
        assert!(!valid_form("Archive\nOther", "admin"));
    }
}
