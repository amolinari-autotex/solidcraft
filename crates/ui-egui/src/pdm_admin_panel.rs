//! Explicit, read-only administration. Server capabilities are never inferred from a username.
use crate::{SolveApp, theme::Tokens};
use solidcraft_engine::pdm::AdminReadStatus;

pub(super) fn open(app: &mut SolveApp) -> Result<(), String> {
    let status = app.pdm.runtime.status()?;
    if !super::admin_visible(&status) {
        return Err(app.tr("ui.pdm_admin_forbidden").into());
    }
    if app.file_picker_busy() || app.file_load.busy() || app.dialog.is_some() {
        return Err(app.tr("ui.pdm_reason_busy").into());
    }
    if let Some(reason) = status.action_unavailable("pdm.admin", None, None, false, false, None) {
        return Err(app.tr(reason).into());
    }
    super::enter(app)?;
    app.pdm.settings_open = false;
    app.pdm.admin_open = true;
    app.pdm.open = false;
    super::dispatch(app, "pdm.admin.read", serde_json::json!({}));
    Ok(())
}

fn status_key(status: AdminReadStatus) -> &'static str {
    match status {
        AdminReadStatus::Available => "ui.pdm_admin_available",
        AdminReadStatus::Unsupported => "ui.pdm_admin_unsupported",
        AdminReadStatus::Forbidden => "ui.pdm_admin_forbidden",
        AdminReadStatus::Unauthorized => "ui.pdm_admin_unauthorized",
        AdminReadStatus::Unavailable => "ui.pdm_admin_unavailable",
    }
}

pub(super) fn show(app: &mut SolveApp, ui: &mut egui::Ui) {
    egui::Frame::new().fill(Tokens::get().panel).inner_margin(12.0).show(ui, |ui| {
        ui.set_min_size(ui.available_size());
        contents(app, ui);
    });
}

fn contents(app: &mut SolveApp, ui: &mut egui::Ui) {
    let Ok(status) = app.pdm.runtime.status() else { return };
    let t = Tokens::get();
    ui.horizontal_wrapped(|ui| {
        let back = ui.button(app.tr("ui.back"));
        super::handle("admin_back", &back);
        if back.clicked() {
            app.pdm.admin_open = false;
        }
        ui.heading(app.tr("ui.pdm_admin_title"));
        let available = status.busy.is_none() && !app.file_picker_busy() && !app.file_load.busy();
        let refresh = ui.add_enabled(available, egui::Button::new(app.tr("ui.pdm_refresh")));
        super::handle("admin_refresh", &refresh);
        if refresh.clicked() {
            super::dispatch(app, "pdm.admin.read", serde_json::json!({}));
        }
    });
    ui.separator();
    if status.busy.is_some() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(app.tr("ui.pdm_busy"));
        });
    }
    let Some(administration) = &status.administration else {
        if status.busy.is_none() {
            ui.colored_label(t.text_dim, app.tr(status.error.as_deref().unwrap_or("ui.pdm_admin_unavailable")));
        }
        return;
    };
    if let Some(backend) = &administration.metadata_backend {
        ui.label(format!("{}: {backend}", app.tr("ui.pdm_admin_backend")));
    }
    if let Some(principal) = &administration.principal {
        ui.label(format!("{}: {} · {}", app.tr("ui.pdm_admin_principal"), principal.id, principal.role));
    }
    egui::ScrollArea::both().id_salt("pdm_admin_content").auto_shrink([false, false]).show(ui, |ui| {
        ui.heading(app.tr("ui.pdm_admin_users"));
        if administration.users_status == AdminReadStatus::Available {
            if let Some(revision) = administration.users_revision {
                ui.small(format!("r{revision}"));
            }
            egui::Grid::new("pdm_admin_users").striped(true).show(ui, |ui| {
                for user in &administration.users {
                    ui.label(&user.id);
                    ui.label(&user.role);
                    ui.label(app.tr(if user.enabled { "ui.pdm_admin_enabled" } else { "ui.pdm_admin_disabled" }));
                    ui.end_row();
                }
            });
        } else {
            ui.label(app.tr(status_key(administration.users_status)));
        }
        ui.separator();
        ui.heading(app.tr("ui.pdm_admin_audit"));
        if administration.audit_status == AdminReadStatus::Available {
            egui::Grid::new("pdm_admin_audit").striped(true).spacing(egui::vec2(14.0, 8.0)).show(ui, |ui| {
                for key in ["ui.pdm_admin_generation", "ui.pdm_author", "ui.pdm_admin_operation", "ui.pdm_admin_subject", "ui.pdm_checked_in"] {
                    ui.strong(app.tr(key));
                }
                ui.end_row();
                for event in &administration.audit {
                    ui.label(event.generation.to_string());
                    ui.label(&event.actor);
                    ui.label(&event.operation);
                    ui.label(event.subject.as_deref().unwrap_or("—"));
                    ui.label(super::local_time(event.unix_ms));
                    ui.end_row();
                }
            });
            if administration.more_audit {
                ui.label(app.tr("ui.pdm_admin_more"));
            }
        } else {
            ui.label(app.tr(status_key(administration.audit_status)));
        }
    });
}
