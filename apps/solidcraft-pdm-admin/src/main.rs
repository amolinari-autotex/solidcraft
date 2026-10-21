//! Separate native server console. Normal CAD startup never enters this binary.
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]
#![deny(unsafe_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]
mod capture;
#[allow(dead_code)]
#[path = "../../solidcraft/src/pdm_credentials.rs"]
mod pdm_credentials;
mod service;
use service::{Action, MemoryCredentials, Service, Snapshot};
use solidcraft_pdm::managed::Role;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

struct ProofFrame {
    output: egui::FullOutput,
    jobs: Vec<egui::ClippedPrimitive>,
    filename: Option<&'static str>,
}
impl ProofFrame {
    fn new(ctx: &egui::Context, mut output: egui::FullOutput, filename: Option<&'static str>) -> Self {
        let shapes = std::mem::take(&mut output.shapes);
        let jobs = ctx.tessellate(shapes, output.pixels_per_point);
        Self { output, jobs, filename }
    }
}
enum Job {
    Service(Action),
    PickDirectory(usize),
    RenderProof { root: PathBuf, frames: Vec<ProofFrame> },
}
struct Update {
    snapshot: Snapshot,
    result: Result<String, String>,
    picked: Option<(usize, String)>,
    proof_saved: bool,
}
struct Worker {
    sender: Option<SyncSender<Job>>,
    receiver: Receiver<Update>,
    join: Option<thread::JoinHandle<()>>,
}
impl Worker {
    fn new(proof: Option<PathBuf>) -> std::io::Result<Self> {
        let (sender, receive) = mpsc::sync_channel::<Job>(1);
        let (send, receiver) = mpsc::sync_channel::<Update>(2);
        let join = thread::Builder::new().name("pdm-console-worker".into()).spawn(move || {
            fn run<C: pdm_credentials::CredentialStore>(
                mut service: Service<C>,
                receive: Receiver<Job>,
                send: SyncSender<Update>,
                proof: Option<PathBuf>,
            ) {
                if let Some(root) = proof {
                    let result = (|| {
                        service.perform(Action::Create { root, administrator: "local-admin".into(), port: 0 })?;
                        service.perform(Action::CreateUser { id: "design-reader".into(), role: Role::Viewer })?;
                        service.perform(Action::CreateUser { id: "design-author".into(), role: Role::Contributor })?;
                        service.perform(Action::Audit { more: false })
                    })();
                    if send
                        .send(Update {
                            snapshot: service.snapshot.clone(),
                            result: result.map_err(|e: solidcraft_pdm::Error| e.to_string()),
                            picked: None,
                            proof_saved: false,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                while let Ok(job) = receive.recv() {
                    let (result, picked, proof_saved) = match job {
                        Job::Service(action) => (service.perform(action).map_err(|e| e.to_string()), None, false),
                        Job::PickDirectory(field) => {
                            let path = rfd::FileDialog::new().set_title("Choose private server directory").pick_folder();
                            (Ok("Directory selection complete".into()), path.map(|path| (field, path.display().to_string())), false)
                        }
                        Job::RenderProof { root, frames } => {
                            let result = pollster::block_on(async {
                                let mut capture = capture::HeadlessCapture::new(1080, 780).await.map_err(|error| error.to_string())?;
                                for frame in frames {
                                    capture.paint_frame(frame.output, frame.jobs, [0.1, 0.1, 0.1, 1.0]).await.map_err(|error| error.to_string())?;
                                    if let Some(filename) = frame.filename {
                                        let pixels = capture.capture_rgba().await.map_err(|error| error.to_string())?;
                                        image::save_buffer(root.join(filename), &pixels, 1080, 780, image::ColorType::Rgba8)
                                            .map_err(|_| "Native console screenshot save failed".to_string())?;
                                    }
                                }
                                Ok("Actual Status, Accounts and Audit widgets rendered to offscreen framebuffer".into())
                            });
                            (result, None, true)
                        }
                    };
                    if send.send(Update { snapshot: service.snapshot.clone(), result, picked, proof_saved }).is_err() {
                        break;
                    }
                }
                if let Err(error) = service.perform(Action::Stop) {
                    eprintln!("Owned console service shutdown failed: {error}");
                }
            }
            if proof.is_some() {
                run(Service::new(MemoryCredentials::default()), receive, send, proof);
            } else {
                run(Service::new(pdm_credentials::OsCredentialStore), receive, send, None);
            }
        })?;
        Ok(Self { sender: Some(sender), receiver, join: Some(join) })
    }
    fn close(&mut self) {
        self.sender = None;
        if let Some(join) = self.join.take()
            && join.join().is_err()
        {
            eprintln!("Console worker exited abnormally");
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.close();
    }
}
enum Confirm {
    Disable(String),
    Reset(String),
    Restore,
}
struct Console {
    worker: Worker,
    snapshot: Snapshot,
    busy: bool,
    message: String,
    error: bool,
    root: String,
    administrator: String,
    port: u16,
    max_file_mib: u64,
    archive_gib: u64,
    user: String,
    role: Role,
    backup: String,
    restore: String,
    confirm: Option<Confirm>,
    page: usize,
    draft_roles: std::collections::BTreeMap<String, Role>,
    proof: Option<PathBuf>,
    screenshot_requested: bool,
    proof_success: Arc<AtomicBool>,
    started: Instant,
}
impl Console {
    fn new(worker: Worker, proof: Option<PathBuf>, proof_success: Arc<AtomicBool>) -> Self {
        Self {
            worker,
            snapshot: Snapshot::default(),
            busy: proof.is_some(),
            message: "Choose a NEW physical server installation, or open an existing console installation.".into(),
            error: false,
            root: String::new(),
            administrator: "local-admin".into(),
            port: 0,
            max_file_mib: 512,
            archive_gib: 20,
            user: String::new(),
            role: Role::Viewer,
            backup: String::new(),
            restore: String::new(),
            confirm: None,
            page: 0,
            draft_roles: Default::default(),
            proof,
            screenshot_requested: false,
            proof_success,
            started: Instant::now(),
        }
    }
    fn dispatch(&mut self, action: Action) {
        if self.snapshot.pending
            && matches!(
                action,
                Action::Create { .. }
                    | Action::CreateConfigured { .. }
                    | Action::Open(_)
                    | Action::CreateUser { .. }
                    | Action::Role { .. }
                    | Action::Enabled { .. }
                    | Action::Reset { .. }
                    | Action::Backup(_)
                    | Action::Restore { .. }
            )
        {
            self.message = "Resolve the pending administration request using Retry before making another change.".into();
            self.error = true;
            return;
        }
        self.send(Job::Service(action));
    }
    fn send(&mut self, job: Job) {
        if self.busy {
            return;
        }
        if let Some(sender) = &self.worker.sender {
            match sender.try_send(job) {
                Ok(()) => {
                    self.busy = true;
                    self.error = false;
                    self.message = "Working…".into();
                }
                Err(_) => {
                    self.error = true;
                    self.message = "Worker unavailable or busy".into();
                }
            }
        }
    }
    fn role_picker(ui: &mut egui::Ui, id: impl std::hash::Hash + std::fmt::Debug, role: &mut Role) {
        egui::ComboBox::from_id_salt(id).selected_text(format!("{role:?}")).show_ui(ui, |ui| {
            ui.selectable_value(role, Role::Viewer, "Viewer");
            ui.selectable_value(role, Role::Contributor, "Contributor");
            ui.selectable_value(role, Role::Administrator, "Administrator");
        });
    }
    fn setup(&mut self, ui: &mut egui::Ui) {
        ui.heading("Physical server installation");
        ui.label("Dedicated directory on this computer, separate from every client work area.");
        ui.label("Use a private parent directory owned by your Windows account; backups also contain private server metadata.");
        ui.add(
            egui::TextEdit::singleline(&mut self.root)
                .desired_width(f32::INFINITY)
                .hint_text("Absolute NEW installation directory or existing console root"),
        );
        ui.horizontal(|ui| {
            if ui.button("Choose parent for NEW installation…").clicked() {
                self.send(Job::PickDirectory(0));
            }
            if ui.button("Choose existing installation…").clicked() {
                self.send(Job::PickDirectory(1));
            }
        });
        ui.horizontal(|ui| {
            ui.label("Initial administrator ID");
            ui.text_edit_singleline(&mut self.administrator);
        });
        ui.horizontal(|ui| {
            ui.label("Loopback port (0 = choose free port for NEW installation)");
            ui.add(egui::DragValue::new(&mut self.port).range(0..=65535));
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Maximum file size (MiB)");
            ui.add(egui::DragValue::new(&mut self.max_file_mib).range(1..=8192));
            ui.label("Archive content capacity (GiB)");
            ui.add(egui::DragValue::new(&mut self.archive_gib).range(1..=16384));
        });
        ui.label("NEW archives: up to 8 GiB per file and 16 TiB per archive; file limit must fit inside archive capacity. Existing installations use their saved policy.");
        let selected_policy = service::stream_policy_from_units(self.max_file_mib, self.archive_gib).ok();
        if selected_policy.is_none() {
            ui.colored_label(egui::Color32::from_rgb(220, 95, 80), "Invalid capacity: the maximum file size must fit inside the archive capacity.");
        }
        ui.horizontal(|ui| {
            if ui.add_enabled(selected_policy.is_some(), egui::Button::new("Create NEW archive and start")).clicked()
                && let Some(stream_policy) = selected_policy
            {
                self.dispatch(Action::CreateConfigured {
                    root: PathBuf::from(&self.root),
                    administrator: self.administrator.clone(),
                    port: self.port,
                    stream_policy,
                });
            }
            if ui.button("Open existing console installation").clicked() {
                self.dispatch(Action::Open(PathBuf::from(&self.root)));
            }
        });
        ui.separator();
        ui.label(
            "New setup generates fresh TLS and a random bearer. Private native credential capture happens before publishing administrator authority.",
        );
        ui.label("Existing archives require their original console metadata, TLS identity and native credential. Partial setup is preserved and reports an error.");
        ui.label("LocalOnly: loopback HTTPS. LAN, relay/cloud, background service installation and remote account enrollment are not provided.");
    }
    fn overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Server status");
        egui::Grid::new("server-status").num_columns(2).spacing([24.0, 10.0]).show(ui, |ui| {
            for (label, value) in [
                ("Service", if self.snapshot.running { "RUNNING · own process" } else { "STOPPED" }),
                ("Mode", "LocalOnly · pinned HTTPS"),
                ("Endpoint", self.snapshot.origin.as_str()),
                ("Physical installation", self.snapshot.root.as_str()),
                ("Metadata", self.snapshot.backend.as_str()),
                (
                    if self.snapshot.verified { "Authenticated administrator" } else { "Configured administrator (unverified)" },
                    self.snapshot.administrator.as_str(),
                ),
            ] {
                ui.strong(label);
                ui.label(value);
                ui.end_row();
            }
            ui.strong("Server identity");
            ui.add(egui::Label::new(&self.snapshot.server_id).wrap());
            ui.end_row();
        });
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.snapshot.running && !self.snapshot.root.is_empty(), egui::Button::new("Start owned service")).clicked() {
                self.dispatch(Action::Start);
            }
            if ui.add_enabled(self.snapshot.running, egui::Button::new("Stop owned service")).clicked() {
                self.dispatch(Action::Stop);
            }
            if ui.add_enabled(self.snapshot.running, egui::Button::new("Refresh live status")).clicked() {
                self.dispatch(Action::Refresh);
            }
        });
        ui.separator();
        ui.strong(if self.snapshot.verified {
            "Effective administrator permissions (verified by server)"
        } else {
            "Administrator authority is unverified; start or refresh live status"
        });
        if self.snapshot.verified {
            ui.label(self.snapshot.permissions.join(" · "));
        }
        ui.add_space(12.0);
        ui.label("Closing this console stops only the service it started. Other PDM processes are never terminated.");
    }
    fn users(&mut self, ui: &mut egui::Ui) {
        ui.heading("Accounts and effective permissions");
        ui.label(format!("Administration revision {} · roles and disabled state come from the server", self.snapshot.revision));
        if !self.snapshot.verified {
            ui.strong("Cached accounts only; refresh live status to verify administrator authority.");
        }
        ui.label("Generated credentials are captured locally in private native storage. A user on another computer cannot sign in until a separate secure enrollment flow exists.");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.user).hint_text("new account ID"));
            Self::role_picker(ui, "new-role", &mut self.role);
            if ui
                .add_enabled(
                    self.snapshot.running && self.snapshot.verified && !self.snapshot.pending,
                    egui::Button::new("Create local credential + account"),
                )
                .clicked()
            {
                self.dispatch(Action::CreateUser { id: self.user.clone(), role: self.role });
            }
        });
        ui.separator();
        for user in self.snapshot.users.clone() {
            let own = user.id == self.snapshot.administrator;
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(&user.id);
                    ui.label(if user.enabled { "Enabled" } else { "Disabled" });
                    let mut role = self.draft_roles.get(&user.id).copied().unwrap_or(user.role);
                    Self::role_picker(ui, &user.id, &mut role);
                    self.draft_roles.insert(user.id.clone(), role);
                    if ui
                        .add_enabled(
                            self.snapshot.running && self.snapshot.verified && !self.snapshot.pending && !own && role != user.role,
                            egui::Button::new("Apply role"),
                        )
                        .clicked()
                    {
                        self.dispatch(Action::Role { id: user.id.clone(), role });
                    }
                    if ui
                        .add_enabled(
                            self.snapshot.running && self.snapshot.verified && !self.snapshot.pending && !own,
                            egui::Button::new(if user.enabled { "Disable…" } else { "Enable" }),
                        )
                        .clicked()
                    {
                        if user.enabled {
                            self.confirm = Some(Confirm::Disable(user.id.clone()));
                        } else {
                            self.dispatch(Action::Enabled { id: user.id.clone(), enabled: true });
                        }
                    }
                    if ui
                        .add_enabled(
                            self.snapshot.running && self.snapshot.verified && !self.snapshot.pending && !own,
                            egui::Button::new("Reset credential…"),
                        )
                        .clicked()
                    {
                        self.confirm = Some(Confirm::Reset(user.id.clone()));
                    }
                    if own {
                        ui.weak("current administrator");
                    }
                });
                ui.small(if user.permissions.is_empty() {
                    "Effective permissions: none".into()
                } else {
                    format!("Effective permissions: {}", user.permissions.join(" · "))
                });
            });
        }
    }
    fn audit(&mut self, ui: &mut egui::Ui) {
        ui.heading("Successful server transitions");
        ui.label("This audit is not a denied-access log or a tamper-proof ledger.");
        ui.horizontal(|ui| {
            if ui.add_enabled(self.snapshot.running, egui::Button::new("Load first page")).clicked() {
                self.dispatch(Action::Audit { more: false });
            }
            if ui.add_enabled(self.snapshot.running && self.snapshot.next_audit.is_some(), egui::Button::new("Next page")).clicked() {
                self.dispatch(Action::Audit { more: true });
            }
        });
        for event in &self.snapshot.audit {
            ui.separator();
            ui.label(format!(
                "#{} · {} · {} · {} · Unix ms {}",
                event.generation,
                event.actor,
                event.operation,
                event.subject.as_deref().unwrap_or("—"),
                event.unix_ms
            ));
            if let Some(change) = &event.change {
                ui.small(format!(
                    "Role {:?} → {:?} · enabled {:?} → {} · credential replaced {}",
                    change.previous_role, change.role, change.previous_enabled, change.enabled, change.credential_replaced
                ));
            }
        }
    }
    fn backups(&mut self, ui: &mut egui::Ui) {
        ui.heading("Offline backup and restore");
        ui.label("Stop the owned service before backup or restore. Destination directories must be NEW and absolute.");
        ui.label("Backup directory / restore source");
        ui.add(egui::TextEdit::singleline(&mut self.backup).desired_width(f32::INFINITY));
        ui.horizontal(|ui| {
            if ui.button("Choose parent for NEW backup…").clicked() {
                self.send(Job::PickDirectory(2));
            }
            if ui.button("Choose existing backup…").clicked() {
                self.send(Job::PickDirectory(3));
            }
        });
        if ui.add_enabled(!self.snapshot.running && !self.snapshot.root.is_empty(), egui::Button::new("Create verified offline backup")).clicked() {
            self.dispatch(Action::Backup(PathBuf::from(&self.backup)));
        }
        ui.add_space(12.0);
        ui.label("NEW physical installation for restore");
        ui.add(egui::TextEdit::singleline(&mut self.restore).desired_width(f32::INFINITY));
        if ui.button("Choose parent for NEW restore…").clicked() {
            self.send(Job::PickDirectory(4));
        }
        if ui.add_enabled(!self.snapshot.running && !self.snapshot.root.is_empty(), egui::Button::new("Restore to NEW installation…")).clicked() {
            self.confirm = Some(Confirm::Restore);
        }
        ui.label("Restore accepts a verified backup of the selected server identity and retains its TLS trust, port and captured OS credential. The original installation remains intact. Do not start both copies at once.");
        ui.label("Archive backups do not include TLS private keys or OS credentials. Retain the original console installation and native credential storage for recovery.");
    }
}
impl eframe::App for Console {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(update) = self.worker.receiver.try_recv() {
            self.snapshot = update.snapshot;
            self.busy = false;
            if update.proof_saved {
                if update.result.is_ok() && !self.error && self.snapshot.running && self.snapshot.verified {
                    self.proof_success.store(true, Ordering::Relaxed);
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if let Some((field, path)) = update.picked {
                match field {
                    0 => self.root = PathBuf::from(path).join("solidcraft-pdm-server").display().to_string(),
                    1 => self.root = path,
                    2 => self.backup = PathBuf::from(path).join("solidcraft-pdm-backup").display().to_string(),
                    3 => self.backup = path,
                    4 => self.restore = PathBuf::from(path).join("solidcraft-pdm-restored").display().to_string(),
                    _ => {}
                }
            }
            match update.result {
                Ok(message) => {
                    self.message = message;
                    self.error = false;
                    if self.proof.is_some() {
                        self.page = 1;
                    }
                }
                Err(error) => {
                    self.message = error;
                    self.error = true;
                }
            }
        }
        if let Some(root) = self.proof.clone() {
            if !self.busy && !self.screenshot_requested {
                self.screenshot_requested = true;
                // eframe intentionally suppresses UI passes on hidden windows.
                // The independent context below renders precisely the same draw
                // function, retaining ALL initial font/texture deltas.
                let proof_ctx = egui::Context::default();
                let mut frames = Vec::new();
                for (page, filename) in [(1, "server-console-proof.png"), (2, "server-console-accounts.png"), (3, "server-console-audit.png")] {
                    self.page = page;
                    for settle in 0..4 {
                        let input = egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1080.0, 780.0))),
                            time: Some(frames.len() as f64 / 60.0),
                            ..Default::default()
                        };
                        let output = proof_ctx.run_ui(input, |ui| self.draw_frame(ui));
                        frames.push(ProofFrame::new(&proof_ctx, output, (settle == 3).then_some(filename)));
                    }
                }
                self.send(Job::RenderProof { root, frames });
            }
            if self.started.elapsed() > Duration::from_secs(45) {
                eprintln!("Console proof deadline exceeded");
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        ctx.request_repaint_after(Duration::from_millis(80));
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw_frame(ui);
    }
    fn on_exit(&mut self) {
        self.worker.close();
    }
}
impl Console {
    fn draw_frame(&mut self, ui: &mut egui::Ui) {
        egui::Frame::central_panel(ui.style()).show(ui, |ui| self.draw(ui));
    }
    fn draw(&mut self, ui: &mut egui::Ui) {
        ui.heading("SolidCraft PDM · Server console");
        ui.label("Local server administration · prototype");
        ui.horizontal(|ui| {
            for (index, label) in ["Setup", "Status", "Accounts", "Audit", "Backup / Restore"].iter().enumerate() {
                ui.selectable_value(&mut self.page, index, *label);
            }
        });
        ui.separator();
        if self.snapshot.pending {
            ui.horizontal(|ui| {
                ui.strong("Administration result pending; new mutations are blocked.");
                if ui.add_enabled(!self.busy && self.snapshot.running, egui::Button::new("Retry exact pending request")).clicked() {
                    self.dispatch(Action::Retry);
                }
            });
        }
        ui.horizontal(|ui| {
            if self.busy {
                ui.spinner();
            }
            let color = if self.error { egui::Color32::from_rgb(220, 95, 80) } else { ui.visuals().text_color() };
            ui.colored_label(color, &self.message);
        });
        ui.separator();
        ui.add_enabled_ui(!self.busy, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.page {
                0 => self.setup(ui),
                1 => self.overview(ui),
                2 => self.users(ui),
                3 => self.audit(ui),
                _ => self.backups(ui),
            });
        });
        if let Some(confirm) = self.confirm.take() {
            let text = match &confirm { Confirm::Disable(id) => format!("Disable account {id}? Its credentials will stop authenticating on the next request."), Confirm::Reset(id) => format!("Replace credential for {id}? The old credential will stop working; the new credential is captured only on this machine."), Confirm::Restore => "Restore this verified backup to the NEW installation directory? The original remains intact; retain its private credential and TLS data.".into() };
            let mut keep = true;
            egui::Window::new("Confirm administration change").collapsible(false).resizable(false).show(ui.ctx(), |ui| {
                ui.label(text);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        keep = false;
                    }
                    if ui.button("Confirm").clicked() {
                        let action = match &confirm {
                            Confirm::Disable(id) => Action::Enabled { id: id.clone(), enabled: false },
                            Confirm::Reset(id) => Action::Reset { id: id.clone() },
                            Confirm::Restore => Action::Restore { source: PathBuf::from(&self.backup), destination: PathBuf::from(&self.restore) },
                        };
                        self.dispatch(action);
                        keep = false;
                    }
                });
            });
            if keep {
                self.confirm = Some(confirm);
            }
        }
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let proof = if args.is_empty() {
        None
    } else if args.len() == 2 && args.first().is_some_and(|arg| arg == "--headless-proof") {
        let root = PathBuf::from(args.get(1).ok_or("missing NEW absolute proof root")?);
        if !root.is_absolute() {
            return Err("proof requires a NEW absolute root".into());
        }
        Some(root)
    } else {
        return Err("usage: solidcraft-pdm-admin [--headless-proof NEW_ABSOLUTE_ROOT]".into());
    };
    let worker = Worker::new(proof.clone())?;
    let is_proof = proof.is_some();
    let proof_success = Arc::new(AtomicBool::new(false));
    let result_flag = proof_success.clone();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1080.0, 780.0]).with_visible(proof.is_none()),
        ..Default::default()
    };
    eframe::run_native("SolidCraft PDM Server", options, Box::new(move |_cc| Ok(Box::new(Console::new(worker, proof, proof_success)))))?;
    if is_proof && !result_flag.load(Ordering::Relaxed) {
        return Err("native console proof did not complete successfully".into());
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    let noninteractive = std::env::args().skip(1).any(|argument| argument == "--headless-proof");
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if noninteractive {
                eprintln!("SolidCraft PDM console startup/proof failed: {error}");
            } else {
                rfd::MessageDialog::new()
                    .set_title("SolidCraft PDM Server — startup failed")
                    .set_level(rfd::MessageLevel::Error)
                    .set_description(format!("The server console could not start or its native renderer failed. Preserve any existing installation and check the error below.\n\n{error}"))
                    .show();
            }
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proof_tessellation_keeps_glyph_uvs_from_the_original_frame() {
        let ctx = egui::Context::default();
        let input =
            || egui::RawInput { screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1080.0, 780.0))), ..Default::default() };
        let output = ctx.run_ui(input(), |ui| {
            ui.label("SolidCraft PDM server administration");
        });
        let original_shapes = output.shapes.clone();
        let pixels_per_point = output.pixels_per_point;
        let frame = ProofFrame::new(&ctx, output, Some("status.png"));
        assert!(frame.output.shapes.is_empty());
        assert!(!frame.output.textures_delta.set.is_empty());
        let uvs = |jobs: &[egui::ClippedPrimitive]| {
            jobs.iter()
                .flat_map(|job| match &job.primitive {
                    egui::epaint::Primitive::Mesh(mesh) => mesh.vertices.iter().map(|vertex| vertex.uv).collect::<Vec<_>>(),
                    _ => Vec::new(),
                })
                .collect::<Vec<_>>()
        };
        let original_uvs = uvs(&frame.jobs);
        // A later page adds large glyphs and grows the atlas. Historical text
        // must retain its contemporaneous tessellation instead of using this
        // later context when the worker finally paints the earlier page.
        let glyphs: String = (' '..='~').collect();
        for size in [48.0, 96.0, 144.0] {
            let _ = ctx.run_ui(input(), |ui| {
                ui.label(egui::RichText::new(&glyphs).size(size));
            });
        }
        let delayed = ctx.tessellate(original_shapes, pixels_per_point);
        assert_ne!(original_uvs, uvs(&delayed), "regression fixture must grow the font atlas");
        assert_eq!(original_uvs, uvs(&frame.jobs));
    }
    #[test]
    fn worker_uses_memory_credentials_and_stops_only_owned_listener() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("solidcraft-console-worker-{}", solidcraft_pdm::AuthToken::generate()?));
        let mut worker = Worker::new(Some(root.clone()))?;
        let update = worker.receiver.recv_timeout(Duration::from_secs(30))?;
        assert!(update.result.is_ok(), "worker setup failed");
        assert!(update.snapshot.running);
        assert_eq!(update.snapshot.users.len(), 3);
        worker.sender.as_ref().ok_or("worker sender missing")?.try_send(Job::Service(Action::Stop))?;
        let stopped = worker.receiver.recv_timeout(Duration::from_secs(10))?;
        assert!(stopped.result.is_ok());
        assert!(!stopped.snapshot.running);
        worker.close();
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
