//! Test-only true egui framebuffer capture without creating a user window.
#![cfg(all(test, not(target_arch = "wasm32")))]
use eframe::egui_wgpu::{Renderer, RendererOptions, ScreenDescriptor, wgpu};
use std::{collections::BTreeMap, fmt, sync::mpsc, time::Duration};

const MAX_SIDE: u32 = 2048;
const STAGE_TIMEOUT_SECS: u64 = 30;
const POLL_INTERVAL_MS: u64 = 100;
const STAGE_POLL_FRAMES: u32 = (STAGE_TIMEOUT_SECS * 1000 / POLL_INTERVAL_MS) as u32 + 1;
// Twelve async phases (setup/login and archive/history/restore) each have a deadline.
// Keep additional bounded room for initial layout, clicks and final image frames.
const ASYNC_PHASES: u32 = 12;
const MAX_FRAMES: u32 = ASYNC_PHASES * STAGE_POLL_FRAMES + 256;
const MAX_TEXTURES: usize = 256;
const MAX_TEXTURE_SIDE: usize = 4096;
const MAX_TEXTURE_PIXELS: usize = 32 * 1024 * 1024;
const MAX_VERTICES: usize = 2_000_000;
const MAX_INDICES: usize = 6_000_000;
const FORMAT: wgpu::TextureFormat = wgpu::TextureFormat::Rgba8UnormSrgb;
const GPU_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct CaptureError(pub &'static str);
impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for CaptureError {}
type Result<T> = std::result::Result<T, CaptureError>;

/// Persistent device, renderer and atlas. No viewport callbacks are supported:
/// an accidental Design viewport is rejected rather than rendered incorrectly.
pub struct HeadlessCapture {
    device: wgpu::Device,
    queue: wgpu::Queue,
    renderer: Renderer,
    target: wgpu::Texture,
    dimensions: [u32; 2],
    frames: u32,
    poisoned: bool,
    textures: BTreeMap<egui::TextureId, [usize; 2]>,
}
impl HeadlessCapture {
    pub async fn new(width: u32, height: u32) -> Result<Self> {
        if !(16..=MAX_SIDE).contains(&width) || !(16..=MAX_SIDE).contains(&height) {
            return Err(CaptureError("Headless capture dimensions are outside the test limit"));
        }
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle_from_env());
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions { compatible_surface: None, ..Default::default() })
            .await
            .map_err(|_| CaptureError("No headless GPU adapter is available; GUI proof was not produced"))?;
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("PDM test capture"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults().using_resolution(adapter.limits()),
                ..Default::default()
            })
            .await
            .map_err(|_| CaptureError("Could not create a headless GPU device"))?;
        let validation_scope = device.push_error_scope(wgpu::ErrorFilter::Validation);
        let renderer = Renderer::new(&device, FORMAT, RendererOptions { msaa_samples: 1, depth_stencil_format: None, ..Default::default() });
        let target = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("PDM actual egui capture"),
            size: wgpu::Extent3d { width, height, depth_or_array_layers: 1 },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: FORMAT,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
            view_formats: &[],
        });
        if validation_scope.pop().await.is_some() {
            return Err(CaptureError("Headless renderer initialization failed validation"));
        }
        Ok(Self { device, queue, renderer, target, dimensions: [width, height], frames: 0, poisoned: false, textures: BTreeMap::new() })
    }

    fn validate_textures(&self, output: &egui::FullOutput) -> Result<BTreeMap<egui::TextureId, [usize; 2]>> {
        if output.textures_delta.set.len() > MAX_TEXTURES || output.textures_delta.free.len() > MAX_TEXTURES {
            return Err(CaptureError("Too many GUI texture changes"));
        }
        let mut known = self.textures.clone();
        let delta_count = output.textures_delta.set.values().fold(0_usize, |count, deltas| count.saturating_add(deltas.len()));
        if delta_count > MAX_TEXTURES {
            return Err(CaptureError("Too many GUI texture updates"));
        }
        for (id, deltas) in &output.textures_delta.set {
            for delta in deltas {
                let size = delta.image.size();
                if size.into_iter().any(|side| side == 0 || side > MAX_TEXTURE_SIDE) {
                    return Err(CaptureError("GUI texture dimensions exceed capture limits"));
                }
                if let Some(pos) = delta.pos {
                    let destination = known.get(id).ok_or(CaptureError("GUI atlas update arrived without its first frame"))?;
                    for axis in 0..2 {
                        let end = pos
                            .get(axis)
                            .copied()
                            .and_then(|p| size.get(axis).and_then(|s| p.checked_add(*s)))
                            .ok_or(CaptureError("Invalid GUI texture update extent"))?;
                        if end > destination.get(axis).copied().unwrap_or(0) {
                            return Err(CaptureError("GUI texture update exceeds its allocation"));
                        }
                    }
                } else {
                    known.insert(*id, size);
                }
            }
        }
        if known.len() > MAX_TEXTURES {
            return Err(CaptureError("Too many allocated GUI textures"));
        }
        let pixels = known
            .values()
            .try_fold(0_usize, |sum, size| size.first().zip(size.get(1)).and_then(|(w, h)| w.checked_mul(*h)).and_then(|p| sum.checked_add(p)))
            .ok_or(CaptureError("GUI texture allocation overflow"))?;
        if pixels > MAX_TEXTURE_PIXELS {
            return Err(CaptureError("GUI texture memory exceeds capture limit"));
        }
        Ok(known)
    }

    pub async fn paint_frame(&mut self, ctx: &egui::Context, output: egui::FullOutput, background: [f32; 4]) -> Result<()> {
        if self.poisoned {
            return Err(CaptureError("Capture cannot continue after an earlier GPU failure"));
        }
        if self.frames >= MAX_FRAMES {
            return Err(CaptureError("GUI capture frame limit reached"));
        }
        let scale = output.pixels_per_point;
        if !scale.is_finite() || !(0.25..=4.0).contains(&scale) {
            return Err(CaptureError("Invalid GUI pixel scale"));
        }
        let mut known = self.validate_textures(&output)?;
        let jobs = ctx.tessellate(output.shapes, scale);
        if jobs.len() > 20_000 {
            return Err(CaptureError("Too many GUI paint jobs"));
        }
        let (mut vertices, mut indices) = (0_usize, 0_usize);
        for job in &jobs {
            let egui::epaint::Primitive::Mesh(mesh) = &job.primitive else {
                return Err(CaptureError("Viewport callback encountered; enter PDM before capture"));
            };
            if !known.contains_key(&mesh.texture_id) {
                return Err(CaptureError("GUI mesh references an unavailable texture"));
            }
            if !mesh.is_valid() {
                return Err(CaptureError("Invalid GUI paint mesh"));
            }
            vertices = vertices.checked_add(mesh.vertices.len()).ok_or(CaptureError("GUI vertex count overflow"))?;
            indices = indices.checked_add(mesh.indices.len()).ok_or(CaptureError("GUI index count overflow"))?;
        }
        if vertices > MAX_VERTICES || indices > MAX_INDICES {
            return Err(CaptureError("GUI mesh memory exceeds capture limit"));
        }
        self.poisoned = true;
        let validation_scope = self.device.push_error_scope(wgpu::ErrorFilter::Validation);
        for (id, deltas) in &output.textures_delta.set {
            for delta in deltas {
                self.renderer.update_texture(&self.device, &self.queue, *id, delta);
            }
        }
        let descriptor = ScreenDescriptor { size_in_pixels: self.dimensions, pixels_per_point: scale };
        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("PDM GUI test paint") });
        let extra = self.renderer.update_buffers(&self.device, &self.queue, &mut encoder, &jobs, &descriptor);
        let view = self.target.create_view(&Default::default());
        {
            // eframe supplies premultiplied gamma-space clear values. This test's
            // sRGB target needs linear values, with opaque PNG presentation.
            let [r, g, b, _] = background;
            let clear = wgpu::Color {
                r: f64::from(egui::ecolor::linear_from_gamma(r)),
                g: f64::from(egui::ecolor::linear_from_gamma(g)),
                b: f64::from(egui::ecolor::linear_from_gamma(b)),
                a: 1.0,
            };
            let attachments = [Some(wgpu::RenderPassColorAttachment {
                view: &view,
                depth_slice: None,
                resolve_target: None,
                ops: wgpu::Operations { load: wgpu::LoadOp::Clear(clear), store: wgpu::StoreOp::Store },
            })];
            let mut pass = encoder
                .begin_render_pass(&wgpu::RenderPassDescriptor {
                    label: Some("PDM GUI test pass"),
                    color_attachments: &attachments,
                    depth_stencil_attachment: None,
                    timestamp_writes: None,
                    occlusion_query_set: None,
                    multiview_mask: None,
                })
                .forget_lifetime();
            self.renderer.render(&mut pass, &jobs, &descriptor);
        }
        let submission = self.queue.submit(extra.into_iter().chain([encoder.finish()]));
        self.device
            .poll(wgpu::PollType::Wait { submission_index: Some(submission), timeout: Some(GPU_WAIT) })
            .map_err(|_| CaptureError("Headless GUI rendering timed out or the GPU was lost"))?;
        if validation_scope.pop().await.is_some() {
            return Err(CaptureError("Headless GUI rendering failed validation"));
        }
        for id in &output.textures_delta.free {
            self.renderer.free_texture(id);
            known.remove(id);
        }
        self.textures = known;
        self.frames += 1;
        self.poisoned = false;
        Ok(())
    }

    pub async fn capture_png(&mut self) -> Result<Vec<u8>> {
        if self.poisoned || self.frames == 0 {
            return Err(CaptureError("No completed GUI frame is available"));
        }
        let [width, height] = self.dimensions;
        let row = width.checked_mul(4).ok_or(CaptureError("GUI readback row overflow"))?;
        let alignment = wgpu::COPY_BYTES_PER_ROW_ALIGNMENT;
        let padded = row.checked_add(alignment - 1).map(|n| n / alignment * alignment).ok_or(CaptureError("GUI padded row overflow"))?;
        let total = u64::from(padded).checked_mul(u64::from(height)).ok_or(CaptureError("GUI readback size overflow"))?;
        if total > 32 * 1024 * 1024 {
            return Err(CaptureError("GUI readback exceeds memory limit"));
        }
        self.poisoned = true;
        let validation_scope = self.device.push_error_scope(wgpu::ErrorFilter::Validation);
        let read = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("PDM GUI readback"),
            size: total,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let mut encoder = self.device.create_command_encoder(&Default::default());
        encoder.copy_texture_to_buffer(
            self.target.as_image_copy(),
            wgpu::TexelCopyBufferInfo {
                buffer: &read,
                layout: wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(padded), rows_per_image: Some(height) },
            },
            wgpu::Extent3d { width, height, depth_or_array_layers: 1 },
        );
        let submission = self.queue.submit([encoder.finish()]);
        let (send, receive) = mpsc::sync_channel(1);
        let slice = read.slice(..);
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = send.send(result);
        });
        self.device
            .poll(wgpu::PollType::Wait { submission_index: Some(submission), timeout: Some(GPU_WAIT) })
            .map_err(|_| CaptureError("Headless GUI readback timed out or the GPU was lost"))?;
        receive
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| CaptureError("GUI readback callback did not complete"))?
            .map_err(|_| CaptureError("GUI readback mapping failed"))?;
        if validation_scope.pop().await.is_some() {
            return Err(CaptureError("GUI readback failed validation"));
        }
        let result = (|| {
            let mapped = slice.get_mapped_range().map_err(|_| CaptureError("GUI readback mapped range is unavailable"))?;
            let row = usize::try_from(row).map_err(|_| CaptureError("GUI row is not addressable"))?;
            let stride = usize::try_from(padded).map_err(|_| CaptureError("GUI stride is not addressable"))?;
            let expected = row.checked_mul(height as usize).ok_or(CaptureError("GUI output size overflow"))?;
            let mut rgba = Vec::with_capacity(expected);
            for bytes in mapped.chunks_exact(stride).take(height as usize) {
                rgba.extend_from_slice(bytes.get(..row).ok_or(CaptureError("GUI mapped row is truncated"))?);
            }
            if rgba.len() != expected {
                return Err(CaptureError("GUI readback has missing rows"));
            }
            solidcraft_engine::render::png(width as usize, height as usize, rgba).ok_or(CaptureError("GUI PNG encoding failed"))
        })();
        read.unmap();
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
}

/// Exact app-side frame integration. The caller supplies the REAL native
/// service_with_credentials(..., Memory) callback, not a fake server response.
/// Use temporary isolated settings/index/store roots when constructing that service.
pub struct GuidedUiProof {
    pub app: solidcraft_ui_egui::SolveApp,
    pub ctx: egui::Context,
    capture: HeadlessCapture,
    frame: u32,
}
impl eframe::App for GuidedUiProof {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.app.ui(ui);
    }
}
impl GuidedUiProof {
    pub async fn new(worker: solidcraft_ui_egui::pdm_panel::Start) -> Result<Self> {
        let mut app = solidcraft_ui_egui::SolveApp::new(
            solidcraft_engine::Session::default(),
            solidcraft_ui_egui::Services { pdm: Some(worker), ..Default::default() },
        );
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        // Theme and fonts are initialized before the FIRST frame; its atlas delta
        // is sent straight to our renderer, never discarded by Harness::frame.
        solidcraft_ui_egui::theme::set_dark(app.ui.dark);
        solidcraft_ui_egui::theme::set_vision(app.preferences.color_vision);
        solidcraft_ui_egui::theme::apply(&ctx);
        solidcraft_ui_egui::fonts::setup_fonts_for(&ctx, &app.preferences.language, &app.preferences.ui_font);
        app.start("pdm.panel");
        if !app.pdm.workspace_active {
            return Err(CaptureError("PDM workspace did not open before capture"));
        }
        let capture = HeadlessCapture::new(1280, 900).await?;
        let mut proof = Self { app, ctx, capture, frame: 0 };
        proof.frame(Vec::new()).await?;
        Ok(proof)
    }
    pub async fn frame(&mut self, events: Vec<egui::Event>) -> Result<()> {
        if self.frame >= MAX_FRAMES {
            return Err(CaptureError("Guided GUI frame budget exhausted"));
        }
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 900.0))),
            time: Some(f64::from(self.frame) / 60.0),
            focused: true,
            events,
            ..Default::default()
        };
        self.app.raw_input_hook(&mut input);
        let app = &mut self.app;
        let output = self.ctx.run_ui(input, |ui| {
            app.logic(ui.ctx());
            app.ui(ui);
        });
        // The desktop App uses eframe's default clear_color too.
        let background = eframe::App::clear_color(self, &self.ctx.global_style().visuals);
        self.capture.paint_frame(&self.ctx, output, background).await?;
        self.frame += 1;
        Ok(())
    }
    pub async fn click_handle(&mut self, name: &str) -> Result<()> {
        // A completed worker can remove the identity grid and resize the window.
        // Settle that layout before reading the next widget's coordinates.
        self.frame(Vec::new()).await?;
        self.frame(Vec::new()).await?;
        let at = solidcraft_ui_egui::scenario::handle_at(name).ok_or(CaptureError("Guided GUI widget handle is missing"))?;
        self.frame(vec![egui::Event::PointerMoved(at)]).await?;
        self.frame(vec![egui::Event::PointerButton { pos: at, button: egui::PointerButton::Primary, pressed: true, modifiers: Default::default() }])
            .await?;
        self.frame(vec![egui::Event::PointerButton { pos: at, button: egui::PointerButton::Primary, pressed: false, modifiers: Default::default() }])
            .await
    }
    pub async fn png(&mut self) -> Result<Vec<u8>> {
        // The click changes confirmation state after that frame was drawn.
        // Present the real modal and let its fade-in finish before readback.
        for _ in 0..12 {
            self.frame(Vec::new()).await?;
        }
        self.capture.capture_png().await
    }

    async fn wait_for_idle(&mut self, phase: &'static str) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(STAGE_TIMEOUT_SECS);
        for _ in 0..STAGE_POLL_FRAMES {
            let status = self.app.pdm.runtime.status()?;
            if let Some(error) = status.error {
                return Err(format!("{phase} failed: {error}").into());
            }
            if status.busy.is_none() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("{phase} timed out").into());
            }
            self.frame(Vec::new()).await?;
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS).min(remaining));
        }
        Err(format!("{phase} exceeded its bounded polling budget").into())
    }
}

#[test]
#[ignore = "requires a native headless GPU adapter; manual guided UI proof"]
fn guided_local_setup_and_saved_login_draw_actual_native_results() -> std::result::Result<(), Box<dyn std::error::Error>> {
    pollster::block_on(async {
        let root = std::env::temp_dir().join(format!("solidcraft-guided-ui-proof-{}", std::process::id()));
        std::fs::create_dir(&root)?;
        let worker = crate::pdm::service_with_credentials(None, Some(root.join("connections")), crate::pdm::test_support::Memory::default());
        let mut proof = GuidedUiProof::new(worker).await?;
        proof.wait_for_idle("initial connection inventory").await?;
        proof.frame(Vec::new()).await?;
        std::fs::write(root.join("01-setup.png"), proof.png().await?)?;
        proof.click_handle("pdm:connection_mode_create").await?;
        proof.app.pdm.guided.label = "Local verification archive".into();
        proof.app.pdm.guided.administrator = "admin".into();
        proof.frame(Vec::new()).await?;
        proof.click_handle("pdm:setup_create").await?;
        proof.wait_for_idle("real local setup").await?;
        let active = proof.app.pdm.runtime.status()?.connection.ok_or("setup returned no authenticated identity")?;
        assert_eq!(active.account, "admin");
        assert_eq!(active.role, "Administrator");
        proof.frame(Vec::new()).await?;
        std::fs::write(root.join("02-connected.png"), proof.png().await?)?;
        proof.click_handle("pdm:disconnect_toolbar").await?;
        proof.wait_for_idle("disconnect").await?;
        assert!(proof.app.pdm.runtime.status()?.connection.is_none());
        proof.click_handle("pdm:connect_settings").await?;
        proof.wait_for_idle("saved connection inventory").await?;
        proof.click_handle("pdm:connection_mode_connect").await?;
        proof.click_handle(&format!("pdm:connection:{}", active.id)).await?;
        proof.wait_for_idle("saved login").await?;
        let reopened = proof.app.pdm.runtime.status()?.connection.ok_or("saved login returned no identity")?;
        assert_eq!(reopened.server_id, active.server_id);
        assert_eq!(reopened.account, "admin");
        proof.frame(Vec::new()).await?;
        std::fs::write(root.join("03-saved-login.png"), proof.png().await?)?;
        // Only this proof's authenticated private working folder is used.
        proof.app.pdm.open = false;
        let working = std::path::PathBuf::from(proof.app.pdm.runtime.status()?.managed.root.ok_or("verified working folder is missing")?);
        let working = std::fs::canonicalize(working)?;
        let test_root = std::fs::canonicalize(&root)?;
        if !working.starts_with(&test_root) {
            return Err("working folder escaped the isolated proof root".into());
        }
        let path = working.join("restore-toybox.solidcraft");
        proof.app.run("solid.box", serde_json::json!({"length":10,"width":10,"height":10,"body_name":"Toy box"}))?;
        proof.app.run("file.save", serde_json::json!({"path":path}))?;
        let original_bytes = std::fs::read(&path)?;
        proof.app.run("pdm.archive", serde_json::json!({}))?;
        proof.wait_for_idle("archive original version").await?;
        let document = proof
            .app
            .pdm
            .runtime
            .status()?
            .managed
            .catalog
            .into_iter()
            .find(|entry| entry.logical_path == "restore-toybox.solidcraft")
            .ok_or("archived toy box is missing from catalog")?
            .document;
        proof.app.run("pdm.checkout", serde_json::json!({"document":document}))?;
        proof.wait_for_idle("checkout toy box").await?;
        proof
            .app
            .run("solid.box", serde_json::json!({"length":2,"width":2,"height":2,"corner":[1,1,1],"operation":"new","body_name":"Inside block"}))?;
        proof.app.run("file.save", serde_json::json!({}))?;
        let changed_bytes = std::fs::read(&path)?;
        assert_ne!(changed_bytes, original_bytes);
        proof.app.run("pdm.archive", serde_json::json!({}))?;
        proof.wait_for_idle("archive changed version").await?;
        assert!(proof.app.pdm.workspace_active);
        proof.app.pdm.detail_tab = 0;
        proof.frame(Vec::new()).await?;
        // Real catalog/history handles select the archived version; no fake result
        // or direct assignment of the selection/confirmation is involved.
        proof.click_handle(&format!("pdm:file:{document}")).await?;
        proof.wait_for_idle("load toy box history").await?;
        let before_history = proof.app.pdm.runtime.status()?.managed.history;
        assert_eq!(before_history.len(), 2);
        use sha2::Digest as _;
        let original_hash = format!("{:x}", sha2::Sha256::digest(&original_bytes));
        let changed_hash = format!("{:x}", sha2::Sha256::digest(&changed_bytes));
        assert!(before_history.iter().any(|v| v.version.reference.version == 1 && v.version.sha256 == original_hash));
        assert!(before_history.iter().any(|v| v.version.reference.version == 2 && v.version.sha256 == changed_hash));
        proof.frame(Vec::new()).await?;
        proof.click_handle(&format!("pdm:version:{document}:1")).await?;
        proof.wait_for_idle("load selected historical preview").await?;
        proof.frame(Vec::new()).await?;
        proof.click_handle("pdm:restore_version").await?;
        assert_eq!(proof.app.pdm.restore_confirmation.as_ref().map(|v| v.version), Some(1));
        std::fs::write(root.join("04-confirmation.png"), proof.png().await?)?;
        proof.click_handle("pdm:restore_version_confirm").await?;
        proof.wait_for_idle("restore original as new version").await?;
        assert!(proof.app.pdm.restore_confirmation.is_none());
        assert_eq!(std::fs::read(&path)?, original_bytes);
        assert_eq!(proof.app.docs.count(), 1);
        assert!(!proof.app.session.pdm_read_only);
        assert!(proof.app.session.path.as_deref().is_some_and(|loaded| solidcraft_engine::pdm::same_file_path(loaded, &path.to_string_lossy())));
        let state = proof.app.pdm.runtime.status()?.managed;
        assert_eq!(state.catalog.iter().find(|entry| entry.document == document).and_then(|entry| entry.head), Some(3));
        // A retry of the identical user intent must not publish a fourth version.
        proof.app.run("pdm.restore_version", serde_json::json!({"document":document,"version":1,"restore":true}))?;
        proof.wait_for_idle("retry completed restore").await?;
        proof.app.run("pdm.history", serde_json::json!({"document":document}))?;
        proof.wait_for_idle("verify retained archive history").await?;
        let history = proof.app.pdm.runtime.status()?.managed.history;
        assert_eq!(history.len(), 3);
        for (version, hash) in [(1, &original_hash), (2, &changed_hash), (3, &original_hash)] {
            assert!(history.iter().any(|entry| entry.version.reference.version == version && &entry.version.sha256 == hash));
        }
        assert_eq!(std::fs::read(&path)?, original_bytes);
        assert_eq!(proof.app.docs.count(), 1);
        assert!(!proof.app.session.pdm_read_only);
        assert!(proof.app.session.path.as_deref().is_some_and(|loaded| solidcraft_engine::pdm::same_file_path(loaded, &path.to_string_lossy())));
        assert!(proof.app.pdm.workspace_active);
        proof.frame(Vec::new()).await?;
        std::fs::write(root.join("05-restored.png"), proof.png().await?)?;
        eprintln!("Guided native UI proof: {}", root.display());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
