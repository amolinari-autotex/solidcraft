//! Bounded offscreen renderer adapted from the existing native PDM proof helper.
use eframe::egui_wgpu::{Renderer, RendererOptions, ScreenDescriptor, wgpu};
use std::{collections::BTreeMap, fmt, sync::mpsc, time::Duration};

const MAX_SIDE: u32 = 2048;
// The console proof paints twelve settled frames across three pages.
const MAX_FRAMES: u32 = 64;
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

    pub async fn paint_frame(&mut self, output: egui::FullOutput, jobs: Vec<egui::ClippedPrimitive>, background: [f32; 4]) -> Result<()> {
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
        // Jobs were tessellated immediately after this frame's layout. Deferred
        // tessellation would normalize old glyph UVs with a later atlas size.
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

    pub async fn capture_rgba(&mut self) -> Result<Vec<u8>> {
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
            Ok(rgba)
        })();
        read.unmap();
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
}
