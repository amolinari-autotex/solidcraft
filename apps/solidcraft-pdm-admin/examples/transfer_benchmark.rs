//! Explicit disposable loopback TLS benchmark. Creates a NEW private fixture,
//! keeps random credentials in memory, and prints public metrics only.
//! Server-observed request/connection deltas exclude download verification.
//! Source-inferred counts remain separate, explicitly labelled estimates.
#![deny(unsafe_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[allow(dead_code)]
#[path = "../../solidcraft/src/pdm_credentials.rs"]
mod pdm_credentials;
#[allow(dead_code)]
#[path = "../src/service.rs"]
mod service;

use pdm_credentials::{CredentialContext, CredentialKey, CredentialStore, Purpose};
use serde::Serialize;
use service::{Action, MemoryCredentials, Service};
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Error, Store, Version, VersionRef,
    client::{BinaryTransferSession, Client, read_file},
    http_server::{HttpsConfig, HttpsServer, ServerMetrics},
    managed::{ManagedVersion, Role},
    stream_io::StreamPolicy,
    transfers::{CHUNK_BYTES, TransferCapabilities, TransferInput, TransferProgress, TransferTarget},
};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Write},
    net::Ipv4Addr,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MIB: u64 = 1024 * 1024;
const ADMINISTRATOR: &str = "benchmark-admin";
const AUTHOR: &str = "benchmark-author";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Legacy,
    Session1,
    Session4,
    Session8,
}
impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Session1 => "session1",
            Self::Session4 => "session4",
            Self::Session8 => "session8",
        }
    }
    fn requested_chunk_bytes(self) -> u64 {
        match self {
            Self::Legacy | Self::Session1 => CHUNK_BYTES,
            Self::Session4 => 4 * CHUNK_BYTES,
            Self::Session8 => 8 * CHUNK_BYTES,
        }
    }
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "legacy" => Ok(Self::Legacy),
            "session1" => Ok(Self::Session1),
            "session4" => Ok(Self::Session4),
            "session8" => Ok(Self::Session8),
            _ => Err(Error::Invalid("benchmark mode must be legacy/session1/session4/session8")),
        }
    }
}
enum Sdk {
    Legacy { client: Client, caps: TransferCapabilities },
    Session(BinaryTransferSession),
}
impl Sdk {
    fn new(client: &Client, mode: Mode) -> Result<Self, Error> {
        if mode == Mode::Legacy {
            Ok(Self::Legacy { client: client.clone(), caps: client.transfer_capabilities()?.ok_or(Error::Integrity)? })
        } else {
            Ok(Self::Session(client.transfer_session_with_chunk_bytes(mode.requested_chunk_bytes())?))
        }
    }
    fn capabilities(&self) -> &TransferCapabilities {
        match self {
            Self::Legacy { caps, .. } => caps,
            Self::Session(session) => session.capabilities(),
        }
    }
    fn chunk_bytes(&self) -> u64 {
        match self {
            Self::Legacy { .. } => CHUNK_BYTES,
            Self::Session(session) => session.chunk_bytes(),
        }
    }
    fn begin(&self, input: TransferInput) -> Result<TransferProgress, Error> {
        match self {
            Self::Legacy { client, .. } => client.begin_transfer(input),
            Self::Session(session) => session.begin_transfer(input),
        }
    }
    fn chunk(&self, id: &str, offset: u64, bytes: &[u8], hash: &str) -> Result<TransferProgress, Error> {
        match self {
            Self::Legacy { client, .. } => client.upload_chunk(id, offset, bytes, hash),
            Self::Session(session) => session.upload_chunk(id, offset, bytes, hash),
        }
    }
    fn commit(&self, id: &str, request: &str) -> Result<ManagedVersion, Error> {
        match self {
            Self::Legacy { client, .. } => client.commit_transfer(id, request),
            Self::Session(session) => session.commit_transfer(id, request),
        }
    }
    fn download(&self, reference: &VersionRef, output: &mut dyn Write) -> Result<Version, Error> {
        match self {
            Self::Legacy { client, .. } => client.download_stream(reference, output),
            Self::Session(session) => session.download_stream(reference, output),
        }
    }
}
fn metric_delta(before: ServerMetrics, after: ServerMetrics) -> Result<ServerMetrics, Error> {
    Ok(ServerMetrics {
        http_requests: after.http_requests.checked_sub(before.http_requests).ok_or(Error::Integrity)?,
        tls_connections: after.tls_connections.checked_sub(before.tls_connections).ok_or(Error::Integrity)?,
    })
}

#[derive(Serialize)]
struct ScenarioMetrics {
    scenario: &'static str,
    files: u64,
    chunks: u64,
    payload_bytes: u64,
    upload_wall_seconds: f64,
    source_preparation_wall_seconds: f64,
    download_verification_wall_seconds: f64,
    scenario_wall_seconds: f64,
    payload_mb_per_second: f64,
    source_buffer_bytes: u64,
    requested_chunk_bytes: u64,
    negotiated_chunk_bytes: u64,
    upload_http_requests_observed: u64,
    upload_tls_connections_observed: u64,
    download_http_requests_observed: u64,
    download_tls_connections_observed: u64,
    initial_capability_http_requests_inferred: u64,
    upload_http_requests_inferred: u64,
    download_http_requests_inferred: u64,
    independent_digest_verified_files: u64,
}
#[derive(Serialize)]
struct Metrics {
    format: &'static str,
    started_unix_seconds: u64,
    transport: &'static str,
    sdk_mode: &'static str,
    request_count_evidence: &'static str,
    request_count_model: &'static str,
    tls_counter_scope: &'static str,
    timed_upload_scope: &'static str,
    throughput_unit: &'static str,
    credentials: &'static str,
    max_file_bytes: u64,
    max_archive_bytes: u64,
    fixture_setup_wall_seconds: f64,
    owned_server_stopped: bool,
    scenarios: Vec<ScenarioMetrics>,
}
#[derive(Default)]
struct HashSink {
    bytes: u64,
    hash: Sha256,
}
impl Write for HashSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.checked_add(bytes.len() as u64).ok_or_else(|| io::Error::other("benchmark verification size overflow"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn validate_new_path(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() || path.components().any(|part| matches!(part, Component::ParentDir)) || path.try_exists()? {
        return Err(Error::Invalid("benchmark requires a NEW absolute path"));
    }
    if !path.parent().is_some_and(Path::is_dir) {
        return Err(Error::Invalid("benchmark parent directory must already exist"));
    }
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(Error::Invalid("benchmark path must not contain links"));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(Error::Invalid("benchmark path must not contain reparse points"));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn connect(service: &Service<MemoryCredentials>, root: &Path) -> Result<Client, Error> {
    let snapshot = &service.snapshot;
    let der = read_file(&root.join("tls/certificate.der"), 64 * 1024)?;
    let context = CredentialContext::certificate_der(&der, None).map_err(|_| Error::Integrity)?;
    let key = CredentialKey::new_scoped(&snapshot.origin, &snapshot.server_id, AUTHOR, Purpose::User, &context).map_err(|_| Error::Integrity)?;
    let secret = service.credentials.get(&key).map_err(|_| Error::Integrity)?.ok_or(Error::Integrity)?;
    let client = Client::https_with_ca(&snapshot.origin, AuthToken::parse(secret.expose().into())?, &der)?.bind_server(&snapshot.server_id)?;
    let identity = client.authenticated_identity()?;
    if identity.server_id != snapshot.server_id || identity.principal.id != AUTHOR || identity.principal.role != Role::Contributor {
        return Err(Error::Integrity);
    }
    Ok(client)
}
fn start_owned_server(root: &Path) -> Result<HttpsServer, Error> {
    let installation: service::Installation = serde_json::from_slice(&read_file(&root.join("console.json"), 16 * 1024)?)?;
    let der = read_file(&root.join("tls/certificate.der"), 64 * 1024)?;
    let key = read_file(&root.join("tls/private-key.der"), 16 * 1024)?;
    let config = HttpsConfig::from_der((Ipv4Addr::LOCALHOST, installation.port).into(), vec![der], key)?;
    HttpsServer::start(Store::open(&root.join("archive"))?, config)
}
/// Repeat one bounded chunk for large files; a unique per-file salt makes all
/// 100 small-file content hashes different without retaining their payloads.
fn prepare_source(buffer: &mut [u8], file: u64, seed: &str) {
    let mut hash = Sha256::new();
    hash.update(seed.as_bytes());
    hash.update(file.to_be_bytes());
    let salt = hash.finalize();
    for (offset, byte) in buffer.iter_mut().enumerate() {
        *byte = salt.get(offset % salt.len()).copied().unwrap_or_default() ^ ((offset / salt.len()) as u8);
    }
}
fn full_digest(buffer: &[u8], total: u64) -> Result<String, Error> {
    if buffer.is_empty() {
        return Err(Error::Invalid("empty benchmark source buffer"));
    }
    let mut hash = Sha256::new();
    let mut remaining = total;
    while remaining > 0 {
        let length = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| Error::Integrity)?;
        hash.update(buffer.get(..length).ok_or(Error::Integrity)?);
        remaining -= length as u64;
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn scenario(
    client: &Client,
    server: &HttpsServer,
    mode: Mode,
    large: bool,
    seed: &str,
    known_hashes: &mut BTreeSet<String>,
) -> Result<ScenarioMetrics, Error> {
    let scenario_started = Instant::now();
    let before_initial = server.metrics();
    let capability_started = Instant::now();
    let sdk = Sdk::new(client, mode)?;
    let mut upload_time = capability_started.elapsed();
    let mut observed_upload = metric_delta(before_initial, server.metrics())?;
    let mut observed_download = ServerMetrics::default();
    let caps = sdk.capabilities();
    let chunk_bytes = sdk.chunk_bytes();
    if !caps.binary_transfer_v1 || !caps.can_upload || !(CHUNK_BYTES..=8 * CHUNK_BYTES).contains(&chunk_bytes) {
        return Err(Error::Integrity);
    }
    let files = if large { 1 } else { 100 };
    let bytes_per_file = if large { 32 * MIB } else { 64 * 1024 };
    let mut source = vec![0u8; usize::try_from(chunk_bytes).map_err(|_| Error::Integrity)?];
    let mut chunks = 0u64;
    let mut preparation = Duration::ZERO;
    let mut verification = Duration::ZERO;
    for index in 0..files {
        let prepared = Instant::now();
        let source_length = usize::try_from(bytes_per_file.min(chunk_bytes)).map_err(|_| Error::Integrity)?;
        let buffer = source.get_mut(..source_length).ok_or(Error::Integrity)?;
        prepare_source(buffer, if large { 0 } else { index + 1 }, seed);
        let digest = full_digest(buffer, bytes_per_file)?;
        if !known_hashes.insert(digest.clone()) {
            return Err(Error::Integrity);
        }
        let chunk_hash = format!("{:x}", Sha256::digest(&*buffer));
        let request = format!("benchmark-{}-{index}", if large { "large" } else { "small" });
        let logical_path = format!("benchmark/{request}.bin");
        let input = TransferInput {
            server_id: caps.server_id.clone(),
            recovery_epoch: caps.recovery_epoch,
            request_id: request.clone(),
            target: TransferTarget::NewOnly { logical_path },
            total_bytes: bytes_per_file,
            sha256: digest.clone(),
            dependencies: Vec::new(),
            comment: "Disposable benchmark payload".into(),
        };
        preparation += prepared.elapsed();
        let before_upload = server.metrics();
        let upload_started = Instant::now();
        let transfer = sdk.begin(input)?;
        let mut offset = 0u64;
        while offset < bytes_per_file {
            let length = usize::try_from(chunk_bytes.min(bytes_per_file - offset)).map_err(|_| Error::Integrity)?;
            let bytes = buffer.get(..length).ok_or(Error::Integrity)?;
            let progress = sdk.chunk(&transfer.transfer_id, offset, bytes, &chunk_hash)?;
            offset = offset.checked_add(length as u64).ok_or(Error::Integrity)?;
            if progress.offset != offset {
                return Err(Error::Integrity);
            }
            chunks += 1;
        }
        let committed = sdk.commit(&transfer.transfer_id, &request)?;
        upload_time += upload_started.elapsed();
        let delta = metric_delta(before_upload, server.metrics())?;
        observed_upload.http_requests = observed_upload.http_requests.checked_add(delta.http_requests).ok_or(Error::Integrity)?;
        observed_upload.tls_connections = observed_upload.tls_connections.checked_add(delta.tls_connections).ok_or(Error::Integrity)?;
        if committed.version.sha256 != digest {
            return Err(Error::Integrity);
        }
        let before_download = server.metrics();
        let verify_started = Instant::now();
        let mut sink = HashSink::default();
        let version = sdk.download(&committed.version.reference, &mut sink)?;
        let verified_hash = format!("{:x}", sink.hash.finalize());
        if sink.bytes != bytes_per_file || version != committed.version || verified_hash != digest {
            return Err(Error::Integrity);
        }
        verification += verify_started.elapsed();
        let delta = metric_delta(before_download, server.metrics())?;
        observed_download.http_requests = observed_download.http_requests.checked_add(delta.http_requests).ok_or(Error::Integrity)?;
        observed_download.tls_connections = observed_download.tls_connections.checked_add(delta.tls_connections).ok_or(Error::Integrity)?;
    }
    let payload_bytes = files * bytes_per_file;
    let upload_wall_seconds = upload_time.as_secs_f64();
    Ok(ScenarioMetrics {
        scenario: if large { "single_32_mib" } else { "batch_100_by_64_kib" },
        files,
        chunks,
        payload_bytes,
        upload_wall_seconds,
        source_preparation_wall_seconds: preparation.as_secs_f64(),
        download_verification_wall_seconds: verification.as_secs_f64(),
        scenario_wall_seconds: scenario_started.elapsed().as_secs_f64(),
        payload_mb_per_second: payload_bytes as f64 / upload_wall_seconds.max(0.000_000_001) / 1_000_000.0,
        source_buffer_bytes: chunk_bytes,
        requested_chunk_bytes: mode.requested_chunk_bytes(),
        negotiated_chunk_bytes: chunk_bytes,
        upload_http_requests_observed: observed_upload.http_requests,
        upload_tls_connections_observed: observed_upload.tls_connections,
        download_http_requests_observed: observed_download.http_requests,
        download_tls_connections_observed: observed_download.tls_connections,
        initial_capability_http_requests_inferred: if mode.requested_chunk_bytes() > CHUNK_BYTES { 3 } else { 2 },
        upload_http_requests_inferred: if mode == Mode::Legacy {
            2 + 3 * (files * 2 + chunks)
        } else {
            (if mode.requested_chunk_bytes() > CHUNK_BYTES { 3 } else { 2 }) + files * 2 + chunks
        },
        download_http_requests_inferred: files * (if mode == Mode::Legacy { 3 } else { 1 }) + chunks,
        independent_digest_verified_files: files,
    })
}
fn publish_metrics(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    validate_new_path(path)?;
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let root = PathBuf::from(
        args.first()
            .ok_or("usage: transfer_benchmark NEW_ABSOLUTE_ROOT [--mode legacy|session1|session4|session8] [--json NEW_ABSOLUTE_METRICS_JSON]")?,
    );
    let mut mode = Mode::Legacy;
    let mut mode_set = false;
    let mut json = None;
    let mut index = 1;
    while index < args.len() {
        let value = args.get(index + 1).ok_or("benchmark option value missing")?;
        match args.get(index).map(String::as_str) {
            Some("--mode") if !mode_set => {
                mode = Mode::parse(value)?;
                mode_set = true;
            }
            Some("--json") if json.is_none() => {
                json = Some(PathBuf::from(value));
            }
            _ => return Err("benchmark accepts --mode and --json once each".into()),
        }
        index += 2;
    }
    validate_new_path(&root)?;
    if let Some(path) = &json {
        validate_new_path(path)?;
    }
    let started_unix_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let setup_started = Instant::now();
    let policy = StreamPolicy { version: 1, max_file_bytes: 64 * MIB, max_store_bytes: 20 * 1024 * MIB };
    let mut service = Service::new(MemoryCredentials::default());
    service.perform(Action::CreateConfigured { root: root.clone(), administrator: ADMINISTRATOR.into(), port: 0, stream_policy: policy.clone() })?;
    let created = service.perform(Action::CreateUser { id: AUTHOR.into(), role: Role::Contributor });
    let stopped = service.perform(Action::Stop);
    created?;
    stopped?;
    // Own the server handle directly for public counters, using exactly the
    // original private archive, loopback port, certificate and key just created.
    let server = start_owned_server(&root)?;
    let outcome = (|| {
        let client = connect(&service, &root)?;
        let setup = setup_started.elapsed();
        let seed = AuthToken::generate()?;
        let mut hashes = BTreeSet::new();
        let scenarios =
            vec![scenario(&client, &server, mode, true, &seed, &mut hashes)?, scenario(&client, &server, mode, false, &seed, &mut hashes)?];
        Ok::<_, Error>((setup, scenarios))
    })();
    let shutdown = server.shutdown();
    let (setup, scenarios) = outcome?;
    shutdown?;
    let metrics = Metrics {
        format: "solidcraft-transfer-benchmark/2",
        started_unix_seconds,
        transport: "owned loopback HTTPS with explicit original CA",
        sdk_mode: mode.label(),
        request_count_evidence: "observed owned-server HTTP/TLS counters; separately labelled source-inferred counts are not observations",
        request_count_model: "legacy initial=2, begin/chunk/commit=3 each; session initial=2 (+1 limits negotiation for requested >1MiB), begin/chunk/commit=1 each; verification excluded from upload counters",
        tls_counter_scope: "identity verified before scenario (connection warmup); upload counters measure additional connections, verification deltas reported separately",
        timed_upload_scope: "sum of sequential SDK upload wall intervals plus initial capability/session negotiation; source preparation and verified downloads excluded; no parallel files or requests",
        throughput_unit: "decimal MB/s (1 MB = 1000000 bytes)",
        credentials: "fresh random credentials held in MemoryCredentials; no OS keyring or bearer files",
        max_file_bytes: policy.max_file_bytes,
        max_archive_bytes: policy.max_store_bytes,
        fixture_setup_wall_seconds: setup.as_secs_f64(),
        owned_server_stopped: true,
        scenarios,
    };
    let bytes = serde_json::to_vec_pretty(&metrics)?;
    if let Some(path) = json {
        publish_metrics(&path, &bytes)?;
    }
    io::stdout().write_all(&bytes)?;
    io::stdout().write_all(b"\n")?;
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", serde_json::json!({"result":"error","code":"benchmark_failed","detail":error.to_string()}));
            std::process::ExitCode::FAILURE
        }
    }
}
