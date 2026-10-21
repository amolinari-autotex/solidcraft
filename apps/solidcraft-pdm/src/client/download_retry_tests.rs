//! Pinned-TLS regressions for bounded, network-only adaptive download retries.
//! A raw owned listener can deliberately close a TLS body midway through its
//! declared Content-Length; the normal Full-body listener cannot model this.
use super::Client;
use crate::{
    AuthToken, AuthenticatedIdentity, Error, HTTP_RPC_PATH, Response, Version, VersionRef,
    managed::{Principal, Role},
    stream_io::StreamPolicy,
    transfers::{self, ContentMetadata, TransferCapabilities, TransferLimits, WireResponse},
};
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const MIB: u64 = 1024 * 1024;
const CA: &[u8] = include_bytes!("../../tests/fixtures/pdm-https/ca.der");
const CERTIFICATE: &[u8] = include_bytes!("../../tests/fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/pdm-https/server-key.der");

#[derive(Clone, Copy)]
enum Fault {
    TruncateMetadata,
    RejectMetadataTruncated(u16),
    TruncateFirst,
    TruncateAll,
    Reject(u16, &'static str),
    RejectTruncated(u16),
    WrongChunkHash,
    WrongOffset,
    None,
}

struct Fixture {
    client: Client,
    version: Version,
    bytes: Arc<Vec<u8>>,
    ranges: Arc<Mutex<Vec<(u64, u64)>>>,
    unexpected: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

fn server_id() -> String {
    "a".repeat(64)
}
fn principal() -> Principal {
    Principal { id: "adaptive-reader".into(), role: Role::Contributor }
}

impl Fixture {
    fn new(fault: Fault, total: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = Arc::new((0..total).map(|index| (index % 251) as u8).collect::<Vec<_>>());
        let version = Version {
            reference: VersionRef { document: "c".repeat(64), version: 1 },
            parent: None,
            sha256: crate::digest(&bytes),
            dependencies: Vec::new(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(vec![CERTIFICATE.to_vec().into()], rustls::pki_types::PrivatePkcs8KeyDer::from(KEY.to_vec()).into())?,
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let ranges = Arc::new(Mutex::new(Vec::new()));
        let unexpected = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let state = State { bytes: bytes.clone(), version: version.clone(), ranges: ranges.clone(), unexpected: unexpected.clone(), fault };
        let stopping = stop.clone();
        let thread = thread::Builder::new().name("pdm-download-fault-tls".into()).spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Client rejection of intentionally malformed headers may
                        // close before our write completes. That is expected.
                        if let Err(error) = serve(stream, tls.clone(), &state) {
                            // All errors originate in fixture/TLS/IO parsing;
                            // request headers, bodies and credentials are never
                            // interpolated into these phase diagnostics.
                            eprintln!("download fixture connection failed: {error}");
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                    Err(_) => {
                        state.unexpected.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        })?;
        let client = Client::https_with_ca(&format!("https://{address}"), AuthToken::parse("b".repeat(64))?, CA)?.bind_server(&server_id())?;
        Ok(Self { client, version, bytes, ranges, unexpected, stop, thread: Some(thread) })
    }

    fn requests(&self) -> Result<Vec<(u64, u64)>, io::Error> {
        self.ranges.lock().map(|ranges| ranges.clone()).map_err(|_| io::Error::other("range ledger poisoned"))
    }

    fn finish(mut self) -> TestResult {
        self.join()?;
        assert_eq!(self.unexpected.load(Ordering::Relaxed), 0, "fixture rejected an unexpected route or unbounded request");
        Ok(())
    }

    fn join(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| io::Error::other("TLS fixture thread failed"))?;
        }
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Preserve bounded cleanup even if a regression assertion fails.
        let _cleanup_result = self.join();
    }
}

struct State {
    bytes: Arc<Vec<u8>>,
    version: Version,
    ranges: Arc<Mutex<Vec<(u64, u64)>>>,
    unexpected: Arc<AtomicUsize>,
    fault: Fault,
}

fn serve(socket: TcpStream, config: Arc<rustls::ServerConfig>, state: &State) -> Result<(), Box<dyn std::error::Error>> {
    // Accepted sockets may inherit nonblocking mode on Windows. This fixture
    // uses synchronous rustls IO, so explicitly restore blocking BEFORE TLS.
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let connection = rustls::ServerConnection::new(config)?;
    let mut tls = rustls::StreamOwned::new(connection, socket);
    let target = request_target(&mut tls).map_err(|error| io::Error::other(format!("fixture TLS/HTTP request phase: {error}")))?;
    let path = target.split('?').next().ok_or_else(|| io::Error::other("HTTP target"))?;
    let content_path = format!("/pdm/v1/content/{}/1", state.version.reference.document);
    if path == HTTP_RPC_PATH {
        return json(&mut tls, 200, &Response::Identity { identity: AuthenticatedIdentity { server_id: server_id(), principal: principal() } });
    }
    if path == transfers::CAPABILITIES_PATH {
        return json(
            &mut tls,
            200,
            &WireResponse::Capabilities {
                capabilities: TransferCapabilities {
                    protocol: transfers::PROTOCOL.into(),
                    server_id: server_id(),
                    recovery_epoch: 1,
                    principal: principal(),
                    binary_transfer_v1: true,
                    can_upload: true,
                    limits: Some(StreamPolicy { version: 1, max_file_bytes: 64 * MIB, max_store_bytes: 20 * 1024 * MIB }),
                    chunk_bytes: MIB,
                },
            },
        );
    }
    if path == transfers::LIMITS_PATH {
        return json(
            &mut tls,
            200,
            &WireResponse::Limits {
                limits: TransferLimits {
                    protocol: transfers::LIMITS_PROTOCOL.into(),
                    server_id: server_id(),
                    recovery_epoch: 1,
                    principal: principal(),
                    max_chunk_bytes: 8 * MIB,
                },
            },
        );
    }
    if path == format!("{content_path}/metadata") {
        if let Fault::RejectMetadataTruncated(status) = state.fault {
            write!(
                tls,
                "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{{\"result\":\"error\""
            )?;
            tls.flush()?;
            return Ok(());
        }
        if matches!(state.fault, Fault::TruncateMetadata) {
            tls.write_all(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"result\":\"metadata\"",
            )?;
            tls.flush()?;
            return Ok(());
        }
        return json(
            &mut tls,
            200,
            &WireResponse::Metadata { metadata: ContentMetadata { version: state.version.clone(), total_bytes: state.bytes.len() as u64 } },
        );
    }
    if path != content_path {
        state.unexpected.fetch_add(1, Ordering::Relaxed);
        return json(&mut tls, 404, &WireResponse::error("not_found"));
    }
    let query = target.split_once('?').map(|(_, query)| query).ok_or_else(|| io::Error::other("range missing query"))?;
    let parameter = |name: &str| -> Result<u64, Box<dyn std::error::Error>> {
        let value = query
            .split('&')
            .filter_map(|item| item.split_once('='))
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
            .ok_or_else(|| io::Error::other("range missing parameter"))?;
        Ok(value.parse()?)
    };
    let offset = parameter("offset")?;
    let length = parameter("length")?;
    let attempt = {
        let mut ranges = state.ranges.lock().map_err(|_| io::Error::other("range ledger poisoned"))?;
        if ranges.len() >= 32 {
            state.unexpected.fetch_add(1, Ordering::Relaxed);
            return json(&mut tls, 503, &WireResponse::error("fixture_retry_bound"));
        }
        ranges.push((offset, length));
        ranges.len()
    };
    if let Fault::Reject(status, code) = state.fault {
        return json(&mut tls, status, &WireResponse::error(code));
    }
    if let Fault::RejectTruncated(status) = state.fault {
        // The HTTP status is definitive even when its explanatory JSON body
        // cannot be decoded because the transport ends early.
        write!(
            tls,
            "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{{\"result\":\"error\""
        )?;
        tls.flush()?;
        return Ok(());
    }
    let start = usize::try_from(offset)?;
    let end = usize::try_from(offset.checked_add(length).ok_or_else(|| io::Error::other("range overflow"))?)?;
    let bytes = state.bytes.get(start..end).ok_or_else(|| io::Error::other("range out of bounds"))?;
    let hash = if matches!(state.fault, Fault::WrongChunkHash) { "0".repeat(64) } else { crate::digest(bytes) };
    let advertised_offset = if matches!(state.fault, Fault::WrongOffset) { offset + 1 } else { offset };
    write!(
        tls,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: {length}\r\nx-pdm-sha256: {}\r\nx-pdm-offset: {advertised_offset}\r\nx-pdm-total-bytes: {}\r\nx-chunk-sha256: {hash}\r\n\r\n",
        state.version.sha256,
        state.bytes.len()
    )?;
    if matches!(state.fault, Fault::TruncateAll) || (matches!(state.fault, Fault::TruncateFirst) && attempt == 1) {
        // Intentionally corrupt AND truncate the unacknowledged prefix. A
        // downloader must discard all of it before the smaller retry.
        tls.write_all(&vec![255; 17 * 1024])?;
        tls.flush()?;
        return Ok(()); // Abrupt TLS EOF, no close_notify or complete HTTP body.
    }
    tls.write_all(bytes)?;
    tls.flush()?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

fn request_target(tls: &mut impl Read) -> Result<String, Box<dyn std::error::Error>> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 16 * 1024 {
            return Err(io::Error::other("HTTP request headers exceed fixture bound").into());
        }
        let mut byte = [0u8; 1];
        tls.read_exact(&mut byte)?;
        header.extend_from_slice(&byte);
    }
    let header = std::str::from_utf8(&header)?;
    let target =
        header.lines().next().and_then(|line| line.split_whitespace().nth(1)).ok_or_else(|| io::Error::other("HTTP request line"))?.to_owned();
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    if length > transfers::CONTROL_BYTES {
        return Err(io::Error::other("HTTP request body exceeds fixture bound").into());
    }
    let mut body = vec![0; length];
    tls.read_exact(&mut body)?;
    Ok(target)
}

fn json(
    tls: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    status: u16,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(value)?;
    write!(tls, "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", bytes.len())?;
    tls.write_all(&bytes)?;
    tls.flush()?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

#[test]
fn truncated_range_retries_same_offset_and_keeps_smaller_file_cap() -> TestResult {
    let fixture = Fixture::new(Fault::TruncateFirst, (12 * MIB) as usize)?;
    let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
    assert_eq!(session.chunk_bytes(), 8 * MIB);
    let mut output = Vec::new();
    let version = session.download_stream(&fixture.version.reference, &mut output)?;
    assert_eq!(version, fixture.version);
    assert_eq!(output, *fixture.bytes, "a failed body's partial prefix must never reach output");
    assert_eq!(fixture.requests()?, vec![(0, 8 * MIB), (0, 4 * MIB), (4 * MIB, 4 * MIB), (8 * MIB, 4 * MIB)]);
    fixture.finish()
}

#[test]
fn network_retry_ladder_is_bounded_and_never_publishes_partial_bytes() -> TestResult {
    let fixture = Fixture::new(Fault::TruncateAll, (8 * MIB) as usize)?;
    let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
    let mut output = Vec::new();
    assert!(matches!(session.download_stream(&fixture.version.reference, &mut output), Err(Error::Network(_))));
    assert!(output.is_empty());
    assert_eq!(fixture.requests()?, vec![(0, 8 * MIB), (0, 4 * MIB), (0, MIB), (0, 256 * 1024), (0, 64 * 1024)]);
    fixture.finish()
}

#[test]
fn small_file_network_retry_does_not_repeat_nominal_size_reductions() -> TestResult {
    let fixture = Fixture::new(Fault::TruncateAll, 64 * 1024)?;
    let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
    let mut output = Vec::new();
    assert!(matches!(session.download_stream(&fixture.version.reference, &mut output), Err(Error::Network(_))));
    assert!(output.is_empty());
    assert_eq!(fixture.requests()?, vec![(0, 64 * 1024); 2]);
    fixture.finish()
}

#[test]
fn metadata_body_failure_retains_safe_transport_phase_and_io_kind_without_range_attempts() -> TestResult {
    let fixture = Fixture::new(Fault::TruncateMetadata, 64 * 1024)?;
    let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
    let mut output = Vec::new();
    let error = session.download_stream(&fixture.version.reference, &mut output).unwrap_err();
    let Error::Network(sanitized) = error else { return Err(io::Error::other("expected sanitized network error").into()) };
    assert_eq!(sanitized.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(sanitized.to_string(), "PDM HTTPS transport failed");
    assert!(std::error::Error::source(&sanitized).is_none());
    let safe = sanitized
        .get_ref()
        .and_then(|error| error.downcast_ref::<super::HttpsTransportFailure>())
        .ok_or_else(|| io::Error::other("safe diagnostics missing"))?;
    assert_eq!(safe.phase, super::HttpsPhase::MetadataBody);
    assert_eq!(safe.class, super::HttpsErrorClass::Io);
    assert_eq!(safe.io_kind, io::ErrorKind::UnexpectedEof);
    assert_eq!(safe.http_status, Some(200));
    assert_eq!(safe.timeout, None);
    assert!(output.is_empty());
    assert!(fixture.requests()?.is_empty());

    // Observe the same deliberately malformed LOCAL fixture without the SDK's
    // sanitizer. Emit enum classes only: no error Display/Debug, URL or headers.
    let (origin, agent) = fixture.client.direct_extension_origin()?;
    let caps = session.capabilities();
    let request = ureq::http::Request::builder()
        .method("GET")
        .uri(format!("{origin}/pdm/v1/content/{}/1/metadata", fixture.version.reference.document))
        .header("authorization", super::authorization_header(&fixture.client.token)?)
        .header("x-pdm-server-id", &caps.server_id)
        .header("x-pdm-recovery-epoch", caps.recovery_epoch.to_string())
        .header("content-length", "0")
        .body(&[] as &[u8])?;
    let mut response = agent.run(request)?;
    assert_eq!(response.status().as_u16(), 200);
    let raw_error = response.body_mut().with_config().limit(transfers::CONTROL_BYTES as u64 + 1).read_to_vec().unwrap_err();
    let class = match &raw_error {
        ureq::Error::Io(error) => {
            eprintln!("WAN_LOCAL_DIAGNOSTIC phase=metadata_body http_status=200 error_class=io io_kind={:?}", error.kind());
            "io"
        }
        ureq::Error::Protocol(_) => "protocol",
        ureq::Error::Rustls(_) => "tls",
        ureq::Error::Timeout(_) => "timeout",
        _ => "other",
    };
    eprintln!(
        "WAN_LOCAL_DIAGNOSTIC phase=metadata_body raw_error_class={class} sdk_error_class=network sdk_io_kind=UnexpectedEof safe_phase_retained=true raw_source_retained=false output_bytes=0 injected=truncated_metadata"
    );
    assert!(matches!(class, "io" | "protocol" | "tls"));
    fixture.finish()
}

#[test]
fn metadata_status_rejection_survives_truncated_body_and_invalidates_only_authentication() -> TestResult {
    for (status, code) in [(401, "unauthorized"), (403, "forbidden"), (503, "unavailable")] {
        let fixture = Fixture::new(Fault::RejectMetadataTruncated(status), 64 * 1024)?;
        let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
        let mut output = Vec::new();
        assert!(matches!(session.download_stream(&fixture.version.reference, &mut output), Err(Error::Server(actual)) if actual == code));
        assert!(fixture.requests()?.is_empty());
        assert!(output.is_empty(), "a rejected metadata response never authorizes content publication");
        let expected = if status == 503 { "unavailable" } else { "transfer_session_invalidated" };
        assert!(matches!(session.download_stream(&fixture.version.reference, &mut output), Err(Error::Server(actual)) if actual == expected));
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn metadata_known_error_status_with_truncated_body_is_not_a_network_retry() -> TestResult {
    let fixture = Fixture::new(Fault::RejectMetadataTruncated(409), 64 * 1024)?;
    let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
    let mut output = Vec::new();
    assert!(matches!(session.download_stream(&fixture.version.reference, &mut output), Err(Error::Invalid("metadata error response"))));
    assert!(fixture.requests()?.is_empty());
    assert!(output.is_empty());
    fixture.finish()
}

#[test]
fn one_transient_small_range_failure_can_recover_without_publishing_the_failed_prefix() -> TestResult {
    let fixture = Fixture::new(Fault::TruncateFirst, 64 * 1024)?;
    let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
    let mut output = Vec::new();
    assert_eq!(session.download_stream(&fixture.version.reference, &mut output)?, fixture.version);
    assert_eq!(output, *fixture.bytes);
    assert_eq!(fixture.requests()?, vec![(0, 64 * 1024); 2]);
    fixture.finish()
}

#[test]
fn authorization_and_epoch_failures_never_retry_or_shrink() -> TestResult {
    for (status, code) in [(401, "unauthorized"), (403, "forbidden"), (409, "recovery_epoch_mismatch")] {
        let fixture = Fixture::new(Fault::Reject(status, code), (8 * MIB) as usize)?;
        let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
        let mut output = Vec::new();
        assert!(matches!(session.download_stream(&fixture.version.reference, &mut output), Err(Error::Server(actual)) if actual == code));
        assert!(output.is_empty());
        assert_eq!(fixture.requests()?, vec![(0, 8 * MIB)]);
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn known_error_status_with_truncated_error_body_never_retries() -> TestResult {
    for status in [401, 403, 409, 503] {
        let fixture = Fixture::new(Fault::RejectTruncated(status), (8 * MIB) as usize)?;
        let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
        let mut output = Vec::new();
        assert!(session.download_stream(&fixture.version.reference, &mut output).is_err());
        assert!(output.is_empty());
        assert_eq!(fixture.requests()?, vec![(0, 8 * MIB)], "known HTTP {status} must not become a retryable network failure");
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn complete_body_hash_or_range_header_failure_never_retries() -> TestResult {
    for fault in [Fault::WrongChunkHash, Fault::WrongOffset] {
        let fixture = Fixture::new(fault, (8 * MIB) as usize)?;
        let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
        let mut output = Vec::new();
        assert!(matches!(session.download_stream(&fixture.version.reference, &mut output), Err(Error::Integrity)));
        assert!(output.is_empty());
        assert_eq!(fixture.requests()?, vec![(0, 8 * MIB)]);
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn caller_output_io_failure_is_not_a_network_retry() -> TestResult {
    struct FailedOutput(usize);
    impl Write for FailedOutput {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            self.0 += 1;
            Err(io::Error::other("synthetic output failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let fixture = Fixture::new(Fault::None, (12 * MIB) as usize)?;
    let session = fixture.client.transfer_session_with_chunk_bytes(8 * MIB)?;
    let mut output = FailedOutput(0);
    assert!(matches!(session.download_stream(&fixture.version.reference, &mut output), Err(Error::Io(_))));
    assert_eq!(output.0, 1);
    assert_eq!(fixture.requests()?, vec![(0, 8 * MIB)]);
    fixture.finish()
}
