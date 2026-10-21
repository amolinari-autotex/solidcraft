//! Shared bounded HTTPS listener. No document or relay authority lives here.
use crate::Error;
use http_body_util::Full;
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    task::Poll,
    thread,
    time::Duration,
};
use tokio::{
    sync::{Semaphore, oneshot, watch},
    task::JoinSet,
};
const DEADLINE: Duration = Duration::from_secs(5);
pub(crate) type Reply = Response<Full<Bytes>>;
pub(crate) type Handler = Arc<dyn Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = Reply> + Send>> + Send + Sync>;
pub struct HttpsConfig {
    bind: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    pub(crate) keep_alive: bool,
}

impl HttpsConfig {
    pub fn from_der(bind: SocketAddr, certificates: Vec<Vec<u8>>, key: Vec<u8>) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Invalid("TLS versions"))?
            .with_no_client_auth()
            .with_single_cert(certificates.into_iter().map(Into::into).collect(), rustls::pki_types::PrivatePkcs8KeyDer::from(key).into())
            .map_err(|_| Error::Invalid("TLS certificate or private key"))?;
        Ok(Self { bind, tls: Arc::new(tls), keep_alive: false })
    }
}

pub(crate) struct HttpListener {
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    tls_connections: Arc<AtomicU64>,
}
impl HttpListener {
    pub(crate) fn start(config: HttpsConfig, handler: Handler, connections: usize, lifetime: Duration) -> Result<Self, Error> {
        Self::validate_limits(connections, lifetime)?;
        let listener = std::net::TcpListener::bind(config.bind)?;
        Self::start_with_listener(config, listener, handler, connections, lifetime)
    }
    fn validate_limits(connections: usize, lifetime: Duration) -> Result<(), Error> {
        if connections == 0 || connections > 32 || lifetime > Duration::from_secs(20) || lifetime.is_zero() {
            return Err(Error::Invalid("HTTPS listener limits"));
        }
        Ok(())
    }
    pub(crate) fn start_with_listener(
        config: HttpsConfig,
        listener: std::net::TcpListener,
        handler: Handler,
        connections: usize,
        lifetime: Duration,
    ) -> Result<Self, Error> {
        Self::validate_limits(connections, lifetime)?;
        let address = listener.local_addr()?;
        if address.ip() != config.bind.ip() || (config.bind.port() != 0 && config.bind.port() != address.port()) {
            return Err(Error::Invalid("HTTPS reserved listener does not match configuration"));
        }
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().max_blocking_threads(32).build()?;
        listener.set_nonblocking(true)?;
        let (stop, mut stopped) = oneshot::channel();
        let (ready, readiness) = mpsc::sync_channel(1);
        let tls_connections = Arc::new(AtomicU64::new(0));
        let observed_connections = tls_connections.clone();
        let thread = thread::Builder::new().name("pdm-https-listener".into()).spawn(move || {
            let listener = {
                let _entered = runtime.enter();
                match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                }
            };
            if ready.send(Ok(())).is_err() {
                return;
            }
            runtime.block_on(async move {
                let keep_alive = config.keep_alive;
                let acceptor = tokio_rustls::TlsAcceptor::from(config.tls);
                let permits = Arc::new(Semaphore::new(connections));
                let (shutdown, _) = watch::channel(false);
                let mut tasks = JoinSet::new();
                loop {
                    while tasks.try_join_next().is_some() {}
                    if !matches!(stopped.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
                        break;
                    }
                    match tokio::time::timeout(Duration::from_millis(100), listener.accept()).await {
                        Ok(Ok((stream, _))) => {
                            let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                            let acceptor = acceptor.clone();
                            let handler = handler.clone();
                            let observed_connections = observed_connections.clone();
                            let mut shutdown = shutdown.subscribe();
                            tasks.spawn(async move {
                                let _permit = permit;
                                let Ok(Ok(tls)) = tokio::time::timeout(DEADLINE, acceptor.accept(stream)).await else { return };
                                observed_connections.fetch_add(1, Ordering::Relaxed);
                                if *shutdown.borrow() {
                                    return;
                                }
                                let mut builder = hyper::server::conn::http1::Builder::new();
                                builder
                                    .timer(TokioTimer::new())
                                    .header_read_timeout(DEADLINE)
                                    .max_headers(32)
                                    .max_buf_size(16 * 1024)
                                    .keep_alive(keep_alive);
                                let service = service_fn(move |request| {
                                    let future = handler(request);
                                    async move { Ok::<_, std::convert::Infallible>(future.await) }
                                });
                                let mut connection = Box::pin(builder.serve_connection(TokioIo::new(tls), service));
                                let mut lifetime = Box::pin(tokio::time::sleep(lifetime));
                                let mut stopped = Box::pin(shutdown.changed());
                                let mut draining = false;
                                let mut drain_deadline = None;
                                poll_fn(|cx| {
                                    if !draining {
                                        let expired = lifetime.as_mut().poll(cx).is_ready();
                                        if expired && !keep_alive {
                                            return Poll::Ready(());
                                        }
                                        if expired || stopped.as_mut().poll(cx).is_ready() {
                                            // Retire this connection without cutting an admitted
                                            // request/response at the absolute lifetime boundary.
                                            connection.as_mut().graceful_shutdown();
                                            draining = true;
                                            drain_deadline = Some(Box::pin(tokio::time::sleep(DEADLINE)));
                                        }
                                    }
                                    // Never poll the expired lifetime again: the one-shot
                                    // transition above owns a separate bounded drain timer.
                                    if let Some(deadline) = &mut drain_deadline
                                        && deadline.as_mut().poll(cx).is_ready()
                                    {
                                        return Poll::Ready(());
                                    }
                                    connection.as_mut().poll(cx).map(|_| ())
                                })
                                .await;
                            });
                        }
                        Ok(Err(_)) => break,
                        Err(_) => continue,
                    }
                }
                // Stop accepting before telling every owned connection to drain.
                // Idle keep-alive connections close immediately; active handlers
                // may finish within this bounded grace period.
                drop(listener);
                let _ = shutdown.send(true);
                if tokio::time::timeout(DEADLINE, async { while tasks.join_next().await.is_some() {} }).await.is_err() {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                }
            });
            // Blocking handlers have explicit <=10s deadlines; shutdown waits for them.
            drop(runtime);
        })?;
        let mut listener = Self { address, stop: Some(stop), thread: Some(thread), tls_connections };
        match readiness.recv_timeout(DEADLINE) {
            Ok(Ok(())) => Ok(listener),
            Ok(Err(error)) => {
                let _ = listener.close();
                Err(Error::Io(error))
            }
            Err(_) => {
                let _ = listener.close();
                Err(Error::Invalid("HTTPS startup failed"))
            }
        }
    }
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }
    pub(crate) fn tls_connections(&self) -> u64 {
        self.tls_connections.load(Ordering::Relaxed)
    }
    pub(crate) fn shutdown(mut self) -> Result<(), Error> {
        self.close()
    }
    fn close(&mut self) -> Result<(), Error> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| Error::Invalid("HTTPS worker failed"))?;
        }
        Ok(())
    }
}
impl Drop for HttpListener {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod lifetime_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpStream,
        time::Instant,
    };

    fn listener(delay: Duration, keep_alive: bool) -> HttpListener {
        let mut config = HttpsConfig::from_der(
            "127.0.0.1:0".parse().unwrap(),
            vec![include_bytes!("../tests/fixtures/pdm-https/server.der").to_vec()],
            include_bytes!("../tests/fixtures/pdm-https/server-key.der").to_vec(),
        )
        .unwrap();
        config.keep_alive = keep_alive;
        let handler: Handler = Arc::new(move |_| {
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Response::new(Full::new(Bytes::from_static(b"completed")))
            })
        });
        HttpListener::start(config, handler, 1, Duration::from_millis(100)).unwrap()
    }
    fn tls(address: SocketAddr) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(include_bytes!("../tests/fixtures/pdm-https/ca.der").as_slice())).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connection = rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
        let socket = TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        rustls::StreamOwned::new(connection, socket)
    }
    #[test]
    fn lifetime_expiry_drains_the_active_response_instead_of_aborting_it() {
        let listener = listener(Duration::from_millis(200), true);
        let mut client = tls(listener.address());
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        assert!(response.starts_with(b"HTTP/1.1 200"), "active response was cut at the 100ms lifetime");
        assert!(response.ends_with(b"completed"), "active response body was truncated");
        listener.shutdown().unwrap();
    }
    #[test]
    fn lifetime_expiry_closes_an_idle_connection_immediately() {
        let listener = listener(Duration::ZERO, true);
        let mut client = tls(listener.address());
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
            assert!(head.len() < 8192);
        }
        let mut body = [0u8; 9];
        client.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"completed");
        let started = Instant::now();
        let mut byte = [0u8; 1];
        assert!(!matches!(client.read(&mut byte), Ok(count) if count > 0));
        assert!(started.elapsed() < Duration::from_secs(2));
        listener.shutdown().unwrap();
    }
    #[test]
    fn lifetime_expiry_has_a_five_second_hard_drain_bound() {
        let listener = listener(Duration::from_secs(30), true);
        let mut client = tls(listener.address());
        let started = Instant::now();
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        assert!(!response.starts_with(b"HTTP/1.1 200"));
        assert!(started.elapsed() >= Duration::from_secs(4), "active request was aborted before its drain grace");
        assert!(started.elapsed() < Duration::from_secs(7), "active request exceeded the hard drain bound");
        listener.shutdown().unwrap();
    }

    #[test]
    fn single_request_listener_keeps_original_hard_lifetime() {
        let listener = listener(Duration::from_millis(200), false);
        let mut client = tls(listener.address());
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        assert!(!response.starts_with(b"HTTP/1.1 200"), "single-request response exceeded the original 100ms hard lifetime");
        listener.shutdown().unwrap();
    }
}
