//! Experimental PDM service. Remote HTTPS is an explicit deployment command;
//! ordinary serve/rehearsal commands retain their existing loopback boundaries.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use solidcraft_pdm::{
    AuthToken, Error, Request, Store, VersionRef, bind_loopback,
    client::{Client, read_file},
    read_frame, serve_connection,
};
use std::{
    io::{self, BufRead, Read, Write},
    path::Path,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let argument = |index| args.get(index).map(String::as_str).ok_or(Error::Invalid("missing argument"));
    match args.get(1).map(String::as_str) {
        Some("serve-https-remote") if args.len() == 3 => serve_https_remote(Path::new(argument(2)?))?,
        Some("rehearse-https") if args.len() == 3 => {
            let config = solidcraft_pdm::deployment::DeploymentConfig::load(Path::new(argument(2)?))?;
            let server = solidcraft_pdm::deployment::start_loopback_rehearsal(config)?;
            {
                let mut output = io::stdout().lock();
                serde_json::to_writer(&mut output, server.receipt())?;
                writeln!(output)?;
                output.flush()?;
            }
            // The private launcher owns stdin for this isolated rehearsal.
            // Closing it or sending one shutdown line stops only this server.
            let mut command = Vec::new();
            io::stdin().lock().take(1025).read_until(b'\n', &mut command)?;
            if command.len() > 1024 || !matches!(command.as_slice(), b"" | b"shutdown\n" | b"shutdown\r\n") {
                return Err(Error::Invalid("deployment rehearsal control").into());
            }
            server.shutdown()?;
        }
        Some("backup") if args.len() == 4 => {
            let store = Store::open(Path::new(argument(2)?))?;
            let receipt = store.backup(Path::new(argument(3)?))?;
            serde_json::to_writer_pretty(io::stdout().lock(), &receipt)?;
            println!();
        }
        Some("restore") if args.len() == 4 => {
            let receipt = solidcraft_pdm::backup_restore::restore_backup(Path::new(argument(2)?), Path::new(argument(3)?))?;
            serde_json::to_writer_pretty(io::stdout().lock(), &receipt)?;
            println!();
        }
        Some("restore-redb") if args.len() == 4 => {
            let receipt = solidcraft_pdm::backup_restore::restore_backup_to_redb(Path::new(argument(2)?), Path::new(argument(3)?))?;
            serde_json::to_writer_pretty(io::stdout().lock(), &receipt)?;
            println!();
        }
        Some("verify-backup") if args.len() == 3 => {
            let receipt = solidcraft_pdm::backup_restore::verify_backup(Path::new(argument(2)?))?;
            serde_json::to_writer_pretty(io::stdout().lock(), &receipt)?;
            println!();
        }
        Some("token") if args.len() == 2 => {
            // Intentional credential output only for this explicitly invoked bootstrap command.
            println!("{}", AuthToken::generate()?);
        }
        Some("serve") if args.len() == 4 => {
            let root = args.get(2).ok_or(Error::Invalid("store path"))?;
            let port = args.get(3).ok_or(Error::Invalid("port"))?.parse::<u16>()?;
            let token = AuthToken::from_env()?;
            let mut store = Store::open(Path::new(root))?;
            let listener = bind_loopback(port)?;
            eprintln!("Experimental PDM listening on {}; toy documents only", listener.local_addr()?);
            for stream in listener.incoming() {
                if let Err(error) = stream.map_err(Error::from).and_then(|stream| serve_connection(&mut store, stream, &token)) {
                    eprintln!("PDM connection failed: {error}");
                }
            }
        }
        Some("request") if args.len() == 3 => {
            let port = args.get(2).ok_or(Error::Invalid("port"))?.parse::<u16>()?;
            let request: Request = serde_json::from_slice(&read_frame(io::stdin().lock())?)?;
            let response = Client::new(port, AuthToken::from_env()?).request(request)?;
            serde_json::to_writer(io::stdout().lock(), &response)?;
            println!();
        }
        Some("list") if (3..=4).contains(&args.len()) => {
            let client = Client::new(argument(2)?.parse()?, AuthToken::from_env()?);
            serde_json::to_writer_pretty(io::stdout().lock(), &client.list(args.get(3).cloned())?)?;
            println!();
        }
        Some("check-in") if (6..=7).contains(&args.len()) => {
            let client = Client::new(argument(2)?.parse()?, AuthToken::from_env()?);
            let parent = match argument(4)? { "-" => None, value => Some(value.parse()?) };
            let dependencies = match args.get(6) {
                Some(path) => serde_json::from_slice(&read_file(Path::new(path), 64 * 1024)?)?,
                None => Vec::new(),
            };
            let version = client.check_in_file(argument(3)?.into(), parent, Path::new(argument(5)?), dependencies)?;
            serde_json::to_writer_pretty(io::stdout().lock(), &version)?;
            println!();
        }
        Some("retrieve") if args.len() == 6 => {
            let client = Client::new(argument(2)?.parse()?, AuthToken::from_env()?);
            let reference = VersionRef { document: argument(3)?.into(), version: argument(4)?.parse()? };
            let snapshot = client.retrieve(reference, Path::new(argument(5)?))?;
            serde_json::to_writer_pretty(io::stdout().lock(), &snapshot)?;
            println!();
        }
        _ => return Err("usage: solidcraft-pdm token | serve STORE PORT | rehearse-https CONFIG | serve-https-remote CONFIG | backup STORE NEW_BACKUP | restore BACKUP NEW_STORE | restore-redb BACKUP NEW_STORE | verify-backup BACKUP | request PORT | list PORT [DOCUMENT] | check-in PORT DOCUMENT PARENT_OR_- FILE [DEPENDENCIES_JSON] | retrieve PORT DOCUMENT VERSION NEW_DIRECTORY".into()),
    }
    Ok(())
}

struct ShutdownSignals {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(windows)]
    interrupt: tokio::signal::windows::CtrlC,
}
impl ShutdownSignals {
    fn register() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self { terminate: signal(SignalKind::terminate())?, interrupt: signal(SignalKind::interrupt())? })
        }
        #[cfg(windows)]
        {
            Ok(Self { interrupt: tokio::signal::windows::ctrl_c()? })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "remote service signal handling is unsupported on this platform"))
        }
    }
    async fn wait(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            #[cfg(unix)]
            if self.terminate.poll_recv(cx).is_ready() {
                return std::task::Poll::Ready(Ok(()));
            }
            #[cfg(any(unix, windows))]
            if self.interrupt.poll_recv(cx).is_ready() {
                return std::task::Poll::Ready(Ok(()));
            }
            std::task::Poll::Pending
        })
        .await
    }
}
fn serve_https_remote(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        // Install both Unix handlers before binding or reporting readiness.
        // stdin is deliberately unused: systemd commonly supplies /dev/null.
        let mut shutdown = ShutdownSignals::register()?;
        let config = solidcraft_pdm::deployment::DeploymentConfig::load_explicit_remote(path)?;
        let server = solidcraft_pdm::deployment::start_explicit_remote(config)?;
        {
            let mut output = io::stdout().lock();
            serde_json::to_writer(&mut output, server.receipt())?;
            writeln!(output)?;
            output.flush()?;
        }
        shutdown.wait().await?;
        server.shutdown()?;
        Ok(())
    })
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
