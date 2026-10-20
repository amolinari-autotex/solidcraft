//! Explicit disposable server demonstration. Public fixture credentials and TLS
//! keys only: never reuse this configuration for private designs or a LAN.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Error, Store, backup_restore,
    client::Client,
    deployment::DeploymentConfig,
    managed::{ManagedCheckIn, Principal, PrincipalCredential, Role},
};
use std::{fs, path::Path};
const CA: &[u8] = include_bytes!("../tests/fixtures/pdm-https/ca.der");
const CERT: &[u8] = include_bytes!("../tests/fixtures/pdm-https/server.der");
const KEY: &[u8] = include_bytes!("../tests/fixtures/pdm-https/server-key.der");

fn prepare(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !root.is_absolute() {
        return Err(Error::Invalid("absolute new demo path required").into());
    }
    fs::create_dir(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    let seed = root.join("seed");
    fs::create_dir(&seed)?;
    let credentials = [
        PrincipalCredential {
            principal: Principal { id: "demo-admin".into(), role: Role::Administrator },
            token_sha256: format!("{:x}", Sha256::digest("a".repeat(64).as_bytes())),
        },
        PrincipalCredential {
            principal: Principal { id: "demo-reader".into(), role: Role::Viewer },
            token_sha256: format!("{:x}", Sha256::digest("b".repeat(64).as_bytes())),
        },
    ];
    fs::write(seed.join("managed-principals.json"), serde_json::to_vec(&credentials)?)?;
    Store::open(&seed)?.backup(&root.join("seed-backup"))?;
    let store = root.join("database-store");
    backup_restore::restore_backup_to_redb(&root.join("seed-backup"), &store)?;
    fs::write(root.join("server.der"), CERT)?;
    fs::write(root.join("test-key.der"), KEY)?;
    let config = DeploymentConfig {
        store,
        bind: "127.0.0.1:0".parse()?,
        certificate_chain: vec![root.join("server.der")],
        private_key: root.join("test-key.der"),
    };
    fs::write(root.join("deployment.json"), serde_json::to_vec_pretty(&config)?)?;
    println!("Prepared disposable database demo with public fixture credentials.");
    Ok(())
}
fn probe(address: &str, server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let connect = |token: String| -> Result<Client, Error> {
        Client::https_with_ca(&format!("https://{address}"), AuthToken::parse(token)?, CA)?.bind_server(server)
    };
    let client = connect("a".repeat(64))?;
    let viewer = connect("b".repeat(64))?;
    if viewer.authenticated_identity()?.principal.role != Role::Viewer || viewer.managed_create("must-not-exist.txt".into()).is_ok() {
        return Err(Error::Integrity.into());
    }
    let identity = client.authenticated_identity()?;
    if identity.principal.role != Role::Administrator {
        return Err(Error::Integrity.into());
    }
    if client.managed_catalog()?.entries.is_empty() {
        let entry = client.managed_create("server-demo.txt".into())?;
        let grant = client.managed_checkout(entry.document.clone(), "demo-workspace".into(), "demo-machine".into())?;
        let input = ManagedCheckIn {
            document: entry.document,
            workspace: "demo-workspace".into(),
            machine: "demo-machine".into(),
            checkout_token: grant.token,
            request_id: "demo-first".into(),
            parent: None,
            content: b"Disposable server metadata demonstration. This is not a CAD design.\n".to_vec(),
            dependencies: vec![],
            comment: "First transactional demo version".into(),
        };
        let version = client.managed_check_in(input.clone())?;
        if client.managed_check_in(input.clone())? != version || client.download(&version.version.reference)?.1 != input.content {
            return Err(Error::Integrity.into());
        }
    }
    let catalog = viewer.managed_catalog()?;
    println!(
        "{}",
        serde_json::json!({ "server_id": catalog.server_id, "documents": catalog.entries.len(),
        "authenticated_administrator": identity.principal.id, "viewer_write_denied": true,
        "transport": "pinned fixture HTTPS", "protocol": solidcraft_pdm::PROTOCOL })
    );
    Ok(())
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let arg = |index| args.get(index).map(String::as_str).ok_or(Error::Invalid("demo argument"));
    match (args.get(1).map(String::as_str), args.len()) {
        (Some("prepare"), 3) => prepare(Path::new(arg(2)?)),
        (Some("probe"), 4) => probe(arg(2)?, arg(3)?),
        _ => Err("usage: redb_demo prepare NEW_ABSOLUTE_DIRECTORY | probe ADDRESS SERVER_ID".into()),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
