use serde_json::json;
use sha2::{Digest, Sha256};
use solidcraft_pdm::{
    AuthToken, Store, backup_restore,
    client::Client,
    http_server::{HttpsConfig, HttpsServer},
    stream_io::StreamPolicy,
    transfers::{TransferInput, TransferTarget},
};
struct Root(std::path::PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn setup() -> (Root, std::path::PathBuf, String) {
    let root = Root(std::env::temp_dir().join(format!("binary-http-{}", AuthToken::generate().unwrap())));
    std::fs::create_dir(&root.0).unwrap();
    let token = AuthToken::generate().unwrap();
    let seed = root.0.join("seed");
    std::fs::create_dir(&seed).unwrap();
    std::fs::write(
        seed.join("managed-principals.json"),
        serde_json::to_vec(&json!([{"principal":{"id":"alice","role":"administrator"},"token_sha256":digest(token.as_bytes())}])).unwrap(),
    )
    .unwrap();
    Store::open(&seed).unwrap().backup(&root.0.join("initial")).unwrap();
    let db = root.0.join("db");
    backup_restore::restore_backup_to_redb(&root.0.join("initial"), &db).unwrap();
    Store::open(&db)
        .unwrap()
        .initialize_streaming(StreamPolicy { version: 1, max_file_bytes: 4 * 1024 * 1024, max_store_bytes: 12 * 1024 * 1024 })
        .unwrap();
    (root, db, token)
}
fn start(db: &std::path::Path, token: &str) -> (HttpsServer, Client) {
    let config = HttpsConfig::from_der(
        "127.0.0.1:0".parse().unwrap(),
        vec![include_bytes!("fixtures/pdm-https/server.der").to_vec()],
        include_bytes!("fixtures/pdm-https/server-key.der").to_vec(),
    )
    .unwrap();
    let server = HttpsServer::start(Store::open(db).unwrap(), config).unwrap();
    let client = Client::https_with_ca(
        &format!("https://{}", server.address()),
        AuthToken::parse(token.to_owned()).unwrap(),
        include_bytes!("fixtures/pdm-https/ca.der"),
    )
    .unwrap();
    (server, client)
}
#[test]
fn pinned_https_restart_commit_retry_and_streamed_restore_preserve_large_bytes() {
    let (root, db, token) = setup();
    let (server, client) = start(&db, &token);
    let caps = client.transfer_capabilities().unwrap().unwrap();
    assert!(caps.binary_transfer_v1);
    let bytes = vec![241; 2 * 1024 * 1024 + 193];
    let input = TransferInput {
        server_id: caps.server_id,
        recovery_epoch: caps.recovery_epoch,
        request_id: "new-large".into(),
        target: TransferTarget::NewOnly { logical_path: "opaque/large.bin".into() },
        total_bytes: bytes.len() as u64,
        sha256: digest(&bytes),
        dependencies: vec![],
        comment: "Synthetic opaque bytes".into(),
    };
    let initial = client.begin_transfer(input.clone()).unwrap();
    assert_eq!(initial.offset, 0);
    assert!(client.managed_catalog().unwrap().entries.is_empty());
    let first = &bytes[..1024 * 1024];
    client.upload_chunk(&initial.transfer_id, 0, first, &digest(first)).unwrap();
    assert_eq!(client.upload_chunk(&initial.transfer_id, 0, first, &digest(first)).unwrap().offset, 1024 * 1024);
    server.shutdown().unwrap();
    let (server, client) = start(&db, &token);
    assert_eq!(client.transfer_status(&initial.transfer_id).unwrap().offset, 1024 * 1024);
    for (index, chunk) in bytes.chunks(1024 * 1024).enumerate().skip(1) {
        client.upload_chunk(&initial.transfer_id, (index * 1024 * 1024) as u64, chunk, &digest(chunk)).unwrap();
    }
    let committed = client.commit_transfer(&initial.transfer_id, "new-large").unwrap();
    assert_eq!(client.commit_transfer(&initial.transfer_id, "new-large").unwrap(), committed);
    assert_eq!(client.managed_history(committed.version.reference.document.clone()).unwrap().len(), 1);
    assert!(client.download(&committed.version.reference).is_err(), "no large inline JSON response");
    let mut output = Vec::new();
    let metadata = client.download_stream(&committed.version.reference, &mut output).unwrap();
    assert_eq!(metadata, committed.version);
    assert_eq!(output, bytes);
    assert!(
        matches!(client.request(solidcraft_pdm::Request::WhereUsed{reference:committed.version.reference.clone()}).unwrap(),solidcraft_pdm::Response::WhereUsed{versions}if versions.is_empty())
    );
    server.shutdown().unwrap();
    Store::open(&db).unwrap().backup(&root.0.join("large-backup")).unwrap();
    backup_restore::restore_backup_to_redb(&root.0.join("large-backup"), &root.0.join("restored")).unwrap();
    let (server, client) = start(&root.0.join("restored"), &token);
    let mut output = Vec::new();
    client.download_stream(&committed.version.reference, &mut output).unwrap();
    assert_eq!(output, bytes);
    server.shutdown().unwrap();
}
