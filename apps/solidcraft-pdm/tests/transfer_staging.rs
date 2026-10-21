use sha2::{Digest, Sha256};
use solidcraft_pdm::transfer_staging::{Binding, Limits, Stager, TransferError};
use std::{cell::Cell, io::Read};
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn binding(id: &str) -> Binding {
    Binding { server_id: "a".repeat(64), principal: id.into(), epoch: 1 }
}
fn fixture() -> (std::path::PathBuf, Limits) {
    (
        std::env::temp_dir().join(format!("pdm-transfer-{}", solidcraft_pdm::AuthToken::generate().unwrap())),
        Limits { max_file_bytes: 2 * 1024 * 1024, max_store_bytes: 8 * 1024 * 1024, max_temporary_bytes: 3 * 1024 * 1024, max_sessions: 2 },
    )
}
#[test]
fn raw_large_file_retry_hash_and_new_only_seal() {
    let (root, limits) = fixture();
    let stage = Stager::create(&root, limits).unwrap();
    let bytes = vec![237; 1024 * 1024 + 17];
    let who = binding("alice");
    let id = stage.begin(&who, bytes.len() as u64, digest(&bytes), 0, 1, |_| Ok(())).unwrap();
    let first = &bytes[..1024 * 1024];
    assert_eq!(stage.chunk(&who, &id, 0, first.len() as u64, &digest(first), &mut &first[..], 2, |_| Ok(())).unwrap(), first.len() as u64);
    assert_eq!(stage.chunk(&who, &id, 0, first.len() as u64, &digest(first), &mut &first[..], 3, |_| Ok(())).unwrap(), first.len() as u64);
    let tail = &bytes[first.len()..];
    assert!(matches!(
        stage.chunk(&who, &id, first.len() as u64, tail.len() as u64, &"0".repeat(64), &mut &tail[..], 4, |_| Ok(())),
        Err(TransferError::Checksum)
    ));
    stage.chunk(&who, &id, first.len() as u64, tail.len() as u64, &digest(tail), &mut &tail[..], 5, |_| Ok(())).unwrap();
    let sealed = stage.seal(&who, &id, 6, |_| Ok(())).unwrap();
    assert_eq!(std::fs::read(&sealed.path).unwrap(), bytes);
    assert_eq!(sealed.bytes, bytes.len() as u64);
    assert_eq!(stage.seal(&who, &id, 7, |_| Ok(())).unwrap().path, sealed.path);
    drop(stage);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn durable_resume_preserves_binding_prefix_retry_and_truncates_unacknowledged_tail() {
    use std::io::Write;
    let (root, limits) = fixture();
    let who = binding("alice");
    let stage = Stager::create(&root, limits).unwrap();
    assert!(Stager::open(&root, limits).is_err(), "exclusive root ownership");
    let id = stage.begin(&who, 6, digest(b"abcdef"), 0, 10, |_| Ok(())).unwrap();
    stage.chunk(&who, &id, 0, 3, &digest(b"abc"), &mut &b"abc"[..], 11, |_| Ok(())).unwrap();
    drop(stage);
    let mut raw = std::fs::OpenOptions::new().append(true).open(root.join(&id)).unwrap();
    raw.write_all(b"unacknowledged").unwrap();
    raw.sync_all().unwrap();
    drop(raw);
    let stage = Stager::open(&root, limits).unwrap();
    let status = stage.status(&who, &id, 12, |_| Ok(())).unwrap();
    assert_eq!((status.offset, status.total, status.sha256), (3, 6, digest(b"abcdef")));
    assert!(!status.sealed);
    assert_eq!(std::fs::metadata(root.join(&id)).unwrap().len(), 3);
    assert_eq!(stage.chunk(&who, &id, 0, 3, &digest(b"abc"), &mut &b"abc"[..], 12, |_| Ok(())).unwrap(), 3);
    let mut other_epoch = who.clone();
    other_epoch.epoch += 1;
    assert!(matches!(stage.status(&other_epoch, &id, 12, |_| Ok(())), Err(TransferError::Forbidden)));
    assert!(matches!(stage.status(&binding("bob"), &id, 12, |_| Ok(())), Err(TransferError::Forbidden)));
    assert!(matches!(stage.status(&who, &id, 12, |_| Err(TransferError::Forbidden)), Err(TransferError::Forbidden)));
    stage.chunk(&who, &id, 3, 3, &digest(b"def"), &mut &b"def"[..], 13, |_| Ok(())).unwrap();
    stage.seal(&who, &id, 14, |_| Ok(())).unwrap();
    drop(stage);
    let stage = Stager::open(&root, limits).unwrap();
    assert!(stage.status(&who, &id, 15, |_| Ok(())).unwrap().sealed);
    assert_eq!(stage.seal(&who, &id, 15, |_| Ok(())).unwrap().sha256, digest(b"abcdef"));
    assert!(stage.abort(&who, &id, |_| Ok(())).is_err());
    stage.complete(&who, &id, |_| Ok(())).unwrap();
    assert!(stage.complete(&who, &id, |_| Ok(())).is_ok(), "completion is idempotent");
    drop(stage);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn durable_sealed_reservation_survives_expiry_until_catalog_completion() {
    let (root, mut limits) = fixture();
    limits.max_file_bytes = 3;
    limits.max_temporary_bytes = 3;
    let who = binding("alice");
    let bob = binding("bob");
    let stage = Stager::create(&root, limits).unwrap();
    let id = stage.begin(&who, 3, digest(b"abc"), 0, 0, |_| Ok(())).unwrap();
    stage.chunk(&who, &id, 0, 3, &digest(b"abc"), &mut &b"abc"[..], 1, |_| Ok(())).unwrap();
    let sealed = stage.seal(&who, &id, 2, |_| Ok(())).unwrap();
    drop(stage);
    let stage = Stager::open(&root, limits).unwrap();
    assert_eq!(stage.cleanup_expired(&who, 2_000_000, |_| Ok(())).unwrap(), 0);
    assert!(sealed.path.is_file());
    assert!(matches!(stage.begin(&bob, 1, digest(b"x"), 0, 2_000_000, |_| Ok(())), Err(TransferError::TemporaryQuota)));
    assert!(stage.complete(&bob, &id, |_| Ok(())).is_err());
    assert!(stage.complete(&who, &id, |_| Err(TransferError::Forbidden)).is_err());
    stage.complete(&who, &id, |_| Ok(())).unwrap();
    let next = stage.begin(&bob, 1, digest(b"x"), 3, 2_000_000, |_| Ok(())).unwrap();
    stage.abort(&bob, &next, |_| Ok(())).unwrap();
    drop(stage);
    let stage = Stager::open(&root, limits).unwrap();
    assert!(stage.complete(&who, &id, |_| Ok(())).is_ok());
    drop(stage);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn expiry_cleanup_is_owner_and_epoch_scoped_and_persists_cancellation() {
    let (root, limits) = fixture();
    let who = binding("alice");
    let bob = binding("bob");
    let stage = Stager::create(&root, limits).unwrap();
    let alice_id = stage.begin(&who, 1, digest(b"a"), 0, 0, |_| Ok(())).unwrap();
    let bob_id = stage.begin(&bob, 1, digest(b"b"), 0, 0, |_| Ok(())).unwrap();
    drop(stage);
    let stage = Stager::open(&root, limits).unwrap();
    let mut changed = who.clone();
    changed.epoch += 1;
    assert_eq!(stage.cleanup_expired(&changed, 2_000_000, |_| Ok(())).unwrap(), 0);
    assert!(stage.cleanup_expired(&who, 2_000_000, |_| Err(TransferError::Forbidden)).is_err());
    assert_eq!(stage.cleanup_expired(&who, 2_000_000, |_| Ok(())).unwrap(), 1);
    assert!(!root.join(&alice_id).exists());
    assert!(root.join(&bob_id).exists());
    stage.abort(&bob, &bob_id, |_| Ok(())).unwrap();
    drop(stage);
    let stage = Stager::open(&root, limits).unwrap();
    assert!(stage.status(&who, &alice_id, 1, |_| Ok(())).is_err());
    assert!(stage.status(&bob, &bob_id, 1, |_| Ok(())).is_err());
    drop(stage);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn reopen_rejects_policy_changes_unknown_files_and_short_acknowledged_content() {
    let (root, limits) = fixture();
    let who = binding("alice");
    let stage = Stager::create(&root, limits).unwrap();
    let id = stage.begin(&who, 3, digest(b"abc"), 0, 0, |_| Ok(())).unwrap();
    stage.chunk(&who, &id, 0, 3, &digest(b"abc"), &mut &b"abc"[..], 1, |_| Ok(())).unwrap();
    drop(stage);
    let mut changed = limits;
    changed.max_file_bytes -= 1;
    assert!(Stager::open(&root, changed).is_err());
    std::fs::write(root.join("unknown-entry"), b"x").unwrap();
    assert!(Stager::open(&root, limits).is_err());
    std::fs::remove_file(root.join("unknown-entry")).unwrap();
    std::fs::OpenOptions::new().write(true).open(root.join(&id)).unwrap().set_len(1).unwrap();
    assert!(Stager::open(&root, limits).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn trusted_inventory_retains_bounded_public_bindings_through_restart_and_discard() {
    let (root, limits) = fixture();
    let who = binding("alice");
    let bob = binding("bob");
    let stage = Stager::create(&root, limits).unwrap();
    let alice = stage.begin(&who, 1, digest(b"a"), 0, 0, |_| Ok(())).unwrap();
    let other = stage.begin(&bob, 1, digest(b"b"), 0, 4, |_| Ok(())).unwrap();
    stage.chunk(&who, &alice, 0, 1, &digest(b"a"), &mut &b"a"[..], 1, |_| Ok(())).unwrap();
    stage.seal(&who, &alice, 2, |_| Ok(())).unwrap();
    drop(stage);
    let stage = Stager::open(&root, limits).unwrap();
    let inventory = stage.inventory().unwrap();
    assert_eq!(inventory.len(), 2);
    let first = inventory.iter().find(|entry| entry.id == alice).unwrap();
    assert!(first.binding == who);
    assert_eq!(first.expires, 1_800_000);
    assert!(first.sealed);
    let second = inventory.iter().find(|entry| entry.id == other).unwrap();
    assert!(second.binding == bob);
    assert_eq!(second.expires, 1_800_004);
    assert!(!second.sealed);
    assert!(stage.discard(&bob, &alice, |_| Ok(())).is_err());
    assert!(stage.discard(&who, &alice, |_| Err(TransferError::Forbidden)).is_err());
    stage.discard(&who, &alice, |_| Ok(())).unwrap();
    stage.discard(&who, &alice, |_| Ok(())).unwrap();
    stage.discard(&bob, &other, |_| Ok(())).unwrap();
    assert!(stage.inventory().unwrap().is_empty());
    drop(stage);
    let stage = Stager::open(&root, limits).unwrap();
    assert!(stage.inventory().unwrap().is_empty());
    drop(stage);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn pre_body_identity_revocation_size_and_expiry_rejections() {
    struct Trap<'a>(&'a Cell<u32>);
    impl Read for Trap<'_> {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.0.set(self.0.get() + 1);
            panic!("body consumed before rejection")
        }
    }
    let (root, limits) = fixture();
    let stage = Stager::create(&root, limits).unwrap();
    let who = binding("alice");
    let reads = Cell::new(0);
    assert!(matches!(stage.begin(&who, 3 * 1024 * 1024, digest(b"x"), 0, 0, |_| Ok(())), Err(TransferError::FileTooLarge { .. })));
    let id = stage.begin(&who, 1, digest(b"x"), 0, 0, |_| Ok(())).unwrap();
    assert!(matches!(stage.chunk(&binding("bob"), &id, 0, 1, &digest(b"x"), &mut Trap(&reads), 1, |_| Ok(())), Err(TransferError::Forbidden)));
    assert!(matches!(
        stage.chunk(&who, &id, 0, 1, &digest(b"x"), &mut Trap(&reads), 1, |_| Err(TransferError::Forbidden)),
        Err(TransferError::Forbidden)
    ));
    assert!(stage.chunk(&who, &id, 0, 2, &digest(b"x"), &mut Trap(&reads), 1, |_| Ok(())).is_err());
    assert!(matches!(stage.chunk(&who, &id, 0, 1, &digest(b"x"), &mut Trap(&reads), 1_800_001, |_| Ok(())), Err(TransferError::Expired)));
    assert_eq!(reads.get(), 0);
    stage.abort(&who, &id, |_| Ok(())).unwrap();
    drop(stage);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn quotas_policy_and_existing_root_are_separate_and_preserved() {
    let (root, limits) = fixture();
    let stage = Stager::create(&root, limits).unwrap();
    let who = binding("alice");
    let id = stage.begin(&who, 2 * 1024 * 1024, digest(b"x"), 0, 0, |_| Ok(())).unwrap();
    assert!(matches!(stage.begin(&who, 1, digest(b"x"), 0, 0, |_| Ok(())), Err(TransferError::Busy)));
    assert!(matches!(stage.begin(&binding("bob"), 2 * 1024 * 1024, digest(b"x"), 0, 0, |_| Ok(())), Err(TransferError::TemporaryQuota)));
    stage.abort(&who, &id, |_| Ok(())).unwrap();
    assert!(matches!(stage.begin(&who, 1, digest(b"x"), 8 * 1024 * 1024, 0, |_| Ok(())), Err(TransferError::StorageQuota)));
    assert!(Stager::create(&root, limits).is_err());
    assert!(root.join("policy.json").is_file());
    drop(stage);
    std::fs::remove_dir_all(root).unwrap();
}
