# Explicit single-node HTTPS service

`solidcraft-pdm serve-https-remote /absolute/deployment.json` is the explicit
remote service command. Ordinary `serve` and `rehearse-https` retain their
loopback boundaries. This command requires an existing enrolled archive, TLS
certificate chain and PKCS8 private key, absolute paths without links or parent
traversal, and a nonzero listening port. It does not initialize or migrate stores.
The strict configuration contains paths and a bind address, never credentials:

```json
{
  "store": "/var/lib/solidcraft-pdm/archive",
  "bind": "0.0.0.0:8443",
  "certificate_chain": ["/etc/solidcraft-pdm/server.der"],
  "private_key": "/etc/solidcraft-pdm/server-key.der"
}
```

Choose the intended interface explicitly. First validate the configuration and
credentials on a private/loopback listener, before exposing the intended port.
A successful start prints one public JSON receipt with server ID and address.
stdin EOF does not stop the service. SIGTERM and SIGINT initiate owned graceful
shutdown. Windows handles Ctrl+C. No plaintext or invalid-certificate fallback
is available.

## Debian 12 source build

Use the complete repository at the delivered exact commit; do not extract a
partial Cargo workspace. The root manifest declares Rust 1.95 and edition 2024.
Install the compiler/toolchain only within the authorized deployment scope.
The backend package does not require building the CAD application or its GUI.
Build under a dedicated unprivileged build account with private Cargo, Rustup,
target and temporary directories. Typical Debian prerequisites are
`build-essential`, `pkg-config`, `ca-certificates`, `curl`, `git` and `openssl`.
The operator must review missing packages before installing them.

With the exact source checkout and a verified Rust 1.95 toolchain:

```sh
umask 077
export CARGO_HOME=/var/lib/solidcraft-pdm-build/cargo
export RUSTUP_HOME=/var/lib/solidcraft-pdm-build/rustup
export CARGO_TARGET_DIR=/var/lib/solidcraft-pdm-build/target
export TMPDIR=/var/lib/solidcraft-pdm-build/tmp
rustc --version
cargo --version
nice -n 10 cargo build --locked --release -j2 -p solidcraft-pdm --bin solidcraft-pdm
nice -n 10 cargo test --locked --release -j2 -p solidcraft-pdm --test remote_deployment --test deployment --test https_keepalive -- --test-threads=2
sha256sum "$CARGO_TARGET_DIR/release/solidcraft-pdm"
```

Run from the exact checked-out repository. Record commit, tree, compiler,
command, exit status and executable SHA256. The Unix signal regression must pass
on Linux; Windows results do not establish that result. Preserve the repository
license and third-party license notices with the installed build. The backend
performance and remote-mode increment adds only the Tokio signal feature; its
signal dependency was already present in the workspace lockfile.

## Enrollment, trust and private files

Provision a NEW synthetic archive and test accounts through the existing trusted
local setup flow. A portable committed backup can then be restored to a NEW
Linux destination with `restore-redb`; restoration rotates the recovery epoch.
Do not copy an open redb database or active upload staging. Keep provisioning
credentials in private native storage on the client. A portable archive contains
credential verifiers, not raw bearer secrets. Never reuse a delivered user trial
or print credentials in service logs or command arguments.

For an IP-only test, the certificate must contain the actual IP in its IP SAN.
Create the private CA/server key in an isolated private directory, sign the server
certificate, and provide the leaf DER plus PKCS8 DER key to the service. Keep the
CA private key out of the runtime account. Verify the CA fingerprint through the
trusted SSH channel before importing its public DER certificate into the client.
The client validates chain, hostname/IP, validity and its paired server-ID pin.
Do not use invalid-certificate switches. An eventual DNS certificate can replace
this explicit private trust only through an intentional pairing update.

## Minimal isolated systemd unit

Use a dedicated system account `solidcraft-pdm` without an interactive shell;
install the executable root-owned under `/opt/solidcraft-pdm/bin/`, configuration
and TLS files under `/etc/solidcraft-pdm/`, and the exclusively owned archive
under `/var/lib/solidcraft-pdm/`. Directories containing archive, keys or setup
material are 0700, secret files 0600. The runtime account needs read access to its
server key and write access only to its own data directory. The CA key remains
elsewhere. This unit is a reviewable installation example, not an automatic
provisioning action:

```ini
[Unit]
Description=SolidCraft PDM HTTPS service
After=network.target

[Service]
Type=simple
User=solidcraft-pdm
Group=solidcraft-pdm
WorkingDirectory=/var/lib/solidcraft-pdm
ExecStart=/opt/solidcraft-pdm/bin/solidcraft-pdm serve-https-remote /etc/solidcraft-pdm/deployment.json
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
KillSignal=SIGTERM
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/solidcraft-pdm
StandardInput=null
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Before enabling public access, verify pinned TLS, configured authentication,
permissions, startup receipt, clean SIGTERM/restart and the listening interface.
Review the existing firewall and open only the specifically authorized test port;
do not flush tables, change default policy or disturb existing services.

Rollback stops and disables only this unit, removes only its explicitly added
firewall rule, and restores the previous executable/configuration if applicable.
Preserve the archive, private setup material and backup for investigation; do not
reset or recursively delete data as a rollback shortcut. No existing service,
credential store, system database or client-owned trial is part of this rollback.

## Performance evidence limits

Synthetic loopback measurements are separate from a real remote test. Report
source preparation, upload, verified download, request/TLS counters and total
scene time separately. Use the same datasets and record other concurrent work.
Larger chunks are bounded hints, not a promise of network saturation. Authentication,
epoch fences, quota accounting, fsync ordering and full-file verification remain
mandatory. These tests do not certify power-loss durability or a process RSS ceiling.
