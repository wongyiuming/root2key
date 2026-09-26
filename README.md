# root2key — Rust development branch

Rust implementation of the same transactional web bootstrapper as `go-dev`: take a fresh Ubuntu/CentOS-family VPS that currently allows root/password SSH and move it to a freshly generated Ed25519 key on a random high SSH port without closing the old port before the hardened path is independently verified.

## Current development scope

- Axum web UI/API in a single service
- Ubuntu and CentOS/RHEL-family detection (CentOS, Rocky, AlmaLinux)
- Ed25519 key generation in process memory with `ssh-key`
- libssh2-based SSH connections; the initial server host key is TOFU-pinned for every later verification session
- NAT/SSH-port-forwarding mismatch detection and safe abort
- target-side SSH configuration backup plus a five-minute delayed rollback guard
- temporary key-only sshd on the new port before touching the primary listener
- hardened phase keeps both old and new ports, verifies a new key session, and verifies the password is rejected
- only then is the old SSH port removed; a third fresh key session and old-port TCP closure check are required before commit
- active UFW/firewalld handling and SELinux `ssh_port_t` handling
- root password is never persisted; the generated private key is returned only in the successful HTTP response

## Run

```bash
docker compose up --build -d
```

Open <http://127.0.0.1:8080>.

The supplied Compose file binds the UI to localhost only. Keep the provider console available while this development branch is being tested. NAT VPS products whose public SSH port is mapped to a different internal sshd port are intentionally rejected.
