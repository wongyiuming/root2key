# root2key — Go development branch

`root2key` is a small web bootstrapper for a fresh VPS. It accepts the public host, current SSH port, and root password, then transactionally moves the host to Ed25519 key-only SSH on a random high port.

## Current development scope

- Ubuntu and CentOS/RHEL-family detection (CentOS, Rocky, AlmaLinux)
- Ed25519 key generation in application memory
- initial root/password connection with TOFU host-key pinning for every subsequent connection
- NAT/SSH-port-forwarding detection; port rotation aborts rather than risking lockout
- temporary new-port sshd listener for pre-change key verification
- delayed automatic rollback guard on the target host
- password authentication disabled only after a fresh new-port key session succeeds
- old and new ports kept together for the hardening verification phase
- old port removed only after the hardened new-port session is verified
- final fresh-session verification and old-port closure check before commit
- active UFW/firewalld handling and SELinux `ssh_port_t` handling
- private key returned once in the HTTP response; root passwords are never persisted

## Run

```bash
docker compose up --build -d
```

Open <http://127.0.0.1:8080>.

The supplied Compose file deliberately publishes only on loopback. If this UI is ever exposed remotely, add authentication and TLS before changing the bind address.

## Development warning

This branch changes remote SSH configuration. Keep the VPS provider console available while testing. NAT VPS products where the advertised SSH port is mapped to a different internal sshd port are intentionally rejected in this version.
