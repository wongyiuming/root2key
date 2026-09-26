use std::{
    io::Read,
    net::{TcpStream, ToSocketAddrs},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use rand::{rngs::OsRng as RandOsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::{rand_core::OsRng, Algorithm, LineEnding, PrivateKey};
use ssh2::Session;

const ROLLBACK_DELAY_SECONDS: u64 = 300;

#[derive(Deserialize)]
pub struct BootstrapRequest {
    pub host: String,
    pub port: u16,
    pub password: String,
}

#[derive(Serialize)]
pub struct BootstrapResult {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub os: String,
    pub host_key_fingerprint: String,
    pub private_key: String,
    pub public_key: String,
    pub ssh_config: String,
    pub steps: Vec<String>,
}

pub struct BootstrapFailure {
    pub message: String,
    pub steps: Vec<String>,
}

struct SshClient {
    session: Session,
    fingerprint: String,
}

impl SshClient {
    fn connect_password(host: &str, port: u16, password: &str, expected: Option<&str>) -> Result<Self> {
        let (session, fingerprint) = connect_session(host, port, expected)?;
        session
            .userauth_password("root", password)
            .context("root password authentication failed")?;
        if !session.authenticated() {
            bail!("root password authentication was not accepted");
        }
        Ok(Self { session, fingerprint })
    }

    fn connect_key(host: &str, port: u16, private_key: &str, expected: &str) -> Result<Self> {
        let (session, fingerprint) = connect_session(host, port, Some(expected))?;
        session
            .userauth_pubkey_memory("root", None, private_key, None)
            .context("Ed25519 public-key authentication failed")?;
        if !session.authenticated() {
            bail!("public-key authentication was not accepted");
        }
        Ok(Self { session, fingerprint })
    }

    fn exec_raw(&self, command: &str) -> Result<(String, i32)> {
        let mut channel = self.session.channel_session().context("open SSH channel")?;
        channel.exec(command).with_context(|| format!("execute remote command: {command}"))?;
        let mut stdout = String::new();
        channel.read_to_string(&mut stdout).context("read SSH stdout")?;
        let mut stderr = String::new();
        {
            let mut stderr_stream = channel.stderr();
            stderr_stream.read_to_string(&mut stderr).context("read SSH stderr")?;
        }
        channel.wait_close().context("close SSH channel")?;
        let status = channel.exit_status().context("read remote exit status")?;
        if !stderr.trim().is_empty() {
            if !stdout.ends_with('\n') && !stdout.is_empty() {
                stdout.push('\n');
            }
            stdout.push_str(&stderr);
        }
        Ok((stdout.trim().to_owned(), status))
    }

    fn exec(&self, command: &str) -> Result<String> {
        let (output, status) = self.exec_raw(command)?;
        if status != 0 {
            bail!("remote command exited with {status}: {}", output.trim());
        }
        Ok(output)
    }

    fn succeeds(&self, command: &str) -> bool {
        self.exec_raw(command)
            .map(|(_, status)| status == 0)
            .unwrap_or(false)
    }
}

fn connect_session(host: &str, port: u16, expected: Option<&str>) -> Result<(Session, String)> {
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no address resolved for {host}"))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(8))
        .with_context(|| format!("connect TCP {host}:{port}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(15))).ok();

    let mut session = Session::new().context("create SSH session")?;
    session.set_timeout(15_000);
    session.set_tcp_stream(tcp);
    session.handshake().context("SSH handshake failed")?;

    let (host_key, _) = session.host_key().ok_or_else(|| anyhow!("server did not provide a host key"))?;
    let mut hasher = Sha256::new();
    hasher.update(host_key);
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(hasher.finalize()));
    if let Some(expected) = expected {
        if fingerprint != expected {
            bail!("host key changed: expected {expected}, got {fingerprint}");
        }
    }
    Ok((session, fingerprint))
}

struct Runner {
    req: BootstrapRequest,
    client: SshClient,
    private_key: String,
    public_key: String,
    new_port: u16,
    os_id: String,
    sshd: String,
    backup_dir: String,
    guard_script: String,
    guard_pid: String,
    temp_pid: String,
    firewall: String,
    firewall_added: bool,
    selinux_added: bool,
    rollback_needed: bool,
    steps: Vec<String>,
}

pub fn run(mut req: BootstrapRequest) -> std::result::Result<BootstrapResult, BootstrapFailure> {
    req.host = req.host.trim().to_owned();
    if req.host.is_empty() || req.password.is_empty() {
        return Err(BootstrapFailure { message: "host and root password are required".into(), steps: vec![] });
    }
    if req.port == 0 {
        req.port = 22;
    }

    let initial = match SshClient::connect_password(&req.host, req.port, &req.password, None) {
        Ok(client) => client,
        Err(err) => return Err(BootstrapFailure { message: format!("initial SSH connection failed: {err:#}"), steps: vec!["Connecting with the existing root password".into()] }),
    };

    let mut runner = Runner {
        req,
        client: initial,
        private_key: String::new(),
        public_key: String::new(),
        new_port: 0,
        os_id: String::new(),
        sshd: String::new(),
        backup_dir: String::new(),
        guard_script: String::new(),
        guard_pid: String::new(),
        temp_pid: String::new(),
        firewall: String::new(),
        firewall_added: false,
        selinux_added: false,
        rollback_needed: false,
        steps: vec!["Connected with the existing root password".into()],
    };

    match runner.run_inner() {
        Ok(()) => {
            let alias = safe_alias(&runner.req.host);
            Ok(BootstrapResult {
                host: runner.req.host.clone(),
                port: runner.new_port,
                user: "root".into(),
                os: runner.os_id.clone(),
                host_key_fingerprint: runner.client.fingerprint.clone(),
                private_key: runner.private_key.clone(),
                public_key: runner.public_key.clone(),
                ssh_config: format!(
                    "Host root2key-{alias}\n    HostName {}\n    User root\n    Port {}\n    IdentityFile ~/.ssh/root2key_{alias}\n    IdentitiesOnly yes\n",
                    runner.req.host, runner.new_port
                ),
                steps: runner.steps,
            })
        }
        Err(err) => {
            let mut message = format!("{err:#}");
            if runner.rollback_needed {
                runner.step("Failure detected; attempting immediate rollback");
                if let Err(rollback_err) = runner.rollback() {
                    message = format!("{message}; rollback also failed: {rollback_err:#}");
                } else {
                    runner.step("Rollback completed");
                }
            }
            Err(BootstrapFailure { message, steps: runner.steps })
        }
    }
}

impl Runner {
    fn run_inner(&mut self) -> Result<()> {
        if self.client.exec("id -u")?.trim() != "0" {
            bail!("target session is not root");
        }

        let conn = self.client.exec("printf '%s' \"$SSH_CONNECTION\"")?;
        let fields: Vec<&str> = conn.split_whitespace().collect();
        if fields.len() != 4 {
            bail!("unexpected SSH_CONNECTION value: {conn:?}");
        }
        let local_port: u16 = fields[3].parse().context("parse server-side SSH port")?;
        if local_port != self.req.port {
            bail!(
                "SSH port mapping detected: browser requested port {} but sshd sees local port {}; automatic port rotation is unsafe on NAT/port-forwarded hosts",
                self.req.port,
                local_port
            );
        }

        self.os_id = self.detect_os()?;
        self.step(format!("Detected {}", self.os_id));
        self.sshd = self
            .client
            .exec("command -v sshd 2>/dev/null || printf /usr/sbin/sshd")?
            .trim()
            .to_owned();
        if self.sshd.is_empty() {
            bail!("sshd executable not found");
        }

        self.generate_key()?;
        self.step("Generated a new Ed25519 key pair in memory");
        self.new_port = self.choose_port()?;
        self.step(format!("Selected high SSH port {}", self.new_port));

        self.backup_ssh()?;
        self.rollback_needed = true;
        self.step("Backed up the SSH configuration before making changes");

        self.install_public_key()?;
        self.step("Installed the new public key for root");
        self.prepare_network()?;
        self.arm_rollback()?;
        self.step(format!("Armed a {ROLLBACK_DELAY_SECONDS}-second automatic rollback guard"));

        self.start_temporary_sshd()?;
        self.step("Started a temporary key-only SSH listener");
        self.verify_key_connection()?;
        self.step("Verified a fresh key login on the new port");
        self.stop_temporary_sshd()?;

        self.apply_managed_config(true)?;
        self.step("Disabled password authentication while keeping old and new ports open");
        self.verify_key_connection()?;
        self.step("Verified a second fresh key-only session after hardening");
        self.verify_password_rejected()?;
        self.step("Verified password authentication is rejected on the new port");

        self.apply_managed_config(false)?;
        self.step(format!("Removed the old SSH port {} from sshd configuration", self.req.port));
        self.verify_key_connection()?;
        self.step("Verified a final fresh key session on the new port");
        wait_port_closed(&self.req.host, self.req.port, Duration::from_secs(8))?;
        self.step("Verified the old SSH port no longer accepts TCP connections");

        self.cancel_rollback()?;
        self.rollback_needed = false;
        self.step("Committed changes and cancelled the rollback guard");
        Ok(())
    }

    fn step(&mut self, text: impl Into<String>) {
        self.steps.push(text.into());
    }

    fn detect_os(&self) -> Result<String> {
        let text = self.client.exec("cat /etc/os-release")?;
        let mut id = String::new();
        let mut like = String::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let value = value.trim().trim_matches('"').to_lowercase();
                match key {
                    "ID" => id = value,
                    "ID_LIKE" => like = value,
                    _ => {}
                }
            }
        }
        if id == "ubuntu" {
            return Ok(id);
        }
        if id == "centos" || id == "rocky" || id == "almalinux" || like.contains("rhel") {
            return Ok(id);
        }
        bail!("unsupported distribution {id:?}; this development branch currently supports Ubuntu and RHEL/CentOS-family systems")
    }

    fn generate_key(&mut self) -> Result<()> {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).context("generate Ed25519 key")?;
        self.private_key = key
            .to_openssh(LineEnding::LF)
            .context("encode OpenSSH private key")?
            .to_string();
        let encoded = key.public_key().to_openssh().context("encode OpenSSH public key")?;
        let mut parts = encoded.split_whitespace();
        let algo = parts.next().ok_or_else(|| anyhow!("missing public-key algorithm"))?;
        let blob = parts.next().ok_or_else(|| anyhow!("missing public-key data"))?;
        self.public_key = format!("{algo} {blob} root2key");
        Ok(())
    }

    fn choose_port(&self) -> Result<u16> {
        let used = self.client.exec("ss -H -ltn 2>/dev/null | awk '{print $4}' || true").unwrap_or_default();
        let mut rng = RandOsRng;
        for _ in 0..64 {
            let port = rng.gen_range(20_000u16..=65_535u16);
            if port == self.req.port || used.contains(&format!(":{port}")) {
                continue;
            }
            return Ok(port);
        }
        bail!("could not find an unused high port")
    }

    fn backup_ssh(&mut self) -> Result<()> {
        let mut token = [0u8; 8];
        let mut rng = RandOsRng;
        rng.fill_bytes(&mut token);
        let id = token.iter().map(|b| format!("{b:02x}")).collect::<String>();
        self.backup_dir = format!("/var/lib/root2key/{id}");
        self.guard_script = format!("/var/lib/root2key/rollback-{id}.sh");
        self.client.exec(&format!(
            "install -d -m 700 /var/lib/root2key {} && cp -a /etc/ssh {}",
            shell_quote(&self.backup_dir),
            shell_quote(&format!("{}/ssh", self.backup_dir))
        ))?;
        Ok(())
    }

    fn install_public_key(&self) -> Result<()> {
        let q = shell_quote(self.public_key.trim());
        self.client.exec(&format!(
            "umask 077; install -d -m 700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; grep -qxF -- {q} /root/.ssh/authorized_keys || printf '%s\\n' {q} >> /root/.ssh/authorized_keys"
        ))?;
        Ok(())
    }

    fn prepare_network(&mut self) -> Result<()> {
        let selinux = self.client.exec("getenforce 2>/dev/null || true").unwrap_or_default();
        if selinux.trim().eq_ignore_ascii_case("Enforcing") {
            self.client.exec("command -v semanage >/dev/null 2>&1 || (dnf -y install policycoreutils-python-utils >/dev/null 2>&1 || yum -y install policycoreutils-python >/dev/null 2>&1)")?;
            let check = format!("semanage port -l | awk '$1==\"ssh_port_t\" && $2==\"tcp\" {{print $3}}' | tr ',' '\\n' | grep -qx {}", self.new_port);
            if !self.client.succeeds(&check) {
                self.client.exec(&format!(
                    "semanage port -a -t ssh_port_t -p tcp {} 2>/dev/null || semanage port -m -t ssh_port_t -p tcp {}",
                    self.new_port, self.new_port
                ))?;
                self.selinux_added = true;
                self.step("Allowed the new port in SELinux ssh_port_t policy");
            }
        }

        if self.client.succeeds("systemctl is-active --quiet firewalld") {
            self.firewall = "firewalld".into();
            let query = format!("firewall-cmd --quiet --query-port={}/tcp", self.new_port);
            if !self.client.succeeds(&query) {
                self.client.exec(&format!("firewall-cmd --quiet --add-port={}/tcp", self.new_port))?;
                self.firewall_added = true;
                self.client.exec(&format!("firewall-cmd --quiet --permanent --add-port={}/tcp", self.new_port))?;
                self.step("Opened the new port in firewalld");
            }
            return Ok(());
        }

        let ufw = self.client.exec("ufw status 2>/dev/null | head -n1 || true").unwrap_or_default();
        if ufw.to_lowercase().contains("active") {
            self.firewall = "ufw".into();
            let exists = format!("ufw status | grep -Eq '(^|[[:space:]]){}/tcp([[:space:]]|$)'", self.new_port);
            if !self.client.succeeds(&exists) {
                self.client.exec(&format!("ufw allow {}/tcp >/dev/null", self.new_port))?;
                self.firewall_added = true;
                self.step("Opened the new port in UFW");
            }
        }
        Ok(())
    }

    fn rollback_script_body(&self) -> String {
        let mut body = String::from("#!/bin/sh\nset +e\n");
        body.push_str(&format!("rm -rf /etc/ssh && cp -a {} /etc/ssh\n", shell_quote(&format!("{}/ssh", self.backup_dir))));
        body.push_str(&format!(
            "if [ -f /root/.ssh/authorized_keys ]; then (grep -vxF -- {} /root/.ssh/authorized_keys 2>/dev/null || true) > /root/.ssh/authorized_keys.root2key.tmp; mv /root/.ssh/authorized_keys.root2key.tmp /root/.ssh/authorized_keys; fi\nchmod 600 /root/.ssh/authorized_keys 2>/dev/null || true\n",
            shell_quote(self.public_key.trim())
        ));
        if self.firewall_added && self.firewall == "firewalld" {
            body.push_str(&format!("firewall-cmd --quiet --remove-port={}/tcp >/dev/null 2>&1 || true\n", self.new_port));
            body.push_str(&format!("firewall-cmd --quiet --permanent --remove-port={}/tcp >/dev/null 2>&1 || true\n", self.new_port));
        } else if self.firewall_added && self.firewall == "ufw" {
            body.push_str(&format!("ufw --force delete allow {}/tcp >/dev/null 2>&1 || true\n", self.new_port));
        }
        if self.selinux_added {
            body.push_str(&format!("semanage port -d -t ssh_port_t -p tcp {} >/dev/null 2>&1 || true\n", self.new_port));
        }
        body.push_str(reload_command());
        body.push('\n');
        body.push_str("rm -f -- \"$0\"\n");
        body
    }

    fn arm_rollback(&mut self) -> Result<()> {
        let body = self.rollback_script_body();
        let cmd = format!(
            "cat > {} <<'ROOT2KEY_ROLLBACK'\n{}ROOT2KEY_ROLLBACK\nchmod 700 {}\nnohup sh -c 'sleep {}; exec {}' >/dev/null 2>&1 & echo $!",
            shell_quote(&self.guard_script),
            body,
            shell_quote(&self.guard_script),
            ROLLBACK_DELAY_SECONDS,
            shell_quote(&self.guard_script)
        );
        self.guard_pid = self.client.exec(&cmd)?.trim().to_owned();
        self.guard_pid.parse::<u32>().context("invalid rollback guard PID")?;
        Ok(())
    }

    fn start_temporary_sshd(&mut self) -> Result<()> {
        let pid_file = format!("/run/root2key-sshd-{}.pid", self.new_port);
        let log_file = format!("/tmp/root2key-sshd-{}.log", self.new_port);
        let opts = format!(
            "-p {} -o PidFile={} -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ChallengeResponseAuthentication=no -o PubkeyAuthentication=yes -o PermitRootLogin=prohibit-password -o AuthenticationMethods=publickey",
            self.new_port, pid_file
        );
        self.client.exec(&format!("install -d -m 755 /run/sshd; {} -t {opts}", shell_quote(&self.sshd)))?;
        self.temp_pid = self.client.exec(&format!("nohup {} -D {opts} >{} 2>&1 & echo $!", shell_quote(&self.sshd), shell_quote(&log_file)))?.trim().to_owned();
        thread::sleep(Duration::from_millis(350));
        Ok(())
    }

    fn stop_temporary_sshd(&mut self) -> Result<()> {
        if self.temp_pid.is_empty() {
            return Ok(());
        }
        let pid = self.temp_pid.clone();
        self.client.exec(&format!("kill {} 2>/dev/null || true; for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 {} 2>/dev/null || break; sleep 0.1; done", shell_quote(&pid), shell_quote(&pid)))?;
        self.temp_pid.clear();
        Ok(())
    }

    fn apply_managed_config(&self, keep_old: bool) -> Result<()> {
        let ports = if keep_old && self.req.port != self.new_port {
            format!("Port {}\nPort {}\n", self.req.port, self.new_port)
        } else {
            format!("Port {}\n", self.new_port)
        };
        let managed = format!(
            "{ports}PasswordAuthentication no\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin prohibit-password\nAuthenticationMethods publickey\n"
        );
        let script = format!(
            r##"set -eu
patch_global() {{
  f="$1"
  [ -f "$f" ] || return 0
  awk '
    BEGIN {{ inmatch=0 }}
    {{
      raw=$0; line=$0
      sub(/^[ \t]+/, "", line)
      split(line, a, /[ \t]+/)
      key=tolower(a[1])
      if (key == "match") inmatch=1
      if (!inmatch && (key == "port" || key == "passwordauthentication" || key == "kbdinteractiveauthentication" || key == "challengeresponseauthentication" || key == "pubkeyauthentication" || key == "permitrootlogin" || key == "authenticationmethods")) {{
        print "# root2key-disabled: " raw
        next
      }}
      print raw
    }}
  ' "$f" > "$f.root2key.tmp"
  cat "$f.root2key.tmp" > "$f"
  rm -f "$f.root2key.tmp"
}}
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
  [ "$f" = "/etc/ssh/root2key.conf" ] && continue
  patch_global "$f"
done
if ! grep -qF 'Include /etc/ssh/root2key.conf' /etc/ssh/sshd_config; then
  {{ printf '%s\n' 'Include /etc/ssh/root2key.conf'; cat /etc/ssh/sshd_config; }} > /etc/ssh/sshd_config.root2key.tmp
  cat /etc/ssh/sshd_config.root2key.tmp > /etc/ssh/sshd_config
  rm -f /etc/ssh/sshd_config.root2key.tmp
fi
cat > /etc/ssh/root2key.conf <<'ROOT2KEY_MANAGED'
{managed}ROOT2KEY_MANAGED
{} -t -f /etc/ssh/sshd_config
{}
"##,
            shell_quote(&self.sshd),
            reload_command()
        );
        self.client.exec(&format!("sh -c {}", shell_quote(&script)))?;
        Ok(())
    }

    fn verify_key_connection(&self) -> Result<()> {
        let client = SshClient::connect_key(
            &self.req.host,
            self.new_port,
            &self.private_key,
            &self.client.fingerprint,
        )?;
        if client.exec("id -u")?.trim() != "0" {
            bail!("fresh key-authenticated session did not execute as root");
        }
        Ok(())
    }

    fn verify_password_rejected(&self) -> Result<()> {
        if SshClient::connect_password(
            &self.req.host,
            self.new_port,
            &self.req.password,
            Some(&self.client.fingerprint),
        )
        .is_ok()
        {
            bail!("password authentication is still accepted on the new SSH port");
        }
        Ok(())
    }

    fn rollback(&mut self) -> Result<()> {
        let _ = self.stop_temporary_sshd();
        if !self.guard_script.is_empty() && !self.guard_pid.is_empty() {
            self.client.exec(&format!(
                "kill {} 2>/dev/null || true; sh {}",
                shell_quote(&self.guard_pid),
                shell_quote(&self.guard_script)
            ))?;
            return Ok(());
        }

        if !self.backup_dir.is_empty() {
            self.client.exec(&format!("rm -rf /etc/ssh && cp -a {} /etc/ssh", shell_quote(&format!("{}/ssh", self.backup_dir))))?;
        }
        let _ = self.client.exec(&format!(
            "if [ -f /root/.ssh/authorized_keys ]; then (grep -vxF -- {} /root/.ssh/authorized_keys 2>/dev/null || true) > /root/.ssh/authorized_keys.root2key.tmp; mv /root/.ssh/authorized_keys.root2key.tmp /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; fi",
            shell_quote(self.public_key.trim())
        ));
        if self.firewall_added && self.firewall == "firewalld" {
            let _ = self.client.exec(&format!("firewall-cmd --quiet --remove-port={}/tcp >/dev/null 2>&1 || true; firewall-cmd --quiet --permanent --remove-port={}/tcp >/dev/null 2>&1 || true", self.new_port, self.new_port));
        } else if self.firewall_added && self.firewall == "ufw" {
            let _ = self.client.exec(&format!("ufw --force delete allow {}/tcp >/dev/null 2>&1 || true", self.new_port));
        }
        if self.selinux_added {
            let _ = self.client.exec(&format!("semanage port -d -t ssh_port_t -p tcp {} >/dev/null 2>&1 || true", self.new_port));
        }
        self.client.exec(reload_command())?;
        Ok(())
    }

    fn cancel_rollback(&self) -> Result<()> {
        self.client.exec(&format!(
            "kill {} 2>/dev/null || true; rm -f {}",
            shell_quote(&self.guard_pid),
            shell_quote(&self.guard_script)
        ))?;
        Ok(())
    }
}

fn wait_port_closed(host: &str, port: u16, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let addr = (host, port)
            .to_socket_addrs()
            .with_context(|| format!("resolve {host}:{port}"))?
            .next()
            .ok_or_else(|| anyhow!("no address resolved for {host}"))?;
        if TcpStream::connect_timeout(&addr, Duration::from_millis(700)).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(350));
    }
    bail!("old SSH port {port} still accepts TCP connections")
}

fn reload_command() -> &'static str {
    "(systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || systemctl restart ssh)"
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn safe_alias(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() { "host".into() } else { out }
}
