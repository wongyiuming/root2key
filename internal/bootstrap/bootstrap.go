package bootstrap

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const rollbackDelaySeconds = 300

type Request struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type Result struct {
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	User               string   `json:"user"`
	OS                 string   `json:"os"`
	HostKeyFingerprint string   `json:"host_key_fingerprint"`
	PrivateKey         string   `json:"private_key"`
	PublicKey          string   `json:"public_key"`
	SSHConfig          string   `json:"ssh_config"`
	Steps              []string `json:"steps"`
}

type runner struct {
	req         Request
	client      *ssh.Client
	fingerprint string
	privatePEM  string
	publicKey   string
	signer      ssh.Signer
	newPort     int
	osID        string
	sshd        string
	backupDir   string
	guardPID    string
	guardScript string
	tempPID     string
	firewall    string
	firewallAdd bool
	selinuxAdd  bool
	steps       []string
}

func Run(ctx context.Context, req Request) (Result, error) {
	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" || req.Password == "" {
		return Result{}, errors.New("host and root password are required")
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.Port < 1 || req.Port > 65535 {
		return Result{}, errors.New("invalid SSH port")
	}

	r := &runner{req: req}
	if err := r.run(ctx); err != nil {
		return Result{Steps: r.steps}, err
	}

	return Result{
		Host:               req.Host,
		Port:               r.newPort,
		User:               "root",
		OS:                 r.osID,
		HostKeyFingerprint: r.fingerprint,
		PrivateKey:         r.privatePEM,
		PublicKey:          strings.TrimSpace(r.publicKey),
		SSHConfig: fmt.Sprintf("Host root2key-%s\n    HostName %s\n    User root\n    Port %d\n    IdentityFile ~/.ssh/root2key_%s\n    IdentitiesOnly yes\n", safeAlias(req.Host), req.Host, r.newPort, safeAlias(req.Host)),
		Steps:              r.steps,
	}, nil
}

func (r *runner) run(ctx context.Context) (retErr error) {
	r.step("Connecting with the existing root password")
	client, fp, err := dialPassword(ctx, r.req.Host, r.req.Port, r.req.Password, "")
	if err != nil {
		return fmt.Errorf("initial SSH connection failed: %w", err)
	}
	r.client = client
	r.fingerprint = fp
	defer r.client.Close()

	rollbackNeeded := false
	defer func() {
		if retErr != nil && rollbackNeeded {
			r.step("Failure detected; attempting immediate rollback")
			if err := r.rollback(); err != nil {
				retErr = fmt.Errorf("%w; rollback also failed: %v", retErr, err)
			} else {
				r.step("Rollback completed")
			}
		}
	}()

	uid, err := r.exec("id -u")
	if err != nil || strings.TrimSpace(uid) != "0" {
		return errors.New("target session is not root")
	}

	connInfo, err := r.exec("printf '%s' \"$SSH_CONNECTION\"")
	if err != nil {
		return fmt.Errorf("cannot inspect SSH connection: %w", err)
	}
	fields := strings.Fields(connInfo)
	if len(fields) != 4 {
		return fmt.Errorf("unexpected SSH_CONNECTION value: %q", connInfo)
	}
	remoteLocalPort, _ := strconv.Atoi(fields[3])
	if remoteLocalPort != r.req.Port {
		return fmt.Errorf("SSH port mapping detected: browser requested port %d but sshd sees local port %d; automatic port rotation is unsafe on NAT/port-forwarded hosts", r.req.Port, remoteLocalPort)
	}

	r.osID, err = r.detectOS()
	if err != nil {
		return err
	}
	r.step("Detected " + r.osID)

	r.sshd, err = r.exec("command -v sshd 2>/dev/null || printf /usr/sbin/sshd")
	if err != nil || strings.TrimSpace(r.sshd) == "" {
		return errors.New("sshd executable not found")
	}
	r.sshd = strings.TrimSpace(r.sshd)

	if err := r.generateKey(); err != nil {
		return err
	}
	r.step("Generated a new Ed25519 key pair in memory")

	if err := r.installPublicKey(); err != nil {
		return err
	}
	r.step("Installed the new public key for root")

	r.newPort, err = r.choosePort()
	if err != nil {
		return err
	}
	r.step(fmt.Sprintf("Selected high SSH port %d", r.newPort))

	if err := r.prepareNetwork(); err != nil {
		return err
	}

	if err := r.backupAndArmRollback(); err != nil {
		return err
	}
	rollbackNeeded = true
	r.step(fmt.Sprintf("Armed a %d-second automatic rollback guard", rollbackDelaySeconds))

	if err := r.startTemporarySSHD(); err != nil {
		return err
	}
	defer r.stopTemporarySSHD()
	r.step("Started a temporary key-only SSH listener")

	if err := r.verifyKeyConnection(ctx); err != nil {
		return fmt.Errorf("temporary new-port key login verification failed: %w", err)
	}
	r.step("Verified a fresh key login on the new port")

	if err := r.stopTemporarySSHD(); err != nil {
		return fmt.Errorf("cannot stop temporary sshd: %w", err)
	}

	if err := r.applyManagedConfig(true); err != nil {
		return err
	}
	r.step("Disabled password authentication while keeping old and new ports open")

	if err := r.verifyKeyConnection(ctx); err != nil {
		return fmt.Errorf("new-port key login failed after hardening: %w", err)
	}
	r.step("Verified a second fresh key-only session after hardening")

	if err := r.verifyPasswordRejected(ctx); err != nil {
		return err
	}
	r.step("Verified password authentication is rejected on the new port")

	if err := r.applyManagedConfig(false); err != nil {
		return err
	}
	r.step(fmt.Sprintf("Removed the old SSH port %d from sshd configuration", r.req.Port))

	if err := r.verifyKeyConnection(ctx); err != nil {
		return fmt.Errorf("final key login failed after closing old port: %w", err)
	}
	r.step("Verified a final fresh key session on the new port")

	if err := waitPortClosed(ctx, r.req.Host, r.req.Port, 8*time.Second); err != nil {
		return err
	}
	r.step("Verified the old SSH port no longer accepts TCP connections")

	if err := r.cancelRollback(); err != nil {
		return fmt.Errorf("bootstrap succeeded but rollback guard could not be cancelled: %w", err)
	}
	rollbackNeeded = false
	r.step("Committed changes and cancelled the rollback guard")
	return nil
}

func (r *runner) step(s string) { r.steps = append(r.steps, s) }

func (r *runner) exec(command string) (string, error) {
	session, err := r.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	out, err := session.CombinedOutput(command)
	if err != nil {
		return string(out), fmt.Errorf("remote command failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *runner) detectOS() (string, error) {
	text, err := r.exec("cat /etc/os-release")
	if err != nil {
		return "", fmt.Errorf("cannot read /etc/os-release: %w", err)
	}
	vals := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			vals[k] = strings.Trim(strings.TrimSpace(v), "\"")
		}
	}
	id := strings.ToLower(vals["ID"])
	like := strings.ToLower(vals["ID_LIKE"])
	switch {
	case id == "ubuntu":
		return "ubuntu", nil
	case id == "centos" || strings.Contains(like, "rhel") || id == "rocky" || id == "almalinux":
		return id, nil
	default:
		return "", fmt.Errorf("unsupported distribution %q; this development branch currently supports Ubuntu and RHEL/CentOS-family systems", id)
	}
}

func (r *runner) generateKey() error {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return fmt.Errorf("create SSH signer: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("create SSH public key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "root2key")
	if err != nil {
		return fmt.Errorf("marshal OpenSSH private key: %w", err)
	}
	r.signer = signer
	r.privatePEM = string(pem.EncodeToMemory(block))
	r.publicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " root2key\n"
	return nil
}

func (r *runner) installPublicKey() error {
	q := shellQuote(strings.TrimSpace(r.publicKey))
	cmd := "umask 077; install -d -m 700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; " +
		"grep -qxF -- " + q + " /root/.ssh/authorized_keys || printf '%s\\n' " + q + " >> /root/.ssh/authorized_keys"
	_, err := r.exec(cmd)
	if err != nil {
		return fmt.Errorf("install authorized key: %w", err)
	}
	return nil
}

func (r *runner) choosePort() (int, error) {
	used, _ := r.exec("ss -H -ltn 2>/dev/null | awk '{print $4}' || true")
	for i := 0; i < 64; i++ {
		n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(65535-20000+1))
		if err != nil {
			return 0, err
		}
		p := int(n.Int64()) + 20000
		if p == r.req.Port || strings.Contains(used, ":"+strconv.Itoa(p)) {
			continue
		}
		return p, nil
	}
	return 0, errors.New("could not find an unused high port")
}

func (r *runner) prepareNetwork() error {
	selinux, _ := r.exec("getenforce 2>/dev/null || true")
	if strings.EqualFold(strings.TrimSpace(selinux), "Enforcing") {
		if _, err := r.exec("command -v semanage >/dev/null 2>&1 || (dnf -y install policycoreutils-python-utils >/dev/null 2>&1 || yum -y install policycoreutils-python >/dev/null 2>&1)"); err != nil {
			return fmt.Errorf("SELinux is enforcing and semanage could not be installed: %w", err)
		}
		check := fmt.Sprintf("semanage port -l | awk '$1==\"ssh_port_t\" && $2==\"tcp\" {print $3}' | tr ',' '\\n' | grep -qx %d", r.newPort)
		if _, err := r.exec(check); err != nil {
			cmd := fmt.Sprintf("semanage port -a -t ssh_port_t -p tcp %d 2>/dev/null || semanage port -m -t ssh_port_t -p tcp %d", r.newPort, r.newPort)
			if _, err := r.exec(cmd); err != nil {
				return fmt.Errorf("cannot allow new SSH port in SELinux: %w", err)
			}
			r.selinuxAdd = true
			r.step("Allowed the new port in SELinux ssh_port_t policy")
		}
	}

	if _, err := r.exec("systemctl is-active --quiet firewalld"); err == nil {
		r.firewall = "firewalld"
		query := fmt.Sprintf("firewall-cmd --quiet --query-port=%d/tcp", r.newPort)
		if _, err := r.exec(query); err != nil {
			cmd := fmt.Sprintf("firewall-cmd --quiet --add-port=%d/tcp && firewall-cmd --quiet --permanent --add-port=%d/tcp", r.newPort, r.newPort)
			if _, err := r.exec(cmd); err != nil {
				return fmt.Errorf("cannot open new port in firewalld: %w", err)
			}
			r.firewallAdd = true
			r.step("Opened the new port in firewalld")
		}
		return nil
	}

	ufw, _ := r.exec("ufw status 2>/dev/null | head -n1 || true")
	if strings.Contains(strings.ToLower(ufw), "active") {
		r.firewall = "ufw"
		cmd := fmt.Sprintf("ufw allow %d/tcp >/dev/null", r.newPort)
		if _, err := r.exec(cmd); err != nil {
			return fmt.Errorf("cannot open new port in ufw: %w", err)
		}
		r.firewallAdd = true
		r.step("Opened the new port in UFW")
	}
	return nil
}

func (r *runner) backupAndArmRollback() error {
	token := make([]byte, 8)
	if _, err := io.ReadFull(cryptorand.Reader, token); err != nil {
		return err
	}
	id := fmt.Sprintf("%x", token)
	r.backupDir = "/var/lib/root2key/" + id
	r.guardScript = "/var/lib/root2key/rollback-" + id + ".sh"

	if _, err := r.exec("install -d -m 700 /var/lib/root2key " + shellQuote(r.backupDir) + "; cp -a /etc/ssh " + shellQuote(r.backupDir+"/ssh")); err != nil {
		return fmt.Errorf("backup SSH configuration: %w", err)
	}

	var rollback strings.Builder
	rollback.WriteString("#!/bin/sh\nset +e\n")
	rollback.WriteString("rm -rf /etc/ssh && cp -a " + shellQuote(r.backupDir+"/ssh") + " /etc/ssh\n")
	rollback.WriteString("grep -vxF -- " + shellQuote(strings.TrimSpace(r.publicKey)) + " /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.root2key.tmp 2>/dev/null && mv /root/.ssh/authorized_keys.root2key.tmp /root/.ssh/authorized_keys\n")
	rollback.WriteString("chmod 600 /root/.ssh/authorized_keys 2>/dev/null || true\n")
	if r.firewallAdd && r.firewall == "firewalld" {
		rollback.WriteString(fmt.Sprintf("firewall-cmd --quiet --remove-port=%d/tcp >/dev/null 2>&1 || true\n", r.newPort))
		rollback.WriteString(fmt.Sprintf("firewall-cmd --quiet --permanent --remove-port=%d/tcp >/dev/null 2>&1 || true\n", r.newPort))
	} else if r.firewallAdd && r.firewall == "ufw" {
		rollback.WriteString(fmt.Sprintf("ufw --force delete allow %d/tcp >/dev/null 2>&1 || true\n", r.newPort))
	}
	if r.selinuxAdd {
		rollback.WriteString(fmt.Sprintf("semanage port -d -t ssh_port_t -p tcp %d >/dev/null 2>&1 || true\n", r.newPort))
	}
	rollback.WriteString(reloadCommand() + "\n")
	rollback.WriteString("rm -f -- \"$0\"\n")

	cmd := "cat > " + shellQuote(r.guardScript) + " <<'ROOT2KEY_ROLLBACK'\n" + rollback.String() + "ROOT2KEY_ROLLBACK\nchmod 700 " + shellQuote(r.guardScript) +
		fmt.Sprintf("\nnohup sh -c 'sleep %d; exec %s' >/dev/null 2>&1 & echo $!", rollbackDelaySeconds, shellQuote(r.guardScript))
	pid, err := r.exec(cmd)
	if err != nil {
		return fmt.Errorf("arm rollback guard: %w", err)
	}
	r.guardPID = strings.TrimSpace(pid)
	if _, err := strconv.Atoi(r.guardPID); err != nil {
		return fmt.Errorf("invalid rollback guard PID %q", r.guardPID)
	}
	return nil
}

func (r *runner) startTemporarySSHD() error {
	pidFile := fmt.Sprintf("/run/root2key-sshd-%d.pid", r.newPort)
	logFile := fmt.Sprintf("/tmp/root2key-sshd-%d.log", r.newPort)
	opts := fmt.Sprintf("-p %d -o PidFile=%s -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ChallengeResponseAuthentication=no -o PubkeyAuthentication=yes -o PermitRootLogin=prohibit-password -o AuthenticationMethods=publickey", r.newPort, pidFile)
	test := fmt.Sprintf("install -d -m 755 /run/sshd; %s -t %s", shellQuote(r.sshd), opts)
	if _, err := r.exec(test); err != nil {
		return fmt.Errorf("temporary sshd configuration is invalid: %w", err)
	}
	cmd := fmt.Sprintf("nohup %s -D %s >%s 2>&1 & echo $!", shellQuote(r.sshd), opts, shellQuote(logFile))
	pid, err := r.exec(cmd)
	if err != nil {
		return fmt.Errorf("start temporary sshd: %w", err)
	}
	r.tempPID = strings.TrimSpace(pid)
	time.Sleep(350 * time.Millisecond)
	return nil
}

func (r *runner) stopTemporarySSHD() error {
	if r.tempPID == "" {
		return nil
	}
	_, err := r.exec("kill " + shellQuote(r.tempPID) + " 2>/dev/null || true")
	r.tempPID = ""
	return err
}

func (r *runner) applyManagedConfig(keepOld bool) error {
	ports := fmt.Sprintf("Port %d\n", r.newPort)
	if keepOld && r.req.Port != r.newPort {
		ports = fmt.Sprintf("Port %d\nPort %d\n", r.req.Port, r.newPort)
	}
	managed := ports + "PasswordAuthentication no\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin prohibit-password\nAuthenticationMethods publickey\n"

	script := `set -eu
patch_global() {
  f="$1"
  [ -f "$f" ] || return 0
  awk '
    BEGIN { inmatch=0 }
    {
      raw=$0; line=$0
      sub(/^[ \t]+/, "", line)
      split(line, a, /[ \t]+/)
      key=tolower(a[1])
      if (key == "match") inmatch=1
      if (!inmatch && (key == "port" || key == "passwordauthentication" || key == "kbdinteractiveauthentication" || key == "challengeresponseauthentication" || key == "pubkeyauthentication" || key == "permitrootlogin" || key == "authenticationmethods")) {
        print "# root2key-disabled: " raw
        next
      }
      print raw
    }
  ' "$f" > "$f.root2key.tmp"
  cat "$f.root2key.tmp" > "$f"
  rm -f "$f.root2key.tmp"
}
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
  [ "$f" = "/etc/ssh/root2key.conf" ] && continue
  patch_global "$f"
done
if ! grep -qF 'Include /etc/ssh/root2key.conf' /etc/ssh/sshd_config; then
  { printf '%s\n' 'Include /etc/ssh/root2key.conf'; cat /etc/ssh/sshd_config; } > /etc/ssh/sshd_config.root2key.tmp
  cat /etc/ssh/sshd_config.root2key.tmp > /etc/ssh/sshd_config
  rm -f /etc/ssh/sshd_config.root2key.tmp
fi
cat > /etc/ssh/root2key.conf <<'ROOT2KEY_MANAGED'
` + managed + `ROOT2KEY_MANAGED
` + shellQuote(r.sshd) + ` -t -f /etc/ssh/sshd_config
` + reloadCommand()

	if _, err := r.exec("sh -c " + shellQuote(script)); err != nil {
		return fmt.Errorf("apply sshd configuration: %w", err)
	}
	return nil
}

func (r *runner) verifyKeyConnection(ctx context.Context) error {
	c, _, err := dialSigner(ctx, r.req.Host, r.newPort, r.signer, r.fingerprint)
	if err != nil {
		return err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	out, err := s.CombinedOutput("id -u")
	if err != nil || strings.TrimSpace(string(out)) != "0" {
		return fmt.Errorf("fresh session did not execute as root: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *runner) verifyPasswordRejected(ctx context.Context) error {
	c, _, err := dialPassword(ctx, r.req.Host, r.newPort, r.req.Password, r.fingerprint)
	if err == nil {
		c.Close()
		return errors.New("password authentication is still accepted on the new SSH port")
	}
	return nil
}

func (r *runner) rollback() error {
	r.stopTemporarySSHD()
	if r.guardScript == "" {
		return nil
	}
	_, err := r.exec("kill " + shellQuote(r.guardPID) + " 2>/dev/null || true; sh " + shellQuote(r.guardScript))
	return err
}

func (r *runner) cancelRollback() error {
	if r.guardPID == "" {
		return nil
	}
	_, err := r.exec("kill " + shellQuote(r.guardPID) + " 2>/dev/null || true; rm -f " + shellQuote(r.guardScript))
	return err
}

func dialPassword(ctx context.Context, host string, port int, password, expectedFingerprint string) (*ssh.Client, string, error) {
	return dial(ctx, host, port, []ssh.AuthMethod{ssh.Password(password)}, expectedFingerprint)
}

func dialSigner(ctx context.Context, host string, port int, signer ssh.Signer, expectedFingerprint string) (*ssh.Client, string, error) {
	return dial(ctx, host, port, []ssh.AuthMethod{ssh.PublicKeys(signer)}, expectedFingerprint)
}

func dial(ctx context.Context, host string, port int, auth []ssh.AuthMethod, expectedFingerprint string) (*ssh.Client, string, error) {
	var observed string
	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed = ssh.FingerprintSHA256(key)
		if expectedFingerprint != "" && observed != expectedFingerprint {
			return fmt.Errorf("host key changed: expected %s, got %s", expectedFingerprint, observed)
		}
		return nil
	}
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            auth,
		HostKeyCallback: callback,
		Timeout:         8 * time.Second,
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, "", err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		conn.Close()
		return nil, observed, err
	}
	return ssh.NewClient(c, chans, reqs), observed, nil
}

func waitPortClosed(ctx context.Context, host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		d := net.Dialer{Timeout: 700 * time.Millisecond}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return nil
		}
		c.Close()
		time.Sleep(350 * time.Millisecond)
	}
	return fmt.Errorf("old SSH port %d still accepts TCP connections", port)
}

func reloadCommand() string {
	return "(systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || systemctl restart ssh)"
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func safeAlias(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "host"
	}
	return b.String()
}
