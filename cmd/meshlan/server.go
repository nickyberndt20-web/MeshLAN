package main

import (
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed admin/* deploy/install-mesh-node.sh deploy/upgrade-mesh-node.sh
var adminWeb embed.FS

type nebulaChildProcess struct {
	mu         sync.Mutex
	executable string
	configPath string
	cmd        *exec.Cmd
	done       chan struct{}
	running    bool
	logWriter  io.Writer
}

func (p *nebulaChildProcess) startLocked() error {
	cmd := exec.Command(p.executable, "-config", p.configPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if p.logWriter != nil {
		cmd.Stdout = io.MultiWriter(os.Stdout, p.logWriter)
		cmd.Stderr = io.MultiWriter(os.Stderr, p.logWriter)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	p.cmd, p.done, p.running = cmd, done, true
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		if p.cmd == cmd {
			p.cmd, p.done, p.running = nil, nil, false
		}
		p.mu.Unlock()
		if err != nil {
			log.Printf("Nebula 退出: %v", err)
		}
		close(done)
	}()
	return nil
}

var nebulaCertificateLogPattern = regexp.MustCompile(`certName=(?:"([^"]+)"|([^\s]+)).*fingerprint=([0-9a-fA-F]{64})`)

type nebulaCertificateLogWriter struct {
	mu            sync.Mutex
	pending       string
	onFingerprint func(name, fingerprint string)
}

func (w *nebulaCertificateLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	w.pending += string(data)
	matches := [][2]string{}
	for {
		newline := strings.IndexByte(w.pending, '\n')
		if newline < 0 {
			if len(w.pending) > 64<<10 {
				w.pending = w.pending[len(w.pending)-(32<<10):]
			}
			break
		}
		line := w.pending[:newline]
		w.pending = w.pending[newline+1:]
		match := nebulaCertificateLogPattern.FindStringSubmatch(line)
		if len(match) != 4 {
			continue
		}
		name := match[1]
		if name == "" {
			name = match[2]
		}
		matches = append(matches, [2]string{name, strings.ToLower(match[3])})
	}
	w.mu.Unlock()
	for _, match := range matches {
		if w.onFingerprint != nil {
			w.onFingerprint(match[0], match[1])
		}
	}
	return len(data), nil
}

func (p *nebulaChildProcess) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return nil
	}
	return p.startLocked()
}

func (p *nebulaChildProcess) Restart() error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	if cmd == nil {
		err := p.startLocked()
		p.mu.Unlock()
		return err
	}
	_ = cmd.Process.Kill()
	p.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return errors.New("等待 Nebula 重启超时")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startLocked()
}

func (p *nebulaChildProcess) Stop() {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	if cmd != nil {
		_ = cmd.Process.Kill()
	}
	p.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
}

func (p *nebulaChildProcess) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func serverMain(args []string) error {
	if len(args) == 0 {
		return errors.New("用法：server init|serve|node-init|node-serve|pairing|admin-token|list|publish-update|enable-totp|disable-totp|rotate-master-key|restore-master-key|verify-crypto|activate-update-key|deactivate-update-key|encrypt-backups|scan-plaintext-secrets")
	}
	switch args[0] {
	case "init":
		return serverInit(args[1:])
	case "serve":
		return serverServe(args[1:])
	case "node-init":
		return serverNodeInit(args[1:])
	case "node-serve":
		return serverNodeServe(args[1:])
	case "pairing":
		return serverPairing(args[1:])
	case "admin-token":
		return serverAdminToken(args[1:])
	case "list":
		return serverList(args[1:])
	case "publish-update":
		return serverPublishUpdate(args[1:])
	case "enable-totp":
		return serverEnableTOTP(args[1:])
	case "disable-totp":
		return serverDisableTOTP(args[1:])
	case "rotate-master-key":
		return serverRotateMasterKey(args[1:])
	case "restore-master-key":
		return serverRestoreMasterKey(args[1:])
	case "verify-crypto":
		return serverVerifyCrypto(args[1:])
	case "activate-update-key":
		return serverActivateUpdateKey(args[1:])
	case "deactivate-update-key":
		return serverDeactivateUpdateKey(args[1:])
	case "encrypt-backups":
		return serverEncryptBackups(args[1:])
	case "scan-plaintext-secrets":
		return serverScanPlaintextSecrets(args[1:])
	default:
		return fmt.Errorf("未知 server 命令：%s", args[0])
	}
}

func serverPublishUpdate(args []string) error {
	fs, statePath := serverFlagSet("server publish-update")
	filePath := fs.String("file", "", "Windows amd64 客户端 EXE")
	installerPath := fs.String("installer", "", "可选 Windows 首次安装 Setup EXE")
	nodeAMD64Path := fs.String("node-amd64", "", "可选 Linux amd64 子节点二进制")
	nodeARM64Path := fs.String("node-arm64", "", "可选 Linux arm64 子节点二进制")
	version := fs.String("version", "", "语义版本，如 1.8.0")
	authenticodeThumbprint := fs.String("authenticode-thumbprint", "", "可选的 Authenticode 签名证书指纹")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *filePath == "" || !semanticVersionPattern.MatchString(*version) {
		return errors.New("必须提供有效的 -file 和 -version")
	}
	var state ServerState
	if err := loadJSON(*statePath, &state); err != nil {
		return err
	}
	destination := filepath.Join(filepath.Dir(*statePath), "updates", "windows-amd64", "MeshLAN-Nebula-Windows.exe")
	if err := copyFileAtomic(*filePath, destination, 0o700); err != nil {
		return err
	}
	hash, size, err := fileSHA256(destination)
	if err != nil {
		return err
	}
	state.WindowsUpdatePath = destination
	state.WindowsUpdate = &UpdateManifestPayload{
		Version: *version, Platform: "windows-amd64", SHA256: hash, Size: size,
		PublishedAt: time.Now().UTC(), DownloadPath: "/v1/update/package/windows-amd64",
		AuthenticodeThumbprint: strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(*authenticodeThumbprint), " ", "")),
	}
	if strings.TrimSpace(*installerPath) != "" {
		installerDestination := filepath.Join(filepath.Dir(*statePath), "updates", "windows-amd64", "MeshLAN-Setup-Windows.exe")
		if err := copyFileAtomic(*installerPath, installerDestination, 0o700); err != nil {
			return err
		}
		installerHash, installerSize, err := fileSHA256(installerDestination)
		if err != nil {
			return err
		}
		state.WindowsInstallerPath = installerDestination
		state.WindowsInstaller = &UpdateManifestPayload{Version: *version, Platform: "windows-amd64-setup", SHA256: installerHash, Size: installerSize, PublishedAt: time.Now().UTC(), DownloadPath: "/download/windows"}
	}
	if strings.TrimSpace(*nodeAMD64Path) != "" {
		destination := filepath.Join(filepath.Dir(*statePath), "updates", "linux-amd64", "meshlan-node")
		if err := copyFileAtomic(*nodeAMD64Path, destination, 0o700); err != nil {
			return err
		}
		nodeHash, nodeSize, err := fileSHA256(destination)
		if err != nil {
			return err
		}
		state.LinuxNodeAMD64Path = destination
		state.LinuxNodeAMD64 = &UpdateManifestPayload{Version: *version, Platform: "linux-amd64-node", SHA256: nodeHash, Size: nodeSize, PublishedAt: time.Now().UTC(), DownloadPath: "/download/node/linux-amd64"}
	}
	if strings.TrimSpace(*nodeARM64Path) != "" {
		destination := filepath.Join(filepath.Dir(*statePath), "updates", "linux-arm64", "meshlan-node")
		if err := copyFileAtomic(*nodeARM64Path, destination, 0o700); err != nil {
			return err
		}
		nodeHash, nodeSize, err := fileSHA256(destination)
		if err != nil {
			return err
		}
		state.LinuxNodeARM64Path = destination
		state.LinuxNodeARM64 = &UpdateManifestPayload{Version: *version, Platform: "linux-arm64-node", SHA256: nodeHash, Size: nodeSize, PublishedAt: time.Now().UTC(), DownloadPath: "/download/node/linux-arm64"}
	}
	if err := saveJSON(*statePath, state); err != nil {
		return err
	}
	fmt.Printf("已发布 Windows 更新 %s\nSHA-256: %s\n大小: %d bytes\n", *version, hash, size)
	return nil
}

func selectP2PUpdateSeed(state ServerState, requester string, manifest UpdateManifestPayload, now time.Time) *PeerRecord {
	for index := range state.Peers {
		peer := &state.Peers[index]
		if peer.Revoked || peer.Name == requester || !peer.UpdateSeedReady || !peer.ServiceRunning || now.Sub(peer.LastSeen) >= 75*time.Second {
			continue
		}
		if peerClientVersion(peer.ClientVersion) != manifest.Version || !strings.EqualFold(peer.UpdateSeedSHA256, manifest.SHA256) || peer.UpdateSeedPort < 1 || peer.UpdateSeedPort > 65535 {
			continue
		}
		copy := *peer
		return &copy
	}
	return nil
}

func defaultServerStatePath() string {
	root, _ := appRoot()
	return filepath.Join(root, "server", "server-state.json")
}

func serverFlagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	statePath := fs.String("state", defaultServerStatePath(), "服务端状态文件")
	return fs, statePath
}

func runCommand(executable string, args ...string) error {
	cmd := exec.Command(executable, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", executable, strings.Join(args, " "), strings.TrimSpace(string(output)), err)
	}
	return nil
}

func serverInit(args []string) error {
	fs, statePath := serverFlagSet("server init")
	endpoint := fs.String("endpoint", "", "公网 Lighthouse 地址，如 203.0.113.10:4242")
	subnet := fs.String("subnet", "10.77.0.0/24", "Nebula 虚拟网段")
	nebulaPort := fs.Int("nebula-port", 8080, "Nebula UDP 端口")
	pairingPort := fs.Int("pairing-port", 8080, "自动配对 HTTPS 端口")
	nebulaBin := fs.String("nebula", "nebula", "nebula 可执行文件")
	certBin := fs.String("nebula-cert", "nebula-cert", "nebula-cert 可执行文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return errors.New("必须提供 -endpoint")
	}
	prefix, err := netip.ParsePrefix(*subnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 28 {
		return errors.New("subnet 必须是 /16 到 /28 的 IPv4 CIDR")
	}
	if *nebulaPort < 1 || *pairingPort < 1 || *nebulaPort > 65535 || *pairingPort > 65535 {
		return errors.New("端口无效")
	}
	if _, err := os.Stat(*statePath); err == nil {
		return errors.New("状态文件已存在，拒绝覆盖")
	}
	root := filepath.Dir(*statePath)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	caKey := filepath.Join(root, "ca.key")
	caCert := filepath.Join(root, "ca.crt")
	lighthouseKey := filepath.Join(root, "lighthouse.key")
	lighthouseCert := filepath.Join(root, "lighthouse.crt")
	lighthouseAddress := fmt.Sprintf("%s/%d", prefix.Masked().Addr().Next(), prefix.Bits())
	if err := runCommand(*certBin, "ca", "-name", "MeshLAN", "-duration", "87600h", "-out-key", caKey, "-out-crt", caCert); err != nil {
		return err
	}
	if err := runCommand(*certBin, "sign", "-version", "2", "-ca-key", caKey, "-ca-crt", caCert, "-name", "lighthouse", "-networks", lighthouseAddress, "-groups", "lighthouse,meshlan", "-duration", "78840h", "-out-key", lighthouseKey, "-out-crt", lighthouseCert); err != nil {
		return err
	}
	configPath := filepath.Join(root, "lighthouse.yml")
	config := renderLighthouseConfig(caCert, lighthouseCert, lighthouseKey, *nebulaPort, nil)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return err
	}
	state := ServerState{
		Version: protocolVersion, NetworkName: "MeshLAN", Subnet: prefix.Masked().String(), PublicEndpoint: *endpoint,
		LighthouseAddress: lighthouseAddress, NebulaPort: *nebulaPort, PairingPort: *pairingPort,
		NebulaCertPath: *certBin, NebulaCAKeyPath: caKey, NebulaCACertPath: caCert, Peers: []PeerRecord{},
	}
	if err := ensureServerSecurityIdentity(&state); err != nil {
		return err
	}
	pairingCode, err := issuePairingCode(&state)
	if err != nil {
		return err
	}
	adminToken, err := issueAdminToken(&state)
	if err != nil {
		return err
	}
	if err := saveJSON(*statePath, state); err != nil {
		return err
	}
	fmt.Printf("MeshLAN Nebula 已初始化\nLighthouse: %s\n配对哈希: %s\n管理令牌: %s\n管理页面: https://%s/admin\n配置: %s\nNebula: %s\n", lighthouseAddress, pairingCode, adminToken, pairingAddress(strings.Split(*endpoint, ":")[0], *pairingPort), configPath, *nebulaBin)
	return nil
}

func renderLighthouseConfig(ca, cert, key string, port int, revokedFingerprints []string) string {
	return fmt.Sprintf(`pki:
  ca: %s
  cert: %s
  key: %s
  disconnect_invalid: true
%s

static_host_map: {}

lighthouse:
  am_lighthouse: true
  interval: 30
  hosts: []

listen:
  host: "::"
  port: %d
  windows_bypass_wdf: true

punchy:
  punch: true
  respond: true
  delay: 1s
  respond_delay: 2s

relay:
  relays: []
  am_relay: true
  use_relays: true

tun:
  disabled: false
  dev: MeshLAN-Lighthouse
  mtu: 1300
  network_category: private

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      group: meshlan

logging:
  level: info
  format: text
`, yamlPath(ca), yamlPath(cert), yamlPath(key), renderBlocklistYAML(revokedFingerprints), port)
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]struct {
		window time.Time
		count  int
	}
}

func (l *rateLimiter) allow(remote string) bool {
	host, _, _ := net.SplitHostPort(remote)
	if host == "" {
		host = remote
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[host]
	if now.Sub(entry.window) > time.Minute {
		entry.window, entry.count = now, 0
	}
	entry.count++
	l.entries[host] = entry
	return entry.count <= 10
}

func deviceCredentialsFromRequest(r *http.Request) (name, token string, ok bool) {
	auth := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "MeshLAN-Device "))
	separator := strings.Index(auth, ":")
	if separator < 1 || separator == len(auth)-1 {
		return "", "", false
	}
	return auth[:separator], auth[separator+1:], true
}

func authorizedDevicePeer(state *ServerState, r *http.Request) *PeerRecord {
	name, token, ok := deviceCredentialsFromRequest(r)
	if !ok {
		return nil
	}
	digest := tokenDigest(token)
	for i := range state.Peers {
		if state.Peers[i].Name == name && !state.Peers[i].Revoked && subtle.ConstantTimeCompare([]byte(digest), []byte(state.Peers[i].DeviceTokenHash)) == 1 {
			return &state.Peers[i]
		}
	}
	return nil
}

func adminTokenFromRequest(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get("X-MeshLAN-Admin-Token")); token != "" {
		return token
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authorization, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
}

func removeEnrollment(state *ServerState, id string) bool {
	removed := false
	kept := state.Enrollments[:0]
	for _, enrollment := range state.Enrollments {
		if enrollment.ID == id {
			removed = true
			if state.PairingSecretHash == enrollment.SecretHash {
				state.PairingSecretHash = ""
			}
			continue
		}
		kept = append(kept, enrollment)
	}
	state.Enrollments = kept
	return removed
}

func purgeRevokedEnrollments(state *ServerState) bool {
	changed := false
	kept := state.Enrollments[:0]
	for _, enrollment := range state.Enrollments {
		if enrollment.Revoked {
			changed = true
			if state.PairingSecretHash == enrollment.SecretHash {
				state.PairingSecretHash = ""
			}
			continue
		}
		kept = append(kept, enrollment)
	}
	state.Enrollments = kept
	return changed
}

func purgeExpiredRekeys(state *ServerState, now time.Time) bool {
	changed := false
	kept := state.PendingRekeys[:0]
	for _, pending := range state.PendingRekeys {
		if !now.Before(pending.ExpiresAt) {
			changed = true
			continue
		}
		kept = append(kept, pending)
	}
	state.PendingRekeys = kept
	return changed
}

func removePeer(state *ServerState, name string) bool {
	removed := false
	peers := state.Peers[:0]
	for _, peer := range state.Peers {
		if peer.Name == name {
			removed = true
			continue
		}
		peers = append(peers, peer)
	}
	if !removed {
		return false
	}
	state.Peers = peers
	enrollments := state.Enrollments[:0]
	for _, enrollment := range state.Enrollments {
		if enrollment.BoundName == name {
			if state.PairingSecretHash == enrollment.SecretHash {
				state.PairingSecretHash = ""
			}
			continue
		}
		enrollments = append(enrollments, enrollment)
	}
	state.Enrollments = enrollments
	requests := state.AccessRequests[:0]
	for _, request := range state.AccessRequests {
		if request.OwnerName == name || request.RequesterName == name {
			continue
		}
		requests = append(requests, request)
	}
	state.AccessRequests = requests
	return true
}

func serverServe(args []string) error {
	serverStartedAt := time.Now()
	fs, statePath := serverFlagSet("server serve")
	bind := fs.String("bind", "0.0.0.0", "配对服务监听地址")
	nebulaBin := fs.String("nebula", "nebula", "nebula 可执行文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var state ServerState
	if err := loadJSON(*statePath, &state); err != nil {
		return err
	}
	stateChanged := purgeRevokedEnrollments(&state)
	if purgeExpiredRekeys(&state, time.Now()) {
		stateChanged = true
	}
	if ensurePeerDNSPrefixes(&state) {
		stateChanged = true
	}
	if applyAIProviderDefaults(&state.AIProvider) {
		stateChanged = true
	}
	securityIdentityBefore := serverSecurityIdentitySummary(state)
	if err := ensureServerSecurityIdentity(&state); err != nil {
		return err
	}
	if serverSecurityIdentitySummary(state) != securityIdentityBefore {
		stateChanged = true
	}
	if migrateServerStateSecrets(*statePath, &state) {
		stateChanged = true
	}
	if stateChanged {
		if err := saveJSON(*statePath, state); err != nil {
			return err
		}
	}
	root := filepath.Dir(*statePath)
	history, err := openHistoryStore(filepath.Join(root, "history.sqlite"))
	if err != nil {
		return err
	}
	defer history.Close()
	_ = history.Cleanup(30 * 24 * time.Hour)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			_ = history.Cleanup(30 * 24 * time.Hour)
		}
	}()
	configPath := filepath.Join(root, "lighthouse.yml")
	config := renderLighthouseConfig(state.NebulaCACertPath, filepath.Join(root, "lighthouse.crt"), filepath.Join(root, "lighthouse.key"), state.NebulaPort, revocationFingerprints(state))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return err
	}
	var stateMu sync.Mutex
	go func() {
		refreshMeshNodeHealth(&state, &stateMu, *statePath)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			refreshMeshNodeHealth(&state, &stateMu, *statePath)
		}
	}()
	fileShareTokens := map[string]string{}
	fingerprintWriter := &nebulaCertificateLogWriter{onFingerprint: func(name, fingerprint string) {
		if !validCertificateFingerprint(fingerprint) {
			return
		}
		stateMu.Lock()
		defer stateMu.Unlock()
		peer := findPeerByName(&state, name)
		if peer == nil || peer.CertificateFingerprint == fingerprint {
			return
		}
		peer.CertificateFingerprint = fingerprint
		_ = saveJSON(*statePath, state)
	}}
	nebulaProcess := &nebulaChildProcess{executable: *nebulaBin, configPath: configPath, logWriter: fingerprintWriter}
	if err := nebulaProcess.Start(); err != nil {
		return fmt.Errorf("启动 Nebula 失败: %w", err)
	}
	defer nebulaProcess.Stop()
	certificate, err := tls.X509KeyPair([]byte(state.TLSCertificatePEM), []byte(state.TLSPrivateKeyPEM))
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", net.JoinHostPort(*bind, strconv.Itoa(state.PairingPort)), &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		lastOnline := map[string]bool{}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for now := range ticker.C {
			stateMu.Lock()
			peers := append([]PeerRecord(nil), state.Peers...)
			stateMu.Unlock()
			for _, peer := range peers {
				online := !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) < 75*time.Second
				_ = history.RecordServerPeer(peer, now.UTC(), online)
				if previous, known := lastOnline[peer.Name]; known && previous != online {
					detail := "设备控制心跳离线"
					kind := "peer_offline"
					if online {
						detail, kind = "设备恢复控制心跳", "peer_online"
					}
					_ = history.RecordEvent("server", kind, peer.Name, detail, now.UTC())
				}
				lastOnline[peer.Name] = online
			}
		}
	}()
	limiter := &rateLimiter{entries: map[string]struct {
		window time.Time
		count  int
	}{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, _ *http.Request) {
		data, err := adminWeb.ReadFile("admin/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /download/windows", func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(r.RemoteAddr) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		stateMu.Lock()
		if state.WindowsUpdate == nil || state.WindowsUpdatePath == "" {
			stateMu.Unlock()
			http.Error(w, "Windows client not published", http.StatusNotFound)
			return
		}
		manifest := *state.WindowsUpdate
		path := state.WindowsUpdatePath
		stateMu.Unlock()
		hash, size, err := fileSHA256(path)
		if err != nil || hash != manifest.SHA256 || size != manifest.Size {
			http.Error(w, "published Windows client integrity check failed", http.StatusServiceUnavailable)
			return
		}
		file, err := os.Open(path)
		if err != nil {
			http.Error(w, "Windows client unavailable", http.StatusNotFound)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="MeshLAN-Nebula-Windows-%s.exe"`, manifest.Version))
		w.Header().Set("X-Content-SHA256", manifest.SHA256)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
	})
	mux.HandleFunc("GET /download/node/install.sh", func(w http.ResponseWriter, _ *http.Request) {
		data, err := adminWeb.ReadFile("deploy/install-mesh-node.sh")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="install-mesh-node.sh"`)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /download/node/upgrade.sh", func(w http.ResponseWriter, _ *http.Request) {
		data, err := adminWeb.ReadFile("deploy/upgrade-mesh-node.sh")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="upgrade-mesh-node.sh"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /download/node/linux-amd64", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		manifest, path := state.LinuxNodeAMD64, state.LinuxNodeAMD64Path
		stateMu.Unlock()
		servePublishedArtifact(w, r, manifest, path, "meshlan-node-linux-amd64")
	})
	mux.HandleFunc("GET /download/node/linux-arm64", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		manifest, path := state.LinuxNodeARM64, state.LinuxNodeARM64Path
		stateMu.Unlock()
		servePublishedArtifact(w, r, manifest, path, "meshlan-node-linux-arm64")
	})
	adminSessions := newAdminSessionStore()
	adminAuthorized := func(r *http.Request) bool {
		return adminSessions.verify(adminSessionTokenFromRequest(r.Header.Get("X-MeshLAN-Admin-Session")), time.Now())
	}
	registerAIRoutes(mux, &state, &stateMu, *statePath, history, adminAuthorized)
	mux.HandleFunc("GET /v1/admin/auth-info", func(w http.ResponseWriter, _ *http.Request) {
		stateMu.Lock()
		totpRequired := state.AdminTOTPEnabled
		stateMu.Unlock()
		writeControlJSON(w, http.StatusOK, map[string]any{"totpRequired": totpRequired, "sessionMinutes": int(adminSessionLifetime.Minutes())})
	})
	mux.HandleFunc("POST /v1/admin/session", func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(r.RemoteAddr) {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		var input struct {
			TOTP string `json:"totp"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		stateMu.Lock()
		validToken := verifyAdminToken(state, adminTokenFromRequest(r))
		validTOTP := !state.AdminTOTPEnabled || verifyTOTPCode(state.AdminTOTPSecret, input.TOTP, time.Now())
		stateMu.Unlock()
		if !validToken || !validTOTP {
			http.Error(w, "invalid administrator credentials", http.StatusUnauthorized)
			return
		}
		token, expiresAt, err := adminSessions.issue(time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = history.RecordEvent("server", "admin_session", "admin", "管理会话已建立", time.Now().UTC())
		writeControlJSON(w, http.StatusOK, map[string]any{"sessionToken": token, "expiresAt": expiresAt})
	})
	mux.HandleFunc("POST /v1/admin/session/revoke", func(w http.ResponseWriter, r *http.Request) {
		token := adminSessionTokenFromRequest(r.Header.Get("X-MeshLAN-Admin-Session"))
		if !adminSessions.verify(token, time.Now()) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		adminSessions.revoke(token)
		writeControlJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/admin/totp/setup", func(w http.ResponseWriter, r *http.Request) {
		sessionToken := adminSessionTokenFromRequest(r.Header.Get("X-MeshLAN-Admin-Session"))
		if !adminSessions.verify(sessionToken, time.Now()) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		stateMu.Lock()
		if state.AdminTOTPEnabled {
			stateMu.Unlock()
			http.Error(w, "TOTP already enabled", http.StatusConflict)
			return
		}
		networkName := state.NetworkName
		stateMu.Unlock()
		secret, err := generateTOTPSecret()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		adminSessions.setPendingTOTP(sessionToken, secret)
		writeControlJSON(w, http.StatusOK, map[string]any{"secret": secret, "uri": totpProvisioningURI(networkName, secret)})
	})
	mux.HandleFunc("POST /v1/admin/totp/confirm", func(w http.ResponseWriter, r *http.Request) {
		sessionToken := adminSessionTokenFromRequest(r.Header.Get("X-MeshLAN-Admin-Session"))
		if !adminSessions.verify(sessionToken, time.Now()) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		secret := adminSessions.pendingTOTPSecret(sessionToken)
		if secret == "" || !verifyTOTPCode(secret, input.Code, time.Now()) {
			http.Error(w, "invalid TOTP code", http.StatusUnauthorized)
			return
		}
		stateMu.Lock()
		state.AdminTOTPSecret = secret
		state.AdminTOTPEnabled = true
		err := saveJSON(*statePath, state)
		stateMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		adminSessions.clearPendingTOTP(sessionToken)
		_ = history.RecordEvent("server", "admin_totp_enabled", "admin", "管理员TOTP已启用", time.Now().UTC())
		writeControlJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/admin/totp/disable", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		stateMu.Lock()
		if !state.AdminTOTPEnabled || !verifyTOTPCode(state.AdminTOTPSecret, input.Code, time.Now()) {
			stateMu.Unlock()
			http.Error(w, "invalid TOTP code", http.StatusUnauthorized)
			return
		}
		state.AdminTOTPEnabled = false
		state.AdminTOTPSecret = ""
		err := saveJSON(*statePath, state)
		stateMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = history.RecordEvent("server", "admin_totp_disabled", "admin", "管理员TOTP已关闭", time.Now().UTC())
		writeControlJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/admin/nodes", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			Endpoint string `json:"endpoint"`
			Hash     string `json:"hash"`
			Name     string `json:"name"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&input) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		stateMu.Lock()
		node, err := addMeshNode(&state, *statePath, input.Endpoint, input.Name, input.Hash)
		if err == nil {
			err = saveJSON(*statePath, state)
		}
		stateMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		_ = history.RecordEvent("server", "mesh_node_added", node.Name, node.PublicEndpoint, time.Now().UTC())
		writeControlJSON(w, http.StatusCreated, map[string]any{"ok": true, "node": node})
	})
	mux.HandleFunc("POST /v1/admin/nodes/delete", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			ID string `json:"id"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		stateMu.Lock()
		found, kept := false, state.MeshNodes[:0]
		for _, node := range state.MeshNodes {
			if node.ID == input.ID {
				found = true
				continue
			}
			kept = append(kept, node)
		}
		state.MeshNodes = kept
		err := saveJSON(*statePath, state)
		stateMu.Unlock()
		if !found {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /v1/admin/overview", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		now := time.Now()
		peers := make([]map[string]any, 0, len(state.Peers))
		onlinePeers := 0
		for _, peer := range state.Peers {
			online := !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) < 75*time.Second
			if online {
				onlinePeers++
			}
			peers = append(peers, map[string]any{
				"name": peer.Name, "address": peer.Address, "createdAt": peer.CreatedAt,
				"lastSeen": peer.LastSeen, "online": online,
				"bytesReceived": peer.BytesReceived, "bytesSent": peer.BytesSent,
				"serviceRunning": peer.ServiceRunning && online, "clientVersion": peer.ClientVersion, "revoked": peer.Revoked,
				"certificateFingerprint": peer.CertificateFingerprint, "dnsPrefix": peer.DNSPrefix,
			})
		}
		enrollments := make([]map[string]any, 0, len(state.Enrollments))
		for _, enrollment := range state.Enrollments {
			enrollments = append(enrollments, map[string]any{
				"id": enrollment.ID, "label": enrollment.Label, "createdAt": enrollment.CreatedAt,
				"expiresAt": enrollment.ExpiresAt, "revoked": enrollment.Revoked,
				"boundName": enrollment.BoundName, "used": enrollment.BoundName != "",
			})
		}
		w.Header().Set("Content-Type", "application/json")
		nodes := make([]map[string]any, 0, len(state.MeshNodes))
		for _, node := range state.MeshNodes {
			nodes = append(nodes, map[string]any{"id": node.ID, "name": node.Name, "address": node.Address, "publicEndpoint": node.PublicEndpoint, "controlEndpoint": node.ControlEndpoint, "createdAt": node.CreatedAt, "lastSeen": node.LastSeen, "online": node.Online, "nebulaRunning": node.NebulaRunning, "relayReady": node.RelayReady, "clientCount": node.ClientCount, "bytesReceived": node.BytesReceived, "bytesSent": node.BytesSent, "lastError": node.LastError})
		}
		updateKeyMinimumVersion := "1.10.1"
		updateKeyBlockers := independentUpdateKeyBlockers(state, updateKeyMinimumVersion)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"peers": peers, "nodes": nodes, "enrollments": enrollments, "network": state.Subnet, "endpoint": state.PublicEndpoint,
			"revocationVersion": state.RevocationVersion, "revocations": state.Revocations,
			"windowsUpdate": state.WindowsUpdate,
			"ai":            map[string]any{"settings": state.AIProvider, "keyConfigured": state.AIProviderAPIKey != "", "e2eeReady": state.AIEncryptionPublicKey != "", "bugReports": len(state.AIBugReports)},
			"security": map[string]any{
				"stateEncrypted":   state.SecretStorageVersion >= serverSecretStorageVersion && state.EncryptedServerSecrets != "",
				"caKeyEncrypted":   state.NebulaCAKeyEncrypted && state.NebulaCAKeyPEM != "",
				"signingKeysSplit": state.RevocationPublicKey != "" && state.UpdatePublicKey != "" && state.RevocationPublicKey != state.UpdatePublicKey,
				"updateKeyActive":  state.UpdateKeyActive, "updateKeyEligible": len(updateKeyBlockers) == 0,
				"updateKeyMinimumVersion": updateKeyMinimumVersion, "updateKeyBlockers": updateKeyBlockers,
				"totpEnabled": state.AdminTOTPEnabled,
			},
			"server": map[string]any{
				"controlRunning": true, "nebulaRunning": nebulaProcess.Running(),
				"startedAt": serverStartedAt, "uptimeSeconds": int64(time.Since(serverStartedAt).Seconds()),
				"lighthouseAddress": state.LighthouseAddress, "publicEndpoint": state.PublicEndpoint,
				"pairingPort": state.PairingPort, "onlinePeers": onlinePeers, "totalPeers": len(state.Peers),
			},
		})
	})
	mux.HandleFunc("GET /v1/update/manifest", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if authorizedDevicePeer(&state, r) == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if state.WindowsUpdate == nil || state.WindowsUpdatePath == "" {
			http.Error(w, "no update published", http.StatusNotFound)
			return
		}
		hash, size, err := fileSHA256(state.WindowsUpdatePath)
		if err != nil || hash != state.WindowsUpdate.SHA256 || size != state.WindowsUpdate.Size {
			http.Error(w, "published update integrity check failed", http.StatusServiceUnavailable)
			return
		}
		manifest, err := signedUpdateManifest(state, *state.WindowsUpdate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeControlJSON(w, http.StatusOK, manifest)
	})
	mux.HandleFunc("GET /v1/admin/history", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		authorized := adminAuthorized(r)
		stateMu.Unlock()
		if !authorized {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		hours := 24
		if value := strings.TrimSpace(r.URL.Query().Get("hours")); value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil {
				http.Error(w, "invalid history window", http.StatusBadRequest)
				return
			}
			hours = parsed
		}
		result, err := history.ServerHistory(hours)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeControlJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /v1/update/package/windows-amd64", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		requester := authorizedDevicePeer(&state, r)
		if requester == nil {
			stateMu.Unlock()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if state.WindowsUpdate == nil || state.WindowsUpdatePath == "" {
			stateMu.Unlock()
			http.Error(w, "no update published", http.StatusNotFound)
			return
		}
		manifest := *state.WindowsUpdate
		path := state.WindowsUpdatePath
		requesterName := requester.Name
		var seed *PeerRecord
		if r.Header.Get("X-MeshLAN-No-P2P") != "1" {
			seed = selectP2PUpdateSeed(state, requesterName, manifest, time.Now().UTC())
		}
		stateMu.Unlock()
		if seed != nil {
			location := "http://" + net.JoinHostPort(barePeerAddress(seed.Address), strconv.Itoa(seed.UpdateSeedPort)) + "/.meshlan/update/" + manifest.SHA256
			w.Header().Set("X-MeshLAN-Update-Source", "p2p:"+seed.Name)
			http.Redirect(w, r, location, http.StatusTemporaryRedirect)
			_ = history.RecordEvent("server", "update_p2p_redirect", requesterName, "通过 "+seed.Name+" 获取 "+manifest.Version, time.Now().UTC())
			return
		}
		hash, size, err := fileSHA256(path)
		if err != nil || hash != manifest.SHA256 || size != manifest.Size {
			http.Error(w, "published update integrity check failed", http.StatusServiceUnavailable)
			return
		}
		file, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="MeshLAN-Nebula-Windows-%s.exe"`, manifest.Version))
		w.Header().Set("X-Content-SHA256", manifest.SHA256)
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
	})
	mux.HandleFunc("POST /v1/admin/enrollments", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			Label         string `json:"label"`
			LifetimeHours int    `json:"lifetimeHours"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&input); err != nil || !validName(input.Label) {
			http.Error(w, "invalid label", http.StatusBadRequest)
			return
		}
		if input.LifetimeHours < 1 || input.LifetimeHours > 720 {
			input.LifetimeHours = 24
		}
		code, err := issueEnrollmentCode(&state, input.Label, time.Duration(input.LifetimeHours)*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := saveJSON(*statePath, state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"pairingHash": code, "enrollment": state.Enrollments[len(state.Enrollments)-1]})
	})
	mux.HandleFunc("POST /v1/admin/enrollments/revoke", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if !removeEnrollment(&state, input.ID) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err := saveJSON(*statePath, state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("POST /v1/admin/peers/delete", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil || !validName(input.Name) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		peer := findPeerByName(&state, input.Name)
		if peer == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if !validCertificateFingerprint(peer.CertificateFingerprint) {
			http.Error(w, "设备尚未上报证书指纹；请先让该设备运行 Client 1.8.0 并等待一次心跳，再执行安全删除", http.StatusConflict)
			return
		}
		addCertificateRevocation(&state, peer.Name, peer.CertificateFingerprint, "device_removed")
		if !removePeer(&state, input.Name) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		config := renderLighthouseConfig(state.NebulaCACertPath, filepath.Join(root, "lighthouse.crt"), filepath.Join(root, "lighthouse.key"), state.NebulaPort, revocationFingerprints(state))
		if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := saveJSON(*statePath, state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = history.RecordEvent("server", "peer_revoked", input.Name, "设备证书已吊销并删除", time.Now().UTC())
		if err := nebulaProcess.Restart(); err != nil {
			http.Error(w, "设备已吊销，但 Nebula 重载失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("POST /v1/rekey", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		peer := authorizedDevicePeer(&state, r)
		if peer == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			CertificateFingerprint string `json:"certificateFingerprint"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input)
		if validCertificateFingerprint(input.CertificateFingerprint) {
			peer.CertificateFingerprint = strings.ToLower(strings.TrimSpace(input.CertificateFingerprint))
		}
		if !validCertificateFingerprint(peer.CertificateFingerprint) {
			http.Error(w, "无法确认旧证书指纹，拒绝创建不完整的身份修复事务", http.StatusConflict)
			return
		}
		purgeExpiredRekeys(&state, time.Now())
		code, err := issueRekeyCode(&state, *peer, 10*time.Minute)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := saveJSON(*statePath, state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"pairingHash": code, "expiresInSeconds": 600})
	})
	mux.HandleFunc("POST /v1/rekey/commit", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		name, token, ok := deviceCredentialsFromRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			RekeyID string `json:"rekeyId"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil || input.RekeyID == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		pendingIndex := -1
		for i := range state.PendingRekeys {
			pending := &state.PendingRekeys[i]
			if pending.ID == input.RekeyID && pending.Name == name && time.Now().Before(pending.ExpiresAt) && subtle.ConstantTimeCompare([]byte(tokenDigest(token)), []byte(pending.NewDeviceTokenHash)) == 1 {
				pendingIndex = i
				break
			}
		}
		if pendingIndex < 0 {
			http.Error(w, "pending rekey not found", http.StatusUnauthorized)
			return
		}
		pending := state.PendingRekeys[pendingIndex]
		peer := findPeerByName(&state, name)
		if peer == nil || peer.Address != pending.Address {
			http.Error(w, "peer state changed", http.StatusConflict)
			return
		}
		addCertificateRevocation(&state, peer.Name, pending.OldFingerprint, "identity_rekey")
		peer.PublicKey = pending.NewPublicKey
		peer.CertificateFingerprint = pending.NewCertificateFingerprint
		peer.DeviceTokenHash = pending.NewDeviceTokenHash
		peer.Revoked = false
		state.PendingRekeys = append(state.PendingRekeys[:pendingIndex], state.PendingRekeys[pendingIndex+1:]...)
		enrollments := state.Enrollments[:0]
		for _, enrollment := range state.Enrollments {
			if enrollment.Rekey && enrollment.BoundName == name {
				continue
			}
			enrollments = append(enrollments, enrollment)
		}
		state.Enrollments = enrollments
		config := renderLighthouseConfig(state.NebulaCACertPath, filepath.Join(root, "lighthouse.crt"), filepath.Join(root, "lighthouse.key"), state.NebulaPort, revocationFingerprints(state))
		if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := saveJSON(*statePath, state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = history.RecordEvent("server", "identity_rekey", peer.Name, "新身份已提交，旧证书已吊销", time.Now().UTC())
		if err := nebulaProcess.Restart(); err != nil {
			http.Error(w, "新身份已提交，但 Nebula 重载失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		envelope, err := signedRevocationEnvelope(state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, HeartbeatResponse{OK: true, Revocations: envelope})
	})
	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		viewer := authorizedDevicePeer(&state, r)
		if viewer == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		now := time.Now()
		peers := make([]PeerDirectoryEntry, 0, len(state.Peers))
		services := make([]PublishedServiceMapping, 0)
		files := make([]FileShareDirectoryEntry, 0)
		dnsRecords := buildMeshDNSRecords(state)
		deviceDNS := map[string]string{}
		serviceDNS := map[string]string{}
		for _, record := range dnsRecords {
			if record.Kind == "device" {
				deviceDNS[record.OwnerName] = record.Name
			} else if record.Kind == "service" {
				serviceDNS[record.OwnerName+"|"+record.MappingID] = record.Name
			}
		}
		for _, peer := range state.Peers {
			if peer.Revoked {
				continue
			}
			online := !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) < 75*time.Second
			peers = append(peers, PeerDirectoryEntry{
				Name: peer.Name, Address: peer.Address,
				Online:         online,
				ServiceRunning: peer.ServiceRunning && online, BytesReceived: peer.BytesReceived, BytesSent: peer.BytesSent,
				LastSeen: peer.LastSeen, OnlineSince: peer.OnlineSince, ClientVersion: peer.ClientVersion,
				DNSName: deviceDNS[peer.Name], DNSPrefix: peer.DNSPrefix,
			})
			for _, service := range peer.ServiceMappings {
				service.OwnerName = peer.Name
				service.Protocol = normalizeMappingProtocol(service.Protocol)
				if prefix, err := netip.ParsePrefix(peer.Address); err == nil {
					service.Address = prefix.Addr().String()
				}
				service.Active = service.Active && online && !service.Paused
				service.Healthy = service.Healthy && service.Active
				service.ViewerAccessStatus = viewerAccessStatus(&state, service, viewer.Name)
				service.DNSName = serviceDNS[peer.Name+"|"+service.ID]
				if service.PortlessHTTP {
					scheme := "http://"
					if service.HTTPS {
						scheme = "https://"
					}
					service.URL = scheme + service.DNSName
				}
				services = append(services, service)
			}
			for _, file := range peer.FileShares {
				if !online || !file.ExpiresAt.After(now) || file.DownloadCount >= file.MaxDownloads || (file.RecipientName != "" && file.RecipientName != viewer.Name && peer.Name != viewer.Name) {
					continue
				}
				token := fileShareTokens[peer.Name+"|"+file.ID]
				if token == "" {
					continue
				}
				file.OwnerName = peer.Name
				file.OwnerAddress = barePeerAddress(peer.Address)
				files = append(files, FileShareDirectoryEntry{PublishedFileShare: file, DownloadURL: "http://" + net.JoinHostPort(file.OwnerAddress, "24443") + "/.meshlan/files/" + file.ID + "?token=" + url.QueryEscape(token)})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PeerDirectoryResponse{Peers: peers, Services: services, Files: files, RefreshedAt: now})
	})
	registerAccessControlRoutes(mux, &state, &stateMu, *statePath)
	registerMeshDNSRoutes(mux, &state, &stateMu, *statePath)
	registerMeshHTTPSRoutes(mux, &state, &stateMu, *statePath)
	mux.HandleFunc("POST /v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		name, _, ok := deviceCredentialsFromRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var heartbeat HeartbeatRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&heartbeat); err != nil || heartbeat.Name != name {
			http.Error(w, "invalid heartbeat", http.StatusBadRequest)
			return
		}
		peer := authorizedDevicePeer(&state, r)
		if peer == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if len(heartbeat.ServiceMappings) > 32 {
			http.Error(w, "too many service mappings", http.StatusBadRequest)
			return
		}
		if len(heartbeat.FileShares) > 64 {
			http.Error(w, "too many file shares", http.StatusBadRequest)
			return
		}
		now := time.Now().UTC()
		wasOnline := !peer.LastSeen.IsZero() && now.Sub(peer.LastSeen) < 75*time.Second
		if !wasOnline {
			peer.OnlineSince = now
		} else if peer.OnlineSince.IsZero() {
			peer.OnlineSince = peer.LastSeen
		}
		previousServiceRunning := peer.ServiceRunning
		services := make([]PublishedServiceMapping, 0, len(heartbeat.ServiceMappings))
		usedServicePrefixes := map[string]bool{}
		for _, mapping := range heartbeat.ServiceMappings {
			if len(mapping.ID) < 8 || len(mapping.ID) > 64 || !validServiceName(mapping.ServiceName) || mapping.Port < 1 || mapping.Port > 65535 {
				http.Error(w, "invalid service mapping", http.StatusBadRequest)
				return
			}
			protocol := normalizeMappingProtocol(mapping.Protocol)
			prefix := strings.TrimSpace(mapping.DNSPrefix)
			explicitPrefix := prefix != ""
			if !explicitPrefix {
				prefix = meshDNSLabel(mapping.ServiceName, mapping.ID)
			}
			prefix, prefixErr := normalizeDNSPrefix(prefix)
			if prefixErr != nil || (mapping.PortlessHTTP && protocol != "tcp") {
				http.Error(w, "invalid service DNS or exposure mode", http.StatusBadRequest)
				return
			}
			if usedServicePrefixes[prefix] {
				if explicitPrefix {
					http.Error(w, "duplicate service DNS prefix", http.StatusConflict)
					return
				}
				prefix += "-" + shortStableHash(mapping.ID)
			}
			usedServicePrefixes[prefix] = true
			services = append(services, PublishedServiceMapping{
				ID: mapping.ID, OwnerName: peer.Name, ServiceName: strings.TrimSpace(mapping.ServiceName),
				Address: peer.Address, Port: mapping.Port, Protocol: protocol, DNSPrefix: prefix, PortlessHTTP: mapping.PortlessHTTP, HTTPS: mapping.HTTPS,
				Active: mapping.Active, Paused: mapping.Paused, ApprovalRequired: mapping.ApprovalRequired,
				Healthy: mapping.Healthy, LatencyMs: mapping.LatencyMs, CheckedAt: mapping.CheckedAt, UpdatedAt: time.Now(),
			})
		}
		peer.LastSeen = now
		peer.BytesReceived = heartbeat.BytesReceived
		peer.BytesSent = heartbeat.BytesSent
		peer.ServiceRunning = heartbeat.ServiceRunning
		peer.ClientVersion = heartbeat.ClientVersion
		peer.UpdateSeedReady = heartbeat.UpdateSeedReady
		peer.UpdateSeedSHA256 = strings.ToLower(strings.TrimSpace(heartbeat.UpdateSeedSHA256))
		peer.UpdateSeedPort = heartbeat.UpdateSeedPort
		if !validCertificateFingerprint(peer.UpdateSeedSHA256) || peer.UpdateSeedPort < 1 || peer.UpdateSeedPort > 65535 {
			peer.UpdateSeedReady, peer.UpdateSeedSHA256, peer.UpdateSeedPort = false, "", 0
		}
		if validX25519PublicKey(heartbeat.AIEncryptionPublicKey) {
			peer.AIEncryptionPublicKey = heartbeat.AIEncryptionPublicKey
		}
		updateKeyActivated, updateKeyActivationErr := autoActivateIndependentUpdateKey(&state, "1.10.1")
		if validCertificateFingerprint(heartbeat.CertificateFingerprint) {
			peer.CertificateFingerprint = strings.ToLower(strings.TrimSpace(heartbeat.CertificateFingerprint))
		}
		peer.ServiceMappings = services
		publishedFiles := make([]PublishedFileShare, 0, len(heartbeat.FileShares))
		activeFileKeys := map[string]bool{}
		for _, file := range heartbeat.FileShares {
			if len(file.ID) < 8 || len(file.ID) > 64 || !validFileShareName(file.FileName) || file.Size < 0 || file.Size > 20<<30 || !validCertificateFingerprint(file.SHA256) || file.MaxDownloads < 1 || file.MaxDownloads > 1000 || file.DownloadCount < 0 || file.DownloadCount > file.MaxDownloads || len(file.AccessToken) < 32 || len(file.AccessToken) > 256 || file.ExpiresAt.Before(now.Add(-time.Minute)) || file.ExpiresAt.After(now.Add(30*24*time.Hour)) {
				continue
			}
			if file.RecipientName != "" && findPeerByName(&state, file.RecipientName) == nil {
				continue
			}
			key := peer.Name + "|" + file.ID
			activeFileKeys[key] = true
			fileShareTokens[key] = file.AccessToken
			publishedFiles = append(publishedFiles, PublishedFileShare{ID: file.ID, OwnerName: peer.Name, OwnerAddress: barePeerAddress(peer.Address), FileName: file.FileName, Size: file.Size, SHA256: file.SHA256, RecipientName: file.RecipientName, ExpiresAt: file.ExpiresAt, MaxDownloads: file.MaxDownloads, DownloadCount: file.DownloadCount, UpdatedAt: now})
		}
		for key := range fileShareTokens {
			if strings.HasPrefix(key, peer.Name+"|") && !activeFileKeys[key] {
				delete(fileShareTokens, key)
			}
		}
		peer.FileShares = publishedFiles
		_ = saveJSON(*statePath, state)
		if updateKeyActivated {
			_ = history.RecordEvent("server", "update_key_activated", "system", "所有未吊销客户端已达到 1.10.1，独立更新签名密钥自动激活", now)
		} else if updateKeyActivationErr != nil {
			_ = history.RecordEvent("server", "update_key_activation_failed", "system", updateKeyActivationErr.Error(), now)
		}
		_ = history.RecordServerPeer(*peer, now, true)
		if !wasOnline {
			_ = history.RecordEvent("server", "peer_online", peer.Name, "设备恢复控制心跳", now)
		}
		if previousServiceRunning != peer.ServiceRunning {
			detail := "Nebula 服务已停止"
			if peer.ServiceRunning {
				detail = "Nebula 服务已启动"
			}
			_ = history.RecordEvent("server", "service_state", peer.Name, detail, now)
		}
		revocations, err := signedRevocationEnvelope(state)
		if err != nil {
			http.Error(w, "revocation signing failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{OK: true, Revocations: revocations, Lighthouses: meshNodeEndpoints(state), HTTPSCACertificatePEM: state.HTTPSCACertificatePEM, HTTPSCAFingerprint: state.HTTPSCAFingerprint, AIEncryptionPublicKey: state.AIEncryptionPublicKey})
	})
	mux.HandleFunc("POST /v1/pair", func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(r.RemoteAddr) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		secret := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "MeshLAN "))
		enrollmentID := strings.TrimSpace(r.Header.Get("X-MeshLAN-Enrollment"))
		stateMu.Lock()
		defer stateMu.Unlock()
		enrollment := findEnrollment(&state, enrollmentID, secret)
		if enrollment == nil {
			time.Sleep(200 * time.Millisecond)
			http.Error(w, "invalid pairing hash", http.StatusUnauthorized)
			return
		}
		var request PairRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&request); err != nil || request.Version != protocolVersion || !validName(request.Name) || len(request.PublicKey) > 4096 || !strings.Contains(request.PublicKey, "NEBULA") {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if enrollment.BoundName != "" && enrollment.BoundName != request.Name {
			http.Error(w, "pairing hash already bound to another device", http.StatusConflict)
			return
		}
		if enrollment.BoundPublicKey != "" && enrollment.BoundPublicKey != request.PublicKey {
			http.Error(w, "pairing hash already bound to another device", http.StatusConflict)
			return
		}
		deviceToken, tokenErr := randomToken(32)
		if tokenErr != nil {
			http.Error(w, "device token failed", http.StatusInternalServerError)
			return
		}
		enrollment.BoundName = request.Name
		enrollment.BoundPublicKey = request.PublicKey
		if enrollment.Rekey {
			peer := findPeerByName(&state, request.Name)
			if peer == nil || (enrollment.ReservedAddress != "" && peer.Address != enrollment.ReservedAddress) {
				http.Error(w, "需要修复的设备不存在或地址不匹配", http.StatusConflict)
				return
			}
			for _, other := range state.Peers {
				if other.Name != peer.Name && other.PublicKey == request.PublicKey {
					http.Error(w, "公钥已绑定其他设备", http.StatusConflict)
					return
				}
			}
			candidate := *peer
			candidate.PublicKey = request.PublicKey
			candidate.CertificateFingerprint = ""
			response, err := signPairResponse(state, &candidate, request.PublicKey, root, deviceToken)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			rekeyID, err := randomToken(12)
			if err != nil {
				http.Error(w, "rekey id failed", http.StatusInternalServerError)
				return
			}
			state.PendingRekeys = append(state.PendingRekeys, PendingRekeyRecord{
				ID: rekeyID, Name: peer.Name, Address: peer.Address,
				OldFingerprint: peer.CertificateFingerprint, NewPublicKey: request.PublicKey,
				NewCertificatePEM: response.CertificatePEM, NewCertificateFingerprint: candidate.CertificateFingerprint,
				NewDeviceTokenHash: tokenDigest(deviceToken), CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(10 * time.Minute).UTC(),
			})
			response.RekeyID = rekeyID
			if err := saveJSON(*statePath, state); err != nil {
				http.Error(w, "state write failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		peer, err := findOrCreatePeer(&state, request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		peer.DeviceTokenHash = tokenDigest(deviceToken)
		response, err := signPairResponse(state, peer, request.PublicKey, root, deviceToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := saveJSON(*statePath, state); err != nil {
			http.Error(w, "state write failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	fmt.Printf("Nebula Lighthouse UDP %d；配对 HTTPS %d\n", state.NebulaPort, state.PairingPort)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 10 * time.Minute}
	return server.Serve(listener)
}

func findOrCreatePeer(state *ServerState, request PairRequest) (*PeerRecord, error) {
	for i := range state.Peers {
		peer := &state.Peers[i]
		if peer.Name == request.Name || peer.PublicKey == request.PublicKey {
			if peer.Name != request.Name || peer.PublicKey != request.PublicKey || peer.Revoked {
				return nil, errors.New("设备名称或公钥冲突")
			}
			return peer, nil
		}
	}
	address, err := allocateAddress(*state)
	if err != nil {
		return nil, err
	}
	usedPrefixes := map[string]bool{}
	for _, peer := range state.Peers {
		if prefix, err := normalizeDNSPrefix(peer.DNSPrefix); err == nil {
			usedPrefixes[prefix] = true
		}
	}
	dnsPrefix := uniqueDefaultDNSPrefix(request.Name, usedPrefixes)
	state.Peers = append(state.Peers, PeerRecord{Name: request.Name, DNSPrefix: dnsPrefix, PublicKey: request.PublicKey, Address: address, CreatedAt: time.Now()})
	return &state.Peers[len(state.Peers)-1], nil
}

func materializeNebulaCAKey(state ServerState, root string) (string, func(), error) {
	if state.NebulaCAKeyPEM == "" {
		if state.NebulaCAKeyPath == "" {
			return "", func() {}, errors.New("Nebula CA私钥不可用")
		}
		return state.NebulaCAKeyPath, func() {}, nil
	}
	secretRoot := filepath.Join(root, "runtime-secrets")
	if err := os.MkdirAll(secretRoot, 0o700); err != nil {
		return "", func() {}, err
	}
	file, err := os.CreateTemp(secretRoot, "ca-signing-*.key")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() {
		_ = os.Remove(path)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := file.WriteString(state.NebulaCAKeyPEM); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func signPairResponse(state ServerState, peer *PeerRecord, publicKey string, root string, deviceToken string) (PairResponse, error) {
	publicPath := filepath.Join(root, "pairing-"+peer.Name+".pub")
	certPath := filepath.Join(root, "pairing-"+peer.Name+".crt")
	_ = os.Remove(certPath)
	if err := os.WriteFile(publicPath, []byte(publicKey), 0o600); err != nil {
		return PairResponse{}, err
	}
	defer os.Remove(publicPath)
	caKeyPath, cleanupCAKey, err := materializeNebulaCAKey(state, root)
	if err != nil {
		return PairResponse{}, err
	}
	defer cleanupCAKey()
	if err := runCommand(state.NebulaCertPath, "sign", "-version", "2", "-ca-key", caKeyPath, "-ca-crt", state.NebulaCACertPath, "-name", peer.Name, "-networks", peer.Address, "-groups", "meshlan", "-duration", "8760h", "-in-pub", publicPath, "-out-crt", certPath); err != nil {
		return PairResponse{}, err
	}
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		return PairResponse{}, err
	}
	fingerprint, err := certificateFingerprint(state.NebulaCertPath, certPath)
	if err != nil {
		return PairResponse{}, err
	}
	peer.CertificateFingerprint = fingerprint
	_ = os.Remove(certPath)
	ca, err := os.ReadFile(state.NebulaCACertPath)
	if err != nil {
		return PairResponse{}, err
	}
	controlHost := state.PublicEndpoint
	if host, _, splitErr := net.SplitHostPort(state.PublicEndpoint); splitErr == nil {
		controlHost = strings.Trim(host, "[]")
	}
	return PairResponse{
		Version: protocolVersion, Name: peer.Name, Address: peer.Address,
		CertificatePEM: string(certificate), CACertificatePEM: string(ca),
		LighthouseAddress: state.LighthouseAddress, LighthouseEndpoint: state.PublicEndpoint,
		RelayAddress: state.LighthouseAddress, NetworkName: state.NetworkName,
		DeviceToken: deviceToken, ControlHost: controlHost, ControlPort: state.PairingPort,
		ControlPin: state.TLSCertificatePin, SecurityPublicKey: state.SecurityPublicKey,
		RevocationPublicKey: state.RevocationPublicKey, UpdatePublicKey: state.UpdatePublicKey,
		UpdateKeyActive: state.UpdateKeyActive, DNSPrefix: peer.DNSPrefix, Lighthouses: meshNodeEndpoints(state), HTTPSCACertificatePEM: state.HTTPSCACertificatePEM, HTTPSCAFingerprint: state.HTTPSCAFingerprint, AIEncryptionPublicKey: state.AIEncryptionPublicKey,
	}, nil
}

func serverPairing(args []string) error {
	fs, statePath := serverFlagSet("server pairing")
	label := fs.String("label", "device", "用户或设备标签")
	hours := fs.Int("hours", 24, "配对哈希有效小时数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !validName(*label) || *hours < 1 || *hours > 720 {
		return errors.New("label 或 hours 无效")
	}
	var state ServerState
	if err := loadJSON(*statePath, &state); err != nil {
		return err
	}
	code, err := issueEnrollmentCode(&state, *label, time.Duration(*hours)*time.Hour)
	if err != nil {
		return err
	}
	if err := saveJSON(*statePath, state); err != nil {
		return err
	}
	fmt.Printf("新的配对哈希: %s\n旧哈希已失效，已配对设备不受影响。\n", code)
	return nil
}

func serverAdminToken(args []string) error {
	fs, statePath := serverFlagSet("server admin-token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var state ServerState
	if err := loadJSON(*statePath, &state); err != nil {
		return err
	}
	token, err := issueAdminToken(&state)
	if err != nil {
		return err
	}
	if err := saveJSON(*statePath, state); err != nil {
		return err
	}
	fmt.Printf("新的管理令牌: %s\n旧管理令牌立即失效。\n", token)
	return nil
}

func serverList(args []string) error {
	fs, statePath := serverFlagSet("server list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var state ServerState
	if err := loadJSON(*statePath, &state); err != nil {
		return err
	}
	for _, peer := range state.Peers {
		fmt.Printf("%-20s %-20s revoked=%v\n", peer.Name, peer.Address, peer.Revoked)
	}
	return nil
}
