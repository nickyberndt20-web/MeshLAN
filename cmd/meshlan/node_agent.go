package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func defaultNodeStatePath() string {
	return filepath.Join(filepath.Dir(defaultServerStatePath()), "node-state.json")
}

func serverNodeInit(args []string) error {
	fs := flag.NewFlagSet("server node-init", flag.ContinueOnError)
	statePath := fs.String("state", defaultNodeStatePath(), "子节点状态文件")
	endpoint := fs.String("endpoint", "", "子节点公网 IP 或域名")
	name := fs.String("name", "", "子节点名称")
	controlPort := fs.Int("control-port", 8090, "子节点配对 HTTPS 端口")
	nebulaPort := fs.Int("nebula-port", 4242, "子节点 Nebula UDP 端口")
	nebulaBin := fs.String("nebula", "nebula", "nebula 可执行文件")
	certBin := fs.String("nebula-cert", "nebula-cert", "nebula-cert 可执行文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" || *controlPort < 1 || *controlPort > 65535 || *nebulaPort < 1 || *nebulaPort > 65535 {
		return errors.New("必须提供有效的 -endpoint、-control-port 和 -nebula-port")
	}
	if _, err := os.Stat(*statePath); err == nil {
		return errors.New("子节点状态已存在，拒绝覆盖")
	}
	root := filepath.Dir(*statePath)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	id, err := randomToken(12)
	if err != nil {
		return err
	}
	if *name == "" {
		*name = "node-" + id[:8]
	}
	if !validName(*name) {
		return errors.New("节点名称无效")
	}
	tlsEndpoint := net.JoinHostPort(strings.Trim(*endpoint, "[]"), strconv.Itoa(*controlPort))
	certificate, privateKey, pin, err := generateTLSIdentity(tlsEndpoint)
	if err != nil {
		return err
	}
	privatePath := filepath.Join(root, "node.key")
	publicPath := filepath.Join(root, "node.pub")
	if err := runCommand(*certBin, "keygen", "-out-key", privatePath, "-out-pub", publicPath); err != nil {
		return err
	}
	state := MeshNodeAgentState{Version: protocolVersion, ID: id, Name: *name, PublicEndpoint: net.JoinHostPort(strings.Trim(*endpoint, "[]"), strconv.Itoa(*nebulaPort)), ControlPort: *controlPort, NebulaPort: *nebulaPort, TLSCertificatePEM: certificate, TLSPrivateKeyPEM: privateKey, TLSCertificatePin: pin, PublicKeyPath: publicPath, PrivateKeyPath: privatePath, NebulaBin: *nebulaBin, NebulaCertBin: *certBin}
	code, err := issueNodePairingCode(&state)
	if err != nil {
		return err
	}
	if err := saveJSON(*statePath, state); err != nil {
		return err
	}
	fmt.Printf("MeshLAN 子节点已初始化\n名称: %s\n公网 UDP: %s\n控制端口: %d/TCP\n子节点哈希: %s\n启动: %s server node-serve -state %s\n", state.Name, state.PublicEndpoint, state.ControlPort, code, os.Args[0], *statePath)
	return nil
}

func renderNodeLighthouseConfig(state MeshNodeAgentState) string {
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

punchy:
  punch: true
  respond: true
  delay: 1s
  respond_delay: 2s

relay:
  relays: []
  am_relay: true
  use_relays: false

tun:
  disabled: false
  dev: MeshLAN-Node
  mtu: 1300

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
`, yamlPath(state.CACertificatePath), yamlPath(state.CertificatePath), yamlPath(state.PrivateKeyPath), renderBlocklistYAML(state.RevokedFingerprints), state.NebulaPort)
}

func serverNodeServe(args []string) error {
	fs := flag.NewFlagSet("server node-serve", flag.ContinueOnError)
	statePath := fs.String("state", defaultNodeStatePath(), "子节点状态文件")
	bind := fs.String("bind", "0.0.0.0", "控制服务监听地址")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var state MeshNodeAgentState
	if err := loadJSON(*statePath, &state); err != nil {
		return err
	}
	certificate, err := tls.X509KeyPair([]byte(state.TLSCertificatePEM), []byte(state.TLSPrivateKeyPEM))
	if err != nil {
		return err
	}
	var stateMu sync.Mutex
	nebulaProcess := &nebulaChildProcess{executable: state.NebulaBin}
	startNebula := func() error {
		if !state.Enrolled || state.ConfigPath == "" {
			return nil
		}
		nebulaProcess.configPath = state.ConfigPath
		return nebulaProcess.Restart()
	}
	if state.Enrolled {
		nebulaProcess.configPath = state.ConfigPath
		if err := nebulaProcess.Start(); err != nil {
			return err
		}
	}
	defer nebulaProcess.Stop()
	mux := http.NewServeMux()
	authorized := func(r *http.Request) bool {
		stateMu.Lock()
		defer stateMu.Unlock()
		return nodeSecretMatches(state, r.Header.Get("Authorization"))
	}
	mux.HandleFunc("GET /v1/node/info", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		stateMu.Lock()
		defer stateMu.Unlock()
		publicKey, err := os.ReadFile(state.PublicKeyPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, meshNodeInfo{ID: state.ID, Name: state.Name, PublicKey: string(publicKey), PublicEndpoint: state.PublicEndpoint, NebulaPort: state.NebulaPort, Enrolled: state.Enrolled})
	})
	mux.HandleFunc("POST /v1/node/enroll", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request meshNodeEnrollRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&request) != nil || request.ID != state.ID || !validName(request.Name) || !parseNodeAddress(request.Address) {
			http.Error(w, "invalid enrollment", http.StatusBadRequest)
			return
		}
		revocationPayload, verifyErr := verifyRevocationEnvelope(request.Revocations, request.RevocationPublicKey)
		if verifyErr != nil {
			http.Error(w, verifyErr.Error(), http.StatusUnauthorized)
			return
		}
		stateMu.Lock()
		if state.Enrolled {
			stateMu.Unlock()
			http.Error(w, "already enrolled", http.StatusConflict)
			return
		}
		root := filepath.Dir(*statePath)
		state.Name, state.Address = request.Name, request.Address
		state.RevocationPublicKey = request.RevocationPublicKey
		state.RevocationVersion = revocationPayload.Version
		state.RevokedFingerprints = normalizedFingerprintsFromRevocations(revocationPayload.Revocations)
		state.CertificatePath, state.CACertificatePath, state.ConfigPath = filepath.Join(root, "node.crt"), filepath.Join(root, "ca.crt"), filepath.Join(root, "node.yml")
		err := os.WriteFile(state.CertificatePath, []byte(request.CertificatePEM), 0o600)
		if err == nil {
			err = os.WriteFile(state.CACertificatePath, []byte(request.CACertificatePEM), 0o600)
		}
		if err == nil {
			err = os.WriteFile(state.ConfigPath, []byte(renderNodeLighthouseConfig(state)), 0o600)
		}
		if err == nil {
			state.Enrolled, state.EnrolledAt = true, time.Now().UTC()
			err = saveJSON(*statePath, state)
		}
		stateMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := startNebula(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/node/revocations", func(w http.ResponseWriter, r *http.Request) {
		var envelope SignedRevocationEnvelope
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&envelope) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		stateMu.Lock()
		payload, err := verifyRevocationEnvelope(envelope, state.RevocationPublicKey)
		revocationsChanged := err == nil && payload.Version > state.RevocationVersion
		if revocationsChanged {
			state.RevocationVersion = payload.Version
			state.RevokedFingerprints = normalizedFingerprintsFromRevocations(payload.Revocations)
		}
		desiredConfig := renderNodeLighthouseConfig(state)
		currentConfig, readErr := os.ReadFile(state.ConfigPath)
		configChanged := readErr != nil || string(currentConfig) != desiredConfig
		changed := revocationsChanged || configChanged
		if err == nil && changed {
			err = os.WriteFile(state.ConfigPath, []byte(desiredConfig), 0o600)
		}
		if err == nil && revocationsChanged {
			err = saveJSON(*statePath, state)
		}
		stateMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if changed {
			if err := startNebula(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		writeControlJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /v1/node/health", func(w http.ResponseWriter, _ *http.Request) {
		stateMu.Lock()
		config, _ := os.ReadFile(state.ConfigPath)
		relayEnabled := state.Enrolled && strings.Contains(string(config), "am_relay: true")
		health := meshNodeHealth{ID: state.ID, Name: state.Name, Address: state.Address, Enrolled: state.Enrolled, NebulaRunning: nebulaProcess.Running(), RelayEnabled: relayEnabled, UpdatedAt: time.Now().UTC()}
		stateMu.Unlock()
		writeControlJSON(w, http.StatusOK, health)
	})
	listener, err := tls.Listen("tcp", net.JoinHostPort(*bind, strconv.Itoa(state.ControlPort)), &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("MeshLAN 子节点控制服务: https://%s:%d；Nebula UDP: %d\n", *bind, state.ControlPort, state.NebulaPort)
	return (&http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second}).Serve(listener)
}
