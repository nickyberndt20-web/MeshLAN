package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const nodePairingPrefix = "MLNODE1."

type nodePairingPayload struct {
	Version int    `json:"v"`
	ID      string `json:"i"`
	Secret  string `json:"s"`
	Pin     string `json:"p"`
	Port    int    `json:"c"`
}

type MeshNodeAgentState struct {
	Version             int       `json:"version"`
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	SecretHash          string    `json:"secretHash"`
	PublicEndpoint      string    `json:"publicEndpoint"`
	ControlPort         int       `json:"controlPort"`
	NebulaPort          int       `json:"nebulaPort"`
	TLSCertificatePEM   string    `json:"tlsCertificatePem"`
	TLSPrivateKeyPEM    string    `json:"tlsPrivateKeyPem"`
	TLSCertificatePin   string    `json:"tlsCertificatePin"`
	PublicKeyPath       string    `json:"publicKeyPath"`
	PrivateKeyPath      string    `json:"privateKeyPath"`
	CertificatePath     string    `json:"certificatePath,omitempty"`
	CACertificatePath   string    `json:"caCertificatePath,omitempty"`
	ConfigPath          string    `json:"configPath,omitempty"`
	Address             string    `json:"address,omitempty"`
	Enrolled            bool      `json:"enrolled"`
	EnrolledAt          time.Time `json:"enrolledAt,omitempty"`
	NebulaBin           string    `json:"nebulaBin"`
	NebulaCertBin       string    `json:"nebulaCertBin"`
	RevocationPublicKey string    `json:"revocationPublicKey,omitempty"`
	RevocationVersion   uint64    `json:"revocationVersion,omitempty"`
	RevokedFingerprints []string  `json:"revokedFingerprints,omitempty"`
}

type meshNodeInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	PublicKey      string `json:"publicKey"`
	PublicEndpoint string `json:"publicEndpoint"`
	NebulaPort     int    `json:"nebulaPort"`
	Enrolled       bool   `json:"enrolled"`
}

type meshNodeEnrollRequest struct {
	ID                  string                   `json:"id"`
	Name                string                   `json:"name"`
	Address             string                   `json:"address"`
	CertificatePEM      string                   `json:"certificatePem"`
	CACertificatePEM    string                   `json:"caCertificatePem"`
	RevocationPublicKey string                   `json:"revocationPublicKey"`
	Revocations         SignedRevocationEnvelope `json:"revocations"`
}

type meshNodeHealth struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Address       string    `json:"address"`
	Enrolled      bool      `json:"enrolled"`
	NebulaRunning bool      `json:"nebulaRunning"`
	RelayEnabled  bool      `json:"relayEnabled"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func issueNodePairingCode(state *MeshNodeAgentState) (string, error) {
	secret, err := randomToken(32)
	if err != nil {
		return "", err
	}
	state.SecretHash = tokenDigest(secret)
	payload := nodePairingPayload{Version: protocolVersion, ID: state.ID, Secret: secret, Pin: state.TLSCertificatePin, Port: state.ControlPort}
	data, _ := json.Marshal(payload)
	return nodePairingPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func parseNodePairingCode(value string) (nodePairingPayload, error) {
	if !strings.HasPrefix(strings.TrimSpace(value), nodePairingPrefix) {
		return nodePairingPayload{}, errors.New("子节点哈希格式无效")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(value), nodePairingPrefix))
	if err != nil {
		return nodePairingPayload{}, errors.New("子节点哈希编码无效")
	}
	var payload nodePairingPayload
	if json.Unmarshal(data, &payload) != nil || payload.Version != protocolVersion || payload.ID == "" || payload.Port < 1 || payload.Port > 65535 {
		return nodePairingPayload{}, errors.New("子节点哈希参数无效")
	}
	secret, secretErr := base64.RawURLEncoding.DecodeString(payload.Secret)
	pin, pinErr := base64.RawURLEncoding.DecodeString(payload.Pin)
	if secretErr != nil || len(secret) != 32 || pinErr != nil || len(pin) != 32 {
		return nodePairingPayload{}, errors.New("子节点哈希密钥无效")
	}
	return payload, nil
}

func meshNodeEndpoints(state ServerState) []LighthouseEndpoint {
	nodes := []LighthouseEndpoint{{ID: "primary", Name: "主节点", Address: state.LighthouseAddress, Endpoint: state.PublicEndpoint, Primary: true, Relay: true}}
	for _, node := range state.MeshNodes {
		if node.Address != "" && node.PublicEndpoint != "" && node.Online && node.NebulaRunning {
			nodes = append(nodes, LighthouseEndpoint{ID: node.ID, Name: node.Name, Address: node.Address, Endpoint: node.PublicEndpoint, Relay: node.RelayReady})
		}
	}
	return nodes
}

func normalizedFingerprintsFromRevocations(items []CertificateRevocation) []string {
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, item.Fingerprint)
	}
	return normalizedFingerprints(values)
}

func meshNodeAuthorization(payload nodePairingPayload) string {
	return "MeshLAN-Node " + payload.ID + ":" + payload.Secret
}

func meshNodeRequest(ctx context.Context, endpoint string, payload nodePairingPayload, method, path string, input, output any) error {
	tlsConfig, err := pinnedTLSConfig(payload.Pin)
	if err != nil {
		return err
	}
	var body io.Reader
	if input != nil {
		data, marshalErr := json.Marshal(input)
		if marshalErr != nil {
			return marshalErr
		}
		body = bytes.NewReader(data)
	}
	request, _ := http.NewRequestWithContext(ctx, method, "https://"+pairingAddress(endpoint, payload.Port)+path, body)
	request.Header.Set("Authorization", meshNodeAuthorization(payload))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("子节点 HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		return errors.New("子节点返回数据无效")
	}
	return nil
}

func signMeshNodeCertificate(state ServerState, statePath, name, address, publicKey string) (certificatePEM, caPEM string, err error) {
	root := filepath.Dir(statePath)
	publicPath := filepath.Join(root, "node-"+name+".pub")
	certificatePath := filepath.Join(root, "node-"+name+".crt")
	if err := os.WriteFile(publicPath, []byte(publicKey), 0o600); err != nil {
		return "", "", err
	}
	defer os.Remove(publicPath)
	defer os.Remove(certificatePath)
	caKeyPath, cleanup, err := materializeNebulaCAKey(state, root)
	if err != nil {
		return "", "", err
	}
	defer cleanup()
	if err := runCommand(state.NebulaCertPath, "sign", "-version", "2", "-ca-key", caKeyPath, "-ca-crt", state.NebulaCACertPath, "-name", name, "-networks", address, "-groups", "lighthouse,meshlan", "-duration", "78840h", "-in-pub", publicPath, "-out-crt", certificatePath); err != nil {
		return "", "", err
	}
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		return "", "", err
	}
	ca, err := os.ReadFile(state.NebulaCACertPath)
	return string(certificate), string(ca), err
}

func addMeshNode(state *ServerState, statePath, endpoint, name, code string) (MeshNodeRecord, error) {
	payload, err := parseNodePairingCode(code)
	if err != nil {
		return MeshNodeRecord{}, err
	}
	endpoint = strings.Trim(strings.TrimSpace(endpoint), "[]")
	if host, _, splitErr := net.SplitHostPort(endpoint); splitErr == nil {
		endpoint = strings.Trim(host, "[]")
	}
	if net.ParseIP(endpoint) == nil && !validName(endpoint) {
		return MeshNodeRecord{}, errors.New("子节点 IP 或主机名无效")
	}
	if name == "" {
		name = "node-" + payload.ID[:min(8, len(payload.ID))]
	}
	if !validName(name) {
		return MeshNodeRecord{}, errors.New("子节点名称只能使用字母、数字、点、横线或下划线")
	}
	for _, node := range state.MeshNodes {
		if node.ID == payload.ID || strings.EqualFold(node.Name, name) || strings.EqualFold(node.ControlEndpoint, pairingAddress(endpoint, payload.Port)) {
			return MeshNodeRecord{}, errors.New("子节点已存在或名称冲突")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var info meshNodeInfo
	if err := meshNodeRequest(ctx, endpoint, payload, http.MethodGet, "/v1/node/info", nil, &info); err != nil {
		return MeshNodeRecord{}, err
	}
	if info.ID != payload.ID || info.Enrolled {
		return MeshNodeRecord{}, errors.New("子节点身份不匹配或已经加入其他主控")
	}
	address, err := allocateAddress(*state)
	if err != nil {
		return MeshNodeRecord{}, err
	}
	certificate, ca, err := signMeshNodeCertificate(*state, statePath, name, address, info.PublicKey)
	if err != nil {
		return MeshNodeRecord{}, err
	}
	revocations, err := signedRevocationEnvelope(*state)
	if err != nil {
		return MeshNodeRecord{}, err
	}
	request := meshNodeEnrollRequest{ID: payload.ID, Name: name, Address: address, CertificatePEM: certificate, CACertificatePEM: ca, RevocationPublicKey: state.RevocationPublicKey, Revocations: revocations}
	if err := meshNodeRequest(ctx, endpoint, payload, http.MethodPost, "/v1/node/enroll", request, nil); err != nil {
		return MeshNodeRecord{}, err
	}
	publicEndpoint := net.JoinHostPort(endpoint, strconv.Itoa(info.NebulaPort))
	record := MeshNodeRecord{ID: payload.ID, Name: name, Address: address, PublicEndpoint: publicEndpoint, ControlEndpoint: pairingAddress(endpoint, payload.Port), ControlPin: payload.Pin, CreatedAt: time.Now().UTC(), LastSeen: time.Now().UTC(), Online: true, NebulaRunning: true}
	state.MeshNodes = append(state.MeshNodes, record)
	return record, nil
}

func parseNodeAddress(address string) bool {
	prefix, err := netip.ParsePrefix(address)
	return err == nil && prefix.Addr().Is4()
}

func nodeSecretMatches(state MeshNodeAgentState, authorization string) bool {
	prefix := "MeshLAN-Node " + state.ID + ":"
	if !strings.HasPrefix(authorization, prefix) {
		return false
	}
	actual := tokenDigest(strings.TrimPrefix(authorization, prefix))
	return subtle.ConstantTimeCompare([]byte(actual), []byte(state.SecretHash)) == 1
}

func probeMeshNode(node MeshNodeRecord) (meshNodeHealth, error) {
	tlsConfig, err := pinnedTLSConfig(node.ControlPin)
	if err != nil {
		return meshNodeHealth{}, err
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 6 * time.Second}
	response, err := client.Get("https://" + node.ControlEndpoint + "/v1/node/health")
	if err != nil {
		return meshNodeHealth{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return meshNodeHealth{}, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	var health meshNodeHealth
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&health) != nil || health.ID != node.ID {
		return meshNodeHealth{}, errors.New("子节点健康响应无效")
	}
	return health, nil
}

func syncMeshNodeRevocations(node MeshNodeRecord, envelope SignedRevocationEnvelope) error {
	tlsConfig, err := pinnedTLSConfig(node.ControlPin)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(envelope)
	request, _ := http.NewRequest(http.MethodPost, "https://"+node.ControlEndpoint+"/v1/node/revocations", bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation sync HTTP %d", response.StatusCode)
	}
	return nil
}

func refreshMeshNodeHealth(state *ServerState, mu *sync.Mutex, statePath string) {
	mu.Lock()
	nodes := append([]MeshNodeRecord(nil), state.MeshNodes...)
	revocations, revocationErr := signedRevocationEnvelope(*state)
	mu.Unlock()
	for _, node := range nodes {
		health, err := probeMeshNode(node)
		if err == nil && revocationErr == nil {
			err = syncMeshNodeRevocations(node, revocations)
		}
		mu.Lock()
		for index := range state.MeshNodes {
			if state.MeshNodes[index].ID != node.ID {
				continue
			}
			if err == nil {
				state.MeshNodes[index].ConsecutiveFailures = 0
				state.MeshNodes[index].Online = true
				state.MeshNodes[index].NebulaRunning = health.NebulaRunning
				state.MeshNodes[index].RelayReady = health.RelayEnabled && health.NebulaRunning
				state.MeshNodes[index].LastSeen = time.Now().UTC()
				state.MeshNodes[index].LastError = ""
			} else {
				state.MeshNodes[index].ConsecutiveFailures++
				if state.MeshNodes[index].ConsecutiveFailures >= 3 {
					state.MeshNodes[index].Online = false
					state.MeshNodes[index].NebulaRunning = false
					state.MeshNodes[index].RelayReady = false
				}
				state.MeshNodes[index].LastError = err.Error()
			}
			break
		}
		_ = saveJSON(statePath, *state)
		mu.Unlock()
	}
}

func servePublishedArtifact(w http.ResponseWriter, r *http.Request, manifest *UpdateManifestPayload, path, fileName string) {
	if manifest == nil || path == "" {
		http.Error(w, "artifact not published", http.StatusNotFound)
		return
	}
	hash, size, err := fileSHA256(path)
	if err != nil || hash != manifest.SHA256 || size != manifest.Size {
		http.Error(w, "artifact integrity check failed", http.StatusServiceUnavailable)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		http.Error(w, "artifact unavailable", http.StatusNotFound)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
	w.Header().Set("X-Content-SHA256", manifest.SHA256)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, fileName, info.ModTime(), file)
}
