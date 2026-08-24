package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMeshHTTPSCAIssuesOnlyOwnedMeshNames(t *testing.T) {
	state := ServerState{NetworkName: "TestMesh"}
	if err := ensureMeshHTTPSCA(&state); err != nil {
		t.Fatal(err)
	}
	if state.HTTPSCAFingerprint == "" || strings.Contains(state.HTTPSCAPrivateKeyPEM, "RSA PRIVATE") {
		t.Fatalf("unexpected HTTPS CA state: %#v", state)
	}
	peer := PeerRecord{Name: "owner", DNSPrefix: "alice", Address: "10.77.0.2/24"}
	makeCSR := func(names []string) string {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw}))
	}
	response, err := issueMeshHTTPSCertificate(state, peer, makeCSR([]string{"chat.alice.mesh", "alice.mesh"}))
	if err != nil || response.CAFingerprint != state.HTTPSCAFingerprint || response.NotAfter.Sub(time.Now()) < 29*24*time.Hour {
		t.Fatalf("valid HTTPS CSR failed: response=%#v err=%v", response, err)
	}
	if _, err := issueMeshHTTPSCertificate(state, peer, makeCSR([]string{"example.com"})); err == nil {
		t.Fatal("public DNS name was signed by MeshLAN HTTPS CA")
	}
	if _, err := issueMeshHTTPSCertificate(state, peer, makeCSR([]string{"*.alice.mesh"})); err == nil {
		t.Fatal("wildcard DNS name was signed by MeshLAN HTTPS CA")
	}
}

func TestMeshHTTPSCAPrivateKeyIsEncryptedInServerState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "server-state.json")
	state := ServerState{NetworkName: "TestMesh"}
	if err := ensureMeshHTTPSCA(&state); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) || bytes.Contains(raw, []byte("httpsCaPrivateKeyPem")) {
		t.Fatal("HTTPS CA private key was written in plaintext server state")
	}
	var restored ServerState
	if err := loadJSON(statePath, &restored); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseMeshHTTPSCA(restored); err != nil {
		t.Fatalf("encrypted HTTPS CA could not be restored: %v", err)
	}
}

func TestPublishUpdateStoresClientAndSetupArtifacts(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "server-state.json")
	clientPath := filepath.Join(root, "client.exe")
	setupPath := filepath.Join(root, "setup.exe")
	if err := saveJSON(statePath, ServerState{Version: protocolVersion}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, []byte("client-artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(setupPath, []byte("setup-artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serverPublishUpdate([]string{"-state", statePath, "-file", clientPath, "-installer", setupPath, "-version", "9.8.7"}); err != nil {
		t.Fatal(err)
	}
	var state ServerState
	if err := loadJSON(statePath, &state); err != nil {
		t.Fatal(err)
	}
	if state.WindowsUpdate == nil || state.WindowsUpdate.Version != "9.8.7" || state.WindowsInstaller == nil || state.WindowsInstaller.Version != "9.8.7" || state.WindowsInstaller.DownloadPath != "/download/windows" {
		t.Fatalf("published artifacts missing: %#v", state)
	}
	if data, err := os.ReadFile(state.WindowsInstallerPath); err != nil || string(data) != "setup-artifact" {
		t.Fatalf("setup artifact was not copied: %q err=%v", data, err)
	}
}

func TestPairingCodeStoresOnlyDigest(t *testing.T) {
	state := ServerState{Version: protocolVersion, PublicEndpoint: "203.0.113.10:4242", PairingPort: 4243}
	code, err := issuePairingCode(&state)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parsePairingCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if findEnrollment(&state, payload.ID, payload.Secret) == nil {
		t.Fatal("valid pairing secret rejected")
	}
	if payload.Secret == state.Enrollments[0].SecretHash {
		t.Fatal("server stored bearer secret instead of digest")
	}
	if payload.Pin != state.TLSCertificatePin {
		t.Fatal("TLS certificate pin missing")
	}
}

func TestAuthorizedDevicePeer(t *testing.T) {
	state := ServerState{Peers: []PeerRecord{{Name: "peer-a", DeviceTokenHash: tokenDigest("device-secret")}}}
	request := httptest.NewRequest("GET", "/v1/peers", nil)
	request.Header.Set("Authorization", "MeshLAN-Device peer-a:device-secret")
	if peer := authorizedDevicePeer(&state, request); peer == nil || peer.Name != "peer-a" {
		t.Fatal("valid device token was rejected")
	}
	request.Header.Set("Authorization", "MeshLAN-Device peer-a:wrong-secret")
	if peer := authorizedDevicePeer(&state, request); peer != nil {
		t.Fatal("invalid device token was accepted")
	}
}

func TestValidServiceName(t *testing.T) {
	for _, value := range []string{"本地开发网站", "api-service", "团队 文件服务"} {
		if !validServiceName(value) {
			t.Fatalf("valid service name rejected: %q", value)
		}
	}
	for _, value := range []string{"", "bad<name", "bad\nname"} {
		if validServiceName(value) {
			t.Fatalf("invalid service name accepted: %q", value)
		}
	}
}

func TestViewerAccessStatus(t *testing.T) {
	service := PublishedServiceMapping{ID: "mapping-a", OwnerName: "owner", ApprovalRequired: true}
	state := ServerState{AccessRequests: []ServiceAccessRequest{{OwnerName: "owner", MappingID: "mapping-a", RequesterName: "peer", Status: "approved"}}}
	if got := viewerAccessStatus(&state, service, "peer"); got != "approved" {
		t.Fatalf("status=%q", got)
	}
	if got := viewerAccessStatus(&state, service, "new-peer"); got != "not_requested" {
		t.Fatalf("new status=%q", got)
	}
	service.Paused = true
	if got := viewerAccessStatus(&state, service, "new-peer"); got != "service_paused" {
		t.Fatalf("paused status=%q", got)
	}
}

func TestBuildDeviceControlOnlyReturnsOwnerPolicies(t *testing.T) {
	state := ServerState{Peers: []PeerRecord{
		{Name: "owner", Address: "10.77.0.2/24", ServiceMappings: []PublishedServiceMapping{{ID: "mapping-a", ApprovalRequired: true}}},
		{Name: "peer", Address: "10.77.0.3/24"},
	}}
	control := buildDeviceControl(&state, "owner", time.Now())
	if len(control.Policies) != 1 || len(control.Policies[0].Users) != 1 || control.Policies[0].Users[0].Status != "not_requested" {
		t.Fatalf("unexpected control: %#v", control)
	}
}

func TestAccessControlApprovalFlow(t *testing.T) {
	state := ServerState{Peers: []PeerRecord{
		{Name: "owner", Address: "10.77.0.2/24", DeviceTokenHash: tokenDigest("owner-token"), ServiceMappings: []PublishedServiceMapping{{ID: "mapping-a", ServiceName: "Game", ApprovalRequired: true}}},
		{Name: "peer", Address: "10.77.0.3/24", DeviceTokenHash: tokenDigest("peer-token")},
	}}
	statePath := filepath.Join(t.TempDir(), "state.json")
	mux := http.NewServeMux()
	var stateMu sync.Mutex
	registerAccessControlRoutes(mux, &state, &stateMu, statePath)

	requestBody, _ := json.Marshal(map[string]any{"ownerName": "owner", "mappingId": "mapping-a"})
	request := httptest.NewRequest(http.MethodPost, "/v1/access/request", bytes.NewReader(requestBody))
	request.Header.Set("Authorization", "MeshLAN-Device peer:peer-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(state.AccessRequests) != 1 || state.AccessRequests[0].Status != "pending" {
		t.Fatalf("request failed: code=%d state=%#v body=%s", response.Code, state.AccessRequests, response.Body.String())
	}

	respondBody, _ := json.Marshal(map[string]any{"requestId": state.AccessRequests[0].ID, "approve": true})
	request = httptest.NewRequest(http.MethodPost, "/v1/access/respond", bytes.NewReader(respondBody))
	request.Header.Set("Authorization", "MeshLAN-Device owner:owner-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || state.AccessRequests[0].Status != "approved" {
		t.Fatalf("approval failed: code=%d state=%#v body=%s", response.Code, state.AccessRequests, response.Body.String())
	}

	pauseBody, _ := json.Marshal(map[string]any{"mappingId": "mapping-a", "userName": "peer", "paused": true})
	request = httptest.NewRequest(http.MethodPost, "/v1/access/user", bytes.NewReader(pauseBody))
	request.Header.Set("Authorization", "MeshLAN-Device owner:owner-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || state.AccessRequests[0].Status != "paused" {
		t.Fatalf("pause failed: code=%d state=%#v body=%s", response.Code, state.AccessRequests, response.Body.String())
	}
}

func TestAddressAllocation(t *testing.T) {
	state := ServerState{Subnet: "10.77.0.0/24", LighthouseAddress: "10.77.0.1/24", Peers: []PeerRecord{{Address: "10.77.0.2/24"}}}
	address, err := allocateAddress(state)
	if err != nil || address != "10.77.0.3/24" {
		t.Fatalf("address=%s err=%v", address, err)
	}
}

func TestClientConfigUsesP2PAndRelay(t *testing.T) {
	state := ClientState{
		PrivateKeyPath: "C:/MeshLAN/host.key", CertificatePath: "C:/MeshLAN/host.crt", CACertificatePath: "C:/MeshLAN/ca.crt",
		Pairing: &PairResponse{Address: "10.77.0.2/24", LighthouseAddress: "10.77.0.1/24", LighthouseEndpoint: "203.0.113.10:4242", RelayAddress: "10.77.0.1/24"},
	}
	config, err := renderClientConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"am_lighthouse: false", "interval: 10", "host: \"::\"", "port: 42002", "windows_bypass_wdf: true", "punch: true", "respond: true", "respond_delay: 5s", "am_relay: false", "use_relays: false", "203.0.113.10:4242"} {
		if !strings.Contains(config, expected) {
			t.Fatalf("missing %q in config", expected)
		}
	}
	if strings.Contains(config, "\"10.77.0.1/24\":") || strings.Contains(config, "- \"10.77.0.1/24\"") {
		t.Fatal("Nebula discovery fields must use a bare IP without CIDR suffix")
	}
	if strings.Contains(config, "port: 0") {
		t.Fatal("P2P optimized client config must keep a stable UDP listener port")
	}
	state.ForceP2P = false
	state.P2PModeVersion = p2pModeVersion
	fallbackConfig, err := renderClientConfig(state)
	if err != nil || !strings.Contains(fallbackConfig, "use_relays: true") {
		t.Fatalf("explicit Relay fallback config was not rendered: %v", err)
	}
}

func TestSignedRevocationEnvelopeRejectsTampering(t *testing.T) {
	state := ServerState{}
	if err := ensureServerSecurityIdentity(&state); err != nil {
		t.Fatal(err)
	}
	if state.RevocationPublicKey == "" || state.UpdatePublicKey == "" || state.RevocationPublicKey == state.UpdatePublicKey || state.CryptoKeyVersion != 2 {
		t.Fatalf("signing keys were not split: %#v", state)
	}
	fingerprint := strings.Repeat("ab", 32)
	if !addCertificateRevocation(&state, "peer-a", fingerprint, "device_removed") {
		t.Fatal("valid revocation was not added")
	}
	envelope, err := signedRevocationEnvelope(state)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := verifyRevocationEnvelope(envelope, state.RevocationPublicKey)
	if err != nil || payload.Version != 1 || len(payload.Revocations) != 1 || payload.UpdatePublicKey != state.UpdatePublicKey || payload.UpdateKeyActive {
		t.Fatalf("signed payload was not verified: payload=%#v err=%v", payload, err)
	}
	envelope.Payload += "A"
	if _, err := verifyRevocationEnvelope(envelope, state.RevocationPublicKey); err == nil {
		t.Fatal("tampered revocation payload was accepted")
	}
}

func TestServerStateEncryptsPrivateKeysAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-state.json")
	state := ServerState{
		TLSPrivateKeyPEM: "tls-private-secret", SecurityPrivateKey: "legacy-private-secret",
		RevocationPrivateKey: "revocation-private-secret", UpdatePrivateKey: "update-private-secret",
		AdminTOTPEnabled: true, AdminTOTPSecret: "totp-private-secret",
	}
	if err := saveJSON(path, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"tls-private-secret", "legacy-private-secret", "revocation-private-secret", "update-private-secret", "totp-private-secret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("server secret remained plaintext on disk: %s", secret)
		}
	}
	if !strings.Contains(string(raw), "encryptedServerSecrets") {
		t.Fatalf("encrypted server envelope missing: %s", raw)
	}
	keyInfo, err := os.Stat(path + ".master.key")
	if err != nil || keyInfo.Size() != 32 {
		t.Fatalf("server master key missing or invalid: info=%v err=%v", keyInfo, err)
	}
	var restored ServerState
	if err := loadJSON(path, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.TLSPrivateKeyPEM != state.TLSPrivateKeyPEM || restored.SecurityPrivateKey != state.SecurityPrivateKey || restored.RevocationPrivateKey != state.RevocationPrivateKey || restored.UpdatePrivateKey != state.UpdatePrivateKey || restored.AdminTOTPSecret != state.AdminTOTPSecret {
		t.Fatalf("server secret round trip failed: %#v", restored)
	}
}

func TestTOTPAndAdminSessionLifecycle(t *testing.T) {
	const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(59, 0)
	code, err := totpCode(rfcSecret, now)
	if err != nil || code != "287082" {
		t.Fatalf("unexpected RFC6238 code: code=%s err=%v", code, err)
	}
	if !verifyTOTPCode(rfcSecret, code, now) || verifyTOTPCode(rfcSecret, "000000", now) {
		t.Fatal("TOTP verification did not enforce the expected code")
	}
	sessions := newAdminSessionStore()
	token, expiresAt, err := sessions.issue(now)
	if err != nil || token == "" || !expiresAt.Equal(now.Add(adminSessionLifetime)) || !sessions.verify(token, now) {
		t.Fatalf("session issue failed: token=%q expiry=%v err=%v", token, expiresAt, err)
	}
	sessions.revoke(token)
	if sessions.verify(token, now) {
		t.Fatal("revoked admin session remained valid")
	}
	token, _, _ = sessions.issue(now)
	if sessions.verify(token, now.Add(adminSessionLifetime+time.Second)) {
		t.Fatal("expired admin session remained valid")
	}
	token, _, _ = sessions.issue(now)
	sessions.setPendingTOTP(token, rfcSecret)
	if sessions.pendingTOTPSecret(token) != rfcSecret {
		t.Fatal("pending TOTP secret was not bound to the admin session")
	}
	sessions.clearPendingTOTP(token)
	if sessions.pendingTOTPSecret(token) != "" {
		t.Fatal("pending TOTP secret was not cleared")
	}
}

func TestServerStateRejectsTamperedCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-state.json")
	if err := saveJSON(path, ServerState{TLSPrivateKeyPEM: "tls-private-secret"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var disk ServerState
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if len(disk.EncryptedServerSecrets) < 4 {
		t.Fatal("encrypted server envelope missing")
	}
	last := disk.EncryptedServerSecrets[len(disk.EncryptedServerSecrets)-1]
	if last == 'A' {
		last = 'B'
	} else {
		last = 'A'
	}
	disk.EncryptedServerSecrets = disk.EncryptedServerSecrets[:len(disk.EncryptedServerSecrets)-1] + string(last)
	tampered, _ := json.MarshalIndent(disk, "", "  ")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	var restored ServerState
	if err := loadJSON(path, &restored); err == nil {
		t.Fatal("tampered server ciphertext was accepted")
	}
}

func TestNebulaCAKeyIsEncryptedAndMaterializedTemporarily(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "server-state.json")
	caPath := filepath.Join(root, "ca.key")
	if err := os.WriteFile(caPath, []byte("nebula-ca-private-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := ServerState{NebulaCAKeyPath: caPath, TLSPrivateKeyPEM: "tls-private-secret"}
	if !migrateServerStateSecrets(statePath, &state) || state.NebulaCAKeyPEM != "nebula-ca-private-secret" || !state.NebulaCAKeyEncrypted {
		t.Fatalf("CA migration was not prepared: %#v", state)
	}
	if err := saveJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(caPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext CA key still exists: %v", err)
	}
	raw, _ := os.ReadFile(statePath)
	if strings.Contains(string(raw), "nebula-ca-private-secret") {
		t.Fatal("CA key remained plaintext in server state")
	}
	var restored ServerState
	if err := loadJSON(statePath, &restored); err != nil {
		t.Fatal(err)
	}
	materialized, cleanup, err := materializeNebulaCAKey(restored, root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(materialized)
	if err != nil || string(data) != "nebula-ca-private-secret" {
		t.Fatalf("temporary CA key was not restored: %q err=%v", data, err)
	}
	cleanup()
	if _, err := os.Stat(materialized); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary CA key was not deleted: %v", err)
	}
}

func TestServerMasterKeyRotationAndRecovery(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "server-state.json")
	state := ServerState{TLSPrivateKeyPEM: "tls-private-secret", NebulaCAKeyPEM: "nebula-ca-private-secret", NebulaCAKeyEncrypted: true}
	if err := ensureServerSecurityIdentity(&state); err != nil {
		t.Fatal(err)
	}
	state.SecretStorageVersion = serverSecretStorageVersion
	if err := saveJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	oldKey, err := os.ReadFile(serverMasterKeyPath(statePath))
	if err != nil {
		t.Fatal(err)
	}
	if err := rotateServerMasterKey(statePath); err != nil {
		t.Fatal(err)
	}
	newKey, err := os.ReadFile(serverMasterKeyPath(statePath))
	if err != nil || bytes.Equal(oldKey, newKey) {
		t.Fatalf("master key was not rotated: err=%v", err)
	}
	if err := verifyServerCryptoState(statePath); err != nil {
		t.Fatalf("rotated state failed verification: %v", err)
	}
	if _, err := os.Stat(serverMasterKeyBackupPath(statePath)); err != nil {
		t.Fatal("previous master key backup missing")
	}
	if _, err := os.Stat(serverStateBackupPath(statePath)); err != nil {
		t.Fatal("matching state backup missing")
	}
	if err := restorePreviousServerMasterKey(statePath); err != nil {
		t.Fatal(err)
	}
	restoredKey, _ := os.ReadFile(serverMasterKeyPath(statePath))
	if !bytes.Equal(oldKey, restoredKey) {
		t.Fatal("previous master key was not restored")
	}
	if err := verifyServerCryptoState(statePath); err != nil {
		t.Fatalf("restored state failed verification: %v", err)
	}
}

func TestUpdateKeyActivationRequiresCompatibleClients(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "server-state.json")
	state := ServerState{
		TLSPrivateKeyPEM: "tls-private-secret", NebulaCAKeyPEM: "nebula-ca-private-secret", NebulaCAKeyEncrypted: true,
		Peers: []PeerRecord{{Name: "legacy", ClientVersion: "meshlan-nebula/1.6.0"}, {Name: "modern", ClientVersion: "meshlan-nebula/1.10.5"}},
	}
	if err := ensureServerSecurityIdentity(&state); err != nil {
		t.Fatal(err)
	}
	state.SecretStorageVersion = serverSecretStorageVersion
	if err := saveJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := activateIndependentUpdateKey(statePath, "1.10.1"); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy client did not block update key activation: %v", err)
	}
	var latest ServerState
	if err := loadJSON(statePath, &latest); err != nil {
		t.Fatal(err)
	}
	latest.Peers[0].ClientVersion = "meshlan-nebula/1.10.5"
	if err := saveJSON(statePath, latest); err != nil {
		t.Fatal(err)
	}
	if err := activateIndependentUpdateKey(statePath, "1.10.1"); err != nil {
		t.Fatal(err)
	}
	if err := loadJSON(statePath, &latest); err != nil || !latest.UpdateKeyActive {
		t.Fatalf("update key was not activated: state=%#v err=%v", latest, err)
	}
	if err := deactivateIndependentUpdateKey(statePath); err != nil {
		t.Fatal(err)
	}
	if err := loadJSON(statePath, &latest); err != nil || latest.UpdateKeyActive {
		t.Fatalf("update key was not deactivated: state=%#v err=%v", latest, err)
	}
}

func TestIndependentUpdateKeyAutoActivatesAfterVersionHeartbeats(t *testing.T) {
	state := ServerState{Peers: []PeerRecord{{Name: "a", ClientVersion: "meshlan-nebula/1.10.30"}, {Name: "b", ClientVersion: "meshlan-nebula/1.9.0"}}}
	if err := ensureServerSecurityIdentity(&state); err != nil {
		t.Fatal(err)
	}
	activated, err := autoActivateIndependentUpdateKey(&state, "1.10.1")
	if err != nil || activated || state.UpdateKeyActive {
		t.Fatalf("legacy heartbeat incorrectly activated key: activated=%v state=%#v err=%v", activated, state, err)
	}
	state.Peers[1].ClientVersion = "meshlan-nebula/1.10.29"
	activated, err = autoActivateIndependentUpdateKey(&state, "1.10.1")
	if err != nil || !activated || !state.UpdateKeyActive {
		t.Fatalf("modern heartbeats did not activate key: activated=%v state=%#v err=%v", activated, state, err)
	}
}

func TestP2PUpdateSeedSelectionRequiresExactSignedPackage(t *testing.T) {
	now := time.Now().UTC()
	manifest := UpdateManifestPayload{Version: "1.11.7", SHA256: strings.Repeat("a", 64)}
	state := ServerState{Peers: []PeerRecord{
		{Name: "requester", ClientVersion: "meshlan-nebula/1.10.29", LastSeen: now, ServiceRunning: true},
		{Name: "wrong", ClientVersion: "meshlan-nebula/1.11.7", LastSeen: now, ServiceRunning: true, UpdateSeedReady: true, UpdateSeedSHA256: strings.Repeat("b", 64), UpdateSeedPort: updateSeedPort},
		{Name: "seed", Address: "10.77.0.2/24", ClientVersion: "meshlan-nebula/1.11.7", LastSeen: now, ServiceRunning: true, UpdateSeedReady: true, UpdateSeedSHA256: manifest.SHA256, UpdateSeedPort: updateSeedPort},
	}}
	seed := selectP2PUpdateSeed(state, "requester", manifest, now)
	if seed == nil || seed.Name != "seed" {
		t.Fatalf("valid P2P seed not selected: %#v", seed)
	}
}

func TestLegacyServerBackupsAreEncryptedInPlace(t *testing.T) {
	root := t.TempDir()
	masterPath := filepath.Join(root, "shared-master.key")
	t.Setenv("MESHLAN_MASTER_KEY_FILE", masterPath)
	currentPath := filepath.Join(root, "server-state.json")
	state := ServerState{TLSPrivateKeyPEM: "current-tls-secret", NebulaCAKeyPEM: "current-ca-secret", NebulaCAKeyEncrypted: true}
	if err := ensureServerSecurityIdentity(&state); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(currentPath, state); err != nil {
		t.Fatal(err)
	}
	legacyPaths := []string{
		filepath.Join(root, "server-state.json.pre-upgrade"),
		filepath.Join(root, "backups", "server-state-pre-old.json"),
	}
	for _, path := range legacyPaths {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		legacy := ServerState{TLSPrivateKeyPEM: "legacy-tls-secret", SecurityPrivateKey: state.SecurityPrivateKey, SecurityPublicKey: state.SecurityPublicKey}
		data, _ := json.MarshalIndent(legacy, "", "  ")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	count, err := encryptServerStateBackups(root, currentPath)
	if err != nil || count != len(legacyPaths) {
		t.Fatalf("legacy backup encryption failed: count=%d err=%v", count, err)
	}
	remaining, err := plaintextServerStateBackups(root)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("plaintext backup scan still found files: %v err=%v", remaining, err)
	}
	for _, path := range legacyPaths {
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), "legacy-tls-secret") || !strings.Contains(string(raw), "encryptedServerSecrets") {
			t.Fatalf("legacy backup not encrypted: %s", raw)
		}
		var restored ServerState
		if err := loadJSON(path, &restored); err != nil || restored.TLSPrivateKeyPEM != "legacy-tls-secret" {
			t.Fatalf("encrypted backup did not restore: state=%#v err=%v", restored, err)
		}
	}
}

func TestCertificateFingerprintPatternSupportsV2JSON(t *testing.T) {
	value := strings.Repeat("ef", 32)
	match := certificateFingerprintPattern.FindStringSubmatch(`{"fingerprint": "` + value + `",`)
	if len(match) != 2 || match[1] != value {
		t.Fatalf("fingerprint not parsed: %#v", match)
	}
}

func TestNebulaConfigsContainCertificateBlocklist(t *testing.T) {
	fingerprint := strings.Repeat("cd", 32)
	state := ClientState{
		PrivateKeyPath: "C:/MeshLAN/host.key", CertificatePath: "C:/MeshLAN/host.crt", CACertificatePath: "C:/MeshLAN/ca.crt",
		Pairing:             &PairResponse{Address: "10.77.0.2/24", LighthouseAddress: "10.77.0.1/24", LighthouseEndpoint: "203.0.113.10:8080", RelayAddress: "10.77.0.1/24"},
		RevokedFingerprints: []string{fingerprint},
	}
	clientConfig, err := renderClientConfig(state)
	if err != nil || !strings.Contains(clientConfig, "disconnect_invalid: true") || !strings.Contains(clientConfig, fingerprint) {
		t.Fatalf("client blocklist missing: %v\n%s", err, clientConfig)
	}
	lighthouseConfig := renderLighthouseConfig("ca.crt", "host.crt", "host.key", 8080, []string{fingerprint})
	if !strings.Contains(lighthouseConfig, "disconnect_invalid: true") || !strings.Contains(lighthouseConfig, fingerprint) {
		t.Fatalf("lighthouse blocklist missing:\n%s", lighthouseConfig)
	}
}

func TestRekeyEnrollmentPreservesNameAndAddress(t *testing.T) {
	state := ServerState{PublicEndpoint: "server.example:8080", PairingPort: 8080}
	peer := PeerRecord{Name: "peer-a", Address: "10.77.0.8/24"}
	code, err := issueRekeyCode(&state, peer, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parsePairingCode(code)
	if err != nil {
		t.Fatal(err)
	}
	record := findEnrollment(&state, payload.ID, payload.Secret)
	if record == nil || !record.Rekey || record.BoundName != peer.Name || record.ReservedAddress != peer.Address || record.BoundPublicKey != "" {
		t.Fatalf("unexpected rekey enrollment: %#v", record)
	}
}

func TestSignedUpdateManifestAndVersionComparison(t *testing.T) {
	state := ServerState{}
	if err := ensureServerSecurityIdentity(&state); err != nil {
		t.Fatal(err)
	}
	payload := UpdateManifestPayload{
		Version: "1.8.1", Platform: "windows-amd64", SHA256: strings.Repeat("12", 32), Size: 12345,
		PublishedAt: time.Now(), DownloadPath: "/v1/update/package/windows-amd64",
	}
	manifest, err := signedUpdateManifest(state, payload)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyUpdateManifest(manifest, state.SecurityPublicKey)
	if err != nil || verified.Version != payload.Version {
		t.Fatalf("update manifest verification failed: %#v %v", verified, err)
	}
	manifest.Signature = strings.Repeat("A", len(manifest.Signature))
	if _, err := verifyUpdateManifest(manifest, state.SecurityPublicKey); err == nil {
		t.Fatal("tampered update manifest was accepted")
	}
	state.UpdateKeyActive = true
	manifest, err = signedUpdateManifest(state, payload)
	if err != nil || manifest.PublicKey != state.UpdatePublicKey {
		t.Fatalf("activated update key was not used: manifest=%#v err=%v", manifest, err)
	}
	if _, err := verifyUpdateManifest(manifest, state.UpdatePublicKey); err != nil {
		t.Fatalf("new update key did not verify: %v", err)
	}
	if _, err := verifyUpdateManifest(manifest, state.SecurityPublicKey); err == nil {
		t.Fatal("legacy update key accepted a manifest signed by the new key")
	}
	for _, test := range []struct {
		left, right string
		want        int
	}{{"1.8.0", "1.8.1", -1}, {"2.0.0", "1.9.9", 1}, {"1.8.0", "1.8.0", 0}, {"1.8.0-beta.1", "1.8.0", -1}} {
		got := compareSemanticVersions(test.left, test.right)
		if (got < 0 && test.want >= 0) || (got > 0 && test.want <= 0) || (got == 0 && test.want != 0) {
			t.Fatalf("compare %s %s = %d, want %d", test.left, test.right, got, test.want)
		}
	}
}

func TestSQLiteHistoryPersistsTopologyTrafficAndConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.sqlite")
	store, err := openHistoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := store.RecordLocal(HistoryLocalPoint{At: now, BytesReceived: 1200, BytesSent: 800, ServiceRunning: true, DirectCount: 1}); err != nil {
		t.Fatal(err)
	}
	snapshot := TopologySnapshot{RefreshedAt: now, Peers: []TopologyPeerNode{{Name: "peer-a", Address: "10.77.0.3/24", Online: true, Reachable: true, PathMode: "p2p", LatencyMs: 22, ServiceCount: 1, HealthyServiceCount: 1}}}
	if err := store.RecordTopology(snapshot); err != nil {
		t.Fatal(err)
	}
	connection := ServiceConnectionRecord{MappingID: "mapping-a", ServiceName: "API", UserName: "peer-a", Address: "10.77.0.3", Protocol: "tcp", Allowed: true, Active: 9, FirstSeen: now, LastSeen: now, BytesToLocal: 400, BytesToPeer: 200}
	if err := store.RecordConnection(connection); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordEvent("client", "path_changed", "peer-a", "relay → p2p", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = openHistoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	history, err := store.ClientHistory(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Local) != 1 || history.Local[0].BytesReceived != 1200 || len(history.Peers) != 1 || history.Peers[0].PathMode != "p2p" || len(history.Connections) != 1 || history.Connections[0].BytesToLocal != 400 || len(history.Events) != 1 {
		t.Fatalf("history did not persist: %#v", history)
	}
	if history.Connections[0].Active != 0 {
		t.Fatalf("process-local active connection count survived history reopen: %#v", history.Connections[0])
	}
}

func TestHistorySampleStrideCapsSeriesWithoutDroppingCoverage(t *testing.T) {
	for _, test := range []struct {
		count, maximum, want int
	}{{100, 4000, 1}, {4000, 4000, 1}, {4001, 4000, 2}, {12000, 4000, 3}} {
		if got := historySampleStride(test.count, test.maximum); got != test.want {
			t.Fatalf("historySampleStride(%d,%d)=%d want %d", test.count, test.maximum, got, test.want)
		}
	}
}

func TestAIConversationHistoryPersistsAndBuildsContext(t *testing.T) {
	store, err := openHistoryStore(filepath.Join(t.TempDir(), "history.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	conversation, err := store.CreateAIConversation("新对话")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AddAIMessage(conversation.ID, "user", "先检查 P2P", nil); err != nil {
		t.Fatal(err)
	}
	plan := AIPlan{ID: "plan-1", Reply: "P2P 正常", Summary: "只读检查", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if _, err = store.AddAIMessage(conversation.ID, "assistant", plan.Reply, &plan); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.AIConversation(conversation.ID)
	if err != nil || len(loaded.Messages) != 2 || loaded.Messages[1].Plan == nil || loaded.Messages[1].Plan.ID != "plan-1" {
		t.Fatalf("conversation did not persist: %#v err=%v", loaded, err)
	}
	turns := aiConversationTurns(loaded)
	if len(turns) != 2 || turns[0].Role != "user" || turns[1].Role != "assistant" || turns[1].Content != "P2P 正常" {
		t.Fatalf("unexpected conversation context: %#v", turns)
	}
	if err = store.RenameAIConversation(conversation.ID, "网络排查"); err != nil {
		t.Fatal(err)
	}
	list, err := store.ListAIConversations()
	if err != nil || len(list) != 1 || list[0].Title != "网络排查" {
		t.Fatalf("conversation rename/list failed: %#v err=%v", list, err)
	}
	if err = store.DeleteAIConversation(conversation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AIConversation(conversation.ID); err == nil {
		t.Fatal("deleted conversation still exists")
	}
}

func TestMeshDNSNamesAreStableAndCollisionSafe(t *testing.T) {
	state := ServerState{Peers: []PeerRecord{
		{Name: "desk_top", Address: "10.77.0.2/24", ServiceMappings: []PublishedServiceMapping{
			{ID: "mapping-one", ServiceName: "Chat GPT", Port: 20000, Protocol: "tcp"},
			{ID: "mapping-two", ServiceName: "Chat-GPT", Port: 20001, Protocol: "tcp"},
			{ID: "mapping-cn", ServiceName: "游戏服务器", Port: 24571, Protocol: "udp"},
		}},
		{Name: "desk-top", Address: "10.77.0.3/24"},
	}}
	records := buildMeshDNSRecords(state)
	seen := map[string]bool{}
	deviceNames := []string{}
	for _, record := range records {
		if seen[record.Name] {
			t.Fatalf("duplicate MeshDNS name: %s", record.Name)
		}
		seen[record.Name] = true
		if !strings.HasSuffix(record.Name, ".mesh") {
			t.Fatalf("record outside mesh suffix: %#v", record)
		}
		if record.Kind == "device" {
			deviceNames = append(deviceNames, record.Name)
		}
	}
	if len(deviceNames) != 2 || deviceNames[0] == deviceNames[1] {
		t.Fatalf("device label collision was not resolved: %#v", deviceNames)
	}
	second := buildMeshDNSRecords(state)
	if len(second) != len(records) {
		t.Fatal("MeshDNS record generation is not stable")
	}
	for i := range records {
		if records[i].Name != second[i].Name {
			t.Fatalf("MeshDNS name changed: %s != %s", records[i].Name, second[i].Name)
		}
	}
}

func TestUserAndServiceDNSPrefixesAreAuthoritativeAndDynamic(t *testing.T) {
	state := ServerState{Peers: []PeerRecord{
		{Name: "owner", DNSPrefix: "alice", Address: "10.77.0.2/24", DeviceTokenHash: tokenDigest("owner-token"), ServiceMappings: []PublishedServiceMapping{{ID: "mapping-chat", ServiceName: "ChatGPT", DNSPrefix: "chat", Port: 20000, Protocol: "tcp", PortlessHTTP: true}}},
		{Name: "peer", DNSPrefix: "bob", Address: "10.77.0.3/24", DeviceTokenHash: tokenDigest("peer-token")},
	}}
	records := buildMeshDNSRecords(state)
	wanted := map[string]MeshDNSRecord{}
	for _, record := range records {
		wanted[record.Name] = record
	}
	if _, ok := wanted["alice.mesh"]; !ok {
		t.Fatalf("owner DNS record missing: %#v", records)
	}
	service, ok := wanted["chat.alice.mesh"]
	if !ok || !service.PortlessHTTP || service.URL != "http://chat.alice.mesh" {
		t.Fatalf("portless service DNS record missing: %#v", service)
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	mux := http.NewServeMux()
	var stateMu sync.Mutex
	registerMeshDNSRoutes(mux, &state, &stateMu, statePath)
	body, _ := json.Marshal(map[string]string{"prefix": "charlie"})
	request := httptest.NewRequest(http.MethodPost, "/v1/dns/prefix", bytes.NewReader(body))
	request.Header.Set("Authorization", "MeshLAN-Device owner:owner-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || state.Peers[0].DNSPrefix != "charlie" {
		t.Fatalf("owner prefix update failed: code=%d body=%s state=%#v", response.Code, response.Body.String(), state.Peers[0])
	}
	records = buildMeshDNSRecords(state)
	if records[0].Name == "alice.mesh" {
		t.Fatal("DNS records did not update after owner prefix change")
	}
	body, _ = json.Marshal(map[string]string{"prefix": "bob"})
	request = httptest.NewRequest(http.MethodPost, "/v1/dns/prefix", bytes.NewReader(body))
	request.Header.Set("Authorization", "MeshLAN-Device owner:owner-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate owner prefix accepted: code=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMeshDNSStateMigrationPreservesMappingsAndAssignsUniquePrefixes(t *testing.T) {
	state := ClientState{Name: "desktop", ServiceMappings: []LocalServiceMapping{
		{ID: "mapping-a", ServiceName: "Chat GPT", Protocol: "tcp"},
		{ID: "mapping-b", ServiceName: "Chat-GPT", Protocol: "tcp"},
		{ID: "mapping-c", ServiceName: "Game", Protocol: "udp", PortlessHTTP: true},
	}}
	if !applyMeshDNSPreferenceDefaults(&state) || state.DNSPrefix != "desktop" || !state.MeshDNSEnabled {
		t.Fatalf("MeshDNS defaults not applied: %#v", state)
	}
	if state.ServiceMappings[0].DNSPrefix == state.ServiceMappings[1].DNSPrefix {
		t.Fatalf("duplicate migrated service prefixes: %#v", state.ServiceMappings)
	}
	if state.ServiceMappings[2].PortlessHTTP {
		t.Fatal("UDP mapping retained invalid HTTP gateway mode")
	}
	copy := state
	if applyMeshDNSPreferenceDefaults(&copy) {
		t.Fatalf("MeshDNS migration is not idempotent: %#v", copy)
	}
}

func TestNebulaCertificateLogWriterBackfillsLegacyPeerFingerprint(t *testing.T) {
	fingerprint := strings.Repeat("ab", 32)
	var name, gotFingerprint string
	writer := &nebulaCertificateLogWriter{onFingerprint: func(value, valueFingerprint string) {
		name, gotFingerprint = value, valueFingerprint
	}}
	line := `time=now level=INFO msg="Handshake message received" vpnAddrs=[10.77.0.3] certName=bob certVersion=2 fingerprint=` + fingerprint + ` issuer=ca` + "\n"
	_, _ = writer.Write([]byte(line[:37]))
	_, _ = writer.Write([]byte(line[37:]))
	if name != "bob" || gotFingerprint != fingerprint {
		t.Fatalf("legacy fingerprint not captured: name=%q fingerprint=%q", name, gotFingerprint)
	}
}

func TestClientListenPortIsStablePerNebulaAddress(t *testing.T) {
	state := ClientState{Pairing: &PairResponse{Address: "10.77.0.23/24"}}
	if got := clientListenPort(state); got != 42023 {
		t.Fatalf("listen port=%d", got)
	}
	state.NebulaListenPort = 42777
	if got := clientListenPort(state); got != 42777 {
		t.Fatalf("stored listen port=%d", got)
	}
}

func TestP2PModeDefaultsToStrictAndPreservesExplicitFallback(t *testing.T) {
	var state ClientState
	if !applyP2PModeDefaults(&state) || !state.ForceP2P || state.P2PModeVersion != p2pModeVersion {
		t.Fatalf("new client was not migrated to strict P2P: %#v", state)
	}
	state.ForceP2P = false
	if applyP2PModeDefaults(&state) || state.ForceP2P {
		t.Fatalf("explicit Relay fallback preference was overwritten: %#v", state)
	}
}

func TestIPModePoliciesAreMutuallyExclusive(t *testing.T) {
	base := ClientState{
		PrivateKeyPath: "C:/MeshLAN/host.key", CertificatePath: "C:/MeshLAN/host.crt", CACertificatePath: "C:/MeshLAN/ca.crt",
		Pairing:        &PairResponse{Address: "10.77.0.2/24", LighthouseAddress: "10.77.0.1/24", LighthouseEndpoint: "203.0.113.10:8080", RelayAddress: "10.77.0.1/24"},
		P2PModeVersion: p2pModeVersion, ForceP2P: true, IPModeVersion: ipModeVersion,
	}
	cases := []struct {
		mode      string
		required  []string
		forbidden []string
	}{
		{mode: "dual", required: []string{`host: "::"`}, forbidden: []string{"remote_allow_list:"}},
		{mode: "ipv4", required: []string{`host: "0.0.0.0"`, `"0.0.0.0/0": true`, `"::/0": false`}},
		{mode: "ipv6", required: []string{`host: "::"`, `"0.0.0.0/0": false`, `"203.0.113.10/32": true`, `"::/0": true`}},
	}
	for _, test := range cases {
		state := base
		state.IPMode = test.mode
		config, err := renderClientConfig(state)
		if err != nil {
			t.Fatalf("mode %s: %v", test.mode, err)
		}
		for _, required := range test.required {
			if !strings.Contains(config, required) {
				t.Fatalf("mode %s missing %q", test.mode, required)
			}
		}
		for _, forbidden := range test.forbidden {
			if strings.Contains(config, forbidden) {
				t.Fatalf("mode %s unexpectedly contains %q", test.mode, forbidden)
			}
		}
	}
	var state ClientState
	if !applyIPModeDefaults(&state) || state.IPMode != "dual" || state.IPModeVersion != ipModeVersion {
		t.Fatalf("default IP mode is not dual: %#v", state)
	}
}

func TestInterfaceRoutingDefaultsAndValidation(t *testing.T) {
	var state ClientState
	if !applyInterfaceRoutingDefaults(&state) || state.PreferredP2PInterface != "auto" || state.PreferredBusinessInterface != "auto" {
		t.Fatalf("unexpected interface defaults: %#v", state)
	}
	for _, value := range []string{"auto", "WLAN", "以太网 13"} {
		if !validInterfacePreference(value) {
			t.Fatalf("valid interface rejected: %q", value)
		}
	}
	if validInterfacePreference("bad\nname") {
		t.Fatal("control character accepted in interface name")
	}
}

func TestRevokedEnrollmentIsDeletedInsteadOfRetained(t *testing.T) {
	state := ServerState{PairingSecretHash: "removed-hash", Enrollments: []EnrollmentRecord{
		{ID: "remove", SecretHash: "removed-hash", Revoked: true},
		{ID: "keep", SecretHash: "keep-hash"},
	}}
	if !purgeRevokedEnrollments(&state) || len(state.Enrollments) != 1 || state.Enrollments[0].ID != "keep" {
		t.Fatalf("revoked enrollment was not purged: %#v", state.Enrollments)
	}
	if state.PairingSecretHash != "" {
		t.Fatal("legacy pairing digest survived enrollment deletion")
	}
	if !removeEnrollment(&state, "keep") || len(state.Enrollments) != 0 {
		t.Fatal("explicit revoke did not delete enrollment")
	}
}

func TestRemovePeerCleansBindingsAndReleasesAddress(t *testing.T) {
	state := ServerState{
		Subnet: "10.77.0.0/24", LighthouseAddress: "10.77.0.1/24",
		Peers:       []PeerRecord{{Name: "owner", Address: "10.77.0.2/24"}, {Name: "keep", Address: "10.77.0.3/24"}, {Name: "remove", Address: "10.77.0.4/24"}},
		Enrollments: []EnrollmentRecord{{ID: "bound", BoundName: "remove"}, {ID: "other", BoundName: "keep"}},
		AccessRequests: []ServiceAccessRequest{
			{ID: "owned", OwnerName: "remove", RequesterName: "keep"},
			{ID: "requested", OwnerName: "keep", RequesterName: "remove"},
			{ID: "preserved", OwnerName: "keep", RequesterName: "third"},
		},
	}
	if !removePeer(&state, "remove") {
		t.Fatal("peer was not removed")
	}
	if len(state.Peers) != 2 || len(state.Enrollments) != 1 || state.Enrollments[0].ID != "other" || len(state.AccessRequests) != 1 || state.AccessRequests[0].ID != "preserved" {
		t.Fatalf("related state was not cleaned: %#v", state)
	}
	address, err := allocateAddress(state)
	if err != nil || address != "10.77.0.4/24" {
		t.Fatalf("lowest free address was not released: address=%s err=%v", address, err)
	}
}

func TestAdminUIHasDestructiveManagementActions(t *testing.T) {
	data, err := adminWeb.ReadFile("admin/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, expected := range []string{"踢出并吊销", "吊销授权哈希", "kickClient", "/v1/admin/peers/delete", "设备名和虚拟 IP 会释放", "body:not(.authenticated) .nav-list", "setAuthenticatedChrome(false)"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("admin UI missing %q", expected)
		}
	}
}

func TestPublicClientStateRedactsSecrets(t *testing.T) {
	state := ClientState{EncryptedDeviceToken: "ciphertext", Pairing: &PairResponse{DeviceToken: "plaintext", ControlPin: "public-pin"}}
	public := publicClientState(state)
	if public.EncryptedDeviceToken != "" || public.Pairing == nil || public.Pairing.DeviceToken != "" || public.Pairing.ControlPin != "public-pin" {
		t.Fatalf("public state was not correctly redacted: %#v", public)
	}
	if state.Pairing.DeviceToken != "plaintext" || state.EncryptedDeviceToken != "ciphertext" {
		t.Fatal("redaction mutated the in-memory state")
	}
}

func TestAdminTokenFromRequestPrefersDedicatedHeader(t *testing.T) {
	request := httptest.NewRequest("GET", "/v1/admin/overview", nil)
	request.Header.Set("Authorization", "Bearer legacy-token")
	request.Header.Set("X-MeshLAN-Admin-Token", " dedicated-token ")
	if got := adminTokenFromRequest(request); got != "dedicated-token" {
		t.Fatalf("token=%q", got)
	}
}

func TestAdminTokenFromRequestSupportsBearerFallback(t *testing.T) {
	request := httptest.NewRequest("GET", "/v1/admin/overview", nil)
	request.Header.Set("Authorization", "Bearer legacy-token")
	if got := adminTokenFromRequest(request); got != "legacy-token" {
		t.Fatalf("token=%q", got)
	}
}
