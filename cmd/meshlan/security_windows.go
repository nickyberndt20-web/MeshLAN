//go:build windows

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type IdentityStatus struct {
	Configured             bool   `json:"configured"`
	Valid                  bool   `json:"valid"`
	Fingerprint            string `json:"fingerprint,omitempty"`
	Error                  string `json:"error,omitempty"`
	CanRepair              bool   `json:"canRepair"`
	RevocationVersion      uint64 `json:"revocationVersion"`
	SecurityAppliedVersion uint64 `json:"securityAppliedVersion"`
	DeviceTokenEncrypted   bool   `json:"deviceTokenEncrypted"`
	SecretACLHardened      bool   `json:"secretAclHardened"`
	PrivateKeyBackupReady  bool   `json:"privateKeyBackupReady"`
}

func (a *clientApp) currentCertificateFingerprint(state *ClientState) string {
	if validCertificateFingerprint(state.CertificateFingerprint) {
		return strings.ToLower(state.CertificateFingerprint)
	}
	if err := a.ensureRuntime(); err != nil {
		return ""
	}
	fingerprint, err := certificateFingerprint(a.cert, state.CertificatePath)
	if err != nil {
		return ""
	}
	state.CertificateFingerprint = fingerprint
	return fingerprint
}

func (a *clientApp) identityStatus() IdentityStatus {
	a.stateMu.Lock()
	state, err := a.load()
	if err != nil || state.Pairing == nil {
		a.stateMu.Unlock()
		return IdentityStatus{Error: "本机尚未完成配对"}
	}
	fingerprint := a.currentCertificateFingerprint(&state)
	_ = saveJSON(a.statePath, state)
	a.stateMu.Unlock()
	status := IdentityStatus{Configured: true, Fingerprint: fingerprint, CanRepair: state.Pairing.DeviceToken != "", RevocationVersion: state.RevocationVersion, SecurityAppliedVersion: readRouteGuardStatus(state).SecurityAppliedVersion, DeviceTokenEncrypted: state.SecretStorageVersion >= clientSecretStorageVersion && state.EncryptedDeviceToken != "", SecretACLHardened: clientSecretACLHardened(a.root), PrivateKeyBackupReady: clientPrivateKeyBackupReady(state)}
	if err := a.ensureRuntime(); err != nil {
		status.Error = err.Error()
		return status
	}
	cmd := exec.Command(a.nebula, "-test", "-config", state.ConfigPath)
	hidden(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		status.Error = strings.TrimSpace(string(output))
		if status.Error == "" {
			status.Error = err.Error()
		}
		return status
	}
	status.Valid = true
	return status
}

func (a *clientApp) applyRevocationEnvelope(envelope SignedRevocationEnvelope) (bool, error) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil || state.Pairing == nil {
		return false, errors.New("本机尚未完成配对")
	}
	trustedRevocationKey := state.Pairing.RevocationPublicKey
	if trustedRevocationKey == "" {
		trustedRevocationKey = state.Pairing.SecurityPublicKey
	}
	payload, err := verifyRevocationEnvelope(envelope, trustedRevocationKey)
	if err != nil {
		return false, err
	}
	stateChanged := false
	if state.Pairing.SecurityPublicKey == "" {
		state.Pairing.SecurityPublicKey = envelope.PublicKey
		stateChanged = true
	}
	if state.Pairing.RevocationPublicKey == "" {
		state.Pairing.RevocationPublicKey = envelope.PublicKey
		stateChanged = true
	}
	if payload.UpdatePublicKey != "" && state.Pairing.UpdatePublicKey != payload.UpdatePublicKey {
		state.Pairing.UpdatePublicKey = payload.UpdatePublicKey
		stateChanged = true
	}
	if state.Pairing.UpdateKeyActive != payload.UpdateKeyActive {
		state.Pairing.UpdateKeyActive = payload.UpdateKeyActive
		stateChanged = true
	}
	if payload.Version > state.RevocationVersion {
		fingerprints := make([]string, 0, len(payload.Revocations))
		for _, item := range payload.Revocations {
			fingerprints = append(fingerprints, item.Fingerprint)
		}
		state.RevocationVersion = payload.Version
		state.RevokedFingerprints = normalizedFingerprints(fingerprints)
		config, configErr := renderClientConfig(state)
		if configErr != nil {
			return false, configErr
		}
		if err := os.WriteFile(state.ConfigPath, []byte(config), 0o600); err != nil {
			return false, err
		}
		stateChanged = true
	}
	if stateChanged {
		if err := saveJSON(a.statePath, state); err != nil {
			return false, err
		}
		_ = a.history.RecordEvent("client", "revocations_synced", state.Name, fmt.Sprintf("已应用吊销列表版本 %d", state.RevocationVersion), time.Now().UTC())
	}
	return stateChanged, nil
}

func writeIdentityFiles(state ClientState, privateKey, publicKey, certificate, caCertificate []byte) error {
	files := []struct {
		path string
		data []byte
	}{
		{state.PrivateKeyPath, privateKey},
		{state.PublicKeyPath, publicKey},
		{state.CertificatePath, certificate},
		{state.CACertificatePath, caCertificate},
	}
	for _, file := range files {
		if err := os.WriteFile(file.path, file.data, 0o600); err != nil {
			return err
		}
	}
	config, err := renderClientConfig(state)
	if err != nil {
		return err
	}
	return os.WriteFile(state.ConfigPath, []byte(config), 0o600)
}

func (a *clientApp) repairIdentity() (IdentityStatus, error) {
	a.stateMu.Lock()
	oldState, err := a.load()
	a.stateMu.Unlock()
	if err != nil || oldState.Pairing == nil {
		return IdentityStatus{}, errors.New("本机尚未完成配对")
	}
	if err := a.ensureRuntime(); err != nil {
		return IdentityStatus{}, err
	}
	oldState.CertificateFingerprint = a.currentCertificateFingerprint(&oldState)
	if !validCertificateFingerprint(oldState.CertificateFingerprint) {
		return IdentityStatus{}, errors.New("无法读取旧证书指纹，不能安全吊销旧身份")
	}
	var rekey struct {
		PairingHash string `json:"pairingHash"`
	}
	if err := deviceControlRequest(oldState, http.MethodPost, "/v1/rekey", map[string]any{"certificateFingerprint": oldState.CertificateFingerprint}, &rekey); err != nil {
		return IdentityStatus{}, err
	}
	if rekey.PairingHash == "" {
		return IdentityStatus{}, errors.New("服务端未返回身份修复凭据")
	}
	temporaryRoot := filepath.Join(a.root, fmt.Sprintf("identity-repair-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
		return IdentityStatus{}, err
	}
	defer os.RemoveAll(temporaryRoot)
	privatePath := filepath.Join(temporaryRoot, "host.key")
	publicPath := filepath.Join(temporaryRoot, "host.pub")
	certificatePath := filepath.Join(temporaryRoot, "host.crt")
	caPath := filepath.Join(temporaryRoot, "ca.crt")
	configPath := filepath.Join(temporaryRoot, "config.yml")
	cmd := exec.Command(a.cert, "keygen", "-out-key", privatePath, "-out-pub", publicPath)
	hidden(cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return IdentityStatus{}, fmt.Errorf("生成修复密钥失败: %s", strings.TrimSpace(string(output)))
	}
	publicKey, err := os.ReadFile(publicPath)
	if err != nil {
		return IdentityStatus{}, err
	}
	paired, err := pairWithServer(oldState.Pairing.ControlHost, rekey.PairingHash, PairRequest{Version: protocolVersion, Name: oldState.Name, PublicKey: string(publicKey)})
	if err != nil {
		return IdentityStatus{}, err
	}
	if paired.RekeyID == "" {
		return IdentityStatus{}, errors.New("服务端没有创建暂存身份事务")
	}
	if oldState.Pairing.SecurityPublicKey != "" && paired.SecurityPublicKey != oldState.Pairing.SecurityPublicKey {
		return IdentityStatus{}, errors.New("服务端吊销签名公钥发生变化，拒绝修复")
	}
	if err := os.WriteFile(certificatePath, []byte(paired.CertificatePEM), 0o600); err != nil {
		return IdentityStatus{}, err
	}
	if err := os.WriteFile(caPath, []byte(paired.CACertificatePEM), 0o600); err != nil {
		return IdentityStatus{}, err
	}
	candidate := oldState
	candidate.Pairing = &paired
	candidate.PrivateKeyPath, candidate.PublicKeyPath = privatePath, publicPath
	candidate.CertificatePath, candidate.CACertificatePath, candidate.ConfigPath = certificatePath, caPath, configPath
	candidate.CertificateFingerprint, err = certificateFingerprint(a.cert, certificatePath)
	if err != nil {
		return IdentityStatus{}, err
	}
	config, err := renderClientConfig(candidate)
	if err != nil {
		return IdentityStatus{}, err
	}
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return IdentityStatus{}, err
	}
	testCommand := exec.Command(a.nebula, "-test", "-config", configPath)
	hidden(testCommand)
	if output, err := testCommand.CombinedOutput(); err != nil {
		return IdentityStatus{}, fmt.Errorf("新身份校验失败: %s", strings.TrimSpace(string(output)))
	}
	oldFiles := map[string][]byte{}
	for _, path := range []string{oldState.PrivateKeyPath, oldState.PublicKeyPath, oldState.CertificatePath, oldState.CACertificatePath, oldState.ConfigPath} {
		oldFiles[path], _ = os.ReadFile(path)
	}
	privateKey, _ := os.ReadFile(privatePath)
	certificate, _ := os.ReadFile(certificatePath)
	caCertificate, _ := os.ReadFile(caPath)
	committed := oldState
	committed.Pairing = &paired
	committed.CertificateFingerprint = candidate.CertificateFingerprint
	if err := writeIdentityFiles(committed, privateKey, publicKey, certificate, caCertificate); err != nil {
		return IdentityStatus{}, err
	}
	a.stateMu.Lock()
	err = saveJSON(a.statePath, committed)
	a.stateMu.Unlock()
	if err != nil {
		for path, data := range oldFiles {
			_ = os.WriteFile(path, data, 0o600)
		}
		return IdentityStatus{}, err
	}
	var commitResponse HeartbeatResponse
	if err := deviceControlRequest(committed, http.MethodPost, "/v1/rekey/commit", map[string]any{"rekeyId": paired.RekeyID}, &commitResponse); err != nil {
		for path, data := range oldFiles {
			_ = os.WriteFile(path, data, 0o600)
		}
		a.stateMu.Lock()
		_ = saveJSON(a.statePath, oldState)
		a.stateMu.Unlock()
		return IdentityStatus{}, err
	}
	_, _ = a.applyRevocationEnvelope(commitResponse.Revocations)
	if err := refreshClientPrivateKeyBackup(committed); err != nil {
		return a.identityStatus(), fmt.Errorf("身份已更新，但DPAPI私钥备份失败: %w", err)
	}
	if err := runElevated("powershell.exe", []string{"-NoProfile", "-Command", "Restart-Service -Name Nebula -Force -ErrorAction Stop"}); err != nil {
		return a.identityStatus(), fmt.Errorf("新身份已提交，请重试启动服务: %w", err)
	}
	_ = a.history.RecordEvent("client", "identity_rekey", committed.Name, "身份修复完成，旧证书已吊销", time.Now().UTC())
	return a.identityStatus(), nil
}
