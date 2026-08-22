package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func serverMasterKeyBackupPath(statePath string) string {
	return serverMasterKeyPath(statePath) + ".previous"
}

func serverStateBackupPath(statePath string) string {
	return statePath + ".pre-master-rotation"
}

func writeFreshServerMasterKey(path string) error {
	key := make([]byte, 32)
	if _, err := io.ReadFull(crand.Reader, key); err != nil {
		return err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func rotateServerMasterKey(statePath string) (err error) {
	var state ServerState
	if err = loadJSON(statePath, &state); err != nil {
		return err
	}
	masterPath := serverMasterKeyPath(statePath)
	keyBackup := serverMasterKeyBackupPath(statePath)
	stateBackup := serverStateBackupPath(statePath)
	if err = copyFileAtomic(statePath, stateBackup, 0o600); err != nil {
		return err
	}
	if err = copyFileAtomic(masterPath, keyBackup, 0o600); err != nil {
		return err
	}
	nextKey := masterPath + ".next"
	_ = os.Remove(nextKey)
	if err = writeFreshServerMasterKey(nextKey); err != nil {
		return err
	}
	swapped := false
	defer func() {
		if err == nil || !swapped {
			return
		}
		_ = copyFileAtomic(keyBackup, masterPath, 0o600)
		_ = copyFileAtomic(stateBackup, statePath, 0o600)
	}()
	if err = os.Remove(masterPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = os.Rename(nextKey, masterPath); err != nil {
		_ = copyFileAtomic(keyBackup, masterPath, 0o600)
		return err
	}
	swapped = true
	if err = saveJSON(statePath, state); err != nil {
		return err
	}
	var verified ServerState
	if err = loadJSON(statePath, &verified); err != nil {
		return err
	}
	if !validSigningKeyPair(verified.RevocationPrivateKey, verified.RevocationPublicKey) || !validSigningKeyPair(verified.UpdatePrivateKey, verified.UpdatePublicKey) || verified.NebulaCAKeyPEM == "" {
		err = errors.New("新主密钥重加密后的状态自检失败")
		return err
	}
	return nil
}

func restorePreviousServerMasterKey(statePath string) error {
	masterPath := serverMasterKeyPath(statePath)
	keyBackup := serverMasterKeyBackupPath(statePath)
	stateBackup := serverStateBackupPath(statePath)
	if _, err := os.Stat(keyBackup); err != nil {
		return errors.New("没有可恢复的上一主密钥")
	}
	if _, err := os.Stat(stateBackup); err != nil {
		return errors.New("没有与上一主密钥匹配的状态备份")
	}
	if err := copyFileAtomic(keyBackup, masterPath, 0o600); err != nil {
		return err
	}
	if err := copyFileAtomic(stateBackup, statePath, 0o600); err != nil {
		return err
	}
	var verified ServerState
	return loadJSON(statePath, &verified)
}

func verifyServerCryptoState(statePath string) error {
	var state ServerState
	if err := loadJSON(statePath, &state); err != nil {
		return err
	}
	if state.SecretStorageVersion < serverSecretStorageVersion || state.EncryptedServerSecrets == "" {
		return errors.New("服务端密钥信封未启用")
	}
	if !validSigningKeyPair(state.RevocationPrivateKey, state.RevocationPublicKey) {
		return errors.New("吊销签名密钥自检失败")
	}
	if !validSigningKeyPair(state.UpdatePrivateKey, state.UpdatePublicKey) || state.UpdatePublicKey == state.RevocationPublicKey {
		return errors.New("独立更新签名密钥自检失败")
	}
	if state.NebulaCAKeyPEM == "" || !state.NebulaCAKeyEncrypted {
		return errors.New("Nebula CA私钥未进入密钥信封")
	}
	if _, _, err := parseMeshHTTPSCA(state); err != nil || state.HTTPSCAFingerprint == "" {
		return errors.New("MeshLAN HTTPS CA密钥自检失败")
	}
	if state.AdminTOTPEnabled {
		if _, err := totpCode(state.AdminTOTPSecret, time.Now()); err != nil {
			return errors.New("管理员TOTP密钥自检失败")
		}
	}
	return nil
}

func serverRotateMasterKey(args []string) error {
	fs, statePath := serverFlagSet("server rotate-master-key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := rotateServerMasterKey(*statePath); err != nil {
		return err
	}
	fmt.Printf("主密钥轮换完成\n状态备份: %s\n密钥备份: %s\n", serverStateBackupPath(*statePath), serverMasterKeyBackupPath(*statePath))
	return nil
}

func serverRestoreMasterKey(args []string) error {
	fs, statePath := serverFlagSet("server restore-master-key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := restorePreviousServerMasterKey(*statePath); err != nil {
		return err
	}
	fmt.Println("上一主密钥与匹配状态已恢复；重启服务后生效")
	return nil
}

func serverVerifyCrypto(args []string) error {
	fs, statePath := serverFlagSet("server verify-crypto")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := verifyServerCryptoState(*statePath); err != nil {
		return err
	}
	fmt.Println("服务端加密状态验证通过")
	return nil
}

func peerClientVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "meshlan-nebula/")
}

func independentUpdateKeyBlockers(state ServerState, minimumVersion string) []string {
	legacy := make([]string, 0)
	for _, peer := range state.Peers {
		if peer.Revoked {
			continue
		}
		version := peerClientVersion(peer.ClientVersion)
		if version == "" || compareSemanticVersions(version, minimumVersion) < 0 {
			legacy = append(legacy, fmt.Sprintf("%s(%s)", peer.Name, peer.ClientVersion))
		}
	}
	return legacy
}

func autoActivateIndependentUpdateKey(state *ServerState, minimumVersion string) (bool, error) {
	if state.UpdateKeyActive || len(independentUpdateKeyBlockers(*state, minimumVersion)) > 0 {
		return false, nil
	}
	if err := ensureServerSecurityIdentity(state); err != nil {
		return false, err
	}
	state.UpdateKeyActive = true
	return true, nil
}

func activateIndependentUpdateKey(statePath, minimumVersion string) error {
	if !semanticVersionPattern.MatchString(minimumVersion) {
		return errors.New("最低客户端版本无效")
	}
	var state ServerState
	if err := loadJSON(statePath, &state); err != nil {
		return err
	}
	if err := ensureServerSecurityIdentity(&state); err != nil {
		return err
	}
	legacy := independentUpdateKeyBlockers(state, minimumVersion)
	if len(legacy) > 0 {
		return fmt.Errorf("仍有客户端不支持独立更新密钥: %s", strings.Join(legacy, ", "))
	}
	state.UpdateKeyActive = true
	return saveJSON(statePath, state)
}

func deactivateIndependentUpdateKey(statePath string) error {
	var state ServerState
	if err := loadJSON(statePath, &state); err != nil {
		return err
	}
	state.UpdateKeyActive = false
	return saveJSON(statePath, state)
}

func serverActivateUpdateKey(args []string) error {
	fs, statePath := serverFlagSet("server activate-update-key")
	minimumVersion := fs.String("minimum-version", "1.10.1", "所有未吊销客户端必须达到的最低版本")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := activateIndependentUpdateKey(*statePath, *minimumVersion); err != nil {
		return err
	}
	fmt.Println("独立更新签名密钥已激活；重启服务后客户端将切换验证根")
	return nil
}

func serverDeactivateUpdateKey(args []string) error {
	fs, statePath := serverFlagSet("server deactivate-update-key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := deactivateIndependentUpdateKey(*statePath); err != nil {
		return err
	}
	fmt.Println("独立更新签名密钥已停用；重启服务后恢复兼容签名")
	return nil
}

func containsPlaintextServerSecrets(data []byte) bool {
	if bytes.Contains(data, []byte("BEGIN RSA PRIVATE KEY")) || bytes.Contains(data, []byte("BEGIN EC PRIVATE KEY")) || bytes.Contains(data, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(data, []byte("BEGIN NEBULA X25519 PRIVATE KEY")) {
		return true
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return false
	}
	for _, field := range []string{"tlsPrivateKeyPem", "securityPrivateKey", "revocationPrivateKey", "updatePrivateKey", "httpsCaPrivateKeyPem", "aiProviderApiKey", "aiEncryptionPrivateKey"} {
		value := raw[field]
		if len(value) == 0 {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) == nil && strings.TrimSpace(text) != "" {
			return true
		}
	}
	return false
}

func plaintextServerStateBackups(root string) ([]string, error) {
	result := make([]string, 0)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.Contains(strings.ToLower(info.Name()), "server-state") || strings.HasSuffix(strings.ToLower(info.Name()), ".master.key") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if containsPlaintextServerSecrets(data) {
			result = append(result, path)
		}
		return nil
	})
	return result, err
}

func encryptServerStateBackups(root, currentStatePath string) (int, error) {
	paths, err := plaintextServerStateBackups(root)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, path := range paths {
		if filepath.Clean(path) == filepath.Clean(currentStatePath) {
			continue
		}
		var state ServerState
		if err := loadJSON(path, &state); err != nil {
			return count, fmt.Errorf("读取旧状态备份失败 %s: %w", path, err)
		}
		if err := saveJSON(path, state); err != nil {
			return count, fmt.Errorf("加密旧状态备份失败 %s: %w", path, err)
		}
		count++
	}
	remaining, err := plaintextServerStateBackups(root)
	if err != nil {
		return count, err
	}
	for _, path := range remaining {
		if filepath.Clean(path) != filepath.Clean(currentStatePath) {
			return count, fmt.Errorf("旧状态备份仍包含明文私钥: %s", path)
		}
	}
	return count, nil
}

func serverEncryptBackups(args []string) error {
	fs, statePath := serverFlagSet("server encrypt-backups")
	root := fs.String("root", "", "需要扫描的服务端状态根目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *root == "" {
		*root = filepath.Dir(*statePath)
	}
	count, err := encryptServerStateBackups(*root, *statePath)
	if err != nil {
		return err
	}
	fmt.Printf("旧状态备份加密完成: %d 个文件\n", count)
	return nil
}

func serverScanPlaintextSecrets(args []string) error {
	fs, statePath := serverFlagSet("server scan-plaintext-secrets")
	root := fs.String("root", "", "需要扫描的服务端状态根目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *root == "" {
		*root = filepath.Dir(*statePath)
	}
	paths, err := plaintextServerStateBackups(*root)
	if err != nil {
		return err
	}
	if len(paths) > 0 {
		return fmt.Errorf("发现 %d 个包含明文私钥的状态文件", len(paths))
	}
	fmt.Println("未发现包含明文私钥的服务端状态文件")
	return nil
}
