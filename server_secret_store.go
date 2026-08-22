package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const serverSecretStorageVersion = 1

type serverSecretBundle struct {
	TLSPrivateKeyPEM       string `json:"tlsPrivateKeyPem,omitempty"`
	SecurityPrivateKey     string `json:"securityPrivateKey,omitempty"`
	RevocationPrivateKey   string `json:"revocationPrivateKey,omitempty"`
	UpdatePrivateKey       string `json:"updatePrivateKey,omitempty"`
	NebulaCAKeyPEM         string `json:"nebulaCaKeyPem,omitempty"`
	AdminTOTPSecret        string `json:"adminTotpSecret,omitempty"`
	HTTPSCAPrivateKeyPEM   string `json:"httpsCaPrivateKeyPem,omitempty"`
	AIProviderAPIKey       string `json:"aiProviderApiKey,omitempty"`
	AIEncryptionPrivateKey string `json:"aiEncryptionPrivateKey,omitempty"`
}

func serverMasterKeyPath(statePath string) string {
	if configured := os.Getenv("MESHLAN_MASTER_KEY_FILE"); configured != "" {
		return configured
	}
	return statePath + ".master.key"
}

func readServerMasterKey(statePath string, create bool) ([]byte, error) {
	path := serverMasterKeyPath(statePath)
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("服务端主密钥长度无效")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, fmt.Errorf("读取服务端主密钥失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return readServerMasterKey(statePath, false)
	}
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(key); err != nil {
		file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return key, nil
}

func serverSecretAAD(statePath string) []byte {
	return []byte("MeshLAN-Nebula/server-state/v1|" + filepath.Base(statePath))
}

func encryptServerSecretBundle(statePath string, bundle serverSecretBundle) (string, error) {
	key, err := readServerMasterKey(statePath, true)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	plain, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plain, serverSecretAAD(statePath))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func decryptServerSecretBundle(statePath, value string) (serverSecretBundle, error) {
	var bundle serverSecretBundle
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return bundle, errors.New("服务端密钥密文格式无效")
	}
	key, err := readServerMasterKey(statePath, false)
	if err != nil {
		return bundle, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return bundle, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return bundle, err
	}
	if len(sealed) <= aead.NonceSize() {
		return bundle, errors.New("服务端密钥密文过短")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, serverSecretAAD(statePath))
	if err != nil {
		return bundle, errors.New("服务端密钥密文认证失败")
	}
	if err := json.Unmarshal(plain, &bundle); err != nil {
		return bundle, err
	}
	return bundle, nil
}

func protectServerStateForDisk(path string, state ServerState) (ServerState, error) {
	caKeyPEM := state.NebulaCAKeyPEM
	if caKeyPEM == "" && state.NebulaCAKeyPath != "" {
		if data, err := os.ReadFile(state.NebulaCAKeyPath); err == nil {
			caKeyPEM = string(data)
			state.NebulaCAKeyEncrypted = true
		}
	}
	bundle := serverSecretBundle{
		TLSPrivateKeyPEM: state.TLSPrivateKeyPEM, SecurityPrivateKey: state.SecurityPrivateKey,
		RevocationPrivateKey: state.RevocationPrivateKey, UpdatePrivateKey: state.UpdatePrivateKey, NebulaCAKeyPEM: caKeyPEM,
		AdminTOTPSecret:        state.AdminTOTPSecret,
		HTTPSCAPrivateKeyPEM:   state.HTTPSCAPrivateKeyPEM,
		AIProviderAPIKey:       state.AIProviderAPIKey,
		AIEncryptionPrivateKey: state.AIEncryptionPrivateKey,
	}
	if bundle.TLSPrivateKeyPEM == "" && bundle.SecurityPrivateKey == "" && bundle.RevocationPrivateKey == "" && bundle.UpdatePrivateKey == "" && bundle.NebulaCAKeyPEM == "" && bundle.AdminTOTPSecret == "" && bundle.HTTPSCAPrivateKeyPEM == "" && bundle.AIProviderAPIKey == "" && bundle.AIEncryptionPrivateKey == "" {
		return state, nil
	}
	protected, err := encryptServerSecretBundle(path, bundle)
	if err != nil {
		return ServerState{}, err
	}
	state.TLSPrivateKeyPEM = ""
	state.SecurityPrivateKey = ""
	state.RevocationPrivateKey = ""
	state.UpdatePrivateKey = ""
	state.NebulaCAKeyPEM = ""
	state.AdminTOTPSecret = ""
	state.HTTPSCAPrivateKeyPEM = ""
	state.AIProviderAPIKey = ""
	state.AIEncryptionPrivateKey = ""
	state.EncryptedServerSecrets = protected
	state.SecretStorageVersion = serverSecretStorageVersion
	return state, nil
}

func restoreServerStateFromDisk(path string, state *ServerState) error {
	if state == nil {
		return nil
	}
	if state.EncryptedServerSecrets == "" {
		if state.SecretStorageVersion >= serverSecretStorageVersion && (state.TLSPrivateKeyPEM != "" || state.SecurityPrivateKey != "" || state.RevocationPrivateKey != "" || state.UpdatePrivateKey != "") {
			return errors.New("加密服务端状态缺少密钥密文")
		}
		return nil
	}
	bundle, err := decryptServerSecretBundle(path, state.EncryptedServerSecrets)
	if err != nil {
		return err
	}
	state.TLSPrivateKeyPEM = bundle.TLSPrivateKeyPEM
	state.SecurityPrivateKey = bundle.SecurityPrivateKey
	state.RevocationPrivateKey = bundle.RevocationPrivateKey
	state.UpdatePrivateKey = bundle.UpdatePrivateKey
	state.NebulaCAKeyPEM = bundle.NebulaCAKeyPEM
	state.AdminTOTPSecret = bundle.AdminTOTPSecret
	state.HTTPSCAPrivateKeyPEM = bundle.HTTPSCAPrivateKeyPEM
	state.AIProviderAPIKey = bundle.AIProviderAPIKey
	state.AIEncryptionPrivateKey = bundle.AIEncryptionPrivateKey
	if bundle.NebulaCAKeyPEM != "" {
		state.NebulaCAKeyEncrypted = true
	}
	state.SecretStorageVersion = serverSecretStorageVersion
	return nil
}

func prepareServerJSONValue(path string, value any) (any, error) {
	switch typed := value.(type) {
	case ServerState:
		return protectServerStateForDisk(path, typed)
	case *ServerState:
		if typed == nil {
			return value, nil
		}
		return protectServerStateForDisk(path, *typed)
	default:
		return value, nil
	}
}

func restoreServerJSONValue(path string, value any) error {
	state, ok := value.(*ServerState)
	if !ok {
		return nil
	}
	return restoreServerStateFromDisk(path, state)
}

func migrateServerStateSecrets(path string, state *ServerState) bool {
	if state == nil {
		return false
	}
	changed := false
	if state.SecretStorageVersion < serverSecretStorageVersion && (state.TLSPrivateKeyPEM != "" || state.SecurityPrivateKey != "" || state.RevocationPrivateKey != "" || state.UpdatePrivateKey != "") {
		state.SecretStorageVersion = serverSecretStorageVersion
		changed = true
	}
	if state.NebulaCAKeyPEM == "" && state.NebulaCAKeyPath != "" {
		if data, err := os.ReadFile(state.NebulaCAKeyPath); err == nil {
			state.NebulaCAKeyPEM = string(data)
			state.NebulaCAKeyEncrypted = true
			changed = true
		}
	}
	if state.NebulaCAKeyEncrypted && state.NebulaCAKeyPath != "" {
		if _, err := os.Stat(state.NebulaCAKeyPath); err == nil {
			changed = true
		}
	}
	return changed
}

func finalizeJSONSave(path string, value any) error {
	var state ServerState
	switch typed := value.(type) {
	case ServerState:
		state = typed
	case *ServerState:
		if typed == nil {
			return nil
		}
		state = *typed
	default:
		return nil
	}
	if !state.NebulaCAKeyEncrypted || state.NebulaCAKeyPath == "" || state.NebulaCAKeyPEM == "" {
		return nil
	}
	if err := os.Remove(state.NebulaCAKeyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("删除明文Nebula CA私钥失败: %w", err)
	}
	return nil
}
