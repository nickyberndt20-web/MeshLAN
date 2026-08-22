//go:build windows

package main

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const clientSecretStorageVersion = 1

var clientSecretEntropy = []byte("MeshLAN-Nebula/client-state/device-token/v1")

func dataBlob(value []byte) windows.DataBlob {
	if len(value) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(value)), Data: &value[0]}
}

func copyAndFreeDataBlob(blob windows.DataBlob) []byte {
	if blob.Data == nil || blob.Size == 0 {
		return nil
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data)))
	return append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...)
}

func dpapiProtectString(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	plain := []byte(value)
	input, entropy := dataBlob(plain), dataBlob(clientSecretEntropy)
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return "", fmt.Errorf("DPAPI加密设备令牌失败: %w", err)
	}
	runtime.KeepAlive(plain)
	runtime.KeepAlive(clientSecretEntropy)
	protected := copyAndFreeDataBlob(output)
	if len(protected) == 0 {
		return "", errors.New("DPAPI返回空密文")
	}
	return base64.RawURLEncoding.EncodeToString(protected), nil
}

func dpapiUnprotectString(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	protected, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(protected) == 0 {
		return "", errors.New("设备令牌密文格式无效")
	}
	input, entropy := dataBlob(protected), dataBlob(clientSecretEntropy)
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return "", fmt.Errorf("DPAPI解密设备令牌失败: %w", err)
	}
	runtime.KeepAlive(protected)
	runtime.KeepAlive(clientSecretEntropy)
	plain := copyAndFreeDataBlob(output)
	if len(plain) == 0 {
		return "", errors.New("DPAPI返回空明文")
	}
	return string(plain), nil
}

func protectClientStateForDisk(state ClientState) (ClientState, error) {
	copy := state
	if state.Pairing == nil {
		return copy, nil
	}
	pairing := *state.Pairing
	if pairing.DeviceToken != "" {
		protected, err := dpapiProtectString(pairing.DeviceToken)
		if err != nil {
			return ClientState{}, err
		}
		copy.EncryptedDeviceToken = protected
		copy.SecretStorageVersion = clientSecretStorageVersion
	}
	pairing.DeviceToken = ""
	copy.Pairing = &pairing
	return copy, nil
}

func restoreClientStateFromDisk(state *ClientState) error {
	if state == nil || state.Pairing == nil {
		return nil
	}
	if state.EncryptedDeviceToken == "" {
		if state.SecretStorageVersion >= clientSecretStorageVersion && state.Pairing.DeviceToken != "" {
			return errors.New("加密状态缺少设备令牌密文")
		}
		return nil
	}
	plain, err := dpapiUnprotectString(state.EncryptedDeviceToken)
	if err != nil {
		return err
	}
	if state.Pairing.DeviceToken != "" && subtle.ConstantTimeCompare([]byte(state.Pairing.DeviceToken), []byte(plain)) != 1 {
		return errors.New("明文设备令牌与DPAPI密文不一致")
	}
	state.Pairing.DeviceToken = plain
	state.SecretStorageVersion = clientSecretStorageVersion
	return nil
}

func prepareJSONValue(path string, value any) (any, error) {
	switch typed := value.(type) {
	case ClientState:
		return protectClientStateForDisk(typed)
	case *ClientState:
		if typed == nil {
			return value, nil
		}
		return protectClientStateForDisk(*typed)
	default:
		return prepareServerJSONValue(path, value)
	}
}

func restoreJSONValue(path string, value any) error {
	state, ok := value.(*ClientState)
	if ok {
		return restoreClientStateFromDisk(state)
	}
	return restoreServerJSONValue(path, value)
}

func migrateClientStateSecrets(path string, state *ClientState) error {
	if state == nil || state.Pairing == nil || state.Pairing.DeviceToken == "" || state.SecretStorageVersion >= clientSecretStorageVersion {
		return nil
	}
	state.SecretStorageVersion = clientSecretStorageVersion
	return saveJSON(path, *state)
}

func clientPrivateKeyBackupPath(state ClientState) string {
	return state.PrivateKeyPath + ".dpapi"
}

func refreshClientPrivateKeyBackup(state ClientState) error {
	if state.PrivateKeyPath == "" {
		return errors.New("客户端私钥路径为空")
	}
	privateKey, err := os.ReadFile(state.PrivateKeyPath)
	if err != nil {
		return err
	}
	protected, err := dpapiProtectString(string(privateKey))
	if err != nil {
		return err
	}
	path := clientPrivateKeyBackupPath(state)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(protected), 0o600); err != nil {
		return err
	}
	_ = os.Remove(path)
	return os.Rename(temporary, path)
}

func ensureClientPrivateKeyBackup(state ClientState) error {
	if state.PrivateKeyPath == "" {
		return errors.New("客户端私钥路径为空")
	}
	if _, err := os.Stat(state.PrivateKeyPath); errors.Is(err, os.ErrNotExist) {
		protected, readErr := os.ReadFile(clientPrivateKeyBackupPath(state))
		if readErr != nil {
			return errors.New("客户端私钥和DPAPI备份均不存在")
		}
		plain, decryptErr := dpapiUnprotectString(string(protected))
		if decryptErr != nil {
			return decryptErr
		}
		return os.WriteFile(state.PrivateKeyPath, []byte(plain), 0o600)
	} else if err != nil {
		return err
	}
	if info, err := os.Stat(clientPrivateKeyBackupPath(state)); err == nil && info.Size() > 0 {
		return nil
	}
	return refreshClientPrivateKeyBackup(state)
}

func clientPrivateKeyBackupReady(state ClientState) bool {
	info, err := os.Stat(clientPrivateKeyBackupPath(state))
	return err == nil && info.Size() > 0
}
