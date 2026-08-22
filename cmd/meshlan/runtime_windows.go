//go:build windows

package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	nebulaVersion       = "1.11.0"
	nebulaWindowsURL    = "https://github.com/slackhq/nebula/releases/download/v1.11.0/nebula-windows-amd64.zip"
	nebulaWindowsSHA256 = "dc6b144bd852b5a17fc0c9283d96e6309fd918c9e8f385fab256da6dfdd42232"
)

func verifySHA256(path, expected string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected)
}

func parseTotalSize(response *http.Response, existing int64) int64 {
	if response.StatusCode == http.StatusPartialContent {
		contentRange := response.Header.Get("Content-Range")
		if slash := strings.LastIndex(contentRange, "/"); slash >= 0 {
			if total, err := strconv.ParseInt(contentRange[slash+1:], 10, 64); err == nil {
				return total
			}
		}
		return existing + response.ContentLength
	}
	return response.ContentLength
}

func downloadWithResume(url, destination string) error {
	client := &http.Client{Timeout: 3 * time.Minute}
	for attempt := 0; attempt < 12; attempt++ {
		existing := int64(0)
		if info, err := os.Stat(destination); err == nil {
			existing = info.Size()
		}
		request, _ := http.NewRequest(http.MethodGet, url, nil)
		if existing > 0 {
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-", existing))
		}
		response, err := client.Do(request)
		if err != nil {
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
			response.Body.Close()
			return fmt.Errorf("Nebula 下载 HTTP %d", response.StatusCode)
		}
		total := parseTotalSize(response, existing)
		flags := os.O_CREATE | os.O_WRONLY
		if response.StatusCode == http.StatusPartialContent && existing > 0 {
			flags |= os.O_APPEND
		} else {
			flags |= os.O_TRUNC
			existing = 0
		}
		file, openErr := os.OpenFile(destination, flags, 0o600)
		if openErr != nil {
			response.Body.Close()
			return openErr
		}
		_, copyErr := io.Copy(file, response.Body)
		file.Close()
		response.Body.Close()
		if copyErr != nil {
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		info, statErr := os.Stat(destination)
		if statErr == nil && total > 0 && info.Size() >= total {
			return nil
		}
	}
	return errors.New("Nebula 下载多次中断，请检查代理或网络")
}

func extractNebulaRuntime(archivePath, runtimeDir string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	allowed := map[string]bool{"nebula.exe": true, "nebula-cert.exe": true}
	for _, entry := range reader.File {
		clean := filepath.ToSlash(filepath.Clean(entry.Name))
		if strings.HasPrefix(clean, "../") || filepath.IsAbs(entry.Name) {
			return errors.New("Nebula 压缩包包含不安全路径")
		}
		if !allowed[clean] && !strings.HasPrefix(clean, "dist/") {
			continue
		}
		target := filepath.Join(runtimeDir, filepath.FromSlash(clean))
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		source, err := entry.Open()
		if err != nil {
			return err
		}
		destination, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
		if err != nil {
			source.Close()
			return err
		}
		_, copyErr := io.Copy(destination, source)
		destination.Close()
		source.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	for _, name := range []string{"nebula.exe", "nebula-cert.exe"} {
		if _, err := os.Stat(filepath.Join(runtimeDir, name)); err != nil {
			return fmt.Errorf("官方压缩包缺少 %s", name)
		}
	}
	return nil
}

func ensureNebulaRuntime(runtimeDir string) (string, string, error) {
	nebula := filepath.Join(runtimeDir, "nebula.exe")
	cert := filepath.Join(runtimeDir, "nebula-cert.exe")
	if _, err := os.Stat(nebula); err == nil {
		if _, certErr := os.Stat(cert); certErr == nil {
			return nebula, cert, nil
		}
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return "", "", err
	}
	archive := filepath.Join(runtimeDir, "nebula-windows-amd64.zip.part")
	if err := downloadWithResume(nebulaWindowsURL, archive); err != nil {
		return "", "", err
	}
	if !verifySHA256(archive, nebulaWindowsSHA256) {
		_ = os.Remove(archive)
		return "", "", errors.New("Nebula 官方包 SHA-256 校验失败")
	}
	if err := extractNebulaRuntime(archive, runtimeDir); err != nil {
		return "", "", err
	}
	_ = os.Remove(archive)
	return nebula, cert, nil
}
