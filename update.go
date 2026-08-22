package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const updateSeedPort = 24444

func fileSHA256(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func copyFileAtomic(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary := destination + ".tmp"
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		_ = os.Remove(temporary)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(temporary)
		return closeErr
	}
	_ = os.Remove(destination)
	return os.Rename(temporary, destination)
}

func compareSemanticVersions(left, right string) int {
	parse := func(value string) ([3]int, bool) {
		var result [3]int
		core := strings.SplitN(value, "-", 2)[0]
		parts := strings.Split(core, ".")
		if len(parts) != 3 {
			return result, false
		}
		for i := range parts {
			part, err := strconv.Atoi(parts[i])
			if err != nil || part < 0 {
				return result, false
			}
			result[i] = part
		}
		return result, true
	}
	a, okA := parse(left)
	b, okB := parse(right)
	if !okA || !okB {
		return 0
	}
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	leftPre := strings.Contains(left, "-")
	rightPre := strings.Contains(right, "-")
	if leftPre && !rightPre {
		return -1
	}
	if !leftPre && rightPre {
		return 1
	}
	return strings.Compare(left, right)
}

func clientVersionNumber() string {
	const prefix = "meshlan-nebula/"
	if !strings.HasPrefix(clientVersion, prefix) {
		return "0.0.0"
	}
	return strings.TrimPrefix(clientVersion, prefix)
}

func validateUpdateManifest(payload UpdateManifestPayload) error {
	if !semanticVersionPattern.MatchString(payload.Version) {
		return errors.New("更新版本格式无效")
	}
	if payload.Platform != "windows-amd64" || !validCertificateFingerprint(payload.SHA256) || payload.Size < 1 {
		return errors.New("更新清单无效")
	}
	return nil
}
