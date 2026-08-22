package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

var certificateFingerprintPattern = regexp.MustCompile(`(?im)(?:^\s*Fingerprint:\s*|"fingerprint"\s*:\s*")([0-9a-f]{64})(?:"|\s*$)`)
var semanticVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$`)

func validCertificateFingerprint(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func normalizedFingerprints(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if !validCertificateFingerprint(value) || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func renderBlocklistYAML(values []string) string {
	values = normalizedFingerprints(values)
	if len(values) == 0 {
		return "  blocklist: []\n"
	}
	var builder strings.Builder
	builder.WriteString("  blocklist:\n")
	for _, value := range values {
		fmt.Fprintf(&builder, "    - %q\n", value)
	}
	return builder.String()
}

func validSigningKeyPair(privateText, publicText string) bool {
	privateKey, privateErr := base64.RawURLEncoding.DecodeString(privateText)
	publicKey, publicErr := base64.RawURLEncoding.DecodeString(publicText)
	return privateErr == nil && publicErr == nil && len(privateKey) == ed25519.PrivateKeySize && len(publicKey) == ed25519.PublicKeySize && ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(publicKey))
}

func generateSigningKeyPair() (privateText, publicText string, err error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(privateKey), base64.RawURLEncoding.EncodeToString(publicKey), nil
}

func ensureServerSecurityIdentity(state *ServerState) error {
	if state.SecurityPrivateKey == "" || state.SecurityPublicKey == "" {
		privateKey, publicKey, err := generateSigningKeyPair()
		if err != nil {
			return err
		}
		state.SecurityPrivateKey, state.SecurityPublicKey = privateKey, publicKey
	} else if !validSigningKeyPair(state.SecurityPrivateKey, state.SecurityPublicKey) {
		return errors.New("服务端旧版信任根密钥损坏")
	}
	if state.RevocationPrivateKey == "" || state.RevocationPublicKey == "" {
		state.RevocationPrivateKey, state.RevocationPublicKey = state.SecurityPrivateKey, state.SecurityPublicKey
	} else if !validSigningKeyPair(state.RevocationPrivateKey, state.RevocationPublicKey) {
		return errors.New("服务端吊销签名密钥损坏")
	}
	if state.UpdatePrivateKey == "" || state.UpdatePublicKey == "" {
		privateKey, publicKey, err := generateSigningKeyPair()
		if err != nil {
			return err
		}
		state.UpdatePrivateKey, state.UpdatePublicKey = privateKey, publicKey
	} else if !validSigningKeyPair(state.UpdatePrivateKey, state.UpdatePublicKey) {
		return errors.New("服务端更新签名密钥损坏")
	}
	if state.UpdatePublicKey == state.RevocationPublicKey {
		return errors.New("更新签名与吊销签名不得共用密钥")
	}
	if state.AIEncryptionPrivateKey == "" || state.AIEncryptionPublicKey == "" {
		privateKey, publicKey, err := generateX25519KeyPair()
		if err != nil {
			return err
		}
		state.AIEncryptionPrivateKey, state.AIEncryptionPublicKey = privateKey, publicKey
	} else if !validX25519KeyPair(state.AIEncryptionPrivateKey, state.AIEncryptionPublicKey) {
		return errors.New("服务端AI端到端加密密钥损坏")
	}
	state.CryptoKeyVersion = 2
	return ensureMeshHTTPSCA(state)
}

func serverSecurityIdentitySummary(state ServerState) string {
	return strings.Join([]string{state.SecurityPublicKey, state.RevocationPublicKey, state.UpdatePublicKey, state.HTTPSCAFingerprint, state.AIEncryptionPublicKey, fmt.Sprint(state.UpdateKeyActive), fmt.Sprint(state.CryptoKeyVersion)}, "|")
}

func signedRevocationEnvelope(state ServerState) (SignedRevocationEnvelope, error) {
	privateText, publicText := state.RevocationPrivateKey, state.RevocationPublicKey
	if privateText == "" || publicText == "" {
		privateText, publicText = state.SecurityPrivateKey, state.SecurityPublicKey
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(privateText)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return SignedRevocationEnvelope{}, errors.New("服务端吊销签名私钥无效")
	}
	payload := RevocationPayload{
		Version:         state.RevocationVersion,
		GeneratedAt:     time.Now().UTC(),
		Revocations:     append([]CertificateRevocation(nil), state.Revocations...),
		UpdatePublicKey: state.UpdatePublicKey,
		UpdateKeyActive: state.UpdateKeyActive,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return SignedRevocationEnvelope{}, err
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), payloadBytes)
	return SignedRevocationEnvelope{
		Payload:   base64.RawURLEncoding.EncodeToString(payloadBytes),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
		PublicKey: publicText,
	}, nil
}

func signedUpdateManifest(state ServerState, payload UpdateManifestPayload) (SignedUpdateManifest, error) {
	privateText, publicText := state.RevocationPrivateKey, state.RevocationPublicKey
	if privateText == "" || publicText == "" {
		privateText, publicText = state.SecurityPrivateKey, state.SecurityPublicKey
	}
	if state.UpdateKeyActive {
		privateText, publicText = state.UpdatePrivateKey, state.UpdatePublicKey
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(privateText)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return SignedUpdateManifest{}, errors.New("服务端更新签名私钥无效")
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return SignedUpdateManifest{}, err
	}
	return SignedUpdateManifest{
		Payload:   base64.RawURLEncoding.EncodeToString(payloadBytes),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(privateKey), payloadBytes)),
		PublicKey: publicText,
	}, nil
}

func verifyUpdateManifest(manifest SignedUpdateManifest, trustedPublicKey string) (UpdateManifestPayload, error) {
	if trustedPublicKey == "" {
		trustedPublicKey = manifest.PublicKey
	}
	if trustedPublicKey == "" || manifest.PublicKey != trustedPublicKey {
		return UpdateManifestPayload{}, errors.New("更新清单签名公钥不匹配")
	}
	publicKey, publicErr := base64.RawURLEncoding.DecodeString(trustedPublicKey)
	payloadBytes, payloadErr := base64.RawURLEncoding.DecodeString(manifest.Payload)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(manifest.Signature)
	if publicErr != nil || payloadErr != nil || signatureErr != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return UpdateManifestPayload{}, errors.New("更新清单签名格式无效")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payloadBytes, signature) {
		return UpdateManifestPayload{}, errors.New("更新清单签名验证失败")
	}
	var payload UpdateManifestPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return UpdateManifestPayload{}, err
	}
	if !semanticVersionPattern.MatchString(payload.Version) || payload.Platform != "windows-amd64" || !validCertificateFingerprint(payload.SHA256) || payload.Size < 1 || payload.DownloadPath != "/v1/update/package/windows-amd64" {
		return UpdateManifestPayload{}, errors.New("更新清单参数无效")
	}
	return payload, nil
}

func verifyRevocationEnvelope(envelope SignedRevocationEnvelope, trustedPublicKey string) (RevocationPayload, error) {
	if trustedPublicKey == "" {
		trustedPublicKey = envelope.PublicKey
	}
	if trustedPublicKey == "" || envelope.PublicKey != trustedPublicKey {
		return RevocationPayload{}, errors.New("吊销列表签名公钥不匹配")
	}
	publicKey, publicErr := base64.RawURLEncoding.DecodeString(trustedPublicKey)
	payloadBytes, payloadErr := base64.RawURLEncoding.DecodeString(envelope.Payload)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if publicErr != nil || payloadErr != nil || signatureErr != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return RevocationPayload{}, errors.New("吊销列表签名格式无效")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payloadBytes, signature) {
		return RevocationPayload{}, errors.New("吊销列表签名验证失败")
	}
	var payload RevocationPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return RevocationPayload{}, err
	}
	for _, item := range payload.Revocations {
		if !validCertificateFingerprint(item.Fingerprint) {
			return RevocationPayload{}, errors.New("吊销列表包含无效证书指纹")
		}
	}
	return payload, nil
}

func addCertificateRevocation(state *ServerState, name, fingerprint, reason string) bool {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if !validCertificateFingerprint(fingerprint) {
		return false
	}
	for _, item := range state.Revocations {
		if item.Fingerprint == fingerprint {
			return false
		}
	}
	if reason = strings.TrimSpace(reason); reason == "" {
		reason = "device_removed"
	}
	state.Revocations = append(state.Revocations, CertificateRevocation{
		Fingerprint: fingerprint,
		Name:        name,
		Reason:      reason,
		RevokedAt:   time.Now().UTC(),
	})
	state.RevocationVersion++
	return true
}

func revocationFingerprints(state ServerState) []string {
	values := make([]string, 0, len(state.Revocations))
	for _, item := range state.Revocations {
		values = append(values, item.Fingerprint)
	}
	return normalizedFingerprints(values)
}

func certificateFingerprint(certExecutable, certificatePath string) (string, error) {
	if strings.TrimSpace(certExecutable) == "" || strings.TrimSpace(certificatePath) == "" {
		return "", errors.New("证书工具或证书路径为空")
	}
	output, err := exec.Command(certExecutable, "print", "-path", certificatePath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("读取证书指纹失败: %s", strings.TrimSpace(string(output)))
	}
	match := certificateFingerprintPattern.FindSubmatch(output)
	if len(match) != 2 {
		return "", errors.New("证书输出中缺少 Fingerprint")
	}
	return strings.ToLower(string(match[1])), nil
}
