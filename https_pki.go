package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

func randomCertificateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func certificateSHA256(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func parseMeshHTTPSCA(state ServerState) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBlock, _ := pem.Decode([]byte(state.HTTPSCACertificatePEM))
	keyBlock, _ := pem.Decode([]byte(state.HTTPSCAPrivateKeyPEM))
	if certBlock == nil || keyBlock == nil {
		return nil, nil, errors.New("MeshLAN HTTPS CA材料不完整")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !certificate.IsCA || !privateKey.PublicKey.Equal(certificate.PublicKey) {
		return nil, nil, errors.New("MeshLAN HTTPS CA证书与私钥不匹配")
	}
	return certificate, privateKey, nil
}

func ensureMeshHTTPSCA(state *ServerState) error {
	if state == nil {
		return errors.New("服务端状态为空")
	}
	if state.HTTPSCACertificatePEM != "" || state.HTTPSCAPrivateKeyPEM != "" {
		certificate, _, err := parseMeshHTTPSCA(*state)
		if err != nil {
			return err
		}
		fingerprint := certificateSHA256(certificate.Raw)
		if state.HTTPSCAFingerprint != "" && state.HTTPSCAFingerprint != fingerprint {
			return errors.New("MeshLAN HTTPS CA指纹不匹配")
		}
		state.HTTPSCAFingerprint = fingerprint
		return nil
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "MeshLAN Local HTTPS Root CA", Organization: []string{"MeshLAN"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{".mesh"},
		SubjectKeyId: []byte(state.NetworkName + "-mesh-https"),
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	keyRaw, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	state.HTTPSCACertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	state.HTTPSCAPrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw}))
	state.HTTPSCAFingerprint = certificateSHA256(raw)
	return nil
}

func normalizedMeshHTTPSNames(values []string, ownerPrefix string) ([]string, error) {
	ownerPrefix, err := normalizeDNSPrefix(ownerPrefix)
	if err != nil {
		return nil, err
	}
	ownerName := ownerPrefix + ".mesh"
	suffix := "." + ownerName
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		allowed := value == ownerName
		if strings.HasSuffix(value, suffix) {
			label := strings.TrimSuffix(value, suffix)
			_, labelErr := normalizeDNSPrefix(label)
			allowed = allowed || (labelErr == nil && !strings.Contains(label, "."))
		}
		if !allowed || strings.Contains(value, "*") {
			return nil, errors.New("HTTPS证书名称不属于当前设备的.mesh命名空间")
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	if len(result) == 0 || len(result) > 64 {
		return nil, errors.New("HTTPS证书必须包含1-64个设备域名")
	}
	sort.Strings(result)
	return result, nil
}

func issueMeshHTTPSCertificate(state ServerState, peer PeerRecord, csrPEM string) (MeshHTTPSCertificateResponse, error) {
	caCertificate, caPrivateKey, err := parseMeshHTTPSCA(state)
	if err != nil {
		return MeshHTTPSCertificateResponse{}, err
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return MeshHTTPSCertificateResponse{}, errors.New("HTTPS CSR格式无效")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return MeshHTTPSCertificateResponse{}, errors.New("HTTPS CSR签名无效")
	}
	names, err := normalizedMeshHTTPSNames(csr.DNSNames, peerDNSPrefix(state, peer))
	if err != nil {
		return MeshHTTPSCertificateResponse{}, err
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return MeshHTTPSCertificateResponse{}, err
	}
	now := time.Now().UTC()
	notAfter := now.Add(30 * 24 * time.Hour)
	if notAfter.After(caCertificate.NotAfter) {
		notAfter = caCertificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0], Organization: []string{"MeshLAN Device"}}, DNSNames: names,
		NotBefore: now.Add(-10 * time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, caCertificate, csr.PublicKey, caPrivateKey)
	if err != nil {
		return MeshHTTPSCertificateResponse{}, err
	}
	return MeshHTTPSCertificateResponse{
		CertificatePEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})),
		CACertificatePEM: state.HTTPSCACertificatePEM, CAFingerprint: state.HTTPSCAFingerprint,
		DNSNames: names, NotAfter: notAfter,
	}, nil
}

func registerMeshHTTPSRoutes(mux *http.ServeMux, state *ServerState, stateMu *sync.Mutex, statePath string) {
	mux.HandleFunc("POST /v1/https/certificate", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		peer := authorizedDevicePeer(state, r)
		if peer == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input MeshHTTPSCertificateRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := ensureMeshHTTPSCA(state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response, err := issueMeshHTTPSCertificate(*state, *peer, input.CSRPEM)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := saveJSON(statePath, state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, response)
	})
}
