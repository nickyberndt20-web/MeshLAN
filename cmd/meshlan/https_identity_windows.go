//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type meshHTTPSIdentity struct {
	Version               int       `json:"version"`
	EncryptedPrivateKey   string    `json:"encryptedPrivateKey"`
	CertificatePEM        string    `json:"certificatePem"`
	CACertificatePEM      string    `json:"caCertificatePem"`
	CAFingerprint         string    `json:"caFingerprint"`
	DNSNames              []string  `json:"dnsNames"`
	NotAfter              time.Time `json:"notAfter"`
	TrustInstalled        bool      `json:"trustInstalled"`
	TrustInstallAttempted bool      `json:"trustInstallAttempted"`
	TrustInstallError     string    `json:"trustInstallError,omitempty"`
	UpdatedAt             time.Time `json:"updatedAt"`
}

type MeshHTTPSRootStatus struct {
	Available    bool              `json:"available"`
	Installed    bool              `json:"installed"`
	Fingerprint  string            `json:"fingerprint,omitempty"`
	Scope        string            `json:"scope"`
	InstallError string            `json:"installError,omitempty"`
	HTTPGateway  HTTPGatewayStatus `json:"httpGateway"`
}

func (a *clientApp) meshHTTPSIdentityPath() string {
	return filepath.Join(a.root, "mesh-https-identity.json")
}

func requiredMeshHTTPSNames(state ClientState) []string {
	values := []string{}
	seen := map[string]bool{}
	for _, mapping := range state.ServiceMappings {
		if !mapping.PortlessHTTP || normalizeMappingProtocol(mapping.Protocol) != "tcp" {
			continue
		}
		name := serviceDNSName(mapping.DNSPrefix, state.DNSPrefix)
		if !seen[name] {
			seen[name] = true
			values = append(values, name)
		}
	}
	sort.Strings(values)
	return values
}

func equalDNSNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for index := range a {
		if !strings.EqualFold(a[index], b[index]) {
			return false
		}
	}
	return true
}

func parseCertificatePEM(value string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("证书PEM格式无效")
	}
	return x509.ParseCertificate(block.Bytes)
}

func verifyMeshHTTPSResponse(response MeshHTTPSCertificateResponse, expected []string) error {
	if !equalDNSNames(response.DNSNames, expected) {
		return errors.New("HTTPS证书返回的域名集合不匹配")
	}
	ca, err := parseCertificatePEM(response.CACertificatePEM)
	if err != nil || !ca.IsCA || certificateSHA256(ca.Raw) != response.CAFingerprint {
		return errors.New("HTTPS CA证书或指纹无效")
	}
	leaf, err := parseCertificatePEM(response.CertificatePEM)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range expected {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return errors.New("HTTPS叶证书验证失败: " + err.Error())
		}
	}
	return nil
}

func installMeshHTTPSRoot(certificatePEM string) error {
	certificate, err := parseCertificatePEM(certificatePEM)
	if err != nil || !certificate.IsCA {
		return errors.New("MeshLAN HTTPS根证书无效")
	}
	if installed, checkErr := meshHTTPSRootInstalled(certificatePEM); checkErr == nil && installed {
		return nil
	}
	context, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &certificate.Raw[0], uint32(len(certificate.Raw)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(context)
	storeName, _ := windows.UTF16PtrFromString("ROOT")
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, windows.CERT_SYSTEM_STORE_CURRENT_USER|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	return windows.CertAddCertificateContextToStore(store, context, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil)
}

func meshHTTPSRootInstalled(certificatePEM string) (bool, error) {
	certificate, err := parseCertificatePEM(certificatePEM)
	if err != nil || !certificate.IsCA {
		return false, errors.New("MeshLAN HTTPS根证书无效")
	}
	storeName, _ := windows.UTF16PtrFromString("ROOT")
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, windows.CERT_SYSTEM_STORE_CURRENT_USER|windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return false, err
	}
	defer windows.CertCloseStore(store, 0)
	hash := sha1.Sum(certificate.Raw)
	blob := dataBlob(hash[:])
	context, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	if err != nil || context == nil {
		return false, nil
	}
	defer windows.CertFreeCertificateContext(context)
	return true, nil
}

func uninstallMeshHTTPSRoot(certificatePEM string) error {
	certificate, err := parseCertificatePEM(certificatePEM)
	if err != nil || !certificate.IsCA {
		return errors.New("MeshLAN HTTPS根证书无效")
	}
	hash := sha1.Sum(certificate.Raw)
	installed, err := meshHTTPSRootInstalled(certificatePEM)
	if err != nil || !installed {
		return nil
	}
	thumbprint := strings.ToUpper(hex.EncodeToString(hash[:]))
	command := exec.Command("certutil.exe", "-user", "-delstore", "Root", thumbprint)
	hidden(command)
	if err := command.Run(); err != nil {
		return errors.New("Windows拒绝删除当前用户根证书")
	}
	if installed, _ := meshHTTPSRootInstalled(certificatePEM); installed {
		return errors.New("Windows根证书删除后仍然存在")
	}
	return nil
}

func (a *clientApp) meshHTTPSRootMaterial() (string, string, error) {
	identity, identityErr := a.loadMeshHTTPSIdentity()
	if identityErr == nil && identity.CACertificatePEM != "" {
		return identity.CACertificatePEM, identity.CAFingerprint, nil
	}
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || state.Pairing == nil || state.Pairing.HTTPSCACertificatePEM == "" {
		return "", "", errors.New("尚未从主服务端同步 Mesh HTTPS根证书")
	}
	return state.Pairing.HTTPSCACertificatePEM, state.Pairing.HTTPSCAFingerprint, nil
}

func (a *clientApp) meshHTTPSRootStatus() MeshHTTPSRootStatus {
	certificate, fingerprint, err := a.meshHTTPSRootMaterial()
	status := MeshHTTPSRootStatus{Available: err == nil, Fingerprint: fingerprint, Scope: "当前 Windows 用户 · 受信任的根证书颁发机构", HTTPGateway: a.httpGatewayStatus()}
	if err != nil {
		status.InstallError = err.Error()
		return status
	}
	status.Installed, err = meshHTTPSRootInstalled(certificate)
	if err != nil {
		status.InstallError = err.Error()
	}
	return status
}

func tlsCertificateFromMeshIdentity(identity meshHTTPSIdentity) (tls.Certificate, error) {
	privateKey, err := dpapiUnprotectString(identity.EncryptedPrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	chain := identity.CertificatePEM + identity.CACertificatePEM
	return tls.X509KeyPair([]byte(chain), []byte(privateKey))
}

func (a *clientApp) loadMeshHTTPSIdentity() (meshHTTPSIdentity, error) {
	var identity meshHTTPSIdentity
	err := loadJSON(a.meshHTTPSIdentityPath(), &identity)
	return identity, err
}

func (a *clientApp) ensureMeshHTTPSIdentity(state ClientState) (tls.Certificate, meshHTTPSIdentity, error) {
	names := requiredMeshHTTPSNames(state)
	if len(names) == 0 {
		return tls.Certificate{}, meshHTTPSIdentity{}, errors.New("没有需要HTTPS证书的服务域名")
	}
	identity, loadErr := a.loadMeshHTTPSIdentity()
	if loadErr == nil && identity.Version == 1 && equalDNSNames(identity.DNSNames, names) && time.Until(identity.NotAfter) > 7*24*time.Hour {
		installed, checkErr := meshHTTPSRootInstalled(identity.CACertificatePEM)
		if checkErr == nil && installed {
			identity.TrustInstalled, identity.TrustInstallError = true, ""
			if certificate, certErr := tlsCertificateFromMeshIdentity(identity); certErr == nil {
				return certificate, identity, nil
			}
		}
		if identity.TrustInstallAttempted {
			return tls.Certificate{}, identity, errors.New("MeshLAN HTTPS根证书尚未受信任；需要在客户端中手动重试安装")
		}
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, identity, err
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, privateKey)
	if err != nil {
		return tls.Certificate{}, identity, err
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrRaw}))
	var response MeshHTTPSCertificateResponse
	if err := deviceControlRequest(state, "POST", "/v1/https/certificate", MeshHTTPSCertificateRequest{CSRPEM: csrPEM}, &response); err != nil {
		return tls.Certificate{}, identity, err
	}
	if identity.CAFingerprint != "" && identity.CAFingerprint != response.CAFingerprint {
		return tls.Certificate{}, identity, errors.New("MeshLAN HTTPS CA发生未授权变化")
	}
	if err := verifyMeshHTTPSResponse(response, names); err != nil {
		return tls.Certificate{}, identity, err
	}
	keyRaw, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, identity, err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw}))
	encryptedKey, err := dpapiProtectString(keyPEM)
	if err != nil {
		return tls.Certificate{}, identity, err
	}
	identity = meshHTTPSIdentity{
		Version: 1, EncryptedPrivateKey: encryptedKey, CertificatePEM: response.CertificatePEM,
		CACertificatePEM: response.CACertificatePEM, CAFingerprint: response.CAFingerprint,
		DNSNames: response.DNSNames, NotAfter: response.NotAfter, UpdatedAt: time.Now().UTC(), TrustInstallAttempted: true,
	}
	if err := saveJSON(a.meshHTTPSIdentityPath(), identity); err != nil {
		return tls.Certificate{}, identity, err
	}
	if err := installMeshHTTPSRoot(identity.CACertificatePEM); err != nil {
		identity.TrustInstallError = err.Error()
		_ = saveJSON(a.meshHTTPSIdentityPath(), identity)
		return tls.Certificate{}, identity, err
	}
	identity.TrustInstalled, identity.TrustInstallError = true, ""
	if err := saveJSON(a.meshHTTPSIdentityPath(), identity); err != nil {
		return tls.Certificate{}, identity, err
	}
	certificate, err := tlsCertificateFromMeshIdentity(identity)
	return certificate, identity, err
}

func meshHTTPSPrivateKeyIsEncrypted(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && !strings.Contains(string(data), "PRIVATE KEY")
}

func (a *clientApp) retryMeshHTTPSRootTrust() (HTTPGatewayStatus, error) {
	certificatePEM, _, err := a.meshHTTPSRootMaterial()
	if err != nil {
		return a.httpGatewayStatus(), err
	}
	identity, identityErr := a.loadMeshHTTPSIdentity()
	if err := installMeshHTTPSRoot(certificatePEM); err != nil {
		if identityErr != nil {
			return a.httpGatewayStatus(), err
		}
		if identityErr == nil {
			identity.TrustInstallAttempted = true
			identity.TrustInstalled = false
			identity.TrustInstallError = err.Error()
			_ = saveJSON(a.meshHTTPSIdentityPath(), identity)
		}
		return a.httpGatewayStatus(), err
	}
	installed, err := meshHTTPSRootInstalled(certificatePEM)
	if err != nil || !installed {
		if err == nil {
			err = errors.New("Windows未确认根证书安装")
		}
		if identityErr == nil {
			identity.TrustInstallAttempted = true
			identity.TrustInstalled = false
			identity.TrustInstallError = err.Error()
			_ = saveJSON(a.meshHTTPSIdentityPath(), identity)
		}
		return a.httpGatewayStatus(), err
	}
	if identityErr == nil {
		identity.TrustInstallAttempted = true
		identity.TrustInstalled = true
		identity.TrustInstallError = ""
		identity.UpdatedAt = time.Now().UTC()
		if err := saveJSON(a.meshHTTPSIdentityPath(), identity); err != nil {
			return a.httpGatewayStatus(), err
		}
	}
	if err := a.syncHTTPGateway(); err != nil {
		return a.httpGatewayStatus(), err
	}
	return a.httpGatewayStatus(), nil
}

func (a *clientApp) removeMeshHTTPSRootTrust() (MeshHTTPSRootStatus, error) {
	certificatePEM, _, err := a.meshHTTPSRootMaterial()
	if err != nil {
		return a.meshHTTPSRootStatus(), err
	}
	if err := uninstallMeshHTTPSRoot(certificatePEM); err != nil {
		return a.meshHTTPSRootStatus(), err
	}
	if identity, loadErr := a.loadMeshHTTPSIdentity(); loadErr == nil {
		identity.TrustInstalled = false
		identity.TrustInstallAttempted = true
		identity.TrustInstallError = ""
		identity.UpdatedAt = time.Now().UTC()
		_ = saveJSON(a.meshHTTPSIdentityPath(), identity)
	}
	_ = a.syncHTTPGateway()
	return a.meshHTTPSRootStatus(), nil
}

func (a *clientApp) beginMeshHTTPSRootRemoval() error {
	certificatePEM, _, err := a.meshHTTPSRootMaterial()
	if err != nil {
		return err
	}
	certificate, err := parseCertificatePEM(certificatePEM)
	if err != nil {
		return err
	}
	hash := sha1.Sum(certificate.Raw)
	thumbprint := strings.ToUpper(hex.EncodeToString(hash[:]))
	script := "$null=Start-Process -FilePath 'certutil.exe' -ArgumentList @('-user','-delstore','Root','" + thumbprint + "') -WindowStyle Normal"
	command := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", script)
	hidden(command)
	return command.Start()
}
