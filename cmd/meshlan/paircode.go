package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

const pairingPrefix = "MLN1."

type pairingPayload struct {
	Version int    `json:"v"`
	ID      string `json:"i"`
	Secret  string `json:"s"`
	Pin     string `json:"p"`
	Port    int    `json:"c"`
}

func generateTLSIdentity(endpoint string) (certificatePEM, privateKeyPEM, pin string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}
	host := endpoint
	if parsedHost, _, splitErr := net.SplitHostPort(endpoint); splitErr == nil {
		host = strings.Trim(parsedHost, "[]")
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "MeshLAN Nebula Enrollment"},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", "", err
	}
	privateDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})), base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func tokenDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func issueAdminToken(state *ServerState) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	state.AdminTokenHash = tokenDigest(token)
	return token, nil
}

func verifyAdminToken(state ServerState, token string) bool {
	actual := tokenDigest(strings.TrimSpace(token))
	return state.AdminTokenHash != "" && subtle.ConstantTimeCompare([]byte(actual), []byte(state.AdminTokenHash)) == 1
}

func issuePairingCode(state *ServerState) (string, error) {
	return issueEnrollmentCode(state, "default", 24*time.Hour)
}

func issueEnrollmentCode(state *ServerState, label string, lifetime time.Duration) (string, error) {
	if state.TLSCertificatePEM == "" {
		certificate, privateKey, pin, err := generateTLSIdentity(state.PublicEndpoint)
		if err != nil {
			return "", err
		}
		state.TLSCertificatePEM, state.TLSPrivateKeyPEM, state.TLSCertificatePin = certificate, privateKey, pin
	}
	secretText, err := randomToken(32)
	if err != nil {
		return "", err
	}
	id, err := randomToken(12)
	if err != nil {
		return "", err
	}
	record := EnrollmentRecord{ID: id, Label: label, SecretHash: tokenDigest(secretText), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(lifetime)}
	state.Enrollments = append(state.Enrollments, record)
	state.PairingSecretHash = record.SecretHash
	payload := pairingPayload{Version: protocolVersion, ID: id, Secret: secretText, Pin: state.TLSCertificatePin, Port: state.PairingPort}
	data, _ := json.Marshal(payload)
	return pairingPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func issueRekeyCode(state *ServerState, peer PeerRecord, lifetime time.Duration) (string, error) {
	code, err := issueEnrollmentCode(state, "rekey-"+peer.Name, lifetime)
	if err != nil {
		return "", err
	}
	record := &state.Enrollments[len(state.Enrollments)-1]
	record.Rekey = true
	record.BoundName = peer.Name
	record.ReservedAddress = peer.Address
	return code, nil
}

func parsePairingCode(value string) (pairingPayload, error) {
	if !strings.HasPrefix(strings.TrimSpace(value), pairingPrefix) {
		return pairingPayload{}, errors.New("配对哈希格式无效")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(value), pairingPrefix))
	if err != nil {
		return pairingPayload{}, err
	}
	var payload pairingPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return pairingPayload{}, err
	}
	secret, secretErr := base64.RawURLEncoding.DecodeString(payload.Secret)
	pin, pinErr := base64.RawURLEncoding.DecodeString(payload.Pin)
	if payload.Version != protocolVersion || payload.ID == "" || secretErr != nil || len(secret) != 32 || pinErr != nil || len(pin) != sha256.Size || payload.Port < 1 || payload.Port > 65535 {
		return pairingPayload{}, errors.New("配对哈希参数无效")
	}
	return payload, nil
}

func findEnrollment(state *ServerState, id, secret string) *EnrollmentRecord {
	digest := tokenDigest(secret)
	for i := range state.Enrollments {
		record := &state.Enrollments[i]
		if record.ID == id && !record.Revoked && time.Now().Before(record.ExpiresAt) && subtle.ConstantTimeCompare([]byte(digest), []byte(record.SecretHash)) == 1 {
			return record
		}
	}
	return nil
}

func pinnedTLSConfig(pinText string) (*tls.Config, error) {
	pin, err := base64.RawURLEncoding.DecodeString(pinText)
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("TLS pin 无效")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyConnection: func(connection tls.ConnectionState) error {
			if len(connection.PeerCertificates) != 1 {
				return errors.New("配对服务证书链异常")
			}
			actual := sha256.Sum256(connection.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], pin) != 1 {
				return errors.New("配对服务证书指纹不匹配")
			}
			return nil
		},
	}, nil
}

func pairingAddress(server string, port int) string {
	server = strings.Trim(strings.TrimSpace(server), "[]")
	if host, _, err := net.SplitHostPort(server); err == nil {
		server = strings.Trim(host, "[]")
	}
	return net.JoinHostPort(server, strconv.Itoa(port))
}
