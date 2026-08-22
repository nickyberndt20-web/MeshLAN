package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

const adminSessionLifetime = 30 * time.Minute

type adminSessionStore struct {
	mu          sync.Mutex
	sessions    map[string]time.Time
	pendingTOTP map[string]string
}

func newAdminSessionStore() *adminSessionStore {
	return &adminSessionStore{sessions: map[string]time.Time{}, pendingTOTP: map[string]string{}}
}

func (s *adminSessionStore) issue(now time.Time) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := now.Add(adminSessionLifetime)
	s.mu.Lock()
	defer s.mu.Unlock()
	for digest, expiry := range s.sessions {
		if !now.Before(expiry) {
			delete(s.sessions, digest)
			delete(s.pendingTOTP, digest)
		}
	}
	s.sessions[tokenDigest(token)] = expiresAt
	return token, expiresAt, nil
}

func (s *adminSessionStore) verify(token string, now time.Time) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	digest := tokenDigest(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	expiresAt, ok := s.sessions[digest]
	if !ok || !now.Before(expiresAt) {
		delete(s.sessions, digest)
		return false
	}
	return true
}

func (s *adminSessionStore) revoke(token string) {
	s.mu.Lock()
	digest := tokenDigest(strings.TrimSpace(token))
	delete(s.sessions, digest)
	delete(s.pendingTOTP, digest)
	s.mu.Unlock()
}

func (s *adminSessionStore) setPendingTOTP(token, secret string) {
	s.mu.Lock()
	s.pendingTOTP[tokenDigest(strings.TrimSpace(token))] = secret
	s.mu.Unlock()
}

func (s *adminSessionStore) pendingTOTPSecret(token string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingTOTP[tokenDigest(strings.TrimSpace(token))]
}

func (s *adminSessionStore) clearPendingTOTP(token string) {
	s.mu.Lock()
	delete(s.pendingTOTP, tokenDigest(strings.TrimSpace(token)))
	s.mu.Unlock()
}

func adminSessionTokenFromRequest(requestHeader string) string {
	return strings.TrimSpace(requestHeader)
}

func generateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func totpCode(secretText string, timestamp time.Time) (string, error) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secretText)))
	if err != nil || len(secret) < 16 {
		return "", errors.New("TOTP密钥无效")
	}
	counter := uint64(timestamp.Unix() / 30)
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 | uint32(digest[offset+1])<<16 | uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	return fmt.Sprintf("%06d", value%1000000), nil
}

func verifyTOTPCode(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for offset := -1; offset <= 1; offset++ {
		expected, err := totpCode(secret, now.Add(time.Duration(offset)*30*time.Second))
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpProvisioningURI(networkName, secret string) string {
	if networkName == "" {
		networkName = "MeshLAN"
	}
	return "otpauth://totp/" + url.PathEscape(networkName+":admin") + "?secret=" + url.QueryEscape(secret) + "&issuer=" + url.QueryEscape(networkName) + "&algorithm=SHA1&digits=6&period=30"
}

func serverEnableTOTP(args []string) error {
	fs, statePath := serverFlagSet("server enable-totp")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var state ServerState
	if err := loadJSON(*statePath, &state); err != nil {
		return err
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		return err
	}
	state.AdminTOTPSecret = secret
	state.AdminTOTPEnabled = true
	if err := saveJSON(*statePath, state); err != nil {
		return err
	}
	uri := totpProvisioningURI(state.NetworkName, secret)
	fmt.Printf("TOTP已启用\n密钥: %s\nURI: %s\n", secret, uri)
	return nil
}

func serverDisableTOTP(args []string) error {
	fs, statePath := serverFlagSet("server disable-totp")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var state ServerState
	if err := loadJSON(*statePath, &state); err != nil {
		return err
	}
	state.AdminTOTPEnabled = false
	state.AdminTOTPSecret = ""
	if err := saveJSON(*statePath, state); err != nil {
		return err
	}
	fmt.Println("TOTP已关闭；现有管理会话将在服务重启后失效")
	return nil
}
