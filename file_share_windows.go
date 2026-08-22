//go:build windows

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	fileSharePort    = 24443
	maxFileShareSize = int64(20 << 30)
)

type FileTransferReceipt struct {
	UserName    string    `json:"userName"`
	Address     string    `json:"address"`
	CompletedAt time.Time `json:"completedAt"`
	Bytes       int64     `json:"bytes"`
	Status      string    `json:"status"`
}

type LocalFileShare struct {
	ID             string                `json:"id"`
	FileName       string                `json:"fileName"`
	StoragePath    string                `json:"storagePath"`
	Size           int64                 `json:"size"`
	SHA256         string                `json:"sha256"`
	EncryptedToken string                `json:"encryptedToken"`
	RecipientName  string                `json:"recipientName,omitempty"`
	CreatedAt      time.Time             `json:"createdAt"`
	ExpiresAt      time.Time             `json:"expiresAt"`
	MaxDownloads   int                   `json:"maxDownloads"`
	DownloadCount  int                   `json:"downloadCount"`
	ContentRemoved bool                  `json:"contentRemoved"`
	Receipts       []FileTransferReceipt `json:"receipts,omitempty"`
}

type fileShareStore struct {
	Version int              `json:"version"`
	Shares  []LocalFileShare `json:"shares"`
}

type LocalFileShareView struct {
	ID             string                `json:"id"`
	FileName       string                `json:"fileName"`
	Size           int64                 `json:"size"`
	SHA256         string                `json:"sha256"`
	RecipientName  string                `json:"recipientName,omitempty"`
	CreatedAt      time.Time             `json:"createdAt"`
	ExpiresAt      time.Time             `json:"expiresAt"`
	MaxDownloads   int                   `json:"maxDownloads"`
	DownloadCount  int                   `json:"downloadCount"`
	Available      bool                  `json:"available"`
	ContentRemoved bool                  `json:"contentRemoved"`
	Receipts       []FileTransferReceipt `json:"receipts"`
}

type FileSharePageResponse struct {
	Local       []LocalFileShareView      `json:"local"`
	Received    []FileShareDirectoryEntry `json:"received"`
	ServerReady bool                      `json:"serverReady"`
	Address     string                    `json:"address,omitempty"`
	LastError   string                    `json:"lastError,omitempty"`
	RefreshedAt time.Time                 `json:"refreshedAt"`
}

type fileShareRuntime struct {
	listener  net.Listener
	server    *http.Server
	address   string
	lastError string
}

func validSharedFileName(value string) bool {
	value = strings.TrimSpace(value)
	if !validFileShareName(value) || value != filepath.Base(value) {
		return false
	}
	return true
}

func (a *clientApp) fileShareStorePath() string   { return filepath.Join(a.root, "file-shares.json") }
func (a *clientApp) fileShareContentRoot() string { return filepath.Join(a.root, "shares") }

func (a *clientApp) loadFileShareStore() (fileShareStore, error) {
	var store fileShareStore
	err := loadJSON(a.fileShareStorePath(), &store)
	if errors.Is(err, os.ErrNotExist) {
		return fileShareStore{Version: 1, Shares: []LocalFileShare{}}, nil
	}
	if store.Shares == nil {
		store.Shares = []LocalFileShare{}
	}
	return store, err
}

func (a *clientApp) saveFileShareStore(store fileShareStore) error {
	store.Version = 1
	return saveJSON(a.fileShareStorePath(), store)
}

func localFileShareView(share LocalFileShare, now time.Time) LocalFileShareView {
	available := !share.ContentRemoved && now.Before(share.ExpiresAt) && share.DownloadCount < share.MaxDownloads
	return LocalFileShareView{ID: share.ID, FileName: share.FileName, Size: share.Size, SHA256: share.SHA256, RecipientName: share.RecipientName, CreatedAt: share.CreatedAt, ExpiresAt: share.ExpiresAt, MaxDownloads: share.MaxDownloads, DownloadCount: share.DownloadCount, Available: available, ContentRemoved: share.ContentRemoved, Receipts: append([]FileTransferReceipt(nil), share.Receipts...)}
}

func (a *clientApp) cleanupFileSharesLocked(store *fileShareStore, now time.Time) bool {
	changed := false
	kept := store.Shares[:0]
	for index := range store.Shares {
		share := &store.Shares[index]
		if (!share.ExpiresAt.After(now) || share.DownloadCount >= share.MaxDownloads) && !share.ContentRemoved {
			_ = os.Remove(share.StoragePath)
			share.ContentRemoved = true
			changed = true
		}
		if share.ContentRemoved && now.Sub(share.ExpiresAt) > 7*24*time.Hour {
			changed = true
			continue
		}
		kept = append(kept, *share)
	}
	store.Shares = kept
	return changed
}

func (a *clientApp) createFileShare(reader io.Reader, fileName, recipient string, lifetime time.Duration, maxDownloads int) (LocalFileShareView, error) {
	fileName, recipient = strings.TrimSpace(fileName), strings.TrimSpace(recipient)
	if !validSharedFileName(fileName) {
		return LocalFileShareView{}, errors.New("文件名无效或过长")
	}
	if lifetime < 10*time.Minute || lifetime > 30*24*time.Hour {
		return LocalFileShareView{}, errors.New("有效期必须在10分钟到30天之间")
	}
	if maxDownloads < 1 || maxDownloads > 1000 {
		return LocalFileShareView{}, errors.New("允许下载次数必须在1-1000之间")
	}
	if recipient != "" {
		known := false
		for _, peer := range a.controlSnapshot().Peers {
			if peer.Name == recipient {
				known = true
				break
			}
		}
		if !known {
			return LocalFileShareView{}, errors.New("接收设备不存在")
		}
	}
	id, err := randomToken(12)
	if err != nil {
		return LocalFileShareView{}, err
	}
	token, err := randomToken(32)
	if err != nil {
		return LocalFileShareView{}, err
	}
	encryptedToken, err := dpapiProtectString(token)
	if err != nil {
		return LocalFileShareView{}, err
	}
	if err := os.MkdirAll(a.fileShareContentRoot(), 0o700); err != nil {
		return LocalFileShareView{}, err
	}
	path := filepath.Join(a.fileShareContentRoot(), id+".bin")
	temporary := path + ".part"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return LocalFileShareView{}, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, maxFileShareSize+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > maxFileShareSize {
		_ = os.Remove(temporary)
		if written > maxFileShareSize {
			return LocalFileShareView{}, errors.New("单个分享文件不能超过20GB")
		}
		if copyErr != nil {
			return LocalFileShareView{}, copyErr
		}
		return LocalFileShareView{}, closeErr
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return LocalFileShareView{}, err
	}
	now := time.Now().UTC()
	share := LocalFileShare{ID: id, FileName: fileName, StoragePath: path, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil)), EncryptedToken: encryptedToken, RecipientName: recipient, CreatedAt: now, ExpiresAt: now.Add(lifetime), MaxDownloads: maxDownloads, Receipts: []FileTransferReceipt{}}
	a.fileShareMu.Lock()
	store, err := a.loadFileShareStore()
	if err == nil {
		store.Shares = append(store.Shares, share)
		err = a.saveFileShareStore(store)
	}
	a.fileShareMu.Unlock()
	if err != nil {
		_ = os.Remove(path)
		return LocalFileShareView{}, err
	}
	_ = a.syncFileShareServer()
	go a.sendHeartbeat()
	return localFileShareView(share, now), nil
}

func (a *clientApp) deleteFileShare(id string) error {
	a.fileShareMu.Lock()
	defer a.fileShareMu.Unlock()
	store, err := a.loadFileShareStore()
	if err != nil {
		return err
	}
	found := false
	kept := store.Shares[:0]
	for _, share := range store.Shares {
		if share.ID == id {
			found = true
			_ = os.Remove(share.StoragePath)
			continue
		}
		kept = append(kept, share)
	}
	if !found {
		return errors.New("文件分享不存在")
	}
	store.Shares = kept
	return a.saveFileShareStore(store)
}

func (a *clientApp) fileShareHeartbeat() []FileShareHeartbeat {
	a.fileShareMu.Lock()
	defer a.fileShareMu.Unlock()
	store, err := a.loadFileShareStore()
	if err != nil {
		return nil
	}
	now := time.Now().UTC()
	if a.cleanupFileSharesLocked(&store, now) {
		_ = a.saveFileShareStore(store)
	}
	result := []FileShareHeartbeat{}
	for _, share := range store.Shares {
		if share.ContentRemoved || !share.ExpiresAt.After(now) || share.DownloadCount >= share.MaxDownloads {
			continue
		}
		token, err := dpapiUnprotectString(share.EncryptedToken)
		if err != nil {
			continue
		}
		result = append(result, FileShareHeartbeat{ID: share.ID, FileName: share.FileName, Size: share.Size, SHA256: share.SHA256, RecipientName: share.RecipientName, ExpiresAt: share.ExpiresAt, MaxDownloads: share.MaxDownloads, DownloadCount: share.DownloadCount, AccessToken: token})
	}
	return result
}

func (a *clientApp) findFileShareForRequest(id, token, remoteAddress string) (LocalFileShare, string, error) {
	a.fileShareMu.Lock()
	defer a.fileShareMu.Unlock()
	store, err := a.loadFileShareStore()
	if err != nil {
		return LocalFileShare{}, "", err
	}
	now := time.Now().UTC()
	for _, share := range store.Shares {
		if share.ID != id {
			continue
		}
		plain, err := dpapiUnprotectString(share.EncryptedToken)
		if err != nil || subtle.ConstantTimeCompare([]byte(plain), []byte(token)) != 1 {
			return LocalFileShare{}, "", errors.New("分享口令无效")
		}
		userName := a.remoteUserName(remoteAddress)
		if userName == remoteAddress || (share.RecipientName != "" && share.RecipientName != userName) {
			return LocalFileShare{}, userName, errors.New("当前设备无权接收此文件")
		}
		if share.ContentRemoved || !share.ExpiresAt.After(now) || share.DownloadCount+a.fileReservations[id] >= share.MaxDownloads {
			return LocalFileShare{}, userName, errors.New("分享已过期或下载次数已用完")
		}
		a.fileReservations[id]++
		return share, userName, nil
	}
	return LocalFileShare{}, "", errors.New("文件分享不存在")
}

func (a *clientApp) finishFileTransfer(id, userName, address string, bytes int64, succeeded bool) {
	a.fileShareMu.Lock()
	defer a.fileShareMu.Unlock()
	if a.fileReservations[id] > 0 {
		a.fileReservations[id]--
	}
	store, err := a.loadFileShareStore()
	if err != nil {
		return
	}
	for index := range store.Shares {
		share := &store.Shares[index]
		if share.ID != id {
			continue
		}
		status := "interrupted"
		if succeeded && bytes == share.Size {
			status = "received"
			share.DownloadCount++
		}
		share.Receipts = append(share.Receipts, FileTransferReceipt{UserName: userName, Address: address, CompletedAt: time.Now().UTC(), Bytes: bytes, Status: status})
		if len(share.Receipts) > 100 {
			share.Receipts = share.Receipts[len(share.Receipts)-100:]
		}
		if share.DownloadCount >= share.MaxDownloads {
			_ = os.Remove(share.StoragePath)
			share.ContentRemoved = true
		}
		_ = a.saveFileShareStore(store)
		go a.sendHeartbeat()
		return
	}
}

func (a *clientApp) fileShareHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/.meshlan/files/") {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/.meshlan/files/")
	remoteAddress, _, _ := net.SplitHostPort(r.RemoteAddr)
	share, userName, err := a.findFileShareForRequest(id, r.URL.Query().Get("token"), remoteAddress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	file, err := os.Open(share.StoragePath)
	if err != nil {
		a.finishFileTransfer(id, userName, remoteAddress, 0, false)
		http.Error(w, "文件内容不可用", http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(share.Size, 10))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": share.FileName}))
	w.Header().Set("X-MeshLAN-SHA256", share.SHA256)
	w.Header().Set("Cache-Control", "no-store")
	written, copyErr := io.Copy(w, file)
	closeErr := file.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	a.finishFileTransfer(id, userName, remoteAddress, written, copyErr == nil)
}

func (a *clientApp) syncFileShareServer() error {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || state.Pairing == nil {
		return err
	}
	active := len(a.fileShareHeartbeat()) > 0
	a.fileShareMu.Lock()
	defer a.fileShareMu.Unlock()
	if !active {
		if a.fileShareRuntime != nil && a.fileShareRuntime.server != nil {
			_ = a.fileShareRuntime.server.Close()
		}
		a.fileShareRuntime = nil
		return nil
	}
	meshIP, _, err := meshAddressDetails(state)
	if err != nil {
		return err
	}
	address := net.JoinHostPort(meshIP, strconv.Itoa(fileSharePort))
	if a.fileShareRuntime != nil && a.fileShareRuntime.listener != nil && a.fileShareRuntime.address == address {
		return nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		a.fileShareRuntime = &fileShareRuntime{address: address, lastError: err.Error()}
		return err
	}
	server := &http.Server{Handler: http.HandlerFunc(a.fileShareHandler), ReadHeaderTimeout: 8 * time.Second, IdleTimeout: 2 * time.Minute}
	a.fileShareRuntime = &fileShareRuntime{listener: listener, server: server, address: address}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			a.fileShareMu.Lock()
			if a.fileShareRuntime != nil && a.fileShareRuntime.server == server {
				a.fileShareRuntime.listener = nil
				a.fileShareRuntime.lastError = serveErr.Error()
			}
			a.fileShareMu.Unlock()
		}
	}()
	return nil
}

func (a *clientApp) fileShareStatus() (ready bool, address, lastError string) {
	a.fileShareMu.Lock()
	defer a.fileShareMu.Unlock()
	if a.fileShareRuntime == nil {
		return false, "", ""
	}
	return a.fileShareRuntime.listener != nil, a.fileShareRuntime.address, a.fileShareRuntime.lastError
}

func (a *clientApp) fileSharePage() (FileSharePageResponse, error) {
	a.fileShareMu.Lock()
	store, err := a.loadFileShareStore()
	if err != nil {
		a.fileShareMu.Unlock()
		return FileSharePageResponse{}, err
	}
	now := time.Now().UTC()
	if a.cleanupFileSharesLocked(&store, now) {
		_ = a.saveFileShareStore(store)
	}
	local := make([]LocalFileShareView, 0, len(store.Shares))
	for _, share := range store.Shares {
		local = append(local, localFileShareView(share, now))
	}
	a.fileShareMu.Unlock()
	a.stateMu.Lock()
	state, stateErr := a.load()
	a.stateMu.Unlock()
	received := []FileShareDirectoryEntry{}
	if stateErr == nil && state.Pairing != nil {
		if directory, directoryErr := fetchPeerDirectory(state); directoryErr == nil {
			for _, file := range directory.Files {
				if file.OwnerName != state.Name {
					received = append(received, file)
				}
			}
		}
	}
	sort.Slice(local, func(i, j int) bool { return local[i].CreatedAt.After(local[j].CreatedAt) })
	ready, address, lastError := a.fileShareStatus()
	return FileSharePageResponse{Local: local, Received: received, ServerReady: ready, Address: address, LastError: lastError, RefreshedAt: now}, nil
}

func (a *clientApp) proxyFileShareDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	directory, err := fetchPeerDirectory(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	var selected *FileShareDirectoryEntry
	for index := range directory.Files {
		if directory.Files[index].ID == id && directory.Files[index].OwnerName != state.Name {
			copy := directory.Files[index]
			selected = &copy
			break
		}
	}
	if selected == nil {
		http.Error(w, "文件分享不存在或已过期", http.StatusNotFound)
		return
	}
	parsed, err := url.Parse(selected.DownloadURL)
	if err != nil || parsed.Scheme != "http" {
		http.Error(w, "文件直传地址无效", http.StatusBadGateway)
		return
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 0}
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, selected.DownloadURL, nil)
	response, err := client.Do(request)
	if err != nil {
		http.Error(w, "P2P文件连接失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		http.Error(w, strings.TrimSpace(string(message)), response.StatusCode)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(selected.Size, 10))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": selected.FileName}))
	w.Header().Set("X-MeshLAN-SHA256", selected.SHA256)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, response.Body)
}

func (a *clientApp) fileShareLoop() {
	_ = a.syncFileShareServer()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_ = a.syncFileShareServer()
	}
}

func parseFileShareLifetime(value string) time.Duration {
	hours, _ := strconv.Atoi(strings.TrimSpace(value))
	if hours < 1 {
		hours = 24
	}
	return time.Duration(hours) * time.Hour
}

func fileShareSafeID(value string) bool {
	return len(value) >= 8 && len(value) <= 64 && !strings.ContainsAny(value, `/\\?&`)
}

func formatFileShareError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("文件分享失败: %w", err)
}
