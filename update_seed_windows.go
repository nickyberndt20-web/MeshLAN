//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const updateSeedPort = 24444

type updateSeedRuntime struct {
	listener net.Listener
	server   *http.Server
	address  string
	sha256   string
	size     int64
	lastErr  string
}

func (a *clientApp) updateSeedHandler(runtime *updateSeedRuntime, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	expectedPath := "/.meshlan/update/" + runtime.sha256
	if r.URL.Path != expectedPath {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(a.executable)
	if err != nil {
		http.Error(w, "update seed unavailable", http.StatusServiceUnavailable)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() != runtime.size {
		http.Error(w, "update seed changed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="MeshLAN-Nebula-Windows-%s.exe"`, clientVersionNumber()))
	w.Header().Set("X-Content-SHA256", runtime.sha256)
	w.Header().Set("X-MeshLAN-Update-Seed", "p2p")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, filepath.Base(a.executable), info.ModTime(), file)
}

func (a *clientApp) syncUpdateSeed() error {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || state.Pairing == nil || a.executable == "" {
		return err
	}
	meshIP, _, err := meshAddressDetails(state)
	if err != nil {
		return err
	}
	hash, size, err := fileSHA256(a.executable)
	if err != nil {
		return err
	}
	address := net.JoinHostPort(meshIP, fmt.Sprintf("%d", updateSeedPort))
	a.updateSeedMu.Lock()
	defer a.updateSeedMu.Unlock()
	if current := a.updateSeedRuntime; current != nil && current.listener != nil && current.address == address && strings.EqualFold(current.sha256, hash) {
		return nil
	}
	if current := a.updateSeedRuntime; current != nil && current.server != nil {
		_ = current.server.Close()
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		a.updateSeedRuntime = &updateSeedRuntime{address: address, sha256: hash, size: size, lastErr: err.Error()}
		return err
	}
	runtime := &updateSeedRuntime{listener: listener, address: address, sha256: hash, size: size}
	server := &http.Server{ReadHeaderTimeout: 8 * time.Second, IdleTimeout: 10 * time.Minute}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { a.updateSeedHandler(runtime, w, r) })
	runtime.server = server
	a.updateSeedRuntime = runtime
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			a.updateSeedMu.Lock()
			if a.updateSeedRuntime == runtime {
				runtime.listener = nil
				runtime.lastErr = serveErr.Error()
			}
			a.updateSeedMu.Unlock()
		}
	}()
	return nil
}

func (a *clientApp) updateSeedStatus() (ready bool, sha256 string, port int) {
	a.updateSeedMu.Lock()
	defer a.updateSeedMu.Unlock()
	if a.updateSeedRuntime == nil || a.updateSeedRuntime.listener == nil {
		return false, "", 0
	}
	return true, a.updateSeedRuntime.sha256, updateSeedPort
}

func (a *clientApp) updateSeedLoop() {
	_ = a.syncUpdateSeed()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_ = a.syncUpdateSeed()
	}
}
