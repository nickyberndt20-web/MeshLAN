package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

func dnsPrefixAvailable(state *ServerState, ownerName, prefix string) bool {
	for _, peer := range state.Peers {
		if peer.Revoked || peer.Name == ownerName {
			continue
		}
		if strings.EqualFold(peer.DNSPrefix, prefix) {
			return false
		}
	}
	return true
}

func registerMeshDNSRoutes(mux *http.ServeMux, state *ServerState, stateMu *sync.Mutex, statePath string) {
	mux.HandleFunc("POST /v1/dns/prefix", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		peer := authorizedDevicePeer(state, r)
		if peer == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			Prefix string `json:"prefix"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		prefix, err := normalizeDNSPrefix(input.Prefix)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !dnsPrefixAvailable(state, peer.Name, prefix) {
			http.Error(w, "DNS前缀已被其他设备使用", http.StatusConflict)
			return
		}
		peer.DNSPrefix = prefix
		if err := saveJSON(statePath, *state); err != nil {
			http.Error(w, "state write failed", http.StatusInternalServerError)
			return
		}
		control := buildDeviceControl(state, peer.Name, time.Now().UTC())
		if envelope, signErr := signedRevocationEnvelope(*state); signErr == nil {
			control.Revocations = envelope
		}
		writeControlJSON(w, http.StatusOK, map[string]any{
			"ok": true, "prefix": prefix, "dnsName": prefix + "." + meshDNSSuffix, "control": control,
		})
	})
}
