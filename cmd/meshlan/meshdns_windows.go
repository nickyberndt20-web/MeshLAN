//go:build windows

package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"
)

func (a *clientApp) setOwnMeshDNSPrefix(value string) (MeshDNSStatus, error) {
	prefix, err := normalizeDNSPrefix(value)
	if err != nil {
		return MeshDNSStatus{}, err
	}
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil {
		return MeshDNSStatus{}, err
	}
	var response struct {
		Prefix string `json:"prefix"`
	}
	if err := deviceControlRequest(state, http.MethodPost, "/v1/dns/prefix", map[string]string{"prefix": prefix}, &response); err != nil {
		return MeshDNSStatus{}, err
	}
	a.stateMu.Lock()
	latest, loadErr := a.load()
	if loadErr == nil {
		latest.DNSPrefix = response.Prefix
		latest.MeshDNSPreferenceVersion = meshDNSPreferenceVersion
		loadErr = saveJSON(a.statePath, latest)
	}
	a.stateMu.Unlock()
	if loadErr != nil {
		return MeshDNSStatus{}, loadErr
	}
	if err := a.refreshControl(); err != nil {
		return MeshDNSStatus{}, err
	}
	return a.meshDNSStatus()
}

func meshDNSStatePath(state ClientState) string {
	return filepath.Join(filepath.Dir(state.ConfigPath), "mesh-dns-records.json")
}

func (a *clientApp) syncMeshDNS(records []MeshDNSRecord) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil {
		return err
	}
	stateChanged := applyMeshDNSPreferenceDefaults(&state)
	for _, record := range records {
		if record.Kind == "device" && record.OwnerName == state.Name && validDNSPrefix(record.OwnerPrefix) && state.DNSPrefix != record.OwnerPrefix {
			state.DNSPrefix = record.OwnerPrefix
			stateChanged = true
			break
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	var existing MeshDNSStatus
	if loadJSON(meshDNSStatePath(state), &existing) == nil && existing.Enabled == state.MeshDNSEnabled && reflect.DeepEqual(existing.Records, records) {
		if stateChanged {
			return saveJSON(a.statePath, state)
		}
		return nil
	}
	status := MeshDNSStatus{Enabled: state.MeshDNSEnabled, Suffix: meshDNSSuffix, Records: records, LastUpdated: time.Now().UTC()}
	if err := saveJSON(meshDNSStatePath(state), status); err != nil {
		return err
	}
	return saveJSON(a.statePath, state)
}

func (a *clientApp) setMeshDNSEnabled(enabled bool) error {
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		state.MeshDNSEnabled = enabled
		state.MeshDNSPreferenceVersion = meshDNSPreferenceVersion
		err = saveJSON(a.statePath, state)
	}
	a.stateMu.Unlock()
	if err != nil {
		return err
	}
	control := a.controlSnapshot()
	return a.syncMeshDNS(control.DNSRecords)
}

func (a *clientApp) meshDNSStatus() (MeshDNSStatus, error) {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil {
		return MeshDNSStatus{}, err
	}
	var status MeshDNSStatus
	if err := loadJSON(meshDNSStatePath(state), &status); err != nil && !errors.Is(err, os.ErrNotExist) {
		return MeshDNSStatus{}, err
	}
	status.Enabled = state.MeshDNSEnabled
	status.Suffix = meshDNSSuffix
	status.OwnPrefix = state.DNSPrefix
	if validDNSPrefix(state.DNSPrefix) {
		status.OwnDNSName = state.DNSPrefix + "." + meshDNSSuffix
	}
	guard := readRouteGuardStatus(state)
	status.Applied = guard.DNSRecordsApplied
	status.LastError = guard.DNSLastError
	return status, nil
}
