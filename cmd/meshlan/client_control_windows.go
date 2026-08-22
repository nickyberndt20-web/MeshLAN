//go:build windows

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func deviceControlRequest(state ClientState, method, path string, input any, output any) error {
	return deviceControlRequestWithTimeout(state, method, path, input, output, 20*time.Second)
}

func deviceControlStreamRequest(state ClientState, path string, input any, timeout time.Duration, onEvent func(string, []byte) error) error {
	if state.Pairing == nil || state.Pairing.DeviceToken == "" || state.Pairing.ControlPin == "" {
		return errors.New("本机尚未完成配对")
	}
	tlsConfig, err := pinnedTLSConfig(state.Pairing.ControlPin)
	if err != nil {
		return err
	}
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	url := "https://" + pairingAddress(state.Pairing.ControlHost, state.Pairing.ControlPort) + path
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "MeshLAN-Device "+state.Name+":"+state.Pairing.DeviceToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}, Timeout: timeout}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("控制请求失败 HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 32<<10), 2<<20)
	event, payload := "message", []byte(nil)
	dispatch := func() error {
		if len(payload) == 0 {
			return nil
		}
		err := onEvent(event, payload)
		event, payload = "message", nil
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := dispatch(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			payload = append(payload, []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))...)
		}
	}
	if err := dispatch(); err != nil {
		return err
	}
	return scanner.Err()
}

func deviceControlRequestWithTimeout(state ClientState, method, path string, input any, output any, timeout time.Duration) error {
	if state.Pairing == nil || state.Pairing.DeviceToken == "" || state.Pairing.ControlPin == "" {
		return errors.New("本机尚未完成配对")
	}
	tlsConfig, err := pinnedTLSConfig(state.Pairing.ControlPin)
	if err != nil {
		return err
	}
	var body io.Reader
	if input != nil {
		data, marshalErr := json.Marshal(input)
		if marshalErr != nil {
			return marshalErr
		}
		body = bytes.NewReader(data)
	}
	url := "https://" + pairingAddress(state.Pairing.ControlHost, state.Pairing.ControlPort) + path
	request, _ := http.NewRequest(method, url, body)
	request.Header.Set("Authorization", "MeshLAN-Device "+state.Name+":"+state.Pairing.DeviceToken)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}, Timeout: timeout}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("控制请求失败 HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	if output != nil && len(responseBody) > 0 {
		return json.Unmarshal(responseBody, output)
	}
	return nil
}

func fetchDeviceControl(state ClientState) (DeviceControlResponse, error) {
	var control DeviceControlResponse
	err := deviceControlRequest(state, http.MethodGet, "/v1/control", nil, &control)
	return control, err
}

func (a *clientApp) refreshControl() error {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil {
		return err
	}
	control, err := fetchDeviceControl(state)
	if err != nil {
		return err
	}
	if control.Revocations.Payload != "" {
		if _, err := a.applyRevocationEnvelope(control.Revocations); err != nil {
			return err
		}
	}
	if err := a.syncMeshDNS(control.DNSRecords); err != nil {
		return err
	}
	a.controlMu.Lock()
	a.control = control
	a.controlMu.Unlock()
	return nil
}

func (a *clientApp) controlSnapshot() DeviceControlResponse {
	a.controlMu.RLock()
	defer a.controlMu.RUnlock()
	data, _ := json.Marshal(a.control)
	var copy DeviceControlResponse
	_ = json.Unmarshal(data, &copy)
	return copy
}

func (a *clientApp) remoteUserName(address string) string {
	a.controlMu.RLock()
	defer a.controlMu.RUnlock()
	for _, peer := range a.control.Peers {
		if peer.Address == address {
			return peer.Name
		}
	}
	return address
}

func (a *clientApp) remoteAllowed(mappingID, ownerName string, approvalRequired bool, address string) (bool, string) {
	a.controlMu.RLock()
	defer a.controlMu.RUnlock()
	userName := address
	for _, peer := range a.control.Peers {
		if peer.Address == address {
			userName = peer.Name
			break
		}
	}
	if userName == ownerName {
		return true, userName
	}
	for _, policy := range a.control.Policies {
		if policy.MappingID != mappingID {
			continue
		}
		for _, user := range policy.Users {
			if user.Address != address {
				continue
			}
			if user.Status == "paused" {
				return false, userName
			}
			if approvalRequired {
				return user.Status == "approved" || user.Status == "open", userName
			}
			return true, userName
		}
		break
	}
	return !approvalRequired, userName
}

func (a *clientApp) controlLoop() {
	_ = a.refreshControl()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_ = a.refreshControl()
	}
}
