//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

type ProxyCompatibilityStatus struct {
	Enabled       bool `json:"enabled"`
	Applied       bool `json:"applied"`
	MeshBypass    bool `json:"meshBypass"`
	NoProxyBypass bool `json:"noProxyBypass"`
}

var internetSetOptionW = windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")

func splitProxyValues(value, separator string) []string {
	parts := strings.Split(value, separator)
	result := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || seen[strings.ToLower(part)] {
			continue
		}
		seen[strings.ToLower(part)] = true
		result = append(result, part)
	}
	return result
}

func mergeProxyValues(value, separator string, additions []string, enabled bool) string {
	managed := map[string]bool{}
	for _, item := range additions {
		managed[strings.ToLower(item)] = true
	}
	values := make([]string, 0)
	for _, item := range splitProxyValues(value, separator) {
		if !managed[strings.ToLower(item)] {
			values = append(values, item)
		}
	}
	if enabled {
		values = append(values, additions...)
	}
	return strings.Join(values, separator)
}

func registryStringValue(path, name string) string {
	command := exec.Command("reg.exe", "query", `HKCU\`+path, "/v", name)
	hidden(command)
	output, err := command.Output()
	if err != nil {
		return ""
	}
	text := string(output)
	for _, marker := range []string{"REG_EXPAND_SZ", "REG_SZ"} {
		if index := strings.Index(text, marker); index >= 0 {
			return strings.TrimSpace(text[index+len(marker):])
		}
	}
	return ""
}

func setRegistryStringValue(path, name, value string) error {
	var command *exec.Cmd
	if value == "" {
		command = exec.Command("reg.exe", "delete", `HKCU\`+path, "/v", name, "/f")
	} else {
		command = exec.Command("reg.exe", "add", `HKCU\`+path, "/v", name, "/t", "REG_SZ", "/d", value, "/f")
	}
	hidden(command)
	if err := command.Run(); err != nil && value != "" {
		return err
	}
	return nil
}

func applyMeshProxyBypass(enabled bool) error {
	const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	const environment = `Environment`
	proxyAdditions := []string{"*.mesh", "10.77.*"}
	noProxyAdditions := []string{".mesh", "10.77.0.0/24"}
	proxyOverride := mergeProxyValues(registryStringValue(internetSettings, "ProxyOverride"), ";", proxyAdditions, enabled)
	noProxy := mergeProxyValues(registryStringValue(environment, "NO_PROXY"), ",", noProxyAdditions, enabled)
	if err := setRegistryStringValue(internetSettings, "ProxyOverride", proxyOverride); err != nil {
		return err
	}
	if err := setRegistryStringValue(environment, "NO_PROXY", noProxy); err != nil {
		return err
	}
	if noProxy == "" {
		_ = os.Unsetenv("NO_PROXY")
	} else {
		_ = os.Setenv("NO_PROXY", noProxy)
	}
	_, _, _ = internetSetOptionW.Call(0, 39, 0, 0)
	_, _, _ = internetSetOptionW.Call(0, 37, 0, 0)
	return nil
}

func meshProxyBypassApplied() (meshBypass, noProxyBypass bool) {
	const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	proxy := strings.ToLower(registryStringValue(internetSettings, "ProxyOverride"))
	noProxy := strings.ToLower(registryStringValue(`Environment`, "NO_PROXY"))
	return strings.Contains(proxy, "*.mesh") && strings.Contains(proxy, "10.77.*"), strings.Contains(noProxy, ".mesh") && strings.Contains(noProxy, "10.77.0.0/24")
}

func (a *clientApp) proxyCompatibilityStatus() ProxyCompatibilityStatus {
	a.stateMu.Lock()
	state, _ := a.load()
	a.stateMu.Unlock()
	meshBypass, noProxyBypass := meshProxyBypassApplied()
	return ProxyCompatibilityStatus{Enabled: state.ProxyCompatibilityEnabled, Applied: meshBypass && noProxyBypass, MeshBypass: meshBypass, NoProxyBypass: noProxyBypass}
}

func (a *clientApp) setProxyCompatibility(enabled bool) (ProxyCompatibilityStatus, error) {
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		state.ProxyCompatibilityEnabled = enabled
		state.ProxyCompatibilityVersion = proxyCompatibilityVersion
		err = saveJSON(a.statePath, state)
	}
	a.stateMu.Unlock()
	if err != nil {
		return a.proxyCompatibilityStatus(), err
	}
	if err := applyMeshProxyBypass(enabled); err != nil {
		return a.proxyCompatibilityStatus(), err
	}
	return a.proxyCompatibilityStatus(), nil
}
