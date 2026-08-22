//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	diagnosticIPv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	diagnosticIPv6Pattern = regexp.MustCompile(`(?i)\[?[0-9a-f:%]*:[0-9a-f:%]+\]?`)
)

type diagnosticRedactor struct {
	replacements map[string]string
}

func (r *diagnosticRedactor) Add(kind, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	replacement := diagnosticAlias(kind, value)
	for _, source := range []string{value, strings.ToLower(value), strings.ToUpper(value)} {
		r.replacements[source] = replacement
	}
}

func diagnosticAlias(kind, value string) string {
	hash := sha256.Sum256([]byte(strings.ToLower(value)))
	return "<" + kind + "-" + hex.EncodeToString(hash[:4]) + ">"
}

func newDiagnosticRedactor(state ClientState) *diagnosticRedactor {
	redactor := &diagnosticRedactor{replacements: map[string]string{}}
	for kind, value := range map[string]string{
		"device":       state.Name,
		"dns":          state.DNSPrefix,
		"user":         os.Getenv("USERNAME"),
		"profile":      os.Getenv("USERPROFILE"),
		"appdata":      os.Getenv("APPDATA"),
		"localappdata": os.Getenv("LOCALAPPDATA"),
	} {
		redactor.Add(kind, value)
	}
	return redactor
}

func redactDiagnosticIP(value string) string {
	original := value
	bracketed := strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]")
	value = strings.Trim(value, "[]")
	if zone := strings.LastIndex(value, "%"); zone > 0 {
		value = value[:zone]
	}
	if net.ParseIP(value) == nil {
		return original
	}
	alias := diagnosticAlias("ip", value)
	if bracketed {
		return "[" + alias + "]"
	}
	return alias
}

func (r *diagnosticRedactor) Text(value string) string {
	for source, replacement := range r.replacements {
		value = strings.ReplaceAll(value, source, replacement)
	}
	value = diagnosticIPv4Pattern.ReplaceAllStringFunc(value, func(candidate string) string {
		if net.ParseIP(candidate) == nil {
			return candidate
		}
		return diagnosticAlias("ip", candidate)
	})
	value = diagnosticIPv6Pattern.ReplaceAllStringFunc(value, redactDiagnosticIP)
	return value
}

func (r *diagnosticRedactor) JSON(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return []byte(`{"error":"JSON encoding failed"}`)
	}
	return []byte(r.Text(string(data)))
}

func diagnosticCommand(name string, arguments ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	hidden(command)
	output, err := command.CombinedOutput()
	if len(output) > 256<<10 {
		output = output[:256<<10]
	}
	if ctx.Err() != nil {
		return string(output) + "\n[command timed out]"
	}
	if err != nil {
		return string(output) + "\n[command error: " + err.Error() + "]"
	}
	return string(output)
}

func diagnosticZipEntry(writer *zip.Writer, name string, data []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetModTime(time.Now().UTC())
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = entry.Write(data)
	return err
}

func (a *clientApp) buildDiagnosticReport() ([]byte, string, error) {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil {
		return nil, "", err
	}
	redactor := newDiagnosticRedactor(state)
	for _, peer := range a.controlSnapshot().Peers {
		redactor.Add("peer", peer.Name)
	}
	a.diagnosticMu.Lock()
	nat := a.runNATDiagnostic()
	a.diagnosticMu.Unlock()
	topology, topologyErr := a.topologySnapshot()
	history, historyErr := a.history.ClientHistory(24)
	network := networkStatus(state)
	identity := a.identityStatus()
	dns, dnsErr := a.meshDNSStatus()
	automation := a.dualStackStatus()
	httpsGateway := a.httpGatewayStatus()
	reportMeta := map[string]any{
		"generatedAt": time.Now().UTC(), "clientVersion": clientVersion, "nebulaVersion": nebulaVersion,
		"device": state.Name, "ipMode": normalizeIPMode(state.IPMode), "forceP2P": state.ForceP2P,
		"preferredP2PInterface": state.PreferredP2PInterface, "preferredBusinessInterface": state.PreferredBusinessInterface,
		"paired": state.Pairing != nil, "autoUpdate": state.AutoUpdate, "lastUpdateCheck": state.LastUpdateCheck,
		"lastUpdateError": state.LastUpdateError, "natLastError": state.NATLastError,
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entries := []struct {
		name string
		data []byte
	}{
		{"README.txt", []byte("MeshLAN 脱敏故障报告\r\n不包含设备私钥、配对令牌、证书内容、管理令牌或报文内容。\r\n所有设备名、用户名、文件路径和 IP 地址均使用稳定匿名标识替换。\r\n")},
		{"summary.json", redactor.JSON(reportMeta)},
		{"network-status.json", redactor.JSON(network)},
		{"nat-stun.json", redactor.JSON(nat)},
		{"identity-status.json", redactor.JSON(identity)},
		{"automation-status.json", redactor.JSON(automation)},
		{"https-gateway-status.json", redactor.JSON(httpsGateway)},
		{"windows/ipconfig.txt", []byte(redactor.Text(diagnosticCommand("ipconfig.exe", "/all")))},
		{"windows/routes.txt", []byte(redactor.Text(diagnosticCommand("route.exe", "print")))},
		{"windows/firewall.txt", []byte(redactor.Text(diagnosticCommand("netsh.exe", "advfirewall", "show", "allprofiles")))},
		{"windows/nebula-service.txt", []byte(redactor.Text(diagnosticCommand("sc.exe", "query", "Nebula")))},
		{"windows/nebula-events.txt", []byte(redactor.Text(diagnosticCommand("powershell.exe", "-NoProfile", "-Command", `$events=@(Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Nebula';StartTime=(Get-Date).AddDays(-1)} -MaxEvents 120 -ErrorAction SilentlyContinue | Select-Object TimeCreated,LevelDisplayName,Message); $events | Format-List | Out-String -Width 4096`)))},
	}
	if topologyErr == nil {
		entries = append(entries, struct {
			name string
			data []byte
		}{"topology.json", redactor.JSON(topology)})
	} else {
		entries = append(entries, struct {
			name string
			data []byte
		}{"topology-error.txt", []byte(redactor.Text(topologyErr.Error()))})
	}
	if historyErr == nil {
		entries = append(entries, struct {
			name string
			data []byte
		}{"recent-history.json", redactor.JSON(history)})
	}
	if dnsErr == nil {
		entries = append(entries, struct {
			name string
			data []byte
		}{"meshdns-status.json", redactor.JSON(dns)})
	}
	for _, entry := range entries {
		if err := diagnosticZipEntry(writer, entry.name, entry.data); err != nil {
			_ = writer.Close()
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	name := fmt.Sprintf("MeshLAN-Diagnostic-%s.zip", time.Now().Format("20060102-150405"))
	return archive.Bytes(), name, nil
}
