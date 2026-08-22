//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientWebUsesExplicitDOMReferences(t *testing.T) {
	data, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, forbidden := range []string{"Name:name.value.trim()", "Server:server.value.trim()", "PairingHash:pairingHash.value.trim()"} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("client UI still relies on named-window global %q", forbidden)
		}
	}
	for _, required := range []string{"document.getElementById('deviceName')", "ui.deviceName.value.trim()", "ui.server.value.trim()", "ui.pairingHash.value.trim()"} {
		if !strings.Contains(html, required) {
			t.Fatalf("client UI is missing explicit DOM reference %q", required)
		}
	}
	for _, required := range []string{"在线设备", "document.getElementById('peersPage')", "api('/api/peers')", "showPage('peers')"} {
		if !strings.Contains(html, required) {
			t.Fatalf("client UI is missing peer-directory element %q", required)
		}
	}
	for _, required := range []string{"服务映射", "document.getElementById('mappingsPage')", "api('/api/mappings')", "全网共享服务", "只能管理本机创建的映射", "document.getElementById('sharedPage')", "showPage('shared')"} {
		if !strings.Contains(html, required) {
			t.Fatalf("client UI is missing service-mapping element %q", required)
		}
	}
	for _, required := range []string{"健康检查", "本地服务不可达", "latencyText", "最后检查"} {
		if !strings.Contains(html, required) {
			t.Fatalf("client UI is missing health-check element %q", required)
		}
	}
	for _, required := range []string{"UDP", "需要创建者手动批准", "消息列表", "暂停", "重新启动", "连接用户", "刷新中...", "showPage('messages')"} {
		if !strings.Contains(html, required) {
			t.Fatalf("client UI is missing access-control element %q", required)
		}
	}
	for _, required := range []string{
		"clientVersion", "nebulaVersion", "默认强制 P2P", "P2P 直连", "Relay 中继", "打洞端口", "UPnP 已映射",
		"TUN 直连锁", "物理出口", "安装物理直连锁并重启", "业务代理保持不变", "强制 P2P 诊断", "恢复 Relay 兜底",
		"网络拓扑", "实时网络拓扑", "topologyCanvas", "selectTopologyPeer", "api('/api/topology')", "真实字节增量",
		"zoomTopology", "resetTopologyView", "fitTopologyView", "pointermove", "端口映射服务明细", "实时数据传输",
		"P2P 打洞向导", "真实 UDP 出口诊断", "同一测试端口访问不同目标", "api('/api/diagnostics/nat'",
		"历史与回放", "SQLite 本地保留 30 天", "拓扑时间回放", "持久连接记录", "api('/api/history",
		"MeshDNS", "meshDNSOwnPrefix", "mappingDNSPrefix", "个人域名前缀", "HTTP域名网关，无需端口",
		"api('/api/dns')", "api('/api/dns/enable'", "api('/api/dns/prefix'", "api('/api/mappings/dns'",
		"Peer 数据协议", "仅 IPv4", "仅 IPv6", "IPv4 + IPv6", "三个模式只能启用一个", "流量分流", "P2P出口网卡", "业务优先网卡",
		"身份与证书安全", "安全修复身份", "签名吊销列表", "安全更新与回滚", "Ed25519清单签名", "每 6 小时检查并静默安装",
		"api('/api/update')", "api('/api/update/apply'", "api('/api/update/rollback'", "api('/api/identity')", "api('/api/identity/repair'",
		"api('/api/settings/interfaces'", "api('/api/settings/ip-mode'", "api('/api/network')", "api('/api/nat/apply'", "api('/api/nat/mode'",
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("client UI is missing P2P diagnostic element %q", required)
		}
	}
	for _, required := range []string{"previousPage==='mappings'&&currentPage!=='mappings'", "ui.mappingResult.textContent=''", "showFeedback?++refreshSequence:refreshSequence", "runLiveRefresh", "document.hidden?15000:3000"} {
		if !strings.Contains(html, required) {
			t.Fatalf("client UI is missing refresh/result lifecycle behavior %q", required)
		}
	}
}

func TestDesktopShellUsesNativeWebViewInsteadOfExternalBrowser(t *testing.T) {
	desktopSource, err := os.ReadFile("desktop_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	clientSource, err := os.ReadFile("client_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"go-webview2", "NewWithOptions", "DataPath", "WindowOptions", "--gui-only", "startNativeDesktopProcess"} {
		if !strings.Contains(string(desktopSource)+string(clientSource), required) {
			t.Fatalf("native desktop integration missing %q", required)
		}
	}
	for _, forbidden := range []string{"msedge.exe", "--app=", "url.dll,FileProtocolHandler"} {
		if strings.Contains(string(clientSource), forbidden) {
			t.Fatalf("client still launches external browser using %q", forbidden)
		}
	}
}

func TestNativeDesktopProvidesTrayAndCloseToTray(t *testing.T) {
	source, err := os.ReadFile("desktop_tray_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Shell_NotifyIconW", "nativeWMClose", "nativeSWHide", "打开 MeshLAN", "nativeMenuExit", "SetForegroundWindow", "SetWindowLongPtrW"} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("native tray integration missing %q", required)
		}
	}
}

func TestBuildProducesPortableNativeWindowsBinary(t *testing.T) {
	build, err := os.ReadFile(filepath.Join("..", "..", "build.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"-H=windowsgui", "MeshLAN-Nebula-Windows.exe", "MeshLAN-Nebula-Windows-$Version.exe"} {
		if !strings.Contains(string(build), required) {
			t.Fatalf("portable Windows build missing %q", required)
		}
	}
	if strings.Contains(string(build), "MeshLAN-Setup-Windows.exe") || strings.Contains(string(build), "meshlan-setup") {
		t.Fatal("portable Windows build must not produce an installer")
	}
}

func TestApplicationIconIsPackagedInPortableBinary(t *testing.T) {
	icon, err := clientWeb.ReadFile("assets/meshlan-icon.png")
	if err != nil || len(icon) < 10000 {
		t.Fatalf("embedded application icon missing or invalid: bytes=%d err=%v", len(icon), err)
	}
	for _, path := range []string{"rsrc_windows_amd64.syso", filepath.Join("assets", "meshlan-icon.ico")} {
		info, err := os.Stat(path)
		if err != nil || info.Size() < 100 {
			t.Fatalf("packaged brand resource missing: %s", path)
		}
	}
}

func TestClientStateEncryptsDeviceTokenWithDPAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-state.json")
	state := ClientState{Name: "desktop", Pairing: &PairResponse{DeviceToken: "device-secret-token"}}
	if err := saveJSON(path, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "device-secret-token") || !strings.Contains(string(raw), "encryptedDeviceToken") {
		t.Fatalf("client secret was not protected on disk: %s", raw)
	}
	var restored ClientState
	if err := loadJSON(path, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Pairing == nil || restored.Pairing.DeviceToken != "device-secret-token" || restored.SecretStorageVersion != clientSecretStorageVersion {
		t.Fatalf("DPAPI round trip failed: %#v", restored)
	}
}

func TestClientStateMigratesLegacyPlaintextToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-state.json")
	legacy := ClientState{Name: "desktop", Pairing: &PairResponse{DeviceToken: "legacy-device-token"}}
	raw, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	app := clientApp{statePath: path}
	restored, err := app.load()
	if err != nil {
		t.Fatal(err)
	}
	if restored.Pairing == nil || restored.Pairing.DeviceToken != "legacy-device-token" {
		t.Fatalf("legacy token was not available in memory: %#v", restored)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(migrated), "legacy-device-token") || !strings.Contains(string(migrated), "encryptedDeviceToken") {
		t.Fatalf("legacy token remained plaintext after migration: %s", migrated)
	}
}

func TestClientStateRejectsTamperedDPAPICiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-state.json")
	state := ClientState{Name: "desktop", Pairing: &PairResponse{DeviceToken: "device-secret-token"}}
	if err := saveJSON(path, state); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var disk ClientState
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if len(disk.EncryptedDeviceToken) < 4 {
		t.Fatal("encrypted token missing")
	}
	last := disk.EncryptedDeviceToken[len(disk.EncryptedDeviceToken)-1]
	if last == 'A' {
		last = 'B'
	} else {
		last = 'A'
	}
	disk.EncryptedDeviceToken = disk.EncryptedDeviceToken[:len(disk.EncryptedDeviceToken)-1] + string(last)
	tampered, _ := json.MarshalIndent(disk, "", "  ")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	var restored ClientState
	if err := loadJSON(path, &restored); err == nil {
		t.Fatal("tampered DPAPI ciphertext was accepted")
	}
}

func TestClientSecretACLArgumentsRemoveInheritance(t *testing.T) {
	args := clientSecretACLArguments(`C:\MeshLAN\client`, "S-1-5-21-1000")
	joined := strings.Join(args, " ")
	for _, required := range []string{"/inheritance:r", "/grant:r", "*S-1-5-21-1000:(OI)(CI)(F)", "*S-1-5-18:(OI)(CI)(F)"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("secret ACL command missing %q: %s", required, joined)
		}
	}
	reset := strings.Join(clientSecretChildResetArguments(`C:\MeshLAN\client`), " ")
	for _, required := range []string{`C:\MeshLAN\client\*`, "/reset", "/T"} {
		if !strings.Contains(reset, required) {
			t.Fatalf("secret child ACL reset missing %q: %s", required, reset)
		}
	}
}

func TestClientPrivateKeyDPAPIBackupAndRestore(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "host.key")
	state := ClientState{PrivateKeyPath: privatePath}
	const privateKey = "synthetic-private-key-material-for-dpapi-round-trip"
	if err := os.WriteFile(privatePath, []byte(privateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refreshClientPrivateKeyBackup(state); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(clientPrivateKeyBackupPath(state))
	if err != nil || strings.Contains(string(backup), "private-material") || !clientPrivateKeyBackupReady(state) {
		t.Fatalf("private key backup was not protected: %q err=%v", backup, err)
	}
	if err := os.Remove(privatePath); err != nil {
		t.Fatal(err)
	}
	if err := ensureClientPrivateKeyBackup(state); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(privatePath)
	if err != nil || string(restored) != privateKey {
		t.Fatalf("private key restore failed: %q err=%v", restored, err)
	}
}

func TestRouteGuardOnlyPinsNebulaUnderlayEndpoints(t *testing.T) {
	for _, required := range []string{
		"HardwareInterface", "Get-WinEvent", "udpAddrs=|Handshake message received",
		"$prefix=$address+'/32'", "New-NetRoute", "PolicyStore ActiveStore",
		"$prefix=$address+'/128'", "AddressFamily IPv6",
		"Restart-Service -Name Nebula", "Get-TunInterfaces", "PreferredAlias", "preferredBusiness", "InterfaceMetric 5", "IPv6DefaultSuppressed", "DestinationPrefix '::/0'",
		"requestedSecurityVersion", "securityAppliedVersion", "revocationVersion",
		"Sync-MeshDNS", "BEGIN MESHLAN MANAGED", "mesh-dns-records.json", "dnsRecordsApplied",
	} {
		if !strings.Contains(routeGuardPowerShell, required) {
			t.Fatalf("route guard is missing %q", required)
		}
	}
	if strings.Contains(routeGuardPowerShell, "New-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'") {
		t.Fatal("route guard must not bypass the proxy for the default route")
	}
}

func TestRouteGuardPowerShellParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route-guard.ps1")
	if err := os.WriteFile(path, []byte(routeGuardPowerShell), 0o600); err != nil {
		t.Fatal(err)
	}
	command := `$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile(` + psQuote(path) + `,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object{$_.Message};exit 1}`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", command)
	hidden(cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("route guard PowerShell parse failed: %v: %s", err, output)
	}
}

func TestUpdateHelperPowerShellParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apply-update.ps1")
	if err := os.WriteFile(path, []byte(updateHelperPowerShell), 0o600); err != nil {
		t.Fatal(err)
	}
	command := `$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile(` + psQuote(path) + `,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object{$_.Message};exit 1}`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", command)
	hidden(cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("update helper PowerShell parse failed: %v: %s", err, output)
	}
}

func TestUpdaterStopsNativeWindowBeforeReplacingExecutable(t *testing.T) {
	for _, required := range []string{"$matchingBefore", "$hadGUI", "MainWindowHandle", "GetFullPath($_.Path)", "Stop-Process -Force", "'--gui-only'"} {
		if !strings.Contains(updateHelperPowerShell, required) {
			t.Fatalf("native desktop update handoff missing %q", required)
		}
	}
}

func TestEncodedPowerShellCommandCannotBeModifiedThroughAStagingFile(t *testing.T) {
	encoded := encodedPowerShellCommand(`Write-Output 'meshlan-encoded-ok'`)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-EncodedCommand", encoded)
	hidden(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "meshlan-encoded-ok") {
		t.Fatalf("encoded PowerShell failed: %v: %s", err, output)
	}
}

func TestRouteGuardStatusAcceptsPowerShellTimestamps(t *testing.T) {
	data := []byte(`{"version":1,"mode":"guarding","bypassReady":true,"lastUpdated":"2026-08-19T12:45:12.1928499Z","lastRestart":"2026-08-19T12:43:58.8651301Z"}`)
	var status RouteGuardStatus
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if !status.BypassReady || status.Mode != "guarding" {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestRouteGuardStatusAcceptsPowerShellUTF8BOM(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	state := ClientState{ConfigPath: filepath.Join(t.TempDir(), "config.yml")}
	_, statusPath := routeGuardPaths(state)
	if err := os.MkdirAll(filepath.Dir(statusPath), 0o700); err != nil {
		t.Fatal(err)
	}
	data := append([]byte{0xef, 0xbb, 0xbf}, []byte(fmt.Sprintf(`{"version":1,"mode":"guarding","bypassReady":true,"lastUpdated":%q}`, time.Now().UTC().Format(time.RFC3339Nano)))...)
	if err := os.WriteFile(statusPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	status := readRouteGuardStatus(state)
	if !status.BypassReady || status.Mode != "guarding" {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestRouteGuardExecutableScriptLivesInProtectedProgramData(t *testing.T) {
	state := ClientState{ConfigPath: filepath.Join(t.TempDir(), "config.yml")}
	scriptPath, statusPath := routeGuardPaths(state)
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	expectedRoot := filepath.Join(programData, "MeshLANNebula")
	if !strings.HasPrefix(strings.ToLower(scriptPath), strings.ToLower(expectedRoot+string(os.PathSeparator))) {
		t.Fatalf("SYSTEM task script is not protected by ProgramData: %s", scriptPath)
	}
	if filepath.Dir(statusPath) != filepath.Dir(scriptPath) {
		t.Fatalf("status must share the protected component directory: %s", statusPath)
	}
}

func TestNebulaHandshakePathPattern(t *testing.T) {
	message := `time=2026-08-19T19:44:43+08:00 level=INFO msg="Handshake message received" vpnAddrs=[10.77.0.3] from="203.0.113.10:8080 (relayed)" certName=bob`
	match := nebulaHandshakePathPattern.FindStringSubmatch(message)
	if len(match) != 4 || match[1] != "10.77.0.3" || match[2] != "203.0.113.10:8080 (relayed)" {
		t.Fatalf("unexpected path match: %#v", match)
	}
}

func TestPingLatencyPatternDoesNotDependOnLocalizedTimeLabel(t *testing.T) {
	for _, output := range []string{"Reply time=23ms TTL=128", "来自目标的回复：时间=26ms TTL=128", "Reply time<1ms TTL=128"} {
		match := pingLatencyPattern.FindStringSubmatch(output)
		if len(match) != 2 {
			t.Fatalf("latency not parsed from %q", output)
		}
	}
}

func TestNormalizeLoopbackHost(t *testing.T) {
	for _, value := range []string{"localhost", "127.0.0.1", "::1"} {
		if _, err := normalizeLoopbackHost(value); err != nil {
			t.Fatalf("loopback host rejected: %q: %v", value, err)
		}
	}
	for _, value := range []string{"0.0.0.0", "192.168.1.1", "example.com"} {
		if _, err := normalizeLoopbackHost(value); err == nil {
			t.Fatalf("non-loopback host accepted: %q", value)
		}
	}
}

func TestMappingPortOccupancyIsProtocolSpecific(t *testing.T) {
	mappings := []LocalServiceMapping{{MeshPort: 24571, Protocol: "tcp"}}
	if !mappingPortUsed(mappings, 24571, "tcp") {
		t.Fatal("TCP occupancy was not detected")
	}
	if mappingPortUsed(mappings, 24571, "udp") {
		t.Fatal("TCP mapping incorrectly blocked the same UDP port")
	}
}

func TestRemoteAccessPolicyEnforcement(t *testing.T) {
	app := &clientApp{control: DeviceControlResponse{
		Peers:    []PeerIdentity{{Name: "owner", Address: "10.77.0.2"}, {Name: "peer", Address: "10.77.0.3"}},
		Policies: []MappingAccessPolicy{{MappingID: "mapping-a", ApprovalRequired: true, Users: []ServiceUserAccess{{UserName: "peer", Address: "10.77.0.3", Status: "approved"}}}},
	}}
	if allowed, _ := app.remoteAllowed("mapping-a", "owner", true, "10.77.0.3"); !allowed {
		t.Fatal("approved peer was denied")
	}
	app.control.Policies[0].Users[0].Status = "paused"
	if allowed, _ := app.remoteAllowed("mapping-a", "owner", true, "10.77.0.3"); allowed {
		t.Fatal("paused peer was allowed")
	}
	if allowed, _ := app.remoteAllowed("mapping-a", "owner", true, "10.77.0.4"); allowed {
		t.Fatal("unknown peer was allowed on approval-required service")
	}
	if allowed, _ := app.remoteAllowed("mapping-a", "owner", false, "10.77.0.4"); !allowed {
		t.Fatal("unknown peer was denied on open service")
	}
	if allowed, _ := app.remoteAllowed("mapping-a", "owner", true, "10.77.0.2"); !allowed {
		t.Fatal("owner was denied its own service")
	}
}

func TestConnectionRecordsPruneDeletedMappings(t *testing.T) {
	app := &clientApp{connections: map[string]*ServiceConnectionRecord{
		"keep":  {MappingID: "mapping-a", ServiceName: "keep"},
		"stale": {MappingID: "mapping-deleted", ServiceName: "stale"},
	}}
	records := app.connectionRecords([]LocalServiceMapping{{ID: "mapping-a"}})
	if len(records) != 1 || records[0].MappingID != "mapping-a" {
		t.Fatalf("unexpected records: %#v", records)
	}
	if _, exists := app.connections["stale"]; exists {
		t.Fatal("stale connection record was not pruned")
	}
}

func TestParseSTUNXORMappedIPv4(t *testing.T) {
	var transaction [12]byte
	for i := range transaction {
		transaction[i] = byte(i + 1)
	}
	response := make([]byte, 32)
	binary.BigEndian.PutUint16(response[0:2], 0x0101)
	binary.BigEndian.PutUint16(response[2:4], 12)
	binary.BigEndian.PutUint32(response[4:8], 0x2112a442)
	copy(response[8:20], transaction[:])
	binary.BigEndian.PutUint16(response[20:22], 0x0020)
	binary.BigEndian.PutUint16(response[22:24], 8)
	response[25] = 0x01
	binary.BigEndian.PutUint16(response[26:28], uint16(45678)^0x2112)
	address := []byte{203, 0, 113, 8}
	cookie := []byte{0x21, 0x12, 0xa4, 0x42}
	for i := range address {
		response[28+i] = address[i] ^ cookie[i]
	}
	mapped, err := parseSTUNMappedAddress(response, transaction)
	if err != nil || mapped.String() != "203.0.113.8:45678" {
		t.Fatalf("mapped=%s err=%v", mapped, err)
	}
}

func TestSTUNClassificationUsesStableMappingAndNebulaEvidence(t *testing.T) {
	results := []STUNProbeResult{{Success: true, PublicEndpoint: "203.0.113.8:42002"}, {Success: true, PublicEndpoint: "203.0.113.8:42002"}}
	behavior, support, _ := classifySTUN(results, false, false)
	if behavior != "endpoint_independent" || support != "likely" {
		t.Fatalf("behavior=%s support=%s", behavior, support)
	}
	behavior, support, _ = classifySTUN(nil, true, false)
	if behavior != "confirmed_by_nebula" || support != "confirmed" {
		t.Fatalf("confirmed behavior=%s support=%s", behavior, support)
	}
}

func TestDiagnosticAdapterSelectionHonorsPreferredPhysicalInterface(t *testing.T) {
	adapters := []diagnosticAdapter{
		{Name: "tun0", Index4: 8, IPv4: "172.19.0.1", Gateway4: "172.19.0.2", Metric4: 1, LikelyTUN: true},
		{Name: "以太网", Index4: 12, IPv4: "192.168.2.20", Gateway4: "192.168.2.1", Metric4: 5},
		{Name: "WLAN", Index4: 35, IPv4: "192.168.1.60", Gateway4: "192.168.1.1", Metric4: 40},
	}
	selected, ok := chooseDiagnosticAdapter(adapters, "WLAN", false)
	if !ok || selected.Name != "WLAN" || selected.Index4 != 35 {
		t.Fatalf("preferred physical adapter not selected: %#v", selected)
	}
	selected, ok = chooseDiagnosticAdapter(adapters, "auto", false)
	if !ok || selected.Name != "以太网" {
		t.Fatalf("lowest metric physical adapter not selected: %#v", selected)
	}
}

func TestMergeDiagnosticNetworkPreservesGuardReadiness(t *testing.T) {
	guard := RouteGuardStatus{Mode: "guarding", BypassReady: true, PhysicalInterface: "stale"}
	live := RouteGuardStatus{PhysicalInterface: "WLAN", PhysicalAddress: "192.168.1.60", Gateway: "192.168.1.1", InterfaceIndex: 35, TUNInterfaces: []string{"tun0"}, IPv6DefaultSuppressed: true}
	merged := mergeDiagnosticNetwork(guard, live)
	if !merged.BypassReady || merged.Mode != "guarding" || merged.PhysicalInterface != "WLAN" || merged.InterfaceIndex != 35 || len(merged.TUNInterfaces) != 1 || !merged.IPv6DefaultSuppressed {
		t.Fatalf("unexpected merged diagnostic network: %#v", merged)
	}
}

func TestOverlayQualitySummaryIncludesLossAndJitter(t *testing.T) {
	quality := summarizeOverlayQuality([]int64{20, 30, -1, 25}, 4)
	if !quality.Reachable || quality.LatencyMs != 25 || quality.PacketLossPct != 25 || quality.JitterMs != 7.5 || quality.Samples != 4 {
		t.Fatalf("unexpected quality summary: %#v", quality)
	}
	down := summarizeOverlayQuality([]int64{-1, -1}, 2)
	if down.Reachable || down.LatencyMs != -1 || down.PacketLossPct != 100 {
		t.Fatalf("unexpected down quality: %#v", down)
	}
}

func TestPathChangeReasonExplainsFamilyAndRelayTransitions(t *testing.T) {
	v4 := peerPathObservation{Signature: "p2p|ipv4|a", Mode: "p2p", Family: "ipv4", Underlay: "1.1.1.1:1", Online: true}
	v6 := peerPathObservation{Signature: "p2p|ipv6|b", Mode: "p2p", Family: "ipv6", Underlay: "[2001:db8::1]:1", Online: true}
	if reason := pathChangeReason(v4, v6); !strings.Contains(reason, "IPV4") || !strings.Contains(reason, "IPV6") {
		t.Fatalf("family switch reason is not specific: %s", reason)
	}
	relay := peerPathObservation{Signature: "relay|ipv6|c", Mode: "relay", Family: "ipv6", Underlay: "[2001:db8::2]:1", Online: true}
	if reason := pathChangeReason(relay, v6); !strings.Contains(reason, "打洞成功") {
		t.Fatalf("relay recovery reason is not specific: %s", reason)
	}
}

func TestOfflinePeerCannotRemainReachableOrExposeStaleUnderlay(t *testing.T) {
	previous := peerPathObservation{Signature: "p2p|ipv6|endpoint", Mode: "p2p", Family: "ipv6", Underlay: "[2001:db8::1]:42004", Online: true}
	offline := peerPathObservation{Signature: "down|unknown|", Mode: "down", Family: "unknown", Online: false}
	if reason := pathChangeReason(previous, offline); !strings.Contains(reason, "离线") {
		t.Fatalf("offline transition reason is ambiguous: %s", reason)
	}
	source, err := os.ReadFile("client_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"if !peers[index].Online", `peers[index].Underlay = ""`, `peers[index].PathMode = "down"`, "peer.ServiceRunning && peer.Online"} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("offline peer normalization missing %q", required)
		}
	}
	html, _ := clientWeb.ReadFile("web/index.html")
	if !strings.Contains(string(html), "path=!p.online||own?null") {
		t.Fatal("peer directory UI can still render stale path for offline peer")
	}
}

func TestDiagnosticRedactorRemovesIdentityPathsAndIPs(t *testing.T) {
	state := ClientState{Name: "private-device-name"}
	redactor := newDiagnosticRedactor(state)
	redactor.replacements[`C:\Users\private`] = "<profile-test>"
	output := redactor.Text(`private-device-name C:\Users\private 192.168.1.60 117.150.175.129:42002 [2409:8a4c::1]:8080 fe80::4059:4e15:3805:2341%35`)
	for _, secret := range []string{"private-device-name", `C:\Users\private`, "192.168.1.60", "117.150.175.129", "2409:8a4c::1", "fe80::4059:4e15:3805:2341"} {
		if strings.Contains(output, secret) {
			t.Fatalf("diagnostic output retained %q: %s", secret, output)
		}
	}
	for _, required := range []string{"<device-", "<profile-test>", "<ip-", ":42002", ":8080"} {
		if !strings.Contains(output, required) {
			t.Fatalf("diagnostic output missing %q: %s", required, output)
		}
	}
}

func TestClientWebIncludesRealQualityAndDiagnosticExportActions(t *testing.T) {
	data, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, required := range []string{"Peer 链路质量", "packetLossPct", "jitterMs", "pathChangeReason", "onlineSince", "downloadDiagnosticReport", "/api/diagnostics/report", "智能双栈竞速", "/api/automation", "autoNetworkScenes", "仅在 IPv4 + IPv6 模式下可用", "updateAutomationAvailability", "需要 IPv4 + IPv6 模式", "showMessageDialog", "等待网络组件响应", "重试网络组件", "checkUpdateButton", "正在检查...", "当前已是最新版本", "节点超时（不影响）", "真实 P2P 握手已确认 IPv6 可用", "发现节点", "/api/lighthouses", "立即同步", "客户端同时向所有可用节点注册"} {
		if !strings.Contains(html, required) {
			t.Fatalf("quality/report UI missing %q", required)
		}
	}
}

func TestLighthousePathsAreExcludedFromPeerCounts(t *testing.T) {
	paths := []NetworkPathRecord{{Address: "10.77.0.3", Mode: "p2p"}, {Address: "10.77.0.4", Mode: "p2p"}}
	nodes := []LighthouseEndpoint{{Address: "10.77.0.1/24", Primary: true}, {Address: "10.77.0.4/24"}}
	filtered := peerPathsExcludingLighthouses(paths, nodes)
	if len(filtered) != 1 || filtered[0].Address != "10.77.0.3" {
		t.Fatalf("lighthouse path leaked into peer counts: %#v", filtered)
	}
}

func TestMeshHTTPSCAIsSynchronizedForClientsWithoutMappings(t *testing.T) {
	serverState := ServerState{}
	if err := ensureMeshHTTPSCA(&serverState); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	statePath := filepath.Join(root, "client-state.json")
	if err := saveJSON(statePath, ClientState{Version: protocolVersion, Pairing: &PairResponse{}}); err != nil {
		t.Fatal(err)
	}
	app := &clientApp{root: root, statePath: statePath}
	if err := app.syncMeshHTTPSCA(serverState.HTTPSCACertificatePEM, serverState.HTTPSCAFingerprint); err != nil {
		t.Fatal(err)
	}
	state, err := app.load()
	if err != nil || state.Pairing.HTTPSCAFingerprint != serverState.HTTPSCAFingerprint || state.Pairing.HTTPSCACertificatePEM == "" {
		t.Fatalf("HTTPS CA was not synchronized: %#v err=%v", state.Pairing, err)
	}
}

func TestUpdateDownloaderSupportsDirectRangeResume(t *testing.T) {
	source, err := os.ReadFile("update_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`request.Header.Set("Range"`, "StatusPartialContent", "自动续传重试5次", "Proxy: nil", "DisableCompression: true"} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("resumable update downloader missing %q", required)
		}
	}
}

func TestP2PUpdateSeedSupportsRangeRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "MeshLAN.exe")
	content := []byte("0123456789abcdef")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	hash, size, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	app := &clientApp{executable: path}
	runtime := &updateSeedRuntime{sha256: hash, size: size}
	request := httptest.NewRequest(http.MethodGet, "http://10.77.0.2/.meshlan/update/"+hash, nil)
	request.Header.Set("Range", "bytes=4-7")
	recorder := httptest.NewRecorder()
	app.updateSeedHandler(runtime, recorder, request)
	if recorder.Code != http.StatusPartialContent || recorder.Body.String() != "4567" || recorder.Header().Get("X-MeshLAN-Update-Seed") != "p2p" {
		t.Fatalf("unexpected seed response: status=%d body=%q headers=%v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

func TestHTTPSCertificateManagementLivesInSettings(t *testing.T) {
	data, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"HTTPS 根证书", "httpsSettingsInstallButton", "httpsSettingsUninstallButton", "/api/https/status", "/api/https/untrust", "完全关闭并重新打开浏览器"} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("HTTPS settings UI missing %q", required)
		}
	}
}

func TestProxyCompatibilityMergePreservesUserRules(t *testing.T) {
	value := mergeProxyValues("localhost;example.com;*.mesh", ";", []string{"*.mesh", "10.77.*"}, true)
	if value != "localhost;example.com;*.mesh;10.77.*" {
		t.Fatalf("unexpected enabled proxy bypass: %q", value)
	}
	value = mergeProxyValues(value, ";", []string{"*.mesh", "10.77.*"}, false)
	if value != "localhost;example.com" {
		t.Fatalf("unexpected restored proxy bypass: %q", value)
	}
	data, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"代理兼容", "proxyCompatibilityToggle", "/api/settings/proxy-compatibility", "无需修改 Clash 规则"} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("proxy compatibility UI missing %q", required)
		}
	}
}

func TestAIAssistantUIRequiresConsentAndSupportsLocalConversations(t *testing.T) {
	data, err := clientWeb.ReadFile("web/ai-assistant.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"AI助手", "/api/ai/chat", "/api/ai/conversations", "/api/ai/execute", "/api/ai/report", "实时工作过程", "修改操作仍需你确认", "端到端加密", "本地历史", "新建对话", "重命名会话", "删除会话"} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("AI assistant UI missing %q", required)
		}
	}
}

func TestPartialAIReplySupportsIncompleteStreamingJSON(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{`{"reply":"你好`, "你好"},
		{`{"reply":"第一行\n第二行","summary":"done"}`, "第一行\n第二行"},
		{`{"reply":"前缀\u4`, "前缀"},
		{`{"summary":"waiting"`, ""},
	}
	for _, test := range cases {
		if got := partialAIReply(test.content); got != test.want {
			t.Fatalf("partialAIReply(%q)=%q want %q", test.content, got, test.want)
		}
	}
}

func TestRelaySelectionUsesHealthScoreAndHysteresis(t *testing.T) {
	candidates := []RelayCandidateScore{
		{Address: "10.77.0.1", Reachable: true, Score: 80},
		{Address: "10.77.0.4", Reachable: true, Score: 30},
	}
	if got := selectPreferredRelay(candidates, "10.77.0.1"); got != "10.77.0.4" {
		t.Fatalf("large relay improvement was ignored: %s", got)
	}
	candidates[1].Score = 70
	if got := selectPreferredRelay(candidates, "10.77.0.1"); got != "10.77.0.1" {
		t.Fatalf("relay switched without hysteresis margin: %s", got)
	}
	candidates[0].Reachable = false
	if got := selectPreferredRelay(candidates, "10.77.0.1"); got != "10.77.0.4" {
		t.Fatalf("unreachable relay did not fail over: %s", got)
	}
}

func TestRouteGuardRestartsOrStartsNebulaDuringRace(t *testing.T) {
	if !strings.Contains(routeGuardPowerShell, "else {Start-Service -Name Nebula -ErrorAction Stop}") {
		t.Fatal("Route Guard can leave Nebula stopped during a race restart")
	}
}

func TestTopologyRedesignAssetsAreEmbedded(t *testing.T) {
	index, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	css, err := clientWeb.ReadFile("web/topology-redesign.css")
	if err != nil {
		t.Fatal(err)
	}
	js, err := clientWeb.ReadFile("web/topology-redesign.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"topology-redesign.css", "topology-redesign.js"} {
		if !strings.Contains(string(index), expected) {
			t.Fatalf("topology asset missing from client page: %s", expected)
		}
	}
	for _, expected := range []string{"topology-zone", "topology-card", "topology-edge-pill", "topology-node.selected"} {
		if !strings.Contains(string(css), expected) {
			t.Fatalf("topology CSS missing %q", expected)
		}
	}
	for _, expected := range []string{"网络出口", "本机核心", "设备链路", "共享服务", "shortTopologyText", "markSelectedTopologyNode"} {
		if !strings.Contains(string(js), expected) {
			t.Fatalf("topology renderer missing %q", expected)
		}
	}
}

func TestHistoryRedesignAssetsAreEmbedded(t *testing.T) {
	index, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	css, err := clientWeb.ReadFile("web/history-redesign.css")
	if err != nil {
		t.Fatal(err)
	}
	js, err := clientWeb.ReadFile("web/history-redesign.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"history-redesign.css", "history-redesign.js"} {
		if !strings.Contains(string(index), expected) {
			t.Fatalf("history asset missing from client page: %s", expected)
		}
	}
	for _, expected := range []string{"history-playback-controls", "history-moment-summary", "history-chart-tooltip", "history-row-changed"} {
		if !strings.Contains(string(css), expected) {
			t.Fatalf("history CSS missing %q", expected)
		}
	}
	for _, expected := range []string{"路径稳定率", "窗口新增流量", "historyChartCursor", "变化", "事件类型", "显示更多", "/api/history/live", "refreshHistoryLivePoint", "实时更新", "rateSeries", "historyStepPath", "吞吐峰值", "链路数量"} {
		if !strings.Contains(string(js), expected) {
			t.Fatalf("history renderer missing %q", expected)
		}
	}
	if !strings.Contains(string(js), "obsoletePlaybackControls.innerHTML") {
		t.Fatal("obsolete history playback controls are not removed from the DOM")
	}
}

func TestRealtimeTelemetryUsesNativeWindowsAPIs(t *testing.T) {
	data, err := os.ReadFile("telemetry_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, expected := range []string{"GetIfTable2Ex", "OpenSCManager", "QueryServiceStatus", "InOctets", "OutOctets"} {
		if !strings.Contains(source, expected) {
			t.Fatalf("native telemetry missing %q", expected)
		}
	}
	if strings.Contains(source, "powershell") || strings.Contains(source, "exec.Command") {
		t.Fatal("native realtime telemetry must not spawn subprocesses")
	}
}

func TestSidebarVersionUsesProductFriendlyLabels(t *testing.T) {
	index, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := clientWeb.ReadFile("web/version-polish.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"version-polish.js", "client-version-release", "client-version-engine", "version-position", "order:3"} {
		if !strings.Contains(string(index), expected) {
			t.Fatalf("version polish markup missing %q", expected)
		}
	}
	for _, expected := range []string{"v'+match[1]", "Core '+match[2]", "MutationObserver", "Nebula"} {
		if !strings.Contains(string(script), expected) {
			t.Fatalf("version polish script missing %q", expected)
		}
	}
}

func TestClientInterfaceSupportsPersistentFourLanguageSwitching(t *testing.T) {
	indexHTML, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	i18n, err := clientWeb.ReadFile("web/i18n.js")
	if err != nil {
		t.Fatal(err)
	}
	indexSource := string(indexHTML)
	for _, expected := range []string{"languageSelect", "setInterfaceLanguage", "zh-CN", "zh-TW", "English", "日本語", "/assets/i18n.js"} {
		if !strings.Contains(indexSource, expected) {
			t.Fatalf("language selector markup missing %q", expected)
		}
	}
	i18nSource := string(i18n)
	for _, expected := range []string{"meshlan.interfaceLanguage", "localStorage.setItem", "MutationObserver", "translateTree", "meshlan:languagechange", "Interface language", "表示言語", "介面語言"} {
		if !strings.Contains(i18nSource, expected) {
			t.Fatalf("i18n runtime missing %q", expected)
		}
	}
	routes, err := os.ReadFile("client_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(routes), "GET /assets/i18n.js") {
		t.Fatal("i18n asset is not served by the native client")
	}
}

func TestNetworkAutomationDefaultsAndQualityScore(t *testing.T) {
	state := ClientState{}
	if !applyNetworkAutomationDefaults(&state) || !state.AutoDualStack || !state.AutoNetworkScenes || state.NetworkAutomationVersion != networkAutomationVersion {
		t.Fatalf("network automation defaults not applied: %#v", state)
	}
	stable := dualStackScore(overlayQualityProbe{Reachable: true, LatencyMs: 20, JitterMs: 2, PacketLossPct: 0})
	degraded := dualStackScore(overlayQualityProbe{Reachable: true, LatencyMs: 100, JitterMs: 20, PacketLossPct: 10})
	if stable <= degraded || degraded <= 0 || dualStackScore(overlayQualityProbe{}) != 0 {
		t.Fatalf("unexpected dual-stack scores stable=%f degraded=%f", stable, degraded)
	}
	scenes := []NetworkSceneProfile{{ID: "home"}, {ID: "mobile"}}
	if findNetworkScene(scenes, "mobile") != 1 || findNetworkScene(scenes, "missing") != -1 {
		t.Fatal("network scene lookup failed")
	}
	nonDual := ClientState{IPMode: "ipv4", AutoDualStack: true, AutoNetworkScenes: true, NetworkAutomationVersion: networkAutomationVersion}
	if !applyNetworkAutomationDefaults(&nonDual) || nonDual.AutoDualStack || nonDual.AutoNetworkScenes {
		t.Fatalf("non-dual mode retained network automation: %#v", nonDual)
	}
}

func TestAutomationRaceStateDoesNotRemainRacingForever(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		enabled        bool
		componentReady bool
		requested      uint64
		applied        uint64
		requestedAt    time.Time
		want           string
	}{
		{false, true, 2, 1, now, "disabled"},
		{true, true, 2, 2, now, "stable"},
		{true, false, 2, 1, now, "component_required"},
		{true, true, 2, 1, now.Add(-10 * time.Second), "racing"},
		{true, true, 2, 1, now.Add(-2 * time.Minute), "pending"},
	}
	for _, test := range tests {
		if got := automationRaceState(test.enabled, test.componentReady, test.requested, test.applied, test.requestedAt, now); got != test.want {
			t.Fatalf("automationRaceState()=%q want %q", got, test.want)
		}
	}
}

func TestNonDualModeRejectsAndDisablesNetworkAutomation(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "client-state.json")
	state := ClientState{Version: protocolVersion, IPMode: "ipv4", IPModeVersion: ipModeVersion, AutoDualStack: false, AutoNetworkScenes: false, NetworkAutomationVersion: networkAutomationVersion}
	if err := saveJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	app := &clientApp{root: root, statePath: statePath}
	if _, err := app.setNetworkAutomation(true, true); !errors.Is(err, errDualStackModeRequired) {
		t.Fatalf("non-dual automation returned %v", err)
	}
	state.AutoDualStack, state.AutoNetworkScenes = true, true
	if err := saveJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := app.setIPMode("ipv6"); err != nil {
		t.Fatal(err)
	}
	updated, err := app.load()
	if err != nil {
		t.Fatal(err)
	}
	if updated.AutoDualStack || updated.AutoNetworkScenes {
		t.Fatalf("switching away from dual retained automation: %#v", updated)
	}
}

func TestRouteGuardCarriesDualStackRaceRequests(t *testing.T) {
	for _, required := range []string{"raceRequestVersion", "raceAppliedVersion", "$raceChanged", "-or $raceChanged", "diagnosticIPv6Targets", "diagnosticTargetsExpiresAt", "RouteMetric 2"} {
		if !strings.Contains(routeGuardPowerShell, required) {
			t.Fatalf("route guard missing dual-stack race integration %q", required)
		}
	}
}

func TestRouteGuardFreshnessUsesSystemHeartbeat(t *testing.T) {
	now := time.Now().UTC()
	if !routeGuardStatusFresh(RouteGuardStatus{LastUpdated: now.Add(-2 * time.Second).Format(time.RFC3339Nano)}, now) {
		t.Fatal("fresh Route Guard heartbeat rejected")
	}
	if routeGuardStatusFresh(RouteGuardStatus{LastUpdated: now.Add(-time.Minute).Format(time.RFC3339Nano)}, now) {
		t.Fatal("stale Route Guard heartbeat accepted")
	}
}

func TestP2PFileShareStreamsAndRecordsReceipt(t *testing.T) {
	root := t.TempDir()
	content := []byte("direct-over-nebula")
	contentPath := filepath.Join(root, "content.bin")
	if err := os.WriteFile(contentPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	encrypted, err := dpapiProtectString(token)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	app := &clientApp{root: root, fileReservations: map[string]int{}, control: DeviceControlResponse{Peers: []PeerIdentity{{Name: "receiver", Address: "10.77.0.3"}}}}
	store := fileShareStore{Version: 1, Shares: []LocalFileShare{{ID: "share-test-123", FileName: "hello.txt", StoragePath: contentPath, Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:]), EncryptedToken: encrypted, ExpiresAt: time.Now().Add(time.Hour), MaxDownloads: 1}}}
	if err := app.saveFileShareStore(store); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://10.77.0.2:24443/.meshlan/files/share-test-123?token="+token, nil)
	request.RemoteAddr = "10.77.0.3:50000"
	response := httptest.NewRecorder()
	app.fileShareHandler(response, request)
	if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), content) {
		t.Fatalf("unexpected file response code=%d body=%q", response.Code, response.Body.Bytes())
	}
	updated, err := app.loadFileShareStore()
	if err != nil || len(updated.Shares) != 1 || updated.Shares[0].DownloadCount != 1 || !updated.Shares[0].ContentRemoved || len(updated.Shares[0].Receipts) != 1 || updated.Shares[0].Receipts[0].Status != "received" {
		t.Fatalf("receipt/count not recorded: store=%#v err=%v", updated, err)
	}
	if _, err := os.Stat(contentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("one-time shared content was not removed")
	}
}

func TestFileShareRejectsTraversalAndUIIsWired(t *testing.T) {
	for _, name := range []string{"../secret.txt", `C:\\secret.txt`, "a/b.txt", "bad?.txt"} {
		if validSharedFileName(name) {
			t.Fatalf("unsafe shared filename accepted: %q", name)
		}
	}
	data, err := clientWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	for _, required := range []string{"文件直传", "createFileShare", "/api/files", "接收文件", "接收确认"} {
		if !strings.Contains(html, required) {
			t.Fatalf("file share UI missing %q", required)
		}
	}
}
