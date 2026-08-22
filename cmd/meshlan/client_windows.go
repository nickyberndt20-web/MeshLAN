//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
)

//go:embed web/* assets/meshlan-icon.png
var clientWeb embed.FS

type clientApp struct {
	root                string
	statePath           string
	runtimeDir          string
	nebula              string
	cert                string
	executable          string
	stateMu             sync.Mutex
	syncMu              sync.Mutex
	heartbeatMu         sync.Mutex
	forwardMu           sync.Mutex
	forwards            map[string]*forwardRuntime
	controlMu           sync.RWMutex
	control             DeviceControlResponse
	connectionMu        sync.Mutex
	connections         map[string]*ServiceConnectionRecord
	topologyMu          sync.Mutex
	history             *historyStore
	historyMu           sync.Mutex
	historyLastTopology time.Time
	peerPathStates      map[string]peerPathObservation
	automationMu        sync.Mutex
	dualStackRuntime    dualStackRuntime
	diagnosticMu        sync.Mutex
	gatewayMu           sync.Mutex
	httpGateway         *httpGatewayRuntime
	fileShareMu         sync.Mutex
	fileShareRuntime    *fileShareRuntime
	fileReservations    map[string]int
	updateSeedMu        sync.Mutex
	updateSeedRuntime   *updateSeedRuntime
	aiMu                sync.Mutex
	aiPlans             map[string]AIPlan
}

func hidden(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func (a *clientApp) ensureRuntime() error {
	nebula, cert, err := ensureNebulaRuntime(a.runtimeDir)
	if err != nil {
		return err
	}
	a.nebula, a.cert = nebula, cert
	return nil
}

func psQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func commandLineQuote(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func encodedPowerShellCommand(script string) string {
	words := utf16.Encode([]rune(script))
	data := make([]byte, len(words)*2)
	for i, word := range words {
		binary.LittleEndian.PutUint16(data[i*2:], word)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func runElevated(executable string, args []string) error {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = psQuote(arg)
	}
	script := fmt.Sprintf("$p=Start-Process -FilePath %s -ArgumentList @(%s) -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode", psQuote(executable), strings.Join(quoted, ","))
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	hidden(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("管理员操作失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func pairWithServer(server, code string, request PairRequest) (PairResponse, error) {
	payload, err := parsePairingCode(code)
	if err != nil {
		return PairResponse{}, err
	}
	tlsConfig, err := pinnedTLSConfig(payload.Pin)
	if err != nil {
		return PairResponse{}, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	body, _ := json.Marshal(request)
	url := "https://" + pairingAddress(server, payload.Port) + "/v1/pair"
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "MeshLAN "+payload.Secret)
	req.Header.Set("X-MeshLAN-Enrollment", payload.ID)
	response, err := client.Do(req)
	if err != nil {
		return PairResponse{}, err
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return PairResponse{}, fmt.Errorf("配对失败 HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var paired PairResponse
	if err := json.Unmarshal(responseBody, &paired); err != nil {
		return PairResponse{}, err
	}
	return paired, nil
}

func fetchPeerDirectory(state ClientState) (PeerDirectoryResponse, error) {
	if state.Pairing == nil || state.Pairing.DeviceToken == "" || state.Pairing.ControlPin == "" {
		return PeerDirectoryResponse{}, errors.New("本机尚未完成配对")
	}
	tlsConfig, err := pinnedTLSConfig(state.Pairing.ControlPin)
	if err != nil {
		return PeerDirectoryResponse{}, err
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}, Timeout: 15 * time.Second}
	url := "https://" + pairingAddress(state.Pairing.ControlHost, state.Pairing.ControlPort) + "/v1/peers"
	request, _ := http.NewRequest(http.MethodGet, url, nil)
	request.Header.Set("Authorization", "MeshLAN-Device "+state.Name+":"+state.Pairing.DeviceToken)
	response, err := client.Do(request)
	if err != nil {
		return PeerDirectoryResponse{}, err
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return PeerDirectoryResponse{}, fmt.Errorf("设备目录请求失败 HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var directory PeerDirectoryResponse
	if err := json.Unmarshal(responseBody, &directory); err != nil {
		return PeerDirectoryResponse{}, err
	}
	return directory, nil
}

func (a *clientApp) load() (ClientState, error) {
	var state ClientState
	err := loadJSON(a.statePath, &state)
	if errors.Is(err, os.ErrNotExist) {
		state = ClientState{
			Version:        protocolVersion,
			PrivateKeyPath: filepath.Join(a.root, "host.key"), PublicKeyPath: filepath.Join(a.root, "host.pub"),
			CertificatePath: filepath.Join(a.root, "host.crt"), CACertificatePath: filepath.Join(a.root, "ca.crt"), ConfigPath: filepath.Join(a.root, "config.yml"),
			ForceP2P: true, P2PModeVersion: p2pModeVersion,
			IPMode: "dual", IPModeVersion: ipModeVersion,
			PreferredP2PInterface: "auto", PreferredBusinessInterface: "auto", InterfaceRoutingVersion: interfaceRoutingVersion,
			AutoUpdate: true, UpdatePreferenceVersion: updatePreferenceVersion,
			MeshDNSEnabled: true, MeshDNSPreferenceVersion: meshDNSPreferenceVersion,
		}
		return state, nil
	}
	if err == nil {
		if migrationErr := migrateClientStateSecrets(a.statePath, &state); migrationErr != nil {
			return ClientState{}, migrationErr
		}
	}
	return state, err
}

func nebulaServiceStatePowerShell() (exists, running bool) {
	script := `$s=Get-Service Nebula -ErrorAction SilentlyContinue; if($null -eq $s){'missing'}elseif($s.Status -eq 'Running'){'running'}else{'stopped'}`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", script)
	hidden(cmd)
	output, err := cmd.Output()
	if err != nil {
		return false, false
	}
	state := strings.TrimSpace(strings.ToLower(string(output)))
	return state != "missing", state == "running"
}

func (a *clientApp) installServiceIfMissing(state ClientState) error {
	exists, _ := nebulaServiceState()
	if exists {
		return nil
	}
	if state.Pairing == nil || state.ConfigPath == "" {
		return errors.New("本机尚未完成配对")
	}
	if err := a.ensureRuntime(); err != nil {
		return err
	}
	return runElevated(a.nebula, []string{"-service", "install", "-config", state.ConfigPath})
}

func (a *clientApp) ensureKeys(state *ClientState) error {
	if err := a.ensureRuntime(); err != nil {
		return err
	}
	if _, err := os.Stat(state.PrivateKeyPath); err == nil {
		return nil
	}
	cmd := exec.Command(a.cert, "keygen", "-out-key", state.PrivateKeyPath, "-out-pub", state.PublicKeyPath)
	hidden(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("生成 Nebula 密钥失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func (a *clientApp) ensureOptimizedClientConfig() (ClientState, bool, error) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil || state.Pairing == nil {
		return state, false, err
	}
	stateChanged := false
	if applyP2PModeDefaults(&state) {
		stateChanged = true
	}
	if applyIPModeDefaults(&state) {
		stateChanged = true
	}
	if applyInterfaceRoutingDefaults(&state) {
		stateChanged = true
	}
	if applyUpdatePreferenceDefaults(&state) {
		stateChanged = true
	}
	if applyMeshDNSPreferenceDefaults(&state) {
		stateChanged = true
	}
	if applyNetworkAutomationDefaults(&state) {
		stateChanged = true
	}
	if applyProxyCompatibilityDefaults(&state) {
		stateChanged = true
	}
	port := clientListenPort(state)
	if state.NebulaListenPort != port {
		state.NebulaListenPort = port
		stateChanged = true
	}
	if state.NATConfigVersion != natConfigVersion {
		state.NATConfigVersion = natConfigVersion
		stateChanged = true
	}
	config, err := renderClientConfig(state)
	if err != nil {
		return state, false, err
	}
	current, readErr := os.ReadFile(state.ConfigPath)
	configChanged := readErr != nil || string(current) != config
	if configChanged {
		if err := os.WriteFile(state.ConfigPath, []byte(config), 0o600); err != nil {
			return state, false, err
		}
	}
	if stateChanged {
		if err := saveJSON(a.statePath, state); err != nil {
			return state, false, err
		}
	}
	return state, configChanged, nil
}

func (a *clientApp) saveNATApplyResult(version int, portMapping string, applyErr error) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil {
		return
	}
	if applyErr == nil {
		state.NATAppliedVersion = version
		state.NATLastError = ""
		state.NATPortMapping = portMapping
	} else {
		state.NATLastError = applyErr.Error()
	}
	_ = saveJSON(a.statePath, state)
}

func (a *clientApp) applyNATOptimization() error {
	state, _, err := a.ensureOptimizedClientConfig()
	if err != nil {
		return err
	}
	if state.Pairing == nil {
		return errors.New("本机尚未完成配对")
	}
	if err := a.ensureRuntime(); err != nil {
		a.saveNATApplyResult(state.NATConfigVersion, state.NATPortMapping, err)
		return err
	}
	if exists, _ := nebulaServiceState(); !exists {
		if err := a.installServiceIfMissing(state); err != nil {
			a.saveNATApplyResult(state.NATConfigVersion, state.NATPortMapping, err)
			return err
		}
	}
	routeGuardStagingPath, routeGuardStatusPath, err := writeRouteGuardScript(state)
	if err != nil {
		a.saveNATApplyResult(state.NATConfigVersion, state.NATPortMapping, err)
		return err
	}
	routeGuardScriptPath, _ := routeGuardPaths(state)
	clientUserSID, err := currentUserSIDString()
	if err != nil {
		a.saveNATApplyResult(state.NATConfigVersion, state.NATPortMapping, err)
		return err
	}
	routeGuardArguments := strings.Join([]string{
		"-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
		"-File", commandLineQuote(routeGuardScriptPath),
		"-StatePath", commandLineQuote(a.statePath),
		"-StatusPath", commandLineQuote(routeGuardStatusPath),
		"-ClientUserSID", commandLineQuote(clientUserSID),
	}, " ")
	resultPath := filepath.Join(a.root, "nat-port-mapping.txt")
	routeGuardHash := fmt.Sprintf("%x", sha256.Sum256([]byte(routeGuardPowerShell)))
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'
$stagedRouteGuard=%s
$secureRouteGuard=%s
$secureDirectory=Split-Path -Parent $secureRouteGuard
New-Item -ItemType Directory -Force -Path $secureDirectory | Out-Null
$routeGuardBytes=[IO.File]::ReadAllBytes($stagedRouteGuard)
$sha=[Security.Cryptography.SHA256]::Create()
try {$routeGuardHash=([BitConverter]::ToString($sha.ComputeHash($routeGuardBytes))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
if($routeGuardHash -ne '%s'){throw 'Route Guard staging hash mismatch'}
[IO.File]::WriteAllBytes($secureRouteGuard,$routeGuardBytes)
& icacls.exe $secureDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
& icacls.exe $secureRouteGuard /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' | Out-Null
$legacyRouteGuard=Join-Path (Split-Path -Parent %s) 'route-guard.ps1'
if($legacyRouteGuard -ne $secureRouteGuard){Remove-Item -LiteralPath $legacyRouteGuard -Force -ErrorAction SilentlyContinue}
$service=Get-Service -Name Nebula -ErrorAction Stop
Set-Service -Name Nebula -StartupType Automatic
if($service.Status -eq 'Running'){Restart-Service -Name Nebula -Force -ErrorAction Stop}else{Start-Service -Name Nebula -ErrorAction Stop}
$mappingStatus='unavailable'
try {
  $physical=Get-NetIPConfiguration -All -ErrorAction Stop | Where-Object {$null -ne $_.NetAdapter -and $_.NetAdapter.HardwareInterface -and $_.NetAdapter.Status -eq 'Up' -and $null -ne $_.IPv4DefaultGateway} | Select-Object -First 1
  $localAddress=$physical.IPv4Address | Where-Object {$_.AddressState -eq 'Preferred'} | Select-Object -First 1 -ExpandProperty IPAddress
  $mappings=(New-Object -ComObject HNetCfg.NATUPnP).StaticPortMappingCollection
  if($null -ne $mappings -and $localAddress) {
    $existing=@($mappings) | Where-Object {$_.ExternalPort -eq %d -and $_.Protocol -eq 'UDP'} | Select-Object -First 1
    if($null -eq $existing) {$null=$mappings.Add(%d,'UDP',%d,$localAddress,$true,'MeshLAN Nebula P2P')}
    $mappingStatus='mapped'
  }
} catch {
  $mappingStatus='failed'
}
Set-Content -LiteralPath %s -Encoding ascii -Value $mappingStatus
$taskName='MeshLAN Route Guard'
$taskAction=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument %s
$taskTrigger=New-ScheduledTaskTrigger -AtStartup
$taskSettings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
$taskPrincipal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description 'Keep MeshLAN Nebula underlay on the physical network and outside TUN proxies.' -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
`, psQuote(routeGuardStagingPath), psQuote(routeGuardScriptPath), routeGuardHash, psQuote(state.ConfigPath), state.NebulaListenPort, state.NebulaListenPort, state.NebulaListenPort, psQuote(resultPath), psQuote(routeGuardArguments))
	defer os.Remove(routeGuardStagingPath)
	defer os.Remove(resultPath)
	err = runElevated("powershell.exe", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedPowerShellCommand(script)})
	portMapping := "unavailable"
	if data, readErr := os.ReadFile(resultPath); readErr == nil && strings.TrimSpace(string(data)) != "" {
		portMapping = strings.TrimSpace(string(data))
	}
	a.saveNATApplyResult(state.NATConfigVersion, portMapping, err)
	if err == nil {
		requireRaceConfirmation := state.AutoDualStack && normalizeIPMode(state.IPMode) == "dual" && state.RaceRequestVersion > 0
		for attempt := 0; attempt < 360; attempt++ {
			guard := readRouteGuardStatus(state)
			componentReady := guard.Version >= routeGuardVersion && guard.Mode == "guarding" && guard.BypassReady
			raceReady := !requireRaceConfirmation || guard.RaceAppliedVersion >= state.RaceRequestVersion
			if componentReady && raceReady {
				return nil
			}
			time.Sleep(250 * time.Millisecond)
		}
		return errors.New("网络组件已注册，但90秒内未确认端点重注册完成；请检查 Route Guard 状态后重试")
	}
	return err
}

func (a *clientApp) setForceP2P(force bool) error {
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		state.ForceP2P = force
		state.P2PModeVersion = p2pModeVersion
		err = saveJSON(a.statePath, state)
	}
	a.stateMu.Unlock()
	if err != nil {
		return err
	}
	_, _, err = a.ensureOptimizedClientConfig()
	return err
}

func (a *clientApp) setIPMode(mode string) error {
	mode = normalizeIPMode(mode)
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		state.IPMode = mode
		state.IPModeVersion = ipModeVersion
		if mode != "dual" {
			state.AutoDualStack = false
			state.AutoNetworkScenes = false
			state.NetworkAutomationVersion = networkAutomationVersion
		}
		err = saveJSON(a.statePath, state)
	}
	a.stateMu.Unlock()
	if err != nil {
		return err
	}
	_, _, err = a.ensureOptimizedClientConfig()
	return err
}

func (a *clientApp) setInterfacePreferences(p2p, business string) error {
	p2p = normalizeInterfacePreference(p2p)
	business = normalizeInterfacePreference(business)
	if !validInterfacePreference(p2p) || !validInterfacePreference(business) {
		return errors.New("网卡名称无效")
	}
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		state.PreferredP2PInterface = p2p
		state.PreferredBusinessInterface = business
		state.InterfaceRoutingVersion = interfaceRoutingVersion
		if index := findNetworkScene(state.NetworkScenes, state.NetworkFingerprint); index >= 0 {
			state.NetworkScenes[index].P2PInterface = p2p
			state.NetworkScenes[index].BusinessInterface = business
			state.NetworkScenes[index].LastSeen = time.Now().UTC()
		}
		err = saveJSON(a.statePath, state)
	}
	a.stateMu.Unlock()
	return err
}

var nebulaHandshakePathPattern = regexp.MustCompile(`vpnAddrs=\[([^\]]+)\].*\sfrom=(?:"([^"]+)"|([^\s]+))`)

var nebulaPathCache struct {
	sync.Mutex
	loadedAt   time.Time
	paths      []NetworkPathRecord
	refreshing bool
}

func readNebulaPathRecords(lighthouseAddress string) []NetworkPathRecord {
	nebulaPathCache.Lock()
	cached := append([]NetworkPathRecord(nil), nebulaPathCache.paths...)
	if time.Since(nebulaPathCache.loadedAt) < 10*time.Second || nebulaPathCache.refreshing {
		nebulaPathCache.Unlock()
		return cached
	}
	nebulaPathCache.refreshing = true
	nebulaPathCache.Unlock()
	go func() {
		paths := queryNebulaPathRecords(lighthouseAddress)
		nebulaPathCache.Lock()
		defer nebulaPathCache.Unlock()
		nebulaPathCache.refreshing = false
		nebulaPathCache.loadedAt = time.Now()
		if paths != nil {
			nebulaPathCache.paths = append([]NetworkPathRecord(nil), paths...)
		}
	}()
	return cached
}

func queryNebulaPathRecords(lighthouseAddress string) []NetworkPathRecord {
	script := `$events=@(Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Nebula';StartTime=(Get-Date).AddDays(-1)} -MaxEvents 160 -ErrorAction SilentlyContinue | Where-Object {$_.Message -like '*Handshake message received*'} | ForEach-Object {[pscustomobject]@{time=$_.TimeCreated.ToUniversalTime().ToString('o');message=$_.Message}}); ConvertTo-Json -InputObject $events -Compress`
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command", script)
	hidden(cmd)
	output, err := cmd.Output()
	if err != nil || len(bytes.TrimSpace(output)) == 0 {
		return nil
	}
	var events []struct {
		Time    time.Time `json:"time"`
		Message string    `json:"message"`
	}
	if err := json.Unmarshal(output, &events); err != nil {
		return nil
	}
	lighthouseAddress = strings.Split(lighthouseAddress, "/")[0]
	seen := map[string]bool{}
	paths := make([]NetworkPathRecord, 0, len(events))
	for _, event := range events {
		message := strings.Join(strings.Fields(event.Message), " ")
		match := nebulaHandshakePathPattern.FindStringSubmatch(message)
		if len(match) != 4 {
			continue
		}
		address := strings.Fields(match[1])[0]
		if address == lighthouseAddress || seen[address] {
			continue
		}
		underlay := match[2]
		if underlay == "" {
			underlay = match[3]
		}
		mode := "p2p"
		if strings.Contains(underlay, "(relayed)") {
			mode = "relay"
			underlay = strings.TrimSpace(strings.TrimSuffix(underlay, "(relayed)"))
		}
		seen[address] = true
		paths = append(paths, NetworkPathRecord{Address: address, Mode: mode, Underlay: underlay, ObservedAt: event.Time})
	}
	return paths
}

func networkStatus(state ClientState) NATStatusResponse {
	status := NATStatusResponse{
		ListenPort: state.NebulaListenPort, ConfigVersion: state.NATConfigVersion,
		AppliedVersion: state.NATAppliedVersion, RestartRequired: state.NATConfigVersion > state.NATAppliedVersion,
		WindowsWFPBypass: true, LastError: state.NATLastError,
		PortMapping: state.NATPortMapping, ForceP2P: state.ForceP2P, RouteGuard: readRouteGuardStatus(state),
	}
	if status.ListenPort == 0 && state.Pairing != nil {
		status.ListenPort = clientListenPort(state)
	}
	if state.Pairing != nil {
		status.Paths = peerPathsExcludingLighthouses(readNebulaPathRecords(state.Pairing.LighthouseAddress), effectiveLighthouseEndpoints(state.Pairing))
	}
	for _, path := range status.Paths {
		if path.Mode == "p2p" {
			status.DirectCount++
		} else if path.Mode == "relay" {
			status.RelayCount++
		}
	}
	return status
}

func peerPathsExcludingLighthouses(paths []NetworkPathRecord, nodes []LighthouseEndpoint) []NetworkPathRecord {
	excluded := map[string]bool{}
	for _, node := range nodes {
		excluded[strings.Split(node.Address, "/")[0]] = true
	}
	filtered := make([]NetworkPathRecord, 0, len(paths))
	for _, path := range paths {
		if !excluded[strings.Split(path.Address, "/")[0]] {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

var pingLatencyPattern = regexp.MustCompile(`(?i)(\d+)\s*ms`)

func probeOverlayAddress(address string) (bool, int64) {
	address = strings.Split(strings.TrimSpace(address), "/")[0]
	if address == "" {
		return false, -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1600*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping.exe", "-n", "1", "-w", "1000", address)
	hidden(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, -1
	}
	match := pingLatencyPattern.FindSubmatch(output)
	if len(match) == 2 {
		if value, parseErr := strconv.ParseInt(string(match[1]), 10, 64); parseErr == nil {
			return true, value
		}
	}
	return true, -1
}

func (a *clientApp) topologySnapshot() (TopologySnapshot, error) {
	a.topologyMu.Lock()
	defer a.topologyMu.Unlock()

	state, err := a.load()
	if err != nil {
		return TopologySnapshot{}, err
	}
	if state.Pairing == nil {
		return TopologySnapshot{}, errors.New("本机尚未完成配对")
	}
	directory, err := fetchPeerDirectory(state)
	if err != nil {
		return TopologySnapshot{}, err
	}
	_, localRunning := nebulaServiceState()
	liveRx, liveTx := state.TotalRx, state.TotalTx
	if interfaceRx, interfaceTx, telemetryRunning := readLocalTelemetry(); telemetryRunning {
		if interfaceRx >= state.LastInterfaceRx {
			liveRx += interfaceRx - state.LastInterfaceRx
		}
		if interfaceTx >= state.LastInterfaceTx {
			liveTx += interfaceTx - state.LastInterfaceTx
		}
	}
	network := networkStatus(state)
	pathByAddress := map[string]NetworkPathRecord{}
	for _, path := range network.Paths {
		pathByAddress[strings.Split(path.Address, "/")[0]] = path
	}
	serviceCount := map[string]int{}
	healthyServiceCount := map[string]int{}
	for _, service := range directory.Services {
		serviceCount[service.OwnerName]++
		if service.Active && service.Healthy {
			healthyServiceCount[service.OwnerName]++
		}
	}
	localMappings := a.mappingHeartbeat(state)
	localViews, _ := a.localMappingViews(state)
	localHealthy := 0
	for _, mapping := range localMappings {
		if mapping.Active && mapping.Healthy {
			localHealthy++
		}
	}

	peers := make([]TopologyPeerNode, 0, len(directory.Peers))
	for _, peer := range directory.Peers {
		if peer.Name == state.Name {
			continue
		}
		address := strings.Split(peer.Address, "/")[0]
		path := pathByAddress[address]
		if !peer.Online {
			path = NetworkPathRecord{}
		}
		peers = append(peers, TopologyPeerNode{
			Name: peer.Name, Address: peer.Address, Online: peer.Online, ServiceRunning: peer.ServiceRunning && peer.Online,
			LatencyMs: -1, PathMode: "unknown", Underlay: path.Underlay, ObservedAt: path.ObservedAt,
			LastSeen: peer.LastSeen, OnlineSince: peer.OnlineSince, ClientVersion: peer.ClientVersion,
			ServiceCount: serviceCount[peer.Name], HealthyServiceCount: healthyServiceCount[peer.Name],
			BytesReceived: peer.BytesReceived, BytesSent: peer.BytesSent,
		})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })

	var probes sync.WaitGroup
	for i := range peers {
		probes.Add(1)
		go func(index int) {
			defer probes.Done()
			if !peers[index].Online {
				peers[index].Reachable = false
				peers[index].LatencyMs = -1
				peers[index].JitterMs = 0
				peers[index].PacketLossPct = 100
				peers[index].ProbeSamples = 0
				peers[index].PathMode = "down"
				peers[index].PathFamily = "unknown"
				peers[index].Underlay = ""
				peers[index].ObservedAt = time.Time{}
				return
			}
			quality := probeOverlayQuality(peers[index].Address, 4)
			peers[index].Reachable, peers[index].LatencyMs = quality.Reachable, quality.LatencyMs
			peers[index].JitterMs, peers[index].PacketLossPct, peers[index].ProbeSamples = quality.JitterMs, quality.PacketLossPct, quality.Samples
			if !quality.Reachable {
				peers[index].PathMode = "down"
				return
			}
			address := strings.Split(peers[index].Address, "/")[0]
			if path, exists := pathByAddress[address]; exists {
				peers[index].PathMode = path.Mode
			} else {
				peers[index].PathMode = "p2p"
			}
		}(i)
	}
	var lighthouseReachable bool
	var lighthouseLatency int64
	probes.Add(1)
	go func() {
		defer probes.Done()
		lighthouseReachable, lighthouseLatency = probeOverlayAddress(state.Pairing.LighthouseAddress)
	}()
	probes.Wait()
	pathChanges := map[string]string{}
	for index := range peers {
		changed, reason := a.observePeerPath(&peers[index], time.Now().UTC())
		if changed {
			pathChanges[peers[index].Name] = reason
		}
	}

	interfaces := make([]TopologyInterfaceNode, 0, 3)
	guard := network.RouteGuard
	if guard.PreferredBusiness != "" {
		interfaces = append(interfaces, TopologyInterfaceNode{
			Role: "business", Alias: guard.PreferredBusiness, Address: guard.BusinessAddress,
			Gateway: guard.BusinessGateway, Active: guard.BusinessActive,
		})
	}
	if guard.PhysicalInterface != "" {
		interfaces = append(interfaces, TopologyInterfaceNode{
			Role: "p2p", Alias: guard.PhysicalInterface, Address: guard.PhysicalAddress,
			Gateway: guard.Gateway, Active: guard.BypassReady,
		})
	}
	if guard.IPv6Interface != "" && guard.IPv6Address != "" {
		interfaces = append(interfaces, TopologyInterfaceNode{
			Role: "p2p", Alias: guard.IPv6Interface, Address: guard.IPv6Address,
			Gateway: guard.IPv6Gateway, Active: guard.BypassReady, IPv6: true,
			Suppressed: guard.IPv6DefaultSuppressed,
		})
	}

	type serviceTraffic struct {
		active  int
		toLocal uint64
		toPeer  uint64
	}
	trafficByMapping := map[string]serviceTraffic{}
	for _, connection := range a.connectionRecords(state.ServiceMappings) {
		if !connection.Allowed {
			continue
		}
		traffic := trafficByMapping[connection.MappingID]
		traffic.active += connection.Active
		traffic.toLocal += connection.BytesToLocal
		traffic.toPeer += connection.BytesToPeer
		trafficByMapping[connection.MappingID] = traffic
	}
	services := make([]TopologyServiceNode, 0, len(directory.Services)+len(localViews))
	for _, service := range directory.Services {
		if service.OwnerName == state.Name {
			continue
		}
		services = append(services, TopologyServiceNode{
			ID: service.ID, OwnerName: service.OwnerName, ServiceName: service.ServiceName,
			Address: service.Address, Port: service.Port, Protocol: normalizeMappingProtocol(service.Protocol),
			DNSName: service.DNSName, URL: service.URL, Active: service.Active, Paused: service.Paused,
			Healthy: service.Healthy, PortlessHTTP: service.PortlessHTTP, ApprovalRequired: service.ApprovalRequired,
			LatencyMs: service.LatencyMs, CheckedAt: service.CheckedAt,
		})
	}
	for _, service := range localViews {
		traffic := trafficByMapping[service.ID]
		services = append(services, TopologyServiceNode{
			ID: service.ID, OwnerName: state.Name, ServiceName: service.ServiceName,
			Address: service.MeshAddress, Port: service.MeshPort, Protocol: normalizeMappingProtocol(service.Protocol),
			DNSName: service.DNSName, URL: service.URL, Local: true, Active: service.Active, Paused: service.Paused,
			Healthy: service.Healthy, PortlessHTTP: service.PortlessHTTP, ApprovalRequired: service.ApprovalRequired,
			LatencyMs: service.LatencyMs, CheckedAt: service.CheckedAt, ActiveConnections: traffic.active,
			BytesToService: traffic.toLocal, BytesFromService: traffic.toPeer,
		})
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].OwnerName != services[j].OwnerName {
			return services[i].OwnerName < services[j].OwnerName
		}
		return services[i].ServiceName < services[j].ServiceName
	})

	snapshot := TopologySnapshot{
		RefreshedAt: time.Now(),
		Local: TopologyLocalNode{
			Name: state.Name, Address: state.Pairing.Address, ServiceRunning: localRunning,
			IPMode: normalizeIPMode(state.IPMode), ForceP2P: state.ForceP2P, ListenPort: state.NebulaListenPort,
			ServiceCount: len(localMappings), HealthyServiceCount: localHealthy,
			BytesReceived: liveRx, BytesSent: liveTx,
		},
		Lighthouse: TopologyLighthouseNode{
			Address: state.Pairing.LighthouseAddress, Endpoint: state.Pairing.LighthouseEndpoint,
			Reachable: lighthouseReachable, LatencyMs: lighthouseLatency,
		},
		Interfaces: interfaces, TUN: append([]string(nil), guard.TUNInterfaces...), Peers: peers, Services: services,
	}
	a.historyMu.Lock()
	shouldRecord := time.Since(a.historyLastTopology) >= 15*time.Second
	if shouldRecord {
		a.historyLastTopology = snapshot.RefreshedAt
		for _, peer := range snapshot.Peers {
			if detail := pathChanges[peer.Name]; detail != "" {
				_ = a.history.RecordEvent("client", "path_changed", peer.Name, detail, snapshot.RefreshedAt)
			}
		}
	}
	a.historyMu.Unlock()
	if shouldRecord {
		_ = a.history.RecordTopology(snapshot)
	}
	return snapshot, nil
}

func (a *clientApp) routes() http.Handler {
	mux := http.NewServeMux()
	a.registerAIConversationRoutes(mux)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		data, _ := clientWeb.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/meshlan-icon.png", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("assets/meshlan-icon.png")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/ai-assistant.js", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/ai-assistant.js")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/ai-assistant.css", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/ai-assistant.css")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/topology-redesign.js", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/topology-redesign.js")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/topology-redesign.css", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/topology-redesign.css")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/history-redesign.js", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/history-redesign.js")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/history-redesign.css", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/history-redesign.css")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/version-polish.js", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/version-polish.js")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/i18n.js", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/i18n.js")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /assets/advanced-settings.js", func(w http.ResponseWriter, _ *http.Request) {
		data, err := clientWeb.ReadFile("web/advanced-settings.js")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, _ *http.Request) {
		state, _ := a.load()
		exists, running := nebulaServiceState()
		status := "STATE: NOT_INSTALLED\n"
		if exists && running {
			status = "STATE: Running\nSERVICE: Nebula\n"
		} else if exists {
			status = "STATE: Stopped\nSERVICE: Nebula\n"
		}
		jsonReply(w, 200, map[string]any{
			"state": publicClientState(state), "status": status, "network": networkStatus(state),
			"clientVersion": clientVersion, "nebulaVersion": nebulaVersion,
		})
	})
	mux.HandleFunc("GET /api/network", func(w http.ResponseWriter, _ *http.Request) {
		state, _, err := a.ensureOptimizedClientConfig()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, networkStatus(state))
	})
	mux.HandleFunc("GET /api/topology", func(w http.ResponseWriter, _ *http.Request) {
		topology, err := a.topologySnapshot()
		if err != nil {
			jsonReply(w, 502, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, topology)
	})
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if value := strings.TrimSpace(r.URL.Query().Get("hours")); value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil {
				jsonReply(w, 400, map[string]string{"error": "历史时间范围无效"})
				return
			}
			hours = parsed
		}
		history, err := a.history.ClientHistory(hours)
		if err != nil {
			jsonReply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, history)
	})
	mux.HandleFunc("GET /api/history/live", func(w http.ResponseWriter, _ *http.Request) {
		point, err := a.liveHistoryPoint()
		if err != nil {
			jsonReply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, http.StatusOK, point)
	})
	mux.HandleFunc("GET /api/dns", func(w http.ResponseWriter, _ *http.Request) {
		status, err := a.meshDNSStatus()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, status)
	})
	mux.HandleFunc("POST /api/diagnostics/nat", func(w http.ResponseWriter, _ *http.Request) {
		a.diagnosticMu.Lock()
		defer a.diagnosticMu.Unlock()
		jsonReply(w, 200, a.runNATDiagnostic())
	})
	mux.HandleFunc("GET /api/diagnostics/report", func(w http.ResponseWriter, _ *http.Request) {
		data, name, err := a.buildDiagnosticReport()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /api/dns/enable", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Enabled bool `json:"enabled"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "MeshDNS 设置无效"})
			return
		}
		if err := a.setMeshDNSEnabled(input.Enabled); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "enabled": input.Enabled})
	})
	mux.HandleFunc("POST /api/dns/prefix", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Prefix string `json:"prefix"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "DNS前缀请求无效"})
			return
		}
		status, err := a.setOwnMeshDNSPrefix(input.Prefix)
		if err != nil {
			jsonReply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "dns": status})
	})
	mux.HandleFunc("GET /api/identity", func(w http.ResponseWriter, _ *http.Request) {
		jsonReply(w, 200, a.identityStatus())
	})
	mux.HandleFunc("GET /api/automation", func(w http.ResponseWriter, _ *http.Request) {
		jsonReply(w, 200, a.dualStackStatus())
	})
	mux.HandleFunc("GET /api/lighthouses", func(w http.ResponseWriter, _ *http.Request) {
		jsonReply(w, http.StatusOK, a.lighthousePage())
	})
	mux.HandleFunc("POST /api/lighthouses/sync", func(w http.ResponseWriter, _ *http.Request) {
		a.sendHeartbeat()
		jsonReply(w, http.StatusOK, a.lighthousePage())
	})
	mux.HandleFunc("GET /api/settings/proxy-compatibility", func(w http.ResponseWriter, _ *http.Request) {
		jsonReply(w, http.StatusOK, a.proxyCompatibilityStatus())
	})
	mux.HandleFunc("POST /api/settings/proxy-compatibility", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Enabled bool `json:"enabled"`
		}
		if decodeRequest(r, &input) != nil {
			jsonReply(w, http.StatusBadRequest, map[string]string{"error": "代理兼容设置无效"})
			return
		}
		status, err := a.setProxyCompatibility(input.Enabled)
		if err != nil {
			jsonReply(w, http.StatusConflict, map[string]any{"error": err.Error(), "status": status})
			return
		}
		jsonReply(w, http.StatusOK, status)
	})
	mux.HandleFunc("GET /api/ai/status", func(w http.ResponseWriter, _ *http.Request) {
		a.stateMu.Lock()
		state, err := a.load()
		a.stateMu.Unlock()
		if err != nil || state.Pairing == nil {
			jsonReply(w, http.StatusConflict, map[string]string{"error": "本机尚未配对"})
			return
		}
		var remote map[string]any
		if err := deviceControlRequest(state, http.MethodGet, "/v1/ai/status", nil, &remote); err != nil {
			jsonReply(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		remote["localE2EE"] = state.AIEncryptedPrivateKey != "" && validX25519PublicKey(state.AIEncryptionPublicKey)
		jsonReply(w, http.StatusOK, remote)
	})
	mux.HandleFunc("POST /api/ai/plan", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Prompt string `json:"prompt"`
		}
		if decodeRequest(r, &input) != nil {
			jsonReply(w, http.StatusBadRequest, map[string]string{"error": "AI请求无效"})
			return
		}
		plan, err := a.requestAIPlan(input.Prompt)
		if err != nil {
			jsonReply(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, http.StatusOK, plan)
	})
	mux.HandleFunc("POST /api/ai/execute", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			PlanID         string `json:"planId"`
			ConversationID string `json:"conversationId"`
		}
		if decodeRequest(r, &input) != nil {
			jsonReply(w, http.StatusBadRequest, map[string]string{"error": "AI执行请求无效"})
			return
		}
		result, err := a.executeAIPlan(input.PlanID)
		if err != nil {
			jsonReply(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		if input.ConversationID != "" {
			lines := make([]string, 0, len(result.Results)+1)
			for _, item := range result.Results {
				prefix := "✓"
				if !item.Success {
					prefix = "✗"
				}
				lines = append(lines, fmt.Sprintf("%s %s：%s", prefix, item.Tool, item.Message))
			}
			lines = append(lines, fmt.Sprintf("复核结果：%s", map[bool]string{true: "通过", false: "仍需处理"}[result.Verified]))
			_, _ = a.history.AddAIMessage(input.ConversationID, "system", strings.Join(lines, "\n"), nil)
			if result.FollowUp != nil {
				_, _ = a.history.AddAIMessage(input.ConversationID, "assistant", result.FollowUp.Reply, result.FollowUp)
			}
		}
		jsonReply(w, http.StatusOK, result)
	})
	mux.HandleFunc("POST /api/ai/report", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			PlanID string `json:"planId"`
			Prompt string `json:"prompt"`
		}
		if decodeRequest(r, &input) != nil {
			jsonReply(w, http.StatusBadRequest, map[string]string{"error": "AI Bug上报请求无效"})
			return
		}
		reportID, err := a.submitAIBugReport(input.PlanID, input.Prompt)
		if err != nil {
			jsonReply(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, http.StatusCreated, map[string]any{"ok": true, "reportId": reportID})
	})
	mux.HandleFunc("POST /api/https/trust", func(w http.ResponseWriter, _ *http.Request) {
		status, err := a.retryMeshHTTPSRootTrust()
		if err != nil {
			jsonReply(w, 409, map[string]any{"error": err.Error(), "httpGateway": status})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "httpGateway": status})
	})
	mux.HandleFunc("GET /api/https/status", func(w http.ResponseWriter, _ *http.Request) {
		jsonReply(w, http.StatusOK, a.meshHTTPSRootStatus())
	})
	mux.HandleFunc("POST /api/https/untrust", func(w http.ResponseWriter, _ *http.Request) {
		err := a.beginMeshHTTPSRootRemoval()
		if err != nil {
			jsonReply(w, http.StatusConflict, map[string]any{"error": err.Error(), "status": a.meshHTTPSRootStatus()})
			return
		}
		jsonReply(w, http.StatusAccepted, map[string]any{"ok": true, "pending": true})
	})
	mux.HandleFunc("POST /api/automation", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Enabled bool `json:"enabled"`
			Scenes  bool `json:"scenes"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "自动网络设置无效"})
			return
		}
		status, err := a.setNetworkAutomation(input.Enabled, input.Scenes)
		if err != nil {
			code := 500
			if errors.Is(err, errDualStackModeRequired) {
				code = 409
			}
			jsonReply(w, code, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, status)
	})
	mux.HandleFunc("POST /api/network-scenes/rename", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "场景请求无效"})
			return
		}
		status, err := a.renameNetworkScene(input.ID, input.Name)
		if err != nil {
			jsonReply(w, 404, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, status)
	})
	mux.HandleFunc("POST /api/network-scenes/delete", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "场景请求无效"})
			return
		}
		status, err := a.deleteNetworkScene(input.ID)
		if err != nil {
			jsonReply(w, 404, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, status)
	})
	mux.HandleFunc("POST /api/identity/repair", func(w http.ResponseWriter, _ *http.Request) {
		status, err := a.repairIdentity()
		if err != nil {
			jsonReply(w, 500, map[string]any{"error": err.Error(), "identity": status})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "identity": status})
	})
	mux.HandleFunc("GET /api/update", func(w http.ResponseWriter, _ *http.Request) {
		status, _ := a.checkForUpdate()
		jsonReply(w, 200, status)
	})
	mux.HandleFunc("POST /api/update/auto", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Enabled bool `json:"enabled"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "自动更新设置无效"})
			return
		}
		if err := a.setAutoUpdate(input.Enabled); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "enabled": input.Enabled})
	})
	mux.HandleFunc("POST /api/update/apply", func(w http.ResponseWriter, _ *http.Request) {
		status, err := a.applyAvailableUpdate()
		if err != nil {
			jsonReply(w, 409, map[string]any{"error": err.Error(), "update": status})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "version": status.Manifest.Version, "restarting": true})
	})
	mux.HandleFunc("POST /api/update/rollback", func(w http.ResponseWriter, _ *http.Request) {
		if err := a.applyRollback(); err != nil {
			jsonReply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "restarting": true})
	})
	mux.HandleFunc("POST /api/nat/apply", func(w http.ResponseWriter, _ *http.Request) {
		if err := a.applyNATOptimization(); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		state, _ := a.load()
		jsonReply(w, 200, map[string]any{"ok": true, "network": networkStatus(state)})
	})
	mux.HandleFunc("POST /api/nat/mode", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ForceP2P bool `json:"forceP2P"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "P2P 模式请求无效"})
			return
		}
		state, err := a.load()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		previous := state.ForceP2P
		if err := a.setForceP2P(input.ForceP2P); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := a.applyNATOptimization(); err != nil {
			_ = a.setForceP2P(previous)
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		state, _ = a.load()
		jsonReply(w, 200, map[string]any{"ok": true, "network": networkStatus(state)})
	})
	mux.HandleFunc("POST /api/settings/ip-mode", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Mode string `json:"mode"`
		}
		if err := decodeRequest(r, &input); err != nil || (input.Mode != "ipv4" && input.Mode != "ipv6" && input.Mode != "dual") {
			jsonReply(w, 400, map[string]string{"error": "IP 模式无效"})
			return
		}
		state, err := a.load()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		previous := normalizeIPMode(state.IPMode)
		if err := a.setIPMode(input.Mode); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := a.applyNATOptimization(); err != nil {
			_ = a.setIPMode(previous)
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		state, _ = a.load()
		jsonReply(w, 200, map[string]any{"ok": true, "mode": state.IPMode, "network": networkStatus(state)})
	})
	mux.HandleFunc("POST /api/settings/interfaces", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			P2P      string `json:"p2p"`
			Business string `json:"business"`
		}
		if err := decodeRequest(r, &input); err != nil || !validInterfacePreference(input.P2P) || !validInterfacePreference(input.Business) {
			jsonReply(w, 400, map[string]string{"error": "网卡设置无效"})
			return
		}
		state, err := a.load()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		previousP2P, previousBusiness := state.PreferredP2PInterface, state.PreferredBusinessInterface
		if err := a.setInterfacePreferences(input.P2P, input.Business); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := a.applyNATOptimization(); err != nil {
			_ = a.setInterfacePreferences(previousP2P, previousBusiness)
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		state, _ = a.load()
		jsonReply(w, 200, map[string]any{"ok": true, "p2p": state.PreferredP2PInterface, "business": state.PreferredBusinessInterface, "network": networkStatus(state)})
	})
	mux.HandleFunc("GET /api/peers", func(w http.ResponseWriter, _ *http.Request) {
		state, err := a.load()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		directory, err := fetchPeerDirectory(state)
		if err != nil {
			jsonReply(w, 502, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, directory)
	})
	mux.HandleFunc("GET /api/mappings", func(w http.ResponseWriter, _ *http.Request) {
		a.syncForwarders()
		_ = a.refreshControl()
		a.stateMu.Lock()
		state, err := a.load()
		a.stateMu.Unlock()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		local, meshAddress := a.localMappingViews(state)
		control := a.controlSnapshot()
		result := ServiceMappingPageResponse{
			Local: local, MeshAddress: meshAddress, RefreshedAt: time.Now(),
			Connections: a.connectionRecords(state.ServiceMappings), Policies: control.Policies,
			DNSPrefix: state.DNSPrefix, HTTPGateway: a.httpGatewayStatus(),
		}
		if directory, directoryErr := fetchPeerDirectory(state); directoryErr == nil {
			result.Shared = directory.Services
			result.RefreshedAt = directory.RefreshedAt
		} else {
			result.SharedError = directoryErr.Error()
		}
		jsonReply(w, 200, result)
	})
	mux.HandleFunc("GET /api/files", func(w http.ResponseWriter, _ *http.Request) {
		page, err := a.fileSharePage()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, page)
	})
	mux.HandleFunc("POST /api/files", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxFileShareSize+(2<<20))
		reader, err := r.MultipartReader()
		if err != nil {
			jsonReply(w, 400, map[string]string{"error": "文件上传格式无效"})
			return
		}
		fields := map[string]string{}
		var created LocalFileShareView
		foundFile := false
		for {
			part, nextErr := reader.NextPart()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				jsonReply(w, 400, map[string]string{"error": nextErr.Error()})
				return
			}
			if part.FormName() != "file" {
				value, _ := io.ReadAll(io.LimitReader(part, 4096))
				fields[part.FormName()] = string(value)
				part.Close()
				continue
			}
			maxDownloads, _ := strconv.Atoi(fields["maxDownloads"])
			created, err = a.createFileShare(part, part.FileName(), fields["recipient"], parseFileShareLifetime(fields["lifetimeHours"]), maxDownloads)
			part.Close()
			if err != nil {
				jsonReply(w, 409, map[string]string{"error": err.Error()})
				return
			}
			foundFile = true
		}
		if !foundFile {
			jsonReply(w, 400, map[string]string{"error": "没有选择文件"})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "share": created})
	})
	mux.HandleFunc("POST /api/files/delete", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		if err := decodeRequest(r, &input); err != nil || !fileShareSafeID(input.ID) {
			jsonReply(w, 400, map[string]string{"error": "文件分享ID无效"})
			return
		}
		if err := a.deleteFileShare(input.ID); err != nil {
			jsonReply(w, 404, map[string]string{"error": err.Error()})
			return
		}
		_ = a.syncFileShareServer()
		go a.sendHeartbeat()
		jsonReply(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/files/download", a.proxyFileShareDownload)
	mux.HandleFunc("POST /api/mappings", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ServiceName      string `json:"serviceName"`
			DNSPrefix        string `json:"dnsPrefix"`
			LocalHost        string `json:"localHost"`
			LocalPort        int    `json:"localPort"`
			MeshPort         int    `json:"meshPort"`
			Protocol         string `json:"protocol"`
			ApprovalRequired bool   `json:"approvalRequired"`
			PortlessHTTP     bool   `json:"portlessHttp"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "映射请求无效"})
			return
		}
		mapping, err := a.addServiceMapping(input.ServiceName, input.DNSPrefix, input.LocalHost, input.LocalPort, input.MeshPort, input.Protocol, input.ApprovalRequired, input.PortlessHTTP)
		if err != nil {
			jsonReply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "mapping": mapping})
	})
	mux.HandleFunc("POST /api/mappings/dns", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID           string `json:"id"`
			DNSPrefix    string `json:"dnsPrefix"`
			PortlessHTTP bool   `json:"portlessHttp"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "映射域名设置无效"})
			return
		}
		mapping, err := a.updateServiceMappingDNS(input.ID, input.DNSPrefix, input.PortlessHTTP)
		if err != nil {
			jsonReply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "mapping": mapping})
	})
	mux.HandleFunc("POST /api/mappings/delete", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "删除请求无效"})
			return
		}
		if err := a.deleteServiceMapping(input.ID); err != nil {
			jsonReply(w, 404, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/mappings/pause", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID     string `json:"id"`
			Paused bool   `json:"paused"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "暂停请求无效"})
			return
		}
		if err := a.setServiceMappingPaused(input.ID, input.Paused); err != nil {
			jsonReply(w, 404, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/messages", func(w http.ResponseWriter, _ *http.Request) {
		if err := a.refreshControl(); err != nil {
			jsonReply(w, 502, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, a.controlSnapshot())
	})
	mux.HandleFunc("POST /api/access/request", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			OwnerName string `json:"ownerName"`
			MappingID string `json:"mappingId"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "访问申请无效"})
			return
		}
		a.stateMu.Lock()
		state, err := a.load()
		a.stateMu.Unlock()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		var output map[string]any
		if err := deviceControlRequest(state, http.MethodPost, "/v1/access/request", input, &output); err != nil {
			jsonReply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		_ = a.refreshControl()
		jsonReply(w, 200, output)
	})
	mux.HandleFunc("POST /api/access/respond", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			RequestID string `json:"requestId"`
			Approve   bool   `json:"approve"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "审批请求无效"})
			return
		}
		a.stateMu.Lock()
		state, err := a.load()
		a.stateMu.Unlock()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		var output map[string]any
		if err := deviceControlRequest(state, http.MethodPost, "/v1/access/respond", input, &output); err != nil {
			jsonReply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		_ = a.refreshControl()
		jsonReply(w, 200, output)
	})
	mux.HandleFunc("POST /api/access/user", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			MappingID string `json:"mappingId"`
			UserName  string `json:"userName"`
			Paused    bool   `json:"paused"`
		}
		if err := decodeRequest(r, &input); err != nil {
			jsonReply(w, 400, map[string]string{"error": "用户访问控制无效"})
			return
		}
		a.stateMu.Lock()
		state, err := a.load()
		a.stateMu.Unlock()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		var output map[string]any
		if err := deviceControlRequest(state, http.MethodPost, "/v1/access/user", input, &output); err != nil {
			jsonReply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		_ = a.refreshControl()
		jsonReply(w, 200, output)
	})
	mux.HandleFunc("POST /api/pair", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Name, Server, PairingHash string }
		if err := decodeRequest(r, &input); err != nil || !validName(input.Name) {
			jsonReply(w, 400, map[string]string{"error": "设备名称或请求无效"})
			return
		}
		state, _ := a.load()
		state.Name = input.Name
		if err := a.ensureKeys(&state); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		publicKey, err := os.ReadFile(state.PublicKeyPath)
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		paired, err := pairWithServer(input.Server, input.PairingHash, PairRequest{Version: protocolVersion, Name: input.Name, PublicKey: string(publicKey)})
		if err != nil {
			jsonReply(w, 502, map[string]string{"error": err.Error()})
			return
		}
		state.Pairing = &paired
		state.LighthouseUpdatedAt = time.Now().UTC()
		state.DNSPrefix = paired.DNSPrefix
		state.NebulaListenPort = clientListenPort(state)
		state.NATConfigVersion = natConfigVersion
		if err := os.WriteFile(state.CertificatePath, []byte(paired.CertificatePEM), 0o600); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := os.WriteFile(state.CACertificatePath, []byte(paired.CACertificatePEM), 0o600); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		config, _ := renderClientConfig(state)
		if err := os.WriteFile(state.ConfigPath, []byte(config), 0o600); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := saveJSON(a.statePath, state); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := a.ensureClientAIIdentity(); err != nil {
			jsonReply(w, 500, map[string]string{"error": "AI加密身份初始化失败: " + err.Error()})
			return
		}
		if err := refreshClientPrivateKeyBackup(state); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := a.applyNATOptimization(); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true, "address": paired.Address})
	})
	mux.HandleFunc("POST /api/stop", func(w http.ResponseWriter, _ *http.Request) {
		if err := runElevated("C:\\Windows\\System32\\sc.exe", []string{"stop", "Nebula"}); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/start", func(w http.ResponseWriter, _ *http.Request) {
		state, _, err := a.ensureOptimizedClientConfig()
		if err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := a.installServiceIfMissing(state); err != nil {
			jsonReply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := runElevated("C:\\Windows\\System32\\sc.exe", []string{"start", "Nebula"}); err != nil {
			time.Sleep(time.Second)
			if _, running := nebulaServiceState(); !running {
				jsonReply(w, 500, map[string]string{"error": err.Error()})
				return
			}
		}
		a.saveNATApplyResult(state.NATConfigVersion, state.NATPortMapping, nil)
		jsonReply(w, 200, map[string]bool{"ok": true})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://127.0.0.1:8777" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func installUserAutostart(executable string) {
	preference := exec.Command("reg.exe", "query", `HKCU\Software\MeshLAN\Preferences`, "/v", "StartOnLogin")
	hidden(preference)
	if output, err := preference.Output(); err == nil && (strings.Contains(string(output), "0x0") || strings.Contains(string(output), "REG_DWORD    0")) {
		remove := exec.Command("reg.exe", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "MeshLANNebula", "/f")
		hidden(remove)
		_ = remove.Run()
		return
	}
	command := fmt.Sprintf("\"%s\" client --no-gui", executable)
	cmd := exec.Command("reg.exe", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "MeshLANNebula", "/t", "REG_SZ", "/d", command, "/f")
	hidden(cmd)
	_ = cmd.Run()
}

func readLocalTelemetryPowerShell() (received, sent uint64, running bool) {
	script := `[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $s=Get-Service Nebula -ErrorAction SilentlyContinue; $n=Get-NetAdapterStatistics -Name MeshLAN -ErrorAction SilentlyContinue; [pscustomobject]@{running=($null -ne $s -and $s.Status -eq 'Running');received=$(if($null -ne $n){$n.ReceivedBytes}else{0});sent=$(if($null -ne $n){$n.SentBytes}else{0})}|ConvertTo-Json -Compress`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", script)
	hidden(cmd)
	output, err := cmd.Output()
	if err != nil {
		return 0, 0, false
	}
	var value struct {
		Running  bool   `json:"running"`
		Received uint64 `json:"received"`
		Sent     uint64 `json:"sent"`
	}
	if json.Unmarshal(output, &value) != nil {
		return 0, 0, false
	}
	return value.Received, value.Sent, value.Running
}

func (a *clientApp) liveHistoryPoint() (HistoryLocalPoint, error) {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil {
		return HistoryLocalPoint{}, err
	}
	interfaceRx, interfaceTx, running := readLocalTelemetry()
	liveRx, liveTx := state.TotalRx, state.TotalTx
	if interfaceRx >= state.LastInterfaceRx {
		liveRx += interfaceRx - state.LastInterfaceRx
	}
	if interfaceTx >= state.LastInterfaceTx {
		liveTx += interfaceTx - state.LastInterfaceTx
	}
	network := networkStatus(state)
	return HistoryLocalPoint{At: time.Now().UTC(), BytesReceived: liveRx, BytesSent: liveTx, ServiceRunning: running, DirectCount: network.DirectCount, RelayCount: network.RelayCount}, nil
}

func (a *clientApp) sendHeartbeat() {
	a.heartbeatMu.Lock()
	defer a.heartbeatMu.Unlock()
	a.syncForwarders()
	a.stateMu.Lock()
	state, err := a.load()
	if err != nil || state.Pairing == nil || state.Pairing.DeviceToken == "" || state.Pairing.ControlPin == "" {
		a.stateMu.Unlock()
		return
	}
	rx, tx, running := readLocalTelemetry()
	if rx >= state.LastInterfaceRx {
		state.TotalRx += rx - state.LastInterfaceRx
	} else {
		state.TotalRx += rx
	}
	if tx >= state.LastInterfaceTx {
		state.TotalTx += tx - state.LastInterfaceTx
	} else {
		state.TotalTx += tx
	}
	state.LastInterfaceRx, state.LastInterfaceTx = rx, tx
	fingerprint := a.currentCertificateFingerprint(&state)
	_ = saveJSON(a.statePath, state)
	mappings := a.mappingHeartbeat(state)
	a.stateMu.Unlock()
	network := networkStatus(state)
	_ = a.history.RecordLocal(HistoryLocalPoint{At: time.Now().UTC(), BytesReceived: state.TotalRx, BytesSent: state.TotalTx, ServiceRunning: running, DirectCount: network.DirectCount, RelayCount: network.RelayCount})
	seedReady, seedSHA256, seedPort := a.updateSeedStatus()
	heartbeat := HeartbeatRequest{Name: state.Name, BytesReceived: state.TotalRx, BytesSent: state.TotalTx, ServiceRunning: running, ClientVersion: clientVersion, CertificateFingerprint: fingerprint, ServiceMappings: mappings, FileShares: a.fileShareHeartbeat(), UpdateSeedReady: seedReady, UpdateSeedSHA256: seedSHA256, UpdateSeedPort: seedPort}
	heartbeat.AIEncryptionPublicKey = state.AIEncryptionPublicKey
	body, _ := json.Marshal(heartbeat)
	tlsConfig, err := pinnedTLSConfig(state.Pairing.ControlPin)
	if err != nil {
		return
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}, Timeout: 15 * time.Second}
	url := "https://" + pairingAddress(state.Pairing.ControlHost, state.Pairing.ControlPort) + "/v1/heartbeat"
	request, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "MeshLAN-Device "+state.Name+":"+state.Pairing.DeviceToken)
	response, err := client.Do(request)
	if err == nil {
		responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			var heartbeatResponse HeartbeatResponse
			if json.Unmarshal(responseBody, &heartbeatResponse) == nil {
				if heartbeatResponse.Revocations.Payload != "" {
					_, _ = a.applyRevocationEnvelope(heartbeatResponse.Revocations)
				}
				if len(heartbeatResponse.Lighthouses) > 0 {
					_ = a.syncLighthouseNodes(heartbeatResponse.Lighthouses)
				}
				if heartbeatResponse.HTTPSCACertificatePEM != "" {
					_ = a.syncMeshHTTPSCA(heartbeatResponse.HTTPSCACertificatePEM, heartbeatResponse.HTTPSCAFingerprint)
				}
				if heartbeatResponse.AIEncryptionPublicKey != "" {
					_ = a.syncServerAIKey(heartbeatResponse.AIEncryptionPublicKey)
				}
			}
		}
	}
}

func (a *clientApp) syncMeshHTTPSCA(certificatePEM, fingerprint string) error {
	certificate, err := parseCertificatePEM(certificatePEM)
	if err != nil || !certificate.IsCA || certificateSHA256(certificate.Raw) != fingerprint {
		return errors.New("主服务端返回的 Mesh HTTPS CA无效")
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil || state.Pairing == nil {
		return err
	}
	if state.Pairing.HTTPSCAFingerprint != "" && state.Pairing.HTTPSCAFingerprint != fingerprint {
		return errors.New("Mesh HTTPS CA指纹发生未授权变化")
	}
	if state.Pairing.HTTPSCAFingerprint == fingerprint && state.Pairing.HTTPSCACertificatePEM == certificatePEM {
		return nil
	}
	state.Pairing.HTTPSCACertificatePEM = certificatePEM
	state.Pairing.HTTPSCAFingerprint = fingerprint
	return saveJSON(a.statePath, state)
}

func (a *clientApp) syncLighthouseNodes(nodes []LighthouseEndpoint) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil || state.Pairing == nil {
		return err
	}
	for index := range nodes {
		if nodes[index].Primary {
			nodes[index].Relay = true
		}
	}
	nodes = orderedLighthouseEndpoints(nodes, state.PreferredRelayAddress, state.RelayCandidates)
	encoded, _ := json.Marshal(nodes)
	current, _ := json.Marshal(state.Pairing.Lighthouses)
	if bytes.Equal(current, encoded) {
		if state.LighthouseUpdatedAt.IsZero() {
			state.LighthouseUpdatedAt = time.Now().UTC()
			return saveJSON(a.statePath, state)
		}
		return nil
	}
	state.Pairing.Lighthouses = append([]LighthouseEndpoint(nil), nodes...)
	state.LighthouseUpdatedAt = time.Now().UTC()
	state.RaceRequestVersion++
	state.LastRaceRequestedAt = time.Now().UTC()
	state.LastRaceReason = "主服务端同步了多节点 Lighthouse 列表"
	config, err := renderClientConfig(state)
	if err == nil {
		err = os.WriteFile(state.ConfigPath, []byte(config), 0o600)
	}
	if err == nil {
		err = saveJSON(a.statePath, state)
	}
	return err
}

func (a *clientApp) lighthousePage() ClientLighthousePage {
	a.stateMu.Lock()
	state, _ := a.load()
	a.stateMu.Unlock()
	nodes := effectiveLighthouseEndpoints(state.Pairing)
	statuses := make([]ClientLighthouseStatus, len(nodes))
	scoreByAddress := map[string]RelayCandidateScore{}
	for _, candidate := range state.RelayCandidates {
		scoreByAddress[candidate.Address] = candidate
	}
	var wait sync.WaitGroup
	for index, node := range nodes {
		wait.Add(1)
		go func(index int, node LighthouseEndpoint) {
			defer wait.Done()
			reachable, latency := probeOverlayAddress(node.Address)
			address := strings.Split(node.Address, "/")[0]
			candidate := scoreByAddress[address]
			statuses[index] = ClientLighthouseStatus{LighthouseEndpoint: node, Reachable: reachable, LatencyMs: latency, Preferred: address == state.PreferredRelayAddress, Score: candidate.Score}
		}(index, node)
	}
	wait.Wait()
	return ClientLighthousePage{Nodes: statuses, UpdatedAt: time.Now().UTC(), SyncedAt: state.LighthouseUpdatedAt, PreferredRelay: state.PreferredRelayAddress}
}

func (a *clientApp) heartbeatLoop() {
	a.sendHeartbeat()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.sendHeartbeat()
	}
}

func jsonReply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeRequest(r *http.Request, target any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(target)
}

func localBackendAvailable(url string) bool {
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 900 * time.Millisecond}
	response, err := client.Get(url + "/")
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func startNativeDesktopProcess(executable string) error {
	command := exec.Command(executable, "client", "--gui-only")
	return command.Start()
}

func clientMain(args []string) error {
	noGUI := false
	guiOnly := false
	updateHealthToken := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--no-browser", "--no-gui":
			noGUI = true
		case "--gui-only":
			guiOnly = true
		case "--update-health-token":
			if i+1 < len(args) {
				updateHealthToken = args[i+1]
				i++
			}
		}
	}
	root, err := appRoot()
	if err != nil {
		return err
	}
	url := "http://127.0.0.1:8777"
	guiProfile := filepath.Join(root, "native-webview2")
	if guiOnly || (!noGUI && localBackendAvailable(url)) {
		return runNativeDesktopWindow(url, guiProfile)
	}
	runtimeDir := filepath.Join(root, "runtime", "nebula-v"+nebulaVersion)
	clientRoot := filepath.Join(root, "client")
	if err := os.MkdirAll(clientRoot, 0o700); err != nil {
		return err
	}
	if err := hardenClientSecretDirectory(clientRoot); err != nil {
		return err
	}
	history, err := openHistoryStore(filepath.Join(clientRoot, "history.sqlite"))
	if err != nil {
		return err
	}
	defer history.Close()
	_ = history.Cleanup(30 * 24 * time.Hour)
	app := &clientApp{root: clientRoot, statePath: filepath.Join(clientRoot, "client-state.json"), runtimeDir: runtimeDir, nebula: filepath.Join(runtimeDir, "nebula.exe"), cert: filepath.Join(runtimeDir, "nebula-cert.exe"), forwards: map[string]*forwardRuntime{}, connections: map[string]*ServiceConnectionRecord{}, history: history, peerPathStates: map[string]peerPathObservation{}, fileReservations: map[string]int{}, aiPlans: map[string]AIPlan{}}
	if previous, historyErr := history.ClientHistory(24 * 30); historyErr == nil {
		for _, record := range previous.Connections {
			record.Active = 0
			key := record.MappingID + "|" + record.Address + "|" + strconv.FormatBool(record.Allowed)
			copy := record
			app.connections[key] = &copy
		}
	}
	optimizedState, _, optimizeErr := app.ensureOptimizedClientConfig()
	if optimizeErr == nil && optimizedState.Pairing != nil {
		if err := ensureClientPrivateKeyBackup(optimizedState); err != nil {
			return err
		}
		_ = applyMeshProxyBypass(optimizedState.ProxyCompatibilityEnabled)
		_ = app.ensureClientAIIdentity()
	}
	executable, _ := os.Executable()
	app.executable = executable
	installUserAutostart(executable)
	go app.forwarderLoop()
	go app.healthLoop()
	go app.controlLoop()
	go app.heartbeatLoop()
	go app.updateLoop()
	go app.updateSeedLoop()
	go app.networkAutomationLoop()
	go app.relayOptimizerLoop()
	go app.fileShareLoop()
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			_ = app.history.Cleanup(30 * 24 * time.Hour)
			_ = hardenClientSecretDirectory(app.root)
		}
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:8777")
	if err != nil {
		if !noGUI {
			return runNativeDesktopWindow(url, guiProfile)
		}
		return err
	}
	if err := writeUpdateHealth(app.root, updateHealthToken); err != nil {
		listener.Close()
		return err
	}
	fmt.Println("MeshLAN Nebula: " + url)
	server := &http.Server{Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second}
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Serve(listener) }()
	if !noGUI {
		for attempt := 0; attempt < 20 && !localBackendAvailable(url); attempt++ {
			time.Sleep(100 * time.Millisecond)
		}
		if err := startNativeDesktopProcess(executable); err != nil {
			_ = server.Close()
			return err
		}
	}
	return <-serverResult
}
