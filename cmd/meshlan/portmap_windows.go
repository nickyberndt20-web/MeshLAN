//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	autoMappingPortStart = 20000
	autoMappingPortEnd   = 29999
	maxServiceMappings   = 32
)

type forwardRuntime struct {
	listener         net.Listener
	packetConn       *net.UDPConn
	target           string
	protocol         string
	serviceName      string
	ownerName        string
	approvalRequired bool
	lastError        string
	healthy          bool
	latencyMs        int64
	checkedAt        time.Time
	healthError      string
	udpMu            sync.Mutex
	udpSessions      map[string]*udpForwardSession
}

type udpForwardSession struct {
	connection *net.UDPConn
	remote     *net.UDPAddr
	lastSeen   time.Time
}

type LocalServiceMappingView struct {
	LocalServiceMapping
	MeshAddress string    `json:"meshAddress"`
	DNSName     string    `json:"dnsName,omitempty"`
	URL         string    `json:"url,omitempty"`
	Active      bool      `json:"active"`
	LastError   string    `json:"lastError,omitempty"`
	Healthy     bool      `json:"healthy"`
	LatencyMs   int64     `json:"latencyMs"`
	CheckedAt   time.Time `json:"checkedAt,omitempty"`
	HealthError string    `json:"healthError,omitempty"`
}

type ServiceMappingPageResponse struct {
	Local       []LocalServiceMappingView `json:"local"`
	Shared      []PublishedServiceMapping `json:"shared"`
	MeshAddress string                    `json:"meshAddress"`
	RefreshedAt time.Time                 `json:"refreshedAt"`
	SharedError string                    `json:"sharedError,omitempty"`
	Connections []ServiceConnectionRecord `json:"connections"`
	Policies    []MappingAccessPolicy     `json:"policies"`
	DNSPrefix   string                    `json:"dnsPrefix,omitempty"`
	HTTPGateway HTTPGatewayStatus         `json:"httpGateway"`
}

func normalizeLoopbackHost(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "localhost" {
		return "127.0.0.1", nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsLoopback() {
		return "", errors.New("本地地址只允许 localhost、127.0.0.1 或 ::1")
	}
	return address.String(), nil
}

func meshAddressDetails(state ClientState) (address, subnet string, err error) {
	if state.Pairing == nil {
		return "", "", errors.New("本机尚未完成配对")
	}
	prefix, err := netip.ParsePrefix(state.Pairing.Address)
	if err != nil || !prefix.Addr().Is4() {
		return "", "", errors.New("本机 MeshLAN 地址无效")
	}
	return prefix.Addr().String(), prefix.Masked().String(), nil
}

func mappingFirewallRuleName(id string) string { return "MeshLAN-Service-" + id }

func (a *clientApp) addMappingFirewall(mapping LocalServiceMapping, meshIP, subnet string) error {
	if a.executable == "" {
		return errors.New("无法确定客户端程序路径")
	}
	localPorts := strconv.Itoa(mapping.MeshPort)
	if mapping.PortlessHTTP && normalizeMappingProtocol(mapping.Protocol) == "tcp" {
		localPorts += ",80,443"
	}
	return runElevated(`C:\Windows\System32\netsh.exe`, []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + mappingFirewallRuleName(mapping.ID), "dir=in", "action=allow", "enable=yes",
		"protocol=" + strings.ToUpper(normalizeMappingProtocol(mapping.Protocol)), "profile=any", "program=" + a.executable,
		"localip=" + meshIP, "localport=" + localPorts, "remoteip=" + subnet,
	})
}

func (a *clientApp) updateMappingFirewall(mapping LocalServiceMapping) error {
	localPorts := strconv.Itoa(mapping.MeshPort)
	if mapping.PortlessHTTP && normalizeMappingProtocol(mapping.Protocol) == "tcp" {
		localPorts += ",80,443"
	}
	return runElevated(`C:\Windows\System32\netsh.exe`, []string{
		"advfirewall", "firewall", "set", "rule", "name=" + mappingFirewallRuleName(mapping.ID),
		"new", "localport=" + localPorts,
	})
}

func (a *clientApp) deleteMappingFirewall(id string) {
	_ = runElevated(`C:\Windows\System32\netsh.exe`, []string{
		"advfirewall", "firewall", "delete", "rule", "name=" + mappingFirewallRuleName(id),
	})
}

func runtimeActive(runtime *forwardRuntime) bool {
	return runtime != nil && (runtime.listener != nil || runtime.packetConn != nil)
}

func closeForwardRuntime(runtime *forwardRuntime) {
	if runtime == nil {
		return
	}
	if runtime.listener != nil {
		_ = runtime.listener.Close()
	}
	if runtime.packetConn != nil {
		_ = runtime.packetConn.Close()
	}
	runtime.udpMu.Lock()
	for _, session := range runtime.udpSessions {
		_ = session.connection.Close()
	}
	runtime.udpSessions = map[string]*udpForwardSession{}
	runtime.udpMu.Unlock()
}

func openMappingRuntime(meshIP, ownerName string, mapping LocalServiceMapping) (*forwardRuntime, error) {
	protocol := normalizeMappingProtocol(mapping.Protocol)
	runtime := &forwardRuntime{
		target: net.JoinHostPort(mapping.LocalHost, strconv.Itoa(mapping.LocalPort)), protocol: protocol,
		serviceName: mapping.ServiceName, ownerName: ownerName, approvalRequired: mapping.ApprovalRequired,
		udpSessions: map[string]*udpForwardSession{},
	}
	if protocol == "udp" {
		address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(meshIP, strconv.Itoa(mapping.MeshPort)))
		if err != nil {
			return nil, err
		}
		packetConn, err := net.ListenUDP("udp", address)
		if err != nil {
			return nil, err
		}
		runtime.packetConn = packetConn
		return runtime, nil
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(meshIP, strconv.Itoa(mapping.MeshPort)))
	if err != nil {
		return nil, err
	}
	runtime.listener = listener
	return runtime, nil
}

func (a *clientApp) updateConnection(mappingID, serviceName, userName, address, protocol string, allowed bool, activeDelta int, bytesToLocal, bytesToPeer uint64) {
	key := mappingID + "|" + address + "|" + strconv.FormatBool(allowed)
	now := time.Now()
	a.forwardMu.Lock()
	a.connectionMu.Lock()
	record := a.connections[key]
	if record == nil {
		if a.forwards[mappingID] == nil {
			a.connectionMu.Unlock()
			a.forwardMu.Unlock()
			return
		}
		record = &ServiceConnectionRecord{MappingID: mappingID, ServiceName: serviceName, UserName: userName, Address: address, Protocol: protocol, Allowed: allowed, FirstSeen: now}
		a.connections[key] = record
	}
	record.UserName = userName
	record.LastSeen = now
	record.Active += activeDelta
	if record.Active < 0 {
		record.Active = 0
	}
	record.BytesToLocal += bytesToLocal
	record.BytesToPeer += bytesToPeer
	snapshot := *record
	a.connectionMu.Unlock()
	a.forwardMu.Unlock()
	_ = a.history.RecordConnection(snapshot)
}

func (a *clientApp) updateConnectionTokenUsage(mappingID, address string, allowed bool, usage serviceTokenUsage) {
	if !usage.Reported {
		return
	}
	key := mappingID + "|" + address + "|" + strconv.FormatBool(allowed)
	a.connectionMu.Lock()
	record := a.connections[key]
	if record == nil {
		a.connectionMu.Unlock()
		return
	}
	record.InputTokens += usage.InputTokens
	record.OutputTokens += usage.OutputTokens
	record.TotalTokens += usage.TotalTokens
	record.CachedTokens += usage.CachedTokens
	record.ReasoningTokens += usage.ReasoningTokens
	record.TokenUsageReports++
	snapshot := *record
	a.connectionMu.Unlock()
	_ = a.history.RecordConnection(snapshot)
}

func (a *clientApp) connectionRecords(mappings []LocalServiceMapping) []ServiceConnectionRecord {
	valid := make(map[string]bool, len(mappings))
	for _, mapping := range mappings {
		valid[mapping.ID] = true
	}
	a.connectionMu.Lock()
	defer a.connectionMu.Unlock()
	records := make([]ServiceConnectionRecord, 0, len(a.connections))
	for key, record := range a.connections {
		if !valid[record.MappingID] {
			delete(a.connections, key)
			continue
		}
		records = append(records, *record)
	}
	return records
}

func (a *clientApp) forwardConnection(runtime *forwardRuntime, mappingID string, source net.Conn) {
	remoteIP, _, _ := net.SplitHostPort(source.RemoteAddr().String())
	allowed, userName := a.remoteAllowed(mappingID, runtime.ownerName, runtime.approvalRequired, remoteIP)
	if !allowed {
		a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "tcp", false, 0, 0, 0)
		_ = source.Close()
		return
	}
	a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "tcp", true, 1, 0, 0)
	defer a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "tcp", true, -1, 0, 0)
	target := runtime.target
	destination, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_ = source.Close()
		return
	}
	type copyResult struct {
		toLocal bool
		bytes   uint64
	}
	done := make(chan copyResult, 2)
	copyOneWay := func(dst, src net.Conn, toLocal bool) {
		count, _ := io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- copyResult{toLocal: toLocal, bytes: uint64(count)}
	}
	go copyOneWay(destination, source, true)
	go copyOneWay(source, destination, false)
	first := <-done
	second := <-done
	toLocal, toPeer := uint64(0), uint64(0)
	for _, result := range []copyResult{first, second} {
		if result.toLocal {
			toLocal += result.bytes
		} else {
			toPeer += result.bytes
		}
	}
	a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "tcp", true, 0, toLocal, toPeer)
	_ = source.Close()
	_ = destination.Close()
}

func (a *clientApp) serveTCPMapping(id string, runtime *forwardRuntime) {
	listener := runtime.listener
	for {
		connection, err := listener.Accept()
		if err != nil {
			a.forwardMu.Lock()
			if runtime := a.forwards[id]; runtime != nil && runtime.listener == listener {
				runtime.listener = nil
				runtime.lastError = err.Error()
			}
			a.forwardMu.Unlock()
			return
		}
		go a.forwardConnection(runtime, id, connection)
	}
}

func (a *clientApp) serveUDPSession(mappingID, sessionKey string, runtime *forwardRuntime, session *udpForwardSession, userName, remoteIP string) {
	buffer := make([]byte, 64<<10)
	defer func() {
		runtime.udpMu.Lock()
		if runtime.udpSessions[sessionKey] == session {
			delete(runtime.udpSessions, sessionKey)
		}
		runtime.udpMu.Unlock()
		_ = session.connection.Close()
		a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "udp", true, -1, 0, 0)
	}()
	for {
		_ = session.connection.SetReadDeadline(time.Now().Add(60 * time.Second))
		count, err := session.connection.Read(buffer)
		if err != nil {
			return
		}
		if _, err := runtime.packetConn.WriteToUDP(buffer[:count], session.remote); err != nil {
			return
		}
		runtime.udpMu.Lock()
		session.lastSeen = time.Now()
		runtime.udpMu.Unlock()
		a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "udp", true, 0, 0, uint64(count))
	}
}

func (a *clientApp) serveUDPMapping(mappingID string, runtime *forwardRuntime) {
	buffer := make([]byte, 64<<10)
	for {
		count, remote, err := runtime.packetConn.ReadFromUDP(buffer)
		if err != nil {
			a.forwardMu.Lock()
			if current := a.forwards[mappingID]; current == runtime {
				current.packetConn = nil
				current.lastError = err.Error()
			}
			a.forwardMu.Unlock()
			return
		}
		remoteIP := remote.IP.String()
		allowed, userName := a.remoteAllowed(mappingID, runtime.ownerName, runtime.approvalRequired, remoteIP)
		if !allowed {
			a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "udp", false, 0, uint64(count), 0)
			continue
		}
		sessionKey := remote.String()
		runtime.udpMu.Lock()
		session := runtime.udpSessions[sessionKey]
		newSession := false
		if session == nil {
			target, resolveErr := net.ResolveUDPAddr("udp", runtime.target)
			if resolveErr != nil {
				runtime.udpMu.Unlock()
				continue
			}
			connection, dialErr := net.DialUDP("udp", nil, target)
			if dialErr != nil {
				runtime.udpMu.Unlock()
				continue
			}
			session = &udpForwardSession{connection: connection, remote: remote, lastSeen: time.Now()}
			runtime.udpSessions[sessionKey] = session
			newSession = true
		} else {
			session.lastSeen = time.Now()
		}
		runtime.udpMu.Unlock()
		if newSession {
			a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "udp", true, 1, 0, 0)
			go a.serveUDPSession(mappingID, sessionKey, runtime, session, userName, remoteIP)
		}
		if _, err := session.connection.Write(buffer[:count]); err == nil {
			a.updateConnection(mappingID, runtime.serviceName, userName, remoteIP, "udp", true, 0, uint64(count), 0)
		}
	}
}

func (a *clientApp) installRuntimeMapping(mapping LocalServiceMapping, runtime *forwardRuntime) {
	a.forwardMu.Lock()
	a.forwards[mapping.ID] = runtime
	a.forwardMu.Unlock()
	if runtime.protocol == "udp" {
		go a.serveUDPMapping(mapping.ID, runtime)
	} else {
		go a.serveTCPMapping(mapping.ID, runtime)
	}
}

func (a *clientApp) syncForwarders() {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || state.Pairing == nil {
		return
	}
	meshIP, _, err := meshAddressDetails(state)
	if err != nil {
		return
	}
	expected := make(map[string]LocalServiceMapping, len(state.ServiceMappings))
	for _, mapping := range state.ServiceMappings {
		mapping.Protocol = normalizeMappingProtocol(mapping.Protocol)
		expected[mapping.ID] = mapping
	}

	a.forwardMu.Lock()
	for id, runtime := range a.forwards {
		mapping, ok := expected[id]
		if !ok || mapping.Paused {
			closeForwardRuntime(runtime)
			delete(a.forwards, id)
		}
	}
	a.forwardMu.Unlock()

	for _, mapping := range state.ServiceMappings {
		mapping.Protocol = normalizeMappingProtocol(mapping.Protocol)
		if mapping.Paused {
			continue
		}
		a.forwardMu.Lock()
		runtime := a.forwards[mapping.ID]
		active := runtimeActive(runtime)
		a.forwardMu.Unlock()
		if active {
			continue
		}
		newRuntime, listenErr := openMappingRuntime(meshIP, state.Name, mapping)
		if listenErr != nil {
			a.forwardMu.Lock()
			a.forwards[mapping.ID] = &forwardRuntime{
				target: net.JoinHostPort(mapping.LocalHost, strconv.Itoa(mapping.LocalPort)), protocol: mapping.Protocol,
				serviceName: mapping.ServiceName, ownerName: state.Name, approvalRequired: mapping.ApprovalRequired,
				lastError: "局域网端口已占用或 MeshLAN 尚未就绪", udpSessions: map[string]*udpForwardSession{},
			}
			a.forwardMu.Unlock()
			continue
		}
		a.installRuntimeMapping(mapping, newRuntime)
	}
	_ = a.syncHTTPGateway()
}

func mappingPortUsed(mappings []LocalServiceMapping, port int, protocol string) bool {
	for _, mapping := range mappings {
		if mapping.MeshPort == port && normalizeMappingProtocol(mapping.Protocol) == normalizeMappingProtocol(protocol) {
			return true
		}
	}
	return false
}

func (a *clientApp) addServiceMapping(serviceName, dnsPrefix, localHost string, localPort, requestedMeshPort int, protocol string, approvalRequired, portlessHTTP bool) (LocalServiceMappingView, error) {
	serviceName = strings.TrimSpace(serviceName)
	protocol = normalizeMappingProtocol(protocol)
	if !validServiceName(serviceName) {
		return LocalServiceMappingView{}, errors.New("服务名称不能为空，且最多 48 个字符")
	}
	normalizedHost, err := normalizeLoopbackHost(localHost)
	if err != nil {
		return LocalServiceMappingView{}, err
	}
	if localPort < 1 || localPort > 65535 || requestedMeshPort < 0 || requestedMeshPort > 65535 {
		return LocalServiceMappingView{}, errors.New("端口必须在 1-65535 之间")
	}
	if portlessHTTP && protocol != "tcp" {
		return LocalServiceMappingView{}, errors.New("无端口HTTP域名只支持TCP映射")
	}

	a.stateMu.Lock()
	state, err := a.load()
	if err != nil {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, err
	}
	applyMeshDNSPreferenceDefaults(&state)
	if len(state.ServiceMappings) >= maxServiceMappings {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, fmt.Errorf("每台设备最多创建 %d 个服务映射", maxServiceMappings)
	}
	meshIP, subnet, err := meshAddressDetails(state)
	if err != nil {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, err
	}
	id, err := randomToken(12)
	if err != nil {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, err
	}
	if strings.TrimSpace(dnsPrefix) == "" {
		dnsPrefix = meshDNSLabel(serviceName, id)
	}
	dnsPrefix, err = normalizeDNSPrefix(dnsPrefix)
	if err != nil {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, err
	}
	for _, existing := range state.ServiceMappings {
		if strings.EqualFold(existing.DNSPrefix, dnsPrefix) {
			a.stateMu.Unlock()
			return LocalServiceMappingView{}, fmt.Errorf("服务DNS前缀 %s 已占用", dnsPrefix)
		}
	}
	mapping := LocalServiceMapping{
		ID: id, ServiceName: serviceName, LocalHost: normalizedHost, LocalPort: localPort,
		Protocol: protocol, DNSPrefix: dnsPrefix, PortlessHTTP: portlessHTTP,
		ApprovalRequired: approvalRequired, CreatedAt: time.Now(),
	}
	var runtime *forwardRuntime
	if requestedMeshPort > 0 {
		if mappingPortUsed(state.ServiceMappings, requestedMeshPort, protocol) {
			a.stateMu.Unlock()
			return LocalServiceMappingView{}, fmt.Errorf("局域网端口 %d 已占用", requestedMeshPort)
		}
		mapping.MeshPort = requestedMeshPort
		runtime, err = openMappingRuntime(meshIP, state.Name, mapping)
		if err != nil {
			a.stateMu.Unlock()
			return LocalServiceMappingView{}, fmt.Errorf("局域网端口 %d 已占用", requestedMeshPort)
		}
	} else {
		for port := autoMappingPortStart; port <= autoMappingPortEnd; port++ {
			if mappingPortUsed(state.ServiceMappings, port, protocol) {
				continue
			}
			mapping.MeshPort = port
			runtime, err = openMappingRuntime(meshIP, state.Name, mapping)
			if err == nil {
				break
			}
		}
		if runtime == nil {
			a.stateMu.Unlock()
			return LocalServiceMappingView{}, errors.New("没有可用的自动映射端口")
		}
	}

	if err := a.addMappingFirewall(mapping, meshIP, subnet); err != nil {
		closeForwardRuntime(runtime)
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, fmt.Errorf("创建 Windows 防火墙规则失败: %w", err)
	}
	state.ServiceMappings = append(state.ServiceMappings, mapping)
	if err := saveJSON(a.statePath, state); err != nil {
		closeForwardRuntime(runtime)
		a.deleteMappingFirewall(mapping.ID)
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, err
	}
	a.stateMu.Unlock()
	a.installRuntimeMapping(mapping, runtime)
	_ = a.syncHTTPGateway()
	go func() {
		a.checkMappingsHealth()
		a.sendHeartbeat()
	}()
	view := LocalServiceMappingView{LocalServiceMapping: mapping, MeshAddress: meshIP, Active: runtimeActive(runtime)}
	view.DNSName = serviceDNSName(mapping.DNSPrefix, state.DNSPrefix)
	if mapping.PortlessHTTP {
		if a.httpGatewayStatus().HTTPSActive {
			view.URL = "https://" + view.DNSName
		} else {
			view.URL = "http://" + view.DNSName
		}
	}
	return view, nil
}

func (a *clientApp) deleteServiceMapping(id string) error {
	id = strings.TrimSpace(id)
	a.stateMu.Lock()
	state, err := a.load()
	if err != nil {
		a.stateMu.Unlock()
		return err
	}
	found := false
	kept := state.ServiceMappings[:0]
	for _, mapping := range state.ServiceMappings {
		if mapping.ID == id {
			found = true
			continue
		}
		kept = append(kept, mapping)
	}
	if !found {
		a.stateMu.Unlock()
		return errors.New("没有找到该映射")
	}
	state.ServiceMappings = kept
	if err := saveJSON(a.statePath, state); err != nil {
		a.stateMu.Unlock()
		return err
	}
	a.stateMu.Unlock()

	a.forwardMu.Lock()
	if runtime := a.forwards[id]; runtime != nil {
		closeForwardRuntime(runtime)
		delete(a.forwards, id)
	}
	a.forwardMu.Unlock()
	a.connectionMu.Lock()
	for key, record := range a.connections {
		if record.MappingID == id {
			delete(a.connections, key)
		}
	}
	a.connectionMu.Unlock()
	a.deleteMappingFirewall(id)
	_ = a.syncHTTPGateway()
	go a.sendHeartbeat()
	return nil
}

func (a *clientApp) setServiceMappingPaused(id string, paused bool) error {
	a.stateMu.Lock()
	state, err := a.load()
	if err != nil {
		a.stateMu.Unlock()
		return err
	}
	found := false
	for i := range state.ServiceMappings {
		if state.ServiceMappings[i].ID == id {
			state.ServiceMappings[i].Paused = paused
			found = true
			break
		}
	}
	if !found {
		a.stateMu.Unlock()
		return errors.New("没有找到该映射")
	}
	if err := saveJSON(a.statePath, state); err != nil {
		a.stateMu.Unlock()
		return err
	}
	a.stateMu.Unlock()
	a.syncForwarders()
	go a.sendHeartbeat()
	return nil
}

func (a *clientApp) updateServiceMappingDNS(id, dnsPrefix string, portlessHTTP bool) (LocalServiceMappingView, error) {
	prefix, err := normalizeDNSPrefix(dnsPrefix)
	if err != nil {
		return LocalServiceMappingView{}, err
	}
	a.stateMu.Lock()
	state, err := a.load()
	if err != nil {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, err
	}
	applyMeshDNSPreferenceDefaults(&state)
	index := -1
	for i, mapping := range state.ServiceMappings {
		if mapping.ID == id {
			index = i
			continue
		}
		if strings.EqualFold(mapping.DNSPrefix, prefix) {
			a.stateMu.Unlock()
			return LocalServiceMappingView{}, fmt.Errorf("服务DNS前缀 %s 已占用", prefix)
		}
	}
	if index < 0 {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, errors.New("没有找到该映射")
	}
	mapping := state.ServiceMappings[index]
	if portlessHTTP && normalizeMappingProtocol(mapping.Protocol) != "tcp" {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, errors.New("无端口HTTP域名只支持TCP映射")
	}
	previousPortless := mapping.PortlessHTTP
	mapping.DNSPrefix = prefix
	mapping.PortlessHTTP = portlessHTTP
	if previousPortless != portlessHTTP {
		if err := a.updateMappingFirewall(mapping); err != nil {
			a.stateMu.Unlock()
			return LocalServiceMappingView{}, fmt.Errorf("更新 Windows 防火墙规则失败: %w", err)
		}
	}
	state.ServiceMappings[index] = mapping
	if err := saveJSON(a.statePath, state); err != nil {
		a.stateMu.Unlock()
		return LocalServiceMappingView{}, err
	}
	a.stateMu.Unlock()
	a.syncForwarders()
	go a.sendHeartbeat()
	views, _ := a.localMappingViews(state)
	for _, view := range views {
		if view.ID == id {
			return view, nil
		}
	}
	meshIP, _, _ := meshAddressDetails(state)
	return LocalServiceMappingView{LocalServiceMapping: mapping, MeshAddress: meshIP}, nil
}

func (a *clientApp) localMappingViews(state ClientState) ([]LocalServiceMappingView, string) {
	meshIP, _, _ := meshAddressDetails(state)
	applyMeshDNSPreferenceDefaults(&state)
	views := make([]LocalServiceMappingView, 0, len(state.ServiceMappings))
	a.forwardMu.Lock()
	defer a.forwardMu.Unlock()
	for _, mapping := range state.ServiceMappings {
		runtime := a.forwards[mapping.ID]
		view := LocalServiceMappingView{LocalServiceMapping: mapping, MeshAddress: meshIP}
		view.DNSName = serviceDNSName(mapping.DNSPrefix, state.DNSPrefix)
		if mapping.PortlessHTTP {
			if a.httpGatewayStatus().HTTPSActive {
				view.URL = "https://" + view.DNSName
			} else {
				view.URL = "http://" + view.DNSName
			}
		}
		if runtime != nil {
			view.Active = runtimeActive(runtime)
			view.LastError = runtime.lastError
			view.Healthy = runtime.healthy
			view.LatencyMs = runtime.latencyMs
			view.CheckedAt = runtime.checkedAt
			view.HealthError = runtime.healthError
		}
		views = append(views, view)
	}
	return views, meshIP
}

func (a *clientApp) mappingHeartbeat(state ClientState) []ServiceMappingHeartbeat {
	statuses := make([]ServiceMappingHeartbeat, 0, len(state.ServiceMappings))
	httpsReady := a.httpGatewayStatus().HTTPSActive
	a.forwardMu.Lock()
	defer a.forwardMu.Unlock()
	for _, mapping := range state.ServiceMappings {
		runtime := a.forwards[mapping.ID]
		active, healthy, latency := false, false, int64(0)
		checkedAt := time.Time{}
		if runtime != nil {
			active = runtimeActive(runtime)
			healthy = runtime.healthy
			latency = runtime.latencyMs
			checkedAt = runtime.checkedAt
		}
		statuses = append(statuses, ServiceMappingHeartbeat{
			ID: mapping.ID, ServiceName: mapping.ServiceName, Port: mapping.MeshPort,
			Protocol: normalizeMappingProtocol(mapping.Protocol), DNSPrefix: mapping.DNSPrefix, PortlessHTTP: mapping.PortlessHTTP, HTTPS: mapping.PortlessHTTP && httpsReady,
			Paused: mapping.Paused, ApprovalRequired: mapping.ApprovalRequired,
			Active: active, Healthy: healthy, LatencyMs: latency, CheckedAt: checkedAt,
		})
	}
	return statuses
}

func (a *clientApp) forwarderLoop() {
	a.syncForwarders()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.syncForwarders()
	}
}

func (a *clientApp) checkMappingsHealth() {
	type target struct {
		id       string
		address  string
		protocol string
	}
	a.forwardMu.Lock()
	targets := make([]target, 0, len(a.forwards))
	for id, runtime := range a.forwards {
		if runtimeActive(runtime) {
			targets = append(targets, target{id: id, address: runtime.target, protocol: runtime.protocol})
		}
	}
	a.forwardMu.Unlock()

	for _, item := range targets {
		if item.protocol == "udp" {
			a.forwardMu.Lock()
			if runtime := a.forwards[item.id]; runtime != nil {
				runtime.checkedAt = time.Now()
				runtime.healthy = runtime.packetConn != nil
				runtime.latencyMs = 0
				runtime.healthError = ""
			}
			a.forwardMu.Unlock()
			continue
		}
		started := time.Now()
		connection, err := net.DialTimeout("tcp", item.address, 2*time.Second)
		latency := time.Since(started).Milliseconds()
		if connection != nil {
			_ = connection.Close()
		}
		a.forwardMu.Lock()
		if runtime := a.forwards[item.id]; runtime != nil {
			runtime.checkedAt = time.Now()
			runtime.healthy = err == nil
			runtime.latencyMs = latency
			if err != nil {
				runtime.healthError = "本地服务不可达"
			} else {
				runtime.healthError = ""
			}
		}
		a.forwardMu.Unlock()
	}
}

func (a *clientApp) healthLoop() {
	a.syncForwarders()
	a.checkMappingsHealth()
	a.sendHeartbeat()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.syncForwarders()
		a.checkMappingsHealth()
		a.sendHeartbeat()
	}
}
