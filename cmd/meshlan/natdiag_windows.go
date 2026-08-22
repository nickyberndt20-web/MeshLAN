//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/bits"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type stunTarget struct {
	Name string
	Host string
	Port int
}

type diagnosticAdapter struct {
	Name         string
	Index4       int
	Index6       int
	Metric4      uint32
	Metric6      uint32
	IPv4         string
	Gateway4     string
	IPv6         string
	Gateway6     string
	Gateway6Hint bool
	LikelyTUN    bool
}

func diagnosticAdapterName(value *uint16) string {
	if value == nil {
		return ""
	}
	return windows.UTF16PtrToString(value)
}

func diagnosticGateway(adapter *windows.IpAdapterAddresses, ipv6 bool) string {
	for gateway := adapter.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
		address := gateway.Address.IP()
		if address == nil || (ipv6 && address.To4() != nil) || (!ipv6 && address.To4() == nil) {
			continue
		}
		return address.String()
	}
	return ""
}

func likelyTunnelAdapter(name string, adapter *windows.IpAdapterAddresses) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "meshlan" {
		return false
	}
	for _, marker := range []string{"wintun", "wireguard", "tun", "tap", "clash", "proxy", "vpn", "sing-box", "singbox"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return adapter.IfType == windows.IF_TYPE_TUNNEL || adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK ||
		(adapter.IfType == windows.IF_TYPE_OTHER && adapter.PhysicalAddressLength == 0)
}

func readDiagnosticAdapters() ([]diagnosticAdapter, error) {
	size := uint32(15 * 1024)
	flags := uint32(windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_ALL_INTERFACES)
	for attempt := 0; attempt < 3; attempt++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(uint32(windows.AF_UNSPEC), flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		result := make([]diagnosticAdapter, 0, 8)
		for adapter := first; adapter != nil; adapter = adapter.Next {
			if adapter.OperStatus != windows.IfOperStatusUp || adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
				continue
			}
			item := diagnosticAdapter{
				Name: diagnosticAdapterName(adapter.FriendlyName), Index4: int(adapter.IfIndex), Index6: int(adapter.Ipv6IfIndex),
				Metric4: adapter.Ipv4Metric, Metric6: adapter.Ipv6Metric,
			}
			if item.Index6 == 0 {
				item.Index6 = item.Index4
			}
			item.Gateway4 = diagnosticGateway(adapter, false)
			item.Gateway6 = diagnosticGateway(adapter, true)
			item.LikelyTUN = likelyTunnelAdapter(item.Name, adapter)
			for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
				ip := address.Address.IP()
				if ip == nil || (address.DadState != 0 && address.DadState != windows.IpDadStatePreferred) {
					continue
				}
				if v4 := ip.To4(); v4 != nil {
					if item.IPv4 == "" && !v4.IsLoopback() && !v4.IsLinkLocalUnicast() {
						item.IPv4 = v4.String()
					}
				} else if item.IPv6 == "" && publicProbeAddress(ip, true) {
					item.IPv6 = ip.String()
				}
			}
			result = append(result, item)
		}
		applyIPv6RouteHints(result)
		return result, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}

func rawRouteIP(address *windows.RawSockaddrInet) net.IP {
	if address == nil {
		return nil
	}
	switch address.Family {
	case windows.AF_INET:
		value := (*windows.RawSockaddrInet4)(unsafe.Pointer(address))
		return net.IP(append([]byte(nil), value.Addr[:]...))
	case windows.AF_INET6:
		value := (*windows.RawSockaddrInet6)(unsafe.Pointer(address))
		return net.IP(append([]byte(nil), value.Addr[:]...))
	default:
		return nil
	}
}

func applyIPv6RouteHints(adapters []diagnosticAdapter) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(uint16(windows.AF_INET6), &table); err != nil || table == nil {
		return
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	type routeHint struct {
		gateway string
		score   int
		metric  uint32
	}
	hints := map[int]routeHint{}
	for _, route := range table.Rows() {
		gateway := rawRouteIP(&route.NextHop)
		if gateway == nil || gateway.To4() != nil || gateway.IsUnspecified() || gateway.IsMulticast() {
			continue
		}
		score := 2
		if route.DestinationPrefix.PrefixLength == 0 {
			score = 0
		} else if route.DestinationPrefix.PrefixLength == 128 {
			score = 1
		}
		current, exists := hints[int(route.InterfaceIndex)]
		if !exists || score < current.score || (score == current.score && route.Metric < current.metric) {
			hints[int(route.InterfaceIndex)] = routeHint{gateway: gateway.String(), score: score, metric: route.Metric}
		}
	}
	for index := range adapters {
		if adapters[index].IPv6 == "" || adapters[index].Gateway6 != "" {
			continue
		}
		if hint, ok := hints[adapters[index].Index6]; ok {
			adapters[index].Gateway6 = hint.gateway
			adapters[index].Gateway6Hint = hint.score > 0
		}
	}
}

func liveDedicatedRoutes(family uint16, interfaceIndex int, gateway string, prefixLength uint8) []string {
	if interfaceIndex <= 0 || gateway == "" {
		return nil
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &table); err != nil || table == nil {
		return nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	targets := []string{}
	seen := map[string]bool{}
	for _, route := range table.Rows() {
		if int(route.InterfaceIndex) != interfaceIndex || route.DestinationPrefix.PrefixLength != prefixLength {
			continue
		}
		nextHop := rawRouteIP(&route.NextHop)
		destination := rawRouteIP(&route.DestinationPrefix.Prefix)
		if nextHop == nil || destination == nil || !strings.EqualFold(nextHop.String(), gateway) || !publicProbeAddress(destination, family == windows.AF_INET6) {
			continue
		}
		value := destination.String()
		if !seen[value] {
			seen[value] = true
			targets = append(targets, value)
		}
	}
	sort.Strings(targets)
	return targets
}

func inferLiveRouteGuard(state ClientState) (RouteGuardStatus, bool) {
	adapters, err := readDiagnosticAdapters()
	if err != nil {
		return RouteGuardStatus{}, false
	}
	status := RouteGuardStatus{Version: routeGuardVersion, Mode: "not_installed", PreferredP2P: state.PreferredP2PInterface, PreferredBusiness: state.PreferredBusinessInterface}
	if adapter, ok := chooseDiagnosticAdapter(adapters, state.PreferredP2PInterface, false); ok {
		status.PhysicalInterface, status.PhysicalAddress, status.Gateway, status.InterfaceIndex = adapter.Name, adapter.IPv4, adapter.Gateway4, adapter.Index4
		status.Targets = liveDedicatedRoutes(uint16(windows.AF_INET), adapter.Index4, adapter.Gateway4, 32)
	}
	if adapter, ok := chooseDiagnosticAdapter(adapters, state.PreferredP2PInterface, true); ok {
		status.IPv6Interface, status.IPv6Address, status.IPv6Gateway, status.IPv6InterfaceIndex = adapter.Name, adapter.IPv6, adapter.Gateway6, adapter.Index6
		status.IPv6Targets = liveDedicatedRoutes(uint16(windows.AF_INET6), adapter.Index6, adapter.Gateway6, 128)
		status.IPv6DefaultSuppressed = adapter.Gateway6Hint
	}
	for _, adapter := range adapters {
		if adapter.LikelyTUN && adapter.Name != "" && (adapter.Gateway4 != "" || adapter.Gateway6 != "") {
			status.TUNInterfaces = append(status.TUNInterfaces, adapter.Name)
		}
		if state.PreferredBusinessInterface != "" && !strings.EqualFold(state.PreferredBusinessInterface, "auto") && strings.EqualFold(adapter.Name, state.PreferredBusinessInterface) && adapter.IPv4 != "" && adapter.Gateway4 != "" {
			status.BusinessActive, status.BusinessAddress, status.BusinessGateway, status.BusinessInterfaceIndex = true, adapter.IPv4, adapter.Gateway4, adapter.Index4
		}
	}
	status.BypassReady = len(status.Targets)+len(status.IPv6Targets) > 0
	if status.BypassReady {
		status.Mode = "guarding"
		status.LastUpdated = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return status, status.BypassReady
}

func chooseDiagnosticAdapter(adapters []diagnosticAdapter, preferred string, ipv6 bool) (diagnosticAdapter, bool) {
	preferred = strings.TrimSpace(preferred)
	candidates := make([]diagnosticAdapter, 0, len(adapters))
	for _, adapter := range adapters {
		if adapter.LikelyTUN {
			continue
		}
		if ipv6 {
			if adapter.IPv6 == "" || adapter.Gateway6 == "" || adapter.Index6 <= 0 {
				continue
			}
		} else if adapter.IPv4 == "" || adapter.Gateway4 == "" || adapter.Index4 <= 0 {
			continue
		}
		candidates = append(candidates, adapter)
	}
	if preferred != "" && !strings.EqualFold(preferred, "auto") {
		for _, adapter := range candidates {
			if strings.EqualFold(adapter.Name, preferred) {
				return adapter, true
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if ipv6 {
			return candidates[i].Metric6 < candidates[j].Metric6
		}
		return candidates[i].Metric4 < candidates[j].Metric4
	})
	if len(candidates) == 0 {
		return diagnosticAdapter{}, false
	}
	return candidates[0], true
}

func liveDiagnosticNetwork(preferred string) (RouteGuardStatus, error) {
	adapters, err := readDiagnosticAdapters()
	if err != nil {
		return RouteGuardStatus{}, err
	}
	status := RouteGuardStatus{PreferredP2P: preferred}
	if adapter, ok := chooseDiagnosticAdapter(adapters, preferred, false); ok {
		status.PhysicalInterface = adapter.Name
		status.PhysicalAddress = adapter.IPv4
		status.Gateway = adapter.Gateway4
		status.InterfaceIndex = adapter.Index4
	}
	if adapter, ok := chooseDiagnosticAdapter(adapters, preferred, true); ok {
		status.IPv6Interface = adapter.Name
		status.IPv6Address = adapter.IPv6
		status.IPv6Gateway = adapter.Gateway6
		status.IPv6InterfaceIndex = adapter.Index6
		status.IPv6DefaultSuppressed = adapter.Gateway6Hint
	}
	seenTUN := map[string]bool{}
	for _, adapter := range adapters {
		if adapter.LikelyTUN && adapter.Name != "" && (adapter.Gateway4 != "" || adapter.Gateway6 != "") && !seenTUN[adapter.Name] {
			seenTUN[adapter.Name] = true
			status.TUNInterfaces = append(status.TUNInterfaces, adapter.Name)
		}
	}
	sort.Strings(status.TUNInterfaces)
	return status, nil
}

func mergeDiagnosticNetwork(guard RouteGuardStatus, live RouteGuardStatus) RouteGuardStatus {
	if live.PhysicalInterface != "" {
		guard.PhysicalInterface, guard.PhysicalAddress, guard.Gateway, guard.InterfaceIndex = live.PhysicalInterface, live.PhysicalAddress, live.Gateway, live.InterfaceIndex
	}
	if live.IPv6Interface != "" {
		guard.IPv6Interface, guard.IPv6Address, guard.IPv6Gateway, guard.IPv6InterfaceIndex = live.IPv6Interface, live.IPv6Address, live.IPv6Gateway, live.IPv6InterfaceIndex
	}
	if len(live.TUNInterfaces) > 0 {
		guard.TUNInterfaces = live.TUNInterfaces
	}
	if live.IPv6DefaultSuppressed {
		guard.IPv6DefaultSuppressed = true
	}
	return guard
}

func publicProbeAddress(address net.IP, ipv6 bool) bool {
	if address == nil || (ipv6 && address.To4() != nil) || (!ipv6 && address.To4() == nil) {
		return false
	}
	parsed, ok := netip.AddrFromSlice(address)
	if !ok {
		return false
	}
	parsed = parsed.Unmap()
	return parsed.IsGlobalUnicast() && !parsed.IsPrivate() && !parsed.IsLoopback() && !parsed.IsLinkLocalUnicast() && !(parsed.Is4() && (parsed.String() >= "198.18.0.0" && parsed.String() <= "198.19.255.255"))
}

func resolveSTUNAddress(ctx context.Context, host string, ipv6 bool) (net.IP, error) {
	addresses, _ := net.DefaultResolver.LookupIP(ctx, "ip", host)
	for _, address := range addresses {
		if publicProbeAddress(address, ipv6) {
			return address, nil
		}
	}
	type dnsAnswer struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	}
	var response struct {
		Answer []dnsAnswer `json:"Answer"`
	}
	recordType := "A"
	expectedType := 1
	if ipv6 {
		recordType, expectedType = "AAAA", 28
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudflare-dns.com/dns-query?name="+host+"&type="+recordType, nil)
	request.Header.Set("Accept", "application/dns-json")
	result, err := (&http.Client{Timeout: 8 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK || json.NewDecoder(result.Body).Decode(&response) != nil {
		return nil, errors.New("DoH 解析失败")
	}
	for _, answer := range response.Answer {
		address := net.ParseIP(answer.Data)
		if answer.Type == expectedType && publicProbeAddress(address, ipv6) {
			return address, nil
		}
	}
	return nil, errors.New("没有可用的公网地址")
}

func forceUDPInterface(connection *net.UDPConn, interfaceIndex int, ipv6 bool) error {
	if interfaceIndex <= 0 {
		return errors.New("物理接口索引无效")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	err = raw.Control(func(handle uintptr) {
		value := interfaceIndex
		level := windows.IPPROTO_IPV6
		if !ipv6 {
			level = windows.IPPROTO_IP
			value = int(bits.ReverseBytes32(uint32(interfaceIndex)))
		}
		socketErr = windows.SetsockoptInt(windows.Handle(handle), level, 31, value)
	})
	if err != nil {
		return err
	}
	return socketErr
}

func newSTUNRequest() ([]byte, [12]byte, error) {
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], 0x0001)
	binary.BigEndian.PutUint32(request[4:8], 0x2112a442)
	var transaction [12]byte
	if _, err := rand.Read(transaction[:]); err != nil {
		return nil, transaction, err
	}
	copy(request[8:], transaction[:])
	return request, transaction, nil
}

func parseSTUNMappedAddress(data []byte, transaction [12]byte) (netip.AddrPort, error) {
	if len(data) < 20 || binary.BigEndian.Uint16(data[0:2]) != 0x0101 || binary.BigEndian.Uint32(data[4:8]) != 0x2112a442 || !bytes.Equal(data[8:20], transaction[:]) {
		return netip.AddrPort{}, errors.New("STUN 响应头无效")
	}
	limit := 20 + int(binary.BigEndian.Uint16(data[2:4]))
	if limit > len(data) {
		limit = len(data)
	}
	for offset := 20; offset+4 <= limit; {
		attributeType := binary.BigEndian.Uint16(data[offset : offset+2])
		length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		value := offset + 4
		if value+length > limit {
			break
		}
		if (attributeType == 0x0020 || attributeType == 0x0001) && length >= 8 {
			family := data[value+1]
			port := binary.BigEndian.Uint16(data[value+2 : value+4])
			if attributeType == 0x0020 {
				port ^= 0x2112
			}
			switch family {
			case 0x01:
				address := append([]byte(nil), data[value+4:value+8]...)
				if attributeType == 0x0020 {
					cookie := []byte{0x21, 0x12, 0xa4, 0x42}
					for i := range address {
						address[i] ^= cookie[i]
					}
				}
				if parsed, ok := netip.AddrFromSlice(address); ok {
					return netip.AddrPortFrom(parsed.Unmap(), port), nil
				}
			case 0x02:
				if length < 20 {
					break
				}
				address := append([]byte(nil), data[value+4:value+20]...)
				if attributeType == 0x0020 {
					mask := append([]byte{0x21, 0x12, 0xa4, 0x42}, transaction[:]...)
					for i := range address {
						address[i] ^= mask[i]
					}
				}
				if parsed, ok := netip.AddrFromSlice(address); ok {
					return netip.AddrPortFrom(parsed, port), nil
				}
			}
		}
		offset = value + length + (4-length%4)%4
	}
	return netip.AddrPort{}, errors.New("STUN 响应没有映射地址")
}

func runSTUNProbes(localAddress string, interfaceIndex int, ipv6 bool, targets []stunTarget) []STUNProbeResult {
	localIP := net.ParseIP(localAddress)
	if localIP == nil {
		return []STUNProbeResult{{Error: "本地地址无效"}}
	}
	network := "udp4"
	bind := &net.UDPAddr{IP: localIP.To4(), Port: 0}
	if ipv6 {
		network = "udp6"
		bind = &net.UDPAddr{IP: localIP, Port: 0, Zone: ""}
	}
	connection, err := net.ListenUDP(network, bind)
	if err != nil {
		return []STUNProbeResult{{Error: err.Error()}}
	}
	defer connection.Close()
	_ = forceUDPInterface(connection, interfaceIndex, ipv6)
	results := make([]STUNProbeResult, 0, len(targets))
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		address, resolveErr := resolveSTUNAddress(ctx, target.Host, ipv6)
		cancel()
		result := STUNProbeResult{Server: target.Name}
		if resolveErr != nil {
			result.Error = resolveErr.Error()
			results = append(results, result)
			continue
		}
		destination := &net.UDPAddr{IP: address, Port: target.Port}
		result.Destination = destination.String()
		request, transaction, requestErr := newSTUNRequest()
		if requestErr != nil {
			result.Error = requestErr.Error()
			results = append(results, result)
			continue
		}
		started := time.Now()
		_ = connection.SetDeadline(time.Now().Add(2500 * time.Millisecond))
		if _, err := connection.WriteToUDP(request, destination); err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		buffer := make([]byte, 2048)
		for {
			count, _, err := connection.ReadFromUDP(buffer)
			if err != nil {
				result.Error = "UDP STUN 超时"
				break
			}
			mapped, err := parseSTUNMappedAddress(buffer[:count], transaction)
			if err != nil {
				continue
			}
			result.Success = true
			result.PublicEndpoint = mapped.String()
			result.LatencyMs = time.Since(started).Milliseconds()
			break
		}
		results = append(results, result)
	}
	return results
}

func resolveDiagnosticTargets(targets []stunTarget, ipv6 bool) ([]stunTarget, []string) {
	resolved := make([]stunTarget, 0, len(targets))
	addresses := make([]string, 0, len(targets))
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		address, err := resolveSTUNAddress(ctx, target.Host, ipv6)
		cancel()
		if err != nil {
			continue
		}
		value := address.String()
		resolved = append(resolved, stunTarget{Name: target.Name, Host: value, Port: target.Port})
		addresses = append(addresses, value)
	}
	return resolved, addresses
}

func (a *clientApp) setDiagnosticIPv6Targets(targets []string, expires time.Time) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil {
		return err
	}
	state.DiagnosticIPv6Targets = append([]string(nil), targets...)
	state.DiagnosticTargetsExpiresAt = expires
	return saveJSON(a.statePath, state)
}

func waitForDiagnosticIPv6Routes(interfaceIndex int, gateway string, targets []string) bool {
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		routes := liveDedicatedRoutes(uint16(windows.AF_INET6), interfaceIndex, gateway, 128)
		seen := map[string]bool{}
		for _, route := range routes {
			seen[route] = true
		}
		ready := len(targets) > 0
		for _, target := range targets {
			ready = ready && seen[target]
		}
		if ready {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func successfulMappings(results []STUNProbeResult) []string {
	seen := map[string]bool{}
	values := []string{}
	for _, result := range results {
		if result.Success && !seen[result.PublicEndpoint] {
			seen[result.PublicEndpoint] = true
			values = append(values, result.PublicEndpoint)
		}
	}
	sort.Strings(values)
	return values
}

func classifySTUN(results []STUNProbeResult, directConfirmed bool, ipv6 bool) (behavior, support, evidence string) {
	if directConfirmed {
		return "confirmed_by_nebula", "confirmed", "Nebula 事件中存在当前地址族的真实 P2P 握手"
	}
	successes := 0
	for _, result := range results {
		if result.Success {
			successes++
		}
	}
	unique := successfulMappings(results)
	if ipv6 && successes > 0 {
		return "public_ipv6", "likely", "公网 IPv6 UDP STUN 可达，不依赖 IPv4 NAT 映射"
	}
	if successes < 2 {
		return "udp_unconfirmed", "unknown", "独立 STUN 成功数不足，可能被 UDP、防火墙、DNS 或网络策略阻止"
	}
	if len(unique) == 1 {
		return "endpoint_independent", "likely", "同一 UDP 测试端口访问多个目标时公网映射保持一致"
	}
	return "endpoint_dependent", "unlikely", "同一 UDP 测试端口访问不同目标得到不同公网映射，符合对称/端点相关 NAT 特征"
}

func underlayFamily(underlay string) int {
	underlay = strings.TrimSpace(strings.TrimSuffix(underlay, "(relayed)"))
	host, _, err := net.SplitHostPort(underlay)
	if err != nil {
		return 0
	}
	address := net.ParseIP(strings.Trim(host, "[]"))
	if address == nil {
		return 0
	}
	if address.To4() != nil {
		return 4
	}
	return 6
}

func (a *clientApp) runNATDiagnostic() NATDiagnosticReport {
	started := time.Now().UTC()
	a.stateMu.Lock()
	state, _ := a.load()
	a.stateMu.Unlock()
	network := networkStatus(state)
	guard := network.RouteGuard
	live, inspectionErr := liveDiagnosticNetwork(state.PreferredP2PInterface)
	if inspectionErr == nil {
		guard = mergeDiagnosticNetwork(guard, live)
	}
	physicalInterface := guard.PhysicalInterface
	if physicalInterface == "" {
		physicalInterface = guard.IPv6Interface
	}
	report := NATDiagnosticReport{
		StartedAt: started, PhysicalInterface: physicalInterface, TUNInterfaces: append([]string(nil), guard.TUNInterfaces...),
		NebulaListenPort: network.ListenPort, RouteGuardReady: guard.BypassReady, UPnPStatus: network.PortMapping,
		DirectPeers: network.DirectCount, RelayPeers: network.RelayCount,
		IPv4:            IPFamilyDiagnostic{Available: guard.PhysicalAddress != "", LocalAddress: guard.PhysicalAddress, Gateway: guard.Gateway, Probes: []STUNProbeResult{}},
		IPv6:            IPFamilyDiagnostic{Available: guard.IPv6Address != "", LocalAddress: guard.IPv6Address, Gateway: guard.IPv6Gateway, Probes: []STUNProbeResult{}},
		Recommendations: []string{},
	}
	v4Confirmed, v6Confirmed := false, false
	for _, path := range network.Paths {
		if path.Mode != "p2p" {
			continue
		}
		switch underlayFamily(path.Underlay) {
		case 4:
			v4Confirmed = true
		case 6:
			v6Confirmed = true
		}
	}
	targets := []stunTarget{{"Cloudflare", "stun.cloudflare.com", 3478}, {"Google", "stun.l.google.com", 19302}, {"Twilio", "global.stun.twilio.com", 3478}}
	if report.IPv4.Available {
		report.IPv4.Probes = runSTUNProbes(report.IPv4.LocalAddress, guard.InterfaceIndex, false, targets)
	} else {
		report.IPv4.Probes = []STUNProbeResult{{Error: "未检测到具有 IPv4 默认网关的物理网卡"}}
	}
	report.IPv4.MappingBehavior, report.IPv4.P2PSupport, report.IPv4.Evidence = classifySTUN(report.IPv4.Probes, v4Confirmed, false)
	if report.IPv6.Available {
		resolvedTargets, routeTargets := resolveDiagnosticTargets(targets[:2], true)
		if len(routeTargets) == 0 {
			report.IPv6.Probes = []STUNProbeResult{{Error: "IPv6 STUN目标解析失败"}}
		} else if err := a.setDiagnosticIPv6Targets(routeTargets, time.Now().UTC().Add(2*time.Minute)); err != nil {
			report.IPv6.Probes = []STUNProbeResult{{Error: "临时IPv6诊断路由请求失败：" + err.Error()}}
		} else {
			defer func() { _ = a.setDiagnosticIPv6Targets(nil, time.Time{}) }()
			if waitForDiagnosticIPv6Routes(guard.IPv6InterfaceIndex, guard.IPv6Gateway, routeTargets) {
				report.IPv6.Probes = runSTUNProbes(report.IPv6.LocalAddress, guard.IPv6InterfaceIndex, true, resolvedTargets)
			} else {
				report.IPv6.Probes = []STUNProbeResult{{Error: "Route Guard未在7秒内应用临时IPv6诊断路由"}}
			}
		}
	} else {
		report.IPv6.Probes = []STUNProbeResult{{Error: "未检测到具有公网 IPv6 和默认网关的物理网卡"}}
	}
	report.IPv6.MappingBehavior, report.IPv6.P2PSupport, report.IPv6.Evidence = classifySTUN(report.IPv6.Probes, v6Confirmed, true)
	if report.IPv6.Available && report.IPv6.P2PSupport == "unknown" && guard.IPv6DefaultSuppressed {
		report.IPv6.MappingBehavior = "dedicated_routes"
		report.IPv6.Evidence = "已检测到公网 IPv6；默认路由因双网卡分流被压制，MeshLAN 使用专用 IPv6 直连路由"
	}
	switch {
	case report.IPv4.P2PSupport == "confirmed" || report.IPv6.P2PSupport == "confirmed":
		report.Verdict = "已确认支持 P2P 直连"
	case report.IPv6.P2PSupport == "likely":
		report.Verdict = "公网 IPv6 可用，P2P 成功概率高"
	case report.IPv4.P2PSupport == "likely":
		report.Verdict = "IPv4 映射稳定，大概率支持 P2P"
	case report.IPv4.P2PSupport == "unlikely" && !report.IPv6.Available:
		report.Verdict = "IPv4 为端点相关 NAT，稳定 P2P 困难"
	default:
		report.Verdict = "暂时无法确认 P2P 能力"
	}
	if !report.RouteGuardReady {
		report.Recommendations = append(report.Recommendations, "先安装物理直连锁，避免 TUN/全局代理劫持 STUN 与 Nebula UDP")
	}
	if inspectionErr != nil {
		report.Recommendations = append(report.Recommendations, "Windows 网络接口读取失败："+inspectionErr.Error())
	}
	if report.IPv4.P2PSupport == "unlikely" {
		report.Recommendations = append(report.Recommendations, "优先使用公网 IPv6；或在路由器映射稳定 UDP 端口")
	}
	if report.IPv4.P2PSupport == "unknown" && report.IPv6.P2PSupport == "unknown" {
		report.Recommendations = append(report.Recommendations, "检查 Windows 防火墙、路由器 UDP、运营商网络和代理 Kill Switch")
	}
	if report.UPnPStatus != "mapped" {
		report.Recommendations = append(report.Recommendations, "路由器支持时启用 UPnP，或手动转发当前 Nebula UDP 端口")
	}
	report.CompletedAt = time.Now().UTC()
	_ = a.history.RecordEvent("client", "nat_diagnostic", state.Name, report.Verdict, report.CompletedAt)
	return report
}
