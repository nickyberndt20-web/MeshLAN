//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

type dualStackRuntime struct {
	Scores      map[string]DualStackFamilyScore
	PoorSamples int
}

var errDualStackModeRequired = errors.New("请先选择 IPv4 + IPv6 模式，再启用智能双栈与网络场景")

func automationRaceState(enabled, componentReady bool, requested, applied uint64, requestedAt, now time.Time) string {
	if !enabled {
		return "disabled"
	}
	if applied >= requested {
		return "stable"
	}
	if !componentReady {
		return "component_required"
	}
	if requestedAt.IsZero() || now.Sub(requestedAt) > 45*time.Second {
		return "pending"
	}
	return "racing"
}

func networkPrefixKey(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	if address.Is4() {
		return netip.PrefixFrom(address, 24).Masked().String()
	}
	return netip.PrefixFrom(address, 64).Masked().String()
}

func currentNetworkFingerprint(state ClientState) (fingerprint, sceneName string, err error) {
	adapters, err := readDiagnosticAdapters()
	if err != nil {
		return "", "", err
	}
	parts := []string{}
	preferred := normalizeInterfacePreference(state.PreferredP2PInterface)
	primary := ""
	for _, adapter := range adapters {
		if adapter.LikelyTUN || (adapter.Gateway4 == "" && adapter.Gateway6 == "") {
			continue
		}
		part := strings.ToLower(adapter.Name) + "|" + adapter.Gateway4 + "|" + adapter.Gateway6 + "|" + networkPrefixKey(adapter.IPv4) + "|" + networkPrefixKey(adapter.IPv6)
		parts = append(parts, part)
		if primary == "" || strings.EqualFold(adapter.Name, preferred) {
			primary = adapter.Name
		}
	}
	if len(parts) == 0 {
		return "", "", errors.New("没有检测到带网关的活动物理网络")
	}
	sort.Strings(parts)
	hash := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	fingerprint = hex.EncodeToString(hash[:8])
	if primary == "" {
		primary = "自动网络"
	}
	return fingerprint, primary + " 网络", nil
}

func findNetworkScene(scenes []NetworkSceneProfile, id string) int {
	for index := range scenes {
		if scenes[index].ID == id {
			return index
		}
	}
	return -1
}

func (a *clientApp) observeNetworkScene() {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || state.Pairing == nil {
		return
	}
	fingerprint, sceneName, err := currentNetworkFingerprint(state)
	if err != nil || fingerprint == state.NetworkFingerprint {
		return
	}
	now := time.Now().UTC()
	a.stateMu.Lock()
	state, err = a.load()
	if err != nil || state.Pairing == nil || fingerprint == state.NetworkFingerprint {
		a.stateMu.Unlock()
		return
	}
	previous := state.CurrentNetworkScene
	index := findNetworkScene(state.NetworkScenes, fingerprint)
	if index < 0 {
		state.NetworkScenes = append(state.NetworkScenes, NetworkSceneProfile{
			ID: fingerprint, Name: sceneName, P2PInterface: normalizeInterfacePreference(state.PreferredP2PInterface),
			BusinessInterface: normalizeInterfacePreference(state.PreferredBusinessInterface), CreatedAt: now, LastSeen: now,
		})
		index = len(state.NetworkScenes) - 1
	} else {
		state.NetworkScenes[index].LastSeen = now
		if state.AutoNetworkScenes {
			state.PreferredP2PInterface = normalizeInterfacePreference(state.NetworkScenes[index].P2PInterface)
			state.PreferredBusinessInterface = normalizeInterfacePreference(state.NetworkScenes[index].BusinessInterface)
		}
	}
	state.NetworkFingerprint = fingerprint
	state.CurrentNetworkScene = state.NetworkScenes[index].Name
	state.LastNetworkChangeAt = now
	if state.AutoDualStack && normalizeIPMode(state.IPMode) == "dual" {
		state.RaceRequestVersion++
		state.LastRaceRequestedAt = now
		state.LastRaceReason = "检测到网络场景变化，重新注册端点并同时尝试 IPv4/IPv6 打洞"
	}
	config, configErr := renderClientConfig(state)
	if configErr == nil {
		configErr = os.WriteFile(state.ConfigPath, []byte(config), 0o600)
	}
	if configErr == nil {
		configErr = saveJSON(a.statePath, state)
	}
	a.stateMu.Unlock()
	if configErr == nil && a.history != nil {
		detail := fmt.Sprintf("%s → %s；已应用 P2P=%s，业务=%s", previous, state.CurrentNetworkScene, state.PreferredP2PInterface, state.PreferredBusinessInterface)
		_ = a.history.RecordEvent("client", "network_scene_changed", state.Name, detail, now)
	}
}

func dualStackScore(quality overlayQualityProbe) float64 {
	if !quality.Reachable {
		return 0
	}
	score := 100 - float64(quality.LatencyMs)/4 - quality.JitterMs/2 - quality.PacketLossPct*1.5
	if score < 0 {
		return 0
	}
	return score
}

func (a *clientApp) recordDualStackQuality(family string, quality overlayQualityProbe) {
	if family != "ipv4" && family != "ipv6" {
		return
	}
	now := time.Now().UTC()
	a.automationMu.Lock()
	if a.dualStackRuntime.Scores == nil {
		a.dualStackRuntime.Scores = map[string]DualStackFamilyScore{}
	}
	current := a.dualStackRuntime.Scores[family]
	alpha := 0.35
	if current.Samples == 0 {
		alpha = 1
	}
	current.Family = family
	current.Score = current.Score*(1-alpha) + dualStackScore(quality)*alpha
	current.LatencyMs = current.LatencyMs*(1-alpha) + float64(max64(quality.LatencyMs, 0))*alpha
	current.JitterMs = current.JitterMs*(1-alpha) + quality.JitterMs*alpha
	current.PacketLossPct = current.PacketLossPct*(1-alpha) + quality.PacketLossPct*alpha
	current.Samples += quality.Samples
	current.UpdatedAt = now
	a.dualStackRuntime.Scores[family] = current
	poor := !quality.Reachable || quality.PacketLossPct >= 34 || quality.LatencyMs >= 300 || quality.JitterMs >= 100
	if poor {
		a.dualStackRuntime.PoorSamples++
	} else {
		a.dualStackRuntime.PoorSamples = 0
	}
	poorSamples := a.dualStackRuntime.PoorSamples
	a.automationMu.Unlock()
	if poorSamples >= 3 {
		a.requestDualStackRace("当前链路连续三个周期质量恶化，重新同时尝试 IPv4/IPv6")
	}
}

func max64(value, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func (a *clientApp) requestDualStackRace(reason string) bool {
	now := time.Now().UTC()
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil || !state.AutoDualStack || normalizeIPMode(state.IPMode) != "dual" || state.Pairing == nil || (!state.LastRaceRequestedAt.IsZero() && now.Sub(state.LastRaceRequestedAt) < 2*time.Minute) {
		return false
	}
	state.RaceRequestVersion++
	state.LastRaceRequestedAt = now
	state.LastRaceReason = reason
	config, err := renderClientConfig(state)
	if err == nil {
		err = os.WriteFile(state.ConfigPath, []byte(config), 0o600)
	}
	if err == nil {
		err = saveJSON(a.statePath, state)
	}
	if err == nil && a.history != nil {
		_ = a.history.RecordEvent("client", "dual_stack_race", state.Name, reason, now)
	}
	return err == nil
}

func (a *clientApp) sampleDualStackQuality() {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || !state.AutoDualStack || normalizeIPMode(state.IPMode) != "dual" || state.Pairing == nil {
		return
	}
	directory, err := fetchPeerDirectory(state)
	if err != nil {
		return
	}
	paths := networkStatus(state).Paths
	pathByAddress := map[string]NetworkPathRecord{}
	for _, path := range paths {
		pathByAddress[strings.Split(path.Address, "/")[0]] = path
	}
	for _, peer := range directory.Peers {
		if peer.Name == state.Name || !peer.Online {
			continue
		}
		address := strings.Split(peer.Address, "/")[0]
		path, exists := pathByAddress[address]
		if !exists || path.Mode != "p2p" {
			continue
		}
		a.recordDualStackQuality(pathFamily(path.Underlay), probeOverlayQuality(peer.Address, 3))
		return
	}
}

func (a *clientApp) networkAutomationLoop() {
	a.observeNetworkScene()
	a.sampleDualStackQuality()
	networkTicker := time.NewTicker(5 * time.Second)
	qualityTicker := time.NewTicker(20 * time.Second)
	defer networkTicker.Stop()
	defer qualityTicker.Stop()
	for {
		select {
		case <-networkTicker.C:
			a.observeNetworkScene()
		case <-qualityTicker.C:
			a.sampleDualStackQuality()
		}
	}
}

func (a *clientApp) dualStackStatus() DualStackRaceStatus {
	a.stateMu.Lock()
	state, _ := a.load()
	a.stateMu.Unlock()
	network := networkStatus(state)
	modeAllowsAutomation := normalizeIPMode(state.IPMode) == "dual"
	status := DualStackRaceStatus{
		Enabled: state.AutoDualStack && modeAllowsAutomation, AutoScenes: state.AutoNetworkScenes && modeAllowsAutomation, State: "disabled", LastRaceAt: state.LastRaceRequestedAt, LastRaceReason: state.LastRaceReason,
		RequestedVersion: state.RaceRequestVersion, AppliedVersion: network.RouteGuard.RaceAppliedVersion,
		NetworkFingerprint: state.NetworkFingerprint, CurrentScene: state.CurrentNetworkScene, LastNetworkChangeAt: state.LastNetworkChangeAt,
		Scores: []DualStackFamilyScore{},
		Scenes: append([]NetworkSceneProfile(nil), state.NetworkScenes...),
	}
	guard := network.RouteGuard
	componentReady := guard.Version >= routeGuardVersion && guard.Mode == "guarding" && guard.BypassReady
	status.State = automationRaceState(status.Enabled, componentReady, status.RequestedVersion, status.AppliedVersion, state.LastRaceRequestedAt, time.Now().UTC())
	for _, path := range network.Paths {
		if path.Mode == "p2p" {
			status.Winner, status.CurrentPath, status.CurrentEndpoint = pathFamily(path.Underlay), path.Mode, path.Underlay
			break
		}
	}
	a.automationMu.Lock()
	for _, family := range []string{"ipv4", "ipv6"} {
		if score, exists := a.dualStackRuntime.Scores[family]; exists {
			status.Scores = append(status.Scores, score)
		}
	}
	a.automationMu.Unlock()
	return status
}

func validNetworkSceneName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len([]rune(value)) > 32 {
		return false
	}
	for _, character := range value {
		if character < 32 || character == '<' || character == '>' {
			return false
		}
	}
	return true
}

func (a *clientApp) renameNetworkScene(id, name string) (DualStackRaceStatus, error) {
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	if !validNetworkSceneName(name) {
		return DualStackRaceStatus{}, errors.New("场景名称不能为空且最多32个字符")
	}
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		index := findNetworkScene(state.NetworkScenes, id)
		if index < 0 {
			err = errors.New("网络场景不存在")
		} else {
			state.NetworkScenes[index].Name = name
			if state.NetworkFingerprint == id {
				state.CurrentNetworkScene = name
			}
			err = saveJSON(a.statePath, state)
		}
	}
	a.stateMu.Unlock()
	if err != nil {
		return DualStackRaceStatus{}, err
	}
	return a.dualStackStatus(), nil
}

func (a *clientApp) deleteNetworkScene(id string) (DualStackRaceStatus, error) {
	id = strings.TrimSpace(id)
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		found := false
		kept := state.NetworkScenes[:0]
		for _, scene := range state.NetworkScenes {
			if scene.ID == id {
				found = true
				continue
			}
			kept = append(kept, scene)
		}
		if !found {
			err = errors.New("网络场景不存在")
		} else {
			state.NetworkScenes = kept
			if state.NetworkFingerprint == id {
				state.NetworkFingerprint = ""
				state.CurrentNetworkScene = ""
			}
			err = saveJSON(a.statePath, state)
		}
	}
	a.stateMu.Unlock()
	if err != nil {
		return DualStackRaceStatus{}, err
	}
	return a.dualStackStatus(), nil
}

func (a *clientApp) setNetworkAutomation(enabled, scenes bool) (DualStackRaceStatus, error) {
	a.stateMu.Lock()
	state, err := a.load()
	if err == nil {
		if (enabled || scenes) && normalizeIPMode(state.IPMode) != "dual" {
			a.stateMu.Unlock()
			return DualStackRaceStatus{}, errDualStackModeRequired
		}
		wasEnabled := state.AutoDualStack
		state.AutoDualStack = enabled
		state.AutoNetworkScenes = scenes
		state.NetworkAutomationVersion = networkAutomationVersion
		if enabled && !wasEnabled {
			state.RaceRequestVersion++
			state.LastRaceRequestedAt = time.Now().UTC()
			state.LastRaceReason = "已启用智能双栈竞速"
			config, configErr := renderClientConfig(state)
			if configErr == nil {
				configErr = os.WriteFile(state.ConfigPath, []byte(config), 0o600)
			}
			if configErr != nil {
				err = configErr
			}
		}
		if err == nil {
			err = saveJSON(a.statePath, state)
		}
	}
	a.stateMu.Unlock()
	if err != nil {
		return DualStackRaceStatus{}, err
	}
	return a.dualStackStatus(), nil
}
