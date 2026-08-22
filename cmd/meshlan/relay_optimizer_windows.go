//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

func relayScore(quality overlayQualityProbe) float64 {
	if !quality.Reachable || quality.LatencyMs < 0 {
		return math.MaxFloat64
	}
	return float64(quality.LatencyMs) + quality.JitterMs*2 + quality.PacketLossPct*5
}

func selectPreferredRelay(candidates []RelayCandidateScore, current string) string {
	reachable := make([]RelayCandidateScore, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Reachable {
			reachable = append(reachable, candidate)
		}
	}
	if len(reachable) == 0 {
		return current
	}
	sort.SliceStable(reachable, func(i, j int) bool { return reachable[i].Score < reachable[j].Score })
	best := reachable[0]
	if current == "" || current == best.Address {
		return best.Address
	}
	for _, candidate := range reachable {
		if candidate.Address != current {
			continue
		}
		threshold := math.Max(20, candidate.Score*0.2)
		if best.Score+threshold >= candidate.Score {
			return current
		}
		break
	}
	return best.Address
}

func orderedLighthouseEndpoints(nodes []LighthouseEndpoint, preferred string, scores []RelayCandidateScore) []LighthouseEndpoint {
	result := append([]LighthouseEndpoint(nil), nodes...)
	scoreByAddress := map[string]float64{}
	for _, score := range scores {
		scoreByAddress[score.Address] = score.Score
	}
	sort.SliceStable(result, func(i, j int) bool {
		left := strings.Split(result[i].Address, "/")[0]
		right := strings.Split(result[j].Address, "/")[0]
		if left == preferred {
			return true
		}
		if right == preferred {
			return false
		}
		leftScore, leftMeasured := scoreByAddress[left]
		rightScore, rightMeasured := scoreByAddress[right]
		if leftMeasured != rightMeasured {
			return leftMeasured
		}
		if leftMeasured && leftScore != rightScore {
			return leftScore < rightScore
		}
		return result[i].Primary && !result[j].Primary
	})
	return result
}

func (a *clientApp) optimizeRelaySelection() error {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || state.Pairing == nil {
		return err
	}
	nodes := effectiveLighthouseEndpoints(state.Pairing)
	type measuredRelay struct {
		index int
		node  LighthouseEndpoint
		probe overlayQualityProbe
	}
	measured := make([]measuredRelay, 0, len(nodes))
	for _, node := range nodes {
		if node.Relay || node.Primary {
			measured = append(measured, measuredRelay{index: len(measured), node: node})
		}
	}
	if len(measured) == 0 {
		return nil
	}
	var wait sync.WaitGroup
	for index := range measured {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			measured[index].probe = probeOverlayQuality(measured[index].node.Address, 3)
		}(index)
	}
	wait.Wait()
	now := time.Now().UTC()
	candidates := make([]RelayCandidateScore, 0, len(measured))
	for _, item := range measured {
		address := strings.Split(item.node.Address, "/")[0]
		candidates = append(candidates, RelayCandidateScore{Address: address, Name: item.node.Name, Reachable: item.probe.Reachable, LatencyMs: item.probe.LatencyMs, JitterMs: item.probe.JitterMs, PacketLossPct: item.probe.PacketLossPct, Score: relayScore(item.probe), MeasuredAt: now})
	}
	preferred := selectPreferredRelay(candidates, state.PreferredRelayAddress)
	for index := range candidates {
		candidates[index].Preferred = candidates[index].Address == preferred
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	latest, err := a.load()
	if err != nil || latest.Pairing == nil {
		return err
	}
	previousPreferred := latest.PreferredRelayAddress
	previousNodes, _ := json.Marshal(latest.Pairing.Lighthouses)
	latest.PreferredRelayAddress = preferred
	latest.RelayCandidates = candidates
	latest.RelaySelectionUpdatedAt = now
	latest.Pairing.Lighthouses = orderedLighthouseEndpoints(latest.Pairing.Lighthouses, preferred, candidates)
	currentNodes, _ := json.Marshal(latest.Pairing.Lighthouses)
	orderChanged := !bytes.Equal(previousNodes, currentNodes)
	if orderChanged {
		config, renderErr := renderClientConfig(latest)
		if renderErr != nil {
			return renderErr
		}
		if err := os.WriteFile(latest.ConfigPath, []byte(config), 0o600); err != nil {
			return err
		}
	}
	if preferred != previousPreferred && !latest.ForceP2P {
		latest.RaceRequestVersion++
		latest.LastRaceRequestedAt = now
		latest.LastRaceReason = "Relay 健康评分变化，已切换优先中继节点"
	}
	return saveJSON(a.statePath, latest)
}

func (a *clientApp) relayOptimizerLoop() {
	time.Sleep(8 * time.Second)
	_ = a.optimizeRelaySelection()
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_ = a.optimizeRelaySelection()
	}
}
