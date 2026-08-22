//go:build windows

package main

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

type overlayQualityProbe struct {
	Reachable     bool
	LatencyMs     int64
	JitterMs      float64
	PacketLossPct float64
	Samples       int
}

type peerPathObservation struct {
	Signature string
	Mode      string
	Family    string
	Underlay  string
	ChangedAt time.Time
	Reason    string
	Online    bool
}

func summarizeOverlayQuality(latencies []int64, attempts int) overlayQualityProbe {
	if attempts < 1 {
		attempts = 1
	}
	valid := make([]int64, 0, len(latencies))
	for _, latency := range latencies {
		if latency >= 0 {
			valid = append(valid, latency)
		}
	}
	result := overlayQualityProbe{LatencyMs: -1, PacketLossPct: float64(attempts-len(valid)) * 100 / float64(attempts), Samples: attempts}
	if len(valid) == 0 {
		return result
	}
	result.Reachable = true
	var total int64
	for _, latency := range valid {
		total += latency
	}
	result.LatencyMs = int64(math.Round(float64(total) / float64(len(valid))))
	if len(valid) > 1 {
		var delta float64
		for index := 1; index < len(valid); index++ {
			delta += math.Abs(float64(valid[index] - valid[index-1]))
		}
		result.JitterMs = math.Round(delta/float64(len(valid)-1)*10) / 10
	}
	return result
}

func probeOverlayQuality(address string, attempts int) overlayQualityProbe {
	if attempts < 1 {
		attempts = 1
	}
	latencies := make([]int64, attempts)
	for index := range latencies {
		latencies[index] = -1
	}
	var wait sync.WaitGroup
	for index := range latencies {
		wait.Add(1)
		go func(sample int) {
			defer wait.Done()
			if reachable, latency := probeOverlayAddress(address); reachable {
				latencies[sample] = latency
			}
		}(index)
	}
	wait.Wait()
	return summarizeOverlayQuality(latencies, attempts)
}

func pathFamily(underlay string) string {
	switch underlayFamily(underlay) {
	case 4:
		return "ipv4"
	case 6:
		return "ipv6"
	default:
		return "unknown"
	}
}

func pathChangeReason(previous, current peerPathObservation) string {
	if !current.Online {
		return "控制心跳超时，设备按离线处理"
	}
	if previous.Signature == "" {
		if current.Mode == "down" {
			return "首次检测时隧道不可达"
		}
		return "首次检测到" + strings.ToUpper(current.Family) + " " + strings.ToUpper(current.Mode) + "路径"
	}
	if previous.Mode == "relay" && current.Mode == "p2p" {
		return "NAT打洞成功，从 Relay 切换为 P2P直连"
	}
	if previous.Mode == "p2p" && current.Mode == "relay" {
		return "P2P直连失效，回退到 Relay"
	}
	if current.Mode == "down" {
		return "Peer探测连续失败，当前隧道不可达"
	}
	if previous.Mode == "down" && current.Mode != "down" {
		return "Peer恢复可达，重新建立" + strings.ToUpper(current.Family) + " " + strings.ToUpper(current.Mode) + "路径"
	}
	if previous.Family != current.Family && previous.Family != "unknown" && current.Family != "unknown" {
		return "底层路径由" + strings.ToUpper(previous.Family) + "切换为" + strings.ToUpper(current.Family)
	}
	if previous.Underlay != current.Underlay {
		return "公网端点或NAT映射发生变化"
	}
	return "链路状态发生变化"
}

func (a *clientApp) observePeerPath(peer *TopologyPeerNode, now time.Time) (bool, string) {
	peer.PathFamily = pathFamily(peer.Underlay)
	current := peerPathObservation{Mode: peer.PathMode, Family: peer.PathFamily, Underlay: peer.Underlay, Online: peer.Online}
	current.Signature = current.Mode + "|" + current.Family + "|" + current.Underlay
	if a.peerPathStates == nil {
		a.peerPathStates = map[string]peerPathObservation{}
	}
	previous := a.peerPathStates[peer.Name]
	if previous.Signature == current.Signature {
		peer.PathChangedAt, peer.PathChangeReason = previous.ChangedAt, previous.Reason
		return false, ""
	}
	current.ChangedAt = now
	current.Reason = pathChangeReason(previous, current)
	a.peerPathStates[peer.Name] = current
	peer.PathChangedAt, peer.PathChangeReason = current.ChangedAt, current.Reason
	return previous.Signature != "", current.Reason
}

func sortedLatencies(values []int64) []int64 {
	copy := append([]int64(nil), values...)
	sort.Slice(copy, func(i, j int) bool { return copy[i] < copy[j] })
	return copy
}
