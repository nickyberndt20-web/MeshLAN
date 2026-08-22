package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
)

const meshDNSSuffix = "mesh"

var reservedDNSPrefixes = map[string]bool{
	"admin": true, "api": true, "localhost": true, "lighthouse": true, "mesh": true, "www": true,
}

func shortStableHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])[:8]
}

func meshDNSLabel(value, fallbackSeed string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastHyphen := false
	for _, r := range value {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			builder.WriteRune(r)
			lastHyphen = false
			continue
		}
		if !lastHyphen && builder.Len() > 0 {
			builder.WriteByte('-')
			lastHyphen = true
		}
	}
	label := strings.Trim(builder.String(), "-")
	if label == "" {
		label = "node-" + shortStableHash(fallbackSeed)
	}
	if len(label) > 48 {
		label = strings.Trim(label[:48], "-") + "-" + shortStableHash(fallbackSeed)
	}
	return label
}

func normalizeDNSPrefix(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 1 || len(value) > 63 || reservedDNSPrefixes[value] {
		return "", errors.New("DNS前缀长度必须为1-63，且不能使用保留名称")
	}
	for index, r := range value {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
		if !valid || ((index == 0 || index == len(value)-1) && r == '-') {
			return "", errors.New("DNS前缀只能包含小写字母、数字和中划线，且不能以中划线开头或结尾")
		}
	}
	return value, nil
}

func validDNSPrefix(value string) bool {
	_, err := normalizeDNSPrefix(value)
	return err == nil
}

func uniqueDefaultDNSPrefix(name string, used map[string]bool) string {
	base := meshDNSLabel(name, name)
	if !reservedDNSPrefixes[base] && !used[base] {
		return base
	}
	candidate := base + "-" + shortStableHash(name)
	if !used[candidate] {
		return candidate
	}
	for index := 2; ; index++ {
		candidate = base + "-" + shortStableHash(name+"-"+strconv.Itoa(index))
		if !used[candidate] {
			return candidate
		}
	}
}

func ensurePeerDNSPrefixes(state *ServerState) bool {
	changed := false
	used := map[string]bool{}
	indexes := make([]int, len(state.Peers))
	for i := range state.Peers {
		indexes[i] = i
	}
	sort.Slice(indexes, func(i, j int) bool { return state.Peers[indexes[i]].Name < state.Peers[indexes[j]].Name })
	for _, index := range indexes {
		peer := &state.Peers[index]
		prefix, err := normalizeDNSPrefix(peer.DNSPrefix)
		if err == nil && !used[prefix] {
			if peer.DNSPrefix != prefix {
				peer.DNSPrefix = prefix
				changed = true
			}
			used[prefix] = true
			continue
		}
		prefix = uniqueDefaultDNSPrefix(peer.Name, used)
		if peer.DNSPrefix != prefix {
			peer.DNSPrefix = prefix
			changed = true
		}
		used[prefix] = true
	}
	return changed
}

func peerDNSPrefix(state ServerState, peer PeerRecord) string {
	if prefix, err := normalizeDNSPrefix(peer.DNSPrefix); err == nil {
		return prefix
	}
	used := map[string]bool{}
	for _, other := range state.Peers {
		if other.Name == peer.Name {
			continue
		}
		if prefix, err := normalizeDNSPrefix(other.DNSPrefix); err == nil {
			used[prefix] = true
		}
	}
	return uniqueDefaultDNSPrefix(peer.Name, used)
}

func serviceDNSPrefix(service PublishedServiceMapping) string {
	if prefix, err := normalizeDNSPrefix(service.DNSPrefix); err == nil {
		return prefix
	}
	return meshDNSLabel(service.ServiceName, service.ID)
}

func serviceDNSName(servicePrefix, ownerPrefix string) string {
	return servicePrefix + "." + ownerPrefix + "." + meshDNSSuffix
}

func buildMeshDNSRecords(state ServerState) []MeshDNSRecord {
	ensurePeerDNSPrefixes(&state)
	records := make([]MeshDNSRecord, 0, len(state.Peers)*2)
	for _, peer := range state.Peers {
		if peer.Revoked {
			continue
		}
		address := barePeerAddress(peer.Address)
		ownerPrefix := peerDNSPrefix(state, peer)
		records = append(records, MeshDNSRecord{Name: ownerPrefix + "." + meshDNSSuffix, Address: address, Kind: "device", OwnerName: peer.Name, OwnerPrefix: ownerPrefix})
		baseCount := map[string]int{}
		for _, service := range peer.ServiceMappings {
			baseCount[serviceDNSPrefix(service)]++
		}
		for _, service := range peer.ServiceMappings {
			servicePrefix := serviceDNSPrefix(service)
			if baseCount[servicePrefix] > 1 {
				servicePrefix += "-" + shortStableHash(service.ID)
			}
			name := serviceDNSName(servicePrefix, ownerPrefix)
			url := ""
			if service.PortlessHTTP && normalizeMappingProtocol(service.Protocol) == "tcp" {
				scheme := "http://"
				if service.HTTPS {
					scheme = "https://"
				}
				url = scheme + name
			}
			records = append(records, MeshDNSRecord{
				Name: name, Address: address, Kind: "service", OwnerName: peer.Name, OwnerPrefix: ownerPrefix, ServiceName: service.ServiceName,
				MappingID: service.ID, Port: service.Port, Protocol: normalizeMappingProtocol(service.Protocol),
				PortlessHTTP: service.PortlessHTTP, URL: url,
			})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		return records[i].Name < records[j].Name
	})
	return records
}
