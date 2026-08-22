package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

func barePeerAddress(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().String()
	}
	return strings.Split(value, "/")[0]
}

func findPeerByName(state *ServerState, name string) *PeerRecord {
	for i := range state.Peers {
		if state.Peers[i].Name == name && !state.Peers[i].Revoked {
			return &state.Peers[i]
		}
	}
	return nil
}

func findPublishedService(state *ServerState, ownerName, mappingID string) (*PeerRecord, *PublishedServiceMapping) {
	owner := findPeerByName(state, ownerName)
	if owner == nil {
		return nil, nil
	}
	for i := range owner.ServiceMappings {
		if owner.ServiceMappings[i].ID == mappingID {
			return owner, &owner.ServiceMappings[i]
		}
	}
	return owner, nil
}

func findAccessRequest(state *ServerState, ownerName, mappingID, requesterName string) *ServiceAccessRequest {
	for i := range state.AccessRequests {
		request := &state.AccessRequests[i]
		if request.OwnerName == ownerName && request.MappingID == mappingID && request.RequesterName == requesterName {
			return request
		}
	}
	return nil
}

func viewerAccessStatus(state *ServerState, service PublishedServiceMapping, viewerName string) string {
	if viewerName == service.OwnerName {
		return "owner"
	}
	if service.Paused {
		return "service_paused"
	}
	if request := findAccessRequest(state, service.OwnerName, service.ID, viewerName); request != nil {
		return request.Status
	}
	if service.ApprovalRequired {
		return "not_requested"
	}
	return "open"
}

func buildDeviceControl(state *ServerState, viewerName string, now time.Time) DeviceControlResponse {
	control := DeviceControlResponse{
		Messages: []AccessMessage{}, Policies: []MappingAccessPolicy{}, Peers: []PeerIdentity{}, DNSRecords: buildMeshDNSRecords(*state), UpdatedAt: now,
	}
	for _, peer := range state.Peers {
		if !peer.Revoked {
			control.Peers = append(control.Peers, PeerIdentity{Name: peer.Name, Address: barePeerAddress(peer.Address)})
		}
	}
	for _, request := range state.AccessRequests {
		if request.OwnerName != viewerName && request.RequesterName != viewerName {
			continue
		}
		direction := "outgoing"
		if request.OwnerName == viewerName {
			direction = "incoming"
		}
		control.Messages = append(control.Messages, AccessMessage{
			ID: request.ID, MappingID: request.MappingID, ServiceName: request.ServiceName,
			OwnerName: request.OwnerName, RequesterName: request.RequesterName,
			Status: request.Status, Direction: direction, CreatedAt: request.CreatedAt, UpdatedAt: request.UpdatedAt,
		})
	}
	owner := findPeerByName(state, viewerName)
	if owner == nil {
		return control
	}
	for _, service := range owner.ServiceMappings {
		policy := MappingAccessPolicy{MappingID: service.ID, ApprovalRequired: service.ApprovalRequired, Users: []ServiceUserAccess{}}
		for _, peer := range state.Peers {
			if peer.Revoked || peer.Name == viewerName {
				continue
			}
			status := "open"
			if service.ApprovalRequired {
				status = "not_requested"
			}
			if request := findAccessRequest(state, viewerName, service.ID, peer.Name); request != nil {
				status = request.Status
			}
			policy.Users = append(policy.Users, ServiceUserAccess{UserName: peer.Name, Address: barePeerAddress(peer.Address), Status: status})
		}
		control.Policies = append(control.Policies, policy)
	}
	return control
}

func writeControlJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func registerAccessControlRoutes(mux *http.ServeMux, state *ServerState, stateMu *sync.Mutex, statePath string) {
	mux.HandleFunc("GET /v1/control", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		viewer := authorizedDevicePeer(state, r)
		if viewer == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		control := buildDeviceControl(state, viewer.Name, time.Now())
		if envelope, err := signedRevocationEnvelope(*state); err == nil {
			control.Revocations = envelope
		}
		writeControlJSON(w, http.StatusOK, control)
	})

	mux.HandleFunc("POST /v1/access/request", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		requester := authorizedDevicePeer(state, r)
		if requester == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			OwnerName string `json:"ownerName"`
			MappingID string `json:"mappingId"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		_, service := findPublishedService(state, strings.TrimSpace(input.OwnerName), strings.TrimSpace(input.MappingID))
		if service == nil {
			http.Error(w, "service not found", http.StatusNotFound)
			return
		}
		if input.OwnerName == requester.Name {
			http.Error(w, "owner does not need access approval", http.StatusConflict)
			return
		}
		if !service.ApprovalRequired {
			writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "open"})
			return
		}
		now := time.Now()
		record := findAccessRequest(state, input.OwnerName, input.MappingID, requester.Name)
		if record != nil && record.Status == "paused" {
			http.Error(w, "access paused by owner", http.StatusConflict)
			return
		}
		if record == nil {
			id, err := randomToken(12)
			if err != nil {
				http.Error(w, "request id failed", http.StatusInternalServerError)
				return
			}
			state.AccessRequests = append(state.AccessRequests, ServiceAccessRequest{
				ID: id, MappingID: service.ID, ServiceName: service.ServiceName, OwnerName: input.OwnerName,
				RequesterName: requester.Name, RequesterAddress: barePeerAddress(requester.Address),
				Status: "pending", CreatedAt: now, UpdatedAt: now,
			})
			record = &state.AccessRequests[len(state.AccessRequests)-1]
		} else if record.Status != "approved" && record.Status != "pending" {
			record.Status = "pending"
			record.UpdatedAt = now
		}
		if err := saveJSON(statePath, *state); err != nil {
			http.Error(w, "state write failed", http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "status": record.Status, "requestId": record.ID})
	})

	mux.HandleFunc("POST /v1/access/respond", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		owner := authorizedDevicePeer(state, r)
		if owner == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			RequestID string `json:"requestId"`
			Approve   bool   `json:"approve"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var record *ServiceAccessRequest
		for i := range state.AccessRequests {
			if state.AccessRequests[i].ID == input.RequestID && state.AccessRequests[i].OwnerName == owner.Name {
				record = &state.AccessRequests[i]
				break
			}
		}
		if record == nil || record.Status != "pending" {
			http.Error(w, "pending request not found", http.StatusNotFound)
			return
		}
		if input.Approve {
			record.Status = "approved"
		} else {
			record.Status = "rejected"
		}
		record.UpdatedAt = time.Now()
		if err := saveJSON(statePath, *state); err != nil {
			http.Error(w, "state write failed", http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "status": record.Status})
	})

	mux.HandleFunc("POST /v1/access/user", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		owner := authorizedDevicePeer(state, r)
		if owner == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			MappingID string `json:"mappingId"`
			UserName  string `json:"userName"`
			Paused    bool   `json:"paused"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		_, service := findPublishedService(state, owner.Name, input.MappingID)
		requester := findPeerByName(state, input.UserName)
		if service == nil || requester == nil || requester.Name == owner.Name {
			http.Error(w, "service or user not found", http.StatusNotFound)
			return
		}
		now := time.Now()
		record := findAccessRequest(state, owner.Name, service.ID, requester.Name)
		if record == nil {
			id, err := randomToken(12)
			if err != nil {
				http.Error(w, "request id failed", http.StatusInternalServerError)
				return
			}
			state.AccessRequests = append(state.AccessRequests, ServiceAccessRequest{
				ID: id, MappingID: service.ID, ServiceName: service.ServiceName, OwnerName: owner.Name,
				RequesterName: requester.Name, RequesterAddress: barePeerAddress(requester.Address),
				CreatedAt: now, UpdatedAt: now,
			})
			record = &state.AccessRequests[len(state.AccessRequests)-1]
		}
		if input.Paused {
			record.Status = "paused"
		} else if service.ApprovalRequired {
			record.Status = "approved"
		} else {
			record.Status = "open"
		}
		record.UpdatedAt = now
		if err := saveJSON(statePath, *state); err != nil {
			http.Error(w, "state write failed", http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "status": record.Status})
	})
}
