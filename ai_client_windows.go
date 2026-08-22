//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const aiClientKeyVersion = 1

var aiSensitivePattern = regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bMLN1\.|\bMLNODE1\.|\bapikey-[a-z0-9_-]{12,}|authorization:\s*bearer)`)

func (a *clientApp) ensureClientAIIdentity() error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil {
		return err
	}
	if state.AIKeyVersion >= aiClientKeyVersion && state.AIEncryptedPrivateKey != "" && validX25519PublicKey(state.AIEncryptionPublicKey) {
		if privateKey, decryptErr := dpapiUnprotectString(state.AIEncryptedPrivateKey); decryptErr == nil && validX25519KeyPair(privateKey, state.AIEncryptionPublicKey) {
			return nil
		}
	}
	privateKey, publicKey, err := generateX25519KeyPair()
	if err != nil {
		return err
	}
	encryptedPrivateKey, err := dpapiProtectString(privateKey)
	if err != nil {
		return err
	}
	state.AIEncryptedPrivateKey = encryptedPrivateKey
	state.AIEncryptionPublicKey = publicKey
	state.AIKeyVersion = aiClientKeyVersion
	return saveJSON(a.statePath, state)
}

func (a *clientApp) clientAIPrivateKey(state ClientState) (string, error) {
	if state.AIEncryptedPrivateKey == "" || !validX25519PublicKey(state.AIEncryptionPublicKey) {
		return "", errors.New("客户端AI加密身份未就绪")
	}
	privateKey, err := dpapiUnprotectString(state.AIEncryptedPrivateKey)
	if err != nil || !validX25519KeyPair(privateKey, state.AIEncryptionPublicKey) {
		return "", errors.New("客户端AI加密私钥无法解密")
	}
	return privateKey, nil
}

func (a *clientApp) syncServerAIKey(publicKey string) error {
	if !validX25519PublicKey(publicKey) {
		return errors.New("服务端AI加密公钥无效")
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil || state.Pairing == nil {
		return err
	}
	if state.Pairing.AIEncryptionPublicKey != "" && state.Pairing.AIEncryptionPublicKey != publicKey {
		return errors.New("服务端AI加密公钥发生未授权变化")
	}
	state.Pairing.AIEncryptionPublicKey = publicKey
	return saveJSON(a.statePath, state)
}

func (a *clientApp) aiContext() map[string]any {
	a.stateMu.Lock()
	state, _ := a.load()
	a.stateMu.Unlock()
	network := networkStatus(state)
	control := a.controlSnapshot()
	peers := control.Peers
	peerContext := make([]map[string]any, 0, len(peers))
	for _, peer := range peers {
		peerContext = append(peerContext, map[string]any{"name": peer.Name, "address": peer.Address})
	}
	mappings, _ := a.localMappingViews(state)
	mappingContext := make([]map[string]any, 0, len(mappings))
	for _, mapping := range mappings {
		mappingContext = append(mappingContext, map[string]any{"id": mapping.ID, "name": mapping.ServiceName, "localHost": mapping.LocalHost, "localPort": mapping.LocalPort, "meshPort": mapping.MeshPort, "protocol": mapping.Protocol, "dnsPrefix": mapping.DNSPrefix, "portlessHttp": mapping.PortlessHTTP, "paused": mapping.Paused, "active": mapping.Active, "healthy": mapping.Healthy, "lastError": mapping.LastError})
	}
	return map[string]any{
		"device":  map[string]any{"name": state.Name, "version": clientVersion, "ipMode": normalizeIPMode(state.IPMode), "forceP2P": state.ForceP2P, "p2pInterface": state.PreferredP2PInterface, "businessInterface": state.PreferredBusinessInterface},
		"network": map[string]any{"serviceRunning": network.AppliedVersion > 0, "directPeers": network.DirectCount, "relayPeers": network.RelayCount, "routeGuard": network.RouteGuard, "lastError": network.LastError},
		"peers":   peerContext, "mappings": mappingContext, "accessMessages": control.Messages, "accessPolicies": control.Policies, "automation": a.dualStackStatus(), "proxyCompatibility": a.proxyCompatibilityStatus(), "https": a.meshHTTPSRootStatus(),
	}
}

func (a *clientApp) requestAIPlan(prompt string) (AIPlan, error) {
	return a.requestAIPlanWithConversation(prompt, nil, nil, nil)
}

func partialAIReply(content string) string {
	key := strings.Index(content, `"reply"`)
	if key < 0 {
		return ""
	}
	remaining := content[key+len(`"reply"`):]
	colon := strings.Index(remaining, ":")
	if colon < 0 {
		return ""
	}
	remaining = strings.TrimLeft(remaining[colon+1:], " \t\r\n")
	if !strings.HasPrefix(remaining, `"`) {
		return ""
	}
	raw := remaining[1:]
	end, escaped := len(raw), false
	for index := 0; index < len(raw); index++ {
		if escaped {
			escaped = false
			continue
		}
		if raw[index] == '\\' {
			escaped = true
			continue
		}
		if raw[index] == '"' {
			end = index
			break
		}
	}
	raw = raw[:end]
	for trim := 0; trim <= 6 && trim <= len(raw); trim++ {
		candidate := `"` + raw[:len(raw)-trim] + `"`
		var decoded string
		if json.Unmarshal([]byte(candidate), &decoded) == nil {
			return decoded
		}
	}
	return ""
}

func (a *clientApp) requestAIPlanWithConversation(prompt string, conversation []AIConversationTurn, progress func(AIWorklogStep), onReplyDelta func(string)) (AIPlan, error) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" || len([]rune(prompt)) > 4000 {
		return AIPlan{}, errors.New("AI请求不能为空且最多4000个字符")
	}
	if aiSensitivePattern.MatchString(prompt) {
		return AIPlan{}, errors.New("请求中疑似包含密钥、私钥或配对哈希，已阻止发送")
	}
	safeConversation := make([]AIConversationTurn, 0, len(conversation))
	for _, turn := range conversation {
		if (turn.Role == "user" || turn.Role == "assistant") && !aiSensitivePattern.MatchString(turn.Content) {
			safeConversation = append(safeConversation, turn)
		}
	}
	if progress != nil {
		progress(AIWorklogStep{Title: "采集实时状态", Detail: "正在读取节点、链路、映射、权限、证书和更新状态。", Status: "running"})
	}
	if err := a.ensureClientAIIdentity(); err != nil {
		return AIPlan{}, err
	}
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || state.Pairing == nil || !validX25519PublicKey(state.Pairing.AIEncryptionPublicKey) {
		return AIPlan{}, errors.New("尚未从主服务端同步AI端到端加密公钥")
	}
	privateKey, err := a.clientAIPrivateKey(state)
	if err != nil {
		return AIPlan{}, err
	}
	jobID, _ := randomToken(12)
	realtimeContext := a.aiContext()
	if progress != nil {
		progress(AIWorklogStep{Title: "采集实时状态", Detail: "节点、链路、映射、权限、证书和更新状态已读取。", Status: "done"})
	}
	plain := aiPlainRequest{Prompt: prompt, Context: realtimeContext, Conversation: safeConversation, ClientVersion: clientVersion}
	plainBytes, _ := json.Marshal(plain)
	if progress != nil {
		progress(AIWorklogStep{Title: "安全检查与加密", Detail: "敏感信息扫描通过，正在使用 X25519 + AES-256-GCM 加密本轮上下文。", Status: "done"})
	}
	envelope, err := sealAIEnvelope(state.Pairing.AIEncryptionPublicKey, plainBytes, []byte("ai-request|"+state.Name+"|"+jobID))
	if err != nil {
		return AIPlan{}, err
	}
	var response aiPlanEnvelopeResponse
	if progress != nil {
		progress(AIWorklogStep{Title: "联网分析", Detail: "服务端正在检索公开资料并调用模型生成可执行计划。", Status: "running"})
	}
	sequence, emittedReply := 0, ""
	var providerContent strings.Builder
	if err := deviceControlStreamRequest(state, "/v1/ai/stream", aiPlanEnvelopeRequest{JobID: jobID, Envelope: envelope}, 330*time.Second, func(event string, payload []byte) error {
		switch event {
		case "delta":
			var streamed aiPlanStreamEnvelope
			if json.Unmarshal(payload, &streamed) != nil || streamed.Sequence != sequence+1 {
				return errors.New("AI流式响应顺序无效")
			}
			sequence = streamed.Sequence
			delta, openErr := openAIEnvelope(privateKey, streamed.Envelope, []byte(fmt.Sprintf("ai-stream|%s|%s|%d", state.Name, jobID, sequence)))
			if openErr != nil {
				return openErr
			}
			providerContent.Write(delta)
			reply := partialAIReply(providerContent.String())
			if onReplyDelta != nil && len(reply) > len(emittedReply) && strings.HasPrefix(reply, emittedReply) {
				onReplyDelta(reply[len(emittedReply):])
				emittedReply = reply
			}
		case "plan":
			if json.Unmarshal(payload, &response) != nil || response.JobID != jobID {
				return errors.New("AI最终计划响应无效")
			}
		case "error":
			var message map[string]string
			_ = json.Unmarshal(payload, &message)
			return errors.New(message["error"])
		}
		return nil
	}); err != nil {
		return AIPlan{}, err
	}
	planBytes, err := openAIEnvelope(privateKey, response.Envelope, []byte("ai-response|"+state.Name+"|"+jobID))
	if err != nil {
		return AIPlan{}, err
	}
	var plan AIPlan
	if json.Unmarshal(planBytes, &plan) != nil || plan.ID == "" || time.Now().After(plan.ExpiresAt) {
		return AIPlan{}, errors.New("服务端AI计划无效或已过期")
	}
	if err := validateAIPlan(&plan); err != nil {
		return AIPlan{}, err
	}
	a.aiMu.Lock()
	if a.aiPlans == nil {
		a.aiPlans = map[string]AIPlan{}
	}
	a.aiPlans[plan.ID] = plan
	a.aiMu.Unlock()
	return plan, nil
}

func aiArgString(arguments map[string]any, name string) string {
	value, _ := arguments[name].(string)
	return strings.TrimSpace(value)
}

func aiArgInt(arguments map[string]any, name string) int {
	switch value := arguments[name].(type) {
	case float64:
		return int(value)
	case int:
		return value
	}
	return 0
}

func aiArgBool(arguments map[string]any, name string) bool {
	value, _ := arguments[name].(bool)
	return value
}

func (a *clientApp) executeAIAction(action AIAction) (string, error) {
	switch action.Tool {
	case "create_service_mapping":
		view, err := a.addServiceMapping(aiArgString(action.Arguments, "serviceName"), aiArgString(action.Arguments, "dnsPrefix"), aiArgString(action.Arguments, "localHost"), aiArgInt(action.Arguments, "localPort"), aiArgInt(action.Arguments, "meshPort"), aiArgString(action.Arguments, "protocol"), aiArgBool(action.Arguments, "approvalRequired"), aiArgBool(action.Arguments, "portlessHttp"))
		return fmt.Sprintf("映射已创建: %s:%d", view.MeshAddress, view.MeshPort), err
	case "delete_service_mapping":
		return "映射已删除", a.deleteServiceMapping(aiArgString(action.Arguments, "id"))
	case "pause_service_mapping":
		paused := aiArgBool(action.Arguments, "paused")
		return map[bool]string{true: "映射已暂停", false: "映射已启动"}[paused], a.setServiceMappingPaused(aiArgString(action.Arguments, "id"), paused)
	case "update_mapping_dns":
		view, err := a.updateServiceMappingDNS(aiArgString(action.Arguments, "id"), aiArgString(action.Arguments, "dnsPrefix"), aiArgBool(action.Arguments, "portlessHttp"))
		return "映射域名已更新: " + view.DNSName, err
	case "request_access", "respond_access", "set_user_access":
		a.stateMu.Lock()
		state, err := a.load()
		a.stateMu.Unlock()
		if err != nil {
			return "", err
		}
		var path string
		var input any
		switch action.Tool {
		case "request_access":
			path = "/v1/access/request"
			input = map[string]any{"ownerName": aiArgString(action.Arguments, "ownerName"), "mappingId": aiArgString(action.Arguments, "mappingId")}
		case "respond_access":
			path = "/v1/access/respond"
			input = map[string]any{"requestId": aiArgString(action.Arguments, "requestId"), "approve": aiArgBool(action.Arguments, "approve")}
		case "set_user_access":
			path = "/v1/access/user"
			input = map[string]any{"mappingId": aiArgString(action.Arguments, "mappingId"), "userName": aiArgString(action.Arguments, "userName"), "paused": aiArgBool(action.Arguments, "paused")}
		}
		var output map[string]any
		err = deviceControlRequest(state, "POST", path, input, &output)
		if err == nil {
			_ = a.refreshControl()
		}
		return "访问权限操作已提交", err
	case "set_ip_mode":
		if err := a.setIPMode(aiArgString(action.Arguments, "mode")); err != nil {
			return "", err
		}
		return "IP模式已应用", a.applyNATOptimization()
	case "set_force_p2p":
		if err := a.setForceP2P(aiArgBool(action.Arguments, "enabled")); err != nil {
			return "", err
		}
		return "P2P策略已应用", a.applyNATOptimization()
	case "set_proxy_compatibility":
		status, err := a.setProxyCompatibility(aiArgBool(action.Arguments, "enabled"))
		return fmt.Sprintf("代理兼容 applied=%v", status.Applied), err
	case "set_interface_routing":
		if err := a.setInterfacePreferences(aiArgString(action.Arguments, "p2p"), aiArgString(action.Arguments, "business")); err != nil {
			return "", err
		}
		return "流量分流已应用", a.applyNATOptimization()
	case "set_network_automation":
		status, err := a.setNetworkAutomation(aiArgBool(action.Arguments, "enabled"), aiArgBool(action.Arguments, "scenes"))
		return "自动网络状态: " + status.State, err
	case "rename_network_scene":
		_, err := a.renameNetworkScene(aiArgString(action.Arguments, "id"), aiArgString(action.Arguments, "name"))
		return "网络场景已重命名", err
	case "delete_network_scene":
		_, err := a.deleteNetworkScene(aiArgString(action.Arguments, "id"))
		return "网络场景已删除", err
	case "sync_lighthouses":
		a.sendHeartbeat()
		return "Lighthouse列表已同步", nil
	case "apply_network_component":
		return "网络组件已应用", a.applyNATOptimization()
	case "start_nebula":
		state, _, err := a.ensureOptimizedClientConfig()
		if err == nil {
			err = a.installServiceIfMissing(state)
		}
		if err == nil {
			err = runElevated("C:\\Windows\\System32\\sc.exe", []string{"start", "Nebula"})
		}
		return "Nebula已启动", err
	case "stop_nebula":
		return "Nebula已停止", runElevated("C:\\Windows\\System32\\sc.exe", []string{"stop", "Nebula"})
	case "run_p2p_diagnostic":
		report := a.runNATDiagnostic()
		return report.Verdict, nil
	case "install_https_root":
		_, err := a.retryMeshHTTPSRootTrust()
		return "HTTPS根证书已安装", err
	case "uninstall_https_root":
		return "已打开Windows证书删除确认", a.beginMeshHTTPSRootRemoval()
	case "repair_identity":
		status, err := a.repairIdentity()
		return fmt.Sprintf("身份修复完成=%v，指纹=%s", status.Valid, status.Fingerprint), err
	case "check_update":
		status, err := a.checkForUpdate()
		return fmt.Sprintf("当前%s，可更新=%v", status.CurrentVersion, status.Available), err
	case "install_update":
		status, err := a.applyAvailableUpdate()
		return fmt.Sprintf("正在安装%s", status.Manifest.Version), err
	case "rollback_update":
		return "正在回滚", a.applyRollback()
	case "set_mesh_dns":
		return "MeshDNS设置已应用", a.setMeshDNSEnabled(aiArgBool(action.Arguments, "enabled"))
	case "set_dns_prefix":
		status, err := a.setOwnMeshDNSPrefix(aiArgString(action.Arguments, "prefix"))
		return "DNS名称: " + status.OwnDNSName, err
	case "delete_file_share":
		return "文件分享已撤销", a.deleteFileShare(aiArgString(action.Arguments, "id"))
	default:
		return "", errors.New("AI工具不受支持")
	}
}

func (a *clientApp) executeAIPlan(planID string) (AIExecutionResult, error) {
	a.aiMu.Lock()
	plan, exists := a.aiPlans[planID]
	if exists {
		delete(a.aiPlans, planID)
	}
	a.aiMu.Unlock()
	if !exists || time.Now().After(plan.ExpiresAt) {
		return AIExecutionResult{}, errors.New("AI计划不存在、已执行或已过期")
	}
	result := AIExecutionResult{PlanID: planID, CompletedAt: time.Now().UTC(), Verified: true}
	skipFollowUp := false
	for _, action := range plan.Actions {
		message, err := a.executeAIAction(action)
		item := AIActionResult{ActionID: action.ID, Tool: action.Tool, Success: err == nil, Message: message}
		if err != nil {
			item.Message = err.Error()
			result.Verified = false
		}
		result.Results = append(result.Results, item)
		if action.Tool == "install_update" && err == nil {
			skipFollowUp = true
			break
		}
	}
	result.CompletedAt = time.Now().UTC()
	if len(result.Results) > 0 && !skipFollowUp {
		resultBytes, _ := json.Marshal(result.Results)
		followUp, followErr := a.requestAIPlan("复核刚刚执行的MeshLAN操作结果。检查新状态是否达到目标；若未解决，生成新的操作计划；若已解决，不要生成动作。执行结果：" + string(resultBytes))
		if followErr == nil {
			result.FollowUp = &followUp
			if len(followUp.Actions) == 0 && !followUp.Unresolved {
				result.Verified = true
			}
		}
	}
	return result, nil
}

func (a *clientApp) submitAIBugReport(planID, prompt string) (string, error) {
	if aiSensitivePattern.MatchString(prompt) {
		return "", errors.New("Bug描述中疑似包含密钥或配对哈希")
	}
	a.aiMu.Lock()
	plan, exists := a.aiPlans[planID]
	a.aiMu.Unlock()
	if !exists {
		return "", errors.New("没有可上报的AI计划")
	}
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil || state.Pairing == nil || !validX25519PublicKey(state.Pairing.AIEncryptionPublicKey) {
		return "", errors.New("AI端到端加密尚未就绪")
	}
	reportID, _ := randomToken(12)
	plain := aiBugPlain{Prompt: strings.TrimSpace(prompt), Plan: plan, Context: a.aiContext(), ClientVersion: clientVersion, CreatedAt: time.Now().UTC()}
	plainBytes, _ := json.Marshal(plain)
	envelope, err := sealAIEnvelope(state.Pairing.AIEncryptionPublicKey, plainBytes, []byte("ai-bug|"+state.Name+"|"+reportID))
	if err != nil {
		return "", err
	}
	var response map[string]any
	if err := deviceControlRequest(state, "POST", "/v1/ai/bugs", aiBugEnvelopeRequest{ReportID: reportID, Severity: "normal", Envelope: envelope}, &response); err != nil {
		return "", err
	}
	return reportID, nil
}
