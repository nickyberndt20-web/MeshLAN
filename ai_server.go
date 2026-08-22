package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type aiPlainRequest struct {
	Prompt        string               `json:"prompt"`
	Context       map[string]any       `json:"context"`
	Conversation  []AIConversationTurn `json:"conversation,omitempty"`
	ClientVersion string               `json:"clientVersion"`
}

type aiPlanEnvelopeRequest struct {
	JobID    string              `json:"jobId"`
	Envelope AIEncryptedEnvelope `json:"envelope"`
}

type aiPlanEnvelopeResponse struct {
	JobID    string              `json:"jobId"`
	Envelope AIEncryptedEnvelope `json:"envelope"`
}

type aiPlanStreamEnvelope struct {
	Sequence int                 `json:"sequence"`
	Envelope AIEncryptedEnvelope `json:"envelope"`
}

type aiBugEnvelopeRequest struct {
	ReportID string              `json:"reportId"`
	Severity string              `json:"severity"`
	Envelope AIEncryptedEnvelope `json:"envelope"`
}

type aiBugPlain struct {
	Prompt        string         `json:"prompt"`
	Plan          AIPlan         `json:"plan"`
	Context       map[string]any `json:"context"`
	ClientVersion string         `json:"clientVersion"`
	CreatedAt     time.Time      `json:"createdAt"`
}

type atlasChatRequest struct {
	Model          string           `json:"model"`
	Messages       []map[string]any `json:"messages"`
	Temperature    *float64         `json:"temperature,omitempty"`
	MaxTokens      int              `json:"max_tokens,omitempty"`
	ResponseFormat map[string]any   `json:"response_format,omitempty"`
	Stream         bool             `json:"stream,omitempty"`
}

type aiWebSearchResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}

type bingRSS struct {
	Channel struct {
		Items []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Description string `xml:"description"`
		} `xml:"item"`
	} `xml:"channel"`
}

var aiSearchHTMLPattern = regexp.MustCompile(`<[^>]+>`)
var aiSearchSecretPattern = regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk|apikey)-[a-z0-9_-]{12,}|\bMLN(?:ODE)?1\S+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}:[0-9a-f:]{2,}\b)`)

type atlasChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage map[string]any `json:"usage,omitempty"`
}

func applyAIProviderDefaults(settings *AIProviderSettings) bool {
	changed := false
	if settings.Version < 1 {
		settings.Version = 1
		settings.WebSearch = true
		changed = true
	}
	if settings.Version < 2 {
		settings.Version = 2
		settings.MaxTokens = 0
		changed = true
	}
	if settings.BaseURL == "" {
		settings.BaseURL = "https://api.atlascloud.ai/v1"
		changed = true
	}
	if settings.Model == "" {
		settings.Model = "xai/grok-4.6"
		changed = true
	}
	if settings.MaxTokens < 0 {
		settings.MaxTokens = 0
		changed = true
	}
	if settings.TimeoutSeconds < 15 || settings.TimeoutSeconds > 300 {
		settings.TimeoutSeconds = 120
		changed = true
	}
	return changed
}

func normalizeAIBaseURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "https://api.atlascloud.ai/v1"
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" || parsed.User != nil {
		return "", errors.New("AI服务地址必须是有效的HTTPS URL")
	}
	return strings.TrimRight(value, "/"), nil
}

func aiSystemPrompt() string {
	return `你是MeshLAN服务端自动化Agent。只根据给定的实时上下文制定计划，不得编造状态。输出严格JSON对象：
{"reply":"面向用户的最终回答","summary":"操作摘要","worklog":[{"title":"检查项","detail":"基于证据的简洁过程说明","status":"done"}],"unresolved":false,"actions":[{"id":"a1","tool":"工具名","arguments":{},"reason":"原因","risk":"low|medium|high","reversible":true}]}
允许的工具：create_service_mapping,delete_service_mapping,pause_service_mapping,update_mapping_dns,request_access,respond_access,set_user_access,set_ip_mode,set_force_p2p,set_proxy_compatibility,set_interface_routing,set_network_automation,rename_network_scene,delete_network_scene,sync_lighthouses,apply_network_component,start_nebula,stop_nebula,run_p2p_diagnostic,install_https_root,uninstall_https_root,repair_identity,check_update,install_update,rollback_update,set_mesh_dns,set_dns_prefix,delete_file_share。
所有修改都必须放入actions等待用户确认；不要输出Shell命令，不要请求或泄露密钥。证据不足时将unresolved设为true，不要猜测。若上下文包含联网检索结果，只能引用确实提供的来源并使用[S1]、[S2]格式标注。`
}

func safeAIWebSearchQuery(prompt string) string {
	prompt = aiSearchSecretPattern.ReplaceAllString(prompt, " ")
	prompt = strings.Join(strings.Fields(prompt), " ")
	runes := []rune(prompt)
	if len(runes) > 320 {
		prompt = string(runes[:320])
	}
	return strings.TrimSpace("MeshLAN Nebula " + prompt)
}

func parseAIWebSearchRSS(body []byte) ([]aiWebSearchResult, error) {
	var feed bingRSS
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, err
	}
	results := make([]aiWebSearchResult, 0, 5)
	for _, item := range feed.Channel.Items {
		link := strings.TrimSpace(item.Link)
		parsed, err := url.Parse(link)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			continue
		}
		snippet := html.UnescapeString(aiSearchHTMLPattern.ReplaceAllString(item.Description, " "))
		results = append(results, aiWebSearchResult{
			Title: strings.TrimSpace(html.UnescapeString(item.Title)),
			URL:   link, Snippet: strings.Join(strings.Fields(snippet), " "),
		})
		if len(results) == 5 {
			break
		}
	}
	return results, nil
}

func performAIWebSearch(ctx context.Context, prompt string) ([]aiWebSearchResult, error) {
	query := safeAIWebSearchQuery(prompt)
	if len(strings.TrimSpace(query)) <= len("MeshLAN Nebula") {
		return nil, errors.New("没有可安全检索的关键词")
	}
	searchURL := "https://www.bing.com/search?format=rss&q=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MeshLAN-AI/1.0")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("搜索服务 HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	return parseAIWebSearchRSS(body)
}

func atlasProviderRequest(settings AIProviderSettings, messages []map[string]any, structured bool) atlasChatRequest {
	request := atlasChatRequest{Model: settings.Model, Messages: messages, MaxTokens: settings.MaxTokens}
	if structured {
		temperature := 0.1
		request.Temperature = &temperature
		request.ResponseFormat = map[string]any{"type": "json_object"}
	}
	return request
}

func parseAIPlanContent(content string, webSearched bool) (AIPlan, error) {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	if start, end := strings.Index(content, "{"), strings.LastIndex(content, "}"); start >= 0 && end > start {
		content = content[start : end+1]
	}
	var plan AIPlan
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &plan); err != nil {
		return AIPlan{}, errors.New("AI未返回有效的结构化操作计划")
	}
	plan.ID, _ = randomToken(12)
	plan.CreatedAt = time.Now().UTC()
	plan.ExpiresAt = plan.CreatedAt.Add(10 * time.Minute)
	plan.WebSearched = webSearched
	for index := range plan.Actions {
		if plan.Actions[index].ID == "" {
			plan.Actions[index].ID = fmt.Sprintf("a%d", index+1)
		}
	}
	return plan, nil
}

func sendAtlasChat(ctx context.Context, client *http.Client, endpoint, apiKey string, request atlasChatRequest) ([]byte, int, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, 0, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+apiKey)
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return responseBody, response.StatusCode, err
}

func callAIProvider(settings AIProviderSettings, apiKey string, request aiPlainRequest) (AIPlan, error) {
	applyAIProviderDefaults(&settings)
	if !settings.Enabled || strings.TrimSpace(apiKey) == "" {
		return AIPlan{}, errors.New("服务端AI尚未启用或测试密钥未配置")
	}
	baseURL, err := normalizeAIBaseURL(settings.BaseURL)
	if err != nil {
		return AIPlan{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(settings.TimeoutSeconds)*time.Second)
	defer cancel()
	contextCopy := make(map[string]any, len(request.Context)+1)
	for key, value := range request.Context {
		contextCopy[key] = value
	}
	webSearched := false
	if settings.WebSearch {
		searchCtx, searchCancel := context.WithTimeout(ctx, 10*time.Second)
		results, searchErr := performAIWebSearch(searchCtx, request.Prompt)
		searchCancel()
		if searchErr == nil && len(results) > 0 {
			contextCopy["webSearchResults"] = results
			webSearched = true
		}
	}
	contextJSON, _ := json.Marshal(contextCopy)
	messages := []map[string]any{{"role": "system", "content": aiSystemPrompt()}}
	for _, turn := range request.Conversation {
		if (turn.Role == "user" || turn.Role == "assistant") && strings.TrimSpace(turn.Content) != "" {
			messages = append(messages, map[string]any{"role": turn.Role, "content": turn.Content})
		}
	}
	messages = append(messages, map[string]any{"role": "user", "content": "当前用户请求：\n" + request.Prompt + "\n\nMeshLAN实时上下文：\n" + string(contextJSON)})
	client := &http.Client{Timeout: time.Duration(settings.TimeoutSeconds) * time.Second}
	endpoint := baseURL + "/chat/completions"
	responseBody, statusCode, err := sendAtlasChat(ctx, client, endpoint, apiKey, atlasProviderRequest(settings, messages, true))
	if err != nil {
		return AIPlan{}, err
	}
	if statusCode == http.StatusBadRequest {
		responseBody, statusCode, err = sendAtlasChat(ctx, client, endpoint, apiKey, atlasProviderRequest(settings, messages, false))
		if err != nil {
			return AIPlan{}, err
		}
	}
	if statusCode != http.StatusOK {
		return AIPlan{}, fmt.Errorf("AI提供商 HTTP %d: %s", statusCode, strings.TrimSpace(string(responseBody)))
	}
	var providerResponse atlasChatResponse
	if err := json.Unmarshal(responseBody, &providerResponse); err != nil || len(providerResponse.Choices) == 0 {
		var wrapped struct {
			Data atlasChatResponse `json:"data"`
		}
		if json.Unmarshal(responseBody, &wrapped) != nil || len(wrapped.Data.Choices) == 0 {
			return AIPlan{}, errors.New("AI提供商返回格式无法识别")
		}
		providerResponse = wrapped.Data
	}
	return parseAIPlanContent(providerResponse.Choices[0].Message.Content, webSearched)
}

type aiDeviceLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
}

func (l *aiDeviceLimiter) allow(device string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[string][]time.Time{}
	}
	cutoff := now.Add(-time.Minute)
	kept := l.entries[device][:0]
	for _, at := range l.entries[device] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) >= 10 {
		l.entries[device] = kept
		return false
	}
	l.entries[device] = append(kept, now)
	return true
}

var aiToolRisk = map[string]string{
	"create_service_mapping": "medium", "delete_service_mapping": "high", "pause_service_mapping": "medium",
	"update_mapping_dns": "medium", "request_access": "medium", "respond_access": "high", "set_user_access": "high",
	"set_ip_mode": "medium", "set_proxy_compatibility": "low", "set_interface_routing": "medium",
	"set_force_p2p": "medium", "rename_network_scene": "medium", "delete_network_scene": "high", "sync_lighthouses": "low",
	"set_network_automation": "medium", "apply_network_component": "high", "start_nebula": "medium", "stop_nebula": "high",
	"run_p2p_diagnostic": "low", "install_https_root": "medium", "uninstall_https_root": "high",
	"check_update": "low", "install_update": "high", "rollback_update": "high", "set_mesh_dns": "medium", "set_dns_prefix": "medium",
	"repair_identity": "high", "delete_file_share": "high",
}

func validateAIPlan(plan *AIPlan) error {
	if plan == nil || len(plan.Reply) > 16<<10 || len(plan.Summary) > 4<<10 || len(plan.Actions) > 12 {
		return errors.New("AI操作计划大小超限")
	}
	if len(plan.Worklog) > 24 {
		return errors.New("AI工作过程条目过多")
	}
	for _, step := range plan.Worklog {
		if len(step.Title) > 256 || len(step.Detail) > 2<<10 {
			return errors.New("AI工作过程大小超限")
		}
	}
	for index := range plan.Actions {
		action := &plan.Actions[index]
		risk, ok := aiToolRisk[action.Tool]
		if !ok {
			return fmt.Errorf("AI请求了未授权工具: %s", action.Tool)
		}
		action.Risk = risk
		arguments, _ := json.Marshal(action.Arguments)
		if len(arguments) > 16<<10 || len(action.Reason) > 2<<10 {
			return errors.New("AI工具参数大小超限")
		}
	}
	return nil
}

func registerAIRoutes(mux *http.ServeMux, state *ServerState, stateMu *sync.Mutex, statePath string, history *historyStore, adminAuthorized func(*http.Request) bool) {
	limiter := &aiDeviceLimiter{}
	registerAIStreamRoute(mux, state, stateMu, history, limiter)
	mux.HandleFunc("GET /v1/admin/ai/status", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		stateMu.Lock()
		settings := state.AIProvider
		applyAIProviderDefaults(&settings)
		response := map[string]any{"settings": settings, "keyConfigured": state.AIProviderAPIKey != "", "e2eeReady": validX25519KeyPair(state.AIEncryptionPrivateKey, state.AIEncryptionPublicKey), "bugReports": len(state.AIBugReports)}
		stateMu.Unlock()
		writeControlJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("POST /v1/admin/ai/config", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input struct {
			Enabled        bool   `json:"enabled"`
			BaseURL        string `json:"baseUrl"`
			Model          string `json:"model"`
			APIKey         string `json:"apiKey"`
			WebSearch      bool   `json:"webSearch"`
			MaxTokens      int    `json:"maxTokens"`
			TimeoutSeconds int    `json:"timeoutSeconds"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&input) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		baseURL, err := normalizeAIBaseURL(input.BaseURL)
		if err != nil || strings.TrimSpace(input.Model) == "" || len(input.Model) > 128 || len(input.APIKey) > 512 {
			http.Error(w, "AI配置无效", http.StatusBadRequest)
			return
		}
		settings := AIProviderSettings{Version: 2, Enabled: input.Enabled, BaseURL: baseURL, Model: strings.TrimSpace(input.Model), WebSearch: input.WebSearch, MaxTokens: input.MaxTokens, TimeoutSeconds: input.TimeoutSeconds, UpdatedAt: time.Now().UTC()}
		applyAIProviderDefaults(&settings)
		stateMu.Lock()
		state.AIProvider = settings
		if strings.TrimSpace(input.APIKey) != "" {
			state.AIProviderAPIKey = strings.TrimSpace(input.APIKey)
		}
		err = saveJSON(statePath, *state)
		keyConfigured := state.AIProviderAPIKey != ""
		stateMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "keyConfigured": keyConfigured})
	})
	mux.HandleFunc("POST /v1/admin/ai/test", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		stateMu.Lock()
		settings, apiKey := state.AIProvider, state.AIProviderAPIKey
		stateMu.Unlock()
		plan, err := callAIProvider(settings, apiKey, aiPlainRequest{Prompt: "只返回一句MeshLAN AI服务连接正常，不执行任何操作。", Context: map[string]any{"test": true}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeControlJSON(w, http.StatusOK, map[string]any{"ok": true, "reply": plan.Reply})
	})
	mux.HandleFunc("GET /v1/ai/status", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		peer := authorizedDevicePeer(state, r)
		if peer == nil {
			stateMu.Unlock()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		settings := state.AIProvider
		response := map[string]any{"enabled": settings.Enabled && state.AIProviderAPIKey != "", "model": settings.Model, "webSearch": settings.WebSearch, "e2ee": state.AIEncryptionPublicKey != "" && peer.AIEncryptionPublicKey != ""}
		stateMu.Unlock()
		writeControlJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("POST /v1/ai/plan", func(w http.ResponseWriter, r *http.Request) {
		var encrypted aiPlanEnvelopeRequest
		if json.NewDecoder(io.LimitReader(r.Body, 512<<10)).Decode(&encrypted) != nil || len(encrypted.JobID) < 8 || len(encrypted.JobID) > 64 {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		stateMu.Lock()
		peer := authorizedDevicePeer(state, r)
		if peer == nil {
			stateMu.Unlock()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		peerName, peerPublic := peer.Name, peer.AIEncryptionPublicKey
		settings, apiKey, serverPrivate := state.AIProvider, state.AIProviderAPIKey, state.AIEncryptionPrivateKey
		stateMu.Unlock()
		if !limiter.allow(peerName, time.Now().UTC()) {
			http.Error(w, "AI请求过于频繁", http.StatusTooManyRequests)
			return
		}
		if !validX25519PublicKey(peerPublic) {
			http.Error(w, "客户端AI加密公钥尚未注册", http.StatusConflict)
			return
		}
		aad := []byte("ai-request|" + peerName + "|" + encrypted.JobID)
		plaintext, err := openAIEnvelope(serverPrivate, encrypted.Envelope, aad)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var plainRequest aiPlainRequest
		if json.Unmarshal(plaintext, &plainRequest) != nil || len([]rune(plainRequest.Prompt)) < 1 || len([]rune(plainRequest.Prompt)) > 4000 {
			http.Error(w, "AI请求正文无效", http.StatusBadRequest)
			return
		}
		conversationRunes := 0
		for _, turn := range plainRequest.Conversation {
			conversationRunes += len([]rune(turn.Content))
			if (turn.Role != "user" && turn.Role != "assistant") || len([]rune(turn.Content)) > 64000 {
				http.Error(w, "AI会话上下文无效", http.StatusBadRequest)
				return
			}
		}
		if len(plainRequest.Conversation) > 32 || conversationRunes > 100000 {
			http.Error(w, "AI会话上下文过大", http.StatusRequestEntityTooLarge)
			return
		}
		plan, err := callAIProvider(settings, apiKey, plainRequest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if err := validateAIPlan(&plan); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		planBytes, _ := json.Marshal(plan)
		responseEnvelope, err := sealAIEnvelope(peerPublic, planBytes, []byte("ai-response|"+peerName+"|"+encrypted.JobID))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = history.RecordEvent("server", "ai_plan", peerName, fmt.Sprintf("AI生成计划: %d个动作", len(plan.Actions)), time.Now().UTC())
		writeControlJSON(w, http.StatusOK, aiPlanEnvelopeResponse{JobID: encrypted.JobID, Envelope: responseEnvelope})
	})
	mux.HandleFunc("POST /v1/ai/bugs", func(w http.ResponseWriter, r *http.Request) {
		var input aiBugEnvelopeRequest
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&input) != nil || len(input.ReportID) < 8 || len(input.ReportID) > 64 {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		stateMu.Lock()
		peer := authorizedDevicePeer(state, r)
		if peer == nil {
			stateMu.Unlock()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		peerName, serverPrivate := peer.Name, state.AIEncryptionPrivateKey
		stateMu.Unlock()
		plaintext, err := openAIEnvelope(serverPrivate, input.Envelope, []byte("ai-bug|"+peerName+"|"+input.ReportID))
		if err != nil || len(plaintext) > 512<<10 {
			http.Error(w, "encrypted bug report invalid", http.StatusBadRequest)
			return
		}
		var report aiBugPlain
		if json.Unmarshal(plaintext, &report) != nil || report.ClientVersion == "" {
			http.Error(w, "bug report invalid", http.StatusBadRequest)
			return
		}
		severity := strings.ToLower(strings.TrimSpace(input.Severity))
		if severity != "high" && severity != "medium" {
			severity = "normal"
		}
		stateMu.Lock()
		state.AIBugReports = append(state.AIBugReports, AIBugReport{ID: input.ReportID, DeviceName: peerName, ClientVersion: report.ClientVersion, Status: "open", Severity: severity, CreatedAt: time.Now().UTC(), Envelope: input.Envelope})
		if len(state.AIBugReports) > 200 {
			state.AIBugReports = append([]AIBugReport(nil), state.AIBugReports[len(state.AIBugReports)-200:]...)
		}
		err = saveJSON(statePath, *state)
		stateMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = history.RecordEvent("server", "ai_bug_report", peerName, "客户端提交加密Bug工单 "+input.ReportID, time.Now().UTC())
		writeControlJSON(w, http.StatusCreated, map[string]any{"ok": true, "reportId": input.ReportID})
	})
	mux.HandleFunc("GET /v1/admin/ai/bugs", func(w http.ResponseWriter, r *http.Request) {
		if !adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		stateMu.Lock()
		reports := append([]AIBugReport(nil), state.AIBugReports...)
		privateKey := state.AIEncryptionPrivateKey
		stateMu.Unlock()
		items := make([]map[string]any, 0, len(reports))
		for _, report := range reports {
			plaintext, err := openAIEnvelope(privateKey, report.Envelope, []byte("ai-bug|"+report.DeviceName+"|"+report.ID))
			var detail aiBugPlain
			if err == nil {
				_ = json.Unmarshal(plaintext, &detail)
			}
			items = append(items, map[string]any{"id": report.ID, "deviceName": report.DeviceName, "clientVersion": report.ClientVersion, "status": report.Status, "severity": report.Severity, "createdAt": report.CreatedAt, "detail": detail})
		}
		writeControlJSON(w, http.StatusOK, map[string]any{"reports": items})
	})
}
