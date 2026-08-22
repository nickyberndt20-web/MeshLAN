package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type atlasChatStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

func beginAtlasChatStream(ctx context.Context, client *http.Client, endpoint, apiKey string, request atlasChatRequest) (*http.Response, []byte, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+apiKey)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "text/event-stream")
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, nil, err
	}
	if response.StatusCode == http.StatusOK {
		return response, nil, nil
	}
	defer response.Body.Close()
	errorBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return nil, errorBody, fmt.Errorf("AI提供商 HTTP %d", response.StatusCode)
}

func callAIProviderStream(settings AIProviderSettings, apiKey string, request aiPlainRequest, onDelta func(string) error) (AIPlan, error) {
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
	messages := []map[string]any{{"role": "system", "content": aiSystemPrompt(request.Language)}}
	for _, turn := range request.Conversation {
		if (turn.Role == "user" || turn.Role == "assistant") && strings.TrimSpace(turn.Content) != "" {
			messages = append(messages, map[string]any{"role": turn.Role, "content": turn.Content})
		}
	}
	messages = append(messages, map[string]any{"role": "user", "content": "当前用户请求：\n" + request.Prompt + "\n\nMeshLAN实时上下文：\n" + string(contextJSON)})
	client := &http.Client{Timeout: time.Duration(settings.TimeoutSeconds) * time.Second}
	endpoint := baseURL + "/chat/completions"
	providerRequest := atlasProviderRequest(settings, messages, true)
	providerRequest.Stream = true
	response, errorBody, streamErr := beginAtlasChatStream(ctx, client, endpoint, apiKey, providerRequest)
	if streamErr != nil && strings.Contains(streamErr.Error(), "HTTP 400") {
		providerRequest = atlasProviderRequest(settings, messages, false)
		providerRequest.Stream = true
		response, errorBody, streamErr = beginAtlasChatStream(ctx, client, endpoint, apiKey, providerRequest)
	}
	if streamErr != nil {
		return AIPlan{}, fmt.Errorf("%w: %s", streamErr, strings.TrimSpace(string(errorBody)))
	}
	defer response.Body.Close()
	var complete strings.Builder
	if !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		if readErr != nil {
			return AIPlan{}, readErr
		}
		var providerResponse atlasChatResponse
		if json.Unmarshal(responseBody, &providerResponse) != nil || len(providerResponse.Choices) == 0 {
			return AIPlan{}, errors.New("AI提供商未返回可识别的流式内容")
		}
		content := providerResponse.Choices[0].Message.Content
		if err := onDelta(content); err != nil {
			return AIPlan{}, err
		}
		complete.WriteString(content)
		return parseAIPlanContent(complete.String(), webSearched)
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var chunk atlasChatStreamChunk
		if json.Unmarshal([]byte(data), &chunk) != nil || len(chunk.Choices) == 0 || chunk.Choices[0].Delta.Content == "" {
			continue
		}
		delta := chunk.Choices[0].Delta.Content
		complete.WriteString(delta)
		if err := onDelta(delta); err != nil {
			return AIPlan{}, err
		}
	}
	if err := scanner.Err(); err != nil {
		return AIPlan{}, err
	}
	if complete.Len() == 0 {
		return AIPlan{}, errors.New("AI提供商流式响应为空")
	}
	return parseAIPlanContent(complete.String(), webSearched)
}

func writeServerAIEvent(w http.ResponseWriter, flusher http.Flusher, event string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func registerAIStreamRoute(mux *http.ServeMux, state *ServerState, stateMu *sync.Mutex, history *historyStore, limiter *aiDeviceLimiter) {
	mux.HandleFunc("POST /v1/ai/stream", func(w http.ResponseWriter, r *http.Request) {
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
		plaintext, err := openAIEnvelope(serverPrivate, encrypted.Envelope, []byte("ai-request|"+peerName+"|"+encrypted.JobID))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var plainRequest aiPlainRequest
		if json.Unmarshal(plaintext, &plainRequest) != nil || len([]rune(plainRequest.Prompt)) < 1 || len([]rune(plainRequest.Prompt)) > 4000 || len(plainRequest.Conversation) > 32 {
			http.Error(w, "AI请求正文无效", http.StatusBadRequest)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		sequence := 0
		plan, err := callAIProviderStream(settings, apiKey, plainRequest, func(delta string) error {
			sequence++
			envelope, sealErr := sealAIEnvelope(peerPublic, []byte(delta), []byte(fmt.Sprintf("ai-stream|%s|%s|%d", peerName, encrypted.JobID, sequence)))
			if sealErr != nil {
				return sealErr
			}
			return writeServerAIEvent(w, flusher, "delta", aiPlanStreamEnvelope{Sequence: sequence, Envelope: envelope})
		})
		if err != nil {
			_ = writeServerAIEvent(w, flusher, "error", map[string]string{"error": err.Error()})
			return
		}
		if err := validateAIPlan(&plan); err != nil {
			_ = writeServerAIEvent(w, flusher, "error", map[string]string{"error": err.Error()})
			return
		}
		planBytes, _ := json.Marshal(plan)
		responseEnvelope, err := sealAIEnvelope(peerPublic, planBytes, []byte("ai-response|"+peerName+"|"+encrypted.JobID))
		if err != nil {
			_ = writeServerAIEvent(w, flusher, "error", map[string]string{"error": err.Error()})
			return
		}
		_ = history.RecordEvent("server", "ai_stream", peerName, fmt.Sprintf("AI流式生成计划: %d个动作，%d个加密片段", len(plan.Actions), sequence), time.Now().UTC())
		_ = writeServerAIEvent(w, flusher, "plan", aiPlanEnvelopeResponse{JobID: encrypted.JobID, Envelope: responseEnvelope})
		_ = writeServerAIEvent(w, flusher, "done", map[string]any{"ok": true, "chunks": sequence})
	})
}
