//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func writeAIStreamEvent(w http.ResponseWriter, flusher http.Flusher, event string, value any) error {
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

func (a *clientApp) registerAIConversationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ai/conversations", func(w http.ResponseWriter, _ *http.Request) {
		conversations, err := a.history.ListAIConversations()
		if err != nil {
			jsonReply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, http.StatusOK, map[string]any{"conversations": conversations})
	})
	mux.HandleFunc("POST /api/ai/conversations", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Title string `json:"title"`
		}
		if decodeRequest(r, &input) != nil {
			jsonReply(w, http.StatusBadRequest, map[string]string{"error": "会话参数无效"})
			return
		}
		conversation, err := a.history.CreateAIConversation(input.Title)
		if err != nil {
			jsonReply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, http.StatusCreated, conversation)
	})
	mux.HandleFunc("GET /api/ai/conversations/{id}", func(w http.ResponseWriter, r *http.Request) {
		conversation, err := a.history.AIConversation(r.PathValue("id"))
		if err != nil {
			jsonReply(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, http.StatusOK, conversation)
	})
	mux.HandleFunc("PATCH /api/ai/conversations/{id}", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Title string `json:"title"`
		}
		if decodeRequest(r, &input) != nil || strings.TrimSpace(input.Title) == "" {
			jsonReply(w, http.StatusBadRequest, map[string]string{"error": "请输入会话名称"})
			return
		}
		if err := a.history.RenameAIConversation(r.PathValue("id"), input.Title); err != nil {
			jsonReply(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /api/ai/conversations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.history.DeleteAIConversation(r.PathValue("id")); err != nil {
			jsonReply(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/ai/chat", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ConversationID string `json:"conversationId"`
			Prompt         string `json:"prompt"`
		}
		if decodeRequest(r, &input) != nil || strings.TrimSpace(input.Prompt) == "" {
			jsonReply(w, http.StatusBadRequest, map[string]string{"error": "消息不能为空"})
			return
		}
		conversation, err := a.history.AIConversation(input.ConversationID)
		if err != nil {
			jsonReply(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			jsonReply(w, http.StatusInternalServerError, map[string]string{"error": "当前窗口不支持流式响应"})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		_ = writeAIStreamEvent(w, flusher, "progress", AIWorklogStep{Title: "保存本地上下文", Detail: "用户消息已写入当前设备的本地历史库。", Status: "done"})
		if conversation.Title == "新对话" {
			_ = a.history.RenameAIConversation(conversation.ID, input.Prompt)
		}
		if _, err = a.history.AddAIMessage(conversation.ID, "user", input.Prompt, nil); err != nil {
			_ = writeAIStreamEvent(w, flusher, "error", map[string]string{"error": err.Error()})
			return
		}
		progress := make(chan AIWorklogStep, 16)
		deltas := make(chan string, 64)
		type planResult struct {
			plan AIPlan
			err  error
		}
		result := make(chan planResult, 1)
		turns := aiConversationTurns(conversation)
		go func() {
			plan, planErr := a.requestAIPlanWithConversation(input.Prompt, turns, func(step AIWorklogStep) {
				select {
				case progress <- step:
				default:
				}
			}, func(delta string) {
				select {
				case deltas <- delta:
				case <-r.Context().Done():
				}
			})
			result <- planResult{plan: plan, err: planErr}
		}()
		started := time.Now()
		ticker := time.NewTicker(7 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case step := <-progress:
				if writeAIStreamEvent(w, flusher, "progress", step) != nil {
					return
				}
			case delta := <-deltas:
				if writeAIStreamEvent(w, flusher, "delta", map[string]string{"content": delta}) != nil {
					return
				}
			case <-ticker.C:
				step := AIWorklogStep{Title: "模型正在处理", Detail: fmt.Sprintf("已等待 %d 秒，连接保持正常。", int(time.Since(started).Seconds())), Status: "running"}
				if writeAIStreamEvent(w, flusher, "progress", step) != nil {
					return
				}
			case output := <-result:
				if output.err != nil {
					_, _ = a.history.AddAIMessage(conversation.ID, "error", "AI请求失败："+output.err.Error(), nil)
					_ = writeAIStreamEvent(w, flusher, "error", map[string]string{"error": output.err.Error()})
					return
				}
				for _, step := range output.plan.Worklog {
					if writeAIStreamEvent(w, flusher, "progress", step) != nil {
						return
					}
				}
				message, saveErr := a.history.AddAIMessage(conversation.ID, "assistant", output.plan.Reply, &output.plan)
				if saveErr != nil {
					_ = writeAIStreamEvent(w, flusher, "error", map[string]string{"error": saveErr.Error()})
					return
				}
				_ = writeAIStreamEvent(w, flusher, "message", message)
				_ = writeAIStreamEvent(w, flusher, "done", map[string]any{"ok": true, "conversationId": conversation.ID})
				return
			}
		}
	})
}
