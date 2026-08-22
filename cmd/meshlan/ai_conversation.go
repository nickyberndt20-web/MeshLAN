package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type AIConversation struct {
	ID        string          `json:"id"`
	Title     string          `json:"title"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
	Messages  []AIChatMessage `json:"messages,omitempty"`
}

type AIChatMessage struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversationId"`
	Role           string    `json:"role"`
	Content        string    `json:"content"`
	Plan           *AIPlan   `json:"plan,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

type AIConversationTurn struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func normalizeAIConversationTitle(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" {
		return "新对话"
	}
	runes := []rune(value)
	if len(runes) > 42 {
		value = string(runes[:42]) + "…"
	}
	return value
}

func (s *historyStore) CreateAIConversation(title string) (AIConversation, error) {
	if s == nil {
		return AIConversation{}, errors.New("本地历史数据库不可用")
	}
	id, err := randomToken(12)
	if err != nil {
		return AIConversation{}, err
	}
	now := time.Now().UTC()
	conversation := AIConversation{ID: id, Title: normalizeAIConversationTitle(title), CreatedAt: now, UpdatedAt: now, Messages: []AIChatMessage{}}
	_, err = s.db.Exec(`INSERT INTO ai_conversations(id,title,created_ms,updated_ms) VALUES(?,?,?,?)`, conversation.ID, conversation.Title, unixMillis(now), unixMillis(now))
	return conversation, err
}

func (s *historyStore) ListAIConversations() ([]AIConversation, error) {
	if s == nil {
		return nil, errors.New("本地历史数据库不可用")
	}
	rows, err := s.db.Query(`SELECT c.id,c.title,c.created_ms,c.updated_ms FROM ai_conversations c ORDER BY c.updated_ms DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AIConversation{}
	for rows.Next() {
		var conversation AIConversation
		var created, updated int64
		if err := rows.Scan(&conversation.ID, &conversation.Title, &created, &updated); err != nil {
			return nil, err
		}
		conversation.CreatedAt, conversation.UpdatedAt = fromUnixMillis(created), fromUnixMillis(updated)
		result = append(result, conversation)
	}
	return result, rows.Err()
}

func (s *historyStore) AIConversation(id string) (AIConversation, error) {
	if s == nil || strings.TrimSpace(id) == "" {
		return AIConversation{}, errors.New("会话不存在")
	}
	var conversation AIConversation
	var created, updated int64
	if err := s.db.QueryRow(`SELECT id,title,created_ms,updated_ms FROM ai_conversations WHERE id=?`, id).Scan(&conversation.ID, &conversation.Title, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AIConversation{}, errors.New("会话不存在")
		}
		return AIConversation{}, err
	}
	conversation.CreatedAt, conversation.UpdatedAt = fromUnixMillis(created), fromUnixMillis(updated)
	conversation.Messages = []AIChatMessage{}
	rows, err := s.db.Query(`SELECT id,role,content,plan_json,created_ms FROM ai_messages WHERE conversation_id=? ORDER BY created_ms ASC,rowid ASC LIMIT 1000`, id)
	if err != nil {
		return AIConversation{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var message AIChatMessage
		var planJSON string
		var at int64
		if err := rows.Scan(&message.ID, &message.Role, &message.Content, &planJSON, &at); err != nil {
			return AIConversation{}, err
		}
		message.ConversationID, message.CreatedAt = id, fromUnixMillis(at)
		if planJSON != "" {
			var plan AIPlan
			if json.Unmarshal([]byte(planJSON), &plan) == nil {
				message.Plan = &plan
			}
		}
		conversation.Messages = append(conversation.Messages, message)
	}
	return conversation, rows.Err()
}

func (s *historyStore) RenameAIConversation(id, title string) error {
	title = normalizeAIConversationTitle(title)
	result, err := s.db.Exec(`UPDATE ai_conversations SET title=?,updated_ms=? WHERE id=?`, title, unixMillis(time.Now().UTC()), id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return errors.New("会话不存在")
	}
	return nil
}

func (s *historyStore) DeleteAIConversation(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM ai_messages WHERE conversation_id=?`, id); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM ai_conversations WHERE id=?`, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return errors.New("会话不存在")
	}
	return tx.Commit()
}

func (s *historyStore) AddAIMessage(conversationID, role, content string, plan *AIPlan) (AIChatMessage, error) {
	role, content = strings.TrimSpace(role), strings.TrimSpace(content)
	if role != "user" && role != "assistant" && role != "system" && role != "error" {
		return AIChatMessage{}, errors.New("消息角色无效")
	}
	if content == "" || len([]rune(content)) > 64000 {
		return AIChatMessage{}, errors.New("消息内容为空或过长")
	}
	id, err := randomToken(12)
	if err != nil {
		return AIChatMessage{}, err
	}
	planJSON := ""
	if plan != nil {
		encoded, marshalErr := json.Marshal(plan)
		if marshalErr != nil {
			return AIChatMessage{}, marshalErr
		}
		planJSON = string(encoded)
	}
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return AIChatMessage{}, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO ai_messages(id,conversation_id,role,content,plan_json,created_ms) VALUES(?,?,?,?,?,?)`, id, conversationID, role, content, planJSON, unixMillis(now)); err != nil {
		return AIChatMessage{}, err
	}
	if _, err = tx.Exec(`UPDATE ai_conversations SET updated_ms=? WHERE id=?`, unixMillis(now), conversationID); err != nil {
		return AIChatMessage{}, err
	}
	if err = tx.Commit(); err != nil {
		return AIChatMessage{}, err
	}
	return AIChatMessage{ID: id, ConversationID: conversationID, Role: role, Content: content, Plan: plan, CreatedAt: now}, nil
}

func aiConversationTurns(conversation AIConversation) []AIConversationTurn {
	turns := make([]AIConversationTurn, 0, 32)
	remaining := 100000
	for index := len(conversation.Messages) - 1; index >= 0 && len(turns) < 32 && remaining > 0; index-- {
		message := conversation.Messages[index]
		if message.Role != "user" && message.Role != "assistant" {
			continue
		}
		runes := []rune(message.Content)
		if len(runes) > remaining {
			runes = runes[len(runes)-remaining:]
		}
		turns = append(turns, AIConversationTurn{Role: message.Role, Content: string(runes)})
		remaining -= len(runes)
	}
	for left, right := 0, len(turns)-1; left < right; left, right = left+1, right-1 {
		turns[left], turns[right] = turns[right], turns[left]
	}
	return turns
}
