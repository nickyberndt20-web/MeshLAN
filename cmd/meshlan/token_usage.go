package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

const maxTokenUsageBody = 8 << 20

type serviceTokenUsage struct {
	InputTokens     uint64
	OutputTokens    uint64
	TotalTokens     uint64
	CachedTokens    uint64
	ReasoningTokens uint64
	Reported        bool
}

type tokenUsageCounter struct {
	body    []byte
	pending []byte
	usage   serviceTokenUsage
}

func tracksTokenUsage(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	return strings.HasSuffix(path, "/chat/completions") ||
		strings.HasSuffix(path, "/responses") ||
		strings.HasSuffix(path, "/messages")
}

func (c *tokenUsageCounter) Observe(data []byte) {
	if c == nil || len(data) == 0 {
		return
	}
	if len(c.body) < maxTokenUsageBody {
		remaining := maxTokenUsageBody - len(c.body)
		if len(data) < remaining {
			remaining = len(data)
		}
		c.body = append(c.body, data[:remaining]...)
	}
	c.pending = append(c.pending, data...)
	for {
		index := bytes.IndexByte(c.pending, '\n')
		if index < 0 {
			break
		}
		line := c.pending[:index]
		c.pending = c.pending[index+1:]
		c.observeSSELine(line)
	}
	if len(c.pending) > 1<<20 {
		c.pending = append([]byte(nil), c.pending[len(c.pending)-(64<<10):]...)
	}
}

func (c *tokenUsageCounter) Result() serviceTokenUsage {
	if c == nil {
		return serviceTokenUsage{}
	}
	c.observeSSELine(c.pending)
	c.observeJSON(c.body)
	if c.usage.TotalTokens == 0 && (c.usage.InputTokens > 0 || c.usage.OutputTokens > 0) {
		c.usage.TotalTokens = c.usage.InputTokens + c.usage.OutputTokens
	}
	return c.usage
}

func (c *tokenUsageCounter) observeSSELine(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || !bytes.HasPrefix(line, []byte("data:")) {
		return
	}
	payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
	if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
		return
	}
	c.observeJSON(payload)
}

func (c *tokenUsageCounter) observeJSON(data []byte) {
	if len(data) == 0 {
		return
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return
	}
	collectTokenUsage(value, false, &c.usage)
}

func collectTokenUsage(value any, withinUsage bool, result *serviceTokenUsage) {
	switch typed := value.(type) {
	case map[string]any:
		usageMap := withinUsage || hasTokenUsageKeys(typed)
		if usageMap {
			mergeTokenUsageMap(typed, result)
		}
		for key, child := range typed {
			key = strings.ToLower(key)
			collectTokenUsage(child, usageMap || key == "usage" || strings.HasSuffix(key, "_usage"), result)
		}
	case []any:
		for _, child := range typed {
			collectTokenUsage(child, withinUsage, result)
		}
	}
}

func hasTokenUsageKeys(value map[string]any) bool {
	for key := range value {
		switch strings.ToLower(key) {
		case "prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "total_tokens", "cached_tokens", "reasoning_tokens":
			return true
		}
	}
	return false
}

func mergeTokenUsageMap(value map[string]any, result *serviceTokenUsage) {
	for key, raw := range value {
		number, ok := tokenCount(raw)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "prompt_tokens", "input_tokens":
			result.InputTokens = max(result.InputTokens, number)
			result.Reported = true
		case "completion_tokens", "output_tokens":
			result.OutputTokens = max(result.OutputTokens, number)
			result.Reported = true
		case "total_tokens":
			result.TotalTokens = max(result.TotalTokens, number)
			result.Reported = true
		case "cached_tokens":
			result.CachedTokens = max(result.CachedTokens, number)
			result.Reported = true
		case "reasoning_tokens":
			result.ReasoningTokens = max(result.ReasoningTokens, number)
			result.Reported = true
		}
	}
}

func tokenCount(value any) (uint64, bool) {
	switch typed := value.(type) {
	case json.Number:
		integer, err := typed.Int64()
		return uint64(max(integer, 0)), err == nil
	case float64:
		return uint64(max(typed, 0)), true
	case int:
		return uint64(max(typed, 0)), true
	case int64:
		return uint64(max(typed, 0)), true
	case uint64:
		return typed, true
	default:
		return 0, false
	}
}
