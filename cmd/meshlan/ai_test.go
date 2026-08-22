package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAIEnvelopeRoundTripAndTamperDetection(t *testing.T) {
	privateKey, publicKey, err := generateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("ai-request|device|job")
	envelope, err := sealAIEnvelope(publicKey, []byte("encrypted diagnostic"), aad)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openAIEnvelope(privateKey, envelope, aad)
	if err != nil || string(plain) != "encrypted diagnostic" {
		t.Fatalf("AI envelope round trip failed: %q %v", plain, err)
	}
	if _, err := openAIEnvelope(privateKey, envelope, []byte("ai-request|other|job")); err == nil {
		t.Fatal("AI envelope accepted altered associated data")
	}
}

func TestAtlasFallbackRequestOmitsUnsupportedParameters(t *testing.T) {
	settings := AIProviderSettings{Model: "xai/grok-4.6", MaxTokens: 0}
	messages := []map[string]any{{"role": "user", "content": "test"}}
	structured, _ := json.Marshal(atlasProviderRequest(settings, messages, true))
	minimal, _ := json.Marshal(atlasProviderRequest(settings, messages, false))
	if !bytes.Contains(structured, []byte(`"response_format"`)) || !bytes.Contains(structured, []byte(`"temperature"`)) {
		t.Fatalf("structured request lost JSON guidance: %s", structured)
	}
	for _, unsupported := range [][]byte{[]byte(`"response_format"`), []byte(`"temperature"`), []byte(`"search_parameters"`), []byte(`"max_tokens"`)} {
		if bytes.Contains(minimal, unsupported) {
			t.Fatalf("fallback request contains optional parameter %s: %s", unsupported, minimal)
		}
	}
}

func TestAISystemPromptFollowsClientInterfaceLanguage(t *testing.T) {
	tests := map[string]string{
		"zh-CN": "简体中文",
		"zh-TW": "繁體中文",
		"en":    "in English",
		"ja":    "すべて日本語",
	}
	for language, expected := range tests {
		prompt := aiSystemPrompt(language)
		if !strings.Contains(prompt, expected) {
			t.Fatalf("AI prompt for %s does not require the selected language: %s", language, prompt)
		}
	}
	if normalizeAIResponseLanguage("unsupported") != "zh-CN" {
		t.Fatal("unsupported AI response language did not fall back to Simplified Chinese")
	}
}

func TestAIWebSearchRSSParsingAndSecretRedaction(t *testing.T) {
	feed := []byte(`<?xml version="1.0"?><rss><channel><item><title>Result &amp; One</title><link>https://example.com/a</link><description><![CDATA[<b>Useful</b> text]]></description></item></channel></rss>`)
	results, err := parseAIWebSearchRSS(feed)
	if err != nil || len(results) != 1 || results[0].Title != "Result & One" || results[0].Snippet != "Useful text" {
		t.Fatalf("unexpected RSS results: %#v err=%v", results, err)
	}
	query := safeAIWebSearchQuery("排查 10.77.0.2 " + "apikey-" + "synthetic-test-secret 的连接")
	if strings.Contains(query, "10.77.0.2") || strings.Contains(query, "apikey-") {
		t.Fatalf("search query leaked sensitive material: %s", query)
	}
}

func TestAISecretsAreEncryptedInServerState(t *testing.T) {
	root := t.TempDir()
	t.Setenv("MESHLAN_MASTER_KEY_FILE", filepath.Join(root, "master.key"))
	statePath := filepath.Join(root, "server-state.json")
	privateKey, publicKey, err := generateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	state := ServerState{AIProviderAPIKey: "test-ai-secret", AIEncryptionPrivateKey: privateKey, AIEncryptionPublicKey: publicKey}
	if err := saveJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(statePath)
	if bytes.Contains(raw, []byte("test-ai-secret")) || bytes.Contains(raw, []byte(privateKey)) {
		t.Fatal("AI secret was stored in plaintext")
	}
	var restored ServerState
	if err := loadJSON(statePath, &restored); err != nil || restored.AIProviderAPIKey != "test-ai-secret" || !validX25519KeyPair(restored.AIEncryptionPrivateKey, restored.AIEncryptionPublicKey) {
		t.Fatalf("AI secrets were not restored: %#v err=%v", restored.AIProvider, err)
	}
}

func TestAIProviderDefaultsAndToolWhitelist(t *testing.T) {
	var settings AIProviderSettings
	if !applyAIProviderDefaults(&settings) || settings.BaseURL != "https://api.atlascloud.ai/v1" || settings.Model != "xai/grok-4.6" || !settings.WebSearch || settings.MaxTokens != 0 {
		t.Fatalf("unexpected AI defaults: %#v", settings)
	}
	if _, err := normalizeAIBaseURL("http://example.com/v1"); err == nil {
		t.Fatal("insecure AI provider URL accepted")
	}
	plan := AIPlan{Reply: "ok", Actions: []AIAction{{Tool: "arbitrary_shell", Arguments: map[string]any{}}}}
	if err := validateAIPlan(&plan); err == nil || !strings.Contains(err.Error(), "未授权工具") {
		t.Fatalf("unknown AI tool accepted: %v", err)
	}
}
