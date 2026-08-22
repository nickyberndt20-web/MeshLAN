package main

import (
	"strings"
	"testing"
)

func TestNodePairingCodeRoundTrip(t *testing.T) {
	certificate, privateKey, pin, err := generateTLSIdentity("203.0.113.10:8090")
	if err != nil {
		t.Fatal(err)
	}
	state := MeshNodeAgentState{Version: protocolVersion, ID: "node-test-id", ControlPort: 8090, TLSCertificatePEM: certificate, TLSPrivateKeyPEM: privateKey, TLSCertificatePin: pin}
	code, err := issueNodePairingCode(&state)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parseNodePairingCode(code)
	if err != nil || payload.ID != state.ID || payload.Port != state.ControlPort || !nodeSecretMatches(state, meshNodeAuthorization(payload)) {
		t.Fatalf("node pairing failed: payload=%#v err=%v", payload, err)
	}
}

func TestClientConfigIncludesEveryHealthyLighthouse(t *testing.T) {
	state := ClientState{CACertificatePath: "ca.crt", CertificatePath: "host.crt", PrivateKeyPath: "host.key", Pairing: &PairResponse{
		Address: "10.77.0.2/24", LighthouseAddress: "10.77.0.1/24", LighthouseEndpoint: "203.0.113.10:8080", RelayAddress: "10.77.0.1/24",
		Lighthouses: []LighthouseEndpoint{{ID: "primary", Address: "10.77.0.1/24", Endpoint: "203.0.113.10:8080", Primary: true, Relay: true}, {ID: "hk-02", Address: "10.77.0.6/24", Endpoint: "198.51.100.20:4242", Relay: true}},
	}, ForceP2P: true, IPMode: "dual"}
	config, err := renderClientConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"10.77.0.1": ["203.0.113.10:8080"]`, `"10.77.0.6": ["198.51.100.20:4242"]`, `- "10.77.0.1"`, `- "10.77.0.6"`} {
		if !strings.Contains(config, expected) {
			t.Fatalf("multi-lighthouse config missing %q:\n%s", expected, config)
		}
	}
	if strings.Count(config, `- "10.77.0.6"`) != 2 {
		t.Fatalf("healthy child relay was not included in both lighthouse and relay lists:\n%s", config)
	}
}

func TestNodeConfigEnablesRelayCapability(t *testing.T) {
	config := renderNodeLighthouseConfig(MeshNodeAgentState{CACertificatePath: "ca.crt", CertificatePath: "node.crt", PrivateKeyPath: "node.key", NebulaPort: 4242})
	if !strings.Contains(config, "am_lighthouse: true") || !strings.Contains(config, "am_relay: true") {
		t.Fatalf("child node is not configured as lighthouse and relay:\n%s", config)
	}
}

func TestAdminPageIncludesMultiNodeManagement(t *testing.T) {
	data, err := adminWeb.ReadFile("admin/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"多节点管理", "添加 Linux 子节点", "nodeEndpoint", "nodeHash", "/v1/admin/nodes", "每15秒健康检查", "Linux一键部署命令", "copyNodeDeployCommand", "TCP 8090", "UDP 4242", "MLNODE1 哈希", "relayReady", "Relay就绪", "/download/node/upgrade.sh", "copyNodeUpgradeCommand", "失败会自动回滚"} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("admin multi-node page missing %q", expected)
		}
	}
}

func TestNodeUpgradeScriptPreservesStateAndVerifiesPackage(t *testing.T) {
	data, err := adminWeb.ReadFile("deploy/upgrade-mesh-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, expected := range []string{"node-state.json", "x-content-sha256", "sha256sum", `backup_path="$binary_path.previous"`, "systemctl restart", "正在回滚", "am_relay: true"} {
		if !strings.Contains(script, expected) {
			t.Fatalf("node upgrade script missing %q", expected)
		}
	}
	if strings.Contains(script, "node-init") {
		t.Fatal("upgrade script must not recreate node identity")
	}
}

func TestAdminPageIncludesEncryptedAIConfiguration(t *testing.T) {
	data, err := adminWeb.ReadFile("admin/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"AI服务", "/v1/admin/ai/config", "/v1/admin/ai/test", "/v1/admin/ai/bugs", "服务端AES-256-GCM密文", "默认启用联网搜索", "AI Bug中心"} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("admin AI page missing %q", expected)
		}
	}
}
