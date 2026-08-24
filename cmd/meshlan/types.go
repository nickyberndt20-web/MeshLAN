package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	protocolVersion           = 2
	natConfigVersion          = 11
	p2pModeVersion            = 1
	ipModeVersion             = 1
	updatePreferenceVersion   = 1
	meshDNSPreferenceVersion  = 2
	networkAutomationVersion  = 2
	proxyCompatibilityVersion = 1
	clientListenPortBase      = 42000
	clientListenPortMaximum   = 42999
)

var clientVersion = "meshlan-nebula/1.9.0"

type EnrollmentRecord struct {
	ID              string    `json:"id"`
	Label           string    `json:"label"`
	SecretHash      string    `json:"secretHash"`
	CreatedAt       time.Time `json:"createdAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	Revoked         bool      `json:"revoked"`
	BoundName       string    `json:"boundName,omitempty"`
	BoundPublicKey  string    `json:"boundPublicKey,omitempty"`
	Rekey           bool      `json:"rekey,omitempty"`
	ReservedAddress string    `json:"reservedAddress,omitempty"`
}

type PeerRecord struct {
	Name                   string                    `json:"name"`
	DNSPrefix              string                    `json:"dnsPrefix,omitempty"`
	PublicKey              string                    `json:"publicKey"`
	Address                string                    `json:"address"`
	CreatedAt              time.Time                 `json:"createdAt"`
	Revoked                bool                      `json:"revoked"`
	DeviceTokenHash        string                    `json:"deviceTokenHash"`
	LastSeen               time.Time                 `json:"lastSeen,omitempty"`
	OnlineSince            time.Time                 `json:"onlineSince,omitempty"`
	BytesReceived          uint64                    `json:"bytesReceived"`
	BytesSent              uint64                    `json:"bytesSent"`
	ServiceRunning         bool                      `json:"serviceRunning"`
	ClientVersion          string                    `json:"clientVersion,omitempty"`
	CertificateFingerprint string                    `json:"certificateFingerprint,omitempty"`
	ServiceMappings        []PublishedServiceMapping `json:"serviceMappings,omitempty"`
	FileShares             []PublishedFileShare      `json:"fileShares,omitempty"`
	UpdateSeedReady        bool                      `json:"updateSeedReady,omitempty"`
	UpdateSeedSHA256       string                    `json:"updateSeedSha256,omitempty"`
	UpdateSeedPort         int                       `json:"updateSeedPort,omitempty"`
	AIEncryptionPublicKey  string                    `json:"aiEncryptionPublicKey,omitempty"`
}

type CertificateRevocation struct {
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name"`
	Reason      string    `json:"reason"`
	RevokedAt   time.Time `json:"revokedAt"`
}

type PendingRekeyRecord struct {
	ID                        string    `json:"id"`
	Name                      string    `json:"name"`
	Address                   string    `json:"address"`
	OldFingerprint            string    `json:"oldFingerprint,omitempty"`
	NewPublicKey              string    `json:"newPublicKey"`
	NewCertificatePEM         string    `json:"newCertificatePem"`
	NewCertificateFingerprint string    `json:"newCertificateFingerprint"`
	NewDeviceTokenHash        string    `json:"newDeviceTokenHash"`
	CreatedAt                 time.Time `json:"createdAt"`
	ExpiresAt                 time.Time `json:"expiresAt"`
}

type RevocationPayload struct {
	Version         uint64                  `json:"version"`
	GeneratedAt     time.Time               `json:"generatedAt"`
	Revocations     []CertificateRevocation `json:"revocations"`
	UpdatePublicKey string                  `json:"updatePublicKey,omitempty"`
	UpdateKeyActive bool                    `json:"updateKeyActive,omitempty"`
}

type SignedRevocationEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

type UpdateManifestPayload struct {
	Version                string    `json:"version"`
	Platform               string    `json:"platform"`
	SHA256                 string    `json:"sha256"`
	Size                   int64     `json:"size"`
	PublishedAt            time.Time `json:"publishedAt"`
	DownloadPath           string    `json:"downloadPath"`
	AuthenticodeThumbprint string    `json:"authenticodeThumbprint,omitempty"`
}

type SignedUpdateManifest struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

type UpdateStatus struct {
	CurrentVersion string                 `json:"currentVersion"`
	Available      bool                   `json:"available"`
	Manifest       *UpdateManifestPayload `json:"manifest,omitempty"`
	AutoUpdate     bool                   `json:"autoUpdate"`
	LastCheckedAt  time.Time              `json:"lastCheckedAt,omitempty"`
	LastError      string                 `json:"lastError,omitempty"`
	RollbackReady  bool                   `json:"rollbackReady"`
}

type ServerState struct {
	Version                int                     `json:"version"`
	NetworkName            string                  `json:"networkName"`
	Subnet                 string                  `json:"subnet"`
	PublicEndpoint         string                  `json:"publicEndpoint"`
	LighthouseAddress      string                  `json:"lighthouseAddress"`
	NebulaPort             int                     `json:"nebulaPort"`
	PairingPort            int                     `json:"pairingPort"`
	PairingSecretHash      string                  `json:"pairingSecretHash"`
	AdminTokenHash         string                  `json:"adminTokenHash"`
	AdminTOTPEnabled       bool                    `json:"adminTotpEnabled,omitempty"`
	AdminTOTPSecret        string                  `json:"-"`
	Enrollments            []EnrollmentRecord      `json:"enrollments"`
	TLSCertificatePEM      string                  `json:"tlsCertificatePem"`
	TLSPrivateKeyPEM       string                  `json:"tlsPrivateKeyPem"`
	TLSCertificatePin      string                  `json:"tlsCertificatePin"`
	NebulaCertPath         string                  `json:"nebulaCertPath"`
	NebulaCAKeyPath        string                  `json:"nebulaCaKeyPath"`
	NebulaCAKeyPEM         string                  `json:"-"`
	NebulaCAKeyEncrypted   bool                    `json:"nebulaCaKeyEncrypted,omitempty"`
	NebulaCACertPath       string                  `json:"nebulaCaCertPath"`
	Peers                  []PeerRecord            `json:"peers"`
	AccessRequests         []ServiceAccessRequest  `json:"accessRequests,omitempty"`
	SecurityPrivateKey     string                  `json:"securityPrivateKey,omitempty"`
	SecurityPublicKey      string                  `json:"securityPublicKey,omitempty"`
	RevocationPrivateKey   string                  `json:"revocationPrivateKey,omitempty"`
	RevocationPublicKey    string                  `json:"revocationPublicKey,omitempty"`
	UpdatePrivateKey       string                  `json:"updatePrivateKey,omitempty"`
	UpdatePublicKey        string                  `json:"updatePublicKey,omitempty"`
	UpdateKeyActive        bool                    `json:"updateKeyActive,omitempty"`
	CryptoKeyVersion       int                     `json:"cryptoKeyVersion,omitempty"`
	RevocationVersion      uint64                  `json:"revocationVersion,omitempty"`
	Revocations            []CertificateRevocation `json:"revocations,omitempty"`
	PendingRekeys          []PendingRekeyRecord    `json:"pendingRekeys,omitempty"`
	WindowsUpdate          *UpdateManifestPayload  `json:"windowsUpdate,omitempty"`
	WindowsUpdatePath      string                  `json:"windowsUpdatePath,omitempty"`
	WindowsInstaller       *UpdateManifestPayload  `json:"windowsInstaller,omitempty"`
	WindowsInstallerPath   string                  `json:"windowsInstallerPath,omitempty"`
	LinuxNodeAMD64         *UpdateManifestPayload  `json:"linuxNodeAmd64,omitempty"`
	LinuxNodeAMD64Path     string                  `json:"linuxNodeAmd64Path,omitempty"`
	LinuxNodeARM64         *UpdateManifestPayload  `json:"linuxNodeArm64,omitempty"`
	LinuxNodeARM64Path     string                  `json:"linuxNodeArm64Path,omitempty"`
	SecretStorageVersion   int                     `json:"secretStorageVersion,omitempty"`
	EncryptedServerSecrets string                  `json:"encryptedServerSecrets,omitempty"`
	HTTPSCACertificatePEM  string                  `json:"httpsCaCertificatePem,omitempty"`
	HTTPSCAPrivateKeyPEM   string                  `json:"-"`
	HTTPSCAFingerprint     string                  `json:"httpsCaFingerprint,omitempty"`
	MeshNodes              []MeshNodeRecord        `json:"meshNodes,omitempty"`
	AIProvider             AIProviderSettings      `json:"aiProvider,omitempty"`
	AIProviderAPIKey       string                  `json:"-"`
	AIEncryptionPrivateKey string                  `json:"-"`
	AIEncryptionPublicKey  string                  `json:"aiEncryptionPublicKey,omitempty"`
	AIBugReports           []AIBugReport           `json:"aiBugReports,omitempty"`
}

type AIProviderSettings struct {
	Version        int       `json:"version"`
	Enabled        bool      `json:"enabled"`
	BaseURL        string    `json:"baseUrl"`
	Model          string    `json:"model"`
	WebSearch      bool      `json:"webSearch"`
	MaxTokens      int       `json:"maxTokens"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
	UpdatedAt      time.Time `json:"updatedAt,omitempty"`
}

type AIEncryptedEnvelope struct {
	Version            int    `json:"version"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

type AIAction struct {
	ID         string         `json:"id"`
	Tool       string         `json:"tool"`
	Arguments  map[string]any `json:"arguments"`
	Reason     string         `json:"reason"`
	Risk       string         `json:"risk"`
	Reversible bool           `json:"reversible"`
}

type AIPlan struct {
	ID          string          `json:"id"`
	Reply       string          `json:"reply"`
	Summary     string          `json:"summary"`
	Actions     []AIAction      `json:"actions"`
	Unresolved  bool            `json:"unresolved"`
	CreatedAt   time.Time       `json:"createdAt"`
	ExpiresAt   time.Time       `json:"expiresAt"`
	WebSearched bool            `json:"webSearched"`
	Worklog     []AIWorklogStep `json:"worklog,omitempty"`
}

type AIWorklogStep struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Status string `json:"status,omitempty"`
}

type AIActionResult struct {
	ActionID string `json:"actionId"`
	Tool     string `json:"tool"`
	Success  bool   `json:"success"`
	Message  string `json:"message"`
}

type AIExecutionResult struct {
	PlanID      string           `json:"planId"`
	Results     []AIActionResult `json:"results"`
	CompletedAt time.Time        `json:"completedAt"`
	Verified    bool             `json:"verified"`
	FollowUp    *AIPlan          `json:"followUp,omitempty"`
}

type AIBugReport struct {
	ID            string              `json:"id"`
	DeviceName    string              `json:"deviceName"`
	ClientVersion string              `json:"clientVersion"`
	Status        string              `json:"status"`
	Severity      string              `json:"severity"`
	CreatedAt     time.Time           `json:"createdAt"`
	Envelope      AIEncryptedEnvelope `json:"envelope"`
}

type MeshNodeRecord struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Address             string    `json:"address"`
	PublicEndpoint      string    `json:"publicEndpoint"`
	ControlEndpoint     string    `json:"controlEndpoint"`
	ControlPin          string    `json:"controlPin"`
	CreatedAt           time.Time `json:"createdAt"`
	LastSeen            time.Time `json:"lastSeen,omitempty"`
	Online              bool      `json:"online"`
	NebulaRunning       bool      `json:"nebulaRunning"`
	RelayReady          bool      `json:"relayReady,omitempty"`
	ClientCount         int       `json:"clientCount,omitempty"`
	BytesReceived       uint64    `json:"bytesReceived,omitempty"`
	BytesSent           uint64    `json:"bytesSent,omitempty"`
	LastError           string    `json:"lastError,omitempty"`
	ConsecutiveFailures int       `json:"consecutiveFailures,omitempty"`
}

type LighthouseEndpoint struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Endpoint string `json:"endpoint"`
	Primary  bool   `json:"primary,omitempty"`
	Relay    bool   `json:"relay,omitempty"`
}

type RelayCandidateScore struct {
	Address       string    `json:"address"`
	Name          string    `json:"name"`
	Reachable     bool      `json:"reachable"`
	LatencyMs     int64     `json:"latencyMs"`
	JitterMs      float64   `json:"jitterMs"`
	PacketLossPct float64   `json:"packetLossPct"`
	Score         float64   `json:"score"`
	Preferred     bool      `json:"preferred"`
	MeasuredAt    time.Time `json:"measuredAt"`
}

type MeshHTTPSCertificateRequest struct {
	CSRPEM string `json:"csrPem"`
}

type MeshHTTPSCertificateResponse struct {
	CertificatePEM   string    `json:"certificatePem"`
	CACertificatePEM string    `json:"caCertificatePem"`
	CAFingerprint    string    `json:"caFingerprint"`
	DNSNames         []string  `json:"dnsNames"`
	NotAfter         time.Time `json:"notAfter"`
}

type PairRequest struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKeyPem"`
}

type PairResponse struct {
	Version               int                  `json:"version"`
	Name                  string               `json:"name"`
	Address               string               `json:"address"`
	CertificatePEM        string               `json:"certificatePem"`
	CACertificatePEM      string               `json:"caCertificatePem"`
	LighthouseAddress     string               `json:"lighthouseAddress"`
	LighthouseEndpoint    string               `json:"lighthouseEndpoint"`
	RelayAddress          string               `json:"relayAddress"`
	NetworkName           string               `json:"networkName"`
	DeviceToken           string               `json:"deviceToken,omitempty"`
	ControlHost           string               `json:"controlHost"`
	ControlPort           int                  `json:"controlPort"`
	ControlPin            string               `json:"controlPin"`
	SecurityPublicKey     string               `json:"securityPublicKey,omitempty"`
	RevocationPublicKey   string               `json:"revocationPublicKey,omitempty"`
	UpdatePublicKey       string               `json:"updatePublicKey,omitempty"`
	UpdateKeyActive       bool                 `json:"updateKeyActive,omitempty"`
	RekeyID               string               `json:"rekeyId,omitempty"`
	DNSPrefix             string               `json:"dnsPrefix,omitempty"`
	Lighthouses           []LighthouseEndpoint `json:"lighthouses,omitempty"`
	HTTPSCACertificatePEM string               `json:"httpsCaCertificatePem,omitempty"`
	HTTPSCAFingerprint    string               `json:"httpsCaFingerprint,omitempty"`
	AIEncryptionPublicKey string               `json:"aiEncryptionPublicKey,omitempty"`
}

type HeartbeatRequest struct {
	Name                   string                    `json:"name"`
	BytesReceived          uint64                    `json:"bytesReceived"`
	BytesSent              uint64                    `json:"bytesSent"`
	ServiceRunning         bool                      `json:"serviceRunning"`
	ClientVersion          string                    `json:"clientVersion"`
	CertificateFingerprint string                    `json:"certificateFingerprint,omitempty"`
	ServiceMappings        []ServiceMappingHeartbeat `json:"serviceMappings,omitempty"`
	FileShares             []FileShareHeartbeat      `json:"fileShares,omitempty"`
	UpdateSeedReady        bool                      `json:"updateSeedReady,omitempty"`
	UpdateSeedSHA256       string                    `json:"updateSeedSha256,omitempty"`
	UpdateSeedPort         int                       `json:"updateSeedPort,omitempty"`
	AIEncryptionPublicKey  string                    `json:"aiEncryptionPublicKey,omitempty"`
}

type FileShareHeartbeat struct {
	ID            string    `json:"id"`
	FileName      string    `json:"fileName"`
	Size          int64     `json:"size"`
	SHA256        string    `json:"sha256"`
	RecipientName string    `json:"recipientName,omitempty"`
	ExpiresAt     time.Time `json:"expiresAt"`
	MaxDownloads  int       `json:"maxDownloads"`
	DownloadCount int       `json:"downloadCount"`
	AccessToken   string    `json:"accessToken"`
}

type PublishedFileShare struct {
	ID            string    `json:"id"`
	OwnerName     string    `json:"ownerName"`
	OwnerAddress  string    `json:"ownerAddress"`
	FileName      string    `json:"fileName"`
	Size          int64     `json:"size"`
	SHA256        string    `json:"sha256"`
	RecipientName string    `json:"recipientName,omitempty"`
	ExpiresAt     time.Time `json:"expiresAt"`
	MaxDownloads  int       `json:"maxDownloads"`
	DownloadCount int       `json:"downloadCount"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type FileShareDirectoryEntry struct {
	PublishedFileShare
	DownloadURL string `json:"downloadUrl"`
}

type HeartbeatResponse struct {
	OK                    bool                     `json:"ok"`
	Revocations           SignedRevocationEnvelope `json:"revocations"`
	Lighthouses           []LighthouseEndpoint     `json:"lighthouses,omitempty"`
	HTTPSCACertificatePEM string                   `json:"httpsCaCertificatePem,omitempty"`
	HTTPSCAFingerprint    string                   `json:"httpsCaFingerprint,omitempty"`
	AIEncryptionPublicKey string                   `json:"aiEncryptionPublicKey,omitempty"`
}

type LocalServiceMapping struct {
	ID               string    `json:"id"`
	ServiceName      string    `json:"serviceName"`
	LocalHost        string    `json:"localHost"`
	LocalPort        int       `json:"localPort"`
	MeshPort         int       `json:"meshPort"`
	Protocol         string    `json:"protocol"`
	DNSPrefix        string    `json:"dnsPrefix,omitempty"`
	PortlessHTTP     bool      `json:"portlessHttp,omitempty"`
	Paused           bool      `json:"paused"`
	ApprovalRequired bool      `json:"approvalRequired"`
	CreatedAt        time.Time `json:"createdAt"`
}

type ServiceConnectionRecord struct {
	MappingID         string    `json:"mappingId"`
	ServiceName       string    `json:"serviceName"`
	UserName          string    `json:"userName"`
	Address           string    `json:"address"`
	Protocol          string    `json:"protocol"`
	Allowed           bool      `json:"allowed"`
	Active            int       `json:"active"`
	FirstSeen         time.Time `json:"firstSeen"`
	LastSeen          time.Time `json:"lastSeen"`
	BytesToLocal      uint64    `json:"bytesToLocal"`
	BytesToPeer       uint64    `json:"bytesToPeer"`
	InputTokens       uint64    `json:"inputTokens,omitempty"`
	OutputTokens      uint64    `json:"outputTokens,omitempty"`
	TotalTokens       uint64    `json:"totalTokens,omitempty"`
	CachedTokens      uint64    `json:"cachedTokens,omitempty"`
	ReasoningTokens   uint64    `json:"reasoningTokens,omitempty"`
	TokenUsageReports uint64    `json:"tokenUsageReports,omitempty"`
}

type ServiceMappingHeartbeat struct {
	ID               string    `json:"id"`
	ServiceName      string    `json:"serviceName"`
	Port             int       `json:"port"`
	Protocol         string    `json:"protocol"`
	DNSPrefix        string    `json:"dnsPrefix,omitempty"`
	PortlessHTTP     bool      `json:"portlessHttp,omitempty"`
	HTTPS            bool      `json:"https,omitempty"`
	Active           bool      `json:"active"`
	Paused           bool      `json:"paused"`
	ApprovalRequired bool      `json:"approvalRequired"`
	Healthy          bool      `json:"healthy"`
	LatencyMs        int64     `json:"latencyMs"`
	CheckedAt        time.Time `json:"checkedAt,omitempty"`
}

type PublishedServiceMapping struct {
	ID                 string    `json:"id"`
	OwnerName          string    `json:"ownerName"`
	ServiceName        string    `json:"serviceName"`
	Address            string    `json:"address"`
	Port               int       `json:"port"`
	Protocol           string    `json:"protocol"`
	DNSPrefix          string    `json:"dnsPrefix,omitempty"`
	PortlessHTTP       bool      `json:"portlessHttp,omitempty"`
	HTTPS              bool      `json:"https,omitempty"`
	Active             bool      `json:"active"`
	Paused             bool      `json:"paused"`
	ApprovalRequired   bool      `json:"approvalRequired"`
	Healthy            bool      `json:"healthy"`
	LatencyMs          int64     `json:"latencyMs"`
	CheckedAt          time.Time `json:"checkedAt,omitempty"`
	UpdatedAt          time.Time `json:"updatedAt"`
	ViewerAccessStatus string    `json:"viewerAccessStatus,omitempty"`
	DNSName            string    `json:"dnsName,omitempty"`
	URL                string    `json:"url,omitempty"`
}

type ServiceAccessRequest struct {
	ID               string    `json:"id"`
	MappingID        string    `json:"mappingId"`
	ServiceName      string    `json:"serviceName"`
	OwnerName        string    `json:"ownerName"`
	RequesterName    string    `json:"requesterName"`
	RequesterAddress string    `json:"requesterAddress"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type ServiceUserAccess struct {
	UserName string `json:"userName"`
	Address  string `json:"address"`
	Status   string `json:"status"`
}

type MappingAccessPolicy struct {
	MappingID        string              `json:"mappingId"`
	ApprovalRequired bool                `json:"approvalRequired"`
	Users            []ServiceUserAccess `json:"users"`
}

type AccessMessage struct {
	ID            string    `json:"id"`
	MappingID     string    `json:"mappingId"`
	ServiceName   string    `json:"serviceName"`
	OwnerName     string    `json:"ownerName"`
	RequesterName string    `json:"requesterName"`
	Status        string    `json:"status"`
	Direction     string    `json:"direction"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type PeerIdentity struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type DeviceControlResponse struct {
	Messages    []AccessMessage          `json:"messages"`
	Policies    []MappingAccessPolicy    `json:"policies"`
	Peers       []PeerIdentity           `json:"peers"`
	UpdatedAt   time.Time                `json:"updatedAt"`
	Revocations SignedRevocationEnvelope `json:"revocations,omitempty"`
	DNSRecords  []MeshDNSRecord          `json:"dnsRecords,omitempty"`
}

type PeerDirectoryEntry struct {
	Name           string    `json:"name"`
	Address        string    `json:"address"`
	Online         bool      `json:"online"`
	ServiceRunning bool      `json:"serviceRunning"`
	BytesReceived  uint64    `json:"bytesReceived"`
	BytesSent      uint64    `json:"bytesSent"`
	LastSeen       time.Time `json:"lastSeen,omitempty"`
	OnlineSince    time.Time `json:"onlineSince,omitempty"`
	ClientVersion  string    `json:"clientVersion,omitempty"`
	DNSName        string    `json:"dnsName,omitempty"`
	DNSPrefix      string    `json:"dnsPrefix,omitempty"`
}

type MeshDNSRecord struct {
	Name         string `json:"name"`
	Address      string `json:"address"`
	Kind         string `json:"kind"`
	OwnerName    string `json:"ownerName,omitempty"`
	OwnerPrefix  string `json:"ownerPrefix,omitempty"`
	ServiceName  string `json:"serviceName,omitempty"`
	MappingID    string `json:"mappingId,omitempty"`
	Port         int    `json:"port,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	PortlessHTTP bool   `json:"portlessHttp,omitempty"`
	URL          string `json:"url,omitempty"`
}

type MeshDNSStatus struct {
	Enabled     bool            `json:"enabled"`
	Suffix      string          `json:"suffix"`
	Records     []MeshDNSRecord `json:"records"`
	Applied     int             `json:"applied"`
	LastUpdated time.Time       `json:"lastUpdated,omitempty"`
	LastError   string          `json:"lastError,omitempty"`
	OwnPrefix   string          `json:"ownPrefix,omitempty"`
	OwnDNSName  string          `json:"ownDnsName,omitempty"`
}

type PeerDirectoryResponse struct {
	Peers       []PeerDirectoryEntry      `json:"peers"`
	Services    []PublishedServiceMapping `json:"services"`
	Files       []FileShareDirectoryEntry `json:"files"`
	RefreshedAt time.Time                 `json:"refreshedAt"`
}

type NetworkPathRecord struct {
	Address    string    `json:"address"`
	Mode       string    `json:"mode"`
	Underlay   string    `json:"underlay,omitempty"`
	ObservedAt time.Time `json:"observedAt,omitempty"`
}

type RouteGuardStatus struct {
	Version                int      `json:"version"`
	Mode                   string   `json:"mode"`
	BypassReady            bool     `json:"bypassReady"`
	PhysicalInterface      string   `json:"physicalInterface,omitempty"`
	PhysicalAddress        string   `json:"physicalAddress,omitempty"`
	Gateway                string   `json:"gateway,omitempty"`
	InterfaceIndex         int      `json:"interfaceIndex,omitempty"`
	Targets                []string `json:"targets,omitempty"`
	IPv6Interface          string   `json:"ipv6Interface,omitempty"`
	IPv6Address            string   `json:"ipv6Address,omitempty"`
	IPv6Gateway            string   `json:"ipv6Gateway,omitempty"`
	IPv6InterfaceIndex     int      `json:"ipv6InterfaceIndex,omitempty"`
	IPv6Targets            []string `json:"ipv6Targets,omitempty"`
	TUNInterfaces          []string `json:"tunInterfaces,omitempty"`
	PreferredP2P           string   `json:"preferredP2P,omitempty"`
	PreferredBusiness      string   `json:"preferredBusiness,omitempty"`
	BusinessActive         bool     `json:"businessActive"`
	IPv6DefaultSuppressed  bool     `json:"ipv6DefaultSuppressed"`
	BusinessAddress        string   `json:"businessAddress,omitempty"`
	BusinessGateway        string   `json:"businessGateway,omitempty"`
	BusinessInterfaceIndex int      `json:"businessInterfaceIndex,omitempty"`
	LastUpdated            string   `json:"lastUpdated,omitempty"`
	LastRestart            string   `json:"lastRestart,omitempty"`
	LastError              string   `json:"lastError,omitempty"`
	SecurityAppliedVersion uint64   `json:"securityAppliedVersion,omitempty"`
	RaceAppliedVersion     uint64   `json:"raceAppliedVersion,omitempty"`
	DNSRecordsApplied      int      `json:"dnsRecordsApplied,omitempty"`
	DNSLastError           string   `json:"dnsLastError,omitempty"`
}

type NetworkSceneProfile struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	P2PInterface      string    `json:"p2pInterface"`
	BusinessInterface string    `json:"businessInterface"`
	CreatedAt         time.Time `json:"createdAt"`
	LastSeen          time.Time `json:"lastSeen"`
}

type DualStackFamilyScore struct {
	Family        string    `json:"family"`
	Score         float64   `json:"score"`
	LatencyMs     float64   `json:"latencyMs"`
	JitterMs      float64   `json:"jitterMs"`
	PacketLossPct float64   `json:"packetLossPct"`
	Samples       int       `json:"samples"`
	UpdatedAt     time.Time `json:"updatedAt,omitempty"`
}

type DualStackRaceStatus struct {
	Enabled             bool                   `json:"enabled"`
	AutoScenes          bool                   `json:"autoScenes"`
	State               string                 `json:"state"`
	Winner              string                 `json:"winner,omitempty"`
	CurrentPath         string                 `json:"currentPath,omitempty"`
	CurrentEndpoint     string                 `json:"currentEndpoint,omitempty"`
	LastRaceAt          time.Time              `json:"lastRaceAt,omitempty"`
	LastRaceReason      string                 `json:"lastRaceReason,omitempty"`
	RequestedVersion    uint64                 `json:"requestedVersion"`
	AppliedVersion      uint64                 `json:"appliedVersion"`
	NetworkFingerprint  string                 `json:"networkFingerprint,omitempty"`
	CurrentScene        string                 `json:"currentScene,omitempty"`
	LastNetworkChangeAt time.Time              `json:"lastNetworkChangeAt,omitempty"`
	Scores              []DualStackFamilyScore `json:"scores"`
	Scenes              []NetworkSceneProfile  `json:"scenes"`
}

type NATStatusResponse struct {
	ListenPort       int                 `json:"listenPort"`
	ConfigVersion    int                 `json:"configVersion"`
	AppliedVersion   int                 `json:"appliedVersion"`
	RestartRequired  bool                `json:"restartRequired"`
	WindowsWFPBypass bool                `json:"windowsWfpBypass"`
	PortMapping      string              `json:"portMapping"`
	ForceP2P         bool                `json:"forceP2P"`
	RouteGuard       RouteGuardStatus    `json:"routeGuard"`
	DirectCount      int                 `json:"directCount"`
	RelayCount       int                 `json:"relayCount"`
	Paths            []NetworkPathRecord `json:"paths"`
	LastError        string              `json:"lastError,omitempty"`
}

type STUNProbeResult struct {
	Server         string `json:"server"`
	Destination    string `json:"destination,omitempty"`
	Success        bool   `json:"success"`
	PublicEndpoint string `json:"publicEndpoint,omitempty"`
	LatencyMs      int64  `json:"latencyMs,omitempty"`
	Error          string `json:"error,omitempty"`
}

type IPFamilyDiagnostic struct {
	Available       bool              `json:"available"`
	LocalAddress    string            `json:"localAddress,omitempty"`
	Gateway         string            `json:"gateway,omitempty"`
	MappingBehavior string            `json:"mappingBehavior"`
	P2PSupport      string            `json:"p2pSupport"`
	Evidence        string            `json:"evidence"`
	Probes          []STUNProbeResult `json:"probes"`
}

type NATDiagnosticReport struct {
	StartedAt         time.Time          `json:"startedAt"`
	CompletedAt       time.Time          `json:"completedAt"`
	PhysicalInterface string             `json:"physicalInterface,omitempty"`
	TUNInterfaces     []string           `json:"tunInterfaces,omitempty"`
	NebulaListenPort  int                `json:"nebulaListenPort"`
	RouteGuardReady   bool               `json:"routeGuardReady"`
	UPnPStatus        string             `json:"upnpStatus"`
	IPv4              IPFamilyDiagnostic `json:"ipv4"`
	IPv6              IPFamilyDiagnostic `json:"ipv6"`
	DirectPeers       int                `json:"directPeers"`
	RelayPeers        int                `json:"relayPeers"`
	Verdict           string             `json:"verdict"`
	Recommendations   []string           `json:"recommendations"`
}

type TopologyInterfaceNode struct {
	Role       string `json:"role"`
	Alias      string `json:"alias"`
	Address    string `json:"address,omitempty"`
	Gateway    string `json:"gateway,omitempty"`
	Active     bool   `json:"active"`
	IPv6       bool   `json:"ipv6"`
	Suppressed bool   `json:"suppressed,omitempty"`
}

type TopologyLocalNode struct {
	Name                string `json:"name"`
	Address             string `json:"address"`
	ServiceRunning      bool   `json:"serviceRunning"`
	IPMode              string `json:"ipMode"`
	ForceP2P            bool   `json:"forceP2P"`
	ListenPort          int    `json:"listenPort"`
	ServiceCount        int    `json:"serviceCount"`
	HealthyServiceCount int    `json:"healthyServiceCount"`
	BytesReceived       uint64 `json:"bytesReceived"`
	BytesSent           uint64 `json:"bytesSent"`
}

type TopologyLighthouseNode struct {
	Address   string `json:"address"`
	Endpoint  string `json:"endpoint"`
	Reachable bool   `json:"reachable"`
	LatencyMs int64  `json:"latencyMs"`
}

type TopologyPeerNode struct {
	Name                string    `json:"name"`
	Address             string    `json:"address"`
	Online              bool      `json:"online"`
	ServiceRunning      bool      `json:"serviceRunning"`
	Reachable           bool      `json:"reachable"`
	LatencyMs           int64     `json:"latencyMs"`
	JitterMs            float64   `json:"jitterMs"`
	PacketLossPct       float64   `json:"packetLossPct"`
	ProbeSamples        int       `json:"probeSamples"`
	PathMode            string    `json:"pathMode"`
	PathFamily          string    `json:"pathFamily,omitempty"`
	Underlay            string    `json:"underlay,omitempty"`
	PathChangedAt       time.Time `json:"pathChangedAt,omitempty"`
	PathChangeReason    string    `json:"pathChangeReason,omitempty"`
	ObservedAt          time.Time `json:"observedAt,omitempty"`
	LastSeen            time.Time `json:"lastSeen,omitempty"`
	OnlineSince         time.Time `json:"onlineSince,omitempty"`
	ClientVersion       string    `json:"clientVersion,omitempty"`
	ServiceCount        int       `json:"serviceCount"`
	HealthyServiceCount int       `json:"healthyServiceCount"`
	BytesReceived       uint64    `json:"bytesReceived"`
	BytesSent           uint64    `json:"bytesSent"`
}

type TopologyServiceNode struct {
	ID                string    `json:"id"`
	OwnerName         string    `json:"ownerName"`
	ServiceName       string    `json:"serviceName"`
	Address           string    `json:"address"`
	Port              int       `json:"port"`
	Protocol          string    `json:"protocol"`
	DNSName           string    `json:"dnsName,omitempty"`
	URL               string    `json:"url,omitempty"`
	Local             bool      `json:"local"`
	Active            bool      `json:"active"`
	Paused            bool      `json:"paused"`
	Healthy           bool      `json:"healthy"`
	PortlessHTTP      bool      `json:"portlessHttp"`
	ApprovalRequired  bool      `json:"approvalRequired"`
	LatencyMs         int64     `json:"latencyMs"`
	CheckedAt         time.Time `json:"checkedAt,omitempty"`
	ActiveConnections int       `json:"activeConnections"`
	BytesToService    uint64    `json:"bytesToService"`
	BytesFromService  uint64    `json:"bytesFromService"`
}

type TopologySnapshot struct {
	RefreshedAt time.Time               `json:"refreshedAt"`
	Local       TopologyLocalNode       `json:"local"`
	Lighthouse  TopologyLighthouseNode  `json:"lighthouse"`
	Interfaces  []TopologyInterfaceNode `json:"interfaces"`
	TUN         []string                `json:"tun"`
	Peers       []TopologyPeerNode      `json:"peers"`
	Services    []TopologyServiceNode   `json:"services"`
}

type ClientState struct {
	Version                    int                   `json:"version"`
	Name                       string                `json:"name"`
	DNSPrefix                  string                `json:"dnsPrefix,omitempty"`
	PrivateKeyPath             string                `json:"privateKeyPath"`
	PublicKeyPath              string                `json:"publicKeyPath"`
	CertificatePath            string                `json:"certificatePath"`
	CertificateFingerprint     string                `json:"certificateFingerprint,omitempty"`
	CACertificatePath          string                `json:"caCertificatePath"`
	ConfigPath                 string                `json:"configPath"`
	Pairing                    *PairResponse         `json:"pairing,omitempty"`
	SecretStorageVersion       int                   `json:"secretStorageVersion,omitempty"`
	EncryptedDeviceToken       string                `json:"encryptedDeviceToken,omitempty"`
	LastInterfaceRx            uint64                `json:"lastInterfaceRx"`
	LastInterfaceTx            uint64                `json:"lastInterfaceTx"`
	TotalRx                    uint64                `json:"totalRx"`
	TotalTx                    uint64                `json:"totalTx"`
	ServiceMappings            []LocalServiceMapping `json:"serviceMappings,omitempty"`
	NebulaListenPort           int                   `json:"nebulaListenPort,omitempty"`
	NATConfigVersion           int                   `json:"natConfigVersion,omitempty"`
	NATAppliedVersion          int                   `json:"natAppliedVersion,omitempty"`
	NATLastError               string                `json:"natLastError,omitempty"`
	NATPortMapping             string                `json:"natPortMapping,omitempty"`
	ForceP2P                   bool                  `json:"forceP2P,omitempty"`
	P2PModeVersion             int                   `json:"p2pModeVersion,omitempty"`
	IPMode                     string                `json:"ipMode,omitempty"`
	IPModeVersion              int                   `json:"ipModeVersion,omitempty"`
	PreferredP2PInterface      string                `json:"preferredP2PInterface,omitempty"`
	PreferredBusinessInterface string                `json:"preferredBusinessInterface,omitempty"`
	InterfaceRoutingVersion    int                   `json:"interfaceRoutingVersion,omitempty"`
	RevocationVersion          uint64                `json:"revocationVersion,omitempty"`
	RevokedFingerprints        []string              `json:"revokedFingerprints,omitempty"`
	AutoUpdate                 bool                  `json:"autoUpdate,omitempty"`
	UpdatePreferenceVersion    int                   `json:"updatePreferenceVersion,omitempty"`
	LastUpdateCheck            time.Time             `json:"lastUpdateCheck,omitempty"`
	LastUpdateError            string                `json:"lastUpdateError,omitempty"`
	MeshDNSEnabled             bool                  `json:"meshDnsEnabled,omitempty"`
	MeshDNSPreferenceVersion   int                   `json:"meshDnsPreferenceVersion,omitempty"`
	AutoDualStack              bool                  `json:"autoDualStack,omitempty"`
	AutoNetworkScenes          bool                  `json:"autoNetworkScenes,omitempty"`
	NetworkAutomationVersion   int                   `json:"networkAutomationVersion,omitempty"`
	NetworkFingerprint         string                `json:"networkFingerprint,omitempty"`
	CurrentNetworkScene        string                `json:"currentNetworkScene,omitempty"`
	LastNetworkChangeAt        time.Time             `json:"lastNetworkChangeAt,omitempty"`
	NetworkScenes              []NetworkSceneProfile `json:"networkScenes,omitempty"`
	RaceRequestVersion         uint64                `json:"raceRequestVersion,omitempty"`
	LastRaceRequestedAt        time.Time             `json:"lastRaceRequestedAt,omitempty"`
	LastRaceReason             string                `json:"lastRaceReason,omitempty"`
	DiagnosticIPv6Targets      []string              `json:"diagnosticIPv6Targets,omitempty"`
	DiagnosticTargetsExpiresAt time.Time             `json:"diagnosticTargetsExpiresAt,omitempty"`
	LighthouseUpdatedAt        time.Time             `json:"lighthouseUpdatedAt,omitempty"`
	PreferredRelayAddress      string                `json:"preferredRelayAddress,omitempty"`
	RelayCandidates            []RelayCandidateScore `json:"relayCandidates,omitempty"`
	RelaySelectionUpdatedAt    time.Time             `json:"relaySelectionUpdatedAt,omitempty"`
	ProxyCompatibilityEnabled  bool                  `json:"proxyCompatibilityEnabled,omitempty"`
	ProxyCompatibilityVersion  int                   `json:"proxyCompatibilityVersion,omitempty"`
	AIEncryptedPrivateKey      string                `json:"aiEncryptedPrivateKey,omitempty"`
	AIEncryptionPublicKey      string                `json:"aiEncryptionPublicKey,omitempty"`
	AIKeyVersion               int                   `json:"aiKeyVersion,omitempty"`
}

type ClientLighthouseStatus struct {
	LighthouseEndpoint
	Reachable bool    `json:"reachable"`
	LatencyMs int64   `json:"latencyMs"`
	Preferred bool    `json:"preferred,omitempty"`
	Score     float64 `json:"score,omitempty"`
}

type ClientLighthousePage struct {
	Nodes          []ClientLighthouseStatus `json:"nodes"`
	UpdatedAt      time.Time                `json:"updatedAt"`
	SyncedAt       time.Time                `json:"syncedAt,omitempty"`
	PreferredRelay string                   `json:"preferredRelay,omitempty"`
}

func publicClientState(state ClientState) ClientState {
	copy := state
	copy.EncryptedDeviceToken = ""
	copy.AIEncryptedPrivateKey = ""
	if state.Pairing != nil {
		pairing := *state.Pairing
		pairing.DeviceToken = ""
		copy.Pairing = &pairing
	}
	return copy
}

const interfaceRoutingVersion = 1

func applyP2PModeDefaults(state *ClientState) bool {
	if state.P2PModeVersion >= p2pModeVersion {
		return false
	}
	state.ForceP2P = true
	state.P2PModeVersion = p2pModeVersion
	return true
}

func normalizeIPMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ipv4":
		return "ipv4"
	case "ipv6":
		return "ipv6"
	default:
		return "dual"
	}
}

func applyIPModeDefaults(state *ClientState) bool {
	normalized := normalizeIPMode(state.IPMode)
	if state.IPModeVersion >= ipModeVersion && state.IPMode == normalized {
		return false
	}
	state.IPMode = normalized
	state.IPModeVersion = ipModeVersion
	return true
}

func normalizeInterfacePreference(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "auto") {
		return "auto"
	}
	return value
}

func applyInterfaceRoutingDefaults(state *ClientState) bool {
	p2p := normalizeInterfacePreference(state.PreferredP2PInterface)
	business := normalizeInterfacePreference(state.PreferredBusinessInterface)
	if state.InterfaceRoutingVersion >= interfaceRoutingVersion && state.PreferredP2PInterface == p2p && state.PreferredBusinessInterface == business {
		return false
	}
	state.PreferredP2PInterface = p2p
	state.PreferredBusinessInterface = business
	state.InterfaceRoutingVersion = interfaceRoutingVersion
	return true
}

func applyUpdatePreferenceDefaults(state *ClientState) bool {
	if state.UpdatePreferenceVersion >= updatePreferenceVersion {
		return false
	}
	state.AutoUpdate = true
	state.UpdatePreferenceVersion = updatePreferenceVersion
	return true
}

func applyMeshDNSPreferenceDefaults(state *ClientState) bool {
	changed := false
	if state.MeshDNSPreferenceVersion < 1 {
		state.MeshDNSEnabled = true
		changed = true
	}
	if !validDNSPrefix(state.DNSPrefix) {
		state.DNSPrefix = uniqueDefaultDNSPrefix(state.Name, map[string]bool{})
		changed = true
	}
	used := map[string]bool{}
	for index := range state.ServiceMappings {
		mapping := &state.ServiceMappings[index]
		prefix, err := normalizeDNSPrefix(mapping.DNSPrefix)
		if err != nil {
			prefix = meshDNSLabel(mapping.ServiceName, mapping.ID)
		}
		if used[prefix] {
			prefix += "-" + shortStableHash(mapping.ID)
		}
		if mapping.DNSPrefix != prefix {
			mapping.DNSPrefix = prefix
			changed = true
		}
		if mapping.PortlessHTTP && normalizeMappingProtocol(mapping.Protocol) != "tcp" {
			mapping.PortlessHTTP = false
			changed = true
		}
		used[prefix] = true
	}
	if state.MeshDNSPreferenceVersion != meshDNSPreferenceVersion {
		state.MeshDNSPreferenceVersion = meshDNSPreferenceVersion
		changed = true
	}
	return changed
}

func applyNetworkAutomationDefaults(state *ClientState) bool {
	changed := false
	if state.NetworkAutomationVersion < networkAutomationVersion {
		state.AutoDualStack = normalizeIPMode(state.IPMode) == "dual"
		state.AutoNetworkScenes = normalizeIPMode(state.IPMode) == "dual"
		state.NetworkAutomationVersion = networkAutomationVersion
		changed = true
	}
	if normalizeIPMode(state.IPMode) != "dual" && (state.AutoDualStack || state.AutoNetworkScenes) {
		state.AutoDualStack = false
		state.AutoNetworkScenes = false
		changed = true
	}
	return changed
}

func applyProxyCompatibilityDefaults(state *ClientState) bool {
	if state.ProxyCompatibilityVersion >= proxyCompatibilityVersion {
		return false
	}
	state.ProxyCompatibilityEnabled = true
	state.ProxyCompatibilityVersion = proxyCompatibilityVersion
	return true
}

func validInterfacePreference(value string) bool {
	value = normalizeInterfacePreference(value)
	if value == "auto" {
		return true
	}
	count := utf8.RuneCountInString(value)
	if count < 1 || count > 128 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func renderIPModePolicy(mode, lighthouseIP string) (listenHost, lighthousePolicy string) {
	switch normalizeIPMode(mode) {
	case "ipv4":
		return "0.0.0.0", `  remote_allow_list:
    "0.0.0.0/0": true
    "::/0": false
  local_allow_list:
    "0.0.0.0/0": true
    "::/0": false
`
	case "ipv6":
		return "::", fmt.Sprintf(`  remote_allow_list:
    "0.0.0.0/0": false
    "%s/32": true
    "::/0": true
  local_allow_list:
    "0.0.0.0/0": false
    "::/0": true
`, lighthouseIP)
	default:
		return "::", ""
	}
}

func validServiceName(name string) bool {
	name = strings.TrimSpace(name)
	count := utf8.RuneCountInString(name)
	if count < 1 || count > 48 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '<' || r == '>' {
			return false
		}
	}
	return true
}

func validFileShareName(value string) bool {
	value = strings.TrimSpace(value)
	count := utf8.RuneCountInString(value)
	if count < 1 || count > 180 || strings.ContainsAny(value, `/\\`) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || strings.ContainsRune(`<>:"|?*`, r) {
			return false
		}
	}
	return true
}

func normalizeMappingProtocol(protocol string) string {
	if strings.EqualFold(strings.TrimSpace(protocol), "udp") {
		return "udp"
	}
	return "tcp"
}

func validName(name string) bool {
	if len(name) < 1 || len(name) > 48 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func saveJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	prepared, err := prepareJSONValue(path, value)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(prepared, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return finalizeJSONSave(path, value)
}

func loadJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Pointer && !reflected.IsNil() && reflected.Elem().CanSet() {
		reflected.Elem().Set(reflect.Zero(reflected.Elem().Type()))
	}
	if err := json.Unmarshal(data, value); err != nil {
		return err
	}
	return restoreJSONValue(path, value)
}

func appRoot() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "MeshLANNebula")
	return path, os.MkdirAll(path, 0o700)
}

func allocateAddress(state ServerState) (string, error) {
	prefix, err := netip.ParsePrefix(state.Subnet)
	if err != nil || !prefix.Addr().Is4() {
		return "", errors.New("Nebula 网段必须是 IPv4 CIDR")
	}
	used := map[netip.Addr]bool{}
	lighthouse, err := netip.ParsePrefix(state.LighthouseAddress)
	if err != nil {
		return "", err
	}
	used[lighthouse.Addr()] = true
	for _, peer := range state.Peers {
		address, parseErr := netip.ParsePrefix(peer.Address)
		if parseErr == nil {
			used[address.Addr()] = true
		}
	}
	for _, node := range state.MeshNodes {
		address, parseErr := netip.ParsePrefix(node.Address)
		if parseErr == nil {
			used[address.Addr()] = true
		}
	}
	for address := prefix.Masked().Addr().Next(); prefix.Contains(address); address = address.Next() {
		if !used[address] {
			return fmt.Sprintf("%s/%d", address, prefix.Bits()), nil
		}
	}
	return "", errors.New("Nebula 地址池已耗尽")
}

func yamlPath(path string) string { return filepath.ToSlash(path) }

func clientListenPort(state ClientState) int {
	if state.NebulaListenPort >= clientListenPortBase && state.NebulaListenPort <= clientListenPortMaximum {
		return state.NebulaListenPort
	}
	if state.Pairing != nil {
		if prefix, err := netip.ParsePrefix(state.Pairing.Address); err == nil && prefix.Addr().Is4() {
			bytes := prefix.Addr().As4()
			return clientListenPortBase + int(bytes[3])
		}
	}
	return clientListenPortBase + 1
}

func renderClientConfig(state ClientState) (string, error) {
	if state.Pairing == nil {
		return "", errors.New("尚未完成配对")
	}
	applyP2PModeDefaults(&state)
	applyIPModeDefaults(&state)
	pairing := state.Pairing
	lighthouses := effectiveLighthouseEndpoints(pairing)
	lighthouseIP := strings.Split(pairing.LighthouseAddress, "/")[0]
	relayIP := strings.Split(pairing.RelayAddress, "/")[0]
	lighthouseEndpointHost := pairing.LighthouseEndpoint
	if host, _, err := net.SplitHostPort(pairing.LighthouseEndpoint); err == nil {
		lighthouseEndpointHost = strings.Trim(host, "[]")
	}
	listenHost, lighthousePolicy := renderIPModePolicy(state.IPMode, lighthouseEndpointHost)
	var staticMaps, lighthouseHosts, relayHosts strings.Builder
	seenAddresses := map[string]bool{}
	for _, node := range lighthouses {
		address := strings.Split(strings.TrimSpace(node.Address), "/")[0]
		endpoint := strings.TrimSpace(node.Endpoint)
		if address == "" || endpoint == "" || seenAddresses[address] {
			continue
		}
		seenAddresses[address] = true
		fmt.Fprintf(&staticMaps, "  \"%s\": [\"%s\"]\n", address, endpoint)
		fmt.Fprintf(&lighthouseHosts, "    - \"%s\"\n", address)
		if node.Relay || node.Primary {
			fmt.Fprintf(&relayHosts, "    - \"%s\"\n", address)
		}
	}
	if staticMaps.Len() == 0 {
		fmt.Fprintf(&staticMaps, "  \"%s\": [\"%s\"]\n", lighthouseIP, pairing.LighthouseEndpoint)
		fmt.Fprintf(&lighthouseHosts, "    - \"%s\"\n", lighthouseIP)
	}
	if relayHosts.Len() == 0 {
		fmt.Fprintf(&relayHosts, "    - \"%s\"\n", relayIP)
	}
	return fmt.Sprintf(`pki:
  ca: %s
  cert: %s
  key: %s
  disconnect_invalid: true
%s

static_host_map:
%s

lighthouse:
  am_lighthouse: false
  interval: 10
  hosts:
%s
%s

listen:
  host: "%s"
  port: %d
  windows_bypass_wdf: true

punchy:
  punch: true
  respond: true
  delay: 1s
  respond_delay: 5s

relay:
  relays:
%s
  am_relay: false
  use_relays: %t

tun:
  disabled: false
  dev: MeshLAN
  mtu: 1300
  network_category: private

firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      group: meshlan

logging:
  level: info
  format: text
`, yamlPath(state.CACertificatePath), yamlPath(state.CertificatePath), yamlPath(state.PrivateKeyPath), renderBlocklistYAML(state.RevokedFingerprints), strings.TrimRight(staticMaps.String(), "\n"), strings.TrimRight(lighthouseHosts.String(), "\n"), lighthousePolicy, listenHost, clientListenPort(state), strings.TrimRight(relayHosts.String(), "\n"), !state.ForceP2P), nil
}

func effectiveLighthouseEndpoints(pairing *PairResponse) []LighthouseEndpoint {
	if pairing == nil {
		return nil
	}
	lighthouses := append([]LighthouseEndpoint(nil), pairing.Lighthouses...)
	if len(lighthouses) == 0 {
		lighthouses = []LighthouseEndpoint{{ID: "primary", Name: "主节点", Address: pairing.LighthouseAddress, Endpoint: pairing.LighthouseEndpoint, Primary: true, Relay: true}}
	}
	return lighthouses
}

func ensureNoTraversal(name string) error {
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\\`) {
		return errors.New("名称包含非法路径字符")
	}
	return nil
}
