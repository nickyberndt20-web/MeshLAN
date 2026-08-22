//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func updateHTTPClient(state ClientState) (*http.Client, error) {
	if state.Pairing == nil || state.Pairing.ControlPin == "" {
		return nil, errors.New("本机尚未完成配对")
	}
	tlsConfig, err := pinnedTLSConfig(state.Pairing.ControlPin)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, DisableCompression: true}, Timeout: 10 * time.Minute}, nil
}

func updateRequest(state ClientState, method, path string) (*http.Request, error) {
	if state.Pairing == nil || state.Pairing.DeviceToken == "" {
		return nil, errors.New("本机尚未完成配对")
	}
	url := "https://" + pairingAddress(state.Pairing.ControlHost, state.Pairing.ControlPort) + path
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "MeshLAN-Device "+state.Name+":"+state.Pairing.DeviceToken)
	return request, nil
}

func (a *clientApp) checkForUpdate() (UpdateStatus, error) {
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	status := UpdateStatus{CurrentVersion: clientVersionNumber(), AutoUpdate: state.AutoUpdate, LastCheckedAt: time.Now().UTC()}
	if err != nil || state.Pairing == nil {
		status.LastError = "本机尚未完成配对"
		return status, errors.New(status.LastError)
	}
	var signed SignedUpdateManifest
	if err := deviceControlRequest(state, http.MethodGet, "/v1/update/manifest", nil, &signed); err != nil {
		status.LastError = err.Error()
		a.saveUpdateCheck(status)
		return status, err
	}
	trustedUpdateKey := state.Pairing.SecurityPublicKey
	if state.Pairing.UpdateKeyActive && state.Pairing.UpdatePublicKey != "" {
		trustedUpdateKey = state.Pairing.UpdatePublicKey
	}
	payload, err := verifyUpdateManifest(signed, trustedUpdateKey)
	if err != nil {
		status.LastError = err.Error()
		a.saveUpdateCheck(status)
		return status, err
	}
	if state.Pairing.SecurityPublicKey == "" && !state.Pairing.UpdateKeyActive {
		a.stateMu.Lock()
		latest, loadErr := a.load()
		if loadErr == nil && latest.Pairing != nil {
			latest.Pairing.SecurityPublicKey = signed.PublicKey
			_ = saveJSON(a.statePath, latest)
		}
		a.stateMu.Unlock()
	}
	status.Manifest = &payload
	status.Available = compareSemanticVersions(status.CurrentVersion, payload.Version) < 0
	status.RollbackReady = a.rollbackPackageExists()
	a.saveUpdateCheck(status)
	return status, nil
}

func (a *clientApp) saveUpdateCheck(status UpdateStatus) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil {
		return
	}
	state.LastUpdateCheck = status.LastCheckedAt
	state.LastUpdateError = status.LastError
	_ = saveJSON(a.statePath, state)
}

func (a *clientApp) setAutoUpdate(enabled bool) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	state, err := a.load()
	if err != nil {
		return err
	}
	state.AutoUpdate = enabled
	state.UpdatePreferenceVersion = updatePreferenceVersion
	return saveJSON(a.statePath, state)
}

func (a *clientApp) downloadUpdate(payload UpdateManifestPayload) (string, error) {
	if err := validateUpdateManifest(payload); err != nil {
		return "", err
	}
	a.stateMu.Lock()
	state, err := a.load()
	a.stateMu.Unlock()
	if err != nil {
		return "", err
	}
	client, err := updateHTTPClient(state)
	if err != nil {
		return "", err
	}
	updateRoot := filepath.Join(a.root, "updates")
	if err := os.MkdirAll(updateRoot, 0o700); err != nil {
		return "", err
	}
	destination := filepath.Join(updateRoot, "MeshLAN-Nebula-Windows-"+payload.Version+".exe")
	temporary := destination + ".part"
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		offset := int64(0)
		if info, statErr := os.Stat(temporary); statErr == nil {
			offset = info.Size()
			if offset > payload.Size {
				_ = os.Remove(temporary)
				offset = 0
			}
		}
		if offset == payload.Size {
			lastErr = nil
			break
		}
		request, requestErr := updateRequest(state, http.MethodGet, payload.DownloadPath)
		if requestErr != nil {
			return "", requestErr
		}
		if offset > 0 {
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		}
		if attempt > 0 {
			request.Header.Set("X-MeshLAN-No-P2P", "1")
		}
		response, requestErr := client.Do(request)
		if requestErr != nil {
			lastErr = requestErr
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		appendResponse := offset > 0 && response.StatusCode == http.StatusPartialContent
		if response.StatusCode != http.StatusOK && !appendResponse {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
			response.Body.Close()
			lastErr = fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		flags := os.O_CREATE | os.O_WRONLY
		if appendResponse {
			flags |= os.O_APPEND
		} else {
			flags |= os.O_TRUNC
			offset = 0
		}
		file, openErr := os.OpenFile(temporary, flags, 0o700)
		if openErr != nil {
			response.Body.Close()
			return "", openErr
		}
		_, copyErr := io.Copy(file, io.LimitReader(response.Body, payload.Size-offset+1))
		response.Body.Close()
		closeErr := file.Close()
		if copyErr != nil {
			lastErr = copyErr
		} else if closeErr != nil {
			lastErr = closeErr
		} else if info, statErr := os.Stat(temporary); statErr != nil {
			lastErr = statErr
		} else if info.Size() < payload.Size {
			lastErr = io.ErrUnexpectedEOF
		} else if info.Size() > payload.Size {
			_ = os.Remove(temporary)
			lastErr = errors.New("更新服务器返回的数据超过清单大小")
		} else {
			lastErr = nil
			break
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	if lastErr != nil {
		return "", fmt.Errorf("更新下载中断，已自动续传重试5次: %w", lastErr)
	}
	hash, size, err := fileSHA256(temporary)
	if err != nil || hash != payload.SHA256 || size != payload.Size {
		_ = os.Remove(temporary)
		return "", errors.New("更新包 SHA-256 或大小校验失败")
	}
	if err := verifyAuthenticode(temporary, payload.AuthenticodeThumbprint); err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	_ = os.Remove(destination)
	if err := os.Rename(temporary, destination); err != nil {
		return "", err
	}
	return destination, nil
}

func verifyAuthenticode(path, expectedThumbprint string) error {
	expectedThumbprint = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(expectedThumbprint), " ", ""))
	if expectedThumbprint == "" {
		return nil
	}
	script := fmt.Sprintf(`$s=Get-AuthenticodeSignature -LiteralPath %s; [pscustomobject]@{status=[string]$s.Status;thumbprint=[string]$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress`, psQuote(path))
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", script)
	hidden(cmd)
	output, err := cmd.Output()
	if err != nil {
		return errors.New("无法验证 Authenticode 签名")
	}
	var result struct {
		Status     string `json:"status"`
		Thumbprint string `json:"thumbprint"`
	}
	if json.Unmarshal(bytes.TrimPrefix(output, []byte{0xef, 0xbb, 0xbf}), &result) != nil || result.Status != "Valid" || !strings.EqualFold(result.Thumbprint, expectedThumbprint) {
		return errors.New("Authenticode 签名无效或发布者证书不匹配")
	}
	return nil
}

func (a *clientApp) rollbackPath() string {
	return a.executable + ".previous.exe"
}

func (a *clientApp) rollbackPackageExists() bool {
	if a.executable == "" {
		return false
	}
	_, err := os.Stat(a.rollbackPath())
	return err == nil
}

const updateHelperPowerShell = `param(
  [Parameter(Mandatory=$true)][string]$Current,
  [Parameter(Mandatory=$true)][string]$Staged,
  [Parameter(Mandatory=$true)][string]$Backup,
  [Parameter(Mandatory=$true)][int]$ParentPid,
  [Parameter(Mandatory=$true)][string]$HealthPath,
  [Parameter(Mandatory=$true)][string]$HealthToken
)
$ErrorActionPreference='Stop'
$currentFull=[IO.Path]::GetFullPath($Current)
$matchingBefore=@(Get-Process -ErrorAction SilentlyContinue | Where-Object {try{[IO.Path]::GetFullPath($_.Path) -eq $currentFull}catch{$false}})
$hadGUI=(@($matchingBefore | Where-Object {$_.MainWindowHandle -ne 0 -or $_.MainWindowTitle -eq 'MeshLAN'}).Count -gt 0)
Wait-Process -Id $ParentPid -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400
Get-Process -ErrorAction SilentlyContinue | Where-Object {try{[IO.Path]::GetFullPath($_.Path) -eq $currentFull}catch{$false}} | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400
Copy-Item -LiteralPath $Current -Destination $Backup -Force
Move-Item -LiteralPath $Staged -Destination $Current -Force
Remove-Item -LiteralPath $HealthPath -Force -ErrorAction SilentlyContinue
$child=Start-Process -FilePath $Current -ArgumentList @('client','--no-gui','--update-health-token',$HealthToken) -WindowStyle Hidden -PassThru
$healthy=$false
for($i=0;$i -lt 60;$i++) {
  Start-Sleep -Seconds 1
  if(Test-Path -LiteralPath $HealthPath) {
    $value=(Get-Content -Raw -LiteralPath $HealthPath -ErrorAction SilentlyContinue).Trim()
    if($value -eq $HealthToken){$healthy=$true;break}
  }
  if($child.HasExited){break}
}
if(-not $healthy) {
  if(-not $child.HasExited){Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue}
  Copy-Item -LiteralPath $Backup -Destination $Current -Force
  Start-Process -FilePath $Current -ArgumentList @('client','--no-gui') -WindowStyle Hidden | Out-Null
	if($hadGUI){Start-Process -FilePath $Current -ArgumentList @('client','--gui-only') | Out-Null}
  exit 2
}
Remove-Item -LiteralPath $HealthPath -Force -ErrorAction SilentlyContinue
if($hadGUI){Start-Process -FilePath $Current -ArgumentList @('client','--gui-only') | Out-Null}
exit 0
`

func (a *clientApp) scheduleExecutableSwap(stagedPath string) error {
	if a.executable == "" {
		return errors.New("无法确定当前程序路径")
	}
	healthToken, err := randomToken(24)
	if err != nil {
		return err
	}
	helperPath := filepath.Join(a.root, "apply-update.ps1")
	healthPath := filepath.Join(a.root, "update-health.txt")
	if err := os.WriteFile(helperPath, []byte(updateHelperPowerShell), 0o600); err != nil {
		return err
	}
	arguments := []string{
		"-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", helperPath,
		"-Current", a.executable, "-Staged", stagedPath, "-Backup", a.rollbackPath(),
		"-ParentPid", strconv.Itoa(os.Getpid()), "-HealthPath", healthPath, "-HealthToken", healthToken,
	}
	cmd := exec.Command("powershell.exe", arguments...)
	hidden(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		time.Sleep(600 * time.Millisecond)
		os.Exit(0)
	}()
	return nil
}

func (a *clientApp) applyAvailableUpdate() (UpdateStatus, error) {
	status, err := a.checkForUpdate()
	if err != nil {
		return status, err
	}
	if !status.Available || status.Manifest == nil {
		return status, errors.New("当前已经是最新版")
	}
	stagedPath, err := a.downloadUpdate(*status.Manifest)
	if err != nil {
		return status, err
	}
	if err := a.scheduleExecutableSwap(stagedPath); err != nil {
		return status, err
	}
	return status, nil
}

func (a *clientApp) applyRollback() error {
	if !a.rollbackPackageExists() {
		return errors.New("没有可回滚的上一版本")
	}
	rollbackStaging := filepath.Join(a.root, "updates", "rollback.exe")
	if err := copyFileAtomic(a.rollbackPath(), rollbackStaging, 0o700); err != nil {
		return err
	}
	return a.scheduleExecutableSwap(rollbackStaging)
}

func (a *clientApp) updateLoop() {
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	<-timer.C
	for {
		a.stateMu.Lock()
		state, err := a.load()
		a.stateMu.Unlock()
		if err == nil && state.AutoUpdate && state.Pairing != nil {
			status, checkErr := a.checkForUpdate()
			if checkErr == nil && status.Available {
				_, _ = a.applyAvailableUpdate()
				return
			}
		}
		time.Sleep(6 * time.Hour)
	}
}

func writeUpdateHealth(root, token string) error {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	return os.WriteFile(filepath.Join(root, "update-health.txt"), []byte(strings.TrimSpace(token)), 0o600)
}
