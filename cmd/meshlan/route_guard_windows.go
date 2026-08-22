//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const routeGuardVersion = 9

func routeGuardPaths(state ClientState) (scriptPath, statusPath string) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	root := filepath.Join(programData, "MeshLANNebula")
	return filepath.Join(root, "route-guard.ps1"), filepath.Join(root, "route-guard-status.json")
}

func writeRouteGuardScript(state ClientState) (scriptPath, statusPath string, err error) {
	if state.ConfigPath == "" {
		return "", "", errors.New("客户端配置路径为空")
	}
	_, statusPath = routeGuardPaths(state)
	scriptPath = filepath.Join(filepath.Dir(state.ConfigPath), "route-guard.pending.ps1")
	if err := os.WriteFile(scriptPath, []byte(routeGuardPowerShell), 0o600); err != nil {
		return "", "", err
	}
	return scriptPath, statusPath, nil
}

func readRouteGuardStatus(state ClientState) RouteGuardStatus {
	_, statusPath := routeGuardPaths(state)
	var status RouteGuardStatus
	readable := false
	if data, err := os.ReadFile(statusPath); err == nil {
		data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
		readable = json.Unmarshal(data, &status) == nil && status.Version > 0
	}
	if !readable {
		if inferred, ok := inferLiveRouteGuard(state); ok {
			inferred.LastError = "状态文件暂不可读，当前结果由实时路由推断"
			return inferred
		}
	}
	if status.Version == 0 {
		status.Version = routeGuardVersion
		status.Mode = "not_installed"
	}
	if readable && !routeGuardStatusFresh(status, time.Now().UTC()) {
		status.Mode = "not_installed"
		status.BypassReady = false
		status.LastError = "Route Guard 后台状态已停止更新"
	}
	return status
}

func routeGuardStatusFresh(status RouteGuardStatus, now time.Time) bool {
	if strings.TrimSpace(status.LastUpdated) == "" {
		return false
	}
	updated, err := time.Parse(time.RFC3339Nano, status.LastUpdated)
	return err == nil && now.Sub(updated) >= -5*time.Second && now.Sub(updated) <= 15*time.Second
}

const routeGuardPowerShell = `param(
  [Parameter(Mandatory=$true)][string]$StatePath,
  [Parameter(Mandatory=$true)][string]$StatusPath,
  [Parameter(Mandatory=$true)][string]$ClientUserSID
)

$ErrorActionPreference='Stop'
$managed=@{}
$managed6=@{}
$lastGateway=''
$lastInterfaceIndex=0
$lastGateway6=''
$lastInterfaceIndex6=0
$lastRestart=[DateTime]::MinValue
$securityAppliedVersion=0
$raceAppliedVersion=0
$dnsRecordsApplied=0
$dnsLastError=''
$lastEventScan=(Get-Date).AddMinutes(-30)
$suppressedIPv6Gateway=''
$suppressedIPv6InterfaceIndex=0
$suppressedIPv6RouteMetric=256
if(Test-Path -LiteralPath $StatusPath) {
  try {
    $previousStatus=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($StatusPath)) | ConvertFrom-Json
    $raceAppliedVersion=[uint64]$previousStatus.raceAppliedVersion
  } catch {}
}

function Save-GuardStatus {
  param(
    [string]$Mode,
    [bool]$BypassReady,
    [object]$Physical,
    [object]$Physical6,
    [string[]]$Targets,
    [string[]]$Targets6,
    [string[]]$TunInterfaces,
    [string]$PreferredP2P='auto',
    [string]$PreferredBusiness='auto',
    [bool]$BusinessActive=$false,
    [bool]$IPv6DefaultSuppressed=$false,
    [string]$BusinessAddress='',
    [string]$BusinessGateway='',
    [int]$BusinessInterfaceIndex=0,
    [string]$LastError=''
  )
  $value=[ordered]@{
    version=9
    mode=$Mode
    bypassReady=$BypassReady
    physicalInterface=$(if($null -ne $Physical){$Physical.InterfaceAlias}else{''})
    physicalAddress=$(if($null -ne $Physical){$Physical.IPAddress}else{''})
    gateway=$(if($null -ne $Physical){$Physical.Gateway}else{''})
    interfaceIndex=$(if($null -ne $Physical){$Physical.InterfaceIndex}else{0})
    targets=@($Targets)
    ipv6Interface=$(if($null -ne $Physical6){$Physical6.InterfaceAlias}else{''})
    ipv6Address=$(if($null -ne $Physical6){$Physical6.IPAddress}else{''})
    ipv6Gateway=$(if($null -ne $Physical6){$Physical6.Gateway}else{''})
    ipv6InterfaceIndex=$(if($null -ne $Physical6){$Physical6.InterfaceIndex}else{0})
    ipv6Targets=@($Targets6)
    tunInterfaces=@($TunInterfaces)
    preferredP2P=$PreferredP2P
    preferredBusiness=$PreferredBusiness
    businessActive=$BusinessActive
    ipv6DefaultSuppressed=$IPv6DefaultSuppressed
    businessAddress=$BusinessAddress
    businessGateway=$BusinessGateway
    businessInterfaceIndex=$BusinessInterfaceIndex
    lastUpdated=[DateTime]::UtcNow.ToString('o')
    lastRestart=$(if($lastRestart -gt [DateTime]::MinValue){$lastRestart.ToUniversalTime().ToString('o')}else{$null})
    lastError=$LastError
    securityAppliedVersion=[uint64]$securityAppliedVersion
    raceAppliedVersion=[uint64]$raceAppliedVersion
    dnsRecordsApplied=[int]$dnsRecordsApplied
    dnsLastError=[string]$dnsLastError
  }
  $temporary=$StatusPath+'.tmp'
  $value | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding utf8
  Move-Item -LiteralPath $temporary -Destination $StatusPath -Force
  & icacls.exe $StatusPath /inheritance:r /grant:r ('*'+$ClientUserSID+':F') '*S-1-5-18:F' /C /Q | Out-Null
}

function Test-PublicIPv4 {
  param([string]$Address)
  try {
    $bytes=([Net.IPAddress]::Parse($Address)).GetAddressBytes()
    if($bytes.Length -ne 4){return $false}
    $a=[int]$bytes[0]; $b=[int]$bytes[1]
    if($a -eq 0 -or $a -eq 10 -or $a -eq 127 -or $a -ge 224){return $false}
    if($a -eq 100 -and $b -ge 64 -and $b -le 127){return $false}
    if($a -eq 169 -and $b -eq 254){return $false}
    if($a -eq 172 -and $b -ge 16 -and $b -le 31){return $false}
    if($a -eq 192 -and $b -eq 168){return $false}
    if($a -eq 198 -and ($b -eq 18 -or $b -eq 19)){return $false}
    return $true
  } catch {
    return $false
  }
}

function Test-PublicIPv6 {
  param([string]$Address)
  try {
    $ip=[Net.IPAddress]::Parse($Address)
    if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6){return $false}
    if($ip.IsIPv6LinkLocal -or $ip.IsIPv6Multicast -or $ip.Equals([Net.IPAddress]::IPv6Loopback)){return $false}
    $bytes=$ip.GetAddressBytes()
    if(($bytes[0] -band 0xfe) -eq 0xfc){return $false}
    return $true
  } catch {
    return $false
  }
}

function Get-PhysicalIPv4Route {
  param([string]$PreferredAlias='auto')
  $candidates=@()
  foreach($configuration in @(Get-NetIPConfiguration -All -ErrorAction Stop)) {
    if($null -eq $configuration.NetAdapter -or -not $configuration.NetAdapter.HardwareInterface){continue}
    if($configuration.NetAdapter.Status -ne 'Up'){continue}
    $gateway=@($configuration.IPv4DefaultGateway | Select-Object -First 1).NextHop
    $address=@($configuration.IPv4Address | Where-Object {$_.AddressState -eq 'Preferred'} | Select-Object -First 1).IPAddress
    if(-not $gateway -or -not $address){continue}
    $metric=(Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $configuration.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceMetric
    if($null -eq $metric){$metric=9999}
    $candidates += [pscustomobject]@{
      InterfaceAlias=$configuration.InterfaceAlias
      InterfaceIndex=[int]$configuration.InterfaceIndex
      IPAddress=[string]$address
      Gateway=[string]$gateway
      Metric=[int]$metric
    }
  }
  if($PreferredAlias -and $PreferredAlias -ne 'auto') {
    $preferred=$candidates | Where-Object {$_.InterfaceAlias -eq $PreferredAlias} | Select-Object -First 1
    if($null -ne $preferred){return $preferred}
  }
  return $candidates | Sort-Object Metric | Select-Object -First 1
}

function Get-PhysicalIPv6Route {
  param([string]$PreferredAlias='auto')
  $candidates=@()
  foreach($configuration in @(Get-NetIPConfiguration -All -ErrorAction Stop)) {
    if($null -eq $configuration.NetAdapter -or -not $configuration.NetAdapter.HardwareInterface){continue}
    if($configuration.NetAdapter.Status -ne 'Up'){continue}
    $gateway=@($configuration.IPv6DefaultGateway | Select-Object -First 1).NextHop
    $address=@($configuration.IPv6Address | Where-Object {$_.AddressState -eq 'Preferred' -and -not $_.PrefixOrigin.ToString().Equals('WellKnown')} | Select-Object -First 1).IPAddress
    if(-not $gateway -or -not $address -or -not (Test-PublicIPv6 ([string]$address))){continue}
    $metric=(Get-NetIPInterface -AddressFamily IPv6 -InterfaceIndex $configuration.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceMetric
    if($null -eq $metric){$metric=9999}
    $candidates += [pscustomobject]@{
      InterfaceAlias=$configuration.InterfaceAlias
      InterfaceIndex=[int]$configuration.InterfaceIndex
      IPAddress=[string]$address
      Gateway=[string]$gateway
      Metric=[int]$metric
    }
  }
  if($PreferredAlias -and $PreferredAlias -ne 'auto') {
    $preferred=$candidates | Where-Object {$_.InterfaceAlias -eq $PreferredAlias} | Select-Object -First 1
    if($null -ne $preferred){return $preferred}
    # 业务网卡在线时可能已压制该接口的 ::/0；从现有Peer /128路由恢复网关信息。
    $routeHint=Get-NetRoute -AddressFamily IPv6 -InterfaceAlias $PreferredAlias -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
      Where-Object {$_.DestinationPrefix -like '*/128' -and $_.NextHop -ne '::'} | Select-Object -First 1
    $addressHint=Get-NetIPAddress -AddressFamily IPv6 -InterfaceAlias $PreferredAlias -ErrorAction SilentlyContinue |
      Where-Object {$_.AddressState -eq 'Preferred' -and (Test-PublicIPv6 ([string]$_.IPAddress))} | Select-Object -First 1
    $adapterHint=Get-NetAdapter -Name $PreferredAlias -ErrorAction SilentlyContinue
    if($null -ne $routeHint -and $null -ne $addressHint -and $null -ne $adapterHint -and $adapterHint.Status -eq 'Up') {
      return [pscustomobject]@{
        InterfaceAlias=$PreferredAlias
        InterfaceIndex=[int]$routeHint.InterfaceIndex
        IPAddress=[string]$addressHint.IPAddress
        Gateway=[string]$routeHint.NextHop
        Metric=9998
      }
    }
    if($null -ne $addressHint -and $null -ne $adapterHint -and $adapterHint.Status -eq 'Up') {
      $neighborHint=Get-NetNeighbor -AddressFamily IPv6 -InterfaceAlias $PreferredAlias -ErrorAction SilentlyContinue |
        Where-Object {$_.IPAddress -like 'fe80::*' -and $_.State -ne 'Unreachable'} |
        Sort-Object @{Expression={if($_.IPAddress -eq 'fe80::1'){0}else{1}}} |
        Select-Object -First 1
      if($null -ne $neighborHint) {
        return [pscustomobject]@{
          InterfaceAlias=$PreferredAlias
          InterfaceIndex=[int]$neighborHint.InterfaceIndex
          IPAddress=[string]$addressHint.IPAddress
          Gateway=[string]$neighborHint.IPAddress
          Metric=9996
        }
      }
    }
    if($suppressedIPv6Gateway -and $suppressedIPv6InterfaceIndex -gt 0 -and $null -ne $addressHint -and $null -ne $adapterHint -and $adapterHint.Status -eq 'Up') {
      return [pscustomobject]@{
        InterfaceAlias=$PreferredAlias
        InterfaceIndex=[int]$suppressedIPv6InterfaceIndex
        IPAddress=[string]$addressHint.IPAddress
        Gateway=[string]$suppressedIPv6Gateway
        Metric=9997
      }
    }
  }
  return $candidates | Sort-Object Metric | Select-Object -First 1
}

function Get-TunInterfaces {
  $names=@()
  foreach($configuration in @(Get-NetIPConfiguration -All -ErrorAction SilentlyContinue)) {
    if($null -eq $configuration.IPv4DefaultGateway -and $null -eq $configuration.IPv6DefaultGateway){continue}
    if($null -ne $configuration.NetAdapter -and $configuration.NetAdapter.HardwareInterface){continue}
    if($configuration.InterfaceAlias -eq 'MeshLAN'){continue}
    $names += [string]$configuration.InterfaceAlias
  }
  return @($names | Sort-Object -Unique)
}

function Sync-MeshDNS {
  $dnsPath=Join-Path (Split-Path -Parent $StatePath) 'mesh-dns-records.json'
  $records=@()
  $enabled=$false
  if(Test-Path -LiteralPath $dnsPath) {
    $dnsText=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($dnsPath))
    $dnsState=$dnsText | ConvertFrom-Json
    $enabled=[bool]$dnsState.enabled
    if($enabled){$records=@($dnsState.records)}
  }
  $lines=@()
  foreach($record in $records) {
    $name=([string]$record.name).Trim().ToLowerInvariant()
    $address=([string]$record.address).Trim()
    $parsed=$null
    if(-not [Net.IPAddress]::TryParse($address,[ref]$parsed)){continue}
    if($name -notmatch '^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.mesh$'){continue}
    $lines += ($address+' '+$name)
  }
  $lines=@($lines | Sort-Object -Unique)
  $hostsPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
  $current=[IO.File]::ReadAllText($hostsPath)
  $without=[regex]::Replace($current,'(?ms)^# BEGIN MESHLAN MANAGED\r?\n.*?^# END MESHLAN MANAGED\r?\n?','').TrimEnd()
  $desired=$without
  $newline=[Environment]::NewLine
  if($enabled -and $lines.Count -gt 0) {
    $block="# BEGIN MESHLAN MANAGED"+$newline+($lines -join $newline)+$newline+"# END MESHLAN MANAGED"
    if($desired){$desired += $newline+$newline}
    $desired += $block
  }
  $desired += $newline
  if($desired -ne $current) {
    [IO.File]::WriteAllText($hostsPath,$desired,[Text.UTF8Encoding]::new($false))
    Clear-DnsClientCache -ErrorAction SilentlyContinue
  }
  return [int]$lines.Count
}

function Add-TargetFromText {
  param([hashtable]$TargetSet,[string]$Text)
  foreach($match in [regex]::Matches($Text,'(?<![0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?=:[0-9]{1,5})')) {
    $address=[string]$match.Groups[1].Value
    if(Test-PublicIPv4 $address){$TargetSet[$address]=$true}
  }
}

function Add-IPv6TargetFromText {
  param([hashtable]$TargetSet,[string]$Text)
  foreach($match in [regex]::Matches($Text,'\[([0-9A-Fa-f:]+)\](?=:[0-9]{1,5})')) {
    $address=[string]$match.Groups[1].Value
    if(Test-PublicIPv6 $address){$TargetSet[$address]=$true}
  }
}

while($true) {
  $physical=$null
  $physical6=$null
  $p2pPreference='auto'
  $businessPreference='auto'
  $businessActive=$false
  $ipv6DefaultSuppressed=$false
  $businessAddress=''
  $businessGateway=''
  $businessInterfaceIndex=0
  try {
    $stateText=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($StatePath))
    $state=$stateText | ConvertFrom-Json
    $requestedSecurityVersion=[uint64]$state.revocationVersion
    $requestedRaceVersion=[uint64]$state.raceRequestVersion
    try {
      $dnsRecordsApplied=Sync-MeshDNS
      $dnsLastError=''
    } catch {
      $dnsRecordsApplied=0
      $dnsLastError=$_.Exception.Message
    }
    $p2pPreference=[string]$state.preferredP2PInterface
    $businessPreference=[string]$state.preferredBusinessInterface
    if(-not $p2pPreference){$p2pPreference='auto'}
    if(-not $businessPreference){$businessPreference='auto'}
    if($businessPreference -ne 'auto') {
      $businessConfig=Get-NetIPConfiguration -InterfaceAlias $businessPreference -ErrorAction SilentlyContinue
      if($null -ne $businessConfig -and $null -ne $businessConfig.NetAdapter -and $businessConfig.NetAdapter.HardwareInterface -and $businessConfig.NetAdapter.Status -eq 'Up' -and $null -ne $businessConfig.IPv4DefaultGateway) {
        Set-NetIPInterface -InterfaceAlias $businessPreference -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 5 -ErrorAction SilentlyContinue
        if($null -ne $businessConfig.IPv6DefaultGateway) {
          Set-NetIPInterface -InterfaceAlias $businessPreference -AddressFamily IPv6 -AutomaticMetric Disabled -InterfaceMetric 5 -ErrorAction SilentlyContinue
        }
        $businessActive=$true
        $businessAddress=[string]($businessConfig.IPv4Address | Where-Object {$_.AddressState -eq 'Preferred'} | Select-Object -First 1 -ExpandProperty IPAddress)
        $businessGateway=[string]($businessConfig.IPv4DefaultGateway | Select-Object -First 1 -ExpandProperty NextHop)
        $businessInterfaceIndex=[int]$businessConfig.InterfaceIndex
      }
    }
    $physical=Get-PhysicalIPv4Route -PreferredAlias $p2pPreference
    $physical6=Get-PhysicalIPv6Route -PreferredAlias $p2pPreference
    if($businessActive -and $p2pPreference -ne 'auto' -and $null -ne $physical6 -and $physical6.InterfaceAlias -eq $p2pPreference) {
      $default6=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $p2pPreference -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
      if($default6.Count -gt 0) {
        $selectedDefault=$default6 | Select-Object -First 1
        $suppressedIPv6Gateway=[string]$selectedDefault.NextHop
        $suppressedIPv6InterfaceIndex=[int]$selectedDefault.InterfaceIndex
        $suppressedIPv6RouteMetric=[int]$selectedDefault.RouteMetric
        $default6 | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
      }
      $ipv6DefaultSuppressed=(@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $p2pPreference -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count -eq 0)
    } elseif(-not $businessActive -and $p2pPreference -ne 'auto') {
      $existingDefault6=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceAlias $p2pPreference -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
      if($existingDefault6.Count -eq 0) {
        $restoreGateway=$suppressedIPv6Gateway
        $restoreIndex=$suppressedIPv6InterfaceIndex
        $restoreMetric=$suppressedIPv6RouteMetric
        if(-not $restoreGateway) {
          $hint=Get-NetRoute -AddressFamily IPv6 -InterfaceAlias $p2pPreference -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object {$_.DestinationPrefix -like '*/128' -and $_.NextHop -ne '::'} | Select-Object -First 1
          if($null -ne $hint) {
            $restoreGateway=[string]$hint.NextHop
            $restoreIndex=[int]$hint.InterfaceIndex
          }
        }
        if($restoreGateway -and $restoreIndex -gt 0) {
          New-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -InterfaceIndex $restoreIndex -NextHop $restoreGateway -RouteMetric $restoreMetric -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
        }
      }
    }
    $tunInterfaces=@(Get-TunInterfaces)
    if($null -eq $physical -and $null -eq $physical6) {
      Save-GuardStatus -Mode 'no_physical_gateway' -BypassReady $false -Physical $null -Physical6 $null -Targets @() -Targets6 @() -TunInterfaces $tunInterfaces -PreferredP2P $p2pPreference -PreferredBusiness $businessPreference -BusinessActive $businessActive -IPv6DefaultSuppressed $ipv6DefaultSuppressed -BusinessAddress $businessAddress -BusinessGateway $businessGateway -BusinessInterfaceIndex $businessInterfaceIndex -LastError 'No active hardware gateway'
      Start-Sleep -Seconds 3
      continue
    }

    if($null -ne $physical -and $lastInterfaceIndex -ne 0 -and ($lastInterfaceIndex -ne $physical.InterfaceIndex -or $lastGateway -ne $physical.Gateway)) {
      foreach($oldAddress in @($managed.Keys)) {
        $oldPrefix=$oldAddress+'/32'
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $oldPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
          Where-Object {$_.Protocol -eq 'NetMgmt'} |
          Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
      }
      $managed=@{}
    }
    if($null -ne $physical) {
      $lastInterfaceIndex=$physical.InterfaceIndex
      $lastGateway=$physical.Gateway
    }
    if($null -ne $physical6 -and $lastInterfaceIndex6 -ne 0 -and ($lastInterfaceIndex6 -ne $physical6.InterfaceIndex -or $lastGateway6 -ne $physical6.Gateway)) {
      foreach($oldAddress in @($managed6.Keys)) {
        $oldPrefix=$oldAddress+'/128'
        Get-NetRoute -AddressFamily IPv6 -DestinationPrefix $oldPrefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
          Where-Object {$_.Protocol -eq 'NetMgmt'} |
          Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
      }
      $managed6=@{}
    }
    if($null -ne $physical6) {
      $lastInterfaceIndex6=$physical6.InterfaceIndex
      $lastGateway6=$physical6.Gateway
    }

    $diagnosticTargets6=@{}
    try {
      $diagnosticExpiry=[DateTime]::Parse([string]$state.diagnosticTargetsExpiresAt).ToUniversalTime()
      if($diagnosticExpiry -gt [DateTime]::UtcNow) {
        foreach($candidate in @($state.diagnosticIPv6Targets)) {
          $address=[string]$candidate
          if(Test-PublicIPv6 $address){$diagnosticTargets6[$address]=$true}
        }
      }
    } catch {}
    if($null -ne $physical6) {
      $diagnosticRoutes=@(Get-NetRoute -AddressFamily IPv6 -InterfaceIndex $physical6.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -like '*/128' -and $_.RouteMetric -eq 2 -and $_.Protocol -eq 'NetMgmt'})
      foreach($route in $diagnosticRoutes) {
        $address=([string]$route.DestinationPrefix).Split('/')[0]
        if(-not $diagnosticTargets6.ContainsKey($address)) {$route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue}
      }
      foreach($address in @($diagnosticTargets6.Keys)) {
        $prefix=$address+'/128'
        $existing=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix $prefix -InterfaceIndex $physical6.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {$_.NextHop -eq $physical6.Gateway})
        if($existing.Count -eq 0) {New-NetRoute -AddressFamily IPv6 -DestinationPrefix $prefix -InterfaceIndex $physical6.InterfaceIndex -NextHop $physical6.Gateway -RouteMetric 2 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null}
      }
    }

    $targets=@{}
    $targets6=@{}
    $controlHost=[string]$state.pairing.controlHost
    if(Test-PublicIPv4 $controlHost){$targets[$controlHost]=$true}
    Add-TargetFromText -TargetSet $targets -Text ([string]$state.pairing.lighthouseEndpoint)
    foreach($node in @($state.pairing.lighthouses)) {
      Add-TargetFromText -TargetSet $targets -Text ([string]$node.endpoint)
      Add-IPv6TargetFromText -TargetSet $targets6 -Text ([string]$node.endpoint)
    }

    $scanEnd=Get-Date
    foreach($event in @(Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Nebula';StartTime=$lastEventScan} -MaxEvents 300 -ErrorAction SilentlyContinue)) {
      if($event.Message -notmatch 'udpAddrs=|Handshake message received'){continue}
      Add-TargetFromText -TargetSet $targets -Text ([string]$event.Message)
      Add-IPv6TargetFromText -TargetSet $targets6 -Text ([string]$event.Message)
    }
    $lastEventScan=$scanEnd
    foreach($address in @($managed.Keys)) {$targets[$address]=$true}
    foreach($address in @($managed6.Keys)) {$targets6[$address]=$true}

    $routeChanged=$false
    foreach($address in $(if($null -ne $physical){@($targets.Keys)}else{@()})) {
      $prefix=$address+'/32'
      $routes=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
      foreach($route in $routes) {
        if($route.InterfaceIndex -ne $physical.InterfaceIndex -or $route.NextHop -ne $physical.Gateway) {
          $route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
          $routeChanged=$true
        }
      }
      $desired=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $physical.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {$_.NextHop -eq $physical.Gateway})
      if($desired.Count -eq 0) {
        New-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $physical.InterfaceIndex -NextHop $physical.Gateway -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        $routeChanged=$true
      }
      $managed[$address]=$true
    }
    foreach($address in $(if($null -ne $physical6){@($targets6.Keys)}else{@()})) {
      $prefix=$address+'/128'
      $routes=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
      foreach($route in $routes) {
        if($route.InterfaceIndex -ne $physical6.InterfaceIndex -or $route.NextHop -ne $physical6.Gateway) {
          $route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
          $routeChanged=$true
        }
      }
      $desired=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix $prefix -InterfaceIndex $physical6.InterfaceIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {$_.NextHop -eq $physical6.Gateway})
      if($desired.Count -eq 0) {
        New-NetRoute -AddressFamily IPv6 -DestinationPrefix $prefix -InterfaceIndex $physical6.InterfaceIndex -NextHop $physical6.Gateway -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        $routeChanged=$true
      }
      $managed6[$address]=$true
    }

    $targetList=@($targets.Keys | Sort-Object)
    $targetList6=@($targets6.Keys | Sort-Object)
    $securityChanged=($requestedSecurityVersion -gt $securityAppliedVersion)
    $raceChanged=($requestedRaceVersion -gt $raceAppliedVersion)
    if(($routeChanged -or $securityChanged -or $raceChanged) -and ($securityChanged -or $raceChanged -or ((Get-Date)-$lastRestart).TotalSeconds -ge 15)) {
      $service=Get-Service -Name Nebula -ErrorAction SilentlyContinue
      if($null -ne $service) {
        if($service.Status -eq 'Running') {Restart-Service -Name Nebula -Force -ErrorAction Stop}
        else {Start-Service -Name Nebula -ErrorAction Stop}
        $lastRestart=Get-Date
      }
      $securityAppliedVersion=$requestedSecurityVersion
      $raceAppliedVersion=$requestedRaceVersion
    }
    Save-GuardStatus -Mode 'guarding' -BypassReady (($targetList.Count+$targetList6.Count) -gt 0) -Physical $physical -Physical6 $physical6 -Targets $targetList -Targets6 $targetList6 -TunInterfaces $tunInterfaces -PreferredP2P $p2pPreference -PreferredBusiness $businessPreference -BusinessActive $businessActive -IPv6DefaultSuppressed $ipv6DefaultSuppressed -BusinessAddress $businessAddress -BusinessGateway $businessGateway -BusinessInterfaceIndex $businessInterfaceIndex
  } catch {
    Save-GuardStatus -Mode 'error' -BypassReady $false -Physical $physical -Physical6 $physical6 -Targets @($managed.Keys) -Targets6 @($managed6.Keys) -TunInterfaces @() -PreferredP2P $p2pPreference -PreferredBusiness $businessPreference -BusinessActive $businessActive -IPv6DefaultSuppressed $ipv6DefaultSuppressed -BusinessAddress $businessAddress -BusinessGateway $businessGateway -BusinessInterfaceIndex $businessInterfaceIndex -LastError $_.Exception.Message
  }
  Start-Sleep -Seconds 2
}
`
