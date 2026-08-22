[CmdletBinding()]
param(
    [ValidateRange(500, 10000)]
    [int]$TimeoutMs = 2500,

    [ValidateRange(1, 10080)]
    [int]$HistoryMinutes = 1440,

    [switch]$SkipNebulaHistory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-UInt16BE {
    param([byte[]]$Data, [int]$Offset)
    return (([int]$Data[$Offset] -shl 8) -bor [int]$Data[$Offset + 1])
}

function New-StunBindingRequest {
    $request = New-Object byte[] 20
    $request[0] = 0x00
    $request[1] = 0x01
    $request[2] = 0x00
    $request[3] = 0x00
    $request[4] = 0x21
    $request[5] = 0x12
    $request[6] = 0xA4
    $request[7] = 0x42

    $transactionId = New-Object byte[] 12
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($transactionId)
    } finally {
        $rng.Dispose()
    }
    [Array]::Copy($transactionId, 0, $request, 8, 12)
    return [pscustomobject]@{ Request = $request; TransactionId = $transactionId }
}

function Test-TransactionId {
    param([byte[]]$Data, [byte[]]$TransactionId)
    if ($Data.Length -lt 20) { return $false }
    for ($i = 0; $i -lt 12; $i++) {
        if ($Data[8 + $i] -ne $TransactionId[$i]) { return $false }
    }
    return $true
}

function Read-StunMappedAddress {
    param([byte[]]$Data)

    if ($Data.Length -lt 20) { return $null }
    $messageLength = Get-UInt16BE -Data $Data -Offset 2
    $limit = [Math]::Min($Data.Length, 20 + $messageLength)
    $offset = 20
    $fallback = $null

    while ($offset + 4 -le $limit) {
        $attributeType = Get-UInt16BE -Data $Data -Offset $offset
        $attributeLength = Get-UInt16BE -Data $Data -Offset ($offset + 2)
        $valueOffset = $offset + 4
        if ($valueOffset + $attributeLength -gt $limit) { break }

        if (($attributeType -eq 0x0020 -or $attributeType -eq 0x0001) -and $attributeLength -ge 8) {
            $family = $Data[$valueOffset + 1]
            if ($family -eq 0x01) {
                $port = Get-UInt16BE -Data $Data -Offset ($valueOffset + 2)
                $addressBytes = New-Object byte[] 4
                for ($i = 0; $i -lt 4; $i++) {
                    $addressBytes[$i] = $Data[$valueOffset + 4 + $i]
                }

                if ($attributeType -eq 0x0020) {
                    $port = $port -bxor 0x2112
                    $cookie = [byte[]](0x21, 0x12, 0xA4, 0x42)
                    for ($i = 0; $i -lt 4; $i++) {
                        $addressBytes[$i] = $addressBytes[$i] -bxor $cookie[$i]
                    }
                }

                $mapped = [pscustomobject]@{
                    Address = ([Net.IPAddress]::new($addressBytes)).ToString()
                    Port = [int]$port
                }
                if ($attributeType -eq 0x0020) { return $mapped }
                $fallback = $mapped
            }
        }

        $offset = $valueOffset + $attributeLength
        $padding = (4 - ($attributeLength % 4)) % 4
        $offset += $padding
    }
    return $fallback
}

function Invoke-StunBinding {
    param(
        [Net.Sockets.UdpClient]$Socket,
        [Net.IPEndPoint]$Server,
        [string]$Name
    )

    $packet = New-StunBindingRequest
    [void]$Socket.Send($packet.Request, $packet.Request.Length, $Server)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)

    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            $response = $Socket.Receive([ref]$remote)
            if (-not (Test-TransactionId -Data $response -TransactionId $packet.TransactionId)) {
                continue
            }
            $mapped = Read-StunMappedAddress -Data $response
            if ($null -eq $mapped) {
                return [pscustomobject]@{ Server = $Name; Destination = $Server.ToString(); Success = $false; PublicEndpoint = ''; Error = '响应中没有IPv4映射地址' }
            }
            return [pscustomobject]@{
                Server = $Name
                Destination = $Server.ToString()
                Success = $true
                PublicEndpoint = "{0}:{1}" -f $mapped.Address, $mapped.Port
                Error = ''
            }
        } catch [Net.Sockets.SocketException] {
            break
        }
    }
    return [pscustomobject]@{ Server = $Name; Destination = $Server.ToString(); Success = $false; PublicEndpoint = ''; Error = 'UDP STUN超时' }
}

function Get-PhysicalIPv4Configuration {
    $candidates = foreach ($configuration in @(Get-NetIPConfiguration -All -ErrorAction Stop)) {
        if ($null -eq $configuration.NetAdapter -or -not $configuration.NetAdapter.HardwareInterface) { continue }
        if ($configuration.NetAdapter.Status -ne 'Up') { continue }
        $gatewayEntry = $configuration.IPv4DefaultGateway | Select-Object -First 1
        $addressEntry = $configuration.IPv4Address | Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
        $gateway = if ($null -ne $gatewayEntry) { [string]$gatewayEntry.NextHop } else { '' }
        $address = if ($null -ne $addressEntry) { [string]$addressEntry.IPAddress } else { '' }
        if (-not $gateway -or -not $address) { continue }
        $metric = (Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $configuration.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceMetric
        if ($null -eq $metric) { $metric = 9999 }
        [pscustomobject]@{
            InterfaceAlias = $configuration.InterfaceAlias
            InterfaceIndex = [int]$configuration.InterfaceIndex
            Address = [string]$address
            Gateway = [string]$gateway
            Metric = [int]$metric
        }
    }
    return $candidates | Sort-Object Metric | Select-Object -First 1
}

function Test-UsableInternetIPv4 {
    param([Net.IPAddress]$Address)
    if ($null -eq $Address -or $Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $bytes = $Address.GetAddressBytes()
    $a = [int]$bytes[0]
    $b = [int]$bytes[1]
    if ($a -eq 0 -or $a -eq 10 -or $a -eq 127 -or $a -ge 224) { return $false }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $false }
    if ($a -eq 169 -and $b -eq 254) { return $false }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $false }
    if ($a -eq 192 -and $b -eq 168) { return $false }
    if ($a -eq 198 -and ($b -eq 18 -or $b -eq 19)) { return $false }
    return $true
}

function Resolve-StunIPv4 {
    param([string]$HostName)

    try {
        $systemAddress = [Net.Dns]::GetHostAddresses($HostName) |
            Where-Object { Test-UsableInternetIPv4 $_ } |
            Select-Object -First 1
        if ($null -ne $systemAddress) { return $systemAddress }
    } catch {
    }

    # Clash/Mihomo/sing-box Fake-IP常返回198.18.0.0/15；DoH只用于取得真实目标IP，
    # 随后的STUN UDP仍由绑定的物理网卡发送。
    try {
        $uri = 'https://cloudflare-dns.com/dns-query?name={0}&type=A' -f [Uri]::EscapeDataString($HostName)
        $response = Invoke-RestMethod -UseBasicParsing -Uri $uri -Headers @{ Accept = 'application/dns-json' } -TimeoutSec 10
        foreach ($answer in @($response.Answer | Where-Object { $_.type -eq 1 })) {
            $address = $null
            if ([Net.IPAddress]::TryParse([string]$answer.data, [ref]$address) -and (Test-UsableInternetIPv4 $address)) {
                return $address
            }
        }
    } catch {
    }
    return $null
}

function Get-NebulaIPv4History {
    if ($SkipNebulaHistory) { return @() }
    try {
        $start = (Get-Date).AddMinutes(-$HistoryMinutes)
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Nebula'; StartTime = $start } -MaxEvents 1200 -ErrorAction Stop
        $matches = foreach ($event in $events) {
            if ($event.Message -notlike '*Handshake message received*' -or $event.Message -match '\(relayed\)') { continue }
            $match = [regex]::Match($event.Message, 'vpnAddrs=\[(?<vpn>(?:\d{1,3}\.){3}\d{1,3})\].*?from="?(?<ip>(?:\d{1,3}\.){3}\d{1,3}):(?<port>\d+)')
            if (-not $match.Success -or $match.Groups['vpn'].Value -eq '10.77.0.1') { continue }
            [pscustomobject]@{
                Time = $event.TimeCreated
                Peer = $match.Groups['vpn'].Value
                PublicEndpoint = '{0}:{1}' -f $match.Groups['ip'].Value, $match.Groups['port'].Value
            }
        }
        return @($matches)
    } catch {
        return @()
    }
}

Write-Host '=== IPv4 P2P 打洞检测 ===' -ForegroundColor Cyan

$physical = Get-PhysicalIPv4Configuration
if ($null -eq $physical) {
    Write-Host '结论：无法检测（未找到带IPv4默认网关的物理网卡）' -ForegroundColor Red
    exit 3
}

$tunInterfaces = @(
    Get-NetIPConfiguration -All -ErrorAction SilentlyContinue |
        Where-Object {
            $null -ne $_.IPv4DefaultGateway -and
            ($null -eq $_.NetAdapter -or -not $_.NetAdapter.HardwareInterface) -and
            $_.InterfaceAlias -ne 'MeshLAN'
        } |
        Select-Object -ExpandProperty InterfaceAlias -Unique
)

Write-Host ("物理网卡：{0} / {1} / 网关 {2}" -f $physical.InterfaceAlias, $physical.Address, $physical.Gateway)
if ($tunInterfaces.Count -gt 0) {
    Write-Host ("检测到TUN：{0}；测试套接字将强制绑定物理网卡。" -f ($tunInterfaces -join ', ')) -ForegroundColor Yellow
}

$history = @(Get-NebulaIPv4History)
if ($history.Count -gt 0) {
    $latest = $history | Select-Object -First 1
    Write-Host ("Nebula历史：已确认IPv4直连，Peer {0}，公网端点 {1}，时间 {2}" -f $latest.Peer, $latest.PublicEndpoint, $latest.Time) -ForegroundColor Green
} else {
    Write-Host 'Nebula历史：指定时间内没有已确认的IPv4 Peer直连。'
}

$targets = @(
    [pscustomobject]@{ Name = 'Cloudflare'; Host = 'stun.cloudflare.com'; Port = 3478 },
    [pscustomobject]@{ Name = 'Google'; Host = 'stun.l.google.com'; Port = 19302 },
    [pscustomobject]@{ Name = 'Twilio'; Host = 'global.stun.twilio.com'; Port = 3478 }
)

$resolvedTargets = @()
$usedAddresses = @{}
foreach ($target in $targets) {
    try {
        $address = Resolve-StunIPv4 -HostName $target.Host
        if ($null -eq $address -or $usedAddresses.ContainsKey($address.ToString())) { continue }
        $usedAddresses[$address.ToString()] = $true
        $resolvedTargets += [pscustomobject]@{ Name = $target.Name; EndPoint = [Net.IPEndPoint]::new($address, $target.Port) }
    } catch {
        Write-Host ("无法解析 {0}: {1}" -f $target.Host, $_.Exception.Message) -ForegroundColor DarkYellow
    }
}

if ($resolvedTargets.Count -lt 2) {
    Write-Host '结论：无法检测（可用的独立IPv4 STUN目标不足2个）' -ForegroundColor Red
    exit 3
}

$udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
try {
    $interfaceForced = $false
    try {
        $networkOrderIndex = [Net.IPAddress]::HostToNetworkOrder([int]$physical.InterfaceIndex)
        # Windows IP_UNICAST_IF=31；旧版.NET Framework未公开UnicastInterface枚举名。
        $udp.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]31, [int]$networkOrderIndex)
        $interfaceForced = $true
    } catch {
        Write-Host '警告：无法设置IP_UNICAST_IF，仍会绑定物理IPv4地址。' -ForegroundColor Yellow
    }
    $udp.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($physical.Address), 0))
    $udp.Client.ReceiveTimeout = $TimeoutMs
    $localEndpoint = [Net.IPEndPoint]$udp.Client.LocalEndPoint
    Write-Host ("本地测试端口：{0}:{1}；强制物理接口：{2}" -f $localEndpoint.Address, $localEndpoint.Port, $interfaceForced)

    $results = foreach ($target in $resolvedTargets) {
        Invoke-StunBinding -Socket $udp -Server $target.EndPoint -Name $target.Name
    }
} finally {
    $udp.Dispose()
}

$results | Format-Table Server, Destination, Success, PublicEndpoint, Error -AutoSize
$successful = @($results | Where-Object Success)

if ($history.Count -gt 0) {
    Write-Host '结论：IPv4 P2P 打洞【支持，已有真实Nebula直连证据】' -ForegroundColor Green
    Write-Host '说明：该结论只确认与历史Peer的NAT组合；换一个对称NAT Peer仍可能失败。'
    exit 0
}

if ($successful.Count -lt 2) {
    Write-Host '结论：IPv4 P2P 打洞【无法判断】' -ForegroundColor Red
    Write-Host '原因：至少两个独立STUN目标没有返回结果，可能是UDP被阻止、DNS故障或网络暂时不可用。'
    exit 3
}

$uniqueMappings = @($successful.PublicEndpoint | Sort-Object -Unique)
if ($uniqueMappings.Count -eq 1) {
    Write-Host '结论：IPv4 P2P 打洞【大概率支持】' -ForegroundColor Green
    Write-Host ("依据：同一UDP端口访问多个目标时公网映射保持为 {0}，属于端点无关或可预测映射。" -f $uniqueMappings[0])
    Write-Host '注意：单机STUN无法绝对证明任意两台Peer一定成功；最终仍以真实双端握手为准。'
    exit 0
}

Write-Host '结论：IPv4 P2P 打洞【不支持稳定直连】' -ForegroundColor Red
Write-Host ("依据：同一UDP端口访问不同目标得到不同公网映射：{0}" -f ($uniqueMappings -join ', '))
Write-Host '这符合端点相关/对称NAT特征；需要IPv6、公网端口转发或Relay。'
exit 2
