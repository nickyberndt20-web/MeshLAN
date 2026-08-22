param(
    [string]$Version = '',
    [string]$CodeSigningThumbprint = '',
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:GOCACHE = Join-Path $PSScriptRoot '.gocache'
New-Item -ItemType Directory -Force -Path 'dist' | Out-Null
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'dist') -Filter 'MeshLAN-Setup-Windows*' -File -ErrorAction SilentlyContinue | Remove-Item -Force

if (-not $Version) {
    $Version = (Get-Content -Raw -LiteralPath 'VERSION').Trim()
}
if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw "Invalid semantic version: $Version"
}
$clientVersionValue = "meshlan-nebula/$Version"
$clientLinkerFlags = "-s -w -H=windowsgui -X main.clientVersion=$clientVersionValue"
$serverLinkerFlags = "-s -w -X main.clientVersion=$clientVersionValue"

go test ./...
if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
go vet ./...
if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }

$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'; $env:GOARCH = 'amd64'
go build -trimpath -ldflags $clientLinkerFlags -o 'dist\MeshLAN-Nebula-Windows.exe' .
if ($LASTEXITCODE -ne 0) { throw 'Windows client build failed' }
if ($CodeSigningThumbprint) {
    $normalizedThumbprint = ($CodeSigningThumbprint -replace '\s','').ToUpperInvariant()
    $certificate = @(
        Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Thumbprint -eq $normalizedThumbprint -and
                $_.HasPrivateKey -and
                $_.NotBefore -le (Get-Date) -and
                $_.NotAfter -gt (Get-Date) -and
                (@($_.EnhancedKeyUsageList.ObjectId.Value) -contains '1.3.6.1.5.5.7.3.3')
            }
    ) | Select-Object -First 1
    if ($null -eq $certificate) {
        throw "No valid code-signing certificate with private key found for thumbprint $normalizedThumbprint"
    }
    $signature = Set-AuthenticodeSignature -LiteralPath 'dist\MeshLAN-Nebula-Windows.exe' -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampUrl
    if ($signature.Status -ne 'Valid') { throw "Authenticode signing failed: $($signature.Status) - $($signature.StatusMessage)" }
    $signature = Get-AuthenticodeSignature -LiteralPath 'dist\MeshLAN-Nebula-Windows.exe'
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $normalizedThumbprint) {
        throw "Authenticode verification failed: $($signature.Status)"
    }
}
Copy-Item -Force 'dist\MeshLAN-Nebula-Windows.exe' "dist\MeshLAN-Nebula-Windows-$Version.exe"
$env:GOOS = 'linux'; $env:GOARCH = 'arm64'
go build -trimpath -ldflags $serverLinkerFlags -o 'dist\meshlan-nebula-server-linux-arm64' .
if ($LASTEXITCODE -ne 0) { throw 'Linux server build failed' }
$env:GOARCH = 'amd64'
go build -trimpath -ldflags $serverLinkerFlags -o 'dist\meshlan-nebula-server-linux-amd64' .
if ($LASTEXITCODE -ne 0) { throw 'Linux amd64 server build failed' }
Copy-Item -Force 'dist\meshlan-nebula-server-linux-arm64' 'dist\meshlan-nebula-node-linux-arm64'
Copy-Item -Force 'dist\meshlan-nebula-server-linux-amd64' 'dist\meshlan-nebula-node-linux-amd64'
Copy-Item -Force 'deploy\install-mesh-node.sh' 'dist\install-mesh-node.sh'

$versionedClient = "dist\MeshLAN-Nebula-Windows-$Version.exe"
$hashes = Get-FileHash -Algorithm SHA256 'dist\meshlan-nebula-server-linux-amd64','dist\meshlan-nebula-server-linux-arm64','dist\meshlan-nebula-node-linux-amd64','dist\meshlan-nebula-node-linux-arm64','dist\install-mesh-node.sh','dist\MeshLAN-Nebula-Windows.exe',$versionedClient
$lines = $hashes | ForEach-Object { '{0}  {1}' -f $_.Hash,(Split-Path -Leaf $_.Path) }
Set-Content -Encoding ascii -Path 'dist\SHA256SUMS.txt' -Value $lines
$releaseMetadata = [ordered]@{
    version = $Version
    clientVersion = $clientVersionValue
    builtAt = (Get-Date).ToUniversalTime().ToString('o')
    artifacts = @($hashes | ForEach-Object { [ordered]@{ name = Split-Path -Leaf $_.Path; sha256 = $_.Hash.ToLowerInvariant() } })
}
$releaseMetadata | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 -Path 'dist\release.json'
$hashes | Select-Object Path, Hash | Format-Table -AutoSize
