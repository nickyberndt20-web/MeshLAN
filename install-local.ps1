param(
    [string]$Source = '',
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not $Source) {
    $Source = (Resolve-Path 'dist\MeshLAN-Nebula-Windows.exe').Path
} else {
    $Source = (Resolve-Path $Source).Path
}
$installRoot = Join-Path $env:LOCALAPPDATA 'MeshLANNebula\app'
$destination = Join-Path $installRoot 'MeshLAN-Nebula-Windows.exe'
$backup = Join-Path $installRoot 'MeshLAN-Nebula-Windows.previous-manual.exe'
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null

Get-Process -Name 'MeshLAN-Nebula-Windows','MeshLAN' -ErrorAction SilentlyContinue |
    Stop-Process -Force
Start-Sleep -Milliseconds 500

if (Test-Path -LiteralPath $destination) {
    Copy-Item -LiteralPath $destination -Destination $backup -Force
}
$staging = $destination + '.new'
Copy-Item -LiteralPath $Source -Destination $staging -Force
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Source).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $staging).Hash) {
    Remove-Item -LiteralPath $staging -Force
    throw 'Installed client hash verification failed'
}
Move-Item -LiteralPath $staging -Destination $destination -Force

if (-not $NoStart) {
    Start-Process -WindowStyle Hidden -FilePath $destination -WorkingDirectory $installRoot
}
Write-Host "Installed client: $destination"
