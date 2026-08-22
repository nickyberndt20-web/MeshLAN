param([string]$Root = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$binaryExtensions = @('.png','.jpg','.jpeg','.gif','.ico','.syso','.exe','.dll','.zip','.gz','.sqlite','.db')
$patterns = [ordered]@{
    'private key block' = '(?s)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
    'GitHub token' = '\bgh[pousr]_[A-Za-z0-9]{30,}\b'
    'OpenAI-style key' = '\bsk-[A-Za-z0-9_-]{20,}\b'
    'API credential assignment' = '(?i)\b(?:api[_-]?key|token|secret)\s*[:=]\s*["''][A-Za-z0-9_./+-]{20,}["'']'
    'pairing code' = '\bMLN1\.[A-Za-z0-9_-]{40,}\b'
    'node enrollment code' = '\bMLNODE1\.[A-Za-z0-9_-]{40,}\b'
    'AWS access key' = '\bAKIA[0-9A-Z]{16}\b'
    'production identifier' = '(?i)\b(?:129\.146\.52\.193|183\.87\.138\.23|admin\.apivix\.com|oci_rga|desktop-c8ro4aq|zhaoxu)\b'
}

$findings = @()
Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force |
    Where-Object {
        $_.FullName -notmatch '[\\/]\.git[\\/]' -and
        $_.FullName -notmatch '[\\/](?:\.gocache|\.gomodcache|\.playwright-cli|dist|output|work)[\\/]' -and
        $_.FullName -ne $PSCommandPath -and
        $binaryExtensions -notcontains $_.Extension.ToLowerInvariant()
    } |
    ForEach-Object {
        $content = [IO.File]::ReadAllText($_.FullName)
        $relativePath = $_.FullName.Substring($rootPath.Length).TrimStart([char[]]@([char]92,[char]47))
        foreach ($entry in $patterns.GetEnumerator()) {
            if ([regex]::IsMatch($content, $entry.Value)) {
                $findings += [pscustomobject]@{
                    File = $relativePath
                    Rule = $entry.Key
                }
            }
        }
    }

if ($findings.Count -gt 0) {
    $findings | Sort-Object File,Rule | Format-Table -AutoSize
    throw "Public secret scan failed with $($findings.Count) finding(s)."
}

Write-Host 'Public secret scan passed.'
