$ErrorActionPreference = "Stop"

$ssh = Get-Command ssh -ErrorAction SilentlyContinue
if (-not $ssh) {
    Write-Error "OpenSSH client (ssh) was not found. Install or enable the Windows OpenSSH Client first."
    exit 1
}

$hostName = Read-Host "VPS hostname or IP"
if ([string]::IsNullOrWhiteSpace($hostName)) {
    Write-Error "A VPS hostname or IP is required."
    exit 1
}

$userName = Read-Host "SSH username"
if ([string]::IsNullOrWhiteSpace($userName)) {
    Write-Error "An SSH username is required."
    exit 1
}

$portInput = Read-Host "SSH port [22]"
$port = 22
if (-not [string]::IsNullOrWhiteSpace($portInput)) {
    if (-not [int]::TryParse($portInput, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        Write-Error "SSH port must be a number from 1 to 65535."
        exit 1
    }
}

$arguments = @("-p", "$port")
$keyPath = Read-Host "Private key path (leave blank to use default/agent/password auth)"
if (-not [string]::IsNullOrWhiteSpace($keyPath)) {
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        Write-Error "Private key file not found: $keyPath"
        exit 1
    }
    $arguments += @("-i", $keyPath)
}

$arguments += "$userName@$hostName"
& $ssh.Source @arguments
exit $LASTEXITCODE
