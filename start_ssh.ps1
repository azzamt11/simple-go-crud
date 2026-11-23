$ErrorActionPreference = "Stop"

$ssh = Get-Command ssh -ErrorAction SilentlyContinue
if (-not $ssh) {
    Write-Error "OpenSSH client (ssh) was not found. Install or enable the Windows OpenSSH Client first."
    exit 1
}

$envPath = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    Write-Error "Environment file not found: $envPath"
    exit 1
}

$envValues = @{}
foreach ($line in Get-Content -LiteralPath $envPath) {
    if ($line -match '^\s*(?:#|$)') {
        continue
    }

    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') {
        $name = $Matches[1]
        $value = $Matches[2]
        if ($value.Length -ge 2 -and
            (($value.StartsWith('"') -and $value.EndsWith('"')) -or
             ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $envValues[$name] = $value
    }
}

$port = 22
if ($envValues.ContainsKey("SSH_PORT") -and
    (-not [int]::TryParse($envValues["SSH_PORT"], [ref]$port) -or $port -lt 1 -or $port -gt 65535)) {
    Write-Error "SSH_PORT in .env must be a number from 1 to 65535."
    exit 1
}

$hostName = $envValues["IP"]
$userName = $envValues["USERNAME"]
if ([string]::IsNullOrWhiteSpace($hostName) -or [string]::IsNullOrWhiteSpace($userName)) {
    Write-Error "Set non-empty IP and USERNAME values in .env."
    exit 1
}

$arguments = @(
    "-p", "$port",
    "-o", "StrictHostKeyChecking=accept-new"
)
$keyPath = $envValues["SSH_KEY_PATH"]
if (-not [string]::IsNullOrWhiteSpace($keyPath)) {
    if (-not [System.IO.Path]::IsPathRooted($keyPath)) {
        $keyPath = Join-Path $PSScriptRoot $keyPath
    }
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        Write-Error "Private key file not found: $keyPath"
        exit 1
    }
    $arguments += @("-i", $keyPath)
}

$arguments += "$userName@$hostName"
& $ssh.Source @arguments
exit $LASTEXITCODE
