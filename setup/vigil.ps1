<#
.SYNOPSIS
    Runs a single-node Wazuh SIEM (manager + indexer + dashboard) on Windows
    with Docker Desktop.

.DESCRIPTION
    Wraps the official wazuh-docker single-node deployment, pinned to one
    version, and adds the steps Windows needs:
      * raises vm.max_map_count inside Docker Desktop's WSL 2 VM (the indexer
        won't start without it, and the setting resets on every reboot)
      * generates the TLS certificates the components use to talk to each other
      * binds the dashboard, indexer and API to localhost only, so only the
        agent ports (1514/1515) are reachable from your lab network

.EXAMPLE
    .\setup\vigil.ps1 up        # first run: clone, certs, start (5-10 min)
    .\setup\vigil.ps1 status    # containers + health checks
    .\setup\vigil.ps1 logs      # follow the manager log
    .\setup\vigil.ps1 down      # stop, keep all data
    .\setup\vigil.ps1 reset     # stop and DELETE all alerts and config
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("up", "down", "status", "logs", "reset")]
    [string]$Action = "up"
)

# Native commands (docker, git, curl, wsl) are checked through $LASTEXITCODE.
# "Stop" would make Windows PowerShell 5.1 abort whenever one of them merely
# writes to stderr, even with 2>$null.
$ErrorActionPreference = "Continue"

$WazuhVersion = "4.14.7"
$RepoRoot     = Split-Path -Parent $PSScriptRoot
$DockerDir    = Join-Path $RepoRoot "wazuh-docker"
$NodeDir      = Join-Path $DockerDir "single-node"
$CertDir      = Join-Path $NodeDir "config\wazuh_indexer_ssl_certs"
$Override     = Join-Path $PSScriptRoot "docker-compose.override.yml"

function Say([string]$msg)  { Write-Host "==> $msg" -ForegroundColor Magenta }
function Ok([string]$msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Warn([string]$msg) { Write-Host "    $msg" -ForegroundColor Yellow }
function Die([string]$msg)  { Write-Host "    $msg" -ForegroundColor Red; exit 1 }

# Run a native command and stop if it fails. PowerShell 5.1 doesn't stop on
# a non-zero exit code by itself.
function Run([string]$exe, [string[]]$argv) {
    & $exe @argv
    if ($LASTEXITCODE -ne 0) { Die "'$exe $($argv -join ' ')' failed (exit $LASTEXITCODE)" }
}

function Compose([string[]]$argv) {
    Push-Location $NodeDir
    try { Run "docker" (@("compose") + $argv) } finally { Pop-Location }
}

function Test-Prerequisites {
    Say "Checking prerequisites"
    foreach ($tool in "docker", "git", "curl.exe") {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            Die "$tool not found. Install Docker Desktop and Git for Windows first."
        }
    }
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) { Die "Docker isn't running. Start Docker Desktop and wait for it to say 'Engine running'." }

    $composeVersion = (& docker compose version --short) -replace "^v", ""
    if ([version]($composeVersion -replace "[^0-9.].*$", "") -lt [version]"2.24") {
        Die "Docker Compose $composeVersion is too old (need 2.24+ for the port override). Update Docker Desktop."
    }

    $memGB = [math]::Round(([int64](& docker info --format "{{.MemTotal}}")) / 1GB, 1)
    if ($memGB -lt 6) {
        Die "Docker has only $memGB GB of RAM. Wazuh needs at least 6 GB: see docs/lab-setup.md (.wslconfig)."
    } elseif ($memGB -lt 8) {
        Warn "Docker has $memGB GB of RAM. Wazuh will run, but 8 GB+ is more comfortable."
    } else {
        Ok "Docker $composeVersion, $memGB GB RAM available"
    }
}

function Set-MaxMapCount {
    # OpenSearch (the indexer) refuses to start below 262144. Docker Desktop
    # runs containers inside a WSL 2 VM called docker-desktop; the setting
    # lives there and is lost whenever that VM restarts.
    Say "Setting vm.max_map_count=262144 in Docker Desktop's VM"
    & wsl.exe -d docker-desktop -u root sysctl -w vm.max_map_count=262144 *> $null
    if ($LASTEXITCODE -ne 0) {
        Warn "Couldn't set it through wsl.exe. If the indexer keeps restarting, run:"
        Warn "  wsl -d docker-desktop -u root sysctl -w vm.max_map_count=262144"
    } else {
        Ok "done (re-applied on every 'up', since it resets on reboot)"
    }
}

function Get-WazuhDocker {
    if (Test-Path (Join-Path $DockerDir ".git")) {
        $tag = (& git -C $DockerDir describe --tags --exact-match 2>$null)
        if ($tag -ne "v$WazuhVersion") {
            Warn "wazuh-docker is at '$tag', expected v$WazuhVersion. Delete the wazuh-docker folder to re-clone."
        }
        return
    }
    Say "Downloading wazuh-docker v$WazuhVersion"
    Run "git" @("-c", "advice.detachedHead=false", "clone", "--depth", "1",
                "--branch", "v$WazuhVersion", "https://github.com/wazuh/wazuh-docker.git", $DockerDir)
}

function New-Certificates {
    if (Test-Path (Join-Path $CertDir "root-ca.pem")) {
        Ok "TLS certificates already exist"
        return
    }
    Say "Generating TLS certificates"
    Compose @("-f", "generate-indexer-certs.yml", "run", "--rm", "generator")
}

function Install-Override {
    # Compose automatically merges docker-compose.override.yml from the same
    # folder, so the upstream files stay untouched.
    Copy-Item $Override (Join-Path $NodeDir "docker-compose.override.yml") -Force -ErrorAction Stop
}

function Wait-Healthy {
    Say "Waiting for Wazuh to come up (first start takes a few minutes)"
    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-Date) -lt $deadline) {
        $code = & curl.exe -k -s -o NUL -w "%{http_code}" "https://localhost/app/login" 2>$null
        if ($code -eq "200") { Ok "dashboard is answering"; return }
        Start-Sleep -Seconds 10
        Write-Host "." -NoNewline
    }
    Write-Host ""
    Warn "Still not up after 10 minutes. Check '.\setup\vigil.ps1 status' and '.\setup\vigil.ps1 logs'."
}

function Show-Status {
    Compose @("ps")
    Say "Health checks"
    $checks = @(
        @{ Name = "Dashboard  https://localhost";       Url = "https://localhost/app/login"; Auth = $null },
        @{ Name = "Indexer    https://localhost:9200";  Url = "https://localhost:9200/_cluster/health"; Auth = "admin:SecretPassword" },
        @{ Name = "API        https://localhost:55000"; Url = "https://localhost:55000/"; Auth = $null }
    )
    foreach ($c in $checks) {
        $argv = @("-k", "-s", "-o", "NUL", "-w", "%{http_code}", "--max-time", "5", $c.Url)
        if ($c.Auth) { $argv = @("-u", $c.Auth) + $argv }
        $code = & curl.exe @argv 2>$null
        # The API answers 401 without a token, which still means it's up.
        if ($code -in "200", "401") { Ok "$($c.Name)  up ($code)" } else { Warn "$($c.Name)  not answering ($code)" }
    }
}

switch ($Action) {
    "up" {
        Test-Prerequisites
        Set-MaxMapCount
        Get-WazuhDocker
        Install-Override
        New-Certificates
        Say "Starting Wazuh $WazuhVersion"
        Compose @("up", "-d")
        Wait-Healthy
        Write-Host ""
        Say "Wazuh is running"
        Ok "Dashboard:  https://localhost   (user: admin  password: SecretPassword)"
        Ok "Agents connect to this PC's LAN IP on ports 1514 and 1515."
        Warn "These are the public default passwords. Change them before you expose"
        Warn "anything beyond your own machine (see docs/lab-setup.md)."
    }
    "status" { Show-Status }
    "logs"   { Compose @("logs", "-f", "--tail", "100", "wazuh.manager") }
    "down"   { Say "Stopping Wazuh (data is kept)"; Compose @("down") }
    "reset" {
        $answer = Read-Host "This deletes ALL Wazuh alerts, agents and settings. Type 'reset' to confirm"
        if ($answer -ne "reset") { Die "Cancelled." }
        Compose @("down", "-v")
        Ok "All Wazuh data deleted. Run '.\setup\vigil.ps1 up' to start fresh."
    }
}
