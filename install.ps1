# Network Configuration Tool
# Advanced Windows network optimization and configuration manager

[CmdletBinding()]
param(
    [switch]$Persistent = $false
)

# =================== Auto-elevate to Administrator (supports irm ... | iex) ===================
function Ensure-Administrator {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) { return }

    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    $argsList = @("-NoProfile","-ExecutionPolicy","Bypass")

    # If running from memory (irm ... | iex), dump to temp and relaunch
    if ([string]::IsNullOrEmpty($PSCommandPath)) {
        $tmp = Join-Path $env:TEMP "win-network-config_install.ps1"
        # $MyInvocation.MyCommand.Definition holds current script content
        Set-Content -Path $tmp -Value $MyInvocation.MyCommand.Definition -Encoding UTF8
        $argsList += @("-File","`"$tmp`"")
    } else {
        $argsList += @("-File","`"$PSCommandPath`"")
    }

    Start-Process -FilePath "powershell.exe" -ArgumentList $argsList -Verb RunAs -WindowStyle Normal | Out-Null
    exit
}
Ensure-Administrator

# =================== Globals & Utils ===================
$global:PersistentMode = [bool]$Persistent
$script:LogPath = Join-Path $env:TE
