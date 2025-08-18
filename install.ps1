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
$script:LogPath = Join-Path $env:TEMP "network_tool.log"

function Log($msg) {
    $ts = (Get-Date).ToString("u")
    $line = "[$ts] $msg"
    Write-Host $line
    Add-Content -Path $script:LogPath -Value $line
}

# =================== Admin check (already ensured) ===================
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# =================== Network Info ===================
function Get-NetworkConfig {
    Write-Host "`n=== Current Network Configuration ===" -ForegroundColor Green
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    foreach ($adapter in $adapters) {
        Write-Host "Interface: $($adapter.Name)" -ForegroundColor Cyan

        try {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($dns) { Write-Host "DNS Servers: $($dns.ServerAddresses -join ', ')" }
        } catch {}

        try {
            $ip = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -notlike "169.254.*"}
            if ($ip) { Write-Host "IP Address: $($ip.IPAddress)" }
        } catch {}

        try {
            $mtu = Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($mtu) { Write-Host "MTU: $($mtu.NlMtu)" }
        } catch {}

        Write-Host ""
    }

    # DoH status (if cmdlet exists)
    try {
        $dohStatus = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($dohStatus) { Write-Host "DoH Status: Enabled" -ForegroundColor Green }
        else { Write-Host "DoH Status: Disabled" -ForegroundColor Yellow }
    } catch {
        Write-Host "DoH Status: Unknown (cmdlet not available on this Windows version)" -ForegroundColor Yellow
    }

    # Hosts file modifications
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
        $customEntries = $hostsContent | Where-Object { $_ -notmatch "^#" -and $_ -match "\S" -and $_ -notmatch "localhost" }
        if ($customEntries) {
            Write-Host "Custom Hosts Entries: $($customEntries.Count)" -ForegroundColor Yellow
        } else {
            Write-Host "Custom Hosts Entries: None"
        }
    } catch {}
}

# =================== DNS ===================
function Set-DNSServers {
    param(
        [Parameter(Mandatory)] [string]$Primary,
        [Parameter(Mandatory)] [string]$Secondary,
        [Parameter(Mandatory)] [string]$Name
    )
    try {
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $Primary, $Secondary -ErrorAction Stop
        }
        Write-Host "DNS set to $Name ($Primary, $Secondary)" -ForegroundColor Green

        if ($global:PersistentMode) {
            Save-PersistentSettings -DNSPrimary $Primary -DNSSecondary $Secondary -DNSName $Name
            Write-Host "Configuration saved - will persist after reboot" -ForegroundColor Yellow
        } else {
            Write-Host "Configuration is temporary (will reset on reboot)" -ForegroundColor Yellow
        }

        Clear-DNSCache
    } catch {
        Write-Host "Error setting DNS: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Reset-DNS {
    try {
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }
        Clear-DNSCache
        Write-Host "DNS reset to automatic (ISP default)" -ForegroundColor Green
    } catch {
        Write-Host "Error resetting DNS: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-DNSCache {
    try {
        ipconfig /flushdns | Out-Null
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-Host "DNS cache cleared successfully" -ForegroundColor Green
    } catch {
        Write-Host "Error clearing DNS cache: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =================== Persistent Settings ===================
function Save-PersistentSettings {
    param(
        [string]$DNSPrimary,
        [string]$DNSSecondary,
        [string]$DNSName
    )
    try {
        $regPath = "HKCU:\Software\NetworkConfigTool"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        if ($DNSPrimary)   { Set-ItemProperty -Path $regPath -Name "DNSPrimary" -Value $DNSPrimary }
        if ($DNSSecondary) { Set-ItemProperty -Path $regPath -Name "DNSSecondary" -Value $DNSSecondary }
        if ($DNSName)      { Set-ItemProperty -Path $regPath -Name "DNSName" -Value $DNSName }
        Set-ItemProperty -Path $regPath -Name "PersistentMode" -Value $true
    } catch {
        Write-Host "Warning: Could not save persistent settings: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Import-PersistentSettings {
    try {
        $regPath = "HKCU:\Software\NetworkConfigTool"
        if (Test-Path $regPath) {
            $persistentMode = Get-ItemProperty -Path $regPath -Name "PersistentMode" -ErrorAction SilentlyContinue
            if ($persistentMode.PersistentMode) {
                $primary = (Get-ItemProperty -Path $regPath -Name "DNSPrimary" -ErrorAction SilentlyContinue).DNSPrimary
                $secondary = (Get-ItemProperty -Path $regPath -Name "DNSSecondary" -ErrorAction SilentlyContinue).DNSSecondary
                $name = (Get-ItemProperty -Path $regPath -Name "DNSName" -ErrorAction SilentlyContinue).DNSName
                if ($primary -and $secondary) {
                    Write-Host "Applying persistent DNS settings: $name" -ForegroundColor Yellow
                    Set-DNSServers -Primary $primary -Secondary $secondary -Name $name
                }
            }
        }
    } catch {
        Write-Host "Warning: Could not load persistent settings" -ForegroundColor Yellow
    }
}

function Clear-PersistentSettings {
    try {
        $regPath = "HKCU:\Software\NetworkConfigTool"
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force
        }
    } catch {
        Write-Host "Warning: Could not clear persistent settings" -ForegroundColor Yellow
    }
}

# =================== Browser Cache ===================
function Clear-ChromeCache {
    try {
        $chromePaths = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache",
            "$env:LOCALAPPDATA\Chromium\User Data\Default\Cache",
            "$env:LOCALAPPDATA\Chromium\User Data\Default\Code Cache"
        )
        foreach ($path in $chromePaths) {
            if (Test-Path $path) {
                Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Chrome/Chromium cache cleared: $path" -ForegroundColor Green
            }
        }
        Write-Host "Chrome/Chromium cache cleared successfully" -ForegroundColor Green
    } catch {
        Write-Host "Error clearing Chrome cache: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-FirefoxCache {
    try {
        $profileRoot = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $profileRoot) {
            $profiles = Get-ChildItem $profileRoot -Directory | Where-Object { $_.Name -match ".*\.default.*" }
            foreach ($profile in $profiles) {
                $cachePath = Join-Path $profile.FullName "cache2"
                if (Test-Path $cachePath) {
                    Remove-Item -Path "$cachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "Firefox cache cleared: $cachePath" -ForegroundColor Green
                }
            }
        }
        Write-Host "Firefox cache cleared successfully" -ForegroundColor Green
    } catch {
        Write-Host "Error clearing Firefox cache: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-EdgeCache {
    try {
        $edgePaths = @(
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache"
        )
        foreach ($path in $edgePaths) {
            if (Test-Path $path) {
                Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Edge cache cleared: $path" -ForegroundColor Green
            }
        }
        Write-Host "Edge cache cleared successfully" -ForegroundColor Green
    } catch {
        Write-Host "Error clearing Edge cache: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-BraveCache {
    try {
        $bravePaths = @(
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache",
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Code Cache"
        )
        foreach ($path in $bravePaths) {
            if (Test-Path $path) {
                Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Brave cache cleared: $path" -ForegroundColor Green
            }
        }
        Write-Host "Brave cache cleared successfully" -ForegroundColor Green
    } catch {
        Write-Host "Error clearing Brave cache: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-OperaCache {
    try {
        $operaPaths = @(
            "$env:LOCALAPPDATA\Opera Software\Opera Stable\Cache",
            "$env:LOCALAPPDATA\Opera Software\Opera Stable\Code Cache"
        )
        foreach ($path in $operaPaths) {
            if (Test-Path $path) {
                Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Opera cache cleared: $path" -ForegroundColor Green
            }
        }
        Write-Host "Opera cache cleared successfully" -ForegroundColor Green
    } catch {
        Write-Host "Error clearing Opera cache: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-AllBrowserCache {
    try {
        Write-Host "Clearing all browser caches..." -ForegroundColor Yellow
        Clear-ChromeCache
        Clear-FirefoxCache
        Clear-EdgeCache
        Clear-BraveCache
        Clear-OperaCache
        Write-Host "All browser caches cleared successfully" -ForegroundColor Green
    } catch {
        Write-Host "Error clearing all browser caches: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-BrowserCache {
    Write-Host "`n=== Browser Cache Management ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Chrome/Chromium"
    Write-Host "2. Firefox"
    Write-Host "3. Edge"
    Write-Host "4. Brave"
    Write-Host "5. Opera"
    Write-Host "6. All browsers"
    Write-Host "0. Back to main menu"
    Write-Host ""

    $choice = Read-Host "Select browser to clear cache"
    switch ($choice) {
        "1" { Clear-ChromeCache }
        "2" { Clear-FirefoxCache }
        "3" { Clear-EdgeCache }
        "4" { Clear-BraveCache }
        "5" { Clear-OperaCache }
        "6" { Clear-AllBrowserCache }
        "0" { return }
        default {
            Write-Host "Invalid option" -ForegroundColor Red
            Start-Sleep 2
        }
    }
}

# =================== DoH ===================
function Enable-DoH {
    try {
        $dnsServers = @(
            @{Server="1.1.1.1"; Template="https://cloudflare-dns.com/dns-query"},
            @{Server="8.8.8.8"; Template="https://dns.google/dns-query"},
            @{Server="9.9.9.9"; Template="https://dns.quad9.net/dns-query"}
        )
        foreach ($dns in $dnsServers) {
            Add-DnsClientDohServerAddress -ServerAddress $dns.Server -DohTemplate $dns.Template -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction SilentlyContinue
        }
        Write-Host "DNS over HTTPS enabled for common servers" -ForegroundColor Green
    } catch {
        Write-Host "Error enabling DoH (or not supported on this OS): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Disable-DoH {
    try {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($dohServers) {
            foreach ($server in $dohServers) {
                Remove-DnsClientDohServerAddress -ServerAddress $server.ServerAddress -ErrorAction SilentlyContinue
            }
        }
        Write-Host "DNS over HTTPS disabled" -ForegroundColor Green
    } catch {
        Write-Host "Error disabling DoH (or not supported on this OS): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# =================== Optimize / Reset ===================
function Optimize-NetworkSettings {
    try {
        Write-Host "Applying network optimizations..." -ForegroundColor Yellow
        netsh int tcp set global autotuninglevel=normal       | Out-Null
        netsh int tcp set global chimney=enabled              | Out-Null
        netsh int tcp set global rss=enabled                  | Out-Null
        netsh int tcp set global timestamps=disabled          | Out-Null
        netsh int tcp set global ecncapability=enabled        | Out-Null
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -NlMtu 1500 -ErrorAction SilentlyContinue
        }
        Write-Host "Network optimization completed" -ForegroundColor Green
        Write-Host "Restart required for full effect" -ForegroundColor Yellow
    } catch {
        Write-Host "Error optimizing network: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Reset-NetworkOptimizations {
    try {
        Write-Host "Resetting network optimizations..." -ForegroundColor Yellow
        netsh int tcp reset   | Out-Null
        netsh winsock reset   | Out-Null
        Write-Host "Network settings reset to defaults" -ForegroundColor Green
        Write-Host "Restart required to complete reset" -ForegroundColor Yellow
    } catch {
        Write-Host "Error resetting network: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =================== Hosts ===================
function Edit-HostsFile {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    do {
        Clear-Host
        Write-Host "=== Hosts File Management ===" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. View current hosts file"
        Write-Host "2. Add custom entry"
        Write-Host "3. Remove custom entries"
        Write-Host "4. Backup hosts file"
        Write-Host "5. Restore hosts file"
        Write-Host "0. Back to main menu"
        Write-Host ""

        $choice = Read-Host "Select an option"
        switch ($choice) {
            "1" {
                Write-Host "`n=== Current Hosts File ===" -ForegroundColor Green
                Get-Content $hostsPath | Write-Host
                Read-Host "`nPress Enter to continue"
            }
            "2" {
                $domain = Read-Host "Enter domain to block/redirect"
                $ip = Read-Host "Enter IP (127.0.0.1 to block, or custom IP)"
                if (-not $ip) { $ip = "127.0.0.1" }
                try {
                    Add-Content $hostsPath "`n$ip`t$domain"
                    Write-Host "Entry added successfully" -ForegroundColor Green
                    Write-Host "`n⚠️  IMPORTANT: Restart your browser or clear browser cache for changes to take effect!" -ForegroundColor Yellow
                    Write-Host "   Use Option 7 (Clear Browser Cache) to automatically clear cache" -ForegroundColor Cyan
                } catch {
                    Write-Host "Error adding entry: $($_.Exception.Message)" -ForegroundColor Red
                }
                Read-Host "`nPress Enter to continue"
            }
            "3" {
                try {
                    $backup = Get-Content $hostsPath
                    $defaultContent = $backup | Where-Object { $_ -match "^#" -or $_ -match "localhost" -or $_ -notmatch "\S" }
                    Set-Content $hostsPath $defaultContent
                    Write-Host "Custom entries removed" -ForegroundColor Green
                } catch {
                    Write-Host "Error removing entries: $($_.Exception.Message)" -ForegroundColor Red
                }
                Read-Host "`nPress Enter to continue"
            }
            "4" {
                try {
                    Copy-Item $hostsPath "$hostsPath.backup" -Force
                    Write-Host "Hosts file backed up to $hostsPath.backup" -ForegroundColor Green
                } catch {
                    Write-Host "Error backing up: $($_.Exception.Message)" -ForegroundColor Red
                }
                Read-Host "`nPress Enter to continue"
            }
            "5" {
                if (Test-Path "$hostsPath.backup") {
                    try {
                        Copy-Item "$hostsPath.backup" $hostsPath -Force
                        Write-Host "Hosts file restored from backup" -ForegroundColor Green
                    } catch {
                        Write-Host "Error restoring: $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "No backup file found" -ForegroundColor Red
                }
                Read-Host "`nPress Enter to continue"
            }
            "0" { return }
            default {
                Write-Host "Invalid option" -ForegroundColor Red
                Start-Sleep 2
            }
        }
    } while ($true)
}

# =================== Diagnostics ===================
function Test-NetworkDiagnostics {
    Write-Host "`n=== Network Diagnostics ===" -ForegroundColor Green
    $testSites = @("google.com", "cloudflare.com", "github.com")
    foreach ($site in $testSites) {
        $result = Test-NetConnection -ComputerName $site -Port 80 -InformationLevel Quiet
        $status = if ($result) { "OK" } else { "FAIL" }
        $color = if ($result) { "Green" } else { "Red" }
        Write-Host "$site : $status" -ForegroundColor $color
    }

    Write-Host "`n=== DNS Resolution Test ===" -ForegroundColor Green
    foreach ($site in $testSites) {
        try {
            $resolved = Resolve-DnsName $site -ErrorAction Stop
            Write-Host "$site : $($resolved[0].IPAddress)" -ForegroundColor Green
        } catch {
            Write-Host "$site : FAILED" -ForegroundColor Red
        }
    }

    Write-Host "`n=== Connection Quality ===" -ForegroundColor Green
    $ping = Test-NetConnection google.com -InformationLevel Detailed
    if ($ping.PingSucceeded) {
        Write-Host "Ping to Google: $($ping.PingReplyDetails.RoundtripTime)ms" -ForegroundColor Green
    } else {
        Write-Host "Ping to Google: FAILED" -ForegroundColor Red
    }
}

# =================== EXE Download & Run ===================
function Install-NetworkBinary {
    param(
        [string]$ExeUrl = "https://raw.githubusercontent.com/TorDotTaxi/Network/main/network.exe",
        [string]$ExeArgs = ""
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $dest = Join-Path $env:TEMP (Split-Path $ExeUrl -Leaf)
    Log "BEGIN install: $ExeUrl"
    $downloaded = $false

    try {
        Log "Downloading via Invoke-WebRequest..."
        Invoke-WebRequest -Uri $ExeUrl -OutFile $dest -UseBasicParsing -ErrorAction Stop
        $downloaded = $true
    } catch {
        Log "IWR failed: $($_.Exception.Message)"
        try {
            Log "Trying Start-BitsTransfer..."
            Start-BitsTransfer -Source $ExeUrl -Destination $dest -ErrorAction Stop
            $downloaded = $true
        } catch {
            Log "BITS failed: $($_.Exception.Message)"
        }
    }

    if (-not $downloaded) {
        Log "Download failed. Abort."
        return
    }

    try {
        if (-not (Test-Path $dest)) { throw "File missing after download." }
        $size = (Get-Item $dest).Length
        if ($size -le 0) { throw "Downloaded size = 0." }

        # Check PE header "MZ"
        $fs = [System.IO.File]::OpenRead($dest)
        try {
            $buf = New-Object byte[] 2
            [void]$fs.Read($buf,0,2)
            $sig = [System.Text.Encoding]::ASCII.GetString($buf)
            if ($sig -ne "MZ") { throw "Not a valid .exe (missing MZ header)." }
        } finally { $fs.Close() }

        Unblock-File -Path $dest -ErrorAction SilentlyContinue
        Log "Downloaded OK (size=$size). Unblocked."
    } catch {
        Log "Validation failed: $($_.Exception.Message)"
        return
    }

    try {
        $workDir = Split-Path $dest -Parent
        Log "Running EXE... (WorkDir=$workDir)"
        $proc = Start-Process -FilePath $dest -ArgumentList $ExeArgs -WorkingDirectory $workDir -Wait -PassThru
        Log "Process exited with code $($proc.ExitCode)"
    } catch {
        Log "Run failed (direct). Trying cmd fallback: $($_.Exception.Message)"
        try {
            $cmd = "cmd.exe"
            $cmdArgs = "/c `"`"$dest`" $ExeArgs`""
            $proc2 = Start-Process -FilePath $cmd -ArgumentList $cmdArgs -Wait -PassThru
            Log "Fallback exited with code $($proc2.ExitCode)"
        } catch {
            Log "Fallback failed: $($_.Exception.Message)"
        }
    }

    Log "END install. Log: $script:LogPath"
}

# =================== Menu ===================
function Show-Menu {
    Clear-Host
    Write-Host "=== Advanced Network Configuration Tool ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "DNS Configuration:"
    Write-Host "1. View current configuration"
    Write-Host "2. Set Cloudflare DNS (1.1.1.1) - Fast & Secure"
    Write-Host "3. Set Google DNS (8.8.8.8) - Reliable"
    Write-Host "4. Set OpenDNS (208.67.222.222) - Family Safe"
    Write-Host "5. Set Quad9 DNS (9.9.9.9) - Malware Protection"
    Write-Host "6. Flush DNS Cache"
    Write-Host "7. Clear Browser Cache"
    Write-Host ""
    Write-Host "Advanced Features:"
    Write-Host "8.  Enable DNS over HTTPS (DoH)"
    Write-Host "9.  Disable DNS over HTTPS (DoH)"
    Write-Host "10. Optimize network settings"
    Write-Host "11. Reset network optimizations"
    Write-Host "12. Manage hosts file"
    Write-Host "13. Run network diagnostics"
    Write-Host ""
    Write-Host "System:"
    Write-Host "14. Reset to ISP default"
    Write-Host "15. Toggle persistent mode (Current: $($global:PersistentMode))"
    Write-Host "16. Download & run network.exe"
    Write-Host "0.  Exit"
    Write-Host ""
}

# =================== Start ===================
Write-Host "Advanced Network Configuration Tool loaded successfully!" -ForegroundColor Green
Write-Host "Administrator privileges: OK" -ForegroundColor Green
Log "Tool started. Admin OK."

if (-not $Persistent) {
    Import-PersistentSettings
}

do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        "1"  { Get-NetworkConfig; Read-Host "`nPress Enter to continue" }
        "2"  { Set-DNSServers -Primary "1.1.1.1" -Secondary "1.0.0.1" -Name "Cloudflare"; Read-Host "`nPress Enter to continue" }
        "3"  { Set-DNSServers -Primary "8.8.8.8" -Secondary "8.8.4.4" -Name "Google"; Read-Host "`nPress Enter to continue" }
        "4"  { Set-DNSServers -Primary "208.67.222.222" -Secondary "208.67.220.220" -Name "OpenDNS"; Read-Host "`nPress Enter to continue" }
        "5"  { Set-DNSServers -Primary "9.9.9.9" -Secondary "149.112.112.112" -Name "Quad9"; Read-Host "`nPress Enter to continue" }
        "6"  { Clear-DNSCache; Read-Host "`nPress Enter to continue" }
        "7"  { Clear-BrowserCache }
        "8"  { Enable-DoH; Read-Host "`nPress Enter to continue" }
        "9"  { Disable-DoH; Read-Host "`nPress Enter to continue" }
        "10" { Optimize-NetworkSettings; Read-Host "`nPress Enter to continue" }
        "11" { Reset-NetworkOptimizations; Read-Host "`nPress Enter to continue" }
        "12" { Edit-HostsFile }
        "13" { Test-NetworkDiagnostics; Read-Host "`nPress Enter to continue" }
        "14" { Reset-DNS; Disable-DoH; Clear-PersistentSettings; Read-Host "`nPress Enter to continue" }
        "15" {
            $global:PersistentMode = -not $global:PersistentMode
            Write-Host "Persistent mode: $($global:PersistentMode)" -ForegroundColor Yellow
            if (-not $global:PersistentMode) {
                Clear-PersistentSettings
                Write-Host "Persistent settings cleared" -ForegroundColor Green
            }
            Read-Host "`nPress Enter to continue"
        }
        "16" {
            Install-NetworkBinary -ExeUrl "https://raw.githubusercontent.com/TorDotTaxi/Network/main/network.exe"
            Read-Host "`nPress Enter to continue"
        }
        "0" {
            if (-not $global:PersistentMode) {
                $reset = Read-Host "Reset all settings to default before exit? (y/N)"
                if ($reset -eq "y" -or $reset -eq "Y") {
                    Reset-DNS
                    Disable-DoH
                    Clear-PersistentSettings
                    Write-Host "Settings reset to default" -ForegroundColor Green
                }
            }
            Write-Host "Goodbye!" -ForegroundColor Green
            break
        }
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep 2
        }
    }
} while ($true)
