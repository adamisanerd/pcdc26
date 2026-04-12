# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Windows System Audit Script
#  pcdc_win_audit.ps1
#
#  PURPOSE:
#  Read-only audit of a Windows system. Run this FIRST on
#  every Windows machine before touching anything.
#  Equivalent to pcdc_linux_audit.sh for Windows.
#
#  Checks:
#  - Local users and groups (admins, hidden accounts)
#  - Password policy
#  - Scheduled tasks (persistence)
#  - Running services and processes
#  - Network connections and listening ports
#  - Firewall status
#  - Shares and SMB configuration
#  - Registry run keys (persistence)
#  - Windows Defender status
#  - Installed software
#  - Recent event log entries
#  - RDP configuration
#  - Auto-start locations
#
#  USAGE:
#    Set-ExecutionPolicy Bypass -Scope Process -Force
#    .\pcdc_win_audit.ps1
#
#  Run as Administrator for full results.
# ============================================================

#Requires -Version 3.0

param(
    [string]$OutputPath = "$env:TEMP\blueTeam",
    [switch]$Quiet
)

# ── Setup ─────────────────────────────────────────────────────
$ErrorActionPreference = "SilentlyContinue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "$OutputPath\logs"
$LogFile = "$LogDir\audit_$Timestamp.log"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

# ── Color output functions ────────────────────────────────────
function Write-OK    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green;  Add-Content $LogFile "[OK]    $msg" }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow; Add-Content $LogFile "[WARN]  $msg" }
function Write-Bad   { param($msg) Write-Host "[BAD]   $msg" -ForegroundColor Red;    Add-Content $LogFile "[BAD]   $msg" }
function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan;   Add-Content $LogFile "[INFO]  $msg" }
function Write-Section {
    param($title)
    $line = "=" * 60
    Write-Host "`n$line" -ForegroundColor Blue
    Write-Host "  $title" -ForegroundColor Blue
    Write-Host "$line`n" -ForegroundColor Blue
    Add-Content $LogFile "`n$line`n  $title`n$line"
}

# ── Check admin ───────────────────────────────────────────────
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $IsAdmin) {
    Write-Warn "Not running as Administrator — some checks will be incomplete"
    Write-Warn "Rerun: Start-Process PowerShell -Verb RunAs"
}

Write-Host "`nPCDC 2026 | Astra 9 Blue Team Windows Audit" -ForegroundColor Blue
Write-Host "Host: $env:COMPUTERNAME | IP: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1).IPAddress)"
Write-Host "User: $env:USERNAME | Time: $(Get-Date)"
Write-Host "Log:  $LogFile`n"

# ============================================================
# SECTION 1: USER & ACCOUNT AUDIT
# ============================================================
Write-Section "SECTION 1: USER & ACCOUNT AUDIT"

Write-Info "All local user accounts:"
$users = Get-LocalUser
$users | ForEach-Object {
    $status = if ($_.Enabled) { "ENABLED" } else { "DISABLED" }
    $lastLogin = if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
    $pwdExpires = if ($_.PasswordExpires) { $_.PasswordExpires.ToString("yyyy-MM-dd") } else { "Never/NotSet" }
    Write-Info "  $($_.Name) | $status | Last login: $lastLogin | PwdExpires: $pwdExpires"
}

Write-Host ""
Write-Info "Local Administrators group members:"
$admins = Get-LocalGroupMember -Group "Administrators" 2>$null
$admins | ForEach-Object {
    if ($_.Name -match "Administrator$") {
        Write-OK "  $($_.Name) (built-in)"
    } else {
        Write-Warn "  $($_.Name) — verify this should be an admin"
    }
}

Write-Host ""
Write-Info "Checking for accounts with no password required:"
Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true } | ForEach-Object {
    Write-Bad "  No password required: $($_.Name)"
}

Write-Host ""
Write-Info "Checking for accounts with password never expires:"
Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null -and $_.Enabled -eq $true } | ForEach-Object {
    Write-Warn "  Password never expires: $($_.Name)"
}

Write-Host ""
Write-Info "Recently created accounts (last 7 days):"
$cutoff = (Get-Date).AddDays(-7)
# Check event log for account creation events
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4720] and System[TimeCreated[@SystemTime>='$($cutoff.ToUniversalTime().ToString("o"))']]]" 2>$null |
    Select-Object -First 10 | ForEach-Object {
        Write-Warn "  Account created: $($_.TimeCreated) — $($_.Message -replace '\s+', ' ' | Select-String 'Account Name:.*' | Select-Object -First 1)"
    }

Write-Host ""
Write-Info "Currently logged-in users:"
query user 2>$null | Write-Host

# ============================================================
# SECTION 2: PASSWORD POLICY
# ============================================================
Write-Section "SECTION 2: PASSWORD POLICY"

$pwPolicy = net accounts 2>$null
$pwPolicy | ForEach-Object { Write-Info "  $_" }

# Check via secedit for more detail
$seceditOutput = "$env:TEMP\secpol.cfg"
secedit /export /cfg $seceditOutput /quiet 2>$null
if (Test-Path $seceditOutput) {
    $policy = Get-Content $seceditOutput
    $minLen = ($policy | Select-String "MinimumPasswordLength").ToString().Split("=")[1].Trim()
    $maxAge = ($policy | Select-String "MaximumPasswordAge").ToString().Split("=")[1].Trim()
    $lockout = ($policy | Select-String "LockoutBadCount").ToString().Split("=")[1].Trim()

    if ([int]$minLen -lt 8) { Write-Bad "  Minimum password length: $minLen (should be >= 8)" }
    else { Write-OK "  Minimum password length: $minLen" }

    if ([int]$lockout -eq 0) { Write-Warn "  Account lockout: DISABLED (brute force risk)" }
    else { Write-OK "  Account lockout after: $lockout attempts" }

    Remove-Item $seceditOutput -Force 2>$null
}

# ============================================================
# SECTION 3: NETWORK & OPEN PORTS
# ============================================================
Write-Section "SECTION 3: NETWORK & OPEN PORTS"

Write-Info "Network interfaces:"
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | ForEach-Object {
    Write-Info "  $($_.InterfaceAlias): $($_.IPAddress)/$($_.PrefixLength)"
}

Write-Host ""
Write-Info "Listening ports and owning processes:"
$listeners = Get-NetTCPConnection -State Listen | Sort-Object LocalPort
$listeners | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess 2>$null
    $procName = if ($proc) { $proc.Name } else { "Unknown" }
    $localAddr = "$($_.LocalAddress):$($_.LocalPort)"
    Write-Info "  TCP $localAddr → PID $($_.OwningProcess) ($procName)"

    # Flag suspicious ports
    $suspiciousPorts = @(4444, 1234, 5555, 6666, 7777, 31337, 8888, 9999, 1337)
    if ($suspiciousPorts -contains $_.LocalPort) {
        Write-Bad "  ^^^ SUSPICIOUS PORT: $($_.LocalPort) — classic backdoor/shell port"
    }
}

Write-Host ""
Write-Info "UDP listeners:"
Get-NetUDPEndpoint | Sort-Object LocalPort | Select-Object -First 20 | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess 2>$null
    $procName = if ($proc) { $proc.Name } else { "Unknown" }
    Write-Info "  UDP $($_.LocalAddress):$($_.LocalPort) → PID $($_.OwningProcess) ($procName)"
}

Write-Host ""
Write-Info "Established connections:"
Get-NetTCPConnection -State Established | Sort-Object RemoteAddress | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess 2>$null
    $procName = if ($proc) { $proc.Name } else { "Unknown" }
    Write-Info "  $($_.LocalAddress):$($_.LocalPort) → $($_.RemoteAddress):$($_.RemotePort) [$procName]"

    # Flag shells with network connections
    $suspiciousProcs = @("cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "nc", "ncat")
    if ($suspiciousProcs -contains $proc.Name) {
        Write-Bad "  ^^^ SHELL/SCRIPT HAS NETWORK CONNECTION: $procName (PID $($_.OwningProcess))"
    }
}

Write-Host ""
Write-Info "Routing table:"
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -ne "127.0.0.1/8" } |
    Format-Table DestinationPrefix, NextHop, InterfaceAlias -AutoSize | Out-String | Write-Host

Write-Host ""
Write-Info "DNS configuration:"
Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object {
    Write-Info "  $($_.InterfaceAlias): $($_.ServerAddresses -join ', ')"
}

Write-Host ""
Write-Info "Hosts file (/etc/hosts equivalent — C:\Windows\System32\drivers\etc\hosts):"
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch "^#" -and $_ -ne "" } | ForEach-Object {
    Write-Info "  $_"
}

# ============================================================
# SECTION 4: SHARES & SMB
# ============================================================
Write-Section "SECTION 4: SHARES & SMB"

Write-Info "Network shares:"
Get-SmbShare | ForEach-Object {
    $name = $_.Name
    $path = $_.Path
    $desc = $_.Description
    if ($name -match '\$$') {
        Write-Info "  $name → $path (admin share)"
    } elseif ($name -eq "IPC$") {
        Write-Info "  $name (IPC share)"
    } else {
        Write-Warn "  $name → $path [$desc] — verify this share is intentional"
        # Check permissions
        $perms = Get-SmbShareAccess -Name $name 2>$null
        $perms | ForEach-Object { Write-Info "    Access: $($_.AccountName) = $($_.AccessRight)" }
    }
}

Write-Host ""
Write-Info "SMB server configuration:"
$smbConfig = Get-SmbServerConfiguration 2>$null
if ($smbConfig) {
    if ($smbConfig.EnableSMB1Protocol) {
        Write-Bad "  SMBv1 ENABLED — EternalBlue/WannaCry risk. Disable: Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
    } else {
        Write-OK "  SMBv1 disabled"
    }
    Write-Info "  SMBv2 enabled: $($smbConfig.EnableSMB2Protocol)"
    Write-Info "  Encryption required: $($smbConfig.EncryptData)"
    if (-not $smbConfig.RequireSecuritySignature) {
        Write-Warn "  SMB signing not required — relay attack risk"
    } else {
        Write-OK "  SMB signing required"
    }
}

# ============================================================
# SECTION 5: SERVICES
# ============================================================
Write-Section "SECTION 5: RUNNING SERVICES"

Write-Info "All running services:"
Get-Service | Where-Object { $_.Status -eq "Running" } | Sort-Object DisplayName | ForEach-Object {
    Write-Info "  $($_.Name) | $($_.DisplayName) | $($_.StartType)"
}

Write-Host ""
Write-Info "Services set to auto-start that are currently stopped:"
Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | ForEach-Object {
    Write-Warn "  Auto-start but stopped: $($_.Name) ($($_.DisplayName))"
}

Write-Host ""
Write-Info "Services with non-standard binary paths (check for tampering):"
Get-WmiObject Win32_Service | Where-Object { $_.PathName -notmatch "^[Cc]:\\Windows" -and $_.State -eq "Running" } | ForEach-Object {
    Write-Warn "  Non-standard path: $($_.Name) → $($_.PathName)"
}

# ============================================================
# SECTION 6: SCHEDULED TASKS
# ============================================================
Write-Section "SECTION 6: SCHEDULED TASKS (PERSISTENCE CHECK)"

Write-Info "Non-Microsoft scheduled tasks (most common persistence location):"
$tasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch "\\Microsoft\\" -and
    $_.State -ne "Disabled"
}

if ($tasks) {
    $tasks | ForEach-Object {
        $action = ($_.Actions | Select-Object -First 1)
        $execute = if ($action.Execute) { $action.Execute } else { "Unknown" }
        $args = if ($action.Arguments) { $action.Arguments } else { "" }
        Write-Warn "  $($_.TaskName) | $($_.TaskPath)"
        Write-Info "    Execute: $execute $args"
        Write-Info "    State: $($_.State) | Author: $($_.Principal.UserId)"

        # Flag suspicious executables
        $suspExec = @("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe")
        if ($suspExec | Where-Object { $execute -like "*$_*" }) {
            Write-Bad "    ^^^ SUSPICIOUS: Scheduled task runs shell/script interpreter"
        }
    }
} else {
    Write-OK "No non-Microsoft scheduled tasks found"
}

Write-Host ""
Write-Info "Recently modified scheduled tasks (last 24 hours):"
Get-ScheduledTask | Where-Object {
    $info = $_ | Get-ScheduledTaskInfo 2>$null
    $info -and $info.LastRunTime -gt (Get-Date).AddHours(-24)
} | ForEach-Object {
    Write-Warn "  Recently ran: $($_.TaskName)"
}

# ============================================================
# SECTION 7: REGISTRY PERSISTENCE
# ============================================================
Write-Section "SECTION 7: REGISTRY PERSISTENCE (RUN KEYS)"

$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $entries = Get-ItemProperty -Path $key 2>$null
        if ($entries) {
            $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                Write-Warn "  [$key]"
                Write-Info "    $($_.Name) = $($_.Value)"

                # Flag suspicious values
                if ($_.Value -match "temp|appdata|%|\.ps1|\.vbs|\.js|cmd\.exe|powershell") {
                    Write-Bad "    ^^^ SUSPICIOUS registry persistence entry"
                }
            }
        }
    }
}

Write-Host ""
Write-Info "Checking common persistence locations in registry:"
$additionalKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"
)
foreach ($key in $additionalKeys) {
    if (Test-Path $key) {
        Write-Info "  $key"
        Get-ItemProperty -Path $key 2>$null | Select-Object -ExcludeProperty PS* |
            Format-List | Out-String | ForEach-Object { Write-Info "    $_" }
    }
}

# ============================================================
# SECTION 8: FIREWALL STATUS
# ============================================================
Write-Section "SECTION 8: FIREWALL STATUS"

$profiles = Get-NetFirewallProfile
$profiles | ForEach-Object {
    if ($_.Enabled) {
        Write-OK "  Firewall ENABLED: $($_.Name) profile"
        Write-Info "    Default inbound: $($_.DefaultInboundAction)"
        Write-Info "    Default outbound: $($_.DefaultOutboundAction)"
    } else {
        Write-Bad "  Firewall DISABLED: $($_.Name) profile — CRITICAL"
    }
}

Write-Host ""
Write-Info "Custom firewall rules (non-default):"
Get-NetFirewallRule | Where-Object {
    $_.Enabled -eq $true -and
    $_.Group -notmatch "^@" -and
    $_.DisplayName -notmatch "^(Windows|Core Networking|File and Printer|Network Discovery|Remote Desktop|Remote Assistance)"
} | Select-Object -First 30 | ForEach-Object {
    $direction = $_.Direction
    $action = $_.Action
    Write-Info "  [$action] $($_.DisplayName) ($direction)"
}

# ============================================================
# SECTION 9: WINDOWS DEFENDER / AV STATUS
# ============================================================
Write-Section "SECTION 9: WINDOWS DEFENDER STATUS"

$defenderStatus = Get-MpComputerStatus 2>$null
if ($defenderStatus) {
    if ($defenderStatus.AntivirusEnabled) {
        Write-OK "  Windows Defender: ENABLED"
    } else {
        Write-Bad "  Windows Defender: DISABLED — no AV protection"
    }

    if ($defenderStatus.RealTimeProtectionEnabled) {
        Write-OK "  Real-time protection: ENABLED"
    } else {
        Write-Bad "  Real-time protection: DISABLED"
    }

    Write-Info "  Last signature update: $($defenderStatus.AntivirusSignatureLastUpdated)"
    Write-Info "  Signature version: $($defenderStatus.AntivirusSignatureVersion)"

    if ($defenderStatus.TamperProtectionSource -eq "Signatures") {
        Write-OK "  Tamper protection: ENABLED"
    } else {
        Write-Warn "  Tamper protection status: $($defenderStatus.TamperProtectionSource)"
    }
} else {
    Write-Warn "  Could not query Windows Defender status"
}

# ============================================================
# SECTION 10: RUNNING PROCESSES
# ============================================================
Write-Section "SECTION 10: RUNNING PROCESSES"

Write-Info "All running processes:"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 |
    Format-Table Name, Id, CPU, WorkingSet, Path -AutoSize | Out-String | Write-Host

Write-Host ""
Write-Info "Processes with no file path (injected/hollow processes):"
Get-Process | Where-Object { -not $_.Path -and $_.Name -notmatch "^(Idle|System|Registry|smss|csrss|wininit|services|lsass|fontdrvhost|dwm)$" } | ForEach-Object {
    Write-Warn "  No path: $($_.Name) (PID $($_.Id)) — possible process injection"
}

Write-Host ""
Write-Info "PowerShell processes:"
Get-Process powershell, pwsh 2>$null | ForEach-Object {
    Write-Warn "  PowerShell running: PID $($_.Id) — check if expected"
    try {
        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
        Write-Info "    Command: $cmdLine"
    } catch {}
}

# ============================================================
# SECTION 11: RDP CONFIGURATION
# ============================================================
Write-Section "SECTION 11: RDP CONFIGURATION"

$rdpEnabled = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" 2>$null).fDenyTSConnections
if ($rdpEnabled -eq 0) {
    Write-Warn "  RDP is ENABLED"

    # Check NLA requirement
    $nla = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" 2>$null).UserAuthentication
    if ($nla -eq 1) {
        Write-OK "  Network Level Authentication (NLA): REQUIRED (good)"
    } else {
        Write-Bad "  NLA: NOT REQUIRED — RDP accessible without pre-auth"
    }

    # Check RDP port
    $rdpPort = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" 2>$null).PortNumber
    if ($rdpPort -ne 3389) {
        Write-Warn "  RDP on non-standard port: $rdpPort"
    } else {
        Write-Info "  RDP port: $rdpPort (standard)"
    }
} else {
    Write-OK "  RDP is DISABLED"
}

# ============================================================
# SECTION 12: EVENT LOG AUDIT
# ============================================================
Write-Section "SECTION 12: EVENT LOG REVIEW"

Write-Info "Recent Security events (last 50 — logins, failures, account changes):"
$secEvents = Get-WinEvent -LogName Security -MaxEvents 200 2>$null | Where-Object {
    $_.Id -in @(4624, 4625, 4634, 4648, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756, 4768, 4769, 4771, 4776)
} | Select-Object -First 50

$secEvents | ForEach-Object {
    $eventType = switch ($_.Id) {
        4624 { "Login SUCCESS" }
        4625 { "Login FAILED" }
        4634 { "Logoff" }
        4648 { "Login with explicit credentials" }
        4720 { "Account CREATED" }
        4722 { "Account ENABLED" }
        4723 { "Password change attempted" }
        4724 { "Password RESET" }
        4725 { "Account DISABLED" }
        4726 { "Account DELETED" }
        4728 { "Member added to security group" }
        4732 { "Member added to local group" }
        4756 { "Member added to universal group" }
        4768 { "Kerberos TGT requested" }
        4769 { "Kerberos service ticket requested" }
        4771 { "Kerberos pre-auth failed" }
        4776 { "NTLM auth attempt" }
        default { "Event $($_.Id)" }
    }
    $time = $_.TimeCreated.ToString("HH:mm:ss")

    if ($_.Id -in @(4625, 4771, 4726, 4720, 4732)) {
        Write-Warn "  [$time] $eventType"
    } else {
        Write-Info "  [$time] $eventType"
    }
}

Write-Host ""
Write-Info "Checking for brute force (>5 failed logins from same source):"
$failedLogins = Get-WinEvent -LogName Security -MaxEvents 1000 2>$null |
    Where-Object { $_.Id -eq 4625 } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
        $ip
    } |
    Group-Object | Where-Object { $_.Count -gt 5 } | Sort-Object Count -Descending

$failedLogins | ForEach-Object {
    Write-Bad "  Brute force from: $($_.Name) — $($_.Count) failed attempts"
}

# ============================================================
# SECTION 13: INSTALLED SOFTWARE
# ============================================================
Write-Section "SECTION 13: INSTALLED SOFTWARE"

Write-Info "Installed software (may reveal unintended attack tools):"
$software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null
$software += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null
$software | Where-Object { $_.DisplayName } |
    Sort-Object DisplayName |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    ForEach-Object {
        # Flag potentially suspicious tools
        $suspTools = @("nmap", "wireshark", "metasploit", "netcat", "ncat", "putty", "winscp",
                       "aircrack", "hashcat", "mimikatz", "cain", "angry ip", "advanced port")
        $isSusp = $suspTools | Where-Object { $_.DisplayName -like "*$_*" }
        if ($isSusp) {
            Write-Warn "  [HACKING TOOL?] $($_.DisplayName) $($_.DisplayVersion)"
        } else {
            Write-Info "  $($_.DisplayName) $($_.DisplayVersion) — $($_.Publisher)"
        }
    }

# ============================================================
# SECTION 14: PATCHING STATUS
# ============================================================
Write-Section "SECTION 14: PATCH STATUS"

Write-Info "OS Version:"
$os = Get-WmiObject Win32_OperatingSystem
Write-Info "  $($os.Caption) Build $($os.BuildNumber) SP $($os.ServicePackMajorVersion)"

Write-Host ""
Write-Info "Recent Windows Updates (last 10):"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | ForEach-Object {
    Write-Info "  $($_.HotFixID) installed $($_.InstalledOn) — $($_.Description)"
}

Write-Host ""
Write-Info "Checking for pending updates:"
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $updates = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
    if ($updates.Updates.Count -gt 0) {
        Write-Warn "  $($updates.Updates.Count) pending updates available"
        $updates.Updates | Select-Object -First 5 | ForEach-Object {
            Write-Warn "    - $($_.Title)"
        }
    } else {
        Write-OK "  System is up to date"
    }
} catch {
    Write-Info "  Could not query Windows Update (may need to run as SYSTEM)"
}

# ============================================================
# DONE
# ============================================================
Write-Section "AUDIT COMPLETE"
Write-OK "Log saved to: $LogFile"
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Review all [BAD] entries first" -ForegroundColor Yellow
Write-Host "  2. Review all [WARN] entries" -ForegroundColor Yellow
Write-Host "  3. Run pcdc_win_harden.ps1 to apply fixes" -ForegroundColor Yellow
Write-Host "  4. Run pcdc_win_monitor.ps1 for continuous monitoring" -ForegroundColor Yellow
