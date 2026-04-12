# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Windows Hardening Script
#  pcdc_win_harden.ps1
#
#  Interactive hardening script — prompts before every
#  significant change. Run after pcdc_win_audit.ps1.
#  Equivalent to pcdc_linux_harden.sh for Windows.
#
#  Covers:
#  - Password resets for all accounts
#  - Account lockdown (disable/remove suspicious users)
#  - Password policy hardening
#  - Firewall configuration
#  - SMBv1 disablement
#  - RDP hardening
#  - Unnecessary service removal
#  - Scheduled task cleanup
#  - Registry run key audit
#  - Share cleanup
#  - Windows Update
#  - Defender configuration
#  - Audit policy
#
#  USAGE:
#    Set-ExecutionPolicy Bypass -Scope Process -Force
#    .\pcdc_win_harden.ps1
#
#  Run as Administrator — required for most changes.
# ============================================================

#Requires -Version 3.0
#Requires -RunAsAdministrator

param(
    [string]$OutputPath = "$env:TEMP\blueTeam"
)

$ErrorActionPreference = "SilentlyContinue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "$OutputPath\logs"
$LogFile = "$LogDir\harden_$Timestamp.log"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-OK      { param($msg) Write-Host "[OK]      $msg" -ForegroundColor Green;  Add-Content $LogFile "[OK]      $msg" }
function Write-Warn    { param($msg) Write-Host "[WARN]    $msg" -ForegroundColor Yellow; Add-Content $LogFile "[WARN]    $msg" }
function Write-Bad     { param($msg) Write-Host "[BAD]     $msg" -ForegroundColor Red;    Add-Content $LogFile "[BAD]     $msg" }
function Write-Info    { param($msg) Write-Host "[INFO]    $msg" -ForegroundColor Cyan;   Add-Content $LogFile "[INFO]    $msg" }
function Write-Action  { param($msg) Write-Host "[ACTION]  $msg" -ForegroundColor Magenta; Add-Content $LogFile "[ACTION]  $msg" }
function Write-Section {
    param($title)
    $line = "=" * 60
    Write-Host "`n$line" -ForegroundColor Blue
    Write-Host "  $title" -ForegroundColor Blue
    Write-Host "$line`n" -ForegroundColor Blue
    Add-Content $LogFile "`n$line`n  $title`n$line"
}

function Confirm-Action {
    param($prompt)
    $response = Read-Host "$prompt [y/N]"
    return $response -match "^[Yy]$"
}

Write-Host "`nPCDC 2026 | Astra 9 Blue Team Windows Hardening" -ForegroundColor Blue
Write-Host "Host: $env:COMPUTERNAME | Time: $(Get-Date)"
Write-Host "Log:  $LogFile`n"
Write-Host "This script prompts before every significant change." -ForegroundColor Yellow
Write-Host "Run pcdc_win_audit.ps1 first if you haven't already.`n" -ForegroundColor Yellow

# ============================================================
# STEP 1: PASSWORD RESETS
# ============================================================
Write-Section "STEP 1: PASSWORD RESETS"

Write-Info "Current local accounts:"
Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object {
    Write-Info "  $($_.Name)"
}

Write-Host ""
Write-Warn "You should change passwords for ALL enabled accounts."
Write-Warn "Use a strong scheme. Write it down on paper, not in a text file."
Write-Host ""

Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object {
    $username = $_.Name
    if (Confirm-Action "Change password for: $username") {
        $newPass = Read-Host "New password for $username" -AsSecureString
        try {
            Set-LocalUser -Name $username -Password $newPass
            Write-OK "Password changed: $username"
            Add-Content $LogFile "PASSWORD CHANGED: $username"
        } catch {
            Write-Warn "Failed to change password for $username`: $_"
        }
    } else {
        Write-Warn "Skipped: $username"
    }
}

# ============================================================
# STEP 2: ACCOUNT LOCKDOWN
# ============================================================
Write-Section "STEP 2: ACCOUNT AUDIT & LOCKDOWN"

Write-Info "Reviewing local accounts..."
Get-LocalUser | ForEach-Object {
    $username = $_.Name
    $enabled = $_.Enabled

    # Always skip built-in accounts we expect
    if ($username -match "^(WDAGUtilityAccount|DefaultAccount)$") {
        Write-Info "  $username — system account, leaving as-is"
        return
    }

    Write-Host ""
    Write-Warn "Account: $username | Enabled: $enabled | Last Login: $($_.LastLogon)"
    Write-Host "  1) Keep as-is"
    Write-Host "  2) Disable account (safe, reversible)"
    Write-Host "  3) Delete account"
    $choice = Read-Host "Choice [1/2/3]"

    switch ($choice) {
        "2" {
            Disable-LocalUser -Name $username
            Write-OK "Disabled: $username"
        }
        "3" {
            if (Confirm-Action "PERMANENTLY delete $username?") {
                Remove-LocalUser -Name $username
                Write-OK "Deleted: $username"
            }
        }
        default { Write-Info "Kept: $username" }
    }
}

Write-Host ""
Write-Info "Reviewing Local Administrators group:"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    $member = $_.Name
    Write-Warn "Admin member: $member"
    if ($member -notmatch "Administrator$" -and (Confirm-Action "Remove $member from Administrators group?")) {
        Remove-LocalGroupMember -Group "Administrators" -Member $member.Split("\")[1] 2>$null
        Write-OK "Removed from Administrators: $member"
    }
}

# Rename built-in Administrator if it hasn't been
$adminAccount = Get-LocalUser -Name "Administrator" 2>$null
if ($adminAccount -and (Confirm-Action "Rename 'Administrator' account to something less obvious?")) {
    $newName = Read-Host "New name for Administrator account"
    Rename-LocalUser -Name "Administrator" -NewName $newName
    Write-OK "Renamed Administrator to: $newName"
}

# Disable Guest
if ((Get-LocalUser -Name "Guest" 2>$null).Enabled) {
    Disable-LocalUser -Name "Guest"
    Write-OK "Guest account disabled"
} else {
    Write-OK "Guest account already disabled"
}

# ============================================================
# STEP 3: PASSWORD POLICY
# ============================================================
Write-Section "STEP 3: PASSWORD POLICY HARDENING"

if (Confirm-Action "Apply strong password policy?") {
    # Min length 12, complexity, history 5, max age 90, lockout after 5
    $tempCfg = "$env:TEMP\secpol_harden.cfg"
    $secdbPath = "$env:TEMP\secpol_harden.sdb"

    @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 5
MaximumPasswordAge = 90
MinimumPasswordAge = 1
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Set-Content -Path $tempCfg -Encoding Unicode

    secedit /configure /db $secdbPath /cfg $tempCfg /quiet 2>$null
    Remove-Item $tempCfg, $secdbPath -Force 2>$null
    Write-OK "Password policy applied: min 12 chars, complexity, lockout after 5 attempts"
} else {
    Write-Warn "Skipped password policy hardening"
}

# ============================================================
# STEP 4: FIREWALL HARDENING
# ============================================================
Write-Section "STEP 4: FIREWALL CONFIGURATION"

Write-Warn "IMPORTANT: Verify scoring engine IPs are known before enabling firewall rules."
Write-Warn "Blocking the scoring engine costs points — same as being down."
Write-Host ""

if (Confirm-Action "Enable Windows Firewall on all profiles?") {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-OK "Firewall enabled on all profiles"
}

if (Confirm-Action "Set default INBOUND to BLOCK on all profiles?") {
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Write-OK "Default inbound: BLOCK"
}

Write-Host ""
Write-Info "Common scored services — add firewall rules for each that applies:"

$serviceRules = @(
    @{Name="RDP"; Port=3389; Proto="TCP"},
    @{Name="HTTP"; Port=80; Proto="TCP"},
    @{Name="HTTPS"; Port=443; Proto="TCP"},
    @{Name="SMB"; Port=445; Proto="TCP"},
    @{Name="SMTP"; Port=25; Proto="TCP"},
    @{Name="DNS"; Port=53; Proto="UDP"},
    @{Name="MSSQL"; Port=1433; Proto="TCP"},
    @{Name="WinRM HTTP"; Port=5985; Proto="TCP"},
    @{Name="WinRM HTTPS"; Port=5986; Proto="TCP"}
)

foreach ($rule in $serviceRules) {
    if (Confirm-Action "Allow inbound $($rule.Name) (port $($rule.Port)/$($rule.Proto))?") {
        New-NetFirewallRule `
            -DisplayName "PCDC-BT-$($rule.Name)" `
            -Direction Inbound `
            -Protocol $rule.Proto `
            -LocalPort $rule.Port `
            -Action Allow `
            -Enabled True 2>$null
        Write-OK "Rule added: Allow inbound $($rule.Name)"
    }
}

Write-Host ""
Write-Warn "To allow a specific scoring engine IP only:"
Write-Warn "  New-NetFirewallRule -DisplayName 'ScoreEngine' -Direction Inbound -RemoteAddress <SCORE_IP> -Action Allow"

# ============================================================
# STEP 5: SMB HARDENING
# ============================================================
Write-Section "STEP 5: SMB HARDENING"

Write-Info "Current SMB configuration:"
$smbConfig = Get-SmbServerConfiguration 2>$null
Write-Info "  SMBv1: $($smbConfig.EnableSMB1Protocol)"
Write-Info "  SMBv2: $($smbConfig.EnableSMB2Protocol)"

if ($smbConfig.EnableSMB1Protocol) {
    if (Confirm-Action "DISABLE SMBv1? (EternalBlue/WannaCry protection — highly recommended)") {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-OK "SMBv1 DISABLED"
    }
}

if (Confirm-Action "Require SMB signing? (prevents relay attacks)") {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
    Write-OK "SMB signing required"
}

Write-Host ""
Write-Info "Current shares:"
Get-SmbShare | Where-Object { $_.Name -notmatch "^\w+\$$" } | ForEach-Object {
    Write-Warn "  Non-admin share: $($_.Name) → $($_.Path)"
    if (Confirm-Action "Remove share '$($_.Name)'?") {
        Remove-SmbShare -Name $_.Name -Force
        Write-OK "Removed share: $($_.Name)"
    }
}

# ============================================================
# STEP 6: RDP HARDENING
# ============================================================
Write-Section "STEP 6: RDP HARDENING"

$rdpEnabled = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections

if ($rdpEnabled -eq 0) {
    Write-Warn "RDP is currently ENABLED"

    if (Confirm-Action "Require Network Level Authentication (NLA) for RDP?") {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
            -Name "UserAuthentication" -Value 1
        Write-OK "NLA required for RDP"
    }

    if (Confirm-Action "Restrict RDP to specific IP (enter 0.0.0.0 to skip)?") {
        $allowedIP = Read-Host "Allow RDP from IP"
        if ($allowedIP -ne "0.0.0.0") {
            New-NetFirewallRule -DisplayName "PCDC-RDP-Restricted" `
                -Direction Inbound -Protocol TCP -LocalPort 3389 `
                -RemoteAddress $allowedIP -Action Allow 2>$null
            # Remove the broader rule if it exists
            Remove-NetFirewallRule -DisplayName "PCDC-BT-RDP" 2>$null
            Write-OK "RDP restricted to: $allowedIP"
        }
    }

    if (Confirm-Action "Limit RDP sessions to 2 concurrent?") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
            -Name "MaxConnectionPolicy" -Value 2
        Write-OK "Max RDP sessions: 2"
    }
} else {
    Write-OK "RDP is disabled"
    if (Confirm-Action "Enable RDP? (only if it's a scored service)") {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -Value 0
        # Require NLA immediately
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
            -Name "UserAuthentication" -Value 1
        Write-OK "RDP enabled with NLA required"
    }
}

# ============================================================
# STEP 7: DISABLE UNNECESSARY SERVICES
# ============================================================
Write-Section "STEP 7: UNNECESSARY SERVICES"

Write-Warn "Only disable services you're SURE are not being scored."
Write-Host ""

$riskyServices = @(
    @{Name="TelnetD"; Display="Telnet Server"},
    @{Name="FTPSVC"; Display="FTP Service (IIS)"},
    @{Name="SNMP"; Display="SNMP Service"},
    @{Name="RemoteRegistry"; Display="Remote Registry"},
    @{Name="Spooler"; Display="Print Spooler (if no printing needed)"},
    @{Name="XblGameSave"; Display="Xbox Game Save"},
    @{Name="XboxNetApiSvc"; Display="Xbox Network Service"},
    @{Name="WMPNetworkSvc"; Display="Windows Media Player Network Sharing"}
)

foreach ($svc in $riskyServices) {
    $service = Get-Service -Name $svc.Name 2>$null
    if ($service -and $service.Status -eq "Running") {
        Write-Warn "Running: $($svc.Display)"
        if (Confirm-Action "Stop and disable $($svc.Display)?") {
            Stop-Service -Name $svc.Name -Force 2>$null
            Set-Service -Name $svc.Name -StartupType Disabled
            Write-OK "Disabled: $($svc.Display)"
        }
    }
}

# ============================================================
# STEP 8: SCHEDULED TASK CLEANUP
# ============================================================
Write-Section "STEP 8: SCHEDULED TASK CLEANUP"

$suspTasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch "\\Microsoft\\" -and $_.State -ne "Disabled"
}

if ($suspTasks) {
    Write-Warn "Non-Microsoft scheduled tasks found:"
    $suspTasks | ForEach-Object {
        $action = ($_.Actions | Select-Object -First 1)
        $execute = if ($action.Execute) { $action.Execute } else { "Unknown" }
        Write-Warn "  $($_.TaskName) → $execute"
        if (Confirm-Action "Disable task '$($_.TaskName)'?") {
            Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath 2>$null
            Write-OK "Disabled task: $($_.TaskName)"
        }
    }
} else {
    Write-OK "No suspicious scheduled tasks found"
}

# ============================================================
# STEP 9: REGISTRY RUN KEY CLEANUP
# ============================================================
Write-Section "STEP 9: REGISTRY PERSISTENCE CLEANUP"

$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $entries = Get-ItemProperty -Path $key 2>$null
        $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            Write-Warn "Registry run entry: $($_.Name) = $($_.Value)"
            if (Confirm-Action "Remove run entry '$($_.Name)'?") {
                Remove-ItemProperty -Path $key -Name $_.Name 2>$null
                Write-OK "Removed: $($_.Name)"
            }
        }
    }
}

# ============================================================
# STEP 10: WINDOWS DEFENDER HARDENING
# ============================================================
Write-Section "STEP 10: WINDOWS DEFENDER"

if (Confirm-Action "Enable and configure Windows Defender?") {
    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false 2>$null
    Write-OK "Real-time protection: ENABLED"

    # Enable cloud protection
    Set-MpPreference -MAPSReporting Advanced 2>$null
    Write-OK "Cloud-based protection: ENABLED"

    # Enable behavior monitoring
    Set-MpPreference -DisableBehaviorMonitoring $false 2>$null
    Write-OK "Behavior monitoring: ENABLED"

    # Enable network protection
    Set-MpPreference -EnableNetworkProtection Enabled 2>$null
    Write-OK "Network protection: ENABLED"

    # Quick scan
    if (Confirm-Action "Run Windows Defender quick scan now?") {
        Start-MpScan -ScanType QuickScan
        Write-OK "Quick scan initiated"
    }
}

# ============================================================
# STEP 11: AUDIT POLICY
# ============================================================
Write-Section "STEP 11: AUDIT POLICY"

Write-Info "Enabling comprehensive audit logging (critical for incident reports)..."
if (Confirm-Action "Enable detailed audit policy?") {
    # Enable key audit categories
    auditpol /set /category:"Account Logon" /success:enable /failure:enable 2>$null
    auditpol /set /category:"Account Management" /success:enable /failure:enable 2>$null
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable 2>$null
    auditpol /set /category:"Object Access" /success:enable /failure:enable 2>$null
    auditpol /set /category:"Policy Change" /success:enable /failure:enable 2>$null
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable 2>$null
    auditpol /set /category:"System" /success:enable /failure:enable 2>$null
    auditpol /set /category:"Process Tracking" /success:enable /failure:enable 2>$null
    Write-OK "Audit policy configured — all critical events will be logged"

    # Increase log size
    wevtutil sl Security /ms:102400000 2>$null  # 100MB
    Write-OK "Security event log size increased to 100MB"
}

# ============================================================
# STEP 12: WINDOWS UPDATE
# ============================================================
Write-Section "STEP 12: WINDOWS UPDATE"

if (Confirm-Action "Check for and install Windows Updates?") {
    Write-Info "Checking for updates (this may take a few minutes)..."
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $updates = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")

        if ($updates.Updates.Count -gt 0) {
            Write-Warn "$($updates.Updates.Count) updates available"
            $updates.Updates | ForEach-Object { Write-Info "  - $($_.Title)" }

            if (Confirm-Action "Install all available updates?") {
                $downloader = $updateSession.CreateUpdateDownloader()
                $downloader.Updates = $updates.Updates
                $downloader.Download()
                Write-OK "Updates downloaded"

                $installer = $updateSession.CreateUpdateInstaller()
                $installer.Updates = $updates.Updates
                $result = $installer.Install()
                Write-OK "Updates installed. Result: $($result.ResultCode)"

                if ($result.RebootRequired) {
                    Write-Warn "REBOOT REQUIRED — reboot after competition if possible"
                    Write-Warn "Do NOT reboot during competition without Captain approval"
                }
            }
        } else {
            Write-OK "System is up to date"
        }
    } catch {
        Write-Warn "Could not run Windows Update automatically"
        Write-Info "Run Windows Update manually: Settings → Update & Security → Windows Update"
    }
}

# ============================================================
# DONE
# ============================================================
Write-Section "HARDENING COMPLETE"
Write-OK "Log saved to: $LogFile"
Write-Host ""
Write-Host "CRITICAL REMINDERS:" -ForegroundColor Yellow
Write-Host "  1. Verify ALL scored services are still reachable" -ForegroundColor Yellow
Write-Host "  2. Test RDP, HTTP, SMB, etc. from another machine" -ForegroundColor Yellow
Write-Host "  3. Check the scoreboard — services should show UP" -ForegroundColor Yellow
Write-Host "  4. Run pcdc_win_monitor.ps1 for ongoing detection" -ForegroundColor Yellow
Write-Host "  5. Do NOT reboot unless absolutely necessary" -ForegroundColor Yellow
