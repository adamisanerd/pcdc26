# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Windows Continuous Monitor
#  pcdc_win_monitor.ps1
#
#  Baselines the system at startup and diffs every cycle.
#  Equivalent to pcdc_linux_monitor.sh for Windows.
#
#  Monitors:
#  - New local user accounts
#  - New local admins
#  - New listening ports
#  - New running services
#  - New scheduled tasks
#  - Registry run key changes
#  - New processes (shell/script engines with connections)
#  - Event log anomalies (brute force, account changes)
#  - Failed login rate (brute force detection)
#  - Scored service health with auto-restart attempt
#  - Windows Defender status changes
#  - New shares
#
#  USAGE:
#    Set-ExecutionPolicy Bypass -Scope Process -Force
#    .\pcdc_win_monitor.ps1 [-Interval 45] [-Services "w3svc","mssqlserver"]
#    .\pcdc_win_monitor.ps1 [-Role Auto|DomainController|WSUS|Web|Mail|File|Workstation]
#
#  Run as Administrator for full visibility.
# ============================================================

#Requires -Version 3.0

param(
    [int]$Interval = 45,
    [string[]]$Services = @(),
    [ValidateSet("Auto","DomainController","WSUS","Web","Mail","File","Workstation")]
    [string]$Role = "Auto",
    [string]$OutputPath = "$env:TEMP\blueTeam"
)

$ErrorActionPreference = "SilentlyContinue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "$OutputPath\logs"
$LogFile = "$LogDir\monitor_$Timestamp.log"
$IncidentLog = "$LogDir\incidents_$Timestamp.log"
$StateDir = "$OutputPath\state"

foreach ($dir in @($LogDir, $StateDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Write-OK      { param($msg) Write-Host "[OK]      $msg" -ForegroundColor Green  }
function Write-Warn    { param($msg) Write-Host "[WARN]    $msg" -ForegroundColor Yellow }
function Write-Alert   {
    param($msg)
    Write-Host "[ALERT]   $msg" -ForegroundColor Red
    $entry = "[$(Get-Date -Format 'HH:mm:ss')] ALERT: $msg"
    Add-Content $IncidentLog $entry
}
function Write-Info    { param($msg) Write-Host "[INFO]    $msg" -ForegroundColor Cyan   }
function Write-Cycle   { param($n) Write-Host "`n$('=' * 60)" -ForegroundColor Magenta
                         Write-Host "  Cycle #$n | $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Magenta
                         Write-Host "$('=' * 60)" -ForegroundColor Magenta }

function Log-Incident {
    param($type, $detail, $srcIP = "UNKNOWN")
    $report = @"

============================================================
INCIDENT: $type
Time:     $(Get-Date)
System:   $env:COMPUTERNAME [$((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1).IPAddress)]
Detail:   $detail
Src IP:   $srcIP
============================================================
"@
    Add-Content $IncidentLog $report
    Write-Host "[INCIDENT LOGGED] $type" -ForegroundColor Red
}

function Resolve-RoleServices {
    param(
        [string]$RoleName,
        [string]$ComputerName
    )

    switch ($RoleName) {
        "DomainController" { return @("DNS", "NTDS", "Netlogon", "Kdc", "LanmanServer") }
        "WSUS"             { return @("WsusService", "W3SVC", "BITS") }
        "Web"              { return @("W3SVC") }
        "Mail"             { return @("MSExchangeIS", "MSExchangeTransport", "W3SVC", "SMTPSVC") }
        "File"             { return @("LanmanServer") }
        "Workstation"      { return @("LanmanWorkstation", "Dnscache") }
        default {
            $name = $ComputerName.ToLowerInvariant()
            if ($name -match "dc|domain")        { return @("DNS", "NTDS", "Netlogon", "Kdc", "LanmanServer") }
            if ($name -match "wsus|update")      { return @("WsusService", "W3SVC", "BITS") }
            if ($name -match "web|iis")          { return @("W3SVC") }
            if ($name -match "mail|exchange")    { return @("MSExchangeIS", "MSExchangeTransport", "W3SVC", "SMTPSVC") }
            if ($name -match "file|fileserver|fs") { return @("LanmanServer") }
            if ($name -match "workstation|client|ws") { return @("LanmanWorkstation", "Dnscache") }
            return @("W3SVC", "DNS", "LanmanServer")
        }
    }
}

# ── Resolve scored services ───────────────────────────────────
if ($Services.Count -eq 0) {
    $Services = Resolve-RoleServices -RoleName $Role -ComputerName $env:COMPUTERNAME
    Write-Warn "No -Services supplied. Auto-selected role-based defaults for Role=$Role on host $env:COMPUTERNAME"
    Write-Warn "Override explicitly with -Services \"w3svc\",\"dns\" if your packet differs."
}

$Services = @($Services | Where-Object { $_ -and $_.Trim().Length -gt 0 } | Select-Object -Unique)
Write-Info "Monitoring services: $($Services -join ', ')"

# ============================================================
# BASELINE CAPTURE
# ============================================================
function Get-Baseline {
    Write-Info "Capturing system baseline..."

    # Users
    Get-LocalUser | Select-Object Name, Enabled, LastLogon |
        ConvertTo-Json | Set-Content "$StateDir\users.baseline.json"

    # Admins
    Get-LocalGroupMember -Group "Administrators" 2>$null |
        Select-Object Name | ConvertTo-Json | Set-Content "$StateDir\admins.baseline.json"

    # Listening ports
    Get-NetTCPConnection -State Listen |
        Select-Object LocalPort, LocalAddress, OwningProcess |
        ConvertTo-Json | Set-Content "$StateDir\ports.baseline.json"

    # Services
    Get-Service | Select-Object Name, Status, StartType |
        ConvertTo-Json | Set-Content "$StateDir\services.baseline.json"

    # Scheduled tasks
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State |
        ConvertTo-Json | Set-Content "$StateDir\tasks.baseline.json"

    # Registry run keys
    $runValues = @{}
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
      "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") | ForEach-Object {
        if (Test-Path $_) {
            $props = Get-ItemProperty -Path $_
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $runValues[$_.Name] = $_.Value
            }
        }
    }
    $runValues | ConvertTo-Json | Set-Content "$StateDir\runkeys.baseline.json"

    # Shares
    Get-SmbShare | Select-Object Name, Path |
        ConvertTo-Json | Set-Content "$StateDir\shares.baseline.json"

    # Defender status hash
    $defStatus = Get-MpComputerStatus 2>$null
    if ($defStatus) {
        @{
            AntivirusEnabled = $defStatus.AntivirusEnabled
            RealTimeProtection = $defStatus.RealTimeProtectionEnabled
        } | ConvertTo-Json | Set-Content "$StateDir\defender.baseline.json"
    }

    Write-OK "Baseline captured."
}

# ============================================================
# CHECK FUNCTIONS
# ============================================================

function Check-NewUsers {
    $current = Get-LocalUser | Select-Object Name, Enabled
    $baseline = Get-Content "$StateDir\users.baseline.json" 2>$null | ConvertFrom-Json

    if ($baseline) {
        $baselineNames = $baseline | ForEach-Object { $_.Name }
        $currentNames  = $current  | ForEach-Object { $_.Name }

        # New accounts
        $newUsers = $currentNames | Where-Object { $_ -notin $baselineNames }
        foreach ($u in $newUsers) {
            Write-Alert "NEW USER ACCOUNT CREATED: $u"
            Log-Incident "NEW USER ACCOUNT" "User '$u' appeared since baseline"
        }

        # Newly enabled accounts
        $baseline | Where-Object { -not $_.Enabled } | ForEach-Object {
            $bUser = $_
            $cUser = $current | Where-Object { $_.Name -eq $bUser.Name }
            if ($cUser -and $cUser.Enabled) {
                Write-Alert "ACCOUNT ENABLED: $($bUser.Name) was disabled at baseline"
                Log-Incident "ACCOUNT ENABLED" "$($bUser.Name) was re-enabled"
            }
        }
    }
}

function Check-NewAdmins {
    $current = Get-LocalGroupMember -Group "Administrators" 2>$null |
        Select-Object -ExpandProperty Name
    $baseline = Get-Content "$StateDir\admins.baseline.json" 2>$null | ConvertFrom-Json
    $baselineNames = $baseline | ForEach-Object { $_.Name }

    foreach ($admin in $current) {
        if ($admin -notin $baselineNames) {
            Write-Alert "NEW LOCAL ADMINISTRATOR: $admin — privilege escalation suspected"
            Log-Incident "NEW LOCAL ADMINISTRATOR" "$admin added to Administrators group"
        }
    }
}

function Check-NewPorts {
    $current = Get-NetTCPConnection -State Listen |
        Select-Object LocalPort, LocalAddress, OwningProcess
    $baseline = Get-Content "$StateDir\ports.baseline.json" 2>$null | ConvertFrom-Json
    $baselinePorts = $baseline | ForEach-Object { $_.LocalPort }

    foreach ($conn in $current) {
        if ($conn.LocalPort -notin $baselinePorts) {
            $proc = Get-Process -Id $conn.OwningProcess 2>$null
            $procName = if ($proc) { $proc.Name } else { "Unknown" }
            Write-Alert "NEW LISTENING PORT: $($conn.LocalAddress):$($conn.LocalPort) owned by $procName (PID $($conn.OwningProcess))"
            Log-Incident "NEW LISTENING PORT" "Port $($conn.LocalPort) opened by $procName"

            # Update baseline
            $current | ConvertTo-Json | Set-Content "$StateDir\ports.baseline.json"
        }
    }
}

function Check-NewServices {
    $current  = Get-Service | Select-Object Name, Status
    $baseline = Get-Content "$StateDir\services.baseline.json" 2>$null | ConvertFrom-Json
    $baselineNames = $baseline | ForEach-Object { $_.Name }

    foreach ($svc in $current) {
        if ($svc.Name -notin $baselineNames) {
            Write-Alert "NEW SERVICE INSTALLED: $($svc.Name) — Status: $($svc.Status)"
            Log-Incident "NEW SERVICE" "$($svc.Name) installed since baseline"
        }
    }

    # Check services that stopped unexpectedly
    $baseline | Where-Object { $_.Status -eq "Running" } | ForEach-Object {
        $bSvc = $_
        $cSvc = $current | Where-Object { $_.Name -eq $bSvc.Name }
        if ($cSvc -and $cSvc.Status -ne "Running") {
            Write-Warn "SERVICE STOPPED: $($bSvc.Name) was running at baseline"
        }
    }
}

function Check-NewScheduledTasks {
    $current  = Get-ScheduledTask | Select-Object TaskName, TaskPath, State
    $baseline = Get-Content "$StateDir\tasks.baseline.json" 2>$null | ConvertFrom-Json
    $baselineNames = $baseline | ForEach-Object { $_.TaskName }

    foreach ($task in $current) {
        if ($task.TaskName -notin $baselineNames -and $task.TaskPath -notmatch "\\Microsoft\\") {
            Write-Alert "NEW SCHEDULED TASK: $($task.TaskName) at $($task.TaskPath)"
            $detail = Get-ScheduledTask -TaskName $task.TaskName 2>$null
            $action = $detail.Actions | Select-Object -First 1
            Write-Alert "  Execute: $($action.Execute) $($action.Arguments)"
            Log-Incident "NEW SCHEDULED TASK" "$($task.TaskName) → $($action.Execute)"
        }
    }
}

function Check-RegistryRunKeys {
    $current = @{}
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
      "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") | ForEach-Object {
        if (Test-Path $_) {
            Get-ItemProperty -Path $_ |
                Select-Object -Property * -ExcludeProperty PS* |
                Get-Member -MemberType NoteProperty | ForEach-Object {
                    $current[$_.Name] = (Get-ItemProperty -Path $_).$($_.Name)
                }
        }
    }

    $baseline = Get-Content "$StateDir\runkeys.baseline.json" 2>$null | ConvertFrom-Json

    if ($baseline) {
        foreach ($key in $current.Keys) {
            if (-not $baseline.$key) {
                Write-Alert "NEW REGISTRY RUN KEY: $key = $($current[$key])"
                Log-Incident "NEW REGISTRY PERSISTENCE" "Run key: $key = $($current[$key])"
            }
        }
    }
}

function Check-SuspiciousProcesses {
    $shellProcs = @("cmd", "powershell", "pwsh", "wscript", "cscript", "mshta",
                    "regsvr32", "rundll32", "certutil", "bitsadmin", "nc", "ncat")

    Get-NetTCPConnection -State Established 2>$null | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess 2>$null
        if ($proc -and $shellProcs -contains $proc.Name) {
            Write-Alert "SHELL/SCRIPT HAS NETWORK CONNECTION: $($proc.Name) (PID $($_.OwningProcess)) → $($_.RemoteAddress):$($_.RemotePort)"
            try {
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine
                Write-Alert "  Command: $cmdLine"
            } catch {}
            Log-Incident "SUSPICIOUS NETWORK CONNECTION" "$($proc.Name) connected to $($_.RemoteAddress):$($_.RemotePort)"
        }
    }
}

function Check-BruteForce {
    $cutoff = (Get-Date).AddMinutes(-2)
    $failures = Get-WinEvent -LogName Security -MaxEvents 500 2>$null |
        Where-Object { $_.Id -eq 4625 -and $_.TimeCreated -gt $cutoff }

    if ($failures.Count -gt 10) {
        Write-Alert "BRUTE FORCE DETECTED: $($failures.Count) failed logins in last 2 minutes"

        # Extract source IPs
        $failures | ForEach-Object {
            $xml = [xml]$_.ToXml()
            ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
        } | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object {
            Write-Alert "  Top attacker: $($_.Name) — $($_.Count) attempts"
            Log-Incident "BRUTE FORCE" "$($failures.Count) failures in 2 min" $_.Name
        }
    }
}

function Check-ScoredServices {
    foreach ($svcName in $Services) {
        $svc = Get-Service -Name $svcName 2>$null
        if ($svc) {
            if ($svc.Status -ne "Running") {
                Write-Alert "SCORED SERVICE DOWN: $svcName — attempting restart"
                try {
                    Start-Service -Name $svcName
                    Start-Sleep -Seconds 3
                    $svc.Refresh()
                    if ($svc.Status -eq "Running") {
                        Write-OK "Restarted: $svcName"
                    } else {
                        Write-Alert "FAILED to restart $svcName — MANUAL INTERVENTION NEEDED"
                        Log-Incident "SCORED SERVICE DOWN" "$svcName could not be restarted"
                    }
                } catch {
                    Write-Alert "Could not restart $svcName`: $_"
                }
            }
        }
    }
}

function Check-DefenderStatus {
    $defStatus = Get-MpComputerStatus 2>$null
    $baseline  = Get-Content "$StateDir\defender.baseline.json" 2>$null | ConvertFrom-Json

    if ($defStatus -and $baseline) {
        if (-not $defStatus.AntivirusEnabled -and $baseline.AntivirusEnabled) {
            Write-Alert "WINDOWS DEFENDER DISABLED — was enabled at baseline"
            Log-Incident "DEFENDER DISABLED" "Windows Defender was turned off"
        }
        if (-not $defStatus.RealTimeProtectionEnabled -and $baseline.RealTimeProtection) {
            Write-Alert "REAL-TIME PROTECTION DISABLED — was enabled at baseline"
            Log-Incident "REAL-TIME PROTECTION DISABLED" "Defender real-time protection turned off"
        }
    }
}

function Check-NewShares {
    $current  = Get-SmbShare | Select-Object Name, Path
    $baseline = Get-Content "$StateDir\shares.baseline.json" 2>$null | ConvertFrom-Json
    $baselineNames = $baseline | ForEach-Object { $_.Name }

    foreach ($share in $current) {
        if ($share.Name -notin $baselineNames) {
            Write-Alert "NEW NETWORK SHARE: $($share.Name) → $($share.Path)"
            Log-Incident "NEW SHARE CREATED" "$($share.Name) → $($share.Path)"
        }
    }
}

# ============================================================
# MAIN LOOP
# ============================================================
Clear-Host
Write-Host "PCDC 2026 | Astra 9 Windows Monitor" -ForegroundColor Blue
Write-Host "$('=' * 50)" -ForegroundColor Blue
Write-Host "Host:     $env:COMPUTERNAME"
Write-Host "Interval: ${Interval}s"
Write-Host "Services: $($Services -join ', ')"
Write-Host "Log:      $LogFile"
Write-Host "Incidents:$IncidentLog"
Write-Host "$('=' * 50)`n" -ForegroundColor Blue

Get-Baseline

Write-Info "Monitoring started. Press Ctrl+C to stop."
Write-Info "Type 'r' + Enter to generate incident report on demand."
Write-Host ""

$cycle = 0
while ($true) {
    $cycle++
    Write-Cycle $cycle

    Check-NewUsers
    Check-NewAdmins
    Check-NewPorts
    Check-NewServices
    Check-NewScheduledTasks
    Check-RegistryRunKeys
    Check-SuspiciousProcesses
    Check-BruteForce
    Check-ScoredServices
    Check-DefenderStatus
    Check-NewShares

    Write-Host ""

    # Non-blocking input check for incident report generation
    if ([Console]::KeyAvailable) {
        $key = [Console]::ReadKey($true)
        if ($key.KeyChar -eq 'r') {
            $reportFile = "$LogDir\incident_report_$(Get-Date -Format 'HHmmss').txt"
            @"
============================================================
PCDC 2026 | ASTRA 9 INCIDENT REPORT — WINDOWS
============================================================
Host:      $env:COMPUTERNAME
IP:        $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1).IPAddress)
Time:      $(Get-Date)
Reporter:  [YOUR NAME]

INCIDENTS DETECTED:
$(Get-Content $IncidentLog 2>$null)

CURRENT SYSTEM STATE:
Logged-in users:
$(query user 2>$null)

Established connections:
$(Get-NetTCPConnection -State Established | Format-Table LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess -AutoSize | Out-String)
============================================================
"@ | Set-Content $reportFile
            Write-OK "Incident report generated: $reportFile"
        }
    }

    # Jitter the sleep ±15% to prevent timing attacks
    $jitter = Get-Random -Minimum ([int]($Interval * 0.85)) -Maximum ([int]($Interval * 1.15))
    Start-Sleep -Seconds $jitter
}
