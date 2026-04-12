# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Active Directory Audit Script
#  pcdc_win_ad_audit.ps1
#
#  Run this on any machine with the RSAT AD tools installed,
#  or directly on a Domain Controller.
#
#  If you have an AD domain in your Blue Team Packet,
#  this is mandatory. AD is the highest-value target on a
#  Windows network. Own AD = own every Windows machine.
#
#  Checks:
#  - Domain admin membership (minimize this)
#  - Kerberoastable accounts (SPNs set on user accounts)
#  - AS-REP roastable accounts (no pre-auth required)
#  - Accounts with AdminCount=1 (historically privileged)
#  - Password-never-expires accounts
#  - Stale accounts (not logged in recently)
#  - New domain accounts (created recently)
#  - Group Policy Objects (new/modified GPOs = persistence)
#  - AD replication health
#  - Domain trusts
#  - SYSVOL/NETLOGON for scripts (common persistence)
#  - DC event logs for DCSync, Golden Ticket indicators
#
#  USAGE:
#    Set-ExecutionPolicy Bypass -Scope Process -Force
#    Import-Module ActiveDirectory
#    .\pcdc_win_ad_audit.ps1
#
#  Run as Domain Admin or equivalent.
# ============================================================

#Requires -Version 3.0

param(
    [string]$OutputPath = "$env:TEMP\blueTeam",
    [string]$Domain = $env:USERDNSDOMAIN
)

$ErrorActionPreference = "SilentlyContinue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "$OutputPath\logs"
$LogFile = "$LogDir\ad_audit_$Timestamp.log"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-OK      { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green;  Add-Content $LogFile "[OK]    $msg" }
function Write-Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow; Add-Content $LogFile "[WARN]  $msg" }
function Write-Bad     { param($msg) Write-Host "[BAD]   $msg" -ForegroundColor Red;    Add-Content $LogFile "[BAD]   $msg" }
function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan;   Add-Content $LogFile "[INFO]  $msg" }
function Write-Section {
    param($title)
    $line = "=" * 60
    Write-Host "`n$line" -ForegroundColor Blue
    Write-Host "  $title" -ForegroundColor Blue
    Write-Host "$line`n" -ForegroundColor Blue
    Add-Content $LogFile "`n$line`n  $title`n$line"
}

# Check AD module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ActiveDirectory module not found." -ForegroundColor Red
    Write-Host "Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Yellow
    exit 1
}
Import-Module ActiveDirectory

Write-Host "`nPCDC 2026 | Astra 9 Blue Team AD Audit" -ForegroundColor Blue
Write-Host "Domain: $Domain | DC: $env:LOGONSERVER | Time: $(Get-Date)"
Write-Host "Log: $LogFile`n"

# ============================================================
# SECTION 1: DOMAIN INFO
# ============================================================
Write-Section "SECTION 1: DOMAIN OVERVIEW"

$domainInfo = Get-ADDomain -Identity $Domain
Write-Info "Domain: $($domainInfo.DNSRoot)"
Write-Info "PDC Emulator: $($domainInfo.PDCEmulator)"
Write-Info "Domain Controllers: $($domainInfo.ReplicaDirectoryServers -join ', ')"
Write-Info "Forest: $($domainInfo.Forest)"
Write-Info "Functional Level: $($domainInfo.DomainMode)"

$dcCount = (Get-ADDomainController -Filter *).Count
Write-Info "DC Count: $dcCount"

# ============================================================
# SECTION 2: PRIVILEGED GROUP MEMBERSHIP
# ============================================================
Write-Section "SECTION 2: PRIVILEGED GROUP MEMBERSHIP"

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins",
                       "Administrators", "Group Policy Creator Owners", "Account Operators",
                       "Backup Operators", "Server Operators")

foreach ($group in $privilegedGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -Recursive 2>$null
        if ($members) {
            Write-Warn "$group ($($members.Count) members):"
            $members | ForEach-Object {
                $type = $_.objectClass
                Write-Info "  $($_.SamAccountName) [$type]"
                if ($group -eq "Domain Admins" -and $members.Count -gt 3) {
                    Write-Bad "  ^^^ Domain Admins has $($members.Count) members — should be minimal"
                }
            }
        } else {
            Write-OK "$group`: empty"
        }
    } catch {
        Write-Info "$group`: could not query"
    }
}

# ============================================================
# SECTION 3: KERBEROASTABLE ACCOUNTS
# ============================================================
Write-Section "SECTION 3: KERBEROASTABLE ACCOUNTS (SPN Set)"

Write-Warn "Accounts with SPNs are targets for Kerberoasting attacks."
Write-Warn "Red team can request their TGS tickets and crack offline."

$kerberoastable = Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
    -Properties ServicePrincipalName, LastLogonDate, PasswordLastSet, AdminCount |
    Where-Object { $_.SamAccountName -ne "krbtgt" }

if ($kerberoastable) {
    $kerberoastable | ForEach-Object {
        Write-Bad "  Kerberoastable: $($_.SamAccountName)"
        Write-Info "    SPNs: $($_.ServicePrincipalName -join ', ')"
        Write-Info "    Last login: $($_.LastLogonDate) | PwdSet: $($_.PasswordLastSet)"
        Write-Info "    AdminCount: $($_.AdminCount)"
        Write-Info "    FIX: Use strong 25+ char password or managed service accounts (gMSA)"
    }
} else {
    Write-OK "No Kerberoastable user accounts found"
}

# ============================================================
# SECTION 4: AS-REP ROASTABLE ACCOUNTS
# ============================================================
Write-Section "SECTION 4: AS-REP ROASTABLE ACCOUNTS"

Write-Warn "These accounts don't require Kerberos pre-authentication."
Write-Warn "Red team can request AS-REP without credentials and crack offline."

$asrepRoastable = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
    -Properties DoesNotRequirePreAuth, LastLogonDate, PasswordLastSet

if ($asrepRoastable) {
    $asrepRoastable | ForEach-Object {
        Write-Bad "  AS-REP Roastable: $($_.SamAccountName)"
        Write-Info "    Last login: $($_.LastLogonDate)"
        Write-Info "    FIX: Enable pre-auth: Set-ADUser $($_.SamAccountName) -KerberosEncryptionType AES256"
    }
} else {
    Write-OK "No AS-REP roastable accounts found"
}

# ============================================================
# SECTION 5: ADMINCOUNT = 1 ACCOUNTS
# ============================================================
Write-Section "SECTION 5: HISTORICALLY PRIVILEGED ACCOUNTS (AdminCount=1)"

Write-Info "AdminCount=1 means this account was once in a privileged group."
Write-Info "These accounts have relaxed ACL inheritance — common attack target."

$adminCountUsers = Get-ADUser -Filter { AdminCount -eq 1 } `
    -Properties AdminCount, MemberOf, LastLogonDate, PasswordLastSet |
    Where-Object { $_.SamAccountName -notin @("Administrator", "krbtgt") }

$privilegedNames = (Get-ADGroupMember -Identity "Domain Admins" -Recursive).SamAccountName

$adminCountUsers | ForEach-Object {
    $isCurrentAdmin = $_.SamAccountName -in $privilegedNames
    if (-not $isCurrentAdmin) {
        Write-Warn "  AdminCount=1 but NOT currently in privileged group: $($_.SamAccountName)"
        Write-Info "    Run SDProp to fix: Invoke-Command {repadmin /syncall /AdeP} then wait for SDProp"
    } else {
        Write-Info "  AdminCount=1 (current admin): $($_.SamAccountName)"
    }
}

# ============================================================
# SECTION 6: ACCOUNT HYGIENE
# ============================================================
Write-Section "SECTION 6: ACCOUNT HYGIENE"

# Password never expires
Write-Info "Accounts with password set to never expire:"
Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } |
    ForEach-Object {
        Write-Warn "  Password never expires: $($_.SamAccountName)"
    }

# Stale accounts
$staleCutoff = (Get-Date).AddDays(-30)
Write-Host ""
Write-Info "Enabled accounts not logged in for 30+ days (stale):"
Get-ADUser -Filter { LastLogonDate -lt $staleCutoff -and Enabled -eq $true } `
    -Properties LastLogonDate |
    ForEach-Object {
        Write-Warn "  Stale: $($_.SamAccountName) — last login: $($_.LastLogonDate)"
    }

# Recently created accounts
$recentCutoff = (Get-Date).AddDays(-7)
Write-Host ""
Write-Info "Accounts created in the last 7 days:"
Get-ADUser -Filter { Created -gt $recentCutoff } -Properties Created | ForEach-Object {
    Write-Warn "  New account: $($_.SamAccountName) — created: $($_.Created)"
}

# Disabled accounts with group memberships
Write-Host ""
Write-Info "Disabled accounts that still have group memberships:"
Get-ADUser -Filter { Enabled -eq $false } -Properties MemberOf | ForEach-Object {
    if ($_.MemberOf.Count -gt 1) {
        Write-Warn "  $($_.SamAccountName) is disabled but in $($_.MemberOf.Count) groups"
    }
}

# ============================================================
# SECTION 7: GROUP POLICY OBJECTS
# ============================================================
Write-Section "SECTION 7: GROUP POLICY OBJECTS"

Write-Info "All GPOs (sorted by last modification — newest first):"
Get-GPO -All | Sort-Object ModificationTime -Descending | ForEach-Object {
    $age = (Get-Date) - $_.ModificationTime
    $ageStr = if ($age.TotalHours -lt 24) {
        "MODIFIED $([int]$age.TotalHours)h ago"
    } elseif ($age.TotalDays -lt 7) {
        "Modified $([int]$age.TotalDays) days ago"
    } else {
        "Modified $($_.ModificationTime.ToString('yyyy-MM-dd'))"
    }

    if ($age.TotalHours -lt 24) {
        Write-Bad "  [RECENT] $($_.DisplayName) — $ageStr"
    } elseif ($age.TotalDays -lt 7) {
        Write-Warn "  $($_.DisplayName) — $ageStr"
    } else {
        Write-Info "  $($_.DisplayName) — $ageStr"
    }
}

# ============================================================
# SECTION 8: DOMAIN TRUSTS
# ============================================================
Write-Section "SECTION 8: DOMAIN TRUSTS"

$trusts = Get-ADTrust -Filter * 2>$null
if ($trusts) {
    $trusts | ForEach-Object {
        Write-Warn "  Trust: $($_.Name) | Direction: $($_.Direction) | Type: $($_.TrustType)"
        if ($_.Direction -eq "Bidirectional") {
            Write-Bad "  ^^^ Bidirectional trust — compromise propagates both ways"
        }
    }
} else {
    Write-OK "No external domain trusts configured"
}

# ============================================================
# SECTION 9: SYSVOL/NETLOGON SCRIPTS
# ============================================================
Write-Section "SECTION 9: SYSVOL AND NETLOGON SCRIPTS"

Write-Info "Scripts in NETLOGON and SYSVOL (common persistence location):"
$sysvolPath = "\\$Domain\SYSVOL\$Domain"
$netlogonPath = "\\$Domain\NETLOGON"

@($sysvolPath, $netlogonPath) | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem -Path $_ -Recurse -File 2>$null | ForEach-Object {
            $age = (Get-Date) - $_.LastWriteTime
            if ($age.TotalHours -lt 24) {
                Write-Bad "  [MODIFIED RECENTLY] $($_.FullName) — $($_.LastWriteTime)"
            } else {
                Write-Info "  $($_.FullName)"
            }
        }
    }
}

# ============================================================
# SECTION 10: DC EVENT LOG - DCSYNC / GOLDEN TICKET
# ============================================================
Write-Section "SECTION 10: DC EVENT LOG - HIGH-VALUE ATTACK INDICATORS"

Write-Info "Checking for DCSync indicators (Event 4662 — replication rights):"
Get-WinEvent -LogName Security -MaxEvents 1000 2>$null |
    Where-Object { $_.Id -eq 4662 } |
    Where-Object { $_.Message -match "1131f968|1131f969|89e95b76" } |
    Select-Object -First 5 | ForEach-Object {
        Write-Bad "  POSSIBLE DCSYNC: $($_.TimeCreated) — $($_.Message | Select-String 'Account Name:.*' | Select-Object -First 1)"
    }

Write-Info "Checking for Golden Ticket indicators (Event 4768 with unusual encryption):"
Get-WinEvent -LogName Security -MaxEvents 500 2>$null |
    Where-Object { $_.Id -eq 4768 } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $encType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TicketEncryptionType" }).'#text'
        # 0x17 = RC4-HMAC, old algorithm — suspicious if domain uses AES
        if ($encType -eq "0x17") {
            Write-Warn "  Kerberos TGT with RC4 encryption (possible Golden Ticket): $($_.TimeCreated)"
        }
    }

Write-Info "Checking for Pass-the-Hash indicators (Event 4624 logon type 3 with NTLM):"
Get-WinEvent -LogName Security -MaxEvents 500 2>$null |
    Where-Object { $_.Id -eq 4624 } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $logonType    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "LogonType" }).'#text'
        $authPackage  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "AuthenticationPackageName" }).'#text'
        $workstation  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "WorkstationName" }).'#text'
        $targetUser   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'

        if ($logonType -eq "3" -and $authPackage -eq "NTLM" -and
            $targetUser -notin @("ANONYMOUS LOGON", "-")) {
            Write-Warn "  NTLM network logon: $targetUser from $workstation at $($_.TimeCreated)"
        }
    }

# ============================================================
# SECTION 11: KRBTGT ACCOUNT
# ============================================================
Write-Section "SECTION 11: KRBTGT ACCOUNT"

$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet, PasswordNeverExpires
Write-Info "krbtgt password last set: $($krbtgt.PasswordLastSet)"
$krbtgtAge = (Get-Date) - $krbtgt.PasswordLastSet
if ($krbtgtAge.TotalDays -gt 180) {
    Write-Warn "krbtgt password is $([int]$krbtgtAge.TotalDays) days old"
    Write-Info "  Consider resetting (TWICE with interval) to invalidate any Golden Tickets"
    Write-Info "  Reset script: Reset-KrbtgtKeyInteractiveWorkflow (Microsoft tool)"
} else {
    Write-OK "krbtgt password reset $([int]$krbtgtAge.TotalDays) days ago"
}

# ============================================================
# DONE
# ============================================================
Write-Section "AD AUDIT COMPLETE"
Write-OK "Log saved to: $LogFile"
Write-Host ""
Write-Host "HIGH PRIORITY FIXES:" -ForegroundColor Yellow
Write-Host "  1. Remove unnecessary Domain Admin members" -ForegroundColor Yellow
Write-Host "  2. Fix Kerberoastable accounts (strong passwords or gMSA)" -ForegroundColor Yellow
Write-Host "  3. Fix AS-REP roastable accounts (enable pre-auth)" -ForegroundColor Yellow
Write-Host "  4. Investigate any GPOs modified in last 24 hours" -ForegroundColor Yellow
Write-Host "  5. Review SYSVOL scripts modified recently" -ForegroundColor Yellow
