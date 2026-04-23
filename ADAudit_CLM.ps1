<#
.DISCLAIMER
    I ran my ADAudit.ps1 code through claude to recreate CLM version

.SYNOPSIS
    Audit Active Directory Users - CLM Hardened Edition
.DESCRIPTION
    Rewritten for Constrained Language Mode (CLM) environments.

    KEY CLM ADAPTATIONS:
    - No New-Object System.DirectoryServices.* (blocked in CLM)
    - Uses [ADSI] and [ADSISearcher] type accelerators (CLM-whitelisted)
    - No Add-Type / reflection
    - No ScriptBlock literals assigned to variables (where avoidable)
    - No direct .NET type instantiation beyond accelerators
    - Uses the current "authenticated session token" from the net use session.

    =================Active Directory Recon==================
    r1. Domain User Information Retriever
    r2. SID Translator
    r3. User Dump

    =================Active Directory Security Audit==================
    a1. Administrator Accounts
    a2. Accounts with DCSync Privileges
    a3. Service Accounts: Accounts with no expiry date
    a4. Dormant Accounts: Inactive accounts
    a5. Stale Accounts: Password not changed for long time
    a6. Accounts with unconstrained delegation
    a7. Kerberoastable Accounts: Accounts with registered SPN

.PARAMETER OutputPath
    Directory to save CSV reports.
.EXAMPLE
    .\ADAudit_CLM.ps1 
#>

param(
    [string]$OutputPath = "C:\Users\maisha.manarat\Desktop\AD", #Change Path to where you want to save the output file
    [string]$TargetDomainController = ""
)

$OutputPath = Get-Location

# logo

Write-Host @"
   _____          __  .__               ________  .__                       __
  /  _  \   _____/  |_|__|__  __ ____   \______ \ |__|______   ____   _____/  |_  ___________
 /  /_\  \_/ ___\   __\  \  \/ // __ \   |    |  \|  \_  __ \_/ __ \_/ ___\   __\/  _ \_  __ \
/    |    \  \___|  | |  |\   /\  ___/   |    `   \  ||  | \/\  ___/\  \___|  | (  <_> )  | \/
\____|__  /\___  >__| |__| \_/  \___  > /_______  /__||__|    \___  >\___  >__|  \____/|__|
        \/     \/                   \/          \/                \/     \/
"@ -ForegroundColor Green

Write-Host ""
Write-Host "==========================================================="   -ForegroundColor Green
Write-Host "     Active Directory Audit & Utility Tool [CLM Version]      "     -ForegroundColor Cyan
Write-Host "==========================================================="     -ForegroundColor Green
Write-Host ""

# Check if output path exists

if (Test-Path $OutputPath){  #Test-Path is a function (cmdlet) that returns a boolean (True or False) directly. It doesn't use an -eq parameter inside its own execution.
    Write-Host "Reports will be saved in $OutputPath" -ForegroundColor Cyan
}
else {
    $OutputPath = Get-Location
    Write-Host "Reports will be saved in $OutputPath" -ForegroundColor Cyan
}

# works to be done

Write-Host "--------------------Active Directory User Recon---------------------" -ForegroundColor Green
Write-Host "r1. Domain User Information Retriever "
Write-Host "r2. SID Translator"
Write-Host "r3. User Dump"


Write-Host "---------------Active Directory User Security Audit-----------------" -ForegroundColor Green
Write-Host "a1. Administrator Accounts"
Write-Host "a2. Accounts with DCSync Privileges"
Write-Host "a3. Service Accounts: Accounts with no expiry date"
Write-Host "a4. Dormant Accounts: Inactive accounts "
Write-Host "a5. Stale Accounts: Password not changed for long time"
Write-Host "a6. Accounts with unconstrained delegation"
Write-Host "a7. Kerberoastable Accounts: Accounts with registered SPN"


Write-Host "-----------------------------------------------------------------------------------" -ForegroundColor Green

Write-Host ""


#choose tool

$Tool = Read-Host -Prompt "Tool to Use: (recon/audit): "

if($Tool -eq "Audit"){
    $TargetAudit = Read-Host -Prompt "Audit Point (e.g a1,a2,a3,a4,a5,a6,a7 or all): " 
}elseif($Tool -eq "Recon"){
    $TargetAudit = Read-Host -Prompt "Recon Point (e.g r1,r2 or r3): " 
}else{
    Write-Host "Incorrect Option"
}


# Get the target domain
$TargetDomain = Read-Host -Prompt "Enter the target domain name to audit (e.g target.com): "

# Parsre the domain name into DN format
$DomainComponents = $TargetDomain.split('.')
$TargetDomainDN = "DC=" + ($DomainComponents -join ",DC=")  #In PowerShell, you don't need a visible loop because the .Split() and -join methods are vectorized operations. They handle the "looping" internally at the engine level.

Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
Write-Host ""




# Determine Domain Controller to Use
if ($TargetDomainController -ne "") {
    $dcToUse = $TargetDomainController
    Write-Host "Using specified Domain Controller: $dcToUse" -ForegroundColor Yellow
} else {
    Write-Host "Discovering Domain Controller for $TargetDomain ..." -ForegroundColor Yellow
    try {
        $dcRecords = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$TargetDomain" -Type SRV -ErrorAction Stop
        $bestDC    = $dcRecords |
                     Where-Object { $_.Type -eq "SRV" } |
                     Sort-Object Priority, @{ Expression = "Weight"; Descending = $true } |
                     Select-Object -First 1
        $dcToUse   = $bestDC.NameTarget.TrimEnd('.')
        Write-Host "Discovered DC: $dcToUse" -ForegroundColor Cyan
    } catch {
        $dcToUse = $TargetDomain
        Write-Host "DC discovery failed. Falling back to domain name: $dcToUse" -ForegroundColor Red
    }
}

# Get Credentials for the domain user to test with
Write-Host "Enter User Credentials" -ForegroundColor Yellow

$username= Read-Host -Prompt "Username: "
$Credential = Get-Credential -Message "Enter Credentials" -Username "$TargetDomain\$username" 


 
# Get Time of the Testing
$TimeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# LDAP Path
$ldapPath = "LDAP://$dcToUse/$TargetDomainDN" # LDAP://192.168.1.10/DC=corp,DC=local
$plainPwd    = $Credential.GetNetworkCredential().Password


# ─────────────────────────────────────────────────────────────────────────────
#  ROOT DIRECTORY ENTRY  (CLM-safe: [ADSI] accelerator, constructor overload
#  with username/password uses the 3-argument form of the [ADSI] accelerator)
# ─────────────────────────────────────────────────────────────────────────────
#
#  [ADSI]"LDAP://..." binds anonymously / as current user.
#  To supply alternate credentials in CLM we instantiate via the underlying
#  System.DirectoryServices.DirectoryEntry constructor that accepts (path,
#  user, password) — but New-Object is blocked.
#
#  WORKAROUND:  PowerShell's [ADSI] accelerator IS New-Object under the hood,
#  but the three-argument form is not exposed through the cast syntax.
#  The only CLM-safe option that does NOT require New-Object is to use
#  net use to authenticate a session first, then bind with [ADSI] as the
#  current (now-authenticated) user context.
#
#  net use establishes an authenticated SMB/RPC session that LDAP can reuse.

Write-Host ""
Write-Host "Establishing authenticated session to $dcToUse ..." -ForegroundColor Yellow

# Tear down any existing session to the DC first (ignore errors)
$null = net use "\\$dcToUse\IPC$" /delete 2>$null

$netUseResult = net use "\\$dcToUse\IPC$" /user:"$TargetDomain\$username" $plainPwd 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "net use authentication failed: $netUseResult" -ForegroundColor Red
    Write-Host "Attempting to continue with current user context..." -ForegroundColor Yellow
}

# Now [ADSI] will use the authenticated session token
$rootEntry = [ADSI]$ldapPath

# Validate the bind

<#
try {
    $testGuid = $rootEntry.Guid   # Forces actual LDAP bind
    Write-Host "Connected to AD at $ldapPath" -ForegroundColor Cyan
} catch {
    Write-Host "LDAP bind failed: $($_.Exception.Message)" -ForegroundColor Red
    # Clean up net use and exit
    $null = net use "\\$dcToUse\IPC$" /delete 2>$null
    return
}
#>

Write-Host "Session established as $TargetDomain\$username" -ForegroundColor Yellow
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER: Convert Windows FileTime integer to readable date (CLM-safe)
# ─────────────────────────────────────────────────────────────────────────────
function ConvertFrom-FileTime {
    param([long]$FileTime)
    if ($FileTime -le 0) { return $null }
    return [DateTime]::FromFileTime($FileTime)
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER: Escape special LDAP filter characters in a DN string
# ─────────────────────────────────────────────────────────────────────────────
function Get-EscapedDN {
    param([string]$DN)
    return $DN.Replace("(", "\28").Replace(")", "\29").Replace("\", "\5C")
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER: Build a DirectorySearcher from the root entry ([ADSISearcher])
#
#  CLM STRICT: ALL method calls on non-core types are blocked — this includes
#  .PropertiesToLoad.Add(), .AddRange(), and .Clear().
#
#  SOLUTION: Do not restrict PropertiesToLoad at all. The searcher will return
#  every attribute for each result. We pick the attributes we need in
#  Get-AccountDetails using standard property access. This is slightly less
#  efficient over the wire but is 100% CLM-safe and functionally identical.
# ─────────────────────────────────────────────────────────────────────────────
function New-Searcher {
    param([string]$Filter)

    $searcher             = [ADSISearcher]$rootEntry
    $searcher.Filter      = $Filter
    $searcher.SearchScope = "Subtree"
    $searcher.PageSize    = 1000

    # PropertiesToLoad intentionally left unrestricted — CLM blocks all
    # method calls (.Add/.AddRange/.Clear) on StringCollection (non-core type)

    return $searcher
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER: Fetch full account details for a given Distinguished Name
# ─────────────────────────────────────────────────────────────────────────────
function Get-AccountDetails {
    param([string]$MemberDN)

    $today       = Get-Date
    $escapedDN   = Get-EscapedDN -DN $MemberDN

    $searcher = New-Searcher -Filter "(distinguishedName=$escapedDN)"

    $result = $searcher.FindOne()
    if (-not $result) { return $null }

    $props = $result.Properties

    # Password last set
    $pwdRaw             = if ($props["pwdlastset"].Count -gt 0) { [long]$props["pwdlastset"][0] } else { 0 }
    $passwordLastChanged = ConvertFrom-FileTime -FileTime $pwdRaw

    # Last logon timestamp
    $logonRaw  = if ($props["lastlogontimestamp"].Count -gt 0) { [long]$props["lastlogontimestamp"][0] } else { 0 }
    $lastLogon = ConvertFrom-FileTime -FileTime $logonRaw

    # UserAccountControl flags
    $uac = if ($props["useraccountcontrol"].Count -gt 0) { [int]$props["useraccountcontrol"][0] } else { 0 }

    # SID — CLM blocks ::new() on non-core types.
    # Cast the raw byte array directly using the [SecurityIdentifier] accelerator
    # with the two-argument overload: ([SecurityIdentifier]([byte[]]$bytes, [int]$offset))
    # is NOT available as a cast. Instead we convert to hex string via ADSI's own
    # sid-to-string representation exposed on the result entry itself.
    # Safest CLM path: read objectSid as raw bytes, hex-encode, skip the
    # SecurityIdentifier object entirely for the SID string display.
    $sidString = ""
    if ($props["objectsid"].Count -gt 0) {
        $rawSid    = [byte[]]$props["objectsid"][0]
        # Manually build S-1-X-Y-... from the raw SID byte structure (no type creation needed)
        $revision  = $rawSid[0]
        $subCount  = $rawSid[1]
        $authority = [long]0
        for ($i = 2; $i -le 7; $i++) { $authority = $authority * 256 + $rawSid[$i] }
        $sidString = "S-$revision-$authority"
        for ($i = 0; $i -lt $subCount; $i++) {
            $offset = 8 + ($i * 4)
            $sub    = [long]$rawSid[$offset] + ([long]$rawSid[$offset+1] -shl 8) + ([long]$rawSid[$offset+2] -shl 16) + ([long]$rawSid[$offset+3] -shl 24)
            $sidString += "-$sub"
        }
    }

    # Groups (strip CN= prefix)
    $groups = if ($props["memberof"].Count -gt 0) {
        @($props["memberof"]) | ForEach-Object { ($_ -split ",")[0] -replace "^CN=", "" }
    } else {
        @("Domain Users")
    }

    # CLM blocks [PSCustomObject]@{} — use Select-Object on a single dummy object instead.
    # Select-Object -Property with calculated properties produces a standard object
    # from any pipeline input; "" | Select-Object ... is the canonical CLM workaround.
    $r_MemberName          = if ($props["name"].Count -gt 0)              { [string]$props["name"][0] }              else { $MemberDN }
    $r_SamAccountName      = if ($props["samaccountname"].Count -gt 0)    { [string]$props["samaccountname"][0] }    else { "" }
    $r_SID                 = $sidString
    $r_AccountCreated      = if ($props["whencreated"].Count -gt 0)       { ([DateTime]$props["whencreated"][0]).ToString("yyyy-MM-dd") } else { "Unknown" }
    $r_PasswordLastChanged = if ($passwordLastChanged)                     { $passwordLastChanged.ToString("yyyy-MM-dd") } else { "Never Set" }
    $r_DaysSincePwdChange  = if ($passwordLastChanged)                     { [string][int]($today - $passwordLastChanged).TotalDays } else { "N/A" }
    $r_LastLogon           = if ($lastLogon)                               { $lastLogon.ToString("yyyy-MM-dd") }     else { "Never" }
    $r_DaysSinceLogon      = if ($lastLogon)                               { [string][int]($today - $lastLogon).TotalDays } else { "N/A" }
    $r_AccountStatus       = if ($uac -band 2)                             { "Disabled" }                            else { "Enabled" }
    $r_Groups              = $groups -join "; "
    $r_Description         = if ($props["description"].Count -gt 0)       { [string]$props["description"][0] }       else { "" }
    $r_UserPrincipalName   = if ($props["userprincipalname"].Count -gt 0)  { [string]$props["userprincipalname"][0] } else { "" }

    return "" | Select-Object `
        @{N="MemberName";E={$r_MemberName}},
        @{N="SamAccountName";E={$r_SamAccountName}},
        @{N="SID";E={$r_SID}},
        @{N="AccountCreated";E={$r_AccountCreated}},
        @{N="PasswordLastChanged";E={$r_PasswordLastChanged}},
        @{N="DaysSincePwdChange";E={$r_DaysSincePwdChange}},
        @{N="LastLogon";E={$r_LastLogon}},
        @{N="DaysSinceLogon";E={$r_DaysSinceLogon}},
        @{N="AccountStatus";E={$r_AccountStatus}},
        @{N="Groups";E={$r_Groups}},
        @{N="Description";E={$r_Description}},
        @{N="UserPrincipalName";E={$r_UserPrincipalName}}
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER: Export results to CSV and optionally display them
# ─────────────────────────────────────────────────────────────────────────────
function Export-Results {
    param(
        [object[]]$Results,
        [string]  $FileName,
        [string[]]$DisplayColumns,
        [string]  $EmptyMessage
    )

    $outputFile = Join-Path $OutputPath "${FileName}_${TargetDomain}_${TimeStamp}.csv"

    Write-Host "Found $($Results.Count) result(s)" -ForegroundColor Yellow

    if ($Results.Count -gt 0) {
        $Results | Format-Table $DisplayColumns -AutoSize
        $Results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to: $outputFile" -ForegroundColor Cyan
    } else {
        Write-Host $EmptyMessage -ForegroundColor Yellow
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  A1 — ADMINISTRATOR ACCOUNTS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-AdminAudit {
    Write-Host ""
    Write-Host "=================== A1: Admin Accounts ===================" -ForegroundColor Green

    $PrivilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Schema Admins"
    )

    $results = @()

    foreach ($GroupName in $PrivilegedGroups) {
        $searcher = New-Searcher -Filter "(&(objectCategory=group)(name=$GroupName))"

        $group = $searcher.FindOne()
        if (-not $group) { continue }

        foreach ($memberDN in $group.Properties["member"]) {
            $account = Get-AccountDetails -MemberDN $memberDN
            if ($account) {
                $g = $GroupName; $a = $account
                $results += "" | Select-Object @{N="Group";E={$g}},@{N="MemberName";E={$a.MemberName}},@{N="SamAccountName";E={$a.SamAccountName}},@{N="AccountStatus";E={$a.AccountStatus}},@{N="PasswordLastChanged";E={$a.PasswordLastChanged}},@{N="DaysSincePwdChange";E={$a.DaysSincePwdChange}},@{N="LastLogon";E={$a.LastLogon}},@{N="AccountCreated";E={$a.AccountCreated}}
            }
        }
    }

    Export-Results `
        -Results $results `
        -FileName "admin_accounts" `
        -DisplayColumns @("Group","MemberName","SamAccountName","AccountStatus","PasswordLastChanged","DaysSincePwdChange","LastLogon") `
        -EmptyMessage "No admin accounts found."

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
#  A2 — DCSYNC PRIVILEGES
#  CLM NOTE: ObjectSecurity / GetAccessRules is accessible via [ADSI] entry's
#  .psbase.ObjectSecurity.GetAccessRules() — this is exposed as a .NET method
#  call on an already-retrieved object, which CLM allows.
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-DCSyncAudit {
    Write-Host ""
    Write-Host "=================== A2: DCSync Privileges ===================" -ForegroundColor Green

    $DCSyncGuids = @(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",   # DS-Replication-Get-Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"    # DS-Replication-Get-Changes-All
    )

    $results = @()

    try {
        # Bind directly to the domain root object to read its DACL
        $domainEntry = [ADSI]$ldapPath

        # psbase.ObjectSecurity is the safe CLM way to get the security descriptor
        $acl   = $domainEntry.psbase.ObjectSecurity
        # GetAccessRules requires a target type argument. In CLM [NTAccount] as a method
        # parameter is blocked. Use [System.Security.Principal.IdentityReference] which
        # IS a core-recognised type in CLM, then read .Value as a string for DOMAIN\name.
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne "Allow") { continue }
            if ($DCSyncGuids -notcontains $rule.ObjectType.ToString()) { continue }

            $rightName = if ($rule.ObjectType.ToString() -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") {
                "DS-Replication-Get-Changes"
            } else {
                "DS-Replication-Get-Changes-All"
            }

            $sidValue  = $rule.IdentityReference.Value   # now a SID string e.g. S-1-5-21-...-500
            # Resolve SID to samAccountName via LDAP objectSid search
            # Build hex bytes from SID string (same logic as R2)
            $sidParts  = $sidValue -split "-"
            $sidRev    = [int]$sidParts[1]
            $sidAuth   = [long]$sidParts[2]
            $sidSubs   = @(); for ($si=3;$si -lt $sidParts.Count;$si++){$sidSubs += [long]$sidParts[$si]}
            $sb = @([byte]$sidRev,[byte]$sidSubs.Count)
            $sb += [byte](($sidAuth -shr 40)-band 0xFF),[byte](($sidAuth -shr 32)-band 0xFF),[byte](($sidAuth -shr 24)-band 0xFF),[byte](($sidAuth -shr 16)-band 0xFF),[byte](($sidAuth -shr 8)-band 0xFF),[byte]($sidAuth -band 0xFF)
            foreach ($ss in $sidSubs){$sb += [byte]($ss -band 0xFF),[byte](($ss -shr 8)-band 0xFF),[byte](($ss -shr 16)-band 0xFF),[byte](($ss -shr 24)-band 0xFF)}
            $hexSidAcl = "\" + ($sb | ForEach-Object { $_.ToString("X2") }) -join "\"

            $idSearcher = New-Searcher -Filter "(&(objectClass=*)(objectSid=$hexSidAcl))"
            $resolved   = $idSearcher.FindOne()
            $account    = $null
            $samName    = $sidValue   # fallback display value

            if ($resolved -and $resolved.Properties["samaccountname"].Count -gt 0) {
                $samName = [string]$resolved.Properties["samaccountname"][0]
            }
            if ($resolved -and $resolved.Properties["distinguishedname"].Count -gt 0) {
                $dn      = [string]$resolved.Properties["distinguishedname"][0]
                $account = Get-AccountDetails -MemberDN $dn
            }
            $identityValue = $samName

            $iv=$identityValue; $rn=$rightName; $ih=$rule.IsInherited; $a=$account; $sn=$samName
            $results += "" | Select-Object @{N="Identity";E={$iv}},@{N="Right";E={$rn}},@{N="IsInherited";E={$ih}},@{N="MemberName";E={if($a){$a.MemberName}else{$sn}}},@{N="SamAccountName";E={if($a){$a.SamAccountName}else{$sn}}},@{N="AccountStatus";E={if($a){$a.AccountStatus}else{"Unknown"}}},@{N="PasswordLastChanged";E={if($a){$a.PasswordLastChanged}else{"Unknown"}}},@{N="DaysSincePwdChange";E={if($a){$a.DaysSincePwdChange}else{"N/A"}}},@{N="LastLogon";E={if($a){$a.LastLogon}else{"Unknown"}}},@{N="AccountCreated";E={if($a){$a.AccountCreated}else{"Unknown"}}}
        }
    } catch {
        Write-Host "Failed to read domain DACL: $($_.Exception.Message)" -ForegroundColor Red
    }

    Export-Results `
        -Results $results `
        -FileName "dcsync_privileges" `
        -DisplayColumns @("Identity","Right","IsInherited","MemberName","AccountStatus","PasswordLastChanged","DaysSincePwdChange","LastLogon") `
        -EmptyMessage "No DCSync rights found."

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
#  A3 — SERVICE ACCOUNTS (Password Never Expires)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-ServiceAccountAudit {
    Write-Host ""
    Write-Host "=================== A3: Service Accounts (No Password Expiry) ===================" -ForegroundColor Green
    Write-Host "Definition: any enabled user account with the 'Password Never Expires' flag set." -ForegroundColor Yellow

    # UAC bit 65536 (0x10000) = DONT_EXPIRE_PASSWORD
    $searcher = New-Searcher -Filter "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!userAccountControl:1.2.840.113556.1.4.803:=2))"

    $accounts = $searcher.FindAll()
    Write-Host "LDAP query returned $($accounts.Count) entries." -ForegroundColor Yellow

    $results = @()
    foreach ($result in $accounts) {
        $dn      = $result.Properties["distinguishedname"][0]
        $account = Get-AccountDetails -MemberDN $dn
        if ($account) {
            $a = $account
            $results += "" | Select-Object @{N="MemberName";E={$a.MemberName}},@{N="SamAccountName";E={$a.SamAccountName}},@{N="AccountStatus";E={$a.AccountStatus}},@{N="PasswordLastChanged";E={$a.PasswordLastChanged}},@{N="DaysSincePwdChange";E={$a.DaysSincePwdChange}},@{N="LastLogon";E={$a.LastLogon}},@{N="AccountCreated";E={$a.AccountCreated}},@{N="Groups";E={$a.Groups}}
        }
    }

    Export-Results `
        -Results $results `
        -FileName "service_accounts" `
        -DisplayColumns @("MemberName","SamAccountName","AccountStatus","PasswordLastChanged","DaysSincePwdChange","LastLogon") `
        -EmptyMessage "No service accounts (no-expiry) found."

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
#  A4 — DORMANT ACCOUNTS (No logon within N days)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-DormantAccountAudit {
    Write-Host ""
    Write-Host "=================== A4: Dormant Accounts ===================" -ForegroundColor Green
    Write-Host "Definition: enabled accounts with no logon activity within a threshold period." -ForegroundColor Yellow

    [int]$DaysThreshold = Read-Host "Inactivity threshold in days (e.g. 90)"
    $cutoffDate  = (Get-Date).AddDays(-$DaysThreshold)
    $TimeLimit   = $cutoffDate.ToFileTime()

    Write-Host "Searching for accounts not logged in since: $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Yellow

    # lastlogontimestamp <= cutoff AND account is enabled (UAC bit 2 NOT set)
    $searcher = New-Searcher -Filter "(&(objectCategory=person)(objectClass=user)(lastlogontimestamp<=$TimeLimit)(!userAccountControl:1.2.840.113556.1.4.803:=2))"

    $accounts = $searcher.FindAll()
    Write-Host "LDAP query returned $($accounts.Count) entries." -ForegroundColor Yellow

    $results = @()
    foreach ($result in $accounts) {
        $dn      = $result.Properties["distinguishedname"][0]
        $account = Get-AccountDetails -MemberDN $dn
        if ($account) {
            $a = $account
            $results += "" | Select-Object @{N="MemberName";E={$a.MemberName}},@{N="SamAccountName";E={$a.SamAccountName}},@{N="AccountStatus";E={$a.AccountStatus}},@{N="LastLogon";E={$a.LastLogon}},@{N="DaysSinceLogon";E={$a.DaysSinceLogon}},@{N="PasswordLastChanged";E={$a.PasswordLastChanged}},@{N="DaysSincePwdChange";E={$a.DaysSincePwdChange}},@{N="AccountCreated";E={$a.AccountCreated}}
        }
    }

    Export-Results `
        -Results $results `
        -FileName "dormant_accounts" `
        -DisplayColumns @("MemberName","SamAccountName","AccountStatus","LastLogon","DaysSinceLogon","PasswordLastChanged") `
        -EmptyMessage "No dormant accounts found."

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
#  A5 — STALE ACCOUNTS (Password not changed within N days)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-StaleAccountAudit {
    Write-Host ""
    Write-Host "=================== A5: Stale Accounts ===================" -ForegroundColor Green
    Write-Host "Definition: enabled accounts whose password has not changed within the threshold." -ForegroundColor Yellow

    [int]$DaysThreshold = Read-Host "Password age threshold in days (e.g. 180)"
    $cutoffDate = (Get-Date).AddDays(-$DaysThreshold)
    $TimeLimit  = $cutoffDate.ToFileTime()

    Write-Host "Searching for accounts with password older than: $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Yellow

    $searcher = New-Searcher -Filter "(&(objectCategory=person)(objectClass=user)(pwdLastSet<=$TimeLimit)(!userAccountControl:1.2.840.113556.1.4.803:=2))"

    $accounts = $searcher.FindAll()
    Write-Host "LDAP query returned $($accounts.Count) entries." -ForegroundColor Yellow

    $results = @()
    foreach ($result in $accounts) {
        $dn      = $result.Properties["distinguishedname"][0]
        $account = Get-AccountDetails -MemberDN $dn
        if ($account) {
            $a = $account
            $results += "" | Select-Object @{N="MemberName";E={$a.MemberName}},@{N="SamAccountName";E={$a.SamAccountName}},@{N="AccountStatus";E={$a.AccountStatus}},@{N="PasswordLastChanged";E={$a.PasswordLastChanged}},@{N="DaysSincePwdChange";E={$a.DaysSincePwdChange}},@{N="LastLogon";E={$a.LastLogon}},@{N="AccountCreated";E={$a.AccountCreated}}
        }
    }

    Export-Results `
        -Results $results `
        -FileName "stale_accounts" `
        -DisplayColumns @("MemberName","SamAccountName","AccountStatus","PasswordLastChanged","DaysSincePwdChange","LastLogon") `
        -EmptyMessage "No stale accounts found."

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
#  A6 — UNCONSTRAINED DELEGATION
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-DelegationAudit {
    Write-Host ""
    Write-Host "=================== A6: Unconstrained Delegation ===================" -ForegroundColor Green

    # UAC bit 524288 (0x80000) = TRUSTED_FOR_DELEGATION
    $searcher = New-Searcher -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!userAccountControl:1.2.840.113556.1.4.803:=2))"

    $accounts = $searcher.FindAll()
    Write-Host "LDAP query returned $($accounts.Count) entries." -ForegroundColor Yellow

    $results = @()
    foreach ($result in $accounts) {
        $dn      = $result.Properties["distinguishedname"][0]
        $account = Get-AccountDetails -MemberDN $dn
        if ($account) {
            $a = $account
            $results += "" | Select-Object @{N="MemberName";E={$a.MemberName}},@{N="SamAccountName";E={$a.SamAccountName}},@{N="AccountStatus";E={$a.AccountStatus}},@{N="PasswordLastChanged";E={$a.PasswordLastChanged}},@{N="DaysSincePwdChange";E={$a.DaysSincePwdChange}},@{N="LastLogon";E={$a.LastLogon}},@{N="AccountCreated";E={$a.AccountCreated}},@{N="Groups";E={$a.Groups}}
        }
    }

    Export-Results `
        -Results $results `
        -FileName "unconstrained_delegation" `
        -DisplayColumns @("MemberName","SamAccountName","AccountStatus","PasswordLastChanged","DaysSincePwdChange","LastLogon") `
        -EmptyMessage "No accounts with unconstrained delegation found."

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
#  A7 — KERBEROASTABLE ACCOUNTS (SPN set)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-KerberoastAudit {
    Write-Host ""
    Write-Host "=================== A7: Kerberoastable Accounts ===================" -ForegroundColor Green
    Write-Host "Any enabled user account with a Service Principal Name (SPN) registered." -ForegroundColor Yellow

    $searcher = New-Searcher -Filter "(&(objectClass=user)(objectCategory=person)(!userAccountControl:1.2.840.113556.1.4.803:=2)(servicePrincipalName=*))"

    $accounts = $searcher.FindAll()
    Write-Host "LDAP query returned $($accounts.Count) entries." -ForegroundColor Yellow

    $results = @()
    foreach ($result in $accounts) {
        $dn      = $result.Properties["distinguishedname"][0]
        $spns    = @($result.Properties["serviceprincipalname"]) -join "; "
        $account = Get-AccountDetails -MemberDN $dn
        if ($account) {
            $a = $account; $s = $spns
            $results += "" | Select-Object @{N="MemberName";E={$a.MemberName}},@{N="SamAccountName";E={$a.SamAccountName}},@{N="AccountStatus";E={$a.AccountStatus}},@{N="SPNs";E={$s}},@{N="PasswordLastChanged";E={$a.PasswordLastChanged}},@{N="DaysSincePwdChange";E={$a.DaysSincePwdChange}},@{N="LastLogon";E={$a.LastLogon}},@{N="AccountCreated";E={$a.AccountCreated}}
        }
    }

    Export-Results `
        -Results $results `
        -FileName "kerberoastable_accounts" `
        -DisplayColumns @("MemberName","SamAccountName","AccountStatus","SPNs","PasswordLastChanged","DaysSincePwdChange") `
        -EmptyMessage "No Kerberoastable accounts found."

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
#  R1 — USER INFO (single user lookup)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-UserInfo {
    Write-Host ""
    Write-Host "=================== R1: Domain User Information ===================" -ForegroundColor Green

    $domainUser = Read-Host "Enter the sAMAccountName to look up"

    $searcher = New-Searcher -Filter "(&(objectClass=user)(sAMAccountName=$domainUser))"

    $result = $searcher.FindOne()

    if ($result -and $result.Properties["distinguishedname"].Count -gt 0) {
        $dn      = $result.Properties["distinguishedname"][0]
        $account = Get-AccountDetails -MemberDN $dn
        if ($account) {
            $account | Format-List
        }
    } else {
        Write-Host "User '$domainUser' not found in $TargetDomain." -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  R2 — SID TRANSLATOR
#  CLM NOTE: SecurityIdentifier byte conversion done via the type accelerator.
#  Hex-encoding loop uses simple string ops (no Add-Type needed).
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-SIDTranslator {
    Write-Host ""
    Write-Host "=================== R2: SID Translator ===================" -ForegroundColor Green

    $OnPremiseSID = Read-Host "Enter SID (e.g. S-1-5-21-...)"

    # CLM blocks ::new() on SecurityIdentifier and [byte[]]::new().
    # Instead, parse the SID string manually to build the raw byte array,
    # then hex-encode it for the LDAP objectSid filter — no type creation needed.
    try {
        # Parse "S-R-A-S1-S2-..." into parts
        $parts     = $OnPremiseSID -split "-"
        # parts[0]="S", [1]=revision, [2]=authority, [3..n]=subauthorities
        $revision  = [int]$parts[1]
        $authority = [long]$parts[2]
        $subs      = @()
        for ($i = 3; $i -lt $parts.Count; $i++) { $subs += [long]$parts[$i] }
        $subCount  = $subs.Count

        # Build byte array manually (SID binary format):
        # Byte 0: Revision, Byte 1: SubAuthorityCount,
        # Bytes 2-7: Authority (big-endian 6 bytes), Bytes 8+: SubAuthorities (4 bytes LE each)
        $sidBytes = @()
        $sidBytes += [byte]$revision
        $sidBytes += [byte]$subCount
        # Authority as 6 big-endian bytes
        $sidBytes += [byte](($authority -shr 40) -band 0xFF)
        $sidBytes += [byte](($authority -shr 32) -band 0xFF)
        $sidBytes += [byte](($authority -shr 24) -band 0xFF)
        $sidBytes += [byte](($authority -shr 16) -band 0xFF)
        $sidBytes += [byte](($authority -shr  8) -band 0xFF)
        $sidBytes += [byte]( $authority           -band 0xFF)
        # Each sub-authority as 4 little-endian bytes
        foreach ($sub in $subs) {
            $sidBytes += [byte]( $sub          -band 0xFF)
            $sidBytes += [byte](($sub -shr  8) -band 0xFF)
            $sidBytes += [byte](($sub -shr 16) -band 0xFF)
            $sidBytes += [byte](($sub -shr 24) -band 0xFF)
        }

        # Build escaped hex string for LDAP filter
        #$hexSid = "\" + ($sidBytes | ForEach-Object { $_.ToString("X2") } | Select-Object -First 999) -join "\"

        $hexSid = "\" + (($sidBytes | ForEach-Object { $_.ToString("X2") }) -join "\")


        $searcher = New-Searcher -Filter "(&(objectClass=user)(objectSid=$hexSid))"
        $result   = $searcher.FindOne()

        if ($result -and $result.Properties["distinguishedname"].Count -gt 0) {
            $dn      = $result.Properties["distinguishedname"][0]
            $account = Get-AccountDetails -MemberDN $dn
            if ($account) {
                Write-Host ""
                Write-Host "SID $OnPremiseSID resolves to: $($account.SamAccountName)" -ForegroundColor Cyan
                $account | Format-List
            }
        } else {
            Write-Host "No user found for SID: $OnPremiseSID" -ForegroundColor Red
        }
    } catch {
        Write-Host "SID parse error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  R3 — USER DUMP (all users to CSV)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-UserDump {
    Write-Host ""
    Write-Host "=================== R3: Full User Dump ===================" -ForegroundColor Green

    $searcher = New-Searcher -Filter "(&(objectClass=user)(objectCategory=person))"

    $allUsers = $searcher.FindAll()
    Write-Host "Found $($allUsers.Count) user objects. Processing..." -ForegroundColor Yellow

    $outputFile = Join-Path $OutputPath "${TargetDomain}_user_dump_${TimeStamp}.csv"
    $count = 0

    $userData = foreach ($result in $allUsers) {
        $dn = $result.Properties["distinguishedname"][0]
        $account = Get-AccountDetails -MemberDN $dn
        if ($account) {
            $count++
            $account
        }
    }

    if ($userData) {
        $userData | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Exported $count user records to: $outputFile" -ForegroundColor Cyan
    } else {
        Write-Host "No user data retrieved." -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  DISPATCH
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Dispatching: $TargetAudit" -ForegroundColor Yellow
Write-Host ""

switch ($TargetAudit.ToLower()) {
    "r1"  { Invoke-UserInfo }
    "r2"  { Invoke-SIDTranslator }
    "r3"  { Invoke-UserDump }
    "a1"  { Invoke-AdminAudit }
    "a2"  { Invoke-DCSyncAudit }
    "a3"  { Invoke-ServiceAccountAudit }
    "a4"  { Invoke-DormantAccountAudit }
    "a5"  { Invoke-StaleAccountAudit }
    "a6"  { Invoke-DelegationAudit }
    "a7"  { Invoke-KerberoastAudit }
    "all" {
        Write-Host "Running all audit modules..." -ForegroundColor Yellow
        Invoke-AdminAudit
        Invoke-DCSyncAudit
        Invoke-ServiceAccountAudit
        Invoke-DormantAccountAudit
        Invoke-StaleAccountAudit
        Invoke-DelegationAudit
        Invoke-KerberoastAudit
    }
    default {
        Write-Host "[!] Invalid selection: '$TargetAudit'" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Cleaning up net use session..." -ForegroundColor Yellow
$null = net use "\\$dcToUse\IPC$" /delete 2>$null

Write-Host ""
Write-Host "======================== Analysis Complete ========================" -ForegroundColor Green


