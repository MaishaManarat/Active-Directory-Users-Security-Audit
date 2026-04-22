<#
.SYNOPSIS
    Audit Active Directory Users
.DESCRIPTION
    This Script has two parts. AD Users Audit and AD User Recon

    =================Active Directory Recon==================
    1. Domain User Information Retriever 
    2. SID Translator
    3. User Dump

    =================Active Directory Security Audit==================
    1. Administrator Accounts
    2. Accounts with DCSync Privileges"
    3. Service Accounts: Accounts with no expiry date"
    4. Dormant Accounts: Inactive accounts "
    5. Stale Accounts: Password not changed for long time"
    6. Accounts with unconstrained delegation"
    7. Kerberoastable Accounts: Accounts with registered SPN"
    
.PARAMETER ExportOnly
    Switch to suppress console output and only export to CSV.
.EXAMPLE
    .\ADAudit.ps1
#>


# Start

param(
    [string]$OutputPath = "C:\Users\maisha.manarat\Desktop\AD", #Change Path to where you want to save the output file
    [string]$ExportOnly,
    [string]$TargetDomainController,
    [string]$TargetAudit,
    [ADSI]$directoryEntry,
    [PsCredential]$Credential
)


# Logo

Write-Host "   _____          __  .__               ________  .__                       __                       
  /  _  \   _____/  |_|__|__  __ ____   \______ \ |__|______   ____   _____/  |_  ___________ ___.__.
 /  /_\  \_/ ___\   __\  \  \/ // __ \   |    |  \|  \_  __ \_/ __ \_/ ___\   __\/  _ \_  __ <   |  |
/    |    \  \___|  | |  |\   /\  ___/   |    `   \  ||  | \/\  ___/\  \___|  | (  <_> )  | \/\___  |
\____|__  /\___  >__| |__| \_/  \___  > /_______  /__||__|    \___  >\___  >__|  \____/|__|   / ____|
        \/     \/                   \/          \/                \/     \/                   \/     " -ForegroundColor Green



Write-Host "`n`n"

Write-Host "======================================================" -ForegroundColor Green
Write-Host "          Active Directory Audit & Utility Tool       " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Green
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
$Tool = Read-Host -Prompt "Tool to Use: (recon/audit): "

if($Tool -eq "Audit"){
    $TargetAudit = Read-Host -Prompt "Audit Point (e.g a1,a2,a3,a4,a5,a6,a7 or all): " 
}elseif($Tool -eq "Recon"){
    $TargetAudit = Read-Host -Prompt "Recon Point (e.g r1,r2 or r3): " 
}else{
    Write-Host "Incorrect Option"
}




Write-Host "-----------------------------------------------------------------------------------" -ForegroundColor Green




# Get the target domain
$TargetDomain = Read-Host -Prompt "Enter the target domain name to audit (e.g target.com): "

# Parsre the domain name into DN format
$DomainComponents = $TargetDomain.split('.')
$TargetDomainDN = "DC=" + ($DomainComponents -join ",DC=")  #In PowerShell, you don't need a visible loop because the .Split() and -join methods are vectorized operations. They handle the "looping" internally at the engine level.

Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
Write-Host ""


# Determine Domain Controller to Use
if ($TargetDomainController){
    $dcToUse = $TargetDomainController
    Write-Host "Using Domain Controller: $dcToUse" -ForegroundColor Yellow
}
else {
    Write-Host "Discovering Domain Controller in $TargetDomain ..." -ForegroundColor Yellow
    try{
        $dcRecords = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$TargetDomain" -Type SRV -ErrorAction Stop
        #$dcToUse = $dcRecords[0].NameTarget.TrimEnd('.') # instead of this, using weight/priortization
        # Sort by Priority (Ascending) then Weight (Descending)
        $bestDC = $dcRecords | Sort-Object Priority, @{Expression="Weight"; Descending=$true} | Select-Object -First 1
        $dcToUse = $bestDC.NameTarget.TrimEnd('.')
        Write-Host "Found Domain Controller $dcToUse " -ForegroundColor Cyan
    }
    catch{
        $dcToUse = $TargetDomain
        Write-Host "Could not find Domain Controllers. Using domain name ($dcToUse) as LDAP endpoint." -ForegroundColor Red
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

# Connect to AD using .NET 
$plainPassword = $Credential.GetNetworkCredential().Password 
$authType = [System.DirectoryServices.AuthenticationTypes]::Secure #Define Authentication Types (Secure + Signing).Using 'Secure' is the standard for Active Directory.

$directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
    $ldapPath, 
    $Credential.UserName, 
    $plainPassword, 
    $authType
)

<#
try {
    $test = $directoryEntry.NativeGuid #NativeGuid is a unique ID that every object in Active Directory has, To get the NativeGuid, PowerShell is forced to actually perform the LDAP "Bind" (the login).
    Write-Host "Success! Connected to AD as $($Credential.UserName)" -ForegroundColor Cyan
}
catch {
    Write-Error "Authentication Failed: $($_.Exception.Message)" 
}

#>




#$directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.Username, $Credential.GetNetworkCredential().Password)
<#
directoryEntry is the name of the "bucket" where the connection is stored.
New-Object System.DirectoryServices.DirectoryEntry tells PowerShell to create a new instance of the DirectoryEntry class we discussed earlier. Think of this as opening a communication channel to the database.
ldapPath tells the script exactly which object in the tree you want to talk to.
#>

Write-Host "Testing initiated using user $($Credential.Username) " -ForegroundColor Yellow



# Helper function to get account details

function Get-AccountDetails {
    param(
        [string]$MemberDN
    )

    $today = Get-Date
    $memberSearcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $escapedDN = $MemberDN.Replace("(", "\28").Replace(")", "\29") #This line is a translator that makes a Distinguished Name (DN) safe to use inside an LDAP search filter.
    $memberSearcher.Filter = "(distinguishedName=$escapedDN)"

    
    #$memberSearcher.Filter = "(distinguishedName=$MemberDN)"
    $memberSearcher.PropertiesToLoad.AddRange(@(
        "name",
        "samaccountname",
        "objectsid",
        "whencreated",
        "pwdlastset",
        "lastlogontimestamp",
        "useraccountcontrol",
        "memberof",
        "description",
        "userprincipalname"
    ))

    $memberResult = $memberSearcher.FindOne()
    if (-not $memberResult) { return $null }

    $props = $memberResult.Properties

    # Parse pwdlastset
    $pwdLastSetRaw = if ($props.pwdlastset) { $props.pwdlastset[0] } else { 0 }
    $passwordLastChanged = if ($pwdLastSetRaw -gt 0) { [DateTime]::FromFileTime($pwdLastSetRaw) } else { $null }

    # Parse lastlogontimestamp
    $lastLogonRaw = if ($props.lastlogontimestamp) { $props.lastlogontimestamp[0] } else { 0 }
    $lastLogon = if ($lastLogonRaw -gt 0) { [DateTime]::FromFileTime($lastLogonRaw) } else { $null }

    # Parse useraccountcontrol
    $uacValue = if ($props.useraccountcontrol) { $props.useraccountcontrol[0] } else { 0 }

    
    # Clean up group names (removes the CN= and OU= parts)
    $groups = if ($props.memberof) { 
        $props.memberof | ForEach-Object { ($_ -split ',')[0].Replace("CN=", "") } 
    } else { "Domain Users" }

    return [PSCustomObject]@{
        MemberName = if ($props.name) { $props.name[0] } else { $MemberDN }
        SamAccountName = if ($props.samaccountname) { $props.samaccountname[0] } else { "" }
        #SID = if ($props.objectsid) { ($props.objectsid[0], 0).Value } else { "" }
        SID = if ($props.objectsid) { (New-Object System.Security.Principal.SecurityIdentifier($props.objectsid[0], 0)).Value } else { "" }
        AccountCreated = if ($props.whencreated) { ([DateTime]$props.whencreated[0]).ToString("yyyy-MM-dd") } else { "Unknown" }
        PasswordLastChanged = if ($passwordLastChanged) { $passwordLastChanged.ToString("yyyy-MM-dd") } else { "Never Set" }
        DaysSincePwdChange  = if ($passwordLastChanged) { [int]($today - $passwordLastChanged).TotalDays } else { "Never Set" }
        LastLogon = if ($lastLogon) { $lastLogon.ToString("yyyy-MM-dd") } else { "Never" }
        AccountStatus = if ($uacValue -band 2) { "Disabled" } else { "Enabled" }
        Groups = ($groups -join "; ")
        Comment = if ($props.description) { $props.description[0] } else { "" }
        UserPrincipalName = if ($props.userprincipalname -and $props.userprincipalname.Count -gt 0) { $props.userprincipalname[0] } else { "" }
    }
}



### Accounts with Admin Accounts ###
function Admins{
    Write-Host ""
    Write-Host "===================Auditing Admin Accounts===================" -ForegroundColor Green

    
    # Privileged Groups
    $PrivilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Schema Admins"
        )

    $results = @()
    foreach ($GroupName in $PrivilegedGroups){
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $Searcher.Filter = "(&(ObjectCategory=group)(name=$GroupName))"
        $Searcher.PropertiesToLoad.AddRange(@("member","name"))
        $group = $Searcher.FindOne()
        if ($group){
            $members = $group.Properties.member
            foreach ($memberDN in $members){
                $account = Get-AccountDetails -MemberDN $memberDN 
                if ($account) {
                    $results += [PSCustomObject]@{
                        Group = $GroupName
                        MemberName = $account.MemberName
                        SamAccountName = $account.SamAccountName
                        #SID = $account.SID
                        AccountCreated = $account.AccountCreated
                        PasswordLastChanged = $account.PasswordLastChanged
                        DaysSincePwdChange  = $account.DaysSincePwdChange
                        LastLogon = $account.LastLogon
                        AccountStatus = $account.AccountStatus
                    }
                }

            }

        }
    }
    
    # Output file
    $OutputFile = Join-Path $OutputPath "admin_accounts_$TargetDomain`_$TimeStamp.csv"

    Write-Host "Found $($results.Count) admin accounts" -ForegroundColor Yellow

    if ($results.Count -gt 0){
        $results | Format-Table Group, MemberName, SamAccountName, AccountStatus, PasswordLastChanged, DaysSincePwdChange, AccountCreated -AutoSize
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Results exported to: $OutputFile" -ForegroundColor Cyan
    }
    else {
        Write-Host "No admin accounts found."
    }

    return $results
}


### Accounts with DCSync Privileges ###
function DCSync{



    Write-Host ""
    Write-Host "=================== Auditing Acounts with DCSync Privileges ===================" -ForegroundColor Green

    # GUIDs for DCSync Rights
    $DCSyncGuids = @(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", # DS-Replication-Get-Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes-All
    )

    $results = @()

    try {

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcher.Filter = "(objectClass=domain)"
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $searcher.PropertiesToLoad.Add("ntSecurityDescriptor")

        $domainResult = $searcher.FindOne()
        
        $sec = $domainResult.GetDirectoryEntry().ObjectSecurity
        
        # Get all Access Rules (ACEs)
        $rules = $sec.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

        foreach ($rule in $rules) {
            # Check if the rule is "Allow" and matches one of our DCSync GUIDs
            if ($rule.AccessControlType -eq "Allow" -and $DCSyncGuids -contains $rule.ObjectType.ToString()) {
                
                # Check for the specific permission name (or ID)
                $rightType = if ($rule.ObjectType.ToString() -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") { 
                    "Get-Changes" 
                } else { 
                    "Get-Changes-All" 
                }
  
                
                $identityValue = $rule.IdentityReference.Value # $rule.IdentityReference.Value gives "DOMAIN\username" format
                $samName = $identityValue -replace '^.*\\', ''  # removes everything up to and including the backslash, Strip the domain prefix to get just the samAccountName for searching


                $resolvesearcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
                $resolvesearcher.Filter = "(samAccountName=$samName)"
                $resolvesearcher.PropertiesToLoad.Add("distinguishedName") 
                $resolvesearcher.PropertiesToLoad.AddRange(@("member","name"))
                $resolved = $resolvesearcher.FindOne()
                
                #$account = $null
                if ($resolved) {
                    $dn = $resolved.Properties.distinguishedname[0]
                    $account = Get-AccountDetails -MemberDN $dn
                }

                $results += [PSCustomObject]@{
                    Identity = $rule.IdentityReference.Value
                    Right = $rightType
                    IsInherited = $rule.IsInherited
                    Inheritance = $rule.InheritanceFlags
                    Group = $GroupName
                    MemberName = $account.MemberName
                    SamAccountName = $account.SamAccountName
                    #SID = $account.SID
                    AccountCreated = $account.AccountCreated
                    PasswordLastChanged = $account.PasswordLastChanged
                    DaysSincePwdChange  = $account.DaysSincePwdChange
                    LastLogon = $account.LastLogon
                    AccountStatus = $account.AccountStatus

                }
            }
        }
    }
    catch {
        Write-Error "Failed to read Security Descriptor: $($_.Exception.Message)"
    }

    

    # Output file
    $OutputFile = Join-Path $OutputPath "accounts_with_dcsync_privileges_$TargetDomain`_$TimeStamp.csv"

    Write-Host "Found $($results.Count) accounts with DCSync-related rights" -ForegroundColor Yellow

    if ($results.Count -gt 0) {
        
        $results | Format-Table Identity, Right, MemberName, SamAccountName, AccountStatus, PasswordLastChanged, DaysSinceChange, AccountCreated, LastLogon -AutoSize
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Full audit exported to: $OutputFile" -ForegroundColor Cyan
    } else {
        Write-Host "No account DCSync rights found" -ForegroundColor Yellow
    }

    return $results
    #Write-Host "Found $($results.Count) accounts with dcsync privileges" -ForegroundColor Yellow
    # Output file

    
}


function ServiceAccounts{
    Write-Host ""
    Write-Host "===================Auditing Service Accounts===================" -ForegroundColor Green
    Write-Host "P.S. For this tool, a service account is defined as any account with no password expiry." -ForegroundColor Yellow

    $results = @()

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $Searcher.Filter = "(&(ObjectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"  # 1.2.840.113556.1.4.803 is a specialized "Bitwise AND" rule. 65536 is the decimal value for the "Password Never Expires" fla
    $Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $Searcher.PropertiesToLoad.AddRange(@("distinguishedName", "name"))
    $accounts = $Searcher.FindAll()
    Write-Host "Searching from: $($testSearcher.SearchRoot.Path)" -ForegroundColor Magenta


    foreach($result in $accounts){
        $dn = $result.Properties.distinguishedname[0]
        $account = Get-AccountDetails -MemberDN $dn
            if ($account) {
                $results += [PSCustomObject]@{
                MemberName = $account.MemberName
                SamAccountName = $account.SamAccountName
                #SID = $account.objectsid
                AccountCreated = $account.AccountCreated
                PasswordLastChanged = $account.PasswordLastChanged
                DaysSincePwdChange  = $account.DaysSincePwdChange
                LastLogon = $account.LastLogon
                AccountStatus = $account.AccountStatus
                }
            }
      
    }
    
    # Output file
    $OutputFile = Join-Path $OutputPath "service_accounts_$TargetDomain`_$TimeStamp.csv"

    Write-Host "Found $($results.Count) service accounts" -ForegroundColor Yellow

    if ($results.Count -gt 0){
        $results | Format-Table MemberName, SamAccountName, AccountStatus, PasswordLastChanged, DaysSincePwdChange, AccountCreated -AutoSize
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Results exported to: $OutputFile" -ForegroundColor Cyan
    }
    else {
        Write-Host "No service accounts found."
    }

    return $results
}


function ServiceAccounts{
    Write-Host ""
    Write-Host "===================Auditing Service Accounts===================" -ForegroundColor Green
    Write-Host "P.S. For this tool, a service account is defined as any account with no password expiry." -ForegroundColor Yellow

    $results = @()

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $Searcher.Filter = "(&(ObjectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"  # 1.2.840.113556.1.4.803 is a specialized "Bitwise AND" rule. 65536 is the decimal value for the "Password Never Expires" flag
    $Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $Searcher.PropertiesToLoad.AddRange(@("distinguishedName", "name"))
    $accounts = $Searcher.FindAll()
    Write-Host "Searching from: $($testSearcher.SearchRoot.Path)" -ForegroundColor Magenta


    foreach($result in $accounts){
        $dn = $result.Properties.distinguishedname[0]
        $account = Get-AccountDetails -MemberDN $dn
            if ($account) {
                $results += [PSCustomObject]@{
                MemberName = $account.MemberName
                SamAccountName = $account.SamAccountName
                #SID = $account.objectsid
                AccountCreated = $account.AccountCreated
                PasswordLastChanged = $account.PasswordLastChanged
                DaysSincePwdChange  = $account.DaysSincePwdChange
                LastLogon = $account.LastLogon
                AccountStatus = $account.AccountStatus
                }
            }
      
    }
    
    # Output file
    $OutputFile = Join-Path $OutputPath "service_accounts_$TargetDomain`_$TimeStamp.csv"

    Write-Host "Found $($results.Count) service accounts" -ForegroundColor Yellow

    if ($results.Count -gt 0){
        $results | Format-Table MemberName, SamAccountName, AccountStatus, PasswordLastChanged, DaysSincePwdChange, AccountCreated -AutoSize
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Results exported to: $OutputFile" -ForegroundColor Cyan
    }
    else {
        Write-Host "No service accounts found."
    }

    return $results
}



function DormantAccounts{
    Write-Host ""
    Write-Host "===================Auditing Dormant Accounts===================" -ForegroundColor Green
    Write-Host "P.S. For this tool, a dormant account is defined as any account that shows no activity within a specified period." -ForegroundColor Yellow
    $DaysThreshold = Read-Host -Prompt "Days Threashold for No Activity: "
    Write-Host "Searching for accounts with passwords older than $DaysThreshold days."

    $cutoffDate = (Get-Date).AddDays(-$DaysThreshold)
    $TimeLimit = $cutoffDate.ToFileTime()


    $results = @()

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry) 
    $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(lastlogontimestamp<=$TimeLimit)(!userAccountControl:1.2.840.113556.1.4.803:=2))"  # 1.2.840.113556.1.4.803 is a specialized "Bitwise AND" rule. 2 is the decimal value for the "disabled" flag
    $Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree  # tells PowerShell how deep into the Active Directory folders (OUs) it should look. basically telling to look inside every single sub-folder and sub-sub-folder all the way to the bottom
    $Searcher.PropertiesToLoad.AddRange(@("distinguishedName", "name")) | Out-Null
    $accounts = $Searcher.FindAll()
    Write-Host "Searching from: $($testSearcher.SearchRoot.Path)" -ForegroundColor Magenta


    foreach($result in $accounts){
        $dn = $result.Properties.distinguishedname[0]
        $account = Get-AccountDetails -MemberDN $dn
            if ($account) {
                $results += [PSCustomObject]@{
                MemberName = $account.MemberName
                SamAccountName = $account.SamAccountName
                #SID = $SID
                AccountCreated = $account.AccountCreated
                PasswordLastChanged = $account.PasswordLastChanged
                DaysSincePwdChange  = $account.DaysSincePwdChange
                LastLogon = $account.LastLogon
                AccountStatus = $account.AccountStatus
                }
            }
      
    }
    
    # Output file
    $OutputFile = Join-Path $OutputPath "dormant_accounts_$TargetDomain`_$TimeStamp.csv"

    Write-Host "Found $($results.Count) dormant accounts" -ForegroundColor Yellow

    if ($results.Count -gt 0){
        $results | Format-Table MemberName, SamAccountName, AccountStatus, PasswordLastChanged, DaysSincePwdChange, AccountCreated -AutoSize
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Results exported to: $OutputFile" -ForegroundColor Cyan
    }
    else {
        Write-Host "No dormant accounts found."
    }

    return $results
}







function StaleAccounts{
    Write-Host ""
    Write-Host "===================Auditing Stale Accounts===================" -ForegroundColor Green
    Write-Host "P.S. For this tool, a stale account is defined as any account that has not changed password within a specified period." -ForegroundColor Yellow
    $DaysThreshold = Read-Host -Prompt "Days Threashold for Password Expiry: "
    Write-Host "Searching for accounts with passwords older than $DaysThreshold days."

    $cutoffDate = (Get-Date).AddDays(-$DaysThreshold)
    $TimeLimit = $cutoffDate.ToFileTime()


    $results = @()

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry) 
    $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(pwdLastSet<=$TimeLimit)(!userAccountControl:1.2.840.113556.1.4.803:=2))"  # 1.2.840.113556.1.4.803 is a specialized "Bitwise AND" rule. 2 is the decimal value for the "disabled" flag
    $Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree  # tells PowerShell how deep into the Active Directory folders (OUs) it should look. basically telling to look inside every single sub-folder and sub-sub-folder all the way to the bottom
    $Searcher.PropertiesToLoad.AddRange(@("distinguishedName", "name")) | Out-Null
    $accounts = $Searcher.FindAll()
    Write-Host "Searching from: $($testSearcher.SearchRoot.Path)" -ForegroundColor Magenta


    foreach($result in $accounts){
        $dn = $result.Properties.distinguishedname[0]
        $account = Get-AccountDetails -MemberDN $dn
            if ($account) {
                $results += [PSCustomObject]@{
                MemberName = $account.MemberName
                SamAccountName = $account.SamAccountName
                #SID = $account.objectsid
                AccountCreated = $account.AccountCreated
                PasswordLastChanged = $account.PasswordLastChanged
                DaysSincePwdChange  = $account.DaysSincePwdChange
                LastLogon = $account.LastLogon
                AccountStatus = $account.AccountStatus
                }
            }
      
    }
    
    # Output file
    $OutputFile = Join-Path $OutputPath "stale_accounts_$TargetDomain`_$TimeStamp.csv"

    Write-Host "Found $($results.Count) stale accounts" -ForegroundColor Yellow

    if ($results.Count -gt 0){
        $results | Format-Table MemberName, SamAccountName, AccountStatus, PasswordLastChanged, DaysSincePwdChange, AccountCreated -AutoSize
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Results exported to: $OutputFile" -ForegroundColor Cyan
    }
    else {
        Write-Host "No stale accounts found."
    }

    return $results
}




function Delegation{
    Write-Host ""
    Write-Host "===================Auditing Accounts with Unconstrained Delegartion =========================" -ForegroundColor Green
   
    $results = @()

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry) 
    $Searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!userAccountControl:1.2.840.113556.1.4.803:=2))"  # Filter: User, Not Disabled, and Trusted for Delegation (524288)
    $Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree  # tells PowerShell how deep into the Active Directory folders (OUs) it should look. basically telling to look inside every single sub-folder and sub-sub-folder all the way to the bottom
    $Searcher.PropertiesToLoad.AddRange(@("distinguishedName", "name")) | Out-Null
    $accounts = $Searcher.FindAll()
    Write-Host "Searching from: $($testSearcher.SearchRoot.Path)" -ForegroundColor Magenta


    foreach($result in $accounts){
        $dn = $result.Properties.distinguishedname[0]
        $account = Get-AccountDetails -MemberDN $dn
            if ($account) {
                $results += [PSCustomObject]@{
                MemberName = $account.MemberName
                SamAccountName = $account.SamAccountName
                #SID = $account.objectsid
                AccountCreated = $account.AccountCreated
                PasswordLastChanged = $account.PasswordLastChanged
                DaysSincePwdChange  = $account.DaysSincePwdChange
                LastLogon = $account.LastLogon
                AccountStatus = $account.AccountStatus
                }
            }
      
    }
    
    # Output file
    $OutputFile = Join-Path $OutputPath "unconstrained_delegation_accounts_$TargetDomain`_$TimeStamp.csv"

    Write-Host "Found $($results.Count) accounts with unconstrained delegation" -ForegroundColor Yellow

    if ($results.Count -gt 0){
        $results | Format-Table MemberName, SamAccountName, AccountStatus, PasswordLastChanged, DaysSincePwdChange, AccountCreated -AutoSize
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Results exported to: $OutputFile" -ForegroundColor Cyan
    }
    else {
        Write-Host "No accounts with unconstrained delegation found."
    }

    return $results
}




function Kerberoast{
    Write-Host ""
    Write-Host "===================Auditing Kerberoastable Accounts =========================" -ForegroundColor Green
    Write-Host "A Kerberoastable account is any Active Directory (AD) user account that has a Service Principal Name (SPN) assigned to it"
   
    $results = @()

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry) 
    $Searcher.Filter = "(&(objectClass=user)(objectCategory=person)(!userAccountControl:1.2.840.113556.1.4.803:=2)(servicePrincipalName=*))"  # Filter: User, Not Disabled, and has an SPN set (servicePrincipalName=*)
    $Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree  # tells PowerShell how deep into the Active Directory folders (OUs) it should look. basically telling to look inside every single sub-folder and sub-sub-folder all the way to the bottom
    $Searcher.PropertiesToLoad.AddRange(@("distinguishedName", "name")) | Out-Null
    $accounts = $Searcher.FindAll()
    Write-Host "Searching from: $($testSearcher.SearchRoot.Path)" -ForegroundColor Magenta


    foreach($result in $accounts){
        $dn = $result.Properties.distinguishedname[0]
        $account = Get-AccountDetails -MemberDN $dn
            if ($account) {
                $results += [PSCustomObject]@{
                MemberName = $account.MemberName
                SamAccountName = $account.SamAccountName
                #SID = $account.objectsid
                AccountCreated = $account.AccountCreated
                PasswordLastChanged = $account.PasswordLastChanged
                DaysSincePwdChange  = $account.DaysSincePwdChange
                LastLogon = $account.LastLogon
                AccountStatus = $account.AccountStatus
                }
            }
      
    }
    
    # Output file
    $OutputFile = Join-Path $OutputPath "kerberoastable_accounts_$TargetDomain`_$TimeStamp.csv"

    Write-Host "Found $($results.Count) kerberoastable accounts" -ForegroundColor Yellow

    if ($results.Count -gt 0){
        $results | Format-Table MemberName, SamAccountName, AccountStatus, PasswordLastChanged, DaysSincePwdChange, AccountCreated -AutoSize
        $results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "Results exported to: $OutputFile" -ForegroundColor Cyan
    }
    else {
        Write-Host "No kerberoastable accounts found."
    }

    return $results
}


function UserInfo{

    Write-Host ""
    Write-Host "===================Domain User Information Retriever==========================" -ForegroundColor Green

    $domainuser = Read-Host "Enter the domain user to check (e.g test.account): "

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $Searcher.Filter = "(&(objectClass=user)(sAMAccountName=$domainuser))"
    $Searcher.PropertiesToLoad.AddRange(@("name", "samaccountname", "distinguishedname"))

    $result = $Searcher.FindOne()

    if ($result){
        $dn = $result.Properties.distinguishedname[0]
        $account = Get-AccountDetails -MemberDN $dn
        Write-Host ""
    
        if($account){
            #$account | Add-Member -NotePropertyName DomainAccount -NotePropertyValue "$TargetDomainName\$($account.SamAccountName)" -Force
            $account | Format-List
        }
    }else{
        Write-Host "Error: Could not resolve the user '$domainuser' in domain '$TargetDomainName'."
    }
}


function SIDTranslator{

    Write-Host ""
    Write-Host "===================SID Translator==========================" -ForegroundColor Green

    $OnPremiseSID = Read-Host "Enter the On-Premises SID (e.g S-1-5-21-....): "

    $sid = New-Object System.Security.Principal.SecurityIdentifier($OnPremiseSID)
    [byte[]]$sidBytes = New-Object byte[] $sid.BinaryLength  #In Active Directory, the objectSid attribute is stored as a byte array (binary), not as a string like S-1-5-21.... If you try to search using the string representation, the DirectorySearcher won't find a match.
    $sid.GetBinaryForm($sidBytes, 0) #convert the string SID into its hex/byte format for LDAP to understand it.
    $hexSid = "\" + (($sidBytes | ForEach-Object { $_.ToString("X2") }) -join "\")


    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $Searcher.Filter = "(&(objectClass=user)(objectSid=$hexSid))"
    $Searcher.PropertiesToLoad.AddRange(@("name", "samaccountname", "distinguishedname"))

    $result = $Searcher.FindOne()

    if ($result){
        $dn = $result.Properties.distinguishedname[0]
        $account = Get-AccountDetails -MemberDN $dn
        Write-Host ""
        Write-Host "The username associated with this SID is:"$account.SamAccountName"" -ForegroundColor Cyan
    
        if($account){
            #$account | Add-Member -NotePropertyName DomainAccount -NotePropertyValue "$TargetDomainName\$($account.SamAccountName)" -Force
            $account | Format-List
        }
    }else{
        Write-Host "Error: Could not resolve the SID '$OnPremisesSID' in domain '$TargetDomainName'."
    }
}


function UserDump{

    Write-Host ""
    Write-Host "===================User Dump==========================" -ForegroundColor Green

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $Searcher.Filter = "(&(objectClass=user)(objectCategory=person))"
    $Searcher.PropertiesToLoad.Add("distinguishedName")

    $Searcher.PageSize = 1000 #PageSize is required for more than 1000 users

    $results = $Searcher.FindAll()
    $totalCount = $results.Count
    Write-Host "Found $totalCount users. Processing data..." -ForegroundColor Yellow


    $userData = foreach ($result in $results) {
        $dn = $result.Properties.distinguishedname[0]
        # Call your existing function
        Get-AccountDetails -MemberDN $dn
    }

    $OutputFile = Join-Path $OutputPath "$($TargetDomain)_user_dump_$($TimeStamp).csv"

    if ($userData) {
        $userData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Successfully dumped $totalCount users to: $OutputFile"
    } else {
        Write-Host "No user data found to export." -ForegroundColor Red
    }

}

<#
In the world of LDAP (the language Active Directory speaks), the logic is Prefix Notation. This means the operator (&, |, !) must always come before the parentheses, not between them.
#>


 # THE AUTHENTICATION TEST 

try {
      # RefreshCache() forces an immediate LDAP Bind. 
     # If the password is wrong or the server is down, it throws a Terminating Error.
    $directoryEntry.RefreshCache()
    
    Write-Host "Success! Authenticated as $($Credential.UserName)" -ForegroundColor Cyan

    Write-Host ""

    # Executable Option Selection


    Switch($TargetAudit){
        "r1" {
            UserInfo -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "r2" {
            SIDTranslator -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "r3" {
            UserDump -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "a1" {
            Admins -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "a2" {
            DCSync -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "a3" {
            ServiceAccounts -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "a4" {
            DormantAccounts -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "a5" {
            StaleAccounts -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "a6" {
            Delegation -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        "a7" {
            Kerberoast -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
    
        "all" {
            Write-Host "Running all auditing modules" -ForegroundColor Yellow
            Admins -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
            DCSync -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
            ServiceAccounts -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
            DormantAccounts -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
            StaleAccounts -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
            Delegation -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
            Kerberoast -TargetDomainName $TargetDomain -TargetDomainDN $TargetDomainDN -Credential $Credential -DomainController $dcToUse -OutpuPath $OutputPath
        }
    
        Default {
            Write-Host "`n[!] Invalid option selected" -ForegroundColor Red
        }
    
    }


}
catch {
    # 3. THE FAIL-SAFE
    Write-Host "Authentication failed. Script cannot continue." -ForegroundColor Red
    #Write-Error "Details: $($_.Exception.Message)"
    
    # Use 'exit' to stop the entire script immediately
    exit 1 
}







Write-Host ""
Write-Host "------------------------Analysis Completed------------------------------------" -ForegroundColor Green
