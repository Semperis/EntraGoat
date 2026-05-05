<#

EntraGoat Scenario 7: Legacy Loophole - When MFA Forgot the Side Door
Setup script to be run with Global Administrator privileges

This scenario provisions a Conditional Access policy that requires MFA, but
only for modern-auth client apps. Legacy authentication endpoints (ROPC, IMAP,
POP, SMTP AUTH, ActiveSync, "other clients") are excluded from the policy
scope, so a target admin account remains reachable via legacy auth without
ever triggering MFA.

Requires Microsoft Entra ID P1 (or higher) for Conditional Access.

#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $null
)


# Configuration
$CAPolicyName = "EntraGoat S7 - Require MFA for All Users"
$Flag = "EntraGoat{L3g@cy_4uth_C0nd1t10n@l_Byp@ss_Pwn3d!}"
$AdminPassword = "Helpdesk!Reset2024"
$LowPrivPassword = "GoatAccess!123"
$standardDelay = 5 # Seconds
$longReplicationDelay = 10

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 7 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|     Legacy Loophole - When MFA Forgot the Side Door          |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

#region Module Check and Import
Write-Verbose "[*] Checking and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns"
)
$MissingModules = @()
foreach ($moduleName in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
        $MissingModules += $moduleName
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Warning "The following required modules are not installed: $($MissingModules -join ', ')."
    $choice = Read-Host "Do you want to attempt to install them from PowerShell Gallery? (Y/N)"
    if ($choice -eq 'Y') {
        try {
            Write-Host "Attempting to install $($MissingModules -join ', ') from PowerShell Gallery. This may take a moment..." -ForegroundColor Yellow
            Install-Module -Name $MissingModules -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop -Verbose:$false
            Write-Verbose "[+] Successfully attempted to install missing modules."
            foreach ($moduleName in $MissingModules) {
                Import-Module $moduleName -ErrorAction SilentlyContinue -Verbose:$false
                if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
                    throw "Failed to import $moduleName"
                }
                Write-Verbose "   Imported $moduleName"
            }
        } catch {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to automatically install or import modules: $($MissingModules -join ', '). Please install them manually (e.g., Install-Module -Name Microsoft.Graph -Scope CurrentUser) and re-run the script. Error: $($_.Exception.Message)" -ForegroundColor White
            exit 1
        }
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Required modules are missing. Please install them and re-run the script." -ForegroundColor White
        exit 1
    }
} else {
    foreach ($moduleName in $RequiredModules) {
        if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
            try {
                Import-Module $moduleName -ErrorAction SilentlyContinue -Verbose:$false
                if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
                    throw "Failed to import $moduleName"
                }
                Write-Verbose "[+] Imported module $moduleName."
            } catch {
                Write-Host "[-] " -ForegroundColor Red -NoNewline
                Write-Host "Failed to import module $moduleName. Error: $($_.Exception.Message)" -ForegroundColor White
                exit 1
            }
        } else {
             Write-Verbose "[*] Module $moduleName is already loaded."
        }
    }
}
Write-Verbose "[+] All required modules appear to be present and loaded."
#endregion Module Check and Import

#region Authentication
Write-Verbose "[*] Connecting to Microsoft Graph..."

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Policy.ReadWrite.ConditionalAccess",
    "Application.Read.All"
)

try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
    }
    $Organization = Get-MgOrganization
    $TenantDomain = ($Organization.VerifiedDomains | Where-Object IsDefault).Name

    Write-Verbose "[+] Connected to tenant: $TenantDomain"
} catch {
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host "Failed to connect: $($_.Exception.Message)" -ForegroundColor White
    exit 1
}
#endregion

#region Helper Functions
function New-EntraGoatUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory=$true)]
        [string]$MailNickname,

        [Parameter(Mandatory=$true)]
        [string]$Password,

        [Parameter(Mandatory=$false)]
        [string]$Department = "",

        [Parameter(Mandatory=$false)]
        [string]$JobTitle = ""
    )

    Write-Verbose "   -> $DisplayName`: $UserPrincipalName"
    $ExistingUser = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue

    if ($ExistingUser) {
        $User = $ExistingUser
        Write-Verbose "      EXISTS (using existing)"
        $passwordProfile = @{
            Password = $Password
            ForceChangePasswordNextSignIn = $false
        }
        Update-MgUser -UserId $User.Id -PasswordProfile $passwordProfile
    } else {
        $UserParams = @{
            DisplayName = $DisplayName
            UserPrincipalName = $UserPrincipalName
            MailNickname = $MailNickname
            AccountEnabled = $true
            PasswordProfile = @{
                ForceChangePasswordNextSignIn = $false
                Password = $Password
            }
        }

        if ($Department) { $UserParams.Department = $Department }
        if ($JobTitle) { $UserParams.JobTitle = $JobTitle }

        $User = New-MgUser @UserParams
        Write-Verbose "      CREATED"
        Start-Sleep -Seconds $standardDelay
    }

    return $User
}
#endregion

#region User Creation
Write-Verbose "[*] Setting up users..."

$LowPrivUPN = "raj.patel@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s7@$TenantDomain"

# Create or get low-privileged user
Write-Verbose "    ->  Regular user: $LowPrivUPN"
$LowPrivUser = New-EntraGoatUser -DisplayName "Raj Patel" -UserPrincipalName $LowPrivUPN -MailNickname "raj.patel" -Password $LowPrivPassword -Department "IT Operations" -JobTitle "Mail Systems Engineer"

# Create or get admin user (the target). Modeled as a hybrid identity used by
# an old on-prem mail relay; Helpdesk gave it a predictable reset and the
# admin never rotated it.
Write-Verbose "    ->  Admin user: $AdminUPN"
$AdminUser = New-EntraGoatUser -DisplayName "EntraGoat Administrator S7" -UserPrincipalName $AdminUPN -MailNickname "entragoat-admin-s7" -Password $AdminPassword -Department "IT Administration" -JobTitle "Messaging Administrator"
#endregion

#region Store admin flag in extension attributes
Write-Verbose "[*] Storing flag in admin user's extension attributes..."
try {
    $UpdateParams = @{
        OnPremisesExtensionAttributes = @{
            ExtensionAttribute1 = $Flag
        }
    }
    Update-MgUser -UserId $AdminUser.Id -BodyParameter $UpdateParams
    Write-Verbose "    ->  Flag stored successfully"
} catch {
    Write-Verbose "    ->  Flag already set or minor error (continuing)"
}
#endregion

#region Assign Global Administrator Role to admin user
Write-Verbose "[*] Assigning Global Administrator role to admin user..."

$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
$DirectoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GlobalAdminRoleId'" -ErrorAction SilentlyContinue
if (-not $DirectoryRole) {
    Write-Verbose "    ->  Activating Global Administrator role..."
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $GlobalAdminRoleId
    $DirectoryRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}

$ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRole.Id -All -ErrorAction SilentlyContinue
$IsAlreadyAssigned = $false
if ($ExistingMembers) {
    foreach ($member in $ExistingMembers) {
        if ($member.Id -eq $AdminUser.Id) {
            $IsAlreadyAssigned = $true
            break
        }
    }
}
if (-not $IsAlreadyAssigned) {
    try {
        $RoleMemberParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($AdminUser.Id)"
        }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $DirectoryRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "    ->  Role assigned successfully"
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "    ->  Role already assigned"
        } else {
            throw $_
        }
    }
} else {
    Write-Verbose "    ->  Role already assigned"
}
#endregion

#region Create Conditional Access Policy (THE MISCONFIGURATION)
# The policy looks correct on paper: All users, All cloud apps, require MFA.
# But the clientAppTypes array only lists modern-auth clients - so legacy
# auth endpoints (Exchange ActiveSync, IMAP, POP, SMTP AUTH, ROPC and other
# "other clients") are silently out of scope. Microsoft's "Block legacy
# authentication" template is the supported control to close this gap;
# without it (or an Authentication Policy that disables basic auth),
# attackers with valid credentials can sign in via legacy protocols and
# never see an MFA prompt.
Write-Verbose "[!] CREATING MISCONFIGURATION: Conditional Access policy with no legacy-auth coverage..."

$ExistingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$CAPolicyName'" -ErrorAction SilentlyContinue
if ($ExistingPolicy) {
    Write-Verbose "    ->  Policy already exists, removing old version to ensure clean state"
    try {
        Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $ExistingPolicy.Id -ErrorAction Stop
        Start-Sleep -Seconds $standardDelay
    } catch {
        Write-Verbose "    ->  Could not remove existing policy (continuing): $($_.Exception.Message)"
    }
}

$caPolicyBody = @{
    displayName = $CAPolicyName
    state = "enabled"
    conditions = @{
        # Modern-auth clients only. exchangeActiveSync and other are NOT
        # listed - that is the intentional gap this scenario teaches.
        clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
        applications = @{
            includeApplications = @("All")
        }
        users = @{
            includeUsers = @("All")
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

try {
    $CreatedPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $caPolicyBody -ErrorAction Stop
    Write-Verbose "    ->  CA policy created: $($CreatedPolicy.DisplayName) ($($CreatedPolicy.Id))"
    Start-Sleep -Seconds $longReplicationDelay
} catch {
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host "Failed to create Conditional Access policy. Tenant must have Entra ID P1 (or higher). Error: $($_.Exception.Message)" -ForegroundColor White
    exit 1
}
#endregion

#region Final Verification
Write-Verbose "[*] Running final verification..."

$policyCheck = $false
$policyHasGap = $false
try {
    $verifyPolicy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $CreatedPolicy.Id -ErrorAction Stop
    if ($verifyPolicy.State -eq "enabled") {
        $policyCheck = $true
    }
    $clientAppTypes = $verifyPolicy.Conditions.ClientAppTypes
    if ($clientAppTypes -and ($clientAppTypes -notcontains "exchangeActiveSync") -and ($clientAppTypes -notcontains "other")) {
        $policyHasGap = $true
    }
} catch {
    Write-Verbose "    ->  Could not re-read policy: $($_.Exception.Message)"
}

if ($policyCheck) {
    Write-Verbose "    ->  [+] CA policy is enabled"
} else {
    Write-Verbose "    ->  [-] CA policy is NOT enabled"
}
if ($policyHasGap) {
    Write-Verbose "    ->  [+] Legacy-auth client types excluded from policy scope (vulnerability present)"
} else {
    Write-Verbose "    ->  [-] Policy unexpectedly covers legacy auth - vulnerability NOT present"
}

# Verify admin role
$roleCheck = $false
try {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRole.Id -All -ErrorAction SilentlyContinue
    if ($members) {
        foreach ($member in $members) {
            if ($member.Id -eq $AdminUser.Id) {
                $roleCheck = $true
                break
            }
        }
    }
} catch {
    # role membership read may fail intermittently
}
if ($roleCheck) {
    Write-Verbose "    ->  [+] Admin user holds Global Administrator"
} else {
    Write-Verbose "    ->  [!] Global Admin role verification uncertain (may still be assigned)"
}

$SetupSuccessful = $policyCheck -and $policyHasGap -and $roleCheck
#endregion

#region Output Summary
if ($VerbosePreference -eq 'Continue') {
    Write-Host ""
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host "|             SCENARIO 7 SETUP COMPLETED (VERBOSE)             |" -ForegroundColor Cyan
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "`nVULNERABILITY DETAILS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  - Conditional Access policy requires MFA but only for modern-auth clients" -ForegroundColor White
    Write-Host "  - clientAppTypes = browser, mobileAppsAndDesktopClients" -ForegroundColor White
    Write-Host "  - Legacy-auth paths (exchangeActiveSync, other) are unscoped" -ForegroundColor White
    Write-Host "  - ROPC, IMAP/POP/SMTP AUTH, and ActiveSync sign-ins bypass MFA entirely" -ForegroundColor White
    Write-Host "  - Admin account password is reachable via password spray over legacy auth" -ForegroundColor White

    Write-Host "`nATTACKER CREDENTIALS:" -ForegroundColor Red
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Username: " -ForegroundColor White -NoNewline
    Write-Host "$LowPrivUPN" -ForegroundColor Cyan
    Write-Host "  Password: " -ForegroundColor White -NoNewline
    Write-Host "$LowPrivPassword" -ForegroundColor Cyan

    Write-Host "`nTARGET:" -ForegroundColor Magenta
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Username: " -ForegroundColor White -NoNewline
    Write-Host "$AdminUPN" -ForegroundColor Cyan
    Write-Host "  Flag Location: " -ForegroundColor White -NoNewline
    Write-Host "extensionAttribute1" -ForegroundColor Cyan

    Write-Host "`nCONDITIONAL ACCESS POLICY:" -ForegroundColor Blue
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Name: " -ForegroundColor White -NoNewline
    Write-Host "$CAPolicyName" -ForegroundColor Cyan
    Write-Host "  Policy ID: " -ForegroundColor White -NoNewline
    Write-Host "$($CreatedPolicy.Id)" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "FLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host ""
} else {
    Write-Host ""
    if ($SetupSuccessful) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "Scenario 7 setup completed successfully" -ForegroundColor White
        Write-Host ""
        Write-Host "Objective: Sign in as the admin user and retrieve the flag." -ForegroundColor Gray
        Write-Host ""
        Write-Host "`nYOUR CREDENTIALS:" -ForegroundColor Red
        Write-Host "----------------------------" -ForegroundColor DarkGray
        Write-Host "  Username: " -ForegroundColor White -NoNewline
        Write-Host "$LowPrivUPN" -ForegroundColor Cyan
        Write-Host "  Password: " -ForegroundColor White -NoNewline
        Write-Host "$LowPrivPassword" -ForegroundColor Cyan

        Write-Host "`nTARGET:" -ForegroundColor Magenta
        Write-Host "----------------------------" -ForegroundColor DarkGray
        Write-Host "  Username: " -ForegroundColor White -NoNewline
        Write-Host "$AdminUPN" -ForegroundColor Cyan

        Write-Host "  Flag Location: " -ForegroundColor White -NoNewline
        Write-Host "extensionAttribute1" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "Hint: Modern auth gets the bouncer. The side door does not." -ForegroundColor DarkGray
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 7 setup failed - give it another shot or run with -Verbose flag to reveal more for debugging (spoiler alert)." -ForegroundColor White
    }
    Write-Host ""
}
#endregion
