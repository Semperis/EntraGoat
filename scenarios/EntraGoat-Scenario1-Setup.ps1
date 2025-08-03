<#

EntraGoat Scenario 1: Misowned and Dangerous - Owner's Manual to Global Admin
Setup script to be run with Global Administrator privileges

#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $null
)


# Configuration
$PrivilegedAppName = "Finance Analytics Dashboard"
$Flag = "EntraGoat{SP_0wn3rsh1p_Pr1v_Esc@l@t10n_Congratz!}"
$AdminPassword = "ComplexP@ssw0rd#2025!"
$LowPrivPassword = "GoatAccess!123"

$standardDelay = 10 # Seconds
$longReplicationDelay = 20

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 1 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|   Misowned and Dangerous - Owner's Manual to Global Admin    |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

#region Module Check and Import
Write-Verbose "[*] Checking and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement"
)
$MissingModules = @()
foreach ($moduleName in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        $MissingModules += $moduleName
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Warning "The following required modules are not installed: $($MissingModules -join ', ')."
    $choice = Read-Host "Do you want to attempt to install them from PowerShell Gallery? (Y/N)"
    if ($choice -eq 'Y') {
        try {
            Write-Host "Attempting to install $($MissingModules -join ', ') from PowerShell Gallery. This may take a moment..." -ForegroundColor Yellow
            Install-Module -Name $MissingModules -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Verbose "[+] Successfully attempted to install missing modules."
            # Import them after installation
            foreach ($moduleName in $MissingModules) {
                Import-Module $moduleName -ErrorAction Stop
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
    # Import modules if they are installed but not loaded
    foreach ($moduleName in $RequiredModules) {
        if (-not (Get-Module -Name $moduleName)) {
            try {
                Import-Module $moduleName -ErrorAction Stop
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
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
)

try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
    }
    # $Context = Get-MgContext 
    $Organization = Get-MgOrganization
    $TenantDomain = ($Organization.VerifiedDomains | Where-Object IsDefault).Name

    Write-Verbose "[+] Connected to tenant: $TenantDomain"
} catch {
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host "Failed to connect: $($_.Exception.Message)" -ForegroundColor White
    exit 1
}
#endregion

#region User Creation
Write-Verbose "[*] Setting up users..."

$LowPrivUPN = "david.martinez@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s1@$TenantDomain"  

# Create (or get) low-privileged user
Write-Verbose "    ->  Regular user: $LowPrivUPN"
$ExistingLowPrivUser = Get-MgUser -Filter "userPrincipalName eq '$LowPrivUPN'" -ErrorAction SilentlyContinue
if ($ExistingLowPrivUser) {
    $LowPrivUser = $ExistingLowPrivUser
    Write-Verbose "       EXISTS (using existing)"
    # Update password to ensure we know it
    $passwordProfile = @{
        Password = $LowPrivPassword
        ForceChangePasswordNextSignIn = $false
    }
    Update-MgUser -UserId $LowPrivUser.Id -PasswordProfile $passwordProfile
} else {
    $LowPrivUserParams = @{
        DisplayName = "David Martinez"
        UserPrincipalName = $LowPrivUPN
        MailNickname = "david.martinez"
        AccountEnabled = $true
        Department = "Finance"
        JobTitle = "Financial Analyst"
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $LowPrivPassword
        }
    }
    $LowPrivUser = New-MgUser @LowPrivUserParams
    Write-Verbose "       CREATED"
    Start-Sleep -Seconds $standardDelay
}

# Create or get admin user
Write-Verbose "    ->  Admin user: $AdminUPN"
$ExistingAdminUser = Get-MgUser -Filter "userPrincipalName eq '$AdminUPN'" -ErrorAction SilentlyContinue
if ($ExistingAdminUser) {
    $AdminUser = $ExistingAdminUser
    Write-Verbose "       EXISTS (using existing)"
    # Update password to ensure we know it
    $passwordProfile = @{
        Password = $AdminPassword
        ForceChangePasswordNextSignIn = $false
    }
    Update-MgUser -UserId $AdminUser.Id -PasswordProfile $passwordProfile
} else {
    $AdminUserParams = @{
        DisplayName = "EntraGoat Administrator S1"
        UserPrincipalName = $AdminUPN
        MailNickname = "entragoat-admin-s1"
        AccountEnabled = $true
        Department = "IT Administration"
        JobTitle = "System Administrator"
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $AdminPassword
        }
    }
    $AdminUser = New-MgUser @AdminUserParams
    Write-Verbose "       CREATED"
    Start-Sleep -Seconds $standardDelay
}
#endregion

#region Store Flag in Admin User
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

#region Assign Global Administrator Role
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

#region Create Application Registration
Write-Verbose "[*] Creating application registration..."
$ExistingApp = Get-MgApplication -Filter "displayName eq '$PrivilegedAppName'" -ErrorAction SilentlyContinue
if ($ExistingApp) {
    $PrivilegedApp = $ExistingApp
    Write-Verbose "    ->  Application exists: $PrivilegedAppName"
} else {
    $AppParams = @{
        DisplayName = $PrivilegedAppName
        SignInAudience = "AzureADMyOrg"
        Description = "Internal Finance analytics and reporting dashboard"
        Web = @{
            RedirectUris = @("https://hr-analytics.contoso.com/callback")
        }
    }
    $PrivilegedApp = New-MgApplication @AppParams
    Write-Verbose "    ->  Application created: $PrivilegedAppName"
    Start-Sleep -Seconds $standardDelay
}
$AppId = $PrivilegedApp.AppId
if ($AppId -is [array]) { $AppId = $AppId[0] }
$AppId = $AppId.ToString()
#endregion

#region Create Service Principal
Write-Verbose "[*] Creating service principal..."
$ExistingSP = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
if ($ExistingSP) {
    $ServicePrincipal = $ExistingSP
    Write-Verbose "    ->  Service principal exists"
    $CurrentTags = $ServicePrincipal.Tags
    if (-not ($CurrentTags -contains "WindowsAzureActiveDirectoryIntegratedApp")) {
        $Tags = @("WindowsAzureActiveDirectoryIntegratedApp") # Visibility tag to make it discoverable via the portal
        Update-MgServicePrincipal -ServicePrincipalId $ServicePrincipal.Id -Tags $Tags
        Write-Verbose "    ->  Updated visibility tags"
    }
} else {
    $SPParams = @{
        AppId = $AppId
        DisplayName = $PrivilegedApp.DisplayName
    }
    $ServicePrincipal = New-MgServicePrincipal @SPParams
    Write-Verbose "    ->  Service principal created"
    Start-Sleep -Seconds $standardDelay
    $Tags = @("WindowsAzureActiveDirectoryIntegratedApp") 
    Update-MgServicePrincipal -ServicePrincipalId $ServicePrincipal.Id -Tags $Tags
}
#endregion

#region Set Low-Priv User as Service Principal Owner (THE MISCONFIGURATION)
Write-Verbose "[!] CREATING MISCONFIGURATION: Setting Finance user as SP owner..."

$ExistingOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $ServicePrincipal.Id
$IsAlreadyOwner = $false
if ($ExistingOwners) {
    foreach ($owner in $ExistingOwners) {
        if ($owner.Id -eq $LowPrivUser.Id) {
            $IsAlreadyOwner = $true
            break
        }
    }
}
if (-not $IsAlreadyOwner) {
    $OwnerParams = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($LowPrivUser.Id)"
    }
    New-MgServicePrincipalOwnerByRef -ServicePrincipalId $ServicePrincipal.Id -BodyParameter $OwnerParams
    Write-Verbose "    ->  Ownership granted"
    Start-Sleep -Seconds $standardDelay
    $UpdatedOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $ServicePrincipal.Id
    $OwnerVerified = $false
    foreach ($owner in $UpdatedOwners) {
        if ($owner.Id -eq $LowPrivUser.Id) {
            $OwnerVerified = $true
            break
        }
    }
    if (-not $OwnerVerified) {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "CRITICAL: Ownership verification failed!" -ForegroundColor White
        exit 1
    }
} else {
    Write-Verbose "    ->  Already owner (vulnerability exists)"
}
#endregion

#region Grant Privileged Authentication Administrator Role
Write-Verbose "[*] Granting Privileged Authentication Administrator role..."

$PrivAuthAdminRoleId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
$PrivAuthAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$PrivAuthAdminRoleId'" -ErrorAction SilentlyContinue
if (-not $PrivAuthAdminRole) {
    Write-Verbose "    ->  Activating Privileged Auth Admin role..."
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $PrivAuthAdminRoleId
    $PrivAuthAdminRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}
$hasRole = $false
try {
    $ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $PrivAuthAdminRole.Id -All -ErrorAction SilentlyContinue
    if ($ExistingMembers) {
        foreach ($member in $ExistingMembers) {
            if ($member.Id -eq $ServicePrincipal.Id) {
                $hasRole = $true
                break
            }
        }
    }
} catch {
    # Role might not have any members yet
}
if (-not $hasRole) {
    try {
        $RoleMemberParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.Id)"
        }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $PrivAuthAdminRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "    ->  Role granted successfully!"
        $hasRole = $true
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*" -or $_.Exception.Message -like "*Request_BadRequest*") {
            Write-Verbose "    ->  Role already assigned"
            $hasRole = $true
        } else {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to assign role: $($_.Exception.Message)" -ForegroundColor White
        }
    }
} else {
    Write-Verbose "    ->  Role already assigned"
}
#endregion

#region Final Verification
Write-Verbose "[*] Running final verification..."

# Verify ownership
$owners = Get-MgServicePrincipalOwner -ServicePrincipalId $ServicePrincipal.Id
$ownerCheck = $false
foreach ($owner in $owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $ownerCheck = $true
        break
    }
}
if ($ownerCheck) {
    Write-Verbose "    ->  [+] Finance user owns service principal"
} else {
    Write-Verbose "    ->  [-] Finance user does NOT own service principal"
}

# Verify role
$roleCheck = $false
try {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $PrivAuthAdminRole.Id -All -ErrorAction SilentlyContinue
    if ($members) {
        foreach ($member in $members) {
            if ($member.Id -eq $ServicePrincipal.Id) {
                $roleCheck = $true
                break
            }
        }
    }
} catch {
    try {
        $spRoles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($ServicePrincipal.Id)'"
        if ($spRoles | Where-Object { $_.RoleDefinitionId -eq $PrivAuthAdminRole.Id }) {
            $roleCheck = $true
        }
    } catch {}
}
if ($roleCheck -or $hasRole) {
    Write-Verbose "    ->  [+] SP has Privileged Authentication Administrator role"
} else {
    Write-Verbose "    ->  [!] Role verification uncertain (may still be assigned)"
}
$SetupSuccessful = $ownerCheck -and ($roleCheck -or $hasRole)
#endregion

#region Output Summary
if ($VerbosePreference -eq 'Continue') {
    # Verbose output with all details
    Write-Host "`n" -NoNewline
    Write-Host "----------------------------------------------------------------" -ForegroundColor Green
    Write-Host "              SCENARIO 1 SETUP COMPLETED                        " -ForegroundColor Green
    Write-Host "----------------------------------------------------------------" -ForegroundColor Green

    Write-Host "`nVULNERABILITY DETAILS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  - Regular user owns a service principal" -ForegroundColor White
    Write-Host "  - Service principal has Privileged Auth Admin role" -ForegroundColor White
    Write-Host "  - Attacker can add credentials and escalate" -ForegroundColor White

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

    Write-Host "`nSERVICE PRINCIPAL:" -ForegroundColor Blue
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Name: " -ForegroundColor White -NoNewline
    Write-Host "$($ServicePrincipal.DisplayName)" -ForegroundColor Cyan
    Write-Host "  SP ID: " -ForegroundColor White -NoNewline
    Write-Host "$($ServicePrincipal.Id)" -ForegroundColor Cyan
    Write-Host "  App ID: " -ForegroundColor White -NoNewline
    Write-Host "$AppId" -ForegroundColor Cyan

    Write-Host "`n" -NoNewline
    Write-Host "FLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host ""
} else {
    # Minimal output for CTF players
    Write-Host "`n" -NoNewline
    if ($SetupSuccessful) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "Scenario 1 setup completed successfully" -ForegroundColor White
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

        Write-Host "Hint: Ownership leaves a mark. Trace what entities bear your name." -ForegroundColor DarkGray
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 1 setup failed - give it another shot or run with -Verbose flag to reveal more for debugging (spoiler alert)." -ForegroundColor White
    }
    Write-Host ""
}
#endregion