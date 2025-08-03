<#

EntraGoat Scenario 6:  CBA (Certificate Bypass Authority) Root Access Granted
Setup script to be run with Global Administrator privileges 

#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$Flag = "EntraGoat{C3rt_Byp@ss_R00t3d_4dm1n}"
$AdminPassword = "AdminP@ssw0rd2025!"
$LowPrivPassword = "TheGoatAccess!123"
$LegacyAutomationAppName = "Legacy-Automation-Service"
$DataSyncAppName = "DataSync-Production"
$OrgConfigAppName = "Organization-Config-Manager"
$AuthPolicyGroupName = "Authentication Policy Managers"

$standardDelay = 10
$longReplicationDelay = 20

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 6 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|   CBA (Certificate Bypass Authority)  Root Access Granted    |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

#region Module check and import
Write-Verbose "[*] Checking and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Groups"
    # "PrivilegedAccess.ReadWrite.AzureADGroup",
    # "RoleEligibilitySchedule.ReadWrite.Directory",
    # "RoleAssignmentSchedule.ReadWrite.Directory"
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
            foreach ($moduleName in $MissingModules) {
                Import-Module $moduleName -ErrorAction Stop
                Write-Verbose "   Imported $moduleName"
            }
        } catch {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to automatically install or import modules: $($MissingModules -join ', '). Please install them manually and re-run the script. Error: $($_.Exception.Message)" -ForegroundColor White
            exit 1
        }
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Required modules are missing. Please install them and re-run the script." -ForegroundColor White
        exit 1
    }
} else {
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
#endregion

#region Authentication
Write-Verbose "[*] Connecting to Microsoft Graph..."
$GraphScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", 
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Group.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "PrivilegedAccess.ReadWrite.AzureADGroup"
)

try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $GraphScopes -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -Scopes $GraphScopes -NoWelcome
    }
    $Organization = Get-MgOrganization
    $TenantDomain = ($Organization.VerifiedDomains | Where-Object IsDefault).Name
    $CurrentTenantId = $Organization.Id
    Write-Verbose "[+] Connected to tenant: $TenantDomain ($CurrentTenantId)"
} catch {
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor White
    exit 1
}
#endregion

#region User Creation
Write-Verbose "[*] Setting up users..."
$LowPrivUPN = "terence.mckenna@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s6@$TenantDomain"

# Create or get low-privileged user
Write-Verbose "    ->  Low-privileged user: $LowPrivUPN"
$ExistingLowPrivUser = Get-MgUser -Filter "userPrincipalName eq '$LowPrivUPN'" -ErrorAction SilentlyContinue
if ($ExistingLowPrivUser) {
    $LowPrivUser = $ExistingLowPrivUser
    Write-Verbose "      EXISTS (using existing)"
} else {
    $LowPrivUserParams = @{
    DisplayName = "Terence McKenna"
    UserPrincipalName = $LowPrivUPN
    MailNickname = "terence.mckenna"
    Department = "DevOps Cognitive Infrastructure"
    JobTitle = "Ethnobotanical Identity Orchestrator"
    AccountEnabled = $true
    PasswordProfile = @{
        ForceChangePasswordNextSignIn = $false
        Password = $LowPrivPassword
    }
}
    $LowPrivUser = New-MgUser @LowPrivUserParams
    Write-Verbose "      CREATED"
    Start-Sleep -Seconds $standardDelay
}

# Create dummy users for realism
Write-Verbose "[*] Creating dummy users for realistic environment..."
$dummyUsers = @(
    @{
        DisplayName = "Alice Johnson"
        UserPrincipalName = "alice.johnson@$TenantDomain"
        MailNickname = "alice.johnson"
        Department = "Security"
        JobTitle = "Security Analyst"
    },
    @{
        DisplayName = "Bob Smith"
        UserPrincipalName = "bob.smith@$TenantDomain"
        MailNickname = "bob.smith"
        Department = "IT Operations"
        JobTitle = "Systems Engineer"
    }
)

foreach ($dummyUser in $dummyUsers) {
    $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($dummyUser.UserPrincipalName)'" -ErrorAction SilentlyContinue
    if (-not $existingUser) {
        $userParams = $dummyUser + @{
            AccountEnabled = $true
            PasswordProfile = @{
                ForceChangePasswordNextSignIn = $false
                Password = "DummyP@ssw0rd$(Get-Random -Maximum 9999)"
            }
        }
        New-MgUser @userParams | Out-Null
        Write-Verbose "    ->  Created dummy user: $($dummyUser.DisplayName)"
    }
}

# Create or get admin user
Write-Verbose "    ->  Admin user: $AdminUPN"
$ExistingAdminUser = Get-MgUser -Filter "userPrincipalName eq '$AdminUPN'" -ErrorAction SilentlyContinue
if ($ExistingAdminUser) {
    $AdminUser = $ExistingAdminUser
    Write-Verbose "      EXISTS (using existing)"
    # Update password to ensure we know it
    $passwordProfile = @{
        Password = $AdminPassword
        ForceChangePasswordNextSignIn = $false
    }
    Update-MgUser -UserId $AdminUser.Id -PasswordProfile $passwordProfile
} else {
    $AdminUserParams = @{
        DisplayName = "EntraGoat Administrator S6"
        UserPrincipalName = $AdminUPN
        MailNickname = "entragoat-admin-s6"
        AccountEnabled = $true
        Department = "Executive"
        JobTitle = "System Administrator"
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $AdminPassword
        }
    }
    $AdminUser = New-MgUser @AdminUserParams
    Write-Verbose "      CREATED"
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
    Update-MgUser -UserId $AdminUser.Id -BodyParameter $UpdateParams -ErrorAction Stop
    Write-Verbose "    ->  Flag stored successfully."
} catch {
    Write-Verbose "    ->  Flag already set (continuing): $($_.Exception.Message)"
}
#endregion

#region Assign GA to Admin User
Write-Verbose "[*] Assigning Global Administrator role to admin user ($AdminUPN)..."
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
$DirectoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GlobalAdminRoleId'" -ErrorAction SilentlyContinue

if (-not $DirectoryRole) {
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $GlobalAdminRoleId
    $DirectoryRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}

$ExistingGARMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRole.Id -All -ErrorAction SilentlyContinue
$IsAlreadyGAMember = $false
if ($ExistingGARMembers) {
    foreach ($member in $ExistingGARMembers) {
        if ($member.Id -eq $AdminUser.Id) {
            $IsAlreadyGAMember = $true
            break
        }
    }
}

if (-not $IsAlreadyGAMember) {
    Write-Verbose "    ->  Assigning GA role to $($AdminUser.UserPrincipalName)..."
    try {
        $RoleMemberParams = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($AdminUser.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $DirectoryRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "    ->  Role assigned successfully."
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "    ->  Role was already assigned."
        } else {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to assign Global Admin role to admin user: $($_.Exception.Message)" -ForegroundColor White
        }
    }
} else {
    Write-Verbose "    ->  Admin user already has Global Administrator role."
}
#endregion

#region Create Legacy Automation App and SP
Write-Verbose "[*] Creating legacy automation application: $LegacyAutomationAppName"
$ExistingLegacyApp = Get-MgApplication -Filter "displayName eq '$LegacyAutomationAppName'" -ErrorAction SilentlyContinue

if ($ExistingLegacyApp) {
    $LegacyApp = $ExistingLegacyApp
    Write-Verbose "    ->  Application exists: $LegacyAutomationAppName"
} else {
    $LegacyAppParams = @{
        DisplayName = $LegacyAutomationAppName
        SignInAudience = "AzureADMyOrg"
        Notes = "Legacy automation service"
    }
    $LegacyApp = New-MgApplication @LegacyAppParams
    Write-Verbose "    ->  Application created: $LegacyAutomationAppName"
    Start-Sleep -Seconds $standardDelay
}

# Add client secret
Write-Verbose "[*] Adding client secret to legacy automation app..."
$secretDescription = "Legacy-Secret-$(Get-Date -Format 'yyyyMMdd')"
$passwordCredential = @{
    DisplayName = $secretDescription
    EndDateTime = (Get-Date).AddYears(1)
}

$LegacyAppSecret = Add-MgApplicationPassword -ApplicationId $LegacyApp.Id -PasswordCredential $passwordCredential
$LegacyAppId = $LegacyApp.AppId
$LegacyClientSecret = $LegacyAppSecret.SecretText # save that for output 
Write-Verbose "    ->  Secret added successfully"

Write-Verbose "[*] Creating service principal for legacy automation app..."
$ExistingLegacySP = Get-MgServicePrincipal -Filter "appId eq '$LegacyAppId'" -ErrorAction SilentlyContinue

if ($ExistingLegacySP) {
    $LegacySP = $ExistingLegacySP
    Write-Verbose "    ->  Service principal exists"
} else {
    $LegacySPParams = @{
        AppId = $LegacyAppId
        DisplayName = $LegacyAutomationAppName
    }
    $LegacySP = New-MgServicePrincipal @LegacySPParams
    Write-Verbose "    ->  Service principal created"
    Start-Sleep -Seconds $standardDelay
}

# Make it visible in Azure Portal UI
$Tags = @("WindowsAzureActiveDirectoryIntegratedApp")
Update-MgServicePrincipal -ServicePrincipalId $LegacySP.Id -Tags $Tags

# Grant Directory.Read.All for easier enumeration
Write-Verbose "[*] Granting minimal permissions to legacy SP..."
$GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$DirectoryReadAllRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq "Directory.Read.All" }

$ExistingGrants = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $LegacySP.Id
$hasDirectoryRead = $ExistingGrants | Where-Object { $_.AppRoleId -eq $DirectoryReadAllRole.Id }

if (-not $hasDirectoryRead) {
    Write-Verbose "    ->  Granting Directory.Read.All..."
    $AppRoleAssignment = @{
        PrincipalId = $LegacySP.Id
        ResourceId = $GraphServicePrincipal.Id
        AppRoleId = $DirectoryReadAllRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $LegacySP.Id -BodyParameter $AppRoleAssignment | Out-Null
    Write-Verbose "      Granted."
    Start-Sleep -Seconds $standardDelay
}

# Grant Application.ReadWrite.OwnedBy to make it able to update creds on any app or SP it owns.
$AppRwOwnedByRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq "Application.ReadWrite.OwnedBy" }
$hasAppRwOwnedBy = $ExistingGrants | Where-Object { $_.AppRoleId -eq $AppRwOwnedByRole.Id }

if (-not $hasAppRwOwnedBy) {
    Write-Verbose "    ->  Granting Application.ReadWrite.OwnedBy..."
    $AppRoleAssignment = @{
        PrincipalId = $LegacySP.Id          
        ResourceId  = $GraphServicePrincipal.Id 
        AppRoleId   = $AppRwOwnedByRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $LegacySP.Id -BodyParameter $AppRoleAssignment | Out-Null
    Write-Verbose "      Granted."
    Start-Sleep -Seconds $standardDelay
}
#endregion

#region Create DataSync app and SP
Write-Verbose "[*] Creating data sync application: $DataSyncAppName"
$ExistingDataSyncApp = Get-MgApplication -Filter "displayName eq '$DataSyncAppName'" -ErrorAction SilentlyContinue

if ($ExistingDataSyncApp) {
    $DataSyncApp = $ExistingDataSyncApp
    Write-Verbose "    ->  Application exists: $DataSyncAppName"
} else {
    $DataSyncAppParams = @{
        DisplayName = $DataSyncAppName
        SignInAudience = "AzureADMyOrg"
        Notes = "Production data synchronization service"
    }
    $DataSyncApp = New-MgApplication @DataSyncAppParams
    Write-Verbose "    ->  Application created: $DataSyncAppName"
    Start-Sleep -Seconds $standardDelay
}

$DataSyncAppId = $DataSyncApp.AppId

Write-Verbose "[*] Creating service principal for data sync app..."
$ExistingDataSyncSP = Get-MgServicePrincipal -Filter "appId eq '$DataSyncAppId'" -ErrorAction SilentlyContinue

if ($ExistingDataSyncSP) {
    $DataSyncSP = $ExistingDataSyncSP
    Write-Verbose "    ->  Service principal exists"
} else {
    $DataSyncSPParams = @{
        AppId = $DataSyncAppId
        DisplayName = $DataSyncAppName
    }
    $DataSyncSP = New-MgServicePrincipal @DataSyncSPParams
    Write-Verbose "    ->  Service principal created"
    Start-Sleep -Seconds $standardDelay
}

# Make it visible in Azure Portal UI
Update-MgServicePrincipal -ServicePrincipalId $DataSyncSP.Id -Tags $Tags

# Grant Organization.ReadWrite.All to DataSync SP
Write-Verbose "[!] Granting Organization.ReadWrite.All to DataSync SP..."
$OrganizationReadWriteAllRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq "Organization.ReadWrite.All" }

$ExistingDataSyncGrants = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $DataSyncSP.Id
$hasOrgReadWriteAll = $ExistingDataSyncGrants | Where-Object { $_.AppRoleId -eq $OrganizationReadWriteAllRole.Id }

if (-not $hasOrgReadWriteAll) {
    Write-Verbose "    ->  Granting Organization.ReadWrite.All..."
    $AppRoleAssignment = @{
        PrincipalId = $DataSyncSP.Id
        ResourceId = $GraphServicePrincipal.Id
        AppRoleId = $OrganizationReadWriteAllRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $DataSyncSP.Id -BodyParameter $AppRoleAssignment | Out-Null
    Write-Verbose "      Granted."
    Start-Sleep -Seconds $standardDelay
}

# Also grant Directory.Read.All for enumeration
$hasDirectoryRead = $ExistingDataSyncGrants | Where-Object { $_.AppRoleId -eq $DirectoryReadAllRole.Id }
if (-not $hasDirectoryRead) {
    Write-Verbose "    ->  Granting Directory.Read.All..."
    $AppRoleAssignment = @{
        PrincipalId = $DataSyncSP.Id
        ResourceId = $GraphServicePrincipal.Id
        AppRoleId = $DirectoryReadAllRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $DataSyncSP.Id -BodyParameter $AppRoleAssignment | Out-Null
    Write-Verbose "      Granted."
    Start-Sleep -Seconds $standardDelay
}
#endregion

#region Create Organization Config Manager app and SP
Write-Verbose "[*] Creating organization config manager application: $OrgConfigAppName"
$ExistingOrgConfigApp = Get-MgApplication -Filter "displayName eq '$OrgConfigAppName'" -ErrorAction SilentlyContinue

if ($ExistingOrgConfigApp) {
    $OrgConfigApp = $ExistingOrgConfigApp
    Write-Verbose "    ->  Application exists: $OrgConfigAppName"
} else {
    $OrgConfigAppParams = @{
        DisplayName = $OrgConfigAppName
        SignInAudience = "AzureADMyOrg"
        Notes = "Service for managing organization-wide configurations"
    }
    $OrgConfigApp = New-MgApplication @OrgConfigAppParams
    Write-Verbose "    ->  Application created: $OrgConfigAppName"
    Start-Sleep -Seconds $standardDelay
}

$OrgConfigAppId = $OrgConfigApp.AppId

Write-Verbose "[*] Creating service principal for org config app..."
$ExistingOrgConfigSP = Get-MgServicePrincipal -Filter "appId eq '$OrgConfigAppId'" -ErrorAction SilentlyContinue

if ($ExistingOrgConfigSP) {
    $OrgConfigSP = $ExistingOrgConfigSP
    Write-Verbose "    ->  Service principal exists"
} else {
    $OrgConfigSPParams = @{
        AppId = $OrgConfigAppId
        DisplayName = $OrgConfigAppName
    }
    $OrgConfigSP = New-MgServicePrincipal @OrgConfigSPParams
    Write-Verbose "    ->  Service principal created"
    Start-Sleep -Seconds $standardDelay
}

Update-MgServicePrincipal -ServicePrincipalId $OrgConfigSP.Id -Tags $Tags


# Grant Policy.ReadWrite.AuthenticationMethod to OrgConfig SP
Write-Verbose "[!] Granting Policy.ReadWrite.AuthenticationMethod to OrgConfig SP..."
$OrgReadWriteAuthMethodRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq "Policy.ReadWrite.AuthenticationMethod" }

$ExistingOrgConfigGrants = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $OrgConfigSP.Id
$hasOrgPermission = $ExistingOrgConfigGrants | Where-Object { $_.AppRoleId -eq $OrgReadWriteAuthMethodRole.Id }

if (-not $hasOrgPermission) {
    Write-Verbose "    ->  Granting Policy.ReadWrite.AuthenticationMethod..."
    $AppRoleAssignment = @{
        PrincipalId = $OrgConfigSP.Id
        ResourceId = $GraphServicePrincipal.Id
        AppRoleId = $OrgReadWriteAuthMethodRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $OrgConfigSP.Id -BodyParameter $AppRoleAssignment | Out-Null
    Write-Verbose "      Granted."
    Start-Sleep -Seconds $standardDelay
}

# Also grant Directory.Read.All for enumeration
$hasDirectoryRead = $ExistingOrgConfigGrants | Where-Object { $_.AppRoleId -eq $DirectoryReadAllRole.Id }
if (-not $hasDirectoryRead) {
    Write-Verbose "    ->  Granting Directory.Read.All..."
    $AppRoleAssignment = @{
        PrincipalId = $OrgConfigSP.Id
        ResourceId = $GraphServicePrincipal.Id
        AppRoleId = $DirectoryReadAllRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $OrgConfigSP.Id -BodyParameter $AppRoleAssignment | Out-Null
    Write-Verbose "      Granted."
    Start-Sleep -Seconds $standardDelay
}
#endregion

#region Create Authentication Policy Managers Group
Write-Verbose "[*] Creating Authentication Policy Managers group..."
$ExistingAuthPolicyGroup = Get-MgGroup -Filter "displayName eq '$AuthPolicyGroupName'" -ErrorAction SilentlyContinue

if ($ExistingAuthPolicyGroup) {
    $AuthPolicyGroup = $ExistingAuthPolicyGroup
    Write-Verbose "    ->  Group exists: $AuthPolicyGroupName"
} else {
    $GroupParams = @{
        DisplayName = $AuthPolicyGroupName
        Description = "Group with Authentication Policy Administrator role"
        MailEnabled = $false
        MailNickname = "auth-policy-managers"
        SecurityEnabled = $true
        IsAssignableToRole = $true
    }
    $AuthPolicyGroup = New-MgGroup @GroupParams
    Write-Verbose "    ->  Group created: $AuthPolicyGroupName"
    Start-Sleep -Seconds $standardDelay
}

# Assign Authentication Policy Administrator role to the group
Write-Verbose "[*] Assigning Authentication Policy Administrator role to group..."
$AuthPolicyAdminRoleId = "0526716b-113d-4c15-b2c8-68e3c22b9f80"  

# Check if role is activated and if the group already has it
$AuthPolicyRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$AuthPolicyAdminRoleId'" -ErrorAction SilentlyContinue
if (-not $AuthPolicyRole) {
    Write-Verbose "    ->  Activating Authentication Policy Administrator role template..."
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $AuthPolicyAdminRoleId
    $AuthPolicyRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}

$ExistingRoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $AuthPolicyRole.Id -All -ErrorAction SilentlyContinue
$IsAlreadyMember = $false
if ($ExistingRoleMembers) {
    foreach ($member in $ExistingRoleMembers) {
        if ($member.Id -eq $AuthPolicyGroup.Id) {
            $IsAlreadyMember = $true
            break
        }
    }
}

if (-not $IsAlreadyMember) {
    Write-Verbose "    ->  Assigning role to group..."
    try {
        $RoleMemberParams = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($AuthPolicyGroup.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $AuthPolicyRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "    ->  Role assigned successfully."
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "    ->  Role was already assigned."
        } else {
            Write-Host "[-] Failed to assign role: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Verbose "    ->  Group already has Authentication Policy Administrator role."
}


Write-Verbose "[*] Assigning Application Administrator role to group Auth Policy group..."

# Assign app admin role to the group
$AppAdminRoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" 

$AppAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$AppAdminRoleId'" -ErrorAction SilentlyContinue
if (-not $AppAdminRole) {
    Write-Verbose "    ->  Activating Application Administrator role template..."
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $AppAdminRoleId
    $AppAdminRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}

# Check if group already has the role
$ExistingAppAdminMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $AppAdminRole.Id -All -ErrorAction SilentlyContinue
$IsAlreadyAppAdmin = $false
if ($ExistingAppAdminMembers) {
    foreach ($member in $ExistingAppAdminMembers) {
        if ($member.Id -eq $AuthPolicyGroup.Id) {
            $IsAlreadyAppAdmin = $true
            break
        }
    }
}

if (-not $IsAlreadyAppAdmin) {
    Write-Verbose "    ->  Assigning Application Administrator role to group..."
    try {
        $RoleMemberParams = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($AuthPolicyGroup.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $AppAdminRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "    ->  Role assigned successfully."
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "    ->  Role was already assigned."
        } else {
            Write-Host "[-] Failed to assign role: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Verbose "    ->  Group already has Application Administrator role."
}
#endregion

#region Set up ownership relationships
Write-Verbose "[!] CREATING MISCONFIGURATION 1: Setting legacy SP as owner of DataSync SP..."

# Make Legacy SP owner of DataSync SP
$ExistingOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $DataSyncSP.Id
$IsAlreadyOwner = $false
if ($ExistingOwners) {
    foreach ($owner in $ExistingOwners) {
        if ($owner.Id -eq $LegacySP.Id) {
            $IsAlreadyOwner = $true
            break
        }
    }
}

if (-not $IsAlreadyOwner) {
    $OwnerParams = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($LegacySP.Id)"
    }
    New-MgServicePrincipalOwnerByRef -ServicePrincipalId $DataSyncSP.Id -BodyParameter $OwnerParams
    Write-Verbose "    ->  SP ownership granted"
    Start-Sleep -Seconds $standardDelay
} else {
    Write-Verbose "    ->  Already SP owner"
}

# Also add as owner of the associated application for credential management
$DataSyncAppObj = Get-MgApplication -Filter "appId eq '$DataSyncAppId'"
$ExistingAppOwners = Get-MgApplicationOwner -ApplicationId $DataSyncAppObj.Id
$IsAlreadyAppOwner = $false
if ($ExistingAppOwners) {
    foreach ($owner in $ExistingAppOwners) {
        if ($owner.Id -eq $LegacySP.Id) {
            $IsAlreadyAppOwner = $true
            break
        }
    }
}

if (-not $IsAlreadyAppOwner) {
    $OwnerParams = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($LegacySP.Id)"
    }
    New-MgApplicationOwnerByRef -ApplicationId $DataSyncAppObj.Id -BodyParameter $OwnerParams
    Write-Verbose "    ->  Application ownership granted (misconfiguration created)"
    Start-Sleep -Seconds $standardDelay
} else {
    Write-Verbose "    ->  Already application owner (misconfiguration exists)"
}

Write-Verbose "[!] CREATING MISCONFIGURATION 2: Making terence user eligible member of Auth Policy group..."

# Make Terence eligible member of Auth Policy Managers group
$eligibleMemberParams = @{
    accessId          = "member"
    principalId       = $LowPrivUser.Id  # Changed from $LegacySP.Id
    groupId           = $AuthPolicyGroup.Id
    action            = "adminAssign"
    scheduleInfo      = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{ 
            type = "afterDuration"
            duration = "P365D"  
        }
    }
    justification     = "Legacy user requires authentication policy management access"
}

try {
    $membershipResponse = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
        -Body $eligibleMemberParams -ContentType "application/json"
    Write-Verbose "    ->  Eligible membership granted (vulnerability created)"
    Start-Sleep -Seconds $standardDelay
} catch {
    Write-Verbose "    ->  Failed to create eligible membership: $($_.Exception.Message)"
}
#endregion


$SetupSuccessful = $true # Assume success unless an exit occurred

#region Output Summary
if ($VerbosePreference -eq 'Continue') {

    Write-Host ""
    Write-Host "|==============================================================|" -ForegroundColor Cyan
    Write-Host "|             SCENARIO 6 SETUP COMPLETED (VERBOSE)             |" -ForegroundColor Cyan
    Write-Host "|==============================================================|" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "`nSERVICE PRINCIPALS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Legacy SP: $LegacyAutomationAppName" -ForegroundColor Cyan
    Write-Host "  Data Sync SP: $DataSyncAppName" -ForegroundColor Cyan
    Write-Host "  Auth Policy SP: $AuthPolicyAdminAppName" -ForegroundColor Cyan

    Write-Host "`nFLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan
}

# Always display for successful setup
if ($SetupSuccessful) {
    Write-Host ""
    
    Write-Host "ATTACKER CREDENTIALS:" -ForegroundColor Magenta
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Username: " -ForegroundColor White -NoNewline
    Write-Host "$LowPrivUPN" -ForegroundColor Cyan
    Write-Host "  Password: " -ForegroundColor White -NoNewline
    Write-Host "$LowPrivPassword" -ForegroundColor Cyan

    Write-Host "`nTARGET:" -ForegroundColor Red
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Username: " -ForegroundColor White -NoNewline
    Write-Host "$AdminUPN" -ForegroundColor Cyan
    Write-Host "  Flag Location: " -ForegroundColor White -NoNewline
    Write-Host "extensionAttribute1" -ForegroundColor Cyan
}

# Always show the leaked secret
Write-Host ""
Write-Host "While reviewing an old PowerShell repo, you stumbled upon a" -ForegroundColor DarkGray
Write-Host "hardcoded secret " -ForegroundColor Yellow -NoNewline
Write-Host "in a script called 'legacy_sync_task.ps1':" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    # TODO: Move this to Key Vault someday" -ForegroundColor DarkGreen
Write-Host "    `$clientId = '$LegacyAppId'" -ForegroundColor Gray
Write-Host "    `$clientSecret = '$LegacyClientSecret'" -ForegroundColor Gray
Write-Host "    `$tenantId = '$CurrentTenantId'" -ForegroundColor Gray
Write-Host ""
Write-Host "The commit message says: 'Legacy auth policy automation - DO NOT DELETE'" -ForegroundColor DarkGray
Write-Host ""

if ($VerbosePreference -ne 'Continue') {
    if ($SetupSuccessful) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "Scenario 6 setup completed successfully." -ForegroundColor White
        Write-Host ""
        Write-Host " Objective: Chain service principal (mis)configurations to enable CBA and impersonate the admin." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Hint: That dusty old automation secret? Forgotten by devs, remembered by the backend." -ForegroundColor DarkGray

    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 6 setup did not complete successfully. Please check verbose output or previous errors." -ForegroundColor White
    }
}
Write-Host ""
#endregion