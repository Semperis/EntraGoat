<#

EntraGoat Scenario 6:  CBA (Certificate Bypass Authority) - Root Access Granted
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
$AdminPassword = "ComplexAdminP@ssw0rd#2025!"
$LowPrivPassword = "TheGoatAccess!123"
$LegacyAutomationAppName = "Legacy-Automation-Service"
$DataSyncAppName = "DataSync-Production"
$OrgConfigAppName = "Organization-Config-Manager"
$AuthPolicyGroupName = "Authentication Policy Managers"
$AIAdminGroupName = "AI Operations Team"
$standardDelay = 5
$longReplicationDelay = 15

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
        # Update password to ensure we know it
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

function New-EntraGoatApplication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$false)]
        [string]$SignInAudience = "AzureADMyOrg",
        
        [Parameter(Mandatory=$false)]
        [array]$RedirectUris = @(),
        
        [Parameter(Mandatory=$false)]
        [array]$Tags = @("WindowsAzureActiveDirectoryIntegratedApp")
    )
    
    Write-Verbose "[*] Creating application: $DisplayName"
    $ExistingApp = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    
    if ($ExistingApp) {
        $App = $ExistingApp
        Write-Verbose "   -> Application exists: $DisplayName"
    } else {
        $AppParams = @{
            DisplayName = $DisplayName
            SignInAudience = $SignInAudience
            Description = $Description
        }
        if ($RedirectUris) {
            $AppParams.Web = @{
                RedirectUris = $RedirectUris
            }
        }
        $App = New-MgApplication @AppParams
        Write-Verbose "   -> Application created: $DisplayName"
        Start-Sleep -Seconds $standardDelay
    }
    
    # Get App ID
    $AppId = $App.AppId
    if ($AppId -is [array]) { $AppId = $AppId[0] }
    $AppId = $AppId.ToString()
    
    # Create service principal
    Write-Verbose "[*] Creating service principal for $DisplayName..."
    $ExistingSP = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
    
    if ($ExistingSP) {
        $SP = $ExistingSP
        Write-Verbose "   -> Service principal exists"
        if ($Tags) {
            Update-MgServicePrincipal -ServicePrincipalId $SP.Id -Tags $Tags -ErrorAction SilentlyContinue
            Write-Verbose "   -> Updated tags"
        }
    } else {
        $SPParams = @{
            AppId = $AppId
            DisplayName = $DisplayName
        }
        $SP = New-MgServicePrincipal @SPParams
        Write-Verbose "   -> Service principal created"
        Start-Sleep -Seconds $standardDelay
        if ($Tags) {
            Update-MgServicePrincipal -ServicePrincipalId $SP.Id -Tags $Tags
        }
    }
    
    return @{
        Application = $App
        ServicePrincipal = $SP
        AppId = $AppId
    }
}

function New-EntraGoatGroup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [string]$Description,
        [Parameter(Mandatory=$true)]
        [string]$MailNickname,
        [Parameter(Mandatory=$false)]
        [string]$RoleTemplateId = $null,
        [Parameter(Mandatory=$false)]
        [bool]$IsAssignableToRole = $true
    )
    
    Write-Verbose "[*] Creating group: $GroupName"
    $ExistingGroup = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    
    if ($ExistingGroup) {
        $Group = $ExistingGroup
        Write-Verbose "   -> Group exists: $GroupName"
    } else {
        $GroupParams = @{
            DisplayName = $GroupName
            Description = $Description
            MailEnabled = $false
            MailNickname = $MailNickname
            SecurityEnabled = $true
            IsAssignableToRole = $IsAssignableToRole
        }
        $Group = New-MgGroup @GroupParams
        Write-Verbose "   -> Group created: $GroupName"
        Start-Sleep -Seconds $standardDelay
    }
    
    # Assign role if specified
    if ($RoleTemplateId) {
        Write-Verbose "[*] Assigning role to group..."
        $DirectoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$RoleTemplateId'" -ErrorAction SilentlyContinue
        if (-not $DirectoryRole) {
            Write-Verbose "   -> Activating role template..."
            $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $RoleTemplateId
            $DirectoryRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
            Start-Sleep -Seconds $standardDelay
        }
        
        $ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRole.Id -All -ErrorAction SilentlyContinue
        $IsAlreadyAssigned = $false
        if ($ExistingMembers) {
            foreach ($member in $ExistingMembers) {
                if ($member.Id -eq $Group.Id) {
                    $IsAlreadyAssigned = $true
                    break
                }
            }
        }
        
        if (-not $IsAlreadyAssigned) {
            try {
                $RoleMemberParams = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($Group.Id)"
                }
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $DirectoryRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
                Write-Verbose "   -> Role assigned successfully"
                Start-Sleep -Seconds $longReplicationDelay
            } catch {
                if ($_.Exception.Message -like "*already exist*") {
                    Write-Verbose "   -> Role already assigned"
                } else {
                    Write-Verbose "   -> Failed to assign role: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "   -> Group already has role"
        }
    }
    
    return $Group
}
#endregion

#region User Creation
Write-Verbose "[*] Setting up users..."
$LowPrivUPN = "terence.mckenna@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s6@$TenantDomain"

# Create main users using helper function
$LowPrivUser = New-EntraGoatUser -DisplayName "Terence McKenna" -UserPrincipalName $LowPrivUPN -MailNickname "terence.mckenna" -Password $LowPrivPassword -Department "DevOps Cognitive Infrastructure" -JobTitle "Ethnobotanical Identity Orchestrator"
$AdminUser = New-EntraGoatUser -DisplayName "EntraGoat Administrator S6" -UserPrincipalName $AdminUPN -MailNickname "entragoat-admin-s6" -Password $AdminPassword -Department "Executive" -JobTitle "System Administrator"

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
    },
    @{
        DisplayName = "Carol Davis"
        UserPrincipalName = "carol.davis@$TenantDomain"
        MailNickname = "carol.davis"
        Department = "Identity Management"
        JobTitle = "Identity Specialist"
    },
    @{
        DisplayName = "David Wilson"
        UserPrincipalName = "david.wilson@$TenantDomain"
        MailNickname = "david.wilson"
        Department = "Authentication Services"
        JobTitle = "Authentication Engineer"
    }
)

$createdDummyUsers = @()
foreach ($dummyUser in $dummyUsers) {
    $newUser = New-EntraGoatUser -DisplayName $dummyUser.DisplayName -UserPrincipalName $dummyUser.UserPrincipalName -MailNickname $dummyUser.MailNickname -Password "DummyP@ssw0rd$(Get-Random -Maximum 9999)" -Department $dummyUser.Department -JobTitle $dummyUser.JobTitle
    $createdDummyUsers += $newUser
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
$LegacyAppResult = New-EntraGoatApplication -DisplayName $LegacyAutomationAppName -Description "Legacy automation service"

# Add client secret
Write-Verbose "[*] Adding client secret to legacy automation app..."
$secretDescription = "Legacy-Secret-$(Get-Date -Format 'yyyyMMdd')"
$passwordCredential = @{
    DisplayName = $secretDescription
    EndDateTime = (Get-Date).AddYears(1)
}

$LegacyAppSecret = Add-MgApplicationPassword -ApplicationId $LegacyAppResult.Application.Id -PasswordCredential $passwordCredential
$LegacyAppId = $LegacyAppResult.AppId
$LegacyClientSecret = $LegacyAppSecret.SecretText # save that for output 
Write-Verbose "    ->  Secret added successfully"

$LegacyApp = $LegacyAppResult.Application
$LegacySP = $LegacyAppResult.ServicePrincipal

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
$DataSyncAppResult = New-EntraGoatApplication -DisplayName $DataSyncAppName -Description "Production data synchronization service"
$DataSyncApp = $DataSyncAppResult.Application
$DataSyncSP = $DataSyncAppResult.ServicePrincipal
$DataSyncAppId = $DataSyncAppResult.AppId

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
$OrgConfigAppResult = New-EntraGoatApplication -DisplayName $OrgConfigAppName -Description "Service for managing organization-wide configurations"
$OrgConfigApp = $OrgConfigAppResult.Application
$OrgConfigSP = $OrgConfigAppResult.ServicePrincipal
$OrgConfigAppId = $OrgConfigAppResult.AppId


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
$AuthPolicyAdminRoleId = "0526716b-113d-4c15-b2c8-68e3c22b9f80"
$AppAdminRoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"

# Create group with Authentication Policy Administrator role
$AuthPolicyGroup = New-EntraGoatGroup -GroupName $AuthPolicyGroupName -Description "Group with Authentication Policy Administrator role" -MailNickname "auth-policy-managers" -RoleTemplateId $AuthPolicyAdminRoleId

# Add dummy users to the Auth Policy group for realism
Write-Verbose "[*] Adding dummy users to Auth Policy group..."
$authPolicyMembers = @($createdDummyUsers[0], $createdDummyUsers[1], $createdDummyUsers[2])  # Alice, Bob, and Carol
foreach ($member in $authPolicyMembers) {
    $currentMembers = Get-MgGroupMember -GroupId $AuthPolicyGroup.Id -All -ErrorAction SilentlyContinue
    $isMember = $currentMembers | Where-Object { $_.Id -eq $member.Id }
    
    if (-not $isMember) {
        $memberParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($member.Id)"
        }
        try {
            New-MgGroupMemberByRef -GroupId $AuthPolicyGroup.Id -BodyParameter $memberParams
            Write-Verbose "    -> Added $($member.DisplayName) to Auth Policy group"
        } catch {
            Write-Verbose "    -> $($member.DisplayName) already in group"
        }
    }
}

# Assign Application Administrator role to the group
Write-Verbose "[*] Assigning Application Administrator role to group Auth Policy group..."
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

#region Create AI Operations Team Group
Write-Verbose "[*] Creating AI Operations Team group..."
$AIAdminGroup = New-EntraGoatGroup -GroupName $AIAdminGroupName -Description "Team responsible for managing AI operations and services" -MailNickname "ai-ops-team" -RoleTemplateId "d2562ede-74db-457e-a7b6-544e236ebb61"

# Make Terence eligible owner of AI Operations group
Write-Verbose "[!] Making terence user eligible owner of AI Operations group..."
$eligibleAIOwnerParams = @{
    accessId          = "owner"
    principalId       = $LowPrivUser.Id
    groupId           = $AIAdminGroup.Id
    action            = "adminAssign"
    scheduleInfo      = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{ 
            type = "afterDuration"
            duration = "P365D"  
        }
    }
    justification     = "AI operations management responsibilities"
}

try {
    $aiOwnershipResponse = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
        -Body $eligibleAIOwnerParams -ContentType "application/json"
    Write-Verbose "    ->  Eligible AI Operations ownership granted"
    Start-Sleep -Seconds $standardDelay
} catch {
    Write-Verbose "    ->  Failed to create eligible AI Operations ownership: $($_.Exception.Message)"
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
    Write-Verbose "    ->  Eligible membership granted"
    Start-Sleep -Seconds $standardDelay
} catch {
    Write-Verbose "    ->  Failed to create eligible membership: $($_.Exception.Message)"
}
#endregion


$SetupSuccessful = $true # Assume success unless an exit occurred

#region Output Summary
if ($VerbosePreference -eq 'Continue') {

    Write-Host ""
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host "|             SCENARIO 6 SETUP COMPLETED (VERBOSE)             |" -ForegroundColor Cyan
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "`nSERVICE PRINCIPALS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host " - Legacy SP: $LegacyAutomationAppName" -ForegroundColor Cyan
    Write-Host " - Data Sync SP: $DataSyncAppName" -ForegroundColor Cyan
    Write-Host " - Auth Policy SP: $AuthPolicyAdminAppName" -ForegroundColor Cyan

    Write-Host "`nGROUPS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host " - Auth Policy Group: $AuthPolicyGroupName" -ForegroundColor Cyan
    Write-Host " - AI Operations Group: $AIAdminGroupName" -ForegroundColor Cyan

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
        Write-Host "Objective: Sign in as the admin user and retrieve the flag." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Hint: That dusty old automation secret? Forgotten by devs, remembered by the backend." -ForegroundColor DarkGray

    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 6 setup did not complete successfully. Please check verbose output or previous errors." -ForegroundColor White
    }
}
Write-Host ""
#endregion