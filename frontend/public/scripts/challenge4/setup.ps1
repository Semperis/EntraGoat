<#
.SYNOPSIS
EntraGoat New PIM Scenario: Eligible Group Ownership Privilege Escalation
Setup script to be run with Global Administrator privileges #>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration Variables
$AppAdminGroupName = "Application Operations Team"  
$PrivAuthGroupName = "Authentication Management Team"   
$TargetAppName = "Infrastructure Monitoring Tool"   
$Flag = "EntraGoat{PIM_Gr0up_Pr1v_Esc@l@t10n_2025!}"
$AdminPassword = "SecureP@ssw0rd#2025!"
$LowPrivPassword = "UserAccess!456"
$DelayShort = 8
$DelayLong = 15

Write-Host "`n" -NoNewline
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "           ENTRAGOAT NEW PIM SCENARIO 4 - INITIALIZATION          " -ForegroundColor Cyan
Write-Host "                  Eligible Ownership Chain                      " -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""

#region Module Verification and Import
Write-Verbose "[*] Verifying and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications", 
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.Governance"
)

$MissingModules = @()
foreach ($module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $MissingModules += $module
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Warning "Missing required modules: $($MissingModules -join ', ')"
    $installChoice = Read-Host "Install missing modules from PowerShell Gallery? (Y/N)"
    if ($installChoice -eq 'Y') {
        try {
            Write-Host "Installing modules: $($MissingModules -join ', ')..." -ForegroundColor Yellow
            Install-Module -Name $MissingModules -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Verbose "[+] Module installation completed"
            foreach ($module in $MissingModules) {
                Import-Module $module -ErrorAction Stop
                Write-Verbose "   ->  Imported $module"
            }
        } catch {
            Write-Host "[-] Module installation failed: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[-] Required modules missing. Please install and re-run." -ForegroundColor Red
        exit 1
    }
} else {
    foreach ($module in $RequiredModules) {
        if (-not (Get-Module -Name $module)) {
            try {
                Import-Module $module -ErrorAction Stop
                Write-Verbose "[+] Imported $module"
            } catch {
                Write-Host "[-] Failed to import $module`: $($_.Exception.Message)" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Verbose "[*] $module already loaded"
        }
    }
}
Write-Verbose "[+] All required modules are available"
#endregion

#region Microsoft Graph Connection
Write-Verbose "[*] Establishing Microsoft Graph connection..."

# Enhanced scopes including PIM group management
$GraphScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All", 
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "PrivilegedAccess.ReadWrite.AzureADGroup"
)

# Try connection with all scopes
try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $GraphScopes -TenantId $TenantId -NoWelcome -ErrorAction Stop
    } else {
        Connect-MgGraph -Scopes $GraphScopes -NoWelcome -ErrorAction Stop
    }
    
    # Test the connection
    $Context = Get-MgContext -ErrorAction Stop
    $OrgInfo = Get-MgOrganization -ErrorAction Stop
    
    $TenantDomain = ($OrgInfo.VerifiedDomains | Where-Object IsDefault).Name
    $CurrentTenantId = $OrgInfo.Id
    Write-Verbose "[+] Connected to tenant: $TenantDomain ($CurrentTenantId)"
    Write-Verbose "    ->  Connected with $($GraphScopes.Count) scopes"
    
} catch {
    Write-Host "[-] Microsoft Graph connection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
    Write-Host " Check your internet connection" -ForegroundColor Yellow
    Write-Host " Try running Connect-MgGraph manually first" -ForegroundColor Yellow
    Write-Host " Ensure you have sufficient permissions" -ForegroundColor Yellow
    Write-Host " Try running as Administrator" -ForegroundColor Yellow
    exit 1
}

# Verify we have the required scopes
$CurrentScopes = (Get-MgContext).Scopes
$HasPIMScopes = $CurrentScopes -contains "PrivilegedAccess.ReadWrite.AzureADGroup"

if (-not $HasPIMScopes) {
    Write-Warning "PIM group scopes not available - some PIM features may not work"
    Write-Verbose "    ->  Current scopes: $(($CurrentScopes | Sort-Object) -join ', ')"
}
#endregion

#region User Account Creation
Write-Verbose "[*] Creating user accounts..."
$LowPrivUPN = "woody@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s4@$TenantDomain"

# Create or get low-privileged user
Write-Verbose "    ->  Creating low-privilege user: $LowPrivUPN"
$ExistingLowPrivUser = Get-MgUser -Filter "userPrincipalName eq '$LowPrivUPN'" -ErrorAction SilentlyContinue
if ($ExistingLowPrivUser) {
    $LowPrivUser = $ExistingLowPrivUser
    Write-Verbose "      User exists, updating password"
    try {
        $passwordUpdate = @{
            Password = $LowPrivPassword
            ForceChangePasswordNextSignIn = $false
        }
        Update-MgUser -UserId $LowPrivUser.Id -PasswordProfile $passwordUpdate -ErrorAction Stop
        Write-Verbose "      Password updated successfully"
    } catch {
        Write-Verbose "      Password update failed (continuing): $($_.Exception.Message)"
    }
} else {
    $LowPrivUserParams = @{
        DisplayName = "Woody"
        UserPrincipalName = $LowPrivUPN
        MailNickname = "woody.chen"
        AccountEnabled = $true
        Department = "IT Support"
        JobTitle = "IT Support Specialist"
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $LowPrivPassword
        }
    }
    try {
        $LowPrivUser = New-MgUser @LowPrivUserParams -ErrorAction Stop
        Write-Verbose "User created successfully"
        Start-Sleep -Seconds $DelayShort
    } catch {
        Write-Host "[-] Failed to create low-privilege user: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Create admin target user
Write-Verbose "Creating admin target user: $AdminUPN"
$ExistingAdminUser = Get-MgUser -Filter "userPrincipalName eq '$AdminUPN'" -ErrorAction SilentlyContinue
if ($ExistingAdminUser) {
    $AdminUser = $ExistingAdminUser
    Write-Verbose "User exists, updating password"
    $passwordUpdate = @{
        Password = $AdminPassword
        ForceChangePasswordNextSignIn = $false
    }
    Update-MgUser -UserId $AdminUser.Id -PasswordProfile $passwordUpdate
} else {
    $AdminUserParams = @{
        DisplayName = "EntraGoat Administrator S4"
        UserPrincipalName = $AdminUPN
        MailNickname = "entragoat-admin-s4"
        AccountEnabled = $true
        Department = "IT Administration"
        JobTitle = "Global Administrator"
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $AdminPassword
        }
    }
    $AdminUser = New-MgUser @AdminUserParams
    Write-Verbose "User created successfully"
    Start-Sleep -Seconds $DelayShort
}
#endregion

#region Flag Storage
Write-Verbose "[*] Storing flag in admin user extension attributes..."
try {
    $ExtensionParams = @{
        OnPremisesExtensionAttributes = @{
            ExtensionAttribute1 = $Flag
        }
    }
    Update-MgUser -UserId $AdminUser.Id -BodyParameter $ExtensionParams -ErrorAction Stop
    Write-Verbose "Flag stored in extensionAttribute1"
} catch {
    Write-Verbose "Flag storage error (continuing): $($_.Exception.Message)"
}
#endregion

#region Global Administrator Role Assignment
Write-Verbose "[*] Assigning Global Administrator role to target admin..."
$GlobalAdminRoleTemplateId = "62e90394-69f5-4237-9190-012177145e10"
$GlobalAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GlobalAdminRoleTemplateId'" -ErrorAction SilentlyContinue

if (-not $GlobalAdminRole) {
    Write-Verbose "Activating Global Administrator role template"
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $GlobalAdminRoleTemplateId
    $GlobalAdminRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $DelayShort
}

$ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id -All -ErrorAction SilentlyContinue
$IsGlobalAdmin = $false
if ($ExistingMembers) {
    foreach ($member in $ExistingMembers) {
        if ($member.Id -eq $AdminUser.Id) {
            $IsGlobalAdmin = $true
            break
        }
    }
}

if (-not $IsGlobalAdmin) {
    Write-Verbose "Assigning Global Administrator role"
    try {
        $RoleMemberRef = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($AdminUser.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $GlobalAdminRole.Id -BodyParameter $RoleMemberRef -ErrorAction Stop
        Write-Verbose "Global Administrator role assigned"
        Start-Sleep -Seconds $DelayLong
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "Role already assigned"
        } else {
            Write-Host "[-] Global Administrator assignment failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Verbose "User already has Global Administrator role"
}
#endregion

#region Application Administrator Group Creation
Write-Verbose "[*] Creating Application Administrator group..."
$ExistingAppGroup = Get-MgGroup -Filter "displayName eq '$AppAdminGroupName'" -ErrorAction SilentlyContinue

if ($ExistingAppGroup) {
    $AppAdminGroup = $ExistingAppGroup
    Write-Verbose "    ->  Group exists: $AppAdminGroupName"
} else {
    $AppGroupParams = @{
        DisplayName = $AppAdminGroupName
        Description = "Group with eligible Application Administrator role for testing"
        MailEnabled = $false
        MailNickname = "test-group-name-4"
        SecurityEnabled = $true
        IsAssignableToRole = $true  # CRITICAL: This must be true for directory role assignments
    }
    $AppAdminGroup = New-MgGroup @AppGroupParams
    Write-Verbose "Group created: $AppAdminGroupName"
    Start-Sleep -Seconds $DelayShort
}

# Verify group is role-assignable
Write-Verbose "[*] Verifying group configuration..."
try {
    $VerifyGroup = Get-MgGroup -GroupId $AppAdminGroup.Id -ErrorAction Stop
    Write-Verbose "[OK] Group found: $($VerifyGroup.DisplayName) (ID: $($VerifyGroup.Id))"
    Write-Verbose "Group IsAssignableToRole: $($VerifyGroup.IsAssignableToRole)"
    
    if (-not $VerifyGroup.IsAssignableToRole) {
        Write-Host "[!] WARNING: Group is not assignable to roles - fixing..." -ForegroundColor Yellow
        try {
            Update-MgGroup -GroupId $AppAdminGroup.Id -IsAssignableToRole:$true -ErrorAction Stop
            Write-Verbose "[OK] Group updated to be role-assignable"
            Start-Sleep -Seconds $DelayLong
        } catch {
            Write-Host " [!] Failed to update group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "[[ERROR]] Group verification failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Create ELIGIBLE Application Administrator role assignment
Write-Verbose "[*] Creating eligible Application Administrator role assignment..."
$AppAdminRoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"

$ExistingEligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($AppAdminGroup.Id)' and roleDefinitionId eq '$AppAdminRoleId'" -ErrorAction SilentlyContinue

if (-not $ExistingEligible) {
    try {
        Write-Verbose "    ->  Creating eligible role assignment for group..."
        $EligibilityRequestParams = @{
            Action = "adminAssign"
            PrincipalId = $AppAdminGroup.Id
            RoleDefinitionId = $AppAdminRoleId
            DirectoryScopeId = "/"
            Justification = "EntraGoat PIM scenario - eligible role assignment"
            ScheduleInfo = @{
                StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                Expiration = @{
                    Type = "noExpiration"
                }
            }
        }
        
        $EligibleRoleResult = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $EligibilityRequestParams -ErrorAction Stop
        Write-Verbose "[OK] Eligible Application Administrator role created successfully"
        Write-Verbose "Request ID: $($EligibleRoleResult.Id)"
        Start-Sleep -Seconds $DelayLong
        
    } catch {
        Write-Host "[!] Eligible role assignment failed: $($_.Exception.Message)" -ForegroundColor Red
        
        # Fallback to active assignment
        Write-Verbose "Attempting fallback: Creating ACTIVE role assignment..."
        try {
            $AppAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$AppAdminRoleId'" -ErrorAction SilentlyContinue
            if (-not $AppAdminRole) {
                Write-Verbose " Activating Application Administrator role template"
                $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $AppAdminRoleId
                $AppAdminRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
                Start-Sleep -Seconds $DelayShort
            }
            
            $RoleMemberRef = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($AppAdminGroup.Id)" }
            New-MgDirectoryRoleMemberByRef -DirectoryRoleId $AppAdminRole.Id -BodyParameter $RoleMemberRef -ErrorAction Stop
            Write-Verbose "[OK] Fallback: Active Application Administrator role assigned"
            Start-Sleep -Seconds $DelayLong
            
        } catch {
            Write-Host "[!] Both eligible and active role assignments failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Verbose "Eligible Application Administrator role already exists"
}
#endregion

#region Target Application and Service Principal
Write-Verbose "[*] Creating target application and service principal..."
$ExistingApp = Get-MgApplication -Filter "displayName eq '$TargetAppName'" -ErrorAction SilentlyContinue

if ($ExistingApp) {
    $TargetApp = $ExistingApp
    Write-Verbose "Application exists: $TargetAppName"
} else {
    $AppParams = @{
        DisplayName = $TargetAppName
        SignInAudience = "AzureADMyOrg"
        Description = "Target application for privilege escalation scenario"
        Web = @{
            RedirectUris = @("https://target-app-4.example.com/callback")
        }
    }
    $TargetApp = New-MgApplication @AppParams
    Write-Verbose "Application created: $TargetAppName"
    Start-Sleep -Seconds $DelayShort
}

$TargetAppId = $TargetApp.AppId
if ($TargetAppId -is [array]) { $TargetAppId = $TargetAppId[0] }
$TargetAppId = $TargetAppId.ToString()

# Create corresponding service principal
Write-Verbose "[*] Creating service principal..."
$ExistingSP = Get-MgServicePrincipal -Filter "appId eq '$TargetAppId'" -ErrorAction SilentlyContinue

if ($ExistingSP) {
    $TargetSP = $ExistingSP
    Write-Verbose " Service principal exists"
} else {
    $SPParams = @{
        AppId = $TargetAppId
        DisplayName = $TargetAppName
    }
    $TargetSP = New-MgServicePrincipal @SPParams
    Write-Verbose "Service principal created"
    Start-Sleep -Seconds $DelayShort
}

# Configure for portal visibility
$SPTags = @("WindowsAzureActiveDirectoryIntegratedApp")
Update-MgServicePrincipal -ServicePrincipalId $TargetSP.Id -Tags $SPTags

# Grant Directory.Read.All permission
Write-Verbose "[*] Granting Directory.Read.All permission..."
$GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$DirectoryReadRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "Directory.Read.All" }

$ExistingPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -All -ErrorAction SilentlyContinue
$HasDirectoryRead = $ExistingPermissions | Where-Object { $_.AppRoleId -eq $DirectoryReadRole.Id }

if (-not $HasDirectoryRead) {
    $PermissionParams = @{
        PrincipalId = $TargetSP.Id
        ResourceId = $GraphSP.Id
        AppRoleId = $DirectoryReadRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -BodyParameter $PermissionParams | Out-Null
    Write-Verbose "    ->  Directory.Read.All permission granted"
    Start-Sleep -Seconds $DelayShort
}
#endregion

#region Privileged Authentication Administrator Group
Write-Verbose "[*] Creating Privileged Authentication Administrator group..."
$ExistingPrivGroup = Get-MgGroup -Filter "displayName eq '$PrivAuthGroupName'" -ErrorAction SilentlyContinue

if ($ExistingPrivGroup) {
    $PrivAuthGroup = $ExistingPrivGroup
    Write-Verbose "    ->  Group exists: $PrivAuthGroupName"
} else {
    $PrivGroupParams = @{
        DisplayName = $PrivAuthGroupName
        Description = "Group with Privileged Authentication Administrator privileges"
        MailEnabled = $false
        MailNickname = "priv-test-group-name-4"
        SecurityEnabled = $true
        IsAssignableToRole = $true
    }
    $PrivAuthGroup = New-MgGroup @PrivGroupParams
    Write-Verbose "    ->  Group created: $PrivAuthGroupName"
    Start-Sleep -Seconds $DelayShort
}

# Assign Privileged Authentication Administrator role (active assignment)
Write-Verbose "[*] Assigning Privileged Authentication Administrator role..."
$PrivAuthRoleId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"

$PrivAuthRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$PrivAuthRoleId'" -ErrorAction SilentlyContinue
if (-not $PrivAuthRole) {
    Write-Verbose "    ->  Activating Privileged Authentication Administrator role template"
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $PrivAuthRoleId
    $PrivAuthRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $DelayShort
}

$ExistingRoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $PrivAuthRole.Id -All -ErrorAction SilentlyContinue
$GroupHasRole = $false
if ($ExistingRoleMembers) {
    foreach ($member in $ExistingRoleMembers) {
        if ($member.Id -eq $PrivAuthGroup.Id) {
            $GroupHasRole = $true
            break
        }
    }
}

if (-not $GroupHasRole) {
    try {
        $RoleRef = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($PrivAuthGroup.Id)"
        }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $PrivAuthRole.Id -BodyParameter $RoleRef -ErrorAction Stop
        Write-Verbose "    ->  Privileged Authentication Administrator role assigned"
        Start-Sleep -Seconds $DelayLong
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "Role already assigned"
        } else {
            Write-Verbose "Role assignment failed: $($_.Exception.Message)"
        }
    }
} else {
    Write-Verbose "Group already has Privileged Authentication Administrator role"
}

# Add service principal to privileged group
Write-Verbose "[*] Adding service principal to privileged auth group..."
$GroupMembers = (Invoke-MgGraphRequest -Uri "/beta/groups/$($PrivAuthGroup.Id)/members" -Method GET).value
$SPIsMember = $false

if ($GroupMembers) {
    $SPIsMember = $GroupMembers | Where-Object { $_.Id -eq $TargetSP.Id }
}

if ($SPIsMember) {
    Write-Verbose "Service principal already member"
} else {
    $MemberRef = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/servicePrincipals/$($TargetSP.Id)"
    }
    try {
        New-MgGroupMemberByRef -GroupId $PrivAuthGroup.Id -BodyParameter $MemberRef -ErrorAction Stop
        Write-Verbose "Service principal added to group"
        Write-Verbose "Waiting for membership propagation..."
        Start-Sleep -Seconds $DelayLong
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "Service principal already member"
            $SPIsMember = $true
        } else {
            Write-Verbose "    ->  Failed to add service principal: $($_.Exception.Message)"
        }
    }
}
#endregion

#region Realistic Environment Users
Write-Verbose "[*] Creating realistic environment users..."

$RealisticUsers = @(
    @{
        DisplayName = "Sarah Martinez"
        UserPrincipalName = "sarah.martinez@$TenantDomain"
        MailNickname = "sarah.martinez"
        Department = "IT Security"
        JobTitle = "Security Analyst"
    },
    @{
        DisplayName = "David Kim"
        UserPrincipalName = "david.kim@$TenantDomain"
        MailNickname = "david.kim"
        Department = "Application Development"
        JobTitle = "Senior Developer"
    },
    @{
        DisplayName = "Jennifer Walsh"
        UserPrincipalName = "jennifer.walsh@$TenantDomain"
        MailNickname = "jennifer.walsh"
        Department = "Identity Management"
        JobTitle = "Identity Specialist"
    }
)

$CreatedUsers = @()
foreach ($user in $RealisticUsers) {
    $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($user.UserPrincipalName)'" -ErrorAction SilentlyContinue
    if (-not $existingUser) {
        $userParams = $user + @{
            AccountEnabled = $true
            PasswordProfile = @{
                ForceChangePasswordNextSignIn = $false
                Password = "EnvP@ssw0rd$(Get-Random -Maximum 999)"
            }
        }
        $newUser = New-MgUser @userParams
        $CreatedUsers += $newUser
        Write-Verbose "Created: $($user.DisplayName)"
    } else {
        $CreatedUsers += $existingUser
        Write-Verbose "Exists: $($user.DisplayName)"
    }
}

# Add some users to groups for realism
Write-Verbose "[*] Adding users to groups for realistic environment..."
$UsersToAddToAppGroup = @($CreatedUsers[0], $CreatedUsers[1])  # Sarah and David
foreach ($user in $UsersToAddToAppGroup) {
    $CurrentMembers = Get-MgGroupMember -GroupId $AppAdminGroup.Id -All -ErrorAction SilentlyContinue
    $IsExistingMember = $CurrentMembers | Where-Object { $_.Id -eq $user.Id }
    
    if (-not $IsExistingMember) {
        $MemberRef = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($user.Id)"
        }
        try {
            New-MgGroupMemberByRef -GroupId $AppAdminGroup.Id -BodyParameter $MemberRef
            Write-Verbose "Added $($user.DisplayName) to $AppAdminGroupName"
        } catch {
            Write-Verbose "$($user.DisplayName) already in group"
        }
    }
}

# Add Jennifer to privileged auth group
$CurrentPrivMembers = Get-MgGroupMember -GroupId $PrivAuthGroup.Id -All -ErrorAction SilentlyContinue
$JenniferIsMember = $CurrentPrivMembers | Where-Object { $_.Id -eq $CreatedUsers[2].Id }

if (-not $JenniferIsMember) {
    $MemberRef = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($CreatedUsers[2].Id)"
    }
    try {
        New-MgGroupMemberByRef -GroupId $PrivAuthGroup.Id -BodyParameter $MemberRef
        Write-Verbose "Added Jennifer Walsh to $PrivAuthGroupName"
    } catch {
        Write-Verbose "Jennifer Walsh already in group"
    }
}

Start-Sleep -Seconds $DelayShort
#endregion

#region Create Eligible Group Ownership (THE VULNERABILITY)
Write-Verbose "[!] CREATING VULNERABILITY: Creating eligible group ownership..."

# Make the low-privileged user eligible owner of the Application Administrator group
Write-Verbose "Creating eligible ownership for '$LowPrivUPN' on '$AppAdminGroupName'..."

$eligibleOwnerParams = @{
    accessId          = "owner"
    principalId       = $LowPrivUser.Id
    groupId           = $AppAdminGroup.Id
    action            = "adminAssign"
    scheduleInfo      = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{
            type = "afterDuration"
            duration = "P365D"  
        }
    }
    justification     = "Regional access coordination administrative privileges"
}

try {
    $ownershipResponse = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
        -Body ($eligibleOwnerParams | ConvertTo-Json -Depth 4) -ContentType "application/json"
    Write-Verbose "[OK] Eligible ownership granted (vulnerability created)"
    Write-Verbose "Assignment ID: $($ownershipResponse.id)"
    Write-Verbose "User '$LowPrivUPN' now has ELIGIBLE ownership of '$AppAdminGroupName'"
    $EligibleOwnershipCreated = $true
    Start-Sleep -Seconds $DelayLong
} catch {
    Write-Verbose "[ERROR] Failed to create eligible ownership: $($_.Exception.Message)"
    Write-Verbose "Attempting fallback: Direct ownership assignment..."
    
    # Fallback to direct ownership if PIM fails
    try {
        $ExistingOwners = Get-MgGroupOwner -GroupId $AppAdminGroup.Id
        $IsDirectOwner = $false
        if ($ExistingOwners) {
            foreach ($owner in $ExistingOwners) {
                if ($owner.Id -eq $LowPrivUser.Id) {
                    $IsDirectOwner = $true
                    break
                }
            }
        }

        if (-not $IsDirectOwner) {
            $OwnerRef = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($LowPrivUser.Id)"
            }
            New-MgGroupOwnerByRef -GroupId $AppAdminGroup.Id -BodyParameter $OwnerRef
            Write-Verbose "[OK] Direct group ownership assigned (fallback vulnerability created)"
            $EligibleOwnershipCreated = $false
            $DirectOwnershipCreated = $true
            Start-Sleep -Seconds $DelayShort
        } else {
            Write-Verbose "Direct group ownership already exists"
            $EligibleOwnershipCreated = $false
            $DirectOwnershipCreated = $true
        }
    } catch {
        Write-Verbose "Both eligible and direct ownership failed: $($_.Exception.Message)"
        $EligibleOwnershipCreated = $false
        $DirectOwnershipCreated = $false
    }
}

if (-not $EligibleOwnershipCreated -and -not $DirectOwnershipCreated) {
    $EligibleOwnershipCreated = $false
    $DirectOwnershipCreated = $false
}
#endregion

#region Final Verification
Write-Verbose "[*] Performing final verification checks..."

# Verify ownership (either eligible or direct)
$Owners = Get-MgGroupOwner -GroupId $AppAdminGroup.Id
$DirectOwnershipVerified = $false
foreach ($owner in $Owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $DirectOwnershipVerified = $true
        break
    }
}

# Check for PIM eligible group ownership
$PIMEligibleOwnership = $false
try {
    $EligibleOwnershipUri = "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($AppAdminGroup.Id)' and principalId eq '$($LowPrivUser.Id)' and accessId eq 'owner'"
    $EligibleResponse = Invoke-MgGraphRequest -Uri $EligibleOwnershipUri -Method GET
    
    if ($EligibleResponse.value -and $EligibleResponse.value.Count -gt 0) {
        $PIMEligibleOwnership = $true
        Write-Verbose "[OK] PIM eligible group ownership found"
    }
} catch {
    Write-Verbose "PIM ownership check failed: $($_.Exception.Message)"
}

# Overall ownership verification
$OwnershipVerified = $PIMEligibleOwnership -or $DirectOwnershipVerified

if ($PIMEligibleOwnership) {
    Write-Verbose "[OK] PIM eligible group ownership verified"
} elseif ($DirectOwnershipVerified) {
    Write-Verbose "[OK] Direct group ownership verified (fallback)"
} else {
    Write-Verbose "[[ERROR]] No group ownership found"
}

# Verify eligible role assignment
$EligibleRole = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($AppAdminGroup.Id)' and roleDefinitionId eq '$AppAdminRoleId'" -ErrorAction SilentlyContinue
$EligibleRoleVerified = $EligibleRole -ne $null

# Also check for active role assignment if eligible failed
$ActiveRoleVerified = $false
if (-not $EligibleRoleVerified) {
    try {
        $AppAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$AppAdminRoleId'" -ErrorAction SilentlyContinue
        if ($AppAdminRole) {
            $ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $AppAdminRole.Id -All -ErrorAction SilentlyContinue
            if ($ExistingMembers) {
                foreach ($member in $ExistingMembers) {
                    if ($member.Id -eq $AppAdminGroup.Id) {
                        $ActiveRoleVerified = $true
                        break
                    }
                }
            }
        }
    } catch {
        Write-Verbose "Active role verification failed: $($_.Exception.Message)"
    }
}

$RoleAssignmentVerified = $EligibleRoleVerified -or $ActiveRoleVerified

if ($EligibleRoleVerified) {
    Write-Verbose "[OK] Eligible Application Administrator role verified"
} elseif ($ActiveRoleVerified) {
    Write-Verbose "[OK] Active Application Administrator role verified (fallback)"
} else {
    Write-Verbose "[[ERROR]] Application Administrator role verification failed"
}

# Verify service principal membership
$PrivGroupMembers = Get-MgGroupMember -GroupId $PrivAuthGroup.Id -All -ErrorAction SilentlyContinue
$SPMembershipVerified = $false
if ($PrivGroupMembers) {
    foreach ($member in $PrivGroupMembers) {
        if ($member.Id -eq $TargetSP.Id) {
            $SPMembershipVerified = $true
            break
        }
    }
}

if ($SPMembershipVerified) {
    Write-Verbose "[OK] Service principal membership verified"
} else {
    Write-Verbose "[[ERROR]] Service principal membership verification failed"
}

$OverallSuccess = $OwnershipVerified -and $RoleAssignmentVerified
#endregion

#region Output Summary
if ($VerbosePreference -eq 'Continue') {
    Write-Host "`n" -NoNewline
    Write-Host "-----------------------------------------------------------" -ForegroundColor Green
    Write-Host "                   NEW PIM SCENARIO SETUP                  " -ForegroundColor Green
    Write-Host "-----------------------------------------------------------" -ForegroundColor Green

    Write-Host "`nPIM EXPLOITATION CHAIN:" -ForegroundColor Yellow
        Write-Host "Low-privileged user has ELIGIBLE ownership of group" -ForegroundColor Magenta
        Write-Host "Must activate ownership through PIM" -ForegroundColor Magenta
    } else {
        Write-Host "Low-privileged user owns Application Administrator group" -ForegroundColor White
    }
    Write-Host "Group has ELIGIBLE Application Administrator role" -ForegroundColor Magenta
    Write-Host "User can add themselves to group" -ForegroundColor White
    Write-Host "User can activate Application Administrator role via PIM" -ForegroundColor Magenta
    Write-Host "Service principal has Privileged Authentication Admin privileges" -ForegroundColor White
    Write-Host "Can compromise service principal and reset Global Admin password" -ForegroundColor White

    Write-Host "`nCONFIGURATION SUMMARY:" -ForegroundColor Yellow
    Write-Host "  App Admin Group: " -ForegroundColor White -NoNewline
    Write-Host "$AppAdminGroupName" -ForegroundColor Cyan
    Write-Host "  Group ID: " -ForegroundColor White -NoNewline
    Write-Host "$($AppAdminGroup.Id)" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Priv Auth Group: " -ForegroundColor White -NoNewline
    Write-Host "$PrivAuthGroupName" -ForegroundColor Cyan
    Write-Host "  Group ID: " -ForegroundColor White -NoNewline
    Write-Host "$($PrivAuthGroup.Id)" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Target SP: " -ForegroundColor White -NoNewline
    Write-Host "$TargetAppName" -ForegroundColor Cyan
    Write-Host "  SP ID: " -ForegroundColor White -NoNewline
    Write-Host "$($TargetSP.Id)" -ForegroundColor DarkCyan

    Write-Host "`nPIM STATUS:" -ForegroundColor Yellow
    if ($PIMEligibleOwnership) {
        Write-Host "Eligible Ownership: " -ForegroundColor White -NoNewline
        Write-Host "CONFIGURED [OK]" -ForegroundColor Green
    } elseif ($DirectOwnershipVerified) {
        Write-Host " Ownership Type: " -ForegroundColor White -NoNewline
        Write-Host "DIRECT (Fallback)" -ForegroundColor Yellow
    } else {
        Write-Host "Ownership Status: " -ForegroundColor White -NoNewline
        Write-Host "NOT CONFIGURED [ERROR]" -ForegroundColor Red
    }

    Write-Host "`nFLAG LOCATION:" -ForegroundColor Green
    Write-Host "  Flag: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan
    Write-Host "  Target: " -ForegroundColor White -NoNewline
    Write-Host "$AdminUPN" -ForegroundColor Cyan -NoNewline
    Write-Host " ->  extensionAttribute1" -ForegroundColor DarkCyan
    Write-Host ""
   
   
    # Minimal output for CTF participants
    Write-Host "`n" -NoNewline
    if ($OverallSuccess) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "New PIM scenario setup completed successfully" -ForegroundColor White
        Write-Host ""
        Write-Host "Objective: Use PIM and group ownership to escalate privileges and retrieve the flag." -ForegroundColor Gray
        Write-Host ""
        Write-Host "`nYOUR CREDENTIALS:" -ForegroundColor Red
        Write-Host "----------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Username: " -ForegroundColor White -NoNewline
        Write-Host "$LowPrivUPN" -ForegroundColor Cyan
        Write-Host "  Password: " -ForegroundColor White -NoNewline
        Write-Host "$LowPrivPassword" -ForegroundColor Cyan

        Write-Host "`nTARGET INFORMATION:" -ForegroundColor Magenta
        Write-Host "----------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Username: " -ForegroundColor White -NoNewline
        Write-Host "$AdminUPN" -ForegroundColor Cyan
        Write-Host "  Flag Location: " -ForegroundColor White -NoNewline
        Write-Host "extensionAttribute1" -ForegroundColor Cyan
        
        Write-Host "`nPIM CONFIGURATION:" -ForegroundColor Yellow
        Write-Host "----------------------------------------------" -ForegroundColor DarkGray
        
        if ($PIMEligibleOwnership) {
            Write-Host "  Eligible Owner: " -ForegroundColor Magenta -NoNewline
            Write-Host "$LowPrivUPN" -ForegroundColor Cyan
        } elseif ($DirectOwnershipVerified) {
            Write-Host "  Direct Owner: " -ForegroundColor White -NoNewline
            Write-Host "$LowPrivUPN" -ForegroundColor Cyan -NoNewline
            Write-Host " (fallback)" -ForegroundColor Yellow
        }
        
        if ($EligibleRoleVerified) {
            Write-Host "  Eligible Role: " -ForegroundColor Magenta -NoNewline
            Write-Host "Application Administrator" -ForegroundColor Cyan
        } elseif ($ActiveRoleVerified) {
            Write-Host "  Active Role: " -ForegroundColor White -NoNewline
            Write-Host "Application Administrator" -ForegroundColor Cyan -NoNewline
            Write-Host " (fallback)" -ForegroundColor Yellow
        }
        Write-Host ""
        if ($PIMEligibleOwnership -and $EligibleRoleVerified) {
            Write-Host "Perfect! Full PIM setup successful. You'll need to:" -ForegroundColor DarkGray
            Write-Host "   1. Activate your eligible ownership via PIM" -ForegroundColor DarkGray
            Write-Host "   2. Add yourself to the group" -ForegroundColor DarkGray  
            Write-Host "   3. Activate the group's Application Administrator role via PIM" -ForegroundColor DarkGray
            Write-Host "   4. Find service principals to escalate further" -ForegroundColor DarkGray
        } elseif ($PIMEligibleOwnership) {
            Write-Host "PIM ownership configured. You have eligible ownership:" -ForegroundColor DarkGray
            Write-Host "   1. Activate your eligible ownership via PIM" -ForegroundColor DarkGray
            Write-Host "   2. Add yourself to the group" -ForegroundColor DarkGray  
            Write-Host "   3. Use the group's Application Administrator privileges" -ForegroundColor DarkGray
            Write-Host "   4. Find service principals to escalate further" -ForegroundColor DarkGray
        } elseif ($DirectOwnershipVerified -and $EligibleRoleVerified) {
            Write-Host "Mixed setup: Direct ownership + Eligible role. You can:" -ForegroundColor DarkGray
            Write-Host "   1. Add yourself to the group (you're the owner)" -ForegroundColor DarkGray
            Write-Host "   2. Activate the Application Administrator role via PIM" -ForegroundColor DarkGray
            Write-Host "   3. Find service principals to escalate further" -ForegroundColor DarkGray
        } elseif ($DirectOwnershipVerified) {
            Write-Host "Direct ownership setup: You own the group directly." -ForegroundColor DarkGray
            Write-Host "   Add yourself to the group and use its privileges!" -ForegroundColor DarkGray
            Write-Host "   The path to Global Admin involves service principals..." -ForegroundColor DarkGray
        } else {
            Write-Host " Warning: Setup may be incomplete. Check the verbose output." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "New PIM scenario setup failed. Run with -Verbose for detailed debugging." -ForegroundColor White
    }
    Write-Host ""


# Cleanup - disconnect from Graph
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
} catch {
    # Ignore cleanup errors
}

Write-Host "Setup complete. Time to exploit some PIM configurations!" -ForegroundColor Green
Write-Host ""
#endregion

# End of script