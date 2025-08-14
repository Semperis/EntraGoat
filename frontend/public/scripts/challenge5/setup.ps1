<#

.SYNOPSIS
EntraGoat Scenario 5: Department of Escalations - AU Ready for This?
Setup script to be run with Global Administrator privileges 

#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups, Microsoft.Graph.DeviceManagement.Administration

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$CustomRoleName = "User Profile Administrator"
$SupportGroupName = "Tier-1 Support Team"
$PrivilegedGroupName = "Regional Access Coordinators"
$AUName = "HR Department"
$Flag = "EntraGoat{Dyn@m1c_AU_P01s0n1ng_FTW!}"
$SupportPassword = "GoatAccess!123"
$AdminPassword = "ComplexAdminP@ssw0rd#2025!"
$standardDelay = 10 
$longReplicationDelay = 20 

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 5 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|        Department of Escalations - AU Ready for This?        |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

$HRUsers = @(
    @{ DisplayName = "Jessica Chen"; UPN = "jessica.chen"; Department = "HR"; JobTitle = "Senior Analyst" }
    @{ DisplayName = "Michael Rodriguez"; UPN = "michael.rodriguez"; Department = "HR"; JobTitle = "Budget Manager" }
    @{ DisplayName = "Amanda Thompson"; UPN = "amanda.thompson"; Department = "HR"; JobTitle = "Accounting Specialist" }
)

$RegionalUsers = @(
    @{ DisplayName = "David Wilson"; UPN = "david.wilson"; Department = "IT Operations"; JobTitle = "Regional IT Coordinator" }
    @{ DisplayName = "Lisa Park"; UPN = "lisa.park"; Department = "Security"; JobTitle = "Identity Access Manager" }
)

#region Module Check and Import
Write-Verbose "[*] Checking and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.DeviceManagement.Administration"
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
#endregion Module Check and Import

#region Authentication
Write-Verbose "[*] Connecting to Microsoft Graph..."
$GraphScopes = @(
    "RoleManagement.ReadWrite.Directory",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Group.ReadWrite.All",
    "AdministrativeUnit.ReadWrite.All",
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
$SupportUPN = "sarah.connor@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s5@$TenantDomain"

# Create or get support user
Write-Verbose "    -> Support user: $SupportUPN"
$ExistingSupportUser = Get-MgUser -Filter "userPrincipalName eq '$SupportUPN'" -ErrorAction SilentlyContinue
if ($ExistingSupportUser) {
    $SupportUser = $ExistingSupportUser
    Write-Verbose "      EXISTS (using existing)"
    # Update password to ensure we know it
    $passwordProfile = @{
        Password = $SupportPassword
        ForceChangePasswordNextSignIn = $false
    }
    Update-MgUser -UserId $SupportUser.Id -PasswordProfile $passwordProfile
} else {
    $SupportUserParams = @{
        DisplayName = "Sarah Connor"
        UserPrincipalName = $SupportUPN
        MailNickname = "sarah.connor"
        AccountEnabled = $true
        Department = "IT Support"
        JobTitle = "Service Desk Analyst"
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $SupportPassword
        }
    }
    $SupportUser = New-MgUser @SupportUserParams
    Write-Verbose "      CREATED"
    Start-Sleep -Seconds $standardDelay
}

# Create dummy HR users (will be added to AU via dynamic membership)
Write-Verbose "    -> Creating HR department users..."
$HRUserObjects = @()
foreach ($userInfo in $HRUsers) {
    $userUPN = "$($userInfo.UPN)@$TenantDomain"
    $existingUser = Get-MgUser -Filter "userPrincipalName eq '$userUPN'" -ErrorAction SilentlyContinue
    
    if ($existingUser) {
        $HRUserObjects += $existingUser
        Write-Verbose "      $($userInfo.DisplayName) EXISTS"
    } else {
        $userParams = @{
            DisplayName = $userInfo.DisplayName
            UserPrincipalName = $userUPN
            MailNickname = $userInfo.UPN
            AccountEnabled = $true
            Department = $userInfo.Department
            JobTitle = $userInfo.JobTitle
            PasswordProfile = @{
                ForceChangePasswordNextSignIn = $false
                Password = "Finance@2025!"
            }
        }
        $newUser = New-MgUser @userParams
        $HRUserObjects += $newUser
        Write-Verbose "      $($userInfo.DisplayName) CREATED"
        Start-Sleep -Seconds $standardDelay
    }
}

# Create dummy Regional Access users
Write-Verbose "    -> Creating Regional Access users..."
$RegionalUserObjects = @()
foreach ($userInfo in $RegionalUsers) {
    $userUPN = "$($userInfo.UPN)@$TenantDomain"
    $existingUser = Get-MgUser -Filter "userPrincipalName eq '$userUPN'" -ErrorAction SilentlyContinue
    
    if ($existingUser) {
        $RegionalUserObjects += $existingUser
        Write-Verbose "      $($userInfo.DisplayName) EXISTS"
    } else {
        $userParams = @{
            DisplayName = $userInfo.DisplayName
            UserPrincipalName = $userUPN
            MailNickname = $userInfo.UPN
            AccountEnabled = $true
            Department = $userInfo.Department
            JobTitle = $userInfo.JobTitle
            PasswordProfile = @{
                ForceChangePasswordNextSignIn = $false
                Password = "Regional@2025!"
            }
        }
        $newUser = New-MgUser @userParams
        $RegionalUserObjects += $newUser
        Write-Verbose "      $($userInfo.DisplayName) CREATED"
        Start-Sleep -Seconds $standardDelay
    }
}

# Create or get GA user
Write-Verbose "    -> Global admin user: $AdminUPN"
$ExistingAdminUser = Get-MgUser -Filter "userPrincipalName eq '$AdminUPN'" -ErrorAction SilentlyContinue
if ($ExistingAdminUser) {
    $AdminUser = $ExistingAdminUser
    Write-Verbose "      EXISTS (using existing)"
    $passwordProfile = @{
        Password = $AdminPassword
        ForceChangePasswordNextSignIn = $false
    }
    Update-MgUser -UserId $AdminUser.Id -PasswordProfile $passwordProfile
} else {
    $AdminUserParams = @{
        DisplayName = "EntraGoat Administrator S5"
        UserPrincipalName = $AdminUPN
        MailNickname = "entragoat-admin-s5"
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
    Write-Verbose "    -> Flag stored successfully."
} catch {
    Write-Verbose "    -> Flag already set or minor error (continuing): $($_.Exception.Message)"
}
#endregion

#region Assign Global Administrator Role to Admin User
Write-Verbose "[*] Assigning Global Administrator role to admin user ($AdminUPN)..."
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
$DirectoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GlobalAdminRoleId'" -ErrorAction SilentlyContinue

if (-not $DirectoryRole) {
    Write-Verbose "    -> Activating Global Administrator role template..."
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
    Write-Verbose "    -> Assigning role to $($AdminUser.UserPrincipalName)..."
    try {
        $RoleMemberParams = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($AdminUser.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $DirectoryRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "    -> Role assigned successfully."
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "    -> Role was already assigned."
        } else {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to assign Global Admin role to admin user: $($_.Exception.Message)" -ForegroundColor White
        }
    }
} else {
    Write-Verbose "    -> Admin user already has Global Administrator role."
}
#endregion

#region Create Custom Role
Write-Verbose "[*] Creating custom role: $CustomRoleName"
$ExistingCustomRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$CustomRoleName'" -ErrorAction SilentlyContinue

if ($ExistingCustomRole) {
    $CustomRole = $ExistingCustomRole
    Write-Verbose "    -> Custom role exists: $CustomRoleName"
} else {
    $RolePermissions = @(
        @{
            # AllowedResourceActions = @(
            #     "microsoft.directory/devices/standard/read",
            #     "microsoft.directory/groups.security/basic/update",
            #     "microsoft.directory/groups/basic/update",
            #     "microsoft.directory/users/basic/update"
            # )
            AllowedResourceActions = @(
                "microsoft.directory/users/basic/update", 
                "microsoft.directory/users/standard/read",
                "microsoft.directory/groups/standard/read"
            )
        }
    )
    
    $CustomRoleParams = @{
        DisplayName = $CustomRoleName
        Description = "Allows updating basic user profile attributes for support staff"
        IsEnabled = $true
        RolePermissions = $RolePermissions
    }
    
    $CustomRole = New-MgRoleManagementDirectoryRoleDefinition -BodyParameter $CustomRoleParams
    Write-Verbose "    -> Custom role created: $CustomRoleName"
    Start-Sleep -Seconds $standardDelay
}
#endregion

#region Create Basic IT Admins Group
Write-Verbose "[*] Creating Basic IT Admins group..."
$ExistingGroup = Get-MgGroup -Filter "displayName eq '$SupportGroupName'" -ErrorAction SilentlyContinue

if ($ExistingGroup) {
    $BasicITGroup = $ExistingGroup
    Write-Verbose "    -> Group exists: $SupportGroupName"
} else {
    $GroupParams = @{
        DisplayName = $SupportGroupName
        Description = "Service desk team providing basic user and device support"
        MailEnabled = $false
        MailNickname = "it-service-desk"
        SecurityEnabled = $true
        IsAssignableToRole = $true
    }
    $SupportGroup = New-MgGroup @GroupParams
    Write-Verbose "    -> Group created: $SupportGroupName"
    Start-Sleep -Seconds $standardDelay
}

# Assign custom role to the support group
Write-Verbose "[*] Assigning custom role to Basic IT Admins group..."
# $ExistingRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($CustomRole.Id)'" -ExpandProperty "principal" -ErrorAction SilentlyContinue
$ExistingRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($SupportGroup.Id)' and roleDefinitionId eq '$($CustomRole.Id)'" -ErrorAction SilentlyContinue

if (-not $ExistingRoleAssignments) {
    try {
        $RoleAssignmentParams = @{
            PrincipalId = $SupportGroup.Id
            RoleDefinitionId = $CustomRole.Id
            DirectoryScopeId = "/"
        }
        New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $RoleAssignmentParams -ErrorAction Stop | Out-Null
        Write-Verbose "    -> Custom role assigned to group"
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "    -> Role already assigned"
        } else {
            Write-Verbose "    -> Failed to assign role: $($_.Exception.Message)"
        }
    }
} else {
    Write-Verbose "    -> Group already has custom role"
}

# Make Sarah eligible member of support group
Write-Verbose "[!] CREATING VULNERABILITY 1: Making support user eligible member of IT Service Desk group..."
$eligibleMemberParams = @{
    accessId          = "member"
    principalId       = $SupportUser.Id
    groupId           = $SupportGroup.Id
    action            = "adminAssign"
    scheduleInfo      = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{ 
            type = "afterDuration"
            duration = "P365D"  
        }
    }
    justification     = "Service desk support responsibilities"
}

try {
    $membershipResponse = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
        -Body $eligibleMemberParams -ContentType "application/json"
    Write-Verbose "    -> Eligible membership granted"
    Start-Sleep -Seconds $standardDelay
} catch {
    Write-Verbose "    -> Failed to create eligible membership: $($_.Exception.Message)"
}
#endregion

#region Create PIM Group for AU-Scoped Role
Write-Verbose "[*] Creating PIM-eligible group..."
$ExistingPrivGroup = Get-MgGroup -Filter "displayName eq '$PrivilegedGroupName'" -ErrorAction SilentlyContinue

if ($ExistingPrivGroup) {
    $PrivilegedGroup = $ExistingPrivGroup
    Write-Verbose "    -> Group exists: $PrivilegedGroupName"
} else {
    $PrivGroupParams = @{
        DisplayName = $PrivilegedGroupName
        Description = "Regional access coordination team for cross-departmental authentication management"
        MailEnabled = $false
        MailNickname = "regional-identity-mgrs"
        SecurityEnabled = $true
        IsAssignableToRole = $true
    }
    $PrivilegedGroup = New-MgGroup @PrivGroupParams
    Write-Verbose "    -> Group created: $PrivilegedGroupName"
    Start-Sleep -Seconds $standardDelay
}

Write-Verbose "[*] Adding Regional Access users to PIM group..."
foreach ($user in $RegionalUserObjects) {
    $groupMembers = Get-MgGroupMember -GroupId $PrivilegedGroup.Id -All -ErrorAction SilentlyContinue
    $isMember = $false
    if ($groupMembers) {
        $isMember = $groupMembers | Where-Object { $_.Id -eq $user.Id }
    }

    if (-not $isMember) {
        try {
            $MemberParams = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($user.Id)"
            }
            New-MgGroupMemberByRef -GroupId $PrivilegedGroup.Id -BodyParameter $MemberParams
            Write-Verbose "    -> Added $($user.DisplayName) to PIM group"
            Start-Sleep -Seconds 2
        } catch {
            Write-Verbose "    -> Failed to add $($user.DisplayName): $($_.Exception.Message)"
        }
    } else {
        Write-Verbose "    -> $($user.DisplayName) already member"
    }
}

# Make support user eligible owner of the PIM group 
Write-Verbose "[!] Setting support user as eligible owner of PIM group..."

$eligibleOwnerParams = @{
    accessId          = "owner"
    principalId       = $SupportUser.Id
    groupId           = $PrivilegedGroup.Id
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
        -Body $eligibleOwnerParams -ContentType "application/json"
    Write-Verbose "    -> Eligible ownership granted (vulnerability created)"
    Start-Sleep -Seconds $standardDelay
} catch {
    Write-Verbose "    -> Failed to create eligible ownership: $($_.Exception.Message)"
}

#region Create Administrative Unit with Dynamic Membership
Write-Verbose "[*] Creating Administrative Unit: $AUName"
$ExistingAU = Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$AUName'" -ErrorAction SilentlyContinue

if ($ExistingAU) {
    $hrAU = $ExistingAU
    Write-Verbose "    -> Administrative Unit exists: $AUName"
} else {
    $AUParams = @{
        DisplayName = $AUName
        Description = "HR department administrative unit for departmental user management"
        MembershipType = "Dynamic"
        MembershipRule = '(user.department -eq "HR")'
        MembershipRuleProcessingState = "On"
    }
    
    $hrAU = New-MgDirectoryAdministrativeUnit -BodyParameter $AUParams
    Write-Verbose "    -> Administrative Unit created: $AUName"
    Write-Verbose "    -> Dynamic rule: (user.department -eq 'HR')"
    Start-Sleep -Seconds $longReplicationDelay
}
#endregion

#region Assign AU-Scoped Privileged Authentication Administrator Role
Write-Verbose "[*] Assigning direct HR AU authentication role to group..."
$PrivAuthAdminRoleId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" # Privileged Authentication Administrator

# Create direct role assignment for the PIM group
$DirectRoleAssignmentParams = @{
    principalId      = $PrivilegedGroup.Id
    roleDefinitionId = $PrivAuthAdminRoleId
    directoryScopeId = "/administrativeUnits/$($hrAU.Id)"
}

try {
    # Check if assignment already exists
    $ExistingAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($PrivilegedGroup.Id)' and roleDefinitionId eq '$PrivAuthAdminRoleId'" -ErrorAction SilentlyContinue | Out-Null

    $hasRole = $false
    if ($ExistingAssignments) {
        foreach ($assignment in $ExistingAssignments) {
            if ($assignment.DirectoryScopeId -eq "/administrativeUnits/$($hrAU.Id)") {
                $hasRole = $true
                break
            }
        }
    }
    
    if (-not $hasRole) {
        New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $DirectRoleAssignmentParams -ErrorAction Stop | Out-Null
        Write-Verbose "    -> Direct role assignment created for group"
        Start-Sleep -Seconds $longReplicationDelay
    } else {
        Write-Verbose "    -> Direct role assignment already exists"
    }
} catch {
    Write-Verbose "    -> Failed to create direct role assignment: $($_.Exception.Message)"
}
#endregion

$SetupSuccessful = $true # Assume success unless an exit occurred

#region Output Summary
if ($VerbosePreference -eq 'Continue') {
    Write-Host ""
    Write-Host "----------------------------------------------------------------" -ForegroundColor Green
    Write-Host "              SCENARIO 5 SETUP COMPLETED                        " -ForegroundColor Green
    Write-Host "----------------------------------------------------------------" -ForegroundColor Green

    Write-Host "`nVULNERABILITY CHAIN:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "   -  Support user has eligible membership in IT Service Desk group" -ForegroundColor White
    Write-Host "   -  IT Service Desk has User Profile Administrator role (update attributes)" -ForegroundColor White
    Write-Host "   -  Support user has eligible ownership of Regional Identity Managers group" -ForegroundColor White
    Write-Host "   -  Regional Identity Managers has AU-scoped Privileged Auth Admin role" -ForegroundColor White
    Write-Host "   -  Finance AU has dynamic rule: (user.department -eq 'Finance')" -ForegroundColor White
    Write-Host "   -  Attack: Activate roles -> Modify admin's department -> Reset password" -ForegroundColor White

    Write-Host "`nGROUPS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Support Group: $SupportGroupName (ID: $($SupportGroup.Id))" -ForegroundColor Cyan
    Write-Host "  Privileged Group: $PrivilegedGroupName (ID: $($PrivilegedGroup.Id))" -ForegroundColor Cyan

    Write-Host "`nADMINISTRATIVE UNIT:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  AU: $AUName (ID: $($financeAU.Id))" -ForegroundColor Cyan
    Write-Host "  Dynamic Rule: (user.department -eq 'Finance')" -ForegroundColor Cyan
    Write-Host "  Scoped Role: Privileged Authentication Administrator" -ForegroundColor Cyan

    Write-Host "`nFLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host ""
} else {
    # Minimal output for CTF players
    Write-Host ""
    if ($SetupSuccessful) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "Scenario 5 setup completed successfully" -ForegroundColor White
        Write-Host ""
        Write-Host "Objective: Sign in as the admin user and retrieve the flag." -ForegroundColor Gray
        Write-Host ""
        Write-Host "`nYOUR CREDENTIALS:" -ForegroundColor Red
        Write-Host "----------------------------" -ForegroundColor DarkGray
        Write-Host "  Username: " -ForegroundColor White -NoNewline
        Write-Host "$SupportUPN" -ForegroundColor Cyan
        Write-Host "  Password: " -ForegroundColor White -NoNewline
        Write-Host "$SupportPassword" -ForegroundColor Cyan

        Write-Host "`nTARGET:" -ForegroundColor Magenta
        Write-Host "----------------------------" -ForegroundColor DarkGray
        Write-Host "  Username: " -ForegroundColor White -NoNewline
        Write-Host "$AdminUPN" -ForegroundColor Cyan

        Write-Host "  Flag Location: " -ForegroundColor White -NoNewline
        Write-Host "extensionAttribute1" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "Hint: Administrative Units create boundaries... until you're on the inside." -ForegroundColor DarkGray

    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 5 setup failed - give it another shot or run with -Verbose flag to reveal more for debugging (spoiler alert)." -ForegroundColor White
    }
    Write-Host ""
}
#endregion