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
$SupportGroupName = "HR Support Team"
$PrivilegedGroupName = "Regional HR Coordinators"
$KnowledgeGroupName = "Knowledge Management Team"
$KaizalaGroupName = "Kaizala Operations Team"
$AUName = "HR Department"
$Flag = "EntraGoat{Dyn@m1c_AU_P01s0n1ng_FTW!}"
$SupportPassword = "GoatAccess!123"
$AdminPassword = "ComplexAdminP@ssw0rd#2025!"
$standardDelay = 5 
$longReplicationDelay = 15 

$HRUsers = @(
    @{ DisplayName = "Jessica Chen"; UPN = "jessica.chen"; Department = "HR"; JobTitle = "Senior Analyst" }
    @{ DisplayName = "Michael Rodriguez"; UPN = "michael.rodriguez"; Department = "HR"; JobTitle = "Budget Manager" }
    @{ DisplayName = "Amanda Thompson"; UPN = "amanda.thompson"; Department = "HR"; JobTitle = "Accounting Specialist" }
)

$RegionalUsers = @(
    @{ DisplayName = "David Wilson"; UPN = "david.wilson"; Department = "IT Operations"; JobTitle = "Regional IT Coordinator" }
    @{ DisplayName = "Lisa Park"; UPN = "lisa.park"; Department = "Security"; JobTitle = "Identity Access Manager" }
)

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 5 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|        Department of Escalations - AU Ready for This?        |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

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
$SupportUPN = "sarah.connor@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s5@$TenantDomain"

$SupportUser = New-EntraGoatUser -DisplayName "Sarah Connor" -UserPrincipalName $SupportUPN -MailNickname "sarah.connor" -Password $SupportPassword -Department "HR" -JobTitle "HR Manager"
$AdminUser = New-EntraGoatUser -DisplayName "EntraGoat Administrator S5" -UserPrincipalName $AdminUPN -MailNickname "entragoat-admin-s5" -Password $AdminPassword -Department "Executive" -JobTitle "System Administrator"

# Create dummy HR users (they will be added to the AU via dynamic membership)
Write-Verbose "    -> Creating HR department users..."
$HRUserObjects = @()
foreach ($userInfo in $HRUsers) {
    $userUPN = "$($userInfo.UPN)@$TenantDomain"
    $newUser = New-EntraGoatUser -DisplayName $userInfo.DisplayName -UserPrincipalName $userUPN -MailNickname $userInfo.UPN -Password "HRUsers@2025!" -Department $userInfo.Department -JobTitle $userInfo.JobTitle
    $HRUserObjects += $newUser
}

# Create dummy Regional Access users
Write-Verbose "    -> Creating Regional Access users..."
$RegionalUserObjects = @()
foreach ($userInfo in $RegionalUsers) {
    $userUPN = "$($userInfo.UPN)@$TenantDomain"
    $newUser = New-EntraGoatUser -DisplayName $userInfo.DisplayName -UserPrincipalName $userUPN -MailNickname $userInfo.UPN -Password "Regional@2025!" -Department $userInfo.Department -JobTitle $userInfo.JobTitle
    $RegionalUserObjects += $newUser
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

#region Create Tier-1 Support Team Group
Write-Verbose "[*] Creating Tier-1 Support Team group..."
$SupportGroup = New-EntraGoatGroup -GroupName $SupportGroupName -Description "HR support team with custom user profile update permissions" -MailNickname "hr-support-desk"

# Assign custom role to the support group
Write-Verbose "[*] Assigning custom role to HR Support Team group..."
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
Write-Verbose "[!] CREATING VULNERABILITY 1: Making Sarah eligible member of HR Support Team group..."
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
    justification     = "HR support responsibilities"
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
$PrivilegedGroup = New-EntraGoatGroup -GroupName $PrivilegedGroupName -Description "Regional HR coordination team for departmental authentication management" -MailNickname "regional-hr-mgrs"

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

# Make Sarah eligible owner of the PIM group 
Write-Verbose "[!] Setting Sarah as eligible owner of PIM group..."

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
    justification     = "Regional HR coordination administrative privileges"
}

try {
    $ownershipResponse = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
        -Body $eligibleOwnerParams -ContentType "application/json"
    Write-Verbose "    -> Eligible ownership granted"
    Start-Sleep -Seconds $standardDelay
} catch {
    Write-Verbose "    -> Failed to create eligible ownership: $($_.Exception.Message)"
}

# 2 more eligible members of PIM group to hide a bit the attack chain and make it look like a real PIM setup

#region Create Knowledge Management Team Group
Write-Verbose "[*] Creating Knowledge Management Team group..."
$KnowledgeGroup = New-EntraGoatGroup -GroupName $KnowledgeGroupName -Description "Team responsible for managing organizational knowledge and documentation" -MailNickname "knowledge-mgmt-team" -RoleTemplateId "b5a8dcf3-09d5-43a9-a639-8e29ef291470"

# Make Sarah eligible member of Knowledge Management group
Write-Verbose "Making Sarah eligible member of Knowledge Management group..."
$eligibleKnowledgeMemberParams = @{
    accessId          = "member"
    principalId       = $SupportUser.Id
    groupId           = $KnowledgeGroup.Id
    action            = "adminAssign"
    scheduleInfo      = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{ 
            type = "afterDuration"
            duration = "P365D"  
        }
    }
    justification     = "Knowledge management support responsibilities"
}

try {
    $knowledgeMembershipResponse = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
        -Body $eligibleKnowledgeMemberParams -ContentType "application/json"
    Write-Verbose "    -> Eligible Knowledge Management membership granted"
    Start-Sleep -Seconds $standardDelay
} catch {
    Write-Verbose "    -> Failed to create eligible Knowledge Management membership: $($_.Exception.Message)"
}
#endregion

#region Create Kaizala Operations Team Group
Write-Verbose "[*] Creating Kaizala Operations Team group..."
$KaizalaGroup = New-EntraGoatGroup -GroupName $KaizalaGroupName -Description "Team responsible for managing Kaizala operations and communications" -MailNickname "kaizala-ops-team" -RoleTemplateId "74ef975b-6605-40af-a5d2-b9539d836353"

# Make Sarah eligible member of Kaizala Operations group
Write-Verbose "[!] Making Sarah eligible member of Kaizala Operations group..."
$eligibleKaizalaMemberParams = @{
    accessId          = "member"
    principalId       = $SupportUser.Id
    groupId           = $KaizalaGroup.Id
    action            = "adminAssign"
    scheduleInfo      = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{ 
            type = "afterDuration"
            duration = "P365D"  
        }
    }
    justification     = "Kaizala operations support responsibilities"
}

try {
    $kaizalaMembershipResponse = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
        -Body $eligibleKaizalaMemberParams -ContentType "application/json"
    Write-Verbose "    -> Eligible Kaizala Operations membership granted"
    Start-Sleep -Seconds $standardDelay
} catch {
    Write-Verbose "    -> Failed to create eligible Kaizala Operations membership: $($_.Exception.Message)"
}
#endregion

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

# Helper to print the minimal output block consistently
function Show-MinimalOutput {
    param(
        [string]$SupportUPN,
        [string]$SupportPassword,
        [string]$AdminUPN
    )

    Write-Host "Objective: Sign in as the admin user and retrieve the flag." -ForegroundColor Gray
    Write-Host ""
    Write-Host "`nYOUR CREDENTIALS:" -ForegroundColor Red
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Username: " -ForegroundColor White -NoNewline
    Write-Host $SupportUPN -ForegroundColor Cyan
    Write-Host "  Password: " -ForegroundColor White -NoNewline
    Write-Host $SupportPassword -ForegroundColor Cyan

    Write-Host "`nTARGET:" -ForegroundColor Magenta
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Username: " -ForegroundColor White -NoNewline
    Write-Host $AdminUPN -ForegroundColor Cyan

    Write-Host "  Flag Location: " -ForegroundColor White -NoNewline
    Write-Host "extensionAttribute1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Hint: Administrative Units create boundaries... until you're on the inside." -ForegroundColor DarkGray
    Write-Host ""
}

#region Output Summary
if ($VerbosePreference -eq 'Continue') {
    Write-Host ""
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host "|             SCENARIO 5 SETUP COMPLETED (VERBOSE)             |" -ForegroundColor Cyan
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "`nVULNERABILITY CHAIN:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "   -  Sarah has eligible membership in HR Support Team group" -ForegroundColor White
    Write-Host "   -  HR Support Team has User Profile Administrator cutome role that allows memebrs to update attributes for all users" -ForegroundColor White
    Write-Host "   -  Sarah also has eligible ownership of Regional HR Coordinators group" -ForegroundColor White
    Write-Host "   -  Regional HR Coordinators has AU-scoped Privileged Authentication Administrator role" -ForegroundColor White
    Write-Host "   -  HR AU has dynamic rule: (user.department -eq 'HR')" -ForegroundColor White
    Write-Host "   -  Attack: Activate eligible assignments -> Modify admin's department -> Reset password" -ForegroundColor White

    Write-Host "`nGROUPS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Support Group: $SupportGroupName (ID: $($SupportGroup.Id))" -ForegroundColor Cyan
    Write-Host "  Privileged Group: $PrivilegedGroupName (ID: $($PrivilegedGroup.Id))" -ForegroundColor Cyan
    Write-Host "  Knowledge Group: $KnowledgeGroupName (ID: $($KnowledgeGroup.Id))" -ForegroundColor Cyan
    Write-Host "  Kaizala Group: $KaizalaGroupName (ID: $($KaizalaGroup.Id))" -ForegroundColor Cyan

    Write-Host "`nADMINISTRATIVE UNIT:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  AU: $AUName (ID: $($hrAU.Id))" -ForegroundColor Cyan
    Write-Host "  Dynamic Rule: (user.department -eq 'HR')" -ForegroundColor Cyan
    Write-Host "  Scoped Role: Privileged Authentication Administrator" -ForegroundColor Cyan

    Write-Host "`nFLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host ""
    Show-MinimalOutput -SupportUPN $SupportUPN -SupportPassword $SupportPassword -AdminUPN $AdminUPN
} else {
    # Minimal output for CTF players
    Write-Host ""
    if ($SetupSuccessful) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "Scenario 5 setup completed successfully" -ForegroundColor White
        Write-Host ""
        Show-MinimalOutput -SupportUPN $SupportUPN -SupportPassword $SupportPassword -AdminUPN $AdminUPN

    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 5 setup failed - give it another shot or run with -Verbose flag to reveal more for debugging (spoiler alert)." -ForegroundColor White
    }
    Write-Host ""
}
#endregion