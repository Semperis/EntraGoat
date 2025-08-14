<#

EntraGoat Scenario 2: Graph Me the Crown (and Roles)
Setup script to be run with Global Administrator privileges

#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$PrivilegedAppName = "Corporate Finance Analytics"  
$Flag = "EntraGoat{4P1_P37mission_4bus3_Succ3ss!}"
$AdminPassword = "ComplexAdminP@ssw0rd#2025!"
$LowPrivPassword = "GoatAccess!123"
$CertificatePassword = "GoatAccess!123"
$standardDelay = 10
$longReplicationDelay = 15 

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 2 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|              Graph Me the Crown (and Roles)                  |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

#region Module Check and Import
Write-Verbose "[*] Checking and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement"
)
$MissingModules = @()
foreach ($moduleName in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        $MissingModules += $moduleName
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Warning "The following required modules are not installed: $($MissingModules -join ', ')."
    $choice = Read-Host "Do you want to attempt to install them from PowerShell Gallery? (Y/N)"
    if ($choice -eq 'Y') {
        try {
            Write-Host "Attempting to install $($MissingModules -join ', ') from PowerShell Gallery. This may take a moment..." -ForegroundColor Yellow
            Install-Module -Name $MissingModules -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Verbose "[+] Successfully attempted to install missing modules."
            # Import them after installation
            foreach ($moduleName in $MissingModules) {
                Import-Module $moduleName -ErrorAction Stop
                Write-Verbose "   Imported $moduleName"
            }
        } catch {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to automatically install or import modules: $($MissingModules -join ', '). Please install them manually (e.g., Install-Module -Name Microsoft.Graph -Scope CurrentUser) and re-run the script. Error: $($_.Exception.Message)" -ForegroundColor White
            exit 1
        }
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Required modules are missing. Please install them and re-run the script." -ForegroundColor White
        exit 1
    }
} else {
    # Import modules if they are installed but not loaded
    foreach ($moduleName in $RequiredModules) {
        if (-not (Get-Module -Name $moduleName)) {
            try {
                Import-Module $moduleName -ErrorAction Stop
                Write-Verbose "[+] Imported module $moduleName."
            } catch {
                Write-Host "[-] " -ForegroundColor Red -NoNewline
                Write-Host "Failed to import module $moduleName. Error: $($_.Exception.Message)" -ForegroundColor White
                exit 1
            }
        } else {
             Write-Verbose "[*] Module $moduleName is already loaded."
        }
    }
}
Write-Verbose "[+] All required modules appear to be present and loaded."
#endregion Module Check and Import

#region Authentication
Write-Verbose "[*] Connecting to Microsoft Graph..."
$GraphScopes = @( 
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
)

try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $GraphScopes -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -Scopes $GraphScopes -NoWelcome
    }
    # $MgContext = Get-MgContext 
    $Organization = Get-MgOrganization
    $TenantDomain = ($Organization.VerifiedDomains | Where-Object IsDefault).Name
    $CurrentTenantId = $Organization.Id 
    Write-Verbose "[+] Connected to tenant: $TenantDomain ($CurrentTenantId)"
} catch {
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor White
    exit 1
}
#endregion

#region User Creation
Write-Verbose "[*] Setting up users..."
$LowPrivUPN = "jennifer.clark@$TenantDomain"  
$AdminUPN = "EntraGoat-admin-s2@$TenantDomain"

# Create or get low-privileged user
Write-Verbose "    ->  Finance user: $LowPrivUPN"
$ExistingLowPrivUser = Get-MgUser -Filter "userPrincipalName eq '$LowPrivUPN'" -ErrorAction SilentlyContinue
if ($ExistingLowPrivUser) {
    $LowPrivUser = $ExistingLowPrivUser
    Write-Verbose "      EXISTS (using existing)"
} else {
    $LowPrivUserParams = @{
        DisplayName = "Jennifer Clark"
        UserPrincipalName = $LowPrivUPN
        MailNickname = "jennifer.clark"
        AccountEnabled = $true
        Department = "Finance"
        JobTitle = "Senior Financial Analyst"
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $LowPrivPassword
        }
    }
    $LowPrivUser = New-MgUser @LowPrivUserParams
    Write-Verbose "      CREATED"
    Start-Sleep -Seconds $standardDelay
}

# Create or get admin user
Write-Verbose " Admin user: $AdminUPN"
$ExistingAdminUser = Get-MgUser -Filter "userPrincipalName eq '$AdminUPN'" -ErrorAction SilentlyContinue
if ($ExistingAdminUser) {
    $AdminUser = $ExistingAdminUser
    Write-Verbose "      EXISTS (using existing)"
} else {
    $AdminUserParams = @{
        DisplayName = "EntraGoat Administrator S2"
        UserPrincipalName = $AdminUPN
        MailNickname = "entragoat-admin-s2"
        AccountEnabled = $true
        Department = "IT Administration"
        JobTitle = "System Administrator"
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $AdminPassword
        }
    }
    $AdminUser = New-MgUser @AdminUserParams
    Write-Verbose "      CREATED"
    Start-Sleep -Seconds $standardDelay
}
#endregion

#region Store admin flag in extension attributes
Write-Verbose "[*] Storing flag in admin user's extension attributes..."
try {
    $UpdateParams = @{
        OnPremisesExtensionAttributes = @{
            ExtensionAttribute1 = $Flag
        }
    }
    Update-MgUser -UserId $AdminUser.Id -BodyParameter $UpdateParams -ErrorAction Stop
    Write-Verbose " Flag stored successfully."
} catch {
    Write-Verbose " Flag already set or minor error (continuing): $($_.Exception.Message)"
}
#endregion

#region Assign Global Administrator Role to Admin User
Write-Verbose "[*] Assigning Global Administrator role to admin user ($AdminUPN)..."
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10" 
$DirectoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GlobalAdminRoleId'" -ErrorAction SilentlyContinue

if (-not $DirectoryRole) {
    Write-Verbose " Activating Global Administrator role template..."
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $GlobalAdminRoleId
    $DirectoryRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}

$ExistingGARMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRole.Id -All -ErrorAction SilentlyContinue
$IsAlreadyGAMember = $false
if ($ExistingGARMembers) {
    foreach ($member in $ExistingGARMembers) {
        if ($member.Id -eq $AdminUser.Id) {
            $IsAlreadyGAMember = $true
            break
        }
    }
}

if (-not $IsAlreadyGAMember) {
    Write-Verbose " Assigning role to $($AdminUser.UserPrincipalName)..."
    try {
        $RoleMemberParams = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($AdminUser.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $DirectoryRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose " Role assigned successfully."
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose " Role was already assigned."
        } else {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to assign Global Admin role to admin user: $($_.Exception.Message)" -ForegroundColor White
        }
    }
} else {
    Write-Verbose " Admin user already has Global Administrator role."
}
#endregion

#region Create Certificate
Write-Verbose "[*] Creating self-signed certificate..."
$cert = New-SelfSignedCertificate `
    -Subject "CN=$PrivilegedAppName" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

# For PFX export (base64 for output to user at the end)
$pfxCertBytesForUserOutput = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $CertificatePassword)
$certBase64ForUserOutput = [System.Convert]::ToBase64String($pfxCertBytesForUserOutput) 

# For adding to application keyCredentials attribute:
# https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0
# 1. 'Key' property needs raw certificate data as byte[]
$rawCertDataBytesForAppKey = $cert.GetRawCertData()

# 2. 'CustomKeyIdentifier' property (specifies a custom key ID) - byte[]
#    The thumbprint string is HEX, so convert it to bytes.
$thumbprintHex = $cert.Thumbprint
$customKeyIdentifierBytes = [byte[]]::new($thumbprintHex.Length / 2)
for ($i = 0; $i -lt $thumbprintHex.Length; $i += 2) {
    $customKeyIdentifierBytes[$i / 2] = [System.Convert]::ToByte($thumbprintHex.Substring($i, 2), 16)
}

Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
Write-Verbose " Certificate created (Thumbprint: $($cert.Thumbprint)) and PFX data prepared. Removed from local store."
#endregion Create Certificate

#region Create Application Registration
Write-Verbose "[*] Creating application registration: $PrivilegedAppName"
$ExistingApp = Get-MgApplication -Filter "displayName eq '$PrivilegedAppName'" -ErrorAction SilentlyContinue
if ($ExistingApp) {
    $VulnerableMgApplication = $ExistingApp 
    Write-Verbose " Application exists: $PrivilegedAppName"
} else {
    $AppParams = @{
        DisplayName = $PrivilegedAppName
        SignInAudience = "AzureADMyOrg"
    }
    $VulnerableMgApplication = New-MgApplication @AppParams
    Write-Verbose " Application created: $PrivilegedAppName"
    Start-Sleep -Seconds $standardDelay
}
$AppId = $VulnerableMgApplication.AppId
if ($AppId -is [array]) { $AppId = $AppId[0] }
$AppId = $AppId.ToString()

Write-Verbose "[*] Adding certificate credential to application..."
# For checking existing credentials, Graph usually returns CustomKeyIdentifier as a Base64 string.
$customKeyIdentifierBase64ForComparison = [System.Convert]::ToBase64String($customKeyIdentifierBytes)

$existingKeyCredentials = (Get-MgApplication -ApplicationId $VulnerableMgApplication.Id -Property KeyCredentials -ErrorAction SilentlyContinue).KeyCredentials
$credentialExists = $false
if ($existingKeyCredentials) {
    # this section checks if a certificate with the same CustomKeyIdentifier already exists (meaning the user has already run this setup)
    foreach($keyCred in $existingKeyCredentials) {
        if ($keyCred.CustomKeyIdentifier -eq $customKeyIdentifierBase64ForComparison) {
            $credentialExists = $true
            Write-Verbose "    ->  Certificate credential with matching CustomKeyIdentifier already exists on the app."
            break
        }
    }
}

if (-not $credentialExists) {
    $keyCredentialHashtable = @{
        Type                = "AsymmetricX509Cert"
        Usage               = "Verify"
        Key                 = $rawCertDataBytesForAppKey      
        DisplayName         = "EntraGoat S2 Certificate"
        CustomKeyIdentifier = $customKeyIdentifierBytes 
    }
    try {
        Update-MgApplication -ApplicationId $VulnerableMgApplication.Id -KeyCredentials @($keyCredentialHashtable) -ErrorAction Stop
        Write-Verbose " Certificate credential added to application."
        Start-Sleep -Seconds $standardDelay
    } catch {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Failed to add certificate to application: $($_.Exception.Message)" -ForegroundColor White
        exit 1
    }
}
#endregion Create Application Registration

#region Create Service Principal
Write-Verbose "[*] Creating service principal for $PrivilegedAppName (App ID: $AppId)..."
$ExistingSP = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
if ($ExistingSP) {
    $ServicePrincipal = $ExistingSP
    Write-Verbose " Service principal exists."
} else {
    $SPParams = @{ AppId = $AppId; DisplayName = $VulnerableMgApplication.DisplayName }
    $ServicePrincipal = New-MgServicePrincipal @SPParams
    Write-Verbose " Service principal created."
    Start-Sleep -Seconds $standardDelay
}

Write-Verbose "[*] Updating service principal tags for UI visibility..."
$Tags = @("WindowsAzureActiveDirectoryIntegratedApp")
Update-MgServicePrincipal -ServicePrincipalId $ServicePrincipal.Id -Tags $Tags -ErrorAction SilentlyContinue
Write-Verbose " Tags updated."
#endregion

#region Grant API Permissions (THE VULNERABILITY)
Write-Verbose "[!] CREATING VULNERABILITY: Granting dangerous API permissions to SP..."
$GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" # Microsoft Graph SP
if (-not $GraphServicePrincipal) {
    Write-Host "[-] CRITICAL: Microsoft Graph Service Principal not found. Cannot grant API permissions." -ForegroundColor Red
    exit 1
}

$ApplicationReadAllRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq "Application.Read.All" }
$AppRoleAssignmentReadWriteAllRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq "AppRoleAssignment.ReadWrite.All" } 

if (-not $ApplicationReadAllRole -or -not $AppRoleAssignmentReadWriteAllRole) {
    Write-Host "[-] CRITICAL: Could not find required AppRole definitions on Microsoft Graph SP (Application.Read.All or AppRoleAssignment.ReadWrite.All)." -ForegroundColor Red
    exit 1
}

$ExistingGrants = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -All -ErrorAction SilentlyContinue

# Grant Application.Read.All (for easier enumeration on the player side)
$hasApplicationReadAll = $ExistingGrants | Where-Object { $_.AppRoleId -eq $ApplicationReadAllRole.Id }
if (-not $hasApplicationReadAll) {
    Write-Verbose " Granting Application.Read.All..."
    $AppRoleAssignment1 = @{ PrincipalId = $ServicePrincipal.Id; ResourceId = $GraphServicePrincipal.Id; AppRoleId = $ApplicationReadAllRole.Id }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -BodyParameter $AppRoleAssignment1 | Out-Null 
    Write-Verbose "      Granted."
    Start-Sleep -Seconds $standardDelay
} else { Write-Verbose " Application.Read.All already granted." }

# Grant AppRoleAssignment.ReadWrite.All 
$hasAppRoleAssignmentReadWriteAll = $ExistingGrants | Where-Object { $_.AppRoleId -eq $AppRoleAssignmentReadWriteAllRole.Id }
if (-not $hasAppRoleAssignmentReadWriteAll) {
    Write-Verbose " Granting AppRoleAssignment.ReadWrite.All (VULNERABLE)..."
    $AppRoleAssignment2 = @{ PrincipalId = $ServicePrincipal.Id; ResourceId = $GraphServicePrincipal.Id; AppRoleId = $AppRoleAssignmentReadWriteAllRole.Id }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -BodyParameter $AppRoleAssignment2 | Out-Null # <--- ADDED | Out-Null
    Write-Verbose "      Granted."
    Start-Sleep -Seconds $longReplicationDelay 
} else { Write-Verbose " AppRoleAssignment.ReadWrite.All already granted (VULNERABLE)." }
#endregion Grant API Permissions 

$SetupSuccessful = $true # Assume success unless an exit occurred

#region Output Summary with Certificate
if ($VerbosePreference -eq 'Continue') {
    # only for VERBOSE output
    Write-Host ""
    Write-Host "|-------------------------------------------------------------------|" -ForegroundColor Green
    Write-Host "|              SCENARIO 2 SETUP COMPLETED (VERBOSE)                 |" -ForegroundColor Green
    Write-Host "|-------------------------------------------------------------------|" -ForegroundColor Green

    Write-Host "`nVULNERABILITY DETAILS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host " - A service principal certificate is 'leaked'." -ForegroundColor White
    Write-Host " - SP Name: $($ServicePrincipal.DisplayName) (App ID: $AppId, SP ID: $($ServicePrincipal.Id))" -ForegroundColor Cyan 
    Write-Host " - SP has 'AppRoleAssignment.ReadWrite.All' for MS Graph." -ForegroundColor White
    Write-Host " - Attacker can use SP to grant itself 'RoleManagement.ReadWrite.Directory'." -ForegroundColor White
    Write-Host " - Then, attacker SP can assign itself Global Administrator." -ForegroundColor White

    Write-Host "`nFLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan
}

# this will show in both verbose and non-verbose if successful
if ($SetupSuccessful) {
    Write-Host "`n" 
    Write-Host "ATTACKER CREDENTIALS:" -ForegroundColor Magenta
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Username: " -ForegroundColor White -NoNewline
    Write-Host "$LowPrivUPN" -ForegroundColor Cyan
    Write-Host "  Password: " -ForegroundColor White -NoNewline
    Write-Host "$LowPrivPassword" -ForegroundColor Cyan

    Write-Host "`nTARGET:" -ForegroundColor Red
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Username: " -ForegroundColor White -NoNewline
    Write-Host "$AdminUPN" -ForegroundColor Cyan
    Write-Host "  Flag Location: " -ForegroundColor White -NoNewline
    Write-Host "extensionAttribute1" -ForegroundColor Cyan
}

# Show cert "falling off the truck"" 
Write-Host "`n" 
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "||                  A WILD CERTIFICATE APPEARED!          ||" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "While a sysadmin was configuring CI/CD pipelines, this certificate" -ForegroundColor DarkGray
Write-Host "somehow got logged to STDOUT. They thought no one would notice..." -ForegroundColor DarkGray
Write-Host ""
Write-Host "          .----------------." -ForegroundColor DarkGray
Write-Host "         |  ACME DEVOPS     |" -ForegroundColor DarkGray
Write-Host "         |                  |--------------." -ForegroundColor DarkGray
Write-Host "         |__________________|_|)            |" -ForegroundColor DarkGray
Write-Host "           (O)          (O)   '.__________.'" -ForegroundColor DarkGray
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "                                       Log Output:" -ForegroundColor Yellow
Write-Host "                                               \\" -ForegroundColor Yellow
Write-Host "                                                ---" -ForegroundColor DarkGray 
Write-Host "                                               |CERT|" -ForegroundColor Yellow
Write-Host "                                               ------" -ForegroundColor Yellow
Write-Host ""
Write-Host "================= CERTIFICATE DETAILS ======================" -ForegroundColor Cyan

Write-Host "PFX Password: " -ForegroundColor White -NoNewline
Write-Host "$CertificatePassword" -ForegroundColor Gray 
Write-Host ""
Write-Host "================= BASE64 ENCODED PFX ======================" -ForegroundColor Cyan
Write-Host $certBase64ForUserOutput -ForegroundColor Gray
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Wonder what you could authenticate with this...? " -ForegroundColor Yellow
Write-Host ""

if ($VerbosePreference -ne 'Continue') {
    if ($SetupSuccessful) {
        Write-Host "Scenario 2 setup completed successfully." -ForegroundColor White
        Write-Host ""
        Write-Host "Objective: Sign in as the admin user and retrieve the flag." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Hint: This cert seems harmless but listen closely. It may speak with someone else`'s authority." -ForegroundColor DarkGray
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 2 setup did not complete successfully. Please check verbose output or previous errors." -ForegroundColor White
    }
}
Write-Host "`n=====================================================" -ForegroundColor DarkGray
Write-Host ""
#endregion Output Summary with Certificate