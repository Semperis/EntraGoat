<#
.SYNOPSIS
EntraGoat Scenario 3: Group Ownership Privilege Escalation Chain
Setup script to be run with Global Administrator privileges 

#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$AppAdminGroupName = "IT Application Managers"  
$PrivAuthGroupName = "Identity Security Team"   
$TargetAppName = "Identity Management Portal"   
$Flag = "EntraGoat{Gr0up_Ch@1n_Pr1v_Esc@l@t10n!}"
$AdminPassword = "ComplexP@ssw0rd#2025!"
$LowPrivPassword = "GoatAccess!123"
$standardDelay = 10 # Seconds
$longReplicationDelay = 20

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 3 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|                Groups all the way to the top                 |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

#region Module Check and Import
Write-Verbose "[*] Checking and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Groups"
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
            foreach ($moduleName in $MissingModules) {
                Import-Module $moduleName -ErrorAction Stop
                Write-Verbose "   Imported $moduleName"
            }
        } catch {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to automatically install or import modules: $($MissingModules -join ', '). Please install them manually and re-run the script. Error: $($_.Exception.Message)" -ForegroundColor White
            exit 1
        }
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Required modules are missing. Please install them and re-run the script." -ForegroundColor White
        exit 1
    }
} else {
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
#endregion

#region Authentication
Write-Verbose "[*] Connecting to Microsoft Graph..."
$GraphScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", 
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All"
)

try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $GraphScopes -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -Scopes $GraphScopes -NoWelcome
    }
    $MgContext = Get-MgContext
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
$LowPrivUPN = "michael.chen@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s3@$TenantDomain"

# Create or get low-privileged user
Write-Verbose "   -> IT Support user: $LowPrivUPN"
$ExistingLowPrivUser = Get-MgUser -Filter "userPrincipalName eq '$LowPrivUPN'" -ErrorAction SilentlyContinue
if ($ExistingLowPrivUser) {
    $LowPrivUser = $ExistingLowPrivUser
    Write-Verbose "      EXISTS (using existing)"
    # Update password to ensure we know it
    $passwordProfile = @{
        Password = $LowPrivPassword
        ForceChangePasswordNextSignIn = $false
    }
    Update-MgUser -UserId $LowPrivUser.Id -PasswordProfile $passwordProfile
} else {
    $LowPrivUserParams = @{
        DisplayName = "Michael Chen"
        UserPrincipalName = $LowPrivUPN
        MailNickname = "michael.chen"
        AccountEnabled = $true
        Department = "IT Support"
        JobTitle = "IT Support Specialist"
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
Write-Verbose "   -> Admin user: $AdminUPN"
$ExistingAdminUser = Get-MgUser -Filter "userPrincipalName eq '$AdminUPN'" -ErrorAction SilentlyContinue
if ($ExistingAdminUser) {
    $AdminUser = $ExistingAdminUser
    Write-Verbose "      EXISTS (using existing)"
    # Update password to ensure we know it
    $passwordProfile = @{
        Password = $AdminPassword
        ForceChangePasswordNextSignIn = $false
    }
    Update-MgUser -UserId $AdminUser.Id -PasswordProfile $passwordProfile
} else {
    $AdminUserParams = @{
        DisplayName = "EntraGoat Administrator S3"
        UserPrincipalName = $AdminUPN
        MailNickname = "entragoat-admin-s3"
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

#region Store Flag in Admin User
Write-Verbose "[*] Storing flag in admin user's extension attributes..."
try {
    $UpdateParams = @{
        OnPremisesExtensionAttributes = @{
            ExtensionAttribute1 = $Flag
        }
    }
    Update-MgUser -UserId $AdminUser.Id -BodyParameter $UpdateParams -ErrorAction Stop
    Write-Verbose "   -> Flag stored successfully."
} catch {
    Write-Verbose "   -> Flag already set or minor error (continuing): $($_.Exception.Message)"
}
#endregion

#region Assign Global Administrator Role to Admin User
Write-Verbose "[*] Assigning Global Administrator role to admin user ($AdminUPN)..."
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
$DirectoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GlobalAdminRoleId'" -ErrorAction SilentlyContinue

if (-not $DirectoryRole) {
    Write-Verbose "   -> Activating Global Administrator role template..."
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
    Write-Verbose "   -> Assigning role to $($AdminUser.UserPrincipalName)..."
    try {
        $RoleMemberParams = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($AdminUser.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $DirectoryRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "   -> Role assigned successfully."
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "   -> Role was already assigned."
        } else {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to assign Global Admin role to admin user: $($_.Exception.Message)" -ForegroundColor White
        }
    }
} else {
    Write-Verbose "   -> Admin user already has Global Administrator role."
}
#endregion

#region Create Application Administrator Group
Write-Verbose "[*] Creating Application Administrator group..."
$ExistingAppAdminGroup = Get-MgGroup -Filter "displayName eq '$AppAdminGroupName'" -ErrorAction SilentlyContinue

if ($ExistingAppAdminGroup) {
    $AppAdminGroup = $ExistingAppAdminGroup
    Write-Verbose "   -> Group exists: $AppAdminGroupName"
} else {
    $AppAdminGroupParams = @{
        DisplayName = $AppAdminGroupName
        Description = "Team responsible for managing enterprise applications"
        MailEnabled = $false
        MailNickname = "it-app-managers"
        SecurityEnabled = $true
        IsAssignableToRole = $true
    }
    $AppAdminGroup = New-MgGroup @AppAdminGroupParams
    Write-Verbose "   -> Group created: $AppAdminGroupName"
    Start-Sleep -Seconds $standardDelay
}

# Assign Application Administrator role to the group
Write-Verbose "[*] Assigning Application Administrator role to group..."
$AppAdminRoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" # Application Administrator

$AppAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$AppAdminRoleId'" -ErrorAction SilentlyContinue
if (-not $AppAdminRole) {
    Write-Verbose "   -> Activating Application Administrator role..."
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $AppAdminRoleId
    $AppAdminRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}

# Check if group already has the role
$ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $AppAdminRole.Id -All -ErrorAction SilentlyContinue
$hasRole = $false
if ($ExistingMembers) {
    foreach ($member in $ExistingMembers) {
        if ($member.Id -eq $AppAdminGroup.Id) {
            $hasRole = $true
            break
        }
    }
}

if (-not $hasRole) {
    try {
        $RoleMemberParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($AppAdminGroup.Id)"
        }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $AppAdminRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "   -> Application Administrator role assigned to group"
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "   -> Role already assigned"
        } else {
            Write-Verbose "   -> Failed to assign role: $($_.Exception.Message)"
        }
    }
} else {
    Write-Verbose "   -> Group already has Application Administrator role"
}
#endregion

#region Create Target Application and Service Principal
Write-Verbose "[*] Creating target application: $TargetAppName"
$ExistingTargetApp = Get-MgApplication -Filter "displayName eq '$TargetAppName'" -ErrorAction SilentlyContinue

if ($ExistingTargetApp) {
    $TargetApp = $ExistingTargetApp
    Write-Verbose "   -> Application exists: $TargetAppName"
} else {
    $TargetAppParams = @{
        DisplayName = $TargetAppName
        SignInAudience = "AzureADMyOrg"
        Description = "Portal for managing user identities and access"
        Web = @{
            RedirectUris = @("https://identity-portal.contoso.com/callback")
        }
    }
    $TargetApp = New-MgApplication @TargetAppParams
    Write-Verbose "   -> Application created: $TargetAppName"
    Start-Sleep -Seconds $standardDelay
}

$TargetAppId = $TargetApp.AppId
if ($TargetAppId -is [array]) { $TargetAppId = $TargetAppId[0] }
$TargetAppId = $TargetAppId.ToString()

# Create service principal
Write-Verbose "[*] Creating service principal for target app..."
$ExistingTargetSP = Get-MgServicePrincipal -Filter "appId eq '$TargetAppId'" -ErrorAction SilentlyContinue

if ($ExistingTargetSP) {
    $TargetSP = $ExistingTargetSP
    Write-Verbose "   -> Service principal exists"
} else {
    $TargetSPParams = @{
        AppId = $TargetAppId
        DisplayName = $TargetAppName
    }
    $TargetSP = New-MgServicePrincipal @TargetSPParams
    Write-Verbose "   -> Service principal created"
    Start-Sleep -Seconds $standardDelay
}

# Make it visible in Azure Portal UI
$Tags = @("WindowsAzureActiveDirectoryIntegratedApp")
Update-MgServicePrincipal -ServicePrincipalId $TargetSP.Id -Tags $Tags

# Grant Directory.Read.All to target SP for enumeration
Write-Verbose "[*] Granting Directory.Read.All to target SP..."
$GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$DirectoryReadAllRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq "Directory.Read.All" }

$ExistingGrants = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -All -ErrorAction SilentlyContinue
$hasDirectoryRead = $ExistingGrants | Where-Object { $_.AppRoleId -eq $DirectoryReadAllRole.Id }

if (-not $hasDirectoryRead) {
    $AppRoleAssignment = @{
        PrincipalId = $TargetSP.Id
        ResourceId = $GraphServicePrincipal.Id
        AppRoleId = $DirectoryReadAllRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -BodyParameter $AppRoleAssignment | Out-Null
    Write-Verbose "   -> Directory.Read.All granted"
    Start-Sleep -Seconds $standardDelay
}
#endregion

#region Create Privileged Authentication Administrator Group
Write-Verbose "[*] Creating Privileged Authentication Administrator group..."
$ExistingPrivAuthGroup = Get-MgGroup -Filter "displayName eq '$PrivAuthGroupName'" -ErrorAction SilentlyContinue

if ($ExistingPrivAuthGroup) {
    $PrivAuthGroup = $ExistingPrivAuthGroup
    Write-Verbose "   -> Group exists: $PrivAuthGroupName"
} else {
    $PrivAuthGroupParams = @{
        DisplayName = $PrivAuthGroupName
        Description = "Security team responsible for identity and authentication management"
        MailEnabled = $false
        MailNickname = "identity-security-team"
        SecurityEnabled = $true
        IsAssignableToRole = $true
    }
    $PrivAuthGroup = New-MgGroup @PrivAuthGroupParams
    Write-Verbose "   -> Group created: $PrivAuthGroupName"
    Start-Sleep -Seconds $standardDelay
}

# Assign Privileged Authentication Administrator role to the group
Write-Verbose "[*] Assigning Privileged Authentication Administrator role to group..."
$PrivAuthAdminRoleId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" # PAA

$PrivAuthAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$PrivAuthAdminRoleId'" -ErrorAction SilentlyContinue
if (-not $PrivAuthAdminRole) {
    Write-Verbose "   -> Activating Privileged Authentication Administrator role..."
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $PrivAuthAdminRoleId
    $PrivAuthAdminRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}

# Check if group already has the role
$ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $PrivAuthAdminRole.Id -All -ErrorAction SilentlyContinue
$hasRole = $false
if ($ExistingMembers) {
    foreach ($member in $ExistingMembers) {
        if ($member.Id -eq $PrivAuthGroup.Id) {
            $hasRole = $true
            break
        }
    }
}

if (-not $hasRole) {
    try {
        $RoleMemberParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($PrivAuthGroup.Id)"
        }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $PrivAuthAdminRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
        Write-Verbose "   -> Privileged Authentication Administrator role assigned to group"
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "   -> Role already assigned"
        } else {
            Write-Verbose "   -> Failed to assign role: $($_.Exception.Message)"
        }
    }
} else {
    Write-Verbose "   -> Group already has Privileged Authentication Administrator role"
}

# Add target SP to Privileged Authentication Administrator group
Write-Verbose "[*] Adding target SP to Privileged Authentication Administrator group..."
# $groupMembers = Get-MgGroupMember -GroupId $PrivAuthGroup.Id -All -ErrorAction SilentlyContinue # Get-MgGroupMember doesn't show SPs on v1.0, so we use a direct API call instead
$groupMembers = (Invoke-MgGraphRequest -Uri "/beta/groups/$($PrivAuthGroup.Id)/members" -Method GET).value
$alreadyMember = $false

if ($groupMembers) {
    $alreadyMember = $groupMembers | Where-Object { $_.Id -eq $TargetSP.Id }
}

if ($alreadyMember) {
    Write-Verbose "   -> Target SP already member of Privileged Authentication Administrator group"
}
else {
    $memberRef = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/servicePrincipals/$($TargetSP.Id)"
    }
    try {
        New-MgGroupMemberByRef -GroupId $PrivAuthGroup.Id -BodyParameter $memberRef -ErrorAction Stop
        Write-Verbose "   -> Target SP added to Privileged Authentication Administrator group"
        Write-Verbose "   -> Waiting for membership to propagate..."
        Start-Sleep -Seconds $longReplicationDelay
    }
    catch {
        # Check if the error is about duplicate member
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "   -> Target SP already member (caught in exception)"
            # force alreadyMember to true so verification passes
            $alreadyMember = $true
        } else {
            Write-Verbose "   -> Failed to add SP to group: $($_.Exception.Message)"
        }
    }
}
#endregion

#region Create Dummy Users for Realism
Write-Verbose "[*] Creating dummy users for realistic environment..."

# Create dummy IT users
$dummyUsers = @(
    @{
        DisplayName = "Emily Rodriguez"
        UserPrincipalName = "emily.rodriguez@$TenantDomain"
        MailNickname = "emily.rodriguez"
        Department = "IT Operations"
        JobTitle = "Senior System Administrator"
    },
    @{
        DisplayName = "James Wilson"
        UserPrincipalName = "james.wilson@$TenantDomain"
        MailNickname = "james.wilson"
        Department = "Application Development"
        JobTitle = "Application Developer"
    },
    @{
        DisplayName = "Lisa Chang"
        UserPrincipalName = "lisa.chang@$TenantDomain"
        MailNickname = "lisa.chang"
        Department = "Security Operations"
        JobTitle = "Security Engineer"
    },
    @{
        DisplayName = "Robert Taylor"
        UserPrincipalName = "robert.taylor@$TenantDomain"
        MailNickname = "robert.taylor"
        Department = "Identity Management"
        JobTitle = "Identity Architect"
    }
)

$createdDummyUsers = @()
foreach ($dummyUser in $dummyUsers) {
    $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($dummyUser.UserPrincipalName)'" -ErrorAction SilentlyContinue
    if (-not $existingUser) {
        $userParams = $dummyUser + @{
            AccountEnabled = $true
            PasswordProfile = @{
                ForceChangePasswordNextSignIn = $false
                Password = "DummyP@ssw0rd$(Get-Random -Maximum 9999)"
            }
        }
        $newUser = New-MgUser @userParams
        $createdDummyUsers += $newUser
        Write-Verbose "   -> Created dummy user: $($dummyUser.DisplayName)"
    } else {
        $createdDummyUsers += $existingUser
        Write-Verbose "   -> Dummy user exists: $($dummyUser.DisplayName)"
    }
}

# Add Emily and James to App Admin group
Write-Verbose "[*] Adding dummy members to groups..."
$appAdminMembers = @($createdDummyUsers[0], $createdDummyUsers[1])  # Emily and James
foreach ($member in $appAdminMembers) {
    $currentMembers = Get-MgGroupMember -GroupId $AppAdminGroup.Id -All -ErrorAction SilentlyContinue
    $isMember = $currentMembers | Where-Object { $_.Id -eq $member.Id }
    
    if (-not $isMember) {
        $memberParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($member.Id)"
        }
        try {
            New-MgGroupMemberByRef -GroupId $AppAdminGroup.Id -BodyParameter $memberParams
            Write-Verbose "   -> Added $($member.DisplayName) to IT Application Managers"
        } catch {
            Write-Verbose "   -> $($member.DisplayName) already in group"
        }
    }
}

# Add Lisa and Robert to PAA group
$privAuthMembers = @($createdDummyUsers[2], $createdDummyUsers[3])  # Lisa and Robert
foreach ($member in $privAuthMembers) {
    $currentMembers = Get-MgGroupMember -GroupId $PrivAuthGroup.Id -All -ErrorAction SilentlyContinue
    $isMember = $currentMembers | Where-Object { $_.Id -eq $member.Id }
    
    if (-not $isMember) {
        $memberParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($member.Id)"
        }
        try {
            New-MgGroupMemberByRef -GroupId $PrivAuthGroup.Id -BodyParameter $memberParams
            Write-Verbose "   -> Added $($member.DisplayName) to Identity Security Team"
        } catch {
            Write-Verbose "   -> $($member.DisplayName) already in group"
        }
    }
}

Start-Sleep -Seconds $standardDelay  # Let memberships settle
#endregion

#region Set Low-Priv User as Owner of App Admin Group (THE MISCONFIGURATION)
Write-Verbose "[!] CREATING MISCONFIGURATION: Setting IT support user as owner of App Admin group..."

$ExistingOwners = Get-MgGroupOwner -GroupId $AppAdminGroup.Id
$IsAlreadyOwner = $false
if ($ExistingOwners) {
    foreach ($owner in $ExistingOwners) {
        if ($owner.Id -eq $LowPrivUser.Id) {
            $IsAlreadyOwner = $true
            break
        }
    }
}

if (-not $IsAlreadyOwner) {
    $OwnerParams = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($LowPrivUser.Id)"
    }
    New-MgGroupOwnerByRef -GroupId $AppAdminGroup.Id -BodyParameter $OwnerParams
    Write-Verbose "   -> Ownership granted (vulnerability created)"
    Start-Sleep -Seconds $standardDelay
} else {
    Write-Verbose "   -> Already owner (vulnerability exists)"
}
#endregion

#region Final Verification
Write-Verbose "[*] Running final verification..."

# Verify group ownership
$owners = Get-MgGroupOwner -GroupId $AppAdminGroup.Id
$ownerCheck = $false
foreach ($owner in $owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $ownerCheck = $true
        break
    }
}
if ($ownerCheck) {
    Write-Verbose "   -> [+] IT support user owns Application Administrator group"
} else {
    Write-Verbose "   -> [-] IT support user does NOT own group"
}

# Verify SP membership in priv auth group
$privAuthMembers = Get-MgGroupMember -GroupId $PrivAuthGroup.Id -All -ErrorAction SilentlyContinue
$spMemberCheck = $false
if ($privAuthMembers) {
    foreach ($member in $privAuthMembers) {
        if ($member.Id -eq $TargetSP.Id) {
            $spMemberCheck = $true
            break
        }
    }
}

# If we couldn't verify but got "already exists" error, consider it successful
if (-not $spMemberCheck -and $alreadyMember) {
    $spMemberCheck = $true
}
if ($spMemberCheck) {
    Write-Verbose "   -> [+] Target SP is member of Privileged Auth Admin group"
} else {
    Write-Verbose "   -> [-] Target SP is NOT member of Privileged Auth Admin group"
    Write-Verbose "   -> This might be a timing issue. Try running the script again."
}

$SetupSuccessful = $ownerCheck #-and $spMemberCheck
#endregion

#region Output Summary
if ($VerbosePreference -eq 'Continue') {
    Write-Host "`n" -NoNewline
    Write-Host "--------------------------------------------------------------" -ForegroundColor Green
    Write-Host "                      SCENARIO 3 SETUP                         " -ForegroundColor Green
    Write-Host "--------------------------------------------------------------" -ForegroundColor Green

    Write-Host "`nEXPLOITATION CHAIN:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  - IT support user owns Application Administrator group" -ForegroundColor White
    Write-Host "  - Can add self to group to gain Application Administrator" -ForegroundColor White
    Write-Host "  - Target SP is member of Privileged Auth Admin group" -ForegroundColor White
    Write-Host "  - Can add credentials to target SP" -ForegroundColor White
    Write-Host "  - Can reset Global Admin password" -ForegroundColor White

    Write-Host "`nGROUPS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  App Admin Group: $AppAdminGroupName (ID: $($AppAdminGroup.Id))" -ForegroundColor Cyan
    Write-Host "  Priv Auth Group: $PrivAuthGroupName (ID: $($PrivAuthGroup.Id))" -ForegroundColor Cyan

    Write-Host "`nSERVICE PRINCIPAL:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Target SP: $TargetAppName (ID: $($TargetSP.Id))" -ForegroundColor Cyan

    Write-Host "`nFLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host ""
} else {
    # Minimal output for CTF players
    Write-Host "`n" -NoNewline
    if ($SetupSuccessful) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "Scenario 3 setup completed successfully" -ForegroundColor White
        Write-Host ""
        Write-Host " Objective: Chain group features to escalate privileges and authentication as the target user to retrieve the flag." -ForegroundColor Gray
        Write-Host ""
        Write-Host "`nYOUR CREDENTIALS:" -ForegroundColor Red
        Write-Host "----------------------------" -ForegroundColor DarkGray
        Write-Host "  Username: " -ForegroundColor White -NoNewline
        Write-Host "$LowPrivUPN" -ForegroundColor Cyan
        Write-Host "  Password: " -ForegroundColor White -NoNewline
        Write-Host "$LowPrivPassword" -ForegroundColor Cyan

        Write-Host "`nTARGET:" -ForegroundColor Magenta
        Write-Host "----------------------------" -ForegroundColor DarkGray
        Write-Host "  Username: " -ForegroundColor White -NoNewline
        Write-Host "$AdminUPN" -ForegroundColor Cyan
        Write-Host "  Flag Location: " -ForegroundColor White -NoNewline
        Write-Host "extensionAttribute1" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Hint: Owning a group isn't harmless, right?" -ForegroundColor DarkGray

    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 3 setup failed - give it another shot or run with -Verbose flag to reveal more for debugging (spoiler alert???)." -ForegroundColor White
}
Write-Host ""
}
#endregion