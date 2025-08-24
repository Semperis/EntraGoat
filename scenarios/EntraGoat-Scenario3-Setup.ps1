<#

.SYNOPSIS
EntraGoat Scenario 3: Group MemberShipwreck - Sailed into Admin Waters
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
$AIGroupName = "AI Development Team"
$AttackSimGroupName = "Security Testing Team" 
$NetworkGroupName = "Network Operations Team"
$NormalGroup1Name = "Marketing Team"
$NormalGroup2Name = "Finance Department"
$Flag = "EntraGoat{Gr0up_Ch@1n_Pr1v_Esc@l@t10n!}"
$AdminPassword = "ComplexAdminP@ssw0rd#2025!"
$LowPrivPassword = "GoatAccess!123"
$standardDelay = 5 
$longReplicationDelay = 10

# Role template IDs 
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
$AIAdminRoleId = "d2562ede-74db-457e-a7b6-544e236ebb61"
$AttackSimAdminRoleId = "c430b396-e693-46cc-96f3-db01bf8bb62a"
$NetworkAdminRoleId = "d37c8bed-0711-4417-ba38-b4abe66ce4c2"
$AppAdminRoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
$PrivAuthAdminRoleId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"


Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 3 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|       Group MemberShipwreck - Sailed into Admin Waters       |" -ForegroundColor Cyan
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
    if (-not (Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
        $MissingModules += $moduleName
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Warning "The following required modules are not installed: $($MissingModules -join ', ')."
    $choice = Read-Host "Do you want to attempt to install them from PowerShell Gallery? (Y/N)"
    if ($choice -eq 'Y') {
        try {
            Write-Host "Attempting to install $($MissingModules -join ', ') from PowerShell Gallery. This may take a moment..." -ForegroundColor Yellow
            Install-Module -Name $MissingModules -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop -Verbose:$false
            Write-Verbose "[+] Successfully attempted to install missing modules."
            foreach ($moduleName in $MissingModules) {
                Import-Module $moduleName -ErrorAction SilentlyContinue -Verbose:$false
                if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
                    throw "Failed to import $moduleName"
                }
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
        if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
            try {
                Import-Module $moduleName -ErrorAction SilentlyContinue -Verbose:$false
                if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
                    throw "Failed to import $moduleName"
                }
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

#region Helper Functions
function New-EntraGoatGroup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$true)]
        [string]$MailNickname,
        
        [Parameter(Mandatory=$false)]
        [string]$RoleTemplateId = $null,
        
        [Parameter(Mandatory=$false)]
        [bool]$IsAssignableToRole = $true
    )
    
    Write-Verbose "[*] Creating $GroupName group..."
    $ExistingGroup = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    
    if ($ExistingGroup) {
        $Group = $ExistingGroup
        Write-Verbose "   -> Group exists: $GroupName"
    } else {
        $GroupParams = @{
            DisplayName = $GroupName
            Description = $Description
            MailEnabled = $false
            MailNickname = $MailNickname
            SecurityEnabled = $true
            IsAssignableToRole = $IsAssignableToRole
        }
        $Group = New-MgGroup @GroupParams
        Write-Verbose "   -> Group created: $GroupName"
        Start-Sleep -Seconds $standardDelay
    }
    
    # Assign role if specified
    if ($RoleTemplateId) {
        Write-Verbose "[*] Assigning role to $GroupName group..."
        $Role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$RoleTemplateId'" -ErrorAction SilentlyContinue
        if (-not $Role) {
            Write-Verbose "   -> Activating role template..."
            $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $RoleTemplateId
            $Role = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
            Start-Sleep -Seconds $standardDelay
        }
        
        # Check if group already has the role
        $ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction SilentlyContinue
        $hasRole = $false
        if ($ExistingMembers) {
            foreach ($member in $ExistingMembers) {
                if ($member.Id -eq $Group.Id) {
                    $hasRole = $true
                    break
                }
            }
        }
        
        if (-not $hasRole) {
            try {
                $RoleMemberParams = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($Group.Id)"
                }
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
                Write-Verbose "   -> Role assigned to $GroupName group"
                Start-Sleep -Seconds $longReplicationDelay
            } catch {
                if ($_.Exception.Message -like "*already exist*") {
                    Write-Verbose "   -> Role already assigned"
                } else {
                    Write-Verbose "   -> Failed to assign role: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "   -> Group already has role"
        }
    }
    
    return $Group
}

function New-EntraGoatUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory=$true)]
        [string]$MailNickname,
        
        [Parameter(Mandatory=$true)]
        [string]$Password,
        
        [Parameter(Mandatory=$false)]
        [string]$Department = "",
        
        [Parameter(Mandatory=$false)]
        [string]$JobTitle = ""
    )
    
    Write-Verbose "   -> $DisplayName`: $UserPrincipalName"
    $ExistingUser = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
    
    if ($ExistingUser) {
        $User = $ExistingUser
        Write-Verbose "      EXISTS (using existing)"
        # Update password to ensure we know it
        $passwordProfile = @{
            Password = $Password
            ForceChangePasswordNextSignIn = $false
        }
        Update-MgUser -UserId $User.Id -PasswordProfile $passwordProfile
    } else {
        $UserParams = @{
            DisplayName = $DisplayName
            UserPrincipalName = $UserPrincipalName
            MailNickname = $MailNickname
            AccountEnabled = $true
            PasswordProfile = @{
                ForceChangePasswordNextSignIn = $false
                Password = $Password
            }
        }
        
        if ($Department) { $UserParams.Department = $Department }
        if ($JobTitle) { $UserParams.JobTitle = $JobTitle }
        
        $User = New-MgUser @UserParams
        Write-Verbose "      CREATED"
        Start-Sleep -Seconds $standardDelay
    }
    
    return $User
}

function Set-GroupOwnership {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Group,
        
        [Parameter(Mandatory=$true)]
        [object]$User,
        
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    Write-Verbose "[*] Setting ownership for $GroupName group..."
    $ExistingOwners = Get-MgGroupOwner -GroupId $Group.Id
    $IsAlreadyOwner = $false
    if ($ExistingOwners) {
        foreach ($owner in $ExistingOwners) {
            if ($owner.Id -eq $User.Id) {
                $IsAlreadyOwner = $true
                break
            }
        }
    }
    
    if (-not $IsAlreadyOwner) {
        $OwnerParams = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($User.Id)"
        }
        New-MgGroupOwnerByRef -GroupId $Group.Id -BodyParameter $OwnerParams
        Write-Verbose "   -> Ownership granted for $GroupName"
        Start-Sleep -Seconds $standardDelay
    } else {
        Write-Verbose "   -> Already owner of $GroupName"
    }
}

function New-EntraGoatApplication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$false)]
        [string]$SignInAudience = "AzureADMyOrg",
        
        [Parameter(Mandatory=$false)]
        [array]$RedirectUris = @("https://identity-portal.contoso.com/callback"),
        
        [Parameter(Mandatory=$false)]
        [array]$Tags = @("WindowsAzureActiveDirectoryIntegratedApp")
    )
    
    Write-Verbose "[*] Creating application: $DisplayName"
    $ExistingApp = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    
    if ($ExistingApp) {
        $App = $ExistingApp
        Write-Verbose "   -> Application exists: $DisplayName"
    } else {
        $AppParams = @{
            DisplayName = $DisplayName
            SignInAudience = $SignInAudience
            Description = $Description
            Web = @{
                RedirectUris = $RedirectUris
            }
        }
        $App = New-MgApplication @AppParams
        Write-Verbose "   -> Application created: $DisplayName"
        Start-Sleep -Seconds $standardDelay
    }
    
    # Get App ID
    $AppId = $App.AppId
    if ($AppId -is [array]) { $AppId = $AppId[0] }
    $AppId = $AppId.ToString()
    
    # Create service principal
    Write-Verbose "[*] Creating service principal for $DisplayName..."
    $ExistingSP = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
    
    if ($ExistingSP) {
        $SP = $ExistingSP
        Write-Verbose "   -> Service principal exists"
    } else {
        $SPParams = @{
            AppId = $AppId
            DisplayName = $DisplayName
        }
        $SP = New-MgServicePrincipal @SPParams
        Write-Verbose "   -> Service principal created"
        Start-Sleep -Seconds $standardDelay
    }
    
    # Apply tags to make it visible in Azure Portal UI
    if ($Tags) {
        Update-MgServicePrincipal -ServicePrincipalId $SP.Id -Tags $Tags
    }
    
    return @{
        Application = $App
        ServicePrincipal = $SP
        AppId = $AppId
    }
}


#endregion

#region User Creation
Write-Verbose "[*] Setting up users..."
$LowPrivUPN = "michael.chen@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s3@$TenantDomain"

# Create users
$LowPrivUser = New-EntraGoatUser -DisplayName "Michael Chen" -UserPrincipalName $LowPrivUPN -MailNickname "michael.chen" -Password $LowPrivPassword -Department "IT Support" -JobTitle "IT Support Specialist"
$AdminUser = New-EntraGoatUser -DisplayName "EntraGoat Administrator S3" -UserPrincipalName $AdminUPN -MailNickname "entragoat-admin-s3" -Password $AdminPassword -Department "IT Administration" -JobTitle "System Administrator"
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
    Write-Verbose "   -> Flag stored successfully."
} catch {
    Write-Verbose "   -> Flag already set or minor error (continuing): $($_.Exception.Message)"
}
#endregion

#region Assign Global Administrator Role to Admin User
Write-Verbose "[*] Assigning Global Administrator role to admin user ($AdminUPN)..."
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
$AppAdminGroup = New-EntraGoatGroup -GroupName $AppAdminGroupName -Description "Team responsible for managing enterprise applications" -MailNickname "it-app-managers" -RoleTemplateId $AppAdminRoleId
#endregion

#region Target application registration and service principal
$TargetAppResult = New-EntraGoatApplication -DisplayName $TargetAppName -Description "Portal for managing user identities and access"
$TargetApp = $TargetAppResult.Application
$TargetSP = $TargetAppResult.ServicePrincipal
$TargetAppId = $TargetAppResult.AppId

# Grant Directory.Read.All to target SP for enumeration (scenario-specific)
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
} else {
    Write-Verbose "   -> Directory.Read.All already granted"
}
#endregion

#region Create Privileged Authentication Administrator Group
$PrivAuthGroup = New-EntraGoatGroup -GroupName $PrivAuthGroupName -Description "Security team responsible for identity and authentication management" -MailNickname "identity-security-team" -RoleTemplateId $PrivAuthAdminRoleId

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

#region Create Additional Groups with Unprivileged Roles
Write-Verbose "[*] Creating additional groups with unprivileged roles..."

# Create AI Development Team group
$AIGroup = New-EntraGoatGroup -GroupName $AIGroupName -Description "Team responsible for AI and machine learning initiatives" -MailNickname "ai-dev-team" -RoleTemplateId $AIAdminRoleId

# Create Security Testing Team group
$AttackSimGroup = New-EntraGoatGroup -GroupName $AttackSimGroupName -Description "Team responsible for security testing and attack simulations" -MailNickname "security-testing-team" -RoleTemplateId $AttackSimAdminRoleId

# Create Network Operations Team group
$NetworkGroup = New-EntraGoatGroup -GroupName $NetworkGroupName -Description "Team responsible for network infrastructure and operations" -MailNickname "network-operations-team" -RoleTemplateId $NetworkAdminRoleId
#endregion

#region Create Normal Groups Without Roles
Write-Verbose "[*] Creating normal groups without roles..."

# Create Marketing Team group
$NormalGroup1 = New-EntraGoatGroup -GroupName $NormalGroup1Name -Description "Team responsible for marketing and communications" -MailNickname "marketing-team" -IsAssignableToRole $false

# Create Finance Department group
$NormalGroup2 = New-EntraGoatGroup -GroupName $NormalGroup2Name -Description "Department responsible for financial operations and budgeting" -MailNickname "finance-department" -IsAssignableToRole $false
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
    $dummyPassword = "DummyP@ssw0rd$(Get-Random -Maximum 9999)"
    $newUser = New-EntraGoatUser -DisplayName $dummyUser.DisplayName -UserPrincipalName $dummyUser.UserPrincipalName -MailNickname $dummyUser.MailNickname -Password $dummyPassword -Department $dummyUser.Department -JobTitle $dummyUser.JobTitle
    $createdDummyUsers += $newUser
}

# Add dummy users to App Admin group
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

Start-Sleep -Seconds $standardDelay  # Let memberships settle and propagate
#endregion

#region Set Low-Priv User as Owner of Groups (THE MISCONFIGURATION)
Write-Verbose "[!] CREATING MISCONFIGURATION: Setting IT support user as owner of IT Application Managers group..."

# Set ownership for all groups
Set-GroupOwnership -Group $AppAdminGroup -User $LowPrivUser -GroupName "IT Application Managers"
Set-GroupOwnership -Group $AIGroup -User $LowPrivUser -GroupName "AI Development Team"
Set-GroupOwnership -Group $AttackSimGroup -User $LowPrivUser -GroupName "Security Testing Team"
Set-GroupOwnership -Group $NetworkGroup -User $LowPrivUser -GroupName "Network Operations Team"
Set-GroupOwnership -Group $NormalGroup1 -User $LowPrivUser -GroupName "Marketing Team"
Set-GroupOwnership -Group $NormalGroup2 -User $LowPrivUser -GroupName "Finance Department"
#endregion

#region Final Verification
Write-Verbose "[*] Running final verification..."

# Verify group ownership for all groups
$ownerChecks = @()

# Check IT Application Managers group ownership
$owners = Get-MgGroupOwner -GroupId $AppAdminGroup.Id
$ownerCheck = $false
foreach ($owner in $owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $ownerCheck = $true
        break
    }
}
$ownerChecks += $ownerCheck
if ($ownerCheck) {
    Write-Verbose "   -> [+] IT support user owns Application Administrator group"
} else {
    Write-Verbose "   -> [-] IT support user does NOT own Application Administrator group"
}

# Check AI Development Team group ownership
$owners = Get-MgGroupOwner -GroupId $AIGroup.Id
$ownerCheck = $false
foreach ($owner in $owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $ownerCheck = $true
        break
    }
}
$ownerChecks += $ownerCheck
if ($ownerCheck) {
    Write-Verbose "   -> [+] IT support user owns AI Development Team group"
} else {
    Write-Verbose "   -> [-] IT support user does NOT own AI Development Team group"
}

# Check Security Testing Team group ownership
$owners = Get-MgGroupOwner -GroupId $AttackSimGroup.Id
$ownerCheck = $false
foreach ($owner in $owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $ownerCheck = $true
        break
    }
}
$ownerChecks += $ownerCheck
if ($ownerCheck) {
    Write-Verbose "   -> [+] IT support user owns Security Testing Team group"
} else {
    Write-Verbose "   -> [-] IT support user does NOT own Security Testing Team group"
}

# Check Network Operations Team group ownership
$owners = Get-MgGroupOwner -GroupId $NetworkGroup.Id
$ownerCheck = $false
foreach ($owner in $owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $ownerCheck = $true
        break
    }
}
$ownerChecks += $ownerCheck
if ($ownerCheck) {
    Write-Verbose "   -> [+] IT support user owns Network Operations Team group"
} else {
    Write-Verbose "   -> [-] IT support user does NOT own Network Operations Team group"
}

# Check Marketing Team group ownership
$owners = Get-MgGroupOwner -GroupId $NormalGroup1.Id
$ownerCheck = $false
foreach ($owner in $owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $ownerCheck = $true
        break
    }
}
$ownerChecks += $ownerCheck
if ($ownerCheck) {
    Write-Verbose "   -> [+] IT support user owns Marketing Team group"
} else {
    Write-Verbose "   -> [-] IT support user does NOT own Marketing Team group"
}

# Check Finance Department group ownership
$owners = Get-MgGroupOwner -GroupId $NormalGroup2.Id
$ownerCheck = $false
foreach ($owner in $owners) {
    if ($owner.Id -eq $LowPrivUser.Id) {
        $ownerCheck = $true
        break
    }
}
$ownerChecks += $ownerCheck
if ($ownerCheck) {
    Write-Verbose "   -> [+] IT support user owns Finance Department group"
} else {
    Write-Verbose "   -> [-] IT support user does NOT own Finance Department group"
}

Start-Sleep -Seconds $standardDelay

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

$SetupSuccessful = ($ownerChecks -notcontains $false) #-and $spMemberCheck
#endregion

#region Output Summary
if ($VerbosePreference -eq 'Continue') {
    Write-Host ""
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host "|             SCENARIO 3 SETUP COMPLETED (VERBOSE)             |" -ForegroundColor Cyan
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "`nGROUPS OWNED BY IT SUPPORT USER:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  App Admin Group: $AppAdminGroupName (ID: $($AppAdminGroup.Id))" -ForegroundColor Cyan
    Write-Host "  AI Admin Group: $AIGroupName (ID: $($AIGroup.Id))" -ForegroundColor Cyan
    Write-Host "  Attack Sim Group: $AttackSimGroupName (ID: $($AttackSimGroup.Id))" -ForegroundColor Cyan
    Write-Host "  Network Admin Group: $NetworkGroupName (ID: $($NetworkGroup.Id))" -ForegroundColor Cyan
    Write-Host "  Marketing Group: $NormalGroup1Name (ID: $($NormalGroup1.Id))" -ForegroundColor Cyan
    Write-Host "  Finance Group: $NormalGroup2Name (ID: $($NormalGroup2.Id))" -ForegroundColor Cyan
    
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

    Write-Host "`nSERVICE PRINCIPAL:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Target SP: $TargetAppName (ID: $($TargetSP.Id))" -ForegroundColor Cyan

    Write-Host "`nFLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host ""
} else {
    # Minimal output for CTF players
    Write-Host ""
    if ($SetupSuccessful) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "Scenario 3 setup completed successfully" -ForegroundColor White
        Write-Host ""
        Write-Host "Objective: Sign in as the admin user and retrieve the flag." -ForegroundColor Gray
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
        Write-Host "Scenario 3 setup failed - give it another shot or run with -Verbose flag to reveal more for debugging (spoiler alert!)." -ForegroundColor White
}
Write-Host ""
}
#endregion