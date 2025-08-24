<#

.SYNOPSIS
EntraGoat Scenario 4: I (Eligibly) Own That
Setup script to be run with Global Administrator privileges 

#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$AppAdminGroupName = "Application Operations Team"  
$PrivAuthGroupName = "Global Infrastructure Team"   
$TargetAppName = "Infrastructure Monitoring Tool"   
$Flag = "EntraGoat{PIM_Gr0up_Pr1v_Esc@l@t10n_2025!}"
$AdminPassword = "ComplexAdminP@ssw0rd#2025!"
$LowPrivPassword = "GoatAccess!123"
$standardDelay = 5 # Seconds
$longReplicationDelay = 15

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|         ENTRAGOAT SCENARIO 4 - SETUP INITIALIZATION          |" -ForegroundColor Cyan
Write-Host "|                    I (Eligibly) Own That                     |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

#region Module Check and Import
Write-Verbose "[*] Checking and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.Governance"
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
            # Import them after installation
            foreach ($moduleName in $MissingModules) {
                Import-Module $moduleName -ErrorAction SilentlyContinue -Verbose:$false
                if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
                    throw "Failed to import $moduleName"
                }
                Write-Verbose "   Imported $moduleName"
            }
        } catch {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to automatically install or import modules: $($MissingModules -join ', '). Please install them manually (e.g., Install-Module -Name Microsoft.Graph -Scope CurrentUser) and re-run the script. Error: $($_.Exception.Message)"
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
        if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
            try {
                Import-Module $moduleName -ErrorAction SilentlyContinue -Verbose:$false
                if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
                    throw "Failed to import $moduleName"
                }
                Write-Verbose "[+] Imported module $moduleName."
            } catch {
                Write-Host "[-] " -ForegroundColor Red -NoNewline
                Write-Host "Failed to import module $moduleName. Error: $($_.Exception.Message)"
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

$RequiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "PrivilegedAccess.ReadWrite.AzureADGroup"
)

try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
    }
    # $Context = Get-MgContext 
    $Organization = Get-MgOrganization
    $TenantDomain = ($Organization.VerifiedDomains | Where-Object IsDefault).Name

    Write-Verbose "[+] Connected to tenant: $TenantDomain"
} catch {
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host "Failed to connect: $($_.Exception.Message)" 
    exit 1
}
#endregion

#region Helper Functions
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

function New-EntraGoatApplication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$false)]
        [string]$SignInAudience = "AzureADMyOrg",
        
        [Parameter(Mandatory=$false)]
        [array]$RedirectUris = @(),
        
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
        }
        if ($RedirectUris) {
            $AppParams.Web = @{
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
        if ($Tags) {
            Update-MgServicePrincipal -ServicePrincipalId $SP.Id -Tags $Tags -ErrorAction SilentlyContinue
            Write-Verbose "   -> Updated tags"
        }
    } else {
        $SPParams = @{
            AppId = $AppId
            DisplayName = $DisplayName
        }
        $SP = New-MgServicePrincipal @SPParams
        Write-Verbose "   -> Service principal created"
        Start-Sleep -Seconds $standardDelay
        if ($Tags) {
            Update-MgServicePrincipal -ServicePrincipalId $SP.Id -Tags $Tags
        }
    }
    
    return @{
        Application = $App
        ServicePrincipal = $SP
        AppId = $AppId
    }
}

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
    
    Write-Verbose "[*] Creating group: $GroupName"
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
        Write-Verbose "[*] Assigning role to group..."
        $DirectoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$RoleTemplateId'" -ErrorAction SilentlyContinue
        if (-not $DirectoryRole) {
            Write-Verbose "   -> Activating role template..."
            $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $RoleTemplateId
            $DirectoryRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
            Start-Sleep -Seconds $standardDelay
        }
        
        $ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRole.Id -All -ErrorAction SilentlyContinue
        $IsAlreadyAssigned = $false
        if ($ExistingMembers) {
            foreach ($member in $ExistingMembers) {
                if ($member.Id -eq $Group.Id) {
                    $IsAlreadyAssigned = $true
                    break
                }
            }
        }
        
        if (-not $IsAlreadyAssigned) {
            try {
                $RoleMemberParams = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($Group.Id)"
                }
                New-MgDirectoryRoleMemberByRef -DirectoryRoleId $DirectoryRole.Id -BodyParameter $RoleMemberParams -ErrorAction Stop
                Write-Verbose "   -> Role assigned successfully"
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
#endregion

#region User Account Creation
Write-Verbose "[*] Creating user accounts..."
$LowPrivUPN = "woody.chen@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s4@$TenantDomain"

# Create users using helper function
$LowPrivUser = New-EntraGoatUser -DisplayName "Woody" -UserPrincipalName $LowPrivUPN -MailNickname "woody.chen" -Password $LowPrivPassword -Department "IT Support" -JobTitle "IT Support Specialist"
$AdminUser = New-EntraGoatUser -DisplayName "EntraGoat Administrator S4" -UserPrincipalName $AdminUPN -MailNickname "entragoat-admin-s4" -Password $AdminPassword -Department "IT Administration" -JobTitle "Global Administrator"
#endregion

#region Flag Storage
Write-Verbose "[*] Storing flag in admin user extension attributes..."
try {
    $ExtensionParams = @{
        OnPremisesExtensionAttributes = @{
            ExtensionAttribute1 = $Flag
        }
    }
    Update-MgUser -UserId $AdminUser.Id -BodyParameter $ExtensionParams -ErrorAction Stop
    Write-Verbose "Flag stored in extensionAttribute1"
} catch {
    Write-Verbose "Flag storage error (continuing): $($_.Exception.Message)"
}
#endregion

#region Global Administrator Role Assignment
Write-Verbose "[*] Assigning Global Administrator role to target admin..."
$GlobalAdminRoleTemplateId = "62e90394-69f5-4237-9190-012177145e10"
$GlobalAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GlobalAdminRoleTemplateId'" -ErrorAction SilentlyContinue

if (-not $GlobalAdminRole) {
    Write-Verbose "Activating Global Administrator role template"
    $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $GlobalAdminRoleTemplateId
    $GlobalAdminRole = New-MgDirectoryRole -RoleTemplateId $RoleTemplate.Id
    Start-Sleep -Seconds $standardDelay
}

$ExistingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id -All -ErrorAction SilentlyContinue
$IsGlobalAdmin = $false
if ($ExistingMembers) {
    foreach ($member in $ExistingMembers) {
        if ($member.Id -eq $AdminUser.Id) {
            $IsGlobalAdmin = $true
            break
        }
    }
}

if (-not $IsGlobalAdmin) {
    Write-Verbose "Assigning Global Administrator role"
    try {
        $RoleMemberRef = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($AdminUser.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $GlobalAdminRole.Id -BodyParameter $RoleMemberRef -ErrorAction Stop
        Write-Verbose "Global Administrator role assigned"
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "Role already assigned"
        } else {
            Write-Host "[-] Global Administrator assignment failed: $($_.Exception.Message)" 
        }
    }
} else {
    Write-Verbose "User already has Global Administrator role"
}
#endregion

#region Application Administrator Group Creation
Write-Verbose "[*] Creating Application Administrator group..."
$AppAdminGroup = New-EntraGoatGroup -GroupName $AppAdminGroupName -Description "Team responsible for operating enterprise applications" -MailNickname "it-ops-app-managers"

# Create ELIGIBLE Application Administrator role assignment
Write-Verbose "[*] Creating eligible Application Administrator role assignment..."
$AppAdminRoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"

$ExistingEligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($AppAdminGroup.Id)' and roleDefinitionId eq '$AppAdminRoleId'" -ErrorAction SilentlyContinue

if (-not $ExistingEligible) {
    try {
        Write-Verbose "    ->  Creating eligible role assignment for group..."
        $EligibilityRequestParams = @{
            Action = "adminAssign"
            PrincipalId = $AppAdminGroup.Id
            RoleDefinitionId = $AppAdminRoleId
            DirectoryScopeId = "/"
            Justification = "EntraGoat PIM scenario - eligible role assignment"
            ScheduleInfo = @{
                StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                Expiration = @{
                    Type = "noExpiration"
                }
            }
        }
        
        $EligibleRoleResult = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $EligibilityRequestParams -ErrorAction Stop
        Write-Verbose "[+] Eligible Application Administrator role created successfully"
        Write-Verbose "Request ID: $($EligibleRoleResult.Id)"
        Start-Sleep -Seconds $longReplicationDelay
        
    } catch {
        Write-Host "[!] Eligible role assignment failed: $($_.Exception.Message)" 
    }
} else {
    Write-Verbose "Eligible Application Administrator role already exists"
}
#endregion

#region Target application registration and service principal
Write-Verbose "[*] Creating target application and service principal..."
$TargetAppResult = New-EntraGoatApplication -DisplayName $TargetAppName -Description "Target application for privilege escalation scenario" -RedirectUris @("https://target-app-4.example.com/callback")
$TargetSP = $TargetAppResult.ServicePrincipal
$TargetAppId = $TargetAppResult.AppId

# Grant Directory.Read.All permission
Write-Verbose "[*] Granting Directory.Read.All permission..."
$GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$DirectoryReadRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "Directory.Read.All" }

$ExistingPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -All -ErrorAction SilentlyContinue
$HasDirectoryRead = $ExistingPermissions | Where-Object { $_.AppRoleId -eq $DirectoryReadRole.Id }

if (-not $HasDirectoryRead) {
    $PermissionParams = @{
        PrincipalId = $TargetSP.Id
        ResourceId = $GraphSP.Id
        AppRoleId = $DirectoryReadRole.Id
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -BodyParameter $PermissionParams | Out-Null
    Write-Verbose "    ->  Directory.Read.All permission granted"
    Start-Sleep -Seconds $standardDelay
}
#endregion

#region Global Administrator Group
Write-Verbose "[*] Creating Global Administrator group..."
$PrivAuthRoleId = "62e90394-69f5-4237-9190-012177145e10"
$PrivAuthGroup = New-EntraGoatGroup -GroupName $PrivAuthGroupName -Description "Group with Global Administrator privileges" -MailNickname "global-infra-team-4" -RoleTemplateId $PrivAuthRoleId

# Add service principal to Global Administrator group
Write-Verbose "[*] Adding service principal to Global Administrator group..."
$GroupMembers = (Invoke-MgGraphRequest -Uri "/beta/groups/$($PrivAuthGroup.Id)/members" -Method GET).value
$SPIsMember = $false

if ($GroupMembers) {
    $SPIsMember = $GroupMembers | Where-Object { $_.Id -eq $TargetSP.Id }
}

if ($SPIsMember) {
    Write-Verbose "Service principal already member"
} else {
    $memberRef = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/servicePrincipals/$($TargetSP.Id)"
    }
    try {
        New-MgGroupMemberByRef -GroupId $PrivAuthGroup.Id -BodyParameter $memberRef -ErrorAction Stop
        Write-Verbose "Service principal added to group"
        Write-Verbose "Waiting for membership propagation..."
        Start-Sleep -Seconds $longReplicationDelay
    } catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Verbose "Service principal already member"
            $SPIsMember = $true
        } else {
            Write-Verbose "    ->  Failed to add service principal: $($_.Exception.Message)"
        }
    }
}
#endregion

#region dummy Users
Write-Verbose "[*] Creating dummy users..."

$DummyUsers = @(
    @{
        DisplayName = "Sarah Martinez"
        UserPrincipalName = "sarah.martinez@$TenantDomain"
        MailNickname = "sarah.martinez"
        Department = "IT Security"
        JobTitle = "Security Analyst"
    },
    @{
        DisplayName = "David Kim"
        UserPrincipalName = "david.kim@$TenantDomain"
        MailNickname = "david.kim"
        Department = "Application Development"
        JobTitle = "Senior Developer"
    },
    @{
        DisplayName = "Jennifer Walsh"
        UserPrincipalName = "jennifer.walsh@$TenantDomain"
        MailNickname = "jennifer.walsh"
        Department = "Identity Management"
        JobTitle = "Identity Specialist"
    }
)

$CreatedUsers = @()
foreach ($user in $DummyUsers) {
    $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($user.UserPrincipalName)'" -ErrorAction SilentlyContinue
    if (-not $existingUser) {
        $userParams = $user + @{
            AccountEnabled = $true
            PasswordProfile = @{
                ForceChangePasswordNextSignIn = $false
                Password = "EnvP@ssw0rd$(Get-Random -Maximum 999)"
            }
        }
        $newUser = New-MgUser @userParams
        $CreatedUsers += $newUser
        Write-Verbose "Created: $($user.DisplayName)"
    } else {
        $CreatedUsers += $existingUser
        Write-Verbose "Exists: $($user.DisplayName)"
    }
}

# Add some users to groups for realism
Write-Verbose "[*] Adding users to groups for realistic environment..."
$UsersToAddToAppGroup = @($CreatedUsers[0], $CreatedUsers[1])  # Sarah and David
foreach ($user in $UsersToAddToAppGroup) {
    $CurrentMembers = Get-MgGroupMember -GroupId $AppAdminGroup.Id -All -ErrorAction SilentlyContinue
    $IsExistingMember = $CurrentMembers | Where-Object { $_.Id -eq $user.Id }
    
    if (-not $IsExistingMember) {
        $MemberRef = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($user.Id)"
        }
        try {
            New-MgGroupMemberByRef -GroupId $AppAdminGroup.Id -BodyParameter $MemberRef
            Write-Verbose "Added $($user.DisplayName) to $AppAdminGroupName"
        } catch {
            Write-Verbose "$($user.DisplayName) already in group"
        }
    }
}

# Add Jennifer to privileged auth group
$CurrentPrivMembers = Get-MgGroupMember -GroupId $PrivAuthGroup.Id -All -ErrorAction SilentlyContinue
$JenniferIsMember = $CurrentPrivMembers | Where-Object { $_.Id -eq $CreatedUsers[2].Id }

if (-not $JenniferIsMember) {
    $MemberRef = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($CreatedUsers[2].Id)"
    }
    try {
        New-MgGroupMemberByRef -GroupId $PrivAuthGroup.Id -BodyParameter $MemberRef
        Write-Verbose "Added Jennifer Walsh to $PrivAuthGroupName"
    } catch {
        Write-Verbose "Jennifer Walsh already in group"
    }
}

Start-Sleep -Seconds $standardDelay
#endregion

#region Create Eligible Group Ownership (THE MISCONFIGURATION)
Write-Verbose "[!] CREATING MISCONFIGURATION: Creating eligible group ownership..."

# Make the low-privileged user eligible owner of the Application Administrator group
Write-Verbose "Creating eligible ownership for '$LowPrivUPN' on '$AppAdminGroupName'..."

$eligibleOwnerParams = @{
    accessId          = "owner"
    principalId       = $LowPrivUser.Id
    groupId           = $AppAdminGroup.Id
    action            = "adminAssign"
    scheduleInfo      = @{
        startDateTime = (Get-Date).ToUniversalTime().ToString("o")
        expiration    = @{
            type = "afterDuration"
            duration = "P365D"  
        }
    }
    justification     = "Regional access coordination administrative privileges"
}

try {
    $ownershipResponse = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
        -Body ($eligibleOwnerParams | ConvertTo-Json -Depth 4) -ContentType "application/json"
    Write-Verbose "[+] Eligible ownership granted (vulnerability created)" 
    Write-Verbose "Assignment ID: $($ownershipResponse.id)"
    Write-Verbose "User '$LowPrivUPN' now has ELIGIBLE ownership of '$AppAdminGroupName'"
    Start-Sleep -Seconds $longReplicationDelay
} catch {
    Write-Verbose "[-] Failed to create eligible ownership. Please review the final verification checks to determine if ownership is already assigned. $($_.Exception.Message)" 
}

#endregion

#region Final Verification
Write-Verbose "[*] Performing final verification checks..."

# Check for PIM eligible group ownership
$PIMEligibleOwnership = $false
try {
    $EligibleOwnershipUri = "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($AppAdminGroup.Id)' and principalId eq '$($LowPrivUser.Id)' and accessId eq 'owner'"
    $EligibleResponse = Invoke-MgGraphRequest -Uri $EligibleOwnershipUri -Method GET
    
    if ($EligibleResponse.value -and $EligibleResponse.value.Count -gt 0) {
        $PIMEligibleOwnership = $true
        Write-Verbose "[+] PIM eligible group ownership found" 
    }
} catch {
    Write-Verbose "[-] PIM ownership check failed: $($_.Exception.Message)"
}

if ($PIMEligibleOwnership) {
    Write-Verbose "[+] PIM eligible group ownership verified"
} else {
    Write-Verbose "[-] No group ownership found"
}

# Verify eligible role assignment
$EligibleRole = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($AppAdminGroup.Id)' and roleDefinitionId eq '$AppAdminRoleId'" -ErrorAction SilentlyContinue
$EligibleRoleVerified = $EligibleRole -ne $null

if ($EligibleRoleVerified) {
    Write-Verbose "[+] Eligible Application Administrator role verified"
} else {
    Write-Verbose "[-] Application Administrator role verification failed"
}

# Verify service principal membership
$PrivGroupMembers = (Invoke-MgGraphRequest -Uri "/beta/groups/$($PrivAuthGroup.Id)/members" -Method GET -ErrorAction SilentlyContinue).value
$SPMembershipVerified = $false
if ($PrivGroupMembers) {
    foreach ($member in $PrivGroupMembers) {
        if ($member.Id -eq $TargetSP.Id) {
            $SPMembershipVerified = $true
            break
        }
    }
}

if ($SPMembershipVerified) {
    Write-Verbose "[+] Service principal membership verified" 
} else {
    Write-Verbose '[-] Service principal membership verification failed' 
}

$OverallSuccess = $PIMEligibleOwnership -and $EligibleRoleVerified
#endregion

#region Output Summary
if ($VerbosePreference -eq 'Continue') {
    # Verbose output with all details
    Write-Host ""
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host "|             SCENARIO 4 SETUP COMPLETED (VERBOSE)             |" -ForegroundColor Cyan
    Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "`nVULNERABILITY DETAILS:" -ForegroundColor Yellow
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  - Low-privileged user has eligible ownership of group" -ForegroundColor White
    Write-Host "  - Group has eligible Application Administrator role" -ForegroundColor White
    Write-Host "  - User can activate role through PIM" -ForegroundColor White
    Write-Host "  - Service principal has Global Administrator privileges via group membership" -ForegroundColor White

    Write-Host "`nATTACKER CREDENTIALS:" -ForegroundColor Red
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

    Write-Host "`nGROUPS:" -ForegroundColor Blue
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  App Admin Group: " -ForegroundColor White -NoNewline
    Write-Host "$AppAdminGroupName" -ForegroundColor Cyan
    Write-Host "  Group ID: " -ForegroundColor White -NoNewline
    Write-Host "$($AppAdminGroup.Id)" -ForegroundColor Cyan
    Write-Host "  Priv Auth Group: " -ForegroundColor White -NoNewline
    Write-Host "$PrivAuthGroupName" -ForegroundColor Cyan
    Write-Host "  Group ID: " -ForegroundColor White -NoNewline
    Write-Host "$($PrivAuthGroup.Id)" -ForegroundColor Cyan

    Write-Host "`nSERVICE PRINCIPAL:" -ForegroundColor Blue
    Write-Host "----------------------------" -ForegroundColor DarkGray
    Write-Host "  Name: " -ForegroundColor White -NoNewline
    Write-Host "$TargetAppName" -ForegroundColor Cyan
    Write-Host "  SP ID: " -ForegroundColor White -NoNewline
    Write-Host "$($TargetSP.Id)" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "FLAG: " -ForegroundColor Green -NoNewline
    Write-Host "$Flag" -ForegroundColor Cyan

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host ""
} else {
    # Minimal output for CTF players
    Write-Host ""
    if ($OverallSuccess) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "Scenario 4 setup completed successfully" -ForegroundColor White
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

        Write-Host "Hint: Authority can be hidden in plain sight, masked until someone chooses to activate it." -ForegroundColor DarkGray
    } else {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Scenario 4 setup failed - give it another shot or run with -Verbose flag to reveal more for debugging (spoiler alert)." -ForegroundColor White
    }
    Write-Host ""
}
#endregion