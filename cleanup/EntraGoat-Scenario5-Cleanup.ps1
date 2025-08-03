# EntraGoat Scenario 5: Cleanup Script
# To be run with Global Administrator privileges.

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups, Microsoft.Graph.DeviceManagement.Administration

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration - matching setup script
$CustomRoleName = "User Profile Administrator"
$SupportGroupName = "Tier-1 Support Team"
$PrivilegedGroupName = "Regional Access Coordinators"
$AUName = "HR Department"

$RequiredScopes = @(
    "RoleManagement.ReadWrite.Directory",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Group.ReadWrite.All",
    "AdministrativeUnit.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleAssignmentSchedule.ReadWrite.Directory"
)

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|           ENTRAGOAT SCENARIO 5 - CLEANUP PROCESS             |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

#region Module Check and Import
Write-Verbose "[*] Checking required Microsoft Graph modules..."
$RequiredCleanupModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications", "Microsoft.Graph.Users", "Microsoft.Graph.Identity.DirectoryManagement")
foreach ($moduleName in $RequiredCleanupModules) {
    if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
        try {
            Import-Module $moduleName -ErrorAction Stop
            Write-Verbose "[+] Imported module $moduleName."
        } catch {
            Write-Host "[-] " -ForegroundColor Red -NoNewline
            Write-Host "Failed to import module $moduleName. Please ensure Microsoft Graph SDK is installed. Error: $($_.Exception.Message)" -ForegroundColor White
            exit 1
        }
    }
}
#endregion

# Connect to Microsoft Graph
if ($TenantId) {
    Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId -NoWelcome
} else {
    Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
}

# Get Tenant Domain
$Organization = Get-MgOrganization
$TenantDomain = ($Organization.VerifiedDomains | Where-Object IsDefault).Name

# Target Objects - matching setup script
$SupportUPN = "sarah.connor@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s5@$TenantDomain"

$HRUserUPNs = @(
    "jessica.chen@$TenantDomain",
    "michael.rodriguez@$TenantDomain", 
    "amanda.thompson@$TenantDomain"
)

$RegionalUserUPNs = @(
    "david.wilson@$TenantDomain",
    "lisa.park@$TenantDomain"
)

$AllUserUPNs = @($SupportUPN, $AdminUPN) + $HRUserUPNs + $RegionalUserUPNs

# Remove PIM eligibilities first
Write-Host "Removing PIM eligibilities..." -ForegroundColor Cyan

# Remove group eligibilities via beta endpoint
$SupportUser = Get-MgUser -Filter "userPrincipalName eq '$SupportUPN'" -ErrorAction SilentlyContinue
if ($SupportUser) {
    try {
        # Get all group eligibilities
        $eligibilities = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '$($SupportUser.Id)'" -ErrorAction Stop
        
        foreach ($eligibility in $eligibilities.value) {
            try {
                $removeParams = @{
                    accessId = $eligibility.accessId
                    principalId = $eligibility.principalId
                    groupId = $eligibility.groupId
                    action = "adminRemove"
                    justification = "Cleanup"
                }
                Invoke-MgGraphRequest -Method POST `
                    -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
                    -Body $removeParams -ContentType "application/json"
                Write-Host "[+] Removed PIM eligibility for $($eligibility.accessId)" -ForegroundColor Green
            } catch {
                Write-Host "[-] Failed to remove PIM eligibility: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } catch {
        # Cannot access PIM eligibilities but thats okay since those will be cleaned up when the user is deleted
    }
}

# Remove AU-scoped role assignments
$hrAU = Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$AUName'" -ErrorAction SilentlyContinue
if ($hrAU) {
    Write-Host "Removing AU-scoped role assignments..." -ForegroundColor Cyan
    $AURoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "directoryScopeId eq '/administrativeUnits/$($hrAU.Id)'" -ErrorAction SilentlyContinue
    foreach ($assignment in $AURoleAssignments) {
        try {
            Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id
            Write-Host "[+] Removed AU-scoped role assignment" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to remove AU-scoped role assignment: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Remove custom role assignments
$CustomRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$CustomRoleName'" -ErrorAction SilentlyContinue
if ($CustomRole) {
    Write-Host "Removing custom role assignments..." -ForegroundColor Cyan
    $CustomRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($CustomRole.Id)'" -ErrorAction SilentlyContinue
    foreach ($assignment in $CustomRoleAssignments) {
        try {
            Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id
            Write-Host "[+] Removed custom role assignment" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to remove custom role assignment: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Remove Administrative Unit
Write-Host "Removing Administrative Unit..." -ForegroundColor Cyan
if ($hrAU) {
    try {
        # Dynamic AUs don't need manual member removal
        Remove-MgDirectoryAdministrativeUnit -AdministrativeUnitId $hrAU.Id -Confirm:$false
        Write-Host "[+] Deleted Administrative Unit: $AUName" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to delete Administrative Unit: $AUName - $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Administrative Unit not found: $AUName" -ForegroundColor Yellow
}

# Remove Custom Role
Write-Host "Removing custom role..." -ForegroundColor Cyan
if ($CustomRole) {
    try {
        Remove-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $CustomRole.Id -Confirm:$false
        Write-Host "[+] Deleted custom role: $CustomRoleName" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to delete custom role: $CustomRoleName - $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Custom role not found: $CustomRoleName" -ForegroundColor Yellow
}

# Remove Groups
Write-Host "Removing groups..." -ForegroundColor Cyan
foreach ($GroupName in @($SupportGroupName, $PrivilegedGroupName)) {
    $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    
    if ($Group) {
        try {
            Remove-MgGroup -GroupId $Group.Id -Confirm:$false
            Write-Host "[+] Deleted group: $GroupName" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to delete group: $GroupName - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] Group not found: $GroupName" -ForegroundColor Yellow
    }
}

# Remove Users
Write-Host "Removing users..." -ForegroundColor Cyan
foreach ($UserUPN in $AllUserUPNs) {
    $User = Get-MgUser -Filter "userPrincipalName eq '$UserUPN'" -ErrorAction SilentlyContinue
    if ($User) {
        try {
            Remove-MgUser -UserId $User.Id -Confirm:$false
            Write-Host "[+] Deleted user: $UserUPN" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to delete user: $UserUPN - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] User not found: $UserUPN" -ForegroundColor Yellow
    }
}

# Wait for deletion
function Wait-ForDeletion {
    param (
        [string]$UPN,
        [string]$GroupName,
        [string]$AUName,
        [int]$TimeoutSeconds = 60
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $exists = $false
        
        if ($UPN -and (Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue)) {
            $exists = $true
        }
        if ($GroupName -and (Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue)) {
            $exists = $true
        }
        if ($AUName -and (Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$AUName'" -ErrorAction SilentlyContinue)) {
            $exists = $true
        }
        
        if (-not $exists) {
            Write-Host "[+] Confirmed inexistence" -ForegroundColor Green
            return
        }
        Start-Sleep -Seconds 3
    }
    Write-Host "[-] Warning: Timed out waiting for deletion." -ForegroundColor Yellow
}

Write-Host "Waiting for all objects to be fully purged before next setup..." -ForegroundColor Cyan
Wait-ForDeletion -UPN $SupportUPN
Wait-ForDeletion -UPN $AdminUPN
Wait-ForDeletion -GroupName $SupportGroupName
Wait-ForDeletion -GroupName $PrivilegedGroupName
Wait-ForDeletion -AUName $AUName

Write-Host "`nCleanup process complete." -ForegroundColor Cyan