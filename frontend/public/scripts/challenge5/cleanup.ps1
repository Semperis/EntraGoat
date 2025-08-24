<#
.SYNOPSIS
EntraGoat Scenario 5: Cleanup Script
To be run with Global Administrator privileges.

.DESCRIPTION
Cleans up:
- Users (sarah.connor, EntraGoat-admin-s5, and dummy users)
- Groups (Regional HR Coordinators and HR Support Team)
- PIM eligibility schedules
- Directory role assignments
- Custom role and its assignments
- Administrative Unit (HR Department)
#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups, Microsoft.Graph.DeviceManagement.Administration

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration - matching setup script
$CustomRoleName = "User Profile Administrator"
$SupportGroupName = "HR Support Team"
$PrivilegedGroupName = "Regional HR Coordinators"
$KnowledgeGroupName = "Knowledge Management Team"
$KaizalaGroupName = "Kaizala Operations Team"
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
    try {
        Import-Module $moduleName -ErrorAction SilentlyContinue -Verbose:$false
        if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue -Verbose:$false)) {
            throw "Failed to import $moduleName"
        }
        Write-Verbose "[+] Imported module $moduleName."
    } catch {
        Write-Host "[-] " -ForegroundColor Red -NoNewline
        Write-Host "Failed to import module $moduleName. Please ensure Microsoft Graph SDK is installed. Error: $($_.Exception.Message)" -ForegroundColor White
        exit 1
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
Write-Host "`n[*] Removing groups..."

foreach ($GroupName in @($SupportGroupName, $PrivilegedGroupName, $KnowledgeGroupName, $KaizalaGroupName)) {
    $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    
    if ($Group) {
        try {
            Remove-MgGroup -GroupId $Group.Id -Confirm:$false
            Write-Host "    [+] Deleted group: $GroupName" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed to delete group: $GroupName - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "    [-] Group not found: $GroupName" -ForegroundColor Yellow
    }
}

# Remove Users
Write-Host "`n[*] Removing users..."

foreach ($UserUPN in $AllUserUPNs) {
    $User = Get-MgUser -Filter "userPrincipalName eq '$UserUPN'" -ErrorAction SilentlyContinue
    if ($User) {
        try {
            Remove-MgUser -UserId $User.Id -Confirm:$false
            Write-Host "    [+] Deleted user: $UserUPN" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed to delete user: $UserUPN - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "    [-] User not found: $UserUPN" -ForegroundColor Yellow
    }
}

# Wait for deletion
function Wait-ForAllDeletions {
    param (
        [array]$ObjectsToCheck,
        [int]$TimeoutSeconds = 90
    )
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $AllDeleted = $true
        
        foreach ($obj in $ObjectsToCheck) {
            if ($obj.Type -eq "User") {
                $Exists = Get-MgUser -Filter "userPrincipalName eq '$($obj.Name)'" -ErrorAction SilentlyContinue
                if ($Exists) {
                    $AllDeleted = $false
                    break
                }
            } elseif ($obj.Type -eq "Group") {
                $Exists = Get-MgGroup -Filter "displayName eq '$($obj.Name)'" -ErrorAction SilentlyContinue
                if ($Exists) {
                    $AllDeleted = $false
                    break
                }
            } elseif ($obj.Type -eq "AdministrativeUnit") {
                $Exists = Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$($obj.Name)'" -ErrorAction SilentlyContinue
                if ($Exists) {
                    $AllDeleted = $false
                    break
                }
            }
        }
        
        if ($AllDeleted) {
            Write-Host "    [+] Confirmed inexistence of all requested objects" -ForegroundColor Green
            return $true
        }
        
        Write-Verbose "Still waiting for deletion..."
        Start-Sleep -Seconds 5
    }
    
    Write-Host "    [-] Warning: Timed out waiting for deletion. Some objects may still exist."
    return $false
}

Write-Host "`n[*] Waiting for objects to be fully purged (this can take a moment)..."

$ObjectsToCheck = @()
$ObjectsToCheck += @{ Type = "User"; Name = $SupportUPN }
$ObjectsToCheck += @{ Type = "User"; Name = $AdminUPN }
$ObjectsToCheck += @{ Type = "Group"; Name = $SupportGroupName }
$ObjectsToCheck += @{ Type = "Group"; Name = $PrivilegedGroupName }
$ObjectsToCheck += @{ Type = "Group"; Name = $KnowledgeGroupName }
$ObjectsToCheck += @{ Type = "Group"; Name = $KaizalaGroupName }
$ObjectsToCheck += @{ Type = "AdministrativeUnit"; Name = $AUName }

$DeletionComplete = Wait-ForAllDeletions -ObjectsToCheck $ObjectsToCheck

if ($DeletionComplete) {
    Write-Host "`n[+] All objects successfully removed from tenant" -ForegroundColor DarkGreen
} else {
    Write-Host "`n Some objects may still be processing deletion" -ForegroundColor Yellow
    Write-Host "   Wait a few minutes before running setup again" -ForegroundColor Yellow
}

Write-Host "`nCleanup process for Scenario 5 complete." -ForegroundColor White