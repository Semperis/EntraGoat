<#
.SYNOPSIS
EntraGoat Scenario 4 Cleanup Script
Removes all objects created by the PIM Eligible Group Ownership scenario

.DESCRIPTION
This script cleans up all resources created by the Scenario 4 setup script including:
- Users (woody.chen, EntraGoat-admin-s4, and dummy users)
- Groups (Application Operations Team and Authentication Management Team)
- Service principal and its application registration (Infrastructure Monitoring Tool)
- PIM eligible assignments and role assignments
#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration Variables (must match setup script)
$AppAdminGroupName = "Application Operations Team"
$PrivAuthGroupName = "Authentication Management Team"
$TargetAppName = "Infrastructure Monitoring Tool"

Write-Host ""
Write-Host "|------------------------------------------------------------|" -ForegroundColor Red
Write-Host "|            ENTRAGOAT SCENARIO 4 - CLEANUP PROCESS          |" -ForegroundColor Red
Write-Host "|------------------------------------------------------------|" -ForegroundColor Red
Write-Host ""

#region Module Verification and Import
Write-Verbose "[*] Verifying and importing required Microsoft Graph modules..."
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications", 
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.Governance"
)

foreach ($module in $RequiredModules) {
    if (-not (Get-Module -Name $module -ErrorAction SilentlyContinue)) {
        try {
            Import-Module $module -ErrorAction Stop
            Write-Verbose "[+] Imported $module"
        } catch {
            Write-Host "[-] Failed to import module $module`: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Please ensure Microsoft Graph SDK is installed." -ForegroundColor Yellow
            exit 1
        }
    } else {
        Write-Verbose "[*] $module already loaded"
    }
}
Write-Verbose "[+] All required modules are available"
#endregion

#region Microsoft Graph Connection
Write-Verbose "[*] Establishing Microsoft Graph connection..."

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
        Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId -NoWelcome -ErrorAction Stop
    } else {
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
    }
    
    $Context = Get-MgContext -ErrorAction Stop
    $OrgInfo = Get-MgOrganization -ErrorAction Stop
    
    $TenantDomain = ($OrgInfo.VerifiedDomains | Where-Object IsDefault).Name
    Write-Verbose "[+] Connected to tenant: $TenantDomain"
    
} catch {
    Write-Host "[-] Microsoft Graph connection failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region Define Target Objects
$LowPrivUPN = "woody.chen@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s4@$TenantDomain"

# Realistic environment users (from setup script)
$RealisticUserUPNs = @(
    "sarah.martinez@$TenantDomain",
    "david.kim@$TenantDomain", 
    "jennifer.walsh@$TenantDomain"
)

$AllUsersToRemove = @($LowPrivUPN, $AdminUPN) + $RealisticUserUPNs
#endregion

#region Remove PIM Eligible Assignments
Write-Host "[*] Removing PIM eligible assignments..." -ForegroundColor Cyan

# Get the groups first to check for PIM assignments
$AppAdminGroup = Get-MgGroup -Filter "displayName eq '$AppAdminGroupName'" -ErrorAction SilentlyContinue
$PrivAuthGroup = Get-MgGroup -Filter "displayName eq '$PrivAuthGroupName'" -ErrorAction SilentlyContinue

if ($AppAdminGroup) {
    Write-Verbose " Checking PIM eligible group ownership for: $AppAdminGroupName"
    
    # Remove eligible group ownership assignments
    try {
        $EligibleOwnershipUri = "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($AppAdminGroup.Id)' and accessId eq 'owner'"
        $EligibleOwnerships = Invoke-MgGraphRequest -Uri $EligibleOwnershipUri -Method GET -ErrorAction SilentlyContinue
        
        if ($EligibleOwnerships.value) {
            foreach ($ownership in $EligibleOwnerships.value) {
                try {
                    Write-Verbose " Removing eligible ownership: $($ownership.id)"
                    $RemovalRequest = @{
                        action = "adminRemove"
                        principalId = $ownership.principalId
                        groupId = $ownership.groupId
                        accessId = "owner"
                        justification = "EntraGoat cleanup - removing eligible ownership"
                    }
                    
                    Invoke-MgGraphRequest -Method POST `
                        -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
                        -Body ($RemovalRequest | ConvertTo-Json -Depth 4) -ContentType "application/json" -ErrorAction Stop
                    
                    Write-Host "[+] Removed eligible group ownership" -ForegroundColor Green
                } catch {
                    Write-Verbose "Failed to remove eligible ownership: $($_.Exception.Message)"
                }
            }
        }
    } catch {
        Write-Verbose "PIM ownership cleanup failed: $($_.Exception.Message)"
    }
    
    # Remove eligible role assignments for the group
    Write-Verbose " Checking eligible role assignments for: $AppAdminGroupName"
    try {
        $EligibleRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$($AppAdminGroup.Id)'" -ErrorAction SilentlyContinue
        if ($EligibleRoles) {
            foreach ($role in $EligibleRoles) {
                try {
                    Write-Verbose "    ->  Removing eligible role: $($role.RoleDefinitionId)"
                    $RemovalRequest = @{
                        Action = "adminRemove"
                        PrincipalId = $role.PrincipalId
                        RoleDefinitionId = $role.RoleDefinitionId
                        DirectoryScopeId = $role.DirectoryScopeId
                        Justification = "EntraGoat cleanup - removing eligible role"
                    }
                    
                    New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $RemovalRequest -ErrorAction Stop | Out-Null
                    Write-Host "[+] Removed eligible role assignment" -ForegroundColor Green
                } catch {
                    Write-Verbose "Failed to remove eligible role: $($_.Exception.Message)"
                }
            }
        }
    } catch {
        Write-Verbose "Eligible role cleanup failed: $($_.Exception.Message)"
    }
}
#endregion

#region Remove Users
Write-Host "[*] Removing users..." -ForegroundColor Cyan

foreach ($UserUPN in $AllUsersToRemove) {
    $User = Get-MgUser -Filter "userPrincipalName eq '$UserUPN'" -ErrorAction SilentlyContinue
    if ($User) {
        try {
            # Remove any direct role assignments first
            $UserRoles = Get-MgUserMemberOf -UserId $User.Id -All -ErrorAction SilentlyContinue
            if ($UserRoles) {
                foreach ($role in $UserRoles) {
                    if ($role.OdataType -eq "#microsoft.graph.directoryRole") {
                        try {
                            Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -DirectoryObjectId $User.Id -ErrorAction SilentlyContinue
                            Write-Verbose "Removed user from role: $($role.DisplayName)"
                        } catch {
                            Write-Verbose "Failed to remove user from role: $($_.Exception.Message)"
                        }
                    }
                }
            }
            
            Remove-MgUser -UserId $User.Id -Confirm:$false -ErrorAction Stop
            Write-Host "[+] Deleted user: $UserUPN" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to delete user: $UserUPN - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] User not found: $UserUPN" -ForegroundColor Yellow
    }
}
#endregion

#region Remove Groups
Write-Host "[*] Removing groups..." -ForegroundColor Cyan

foreach ($GroupName in @($AppAdminGroupName, $PrivAuthGroupName)) {
    $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    
    if ($Group) {
        try {
            # Remove active role assignments
            Write-Verbose "Removing role assignments for: $GroupName"
            $DirectoryRoles = Get-MgDirectoryRole -All -ErrorAction SilentlyContinue
            foreach ($Role in $DirectoryRoles) {
                $RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction SilentlyContinue
                if ($RoleMembers) {
                    $GroupInRole = $RoleMembers | Where-Object { $_.Id -eq $Group.Id }
                    if ($GroupInRole) {
                        try {
                            Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role.Id -DirectoryObjectId $Group.Id -ErrorAction Stop
                            Write-Host "[+] Removed group from role: $($Role.DisplayName)" -ForegroundColor Green
                        } catch {
                            Write-Verbose "Failed to remove group from role $($Role.DisplayName): $($_.Exception.Message)"
                        }
                    }
                }
            }
            
            # Remove the group
            Remove-MgGroup -GroupId $Group.Id -Confirm:$false -ErrorAction Stop
            Write-Host "[+] Deleted group: $GroupName" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to delete group: $GroupName - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] Group not found: $GroupName" -ForegroundColor Yellow
    }
}
#endregion

#region Remove Service Principal and Application
Write-Host "[*] Removing service principal and application..." -ForegroundColor Cyan

# Find and remove Service Principal first
$TargetSP = Get-MgServicePrincipal -Filter "displayName eq '$TargetAppName'" -ErrorAction SilentlyContinue
if ($TargetSP) {
    try {
        # Remove from any groups first
        Write-Verbose "Removing service principal from groups..."
        $SPMemberships = Get-MgServicePrincipalMemberOf -ServicePrincipalId $TargetSP.Id -All -ErrorAction SilentlyContinue
        foreach ($membership in $SPMemberships) {
            if ($membership.OdataType -eq "#microsoft.graph.group") {
                try {
                    Remove-MgGroupMemberByRef -GroupId $membership.Id -DirectoryObjectId $TargetSP.Id -ErrorAction Stop
                    Write-Verbose "Removed service principal from group: $($membership.DisplayName)"
                } catch {
                    Write-Verbose "Failed to remove SP from group: $($_.Exception.Message)"
                }
            }
        }
        
        # Remove any app role assignments
        Write-Verbose "Removing app role assignments..."
        $AppRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -All -ErrorAction SilentlyContinue
        foreach ($Assignment in $AppRoleAssignments) {
            try {
                Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -AppRoleAssignmentId $Assignment.Id -ErrorAction Stop
                Write-Verbose "Removed app role assignment"
            } catch {
                Write-Verbose "Failed to remove app role assignment: $($_.Exception.Message)"
            }
        }
        
        # Remove the service principal
        Remove-MgServicePrincipal -ServicePrincipalId $TargetSP.Id -Confirm:$false -ErrorAction Stop
        Write-Host "[+] Deleted service principal: $TargetAppName" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to delete service principal: $TargetAppName - $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Service principal not found: $TargetAppName" -ForegroundColor Yellow
}

# Find and remove app registration
$TargetApp = Get-MgApplication -Filter "displayName eq '$TargetAppName'" -ErrorAction SilentlyContinue
if ($TargetApp) {
    try {
        Remove-MgApplication -ApplicationId $TargetApp.Id -Confirm:$false -ErrorAction Stop
        Write-Host "[+] Deleted application registration: $TargetAppName" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to delete application registration: $TargetAppName - $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Application registration not found: $TargetAppName" -ForegroundColor Yellow
}
#endregion

#region Wait for Deletion Completion
Write-Host "[*] Waiting for all objects to be fully purged..." -ForegroundColor Cyan

function Wait-ForDeletion {
    param (
        [string[]]$UserUPNs,
        [string]$AppName,
        [string[]]$GroupNames,
        [int]$TimeoutSeconds = 90
    )
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $AllDeleted = $true
        
        # Check users
        foreach ($UPN in $UserUPNs) {
            $UserExists = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue
            if ($UserExists) {
                $AllDeleted = $false
                break
            }
        }
        
        # Check application and service principal
        if ($AppName -and $AllDeleted) {
            $AppExists = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue
            $SPExists = Get-MgServicePrincipal -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue
            if ($AppExists -or $SPExists) {
                $AllDeleted = $false
            }
        }
        
        # Check groups
        if ($GroupNames -and $AllDeleted) {
            foreach ($GroupName in $GroupNames) {
                $GroupExists = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
                if ($GroupExists) {
                    $AllDeleted = $false
                    break
                }
            }
        }
        
        if ($AllDeleted) {
            Write-Host "[+] Confirmed deletion of all target objects" -ForegroundColor Green
            return $true
        }
        
        Write-Verbose "Waiting for deletion to complete..."
        Start-Sleep -Seconds 5
    }
    
    Write-Host "[-] Warning: Timed out waiting for deletion. Some objects may still exist." -ForegroundColor Yellow
    return $false
}

$DeletionComplete = Wait-ForDeletion -UserUPNs $AllUsersToRemove -AppName $TargetAppName -GroupNames @($AppAdminGroupName, $PrivAuthGroupName)
#endregion

#region Cleanup Summary
Write-Host "`nCLEANED UP OBJECTS:" -ForegroundColor Yellow
Write-Host "  Users:" -ForegroundColor White
foreach ($UPN in $AllUsersToRemove) {
    Write-Host "$UPN" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Groups:" -ForegroundColor White
Write-Host "$AppAdminGroupName" -ForegroundColor Cyan
Write-Host "$PrivAuthGroupName" -ForegroundColor Cyan
Write-Host ""
Write-Host " Applications:" -ForegroundColor White
Write-Host "$TargetAppName (App Registration + Service Principal)" -ForegroundColor Cyan
Write-Host ""
Write-Host " PIM Assignments:" -ForegroundColor White
Write-Host " Eligible group ownership assignments" -ForegroundColor Cyan
Write-Host " Eligible role assignments" -ForegroundColor Cyan

if ($DeletionComplete) {
    Write-Host "`n[OK] All objects successfully removed from tenant" -ForegroundColor Green
    Write-Host "Ready for fresh Scenario 4 setup!" -ForegroundColor Green
} else {
    Write-Host "`n Some objects may still be processing deletion" -ForegroundColor Yellow
    Write-Host "   Wait a few minutes before running setup again" -ForegroundColor Yellow
}
#endregion

# Cleanup - disconnect from Graph
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
} catch {
    # Ignore cleanup errors
}

Write-Host "`nCleanup process complete." -ForegroundColor Cyan