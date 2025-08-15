<#
.SYNOPSIS
EntraGoat Scenario 3: Cleanup Script
To be run with Global Administrator privileges.

.DESCRIPTION
Cleans up:
- Users (michael.chen, EntraGoat-admin-s3, and dummy users)
- Application registration and its service principal (Identity Management Portal)
- Groups (Identity Security Team and IT Application Managers)
- Directory role assignments
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

# New groups for additional ownership
$AIGroupName = "AI Development Team"
$AttackSimGroupName = "Security Testing Team" 
$NetworkGroupName = "Network Operations Team"

# Additional normal groups without roles
$NormalGroup1Name = "Marketing Team"
$NormalGroup2Name = "Finance Department"

$RequiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", 
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All"
)

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|           ENTRAGOAT SCENARIO 3 - CLEANUP PROCESS             |" -ForegroundColor Cyan
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

# Target Objects
$LowPrivUPN = "michael.chen@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s3@$TenantDomain"
$DummyUserUPNs = @(
    "emily.rodriguez@$TenantDomain",
    "james.wilson@$TenantDomain", 
    "lisa.chang@$TenantDomain",
    "robert.taylor@$TenantDomain"
)

# Cleanup Users
Write-Host "`n[*] Removing users..." -ForegroundColor Cyan

# Remove main users and dummy users
$allUsersToRemove = @($LowPrivUPN, $AdminUPN) + $DummyUserUPNs

foreach ($UserUPN in $allUsersToRemove) {
    Write-Verbose "    ->  Checking user: $UserUPN"
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

# Cleanup Groups
Write-Host "`n[*] Removing groups..." -ForegroundColor Cyan
foreach ($GroupName in @($AppAdminGroupName, $PrivAuthGroupName, $AIGroupName, $AttackSimGroupName, $NetworkGroupName, $NormalGroup1Name, $NormalGroup2Name)) {
    Write-Verbose "    ->  Checking group: $GroupName"
    $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    
    if ($Group) {
        try {
            # First remove role assignments if any
            $DirectoryRoles = Get-MgDirectoryRole -All
            foreach ($Role in $DirectoryRoles) {
                $RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction SilentlyContinue
                if ($RoleMembers) {
                    $GroupInRole = $RoleMembers | Where-Object { $_.Id -eq $Group.Id }
                    if ($GroupInRole) {
                        try {
                            Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role.Id -DirectoryObjectId $Group.Id
                            Write-Host "    [+] Removed group from role: $($Role.DisplayName)" -ForegroundColor Green
                        } catch {
                            Write-Host "    [-] Failed to remove group from role $($Role.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            }
            
            # Now delete the group
            Remove-MgGroup -GroupId $Group.Id -Confirm:$false
            Write-Host "    [+] Deleted group: $GroupName" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed to delete group: $GroupName - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "    [-] Group not found: $GroupName" -ForegroundColor Yellow
    }
}

# Cleanup Service Principal and Application
Write-Host "`n[*] Removing service principal and application registration..." -ForegroundColor Cyan

# Find and remove Service Principal first
$TargetSP = Get-MgServicePrincipal -Filter "displayName eq '$TargetAppName'" -ErrorAction SilentlyContinue
if ($TargetSP) {
    Write-Verbose "    ->  Found service principal: $($TargetSP.DisplayName)"
    try {
        # Remove any app role assignments
        $AppRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -ErrorAction SilentlyContinue
        foreach ($Assignment in $AppRoleAssignments) {
            try {
                Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $TargetSP.Id -AppRoleAssignmentId $Assignment.Id
                Write-Host "    [+] Removed app role assignment" -ForegroundColor Green
            } catch {
                Write-Host "    [-] Failed to remove app role assignment: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        # Remove the service principal
        Remove-MgServicePrincipal -ServicePrincipalId $TargetSP.Id -Confirm:$false
        Write-Host "    [+] Deleted service principal: $TargetAppName" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to delete service principal: $TargetAppName - $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "    [-] Service principal not found: $TargetAppName" -ForegroundColor Yellow
}

# Find and remove app registration
$TargetApp = Get-MgApplication -Filter "displayName eq '$TargetAppName'" -ErrorAction SilentlyContinue
if ($TargetApp) {
    Write-Verbose "    ->  Found application registration: $($TargetApp.DisplayName)"
    try {
        Remove-MgApplication -ApplicationId $TargetApp.Id -Confirm:$false
        Write-Host "    [+] Deleted application registration: $TargetAppName" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to delete application registration: $TargetAppName - $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "    [-] Application registration not found: $TargetAppName" -ForegroundColor Yellow
}

# Wait until all target objects are truly deleted before proceeding
function Wait-ForAllDeletions {
    param (
        [array]$ObjectsToCheck,
        [int]$TimeoutSeconds = 60
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $allDeleted = $true
        
        foreach ($obj in $ObjectsToCheck) {
            if ($obj.Type -eq "User") {
                $exists = Get-MgUser -Filter "userPrincipalName eq '$($obj.Name)'" -ErrorAction SilentlyContinue
                if ($exists) { $allDeleted = $false; break }
            }
            elseif ($obj.Type -eq "App") {
                $appExists = Get-MgApplication -Filter "displayName eq '$($obj.Name)'" -ErrorAction SilentlyContinue
                if ($appExists) { $allDeleted = $false; break }
                $spExists = Get-MgServicePrincipal -Filter "appId eq '$($appExists.AppId)'" -ErrorAction SilentlyContinue
                if ($spExists) { $allDeleted = $false; break }
            }
            elseif ($obj.Type -eq "Group") {
                $exists = Get-MgGroup -Filter "displayName eq '$($obj.Name)'" -ErrorAction SilentlyContinue
                if ($exists) { $allDeleted = $false; break }
            }
        }
        
        if ($allDeleted) {
            Write-Host "`n[+] Confirmed inexistence of all requested objects" -ForegroundColor DarkGreen
            return
        }
        Start-Sleep -Seconds 3
    }
    Write-Host "[-] Warning: Timed out waiting for deletion. You may hit setup race conditions." -ForegroundColor Yellow
}

Write-Host "`n[*] Waiting for objects to be fully purged (this can take a moment)..." -ForegroundColor Cyan
$ObjectsToCheck = @(
    @{Type="User"; Name=$LowPrivUPN},
    @{Type="User"; Name=$AdminUPN},
    @{Type="App"; Name=$TargetAppName},
    @{Type="Group"; Name=$AppAdminGroupName},
    @{Type="Group"; Name=$PrivAuthGroupName},
    @{Type="Group"; Name=$AIGroupName},
    @{Type="Group"; Name=$AttackSimGroupName},
    @{Type="Group"; Name=$NetworkGroupName},
    @{Type="Group"; Name=$NormalGroup1Name},
    @{Type="Group"; Name=$NormalGroup2Name}
)
Wait-ForAllDeletions -ObjectsToCheck $ObjectsToCheck

Write-Host "`nCleanup process for Scenario 3 complete." -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
Write-Host ""