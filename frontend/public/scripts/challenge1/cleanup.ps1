<#
.SYNOPSIS
EntraGoat Scenario 1: Cleanup Script
To be run with Global Administrator privileges.

.DESCRIPTION
Cleans up:
- Users (david.martinez, EntraGoat-admin-s1, and dummy users)
- Application registration and its service principal (Finance Analytics Dashboard)
- Directory role assignments
#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement


[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

$PrivilegedAppName = "Finance Analytics Dashboard"

$RequiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", 
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
)

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|           ENTRAGOAT SCENARIO 1 - CLEANUP PROCESS             |" -ForegroundColor Cyan
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
$LowPrivUPN = "david.martinez@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s1@$TenantDomain"

# Cleanup Users
Write-Host "`n[*] Removing users..." -ForegroundColor Cyan

foreach ($UserUPN in @($LowPrivUPN, $AdminUPN)) {
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

# Cleanup Service Principal and Application
Write-Host "`n[*] Removing service principal and application registration..." -ForegroundColor Cyan
$App = Get-MgApplication -Filter "displayName eq '$PrivilegedAppName'" -ErrorAction SilentlyContinue

if ($App) {
    Write-Verbose "    ->  Found application registration: $($App.DisplayName)"
    
    # Delete SP first
    $SP = Get-MgServicePrincipal -Filter "appId eq '$($App.AppId)'" -ErrorAction SilentlyContinue
    if ($SP) {
        Write-Verbose "    ->  Found service principal: $($SP.DisplayName)"
        try {
            Remove-MgServicePrincipal -ServicePrincipalId $SP.Id -Confirm:$false
            Write-Host "    [+] Deleted service principal: $($SP.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed to delete service principal: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "    [-] Service principal not found for AppId: $($App.AppId)" -ForegroundColor Yellow
    }

    # Delete Application Registration
    Write-Verbose "    ->  Attempting to delete application registration: $($App.DisplayName)"
    try {
        Remove-MgApplication -ApplicationId $App.Id -Confirm:$false
        Write-Host "    [+] Deleted application: $PrivilegedAppName" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to delete application: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "    [-] Application not found: $PrivilegedAppName" -ForegroundColor Yellow
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
                $exists = Get-MgUser -Filter "userPrincipalName eq '$($obj.UPN)'" -ErrorAction SilentlyContinue
                if ($exists) { $allDeleted = $false }
            } elseif ($obj.Type -eq "Application") {
                $appExists = Get-MgApplication -Filter "displayName eq '$($obj.Name)'" -ErrorAction SilentlyContinue
                if ($appExists) {
                    $allDeleted = $false
                    $spExists = Get-MgServicePrincipal -Filter "appId eq '$($appExists.AppId)'" -ErrorAction SilentlyContinue
                    if ($spExists) { $allDeleted = $false }
                }
            }
        }
        
        if ($allDeleted) {
            Write-Host "`n[+] Confirmed inexistence of all requested objects" -ForegroundColor DarkGreen
            return
        }
        Start-Sleep -Seconds 15
    }
    Write-Host "[-] Warning: Timed out waiting for deletion of some objects." -ForegroundColor Yellow
}

Write-Host "`n[*] Waiting for objects to be fully purged (this can take a moment)..." -ForegroundColor Cyan
$objectsToCheck = @(
    @{ Type = "User"; UPN = $LowPrivUPN },
    @{ Type = "User"; UPN = $AdminUPN },
    @{ Type = "Application"; Name = $PrivilegedAppName }
)
Wait-ForAllDeletions -ObjectsToCheck $objectsToCheck

Write-Host "`nCleanup process for Scenario 1 complete." -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
Write-Host ""