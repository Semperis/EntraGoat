<#
.SYNOPSIS
EntraGoat Scenario 2: Cleanup Script
To be run with Global Administrator privileges.

.DESCRIPTION
Cleans up:
- Users (jennifer.clark, EntraGoat-admin-s2, and dummy users)
- Application registration and its service principal (Corporate Finance Analytics)
- Directory role assignments
#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$VulnerableAppName = "Corporate Finance Analytics"

$standardDelay = 10 

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|           ENTRAGOAT SCENARIO 2 - CLEANUP PROCESS             |" -ForegroundColor Cyan
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

#region Authentication
Write-Verbose "[*] Connecting to Microsoft Graph..."
$RequiredScopes = @(
    "Application.ReadWrite.All",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All"
)
try {
    if ($TenantId) {
        Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
    }
    $MgContext = Get-MgContext
    $Organization = Get-MgOrganization
    $TenantDomain = ($Organization.VerifiedDomains | Where-Object IsDefault).Name
    Write-Verbose "[+] Connected to tenant: $TenantDomain"
} catch {
    Write-Host "[-] " -ForegroundColor Red -NoNewline
    Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor White
    exit 1
}
#endregion

# Target Objects
$LowPrivUPN = "jennifer.clark@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s2@$TenantDomain"

#region Cleanup Users
Write-Host "`n[*] Removing users..." -ForegroundColor Cyan
foreach ($UserUPN in @($LowPrivUPN, $AdminUPN)) {
    Write-Verbose "    ->  Checking user: $UserUPN"
    $User = Get-MgUser -Filter "userPrincipalName eq '$UserUPN'" -ErrorAction SilentlyContinue
    if ($User) {
        try {
            Remove-MgUser -UserId $User.Id -Confirm:$false -ErrorAction Stop
            Write-Host "    [+] Deleted user: $UserUPN" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed to delete user ${UserUPN}: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "    [-] User not found (already deleted?): $UserUPN" -ForegroundColor Yellow
    }
}
#endregion

#region Cleanup Service Principal and Application
Write-Host "`n[*] Removing service principal and application registration..." -ForegroundColor Cyan
$App = Get-MgApplication -Filter "displayName eq '$VulnerableAppName'" -ErrorAction SilentlyContinue

if ($App) {
    $AppIdToDelete = if ($App.AppId -is [array]) { $App.AppId[0] } else { $App.AppId.ToString() }
    Write-Verbose "    ->  Found application registration: $($App.DisplayName) (AppID: $AppIdToDelete)"

    # Delete Service Principal first
    $SP = Get-MgServicePrincipal -Filter "appId eq '$AppIdToDelete'" -ErrorAction SilentlyContinue
    if ($SP) {
        Write-Verbose "    ->  Found service principal: $($SP.DisplayName) (ObjectID: $($SP.Id))"
        try {
            Remove-MgServicePrincipal -ServicePrincipalId $SP.Id -Confirm:$false -ErrorAction Stop
            Write-Host "    [+] Deleted service principal: $($SP.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed to delete service principal $($SP.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "    [-] Service principal not found for AppId: $AppIdToDelete (already deleted or never fully created?)" -ForegroundColor Yellow
    }

    # Delete Application Registration
    Write-Verbose "    ->  Attempting to delete application registration: $($App.DisplayName) (ObjectID: $($App.Id))"
    try {
        Remove-MgApplication -ApplicationId $App.Id -Confirm:$false -ErrorAction Stop
        Write-Host "    [+] Deleted application: $VulnerableAppName" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to delete application $VulnerableAppName : $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "    [-] Application not found (already deleted?): $VulnerableAppName" -ForegroundColor Yellow
}
#endregion

#region Wait for Deletion
function Wait-ForAllDeletions {
    param (
        [array]$ObjectsToCheck,
        [int]$TimeoutSeconds = 90
    )
    Write-Verbose "    Waiting up to $TimeoutSeconds seconds for complete deletion of all objects..."
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
                    $appId = if ($appExists.AppId -is [array]) { $appExists.AppId[0] } else { $appExists.AppId.ToString() }
                    $spExists = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
                    if ($spExists) { $allDeleted = $false }
                }
            }
        }
        
        if ($allDeleted) {
            Write-Host "`n[+] Confirmed inexistence of all requested objects" -ForegroundColor DarkGreen
            return
        }
        
                 Write-Verbose "      Still waiting for deletion... ($($sw.Elapsed.Seconds)s / $($TimeoutSeconds)s)"
        Start-Sleep -Seconds $standardDelay
    }
    $sw.Stop()
    Write-Host "[-] Warning: Timed out waiting for full deletion of some objects. Manual check might be needed." -ForegroundColor Yellow
}

Write-Host "`n[*] Waiting for objects to be fully purged (this can take a moment)..." -ForegroundColor Cyan
$objectsToCheck = @(
    @{ Type = "User"; UPN = $LowPrivUPN },
    @{ Type = "User"; UPN = $AdminUPN },
    @{ Type = "Application"; Name = $VulnerableAppName }
)
Wait-ForAllDeletions -ObjectsToCheck $objectsToCheck
#endregion

Write-Host "`nCleanup process for Scenario 2 complete." -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
Write-Host ""