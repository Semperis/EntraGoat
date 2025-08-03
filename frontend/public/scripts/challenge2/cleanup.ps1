<#
.SYNOPSIS
EntraGoat Scenario 2: Cleanup Script
To be run with Global Administrator privileges.

.DESCRIPTION
Removes all Azure AD objects created by the EntraGoat Scenario 2 setup script.
This includes users, the application registration, and its service principal.
#>

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$ScenarioPrefix = "EntraGoat-S2"
$VulnerableAppName = "Corporate Finance Analytics"

$standardDelay = 10 

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "            ENTRAGOAT SCENARIO 2 - CLEANUP PROCESS              " -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
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
    Write-Verbose "    -> Checking user: $UserUPN"
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
Write-Host "`n[*] Removing service principal and application registration for '$VulnerableAppName'..." -ForegroundColor Cyan
$App = Get-MgApplication -Filter "displayName eq '$VulnerableAppName'" -ErrorAction SilentlyContinue

if ($App) {
    $AppIdToDelete = if ($App.AppId -is [array]) { $App.AppId[0] } else { $App.AppId.ToString() }
    Write-Verbose "    -> Found application registration: $($App.DisplayName) (AppID: $AppIdToDelete)"

    # Delete Service Principal first
    $SP = Get-MgServicePrincipal -Filter "appId eq '$AppIdToDelete'" -ErrorAction SilentlyContinue
    if ($SP) {
        Write-Verbose "    -> Found service principal: $($SP.DisplayName) (ObjectID: $($SP.Id))"
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
    Write-Verbose "    -> Attempting to delete application registration: $($App.DisplayName) (ObjectID: $($App.Id))"
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
function Wait-ForDeletion {
    param (
        [string]$UserPrincipalName,
        [string]$ApplicationDisplayName,
        [int]$TimeoutSeconds = 90
    )
    Write-Verbose "    Waiting up to $TimeoutSeconds seconds for complete deletion of objects..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $itemDeleted = $false
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $UserExists = $false
        if ($UserPrincipalName) {
            $UserExists = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
        }

        $AppExists = $false
        $SPExists = $false
        if ($ApplicationDisplayName) {
            $TempApp = Get-MgApplication -Filter "displayName eq '$ApplicationDisplayName'" -ErrorAction SilentlyContinue
            if ($TempApp) {
                $AppExists = $true
                $TempAppId = if ($TempApp.AppId -is [array]) { $TempApp.AppId[0] } else { $TempApp.AppId.ToString() }
                $SPExists = Get-MgServicePrincipal -Filter "appId eq '$TempAppId'" -ErrorAction SilentlyContinue
            }
        }

        if ($UserPrincipalName -and -not $ApplicationDisplayName) {
            if (-not $UserExists) { $itemDeleted = $true; break }
        } elseif (-not $UserPrincipalName -and $ApplicationDisplayName) { 
            if (-not $AppExists -and -not $SPExists) { $itemDeleted = $true; break }
        } elseif ($UserPrincipalName -and $ApplicationDisplayName) { 
             # This case won't be hit with current calls, but good for general function
            if (-not $UserExists -and -not $AppExists -and -not $SPExists) { $itemDeleted = $true; break }
        }

        Write-Verbose "      Still waiting for deletion... ($($sw.Elapsed.Seconds)s / $($TimeoutSeconds)s)"
        Start-Sleep -Seconds $standardDelay
    }
    $sw.Stop()

    if ($itemDeleted) {
        Write-Host "    [+] Confirmed deletion of relevant objects." -ForegroundColor Green
    } else {
        Write-Host "    [-] Warning: Timed out waiting for full deletion of objects related to '$($UserPrincipalName)$($ApplicationDisplayName)'. Manual check might be needed." -ForegroundColor Yellow
    }
}

Write-Host "`n[*] Waiting for objects to be fully purged (this can take a moment)..." -ForegroundColor Cyan
# Wait for users individually
Wait-ForDeletion -UserPrincipalName $LowPrivUPN
Wait-ForDeletion -UserPrincipalName $AdminUPN
# Wait for App/SP
Wait-ForDeletion -ApplicationDisplayName $VulnerableAppName
#endregion

Write-Host "`nCleanup process for Scenario 2 complete." -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor DarkGray
Write-Host ""