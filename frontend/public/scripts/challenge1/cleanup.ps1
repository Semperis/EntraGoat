# EntraGoat Scenario 1: Cleanup Script
# To be run with Global Administrator privileges.

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
Write-Host "Removing users..." -ForegroundColor Cyan

foreach ($UserUPN in @($LowPrivUPN, $AdminUPN)) {
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

# Cleanup Service Principal and Application
Write-Host "Removing service principal and application registration..." -ForegroundColor Cyan
$App = Get-MgApplication -Filter "displayName eq '$PrivilegedAppName'" -ErrorAction SilentlyContinue

if ($App) {
    # Delete SP first
    $SP = Get-MgServicePrincipal -Filter "appId eq '$($App.AppId)'" -ErrorAction SilentlyContinue
    if ($SP) {
        try {
            Remove-MgServicePrincipal -ServicePrincipalId $SP.Id -Confirm:$false
            Write-Host "[+] Deleted service principal: $($SP.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to delete service principal: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] Service principal not found for AppId: $($App.AppId)" -ForegroundColor Yellow
    }

    # Delete Application Registration
    try {
        Remove-MgApplication -ApplicationId $App.Id -Confirm:$false
        Write-Host "[+] Deleted application: $PrivilegedAppName" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to delete application: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Application not found: $PrivilegedAppName" -ForegroundColor Yellow
}

# Wait until all target objects are truly deleted before proceeding
function Wait-ForDeletion {
    param (
        [string]$UPN,
        [string]$AppName,
        [int]$TimeoutSeconds = 60
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $UserExists = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue
        $AppExists = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue
        $SPExists = $null
        if ($AppExists) {
            $SPExists = Get-MgServicePrincipal -Filter "appId eq '$($AppExists.AppId)'" -ErrorAction SilentlyContinue
        }
        if (-not $UserExists -and -not $AppExists -and -not $SPExists) {
            Write-Host "[+] Confirmed inexistence of $UPN and $AppName."
            return
        }
        Start-Sleep -Seconds 15
    }
    Write-Host "[-] Warning: Timed out waiting for deletion of $UPN or $AppName." -ForegroundColor Yellow
}

Write-Host "Waiting for all objects to be fully purged before next setup..." -ForegroundColor Cyan
Wait-ForDeletion -UPN $LowPrivUPN -AppName $PrivilegedAppName
Wait-ForDeletion -UPN $AdminUPN -AppName $PrivilegedAppName

Write-Host "`nCleanup process complete." -ForegroundColor Cyan