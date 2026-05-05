<#
.SYNOPSIS
EntraGoat Scenario 7: Cleanup Script
To be run with Global Administrator privileges.

.DESCRIPTION
Cleans up:
- Users (raj.patel, EntraGoat-admin-s7)
- Conditional Access policy ("EntraGoat S7 - Require MFA for All Users")
- Directory role assignments tied to the deleted admin
#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns


[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

$CAPolicyName = "EntraGoat S7 - Require MFA for All Users"

$RequiredScopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Policy.ReadWrite.ConditionalAccess"
)

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|           ENTRAGOAT SCENARIO 7 - CLEANUP PROCESS             |" -ForegroundColor Cyan
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host ""

#region Module Check and Import
Write-Verbose "[*] Checking required Microsoft Graph modules..."
$RequiredCleanupModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users", "Microsoft.Graph.Identity.DirectoryManagement", "Microsoft.Graph.Identity.SignIns")
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

# Target Objects
$LowPrivUPN = "raj.patel@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s7@$TenantDomain"

# Cleanup Conditional Access Policy first - cheap and isolated
Write-Host "`n[*] Removing Conditional Access policy..." -ForegroundColor Cyan
$CAPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$CAPolicyName'" -ErrorAction SilentlyContinue
if ($CAPolicy) {
    try {
        Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $CAPolicy.Id -ErrorAction Stop
        Write-Host "    [+] Deleted CA policy: $CAPolicyName" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to delete CA policy: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "    [-] CA policy not found: $CAPolicyName" -ForegroundColor Yellow
}

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
            } elseif ($obj.Type -eq "CAPolicy") {
                $polExists = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$($obj.Name)'" -ErrorAction SilentlyContinue
                if ($polExists) { $allDeleted = $false }
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
    @{ Type = "CAPolicy"; Name = $CAPolicyName }
)
Wait-ForAllDeletions -ObjectsToCheck $objectsToCheck

Write-Host "`nCleanup process for Scenario 7 complete." -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
Write-Host ""
