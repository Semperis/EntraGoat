<#
.SYNOPSIS
EntraGoat Scenario 6: Cleanup Script
# To be run with Global Administrator privileges.

.DESCRIPTION
Cleans up:
- Users (terence, EntraGoat-admin-s6, and dummy users)
- Application registrations and service principals (Legacy, DataSync, and OrgConfig)
- Authentication Policy Managers group and role assignments
- PIM eligibility schedules
- CBA configurations and malicious root CAs
- Directory role assignments
#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$LegacyAutomationAppName = "Legacy-Automation-Service"
$DataSyncAppName = "DataSync-Production"
$OrgConfigAppName = "Organization-Config-Manager"
$AuthPolicyGroupName = "Authentication Policy Managers"

$RequiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", 
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Policy.ReadWrite.AuthenticationMethod",
    "Organization.ReadWrite.All"
)

Write-Host ""
Write-Host "|--------------------------------------------------------------|" -ForegroundColor Cyan
Write-Host "|           ENTRAGOAT SCENARIO 6 - CLEANUP PROCESS             |" -ForegroundColor Cyan
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

$Organization = Get-MgOrganization
$TenantDomain = ($Organization.VerifiedDomains | Where-Object IsDefault).Name

$LowPrivUPN = "terence.mckenna@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s6@$TenantDomain"

$dummyUserUPNs = @("alice.johnson@$TenantDomain", "bob.smith@$TenantDomain")

# Cleanup Groups
Write-Host "Removing group..." -ForegroundColor Cyan
$Group = Get-MgGroup -Filter "displayName eq '$AuthPolicyGroupName'" -ErrorAction SilentlyContinue
if ($Group) {
    try {
        # remove role assignments if any
        $DirectoryRoles = Get-MgDirectoryRole -All
        foreach ($Role in $DirectoryRoles) {
            $RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction SilentlyContinue
            if ($RoleMembers) {
                $GroupInRole = $RoleMembers | Where-Object { $_.Id -eq $Group.Id }
                if ($GroupInRole) {
                    try {
                        Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role.Id -DirectoryObjectId $Group.Id
                        Write-Host "[+] Removed group from role: $($Role.DisplayName)" -ForegroundColor Green
                    } catch {
                        Write-Host "[-] Failed to remove group from role $($Role.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
        
        # Now delete the group
        Remove-MgGroup -GroupId $Group.Id -Confirm:$false
        Write-Host "[+] Deleted group: $GroupName" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to delete group: $GroupName - $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[-] Group not found: $GroupName" -ForegroundColor Yellow
}

# Remove user PIM eligibilities
Write-Host "Removing user PIM eligibilities..." -ForegroundColor Cyan

$LowPrivUser = Get-MgUser -Filter "userPrincipalName eq '$LowPrivUPN'" -ErrorAction SilentlyContinue
if ($LowPrivUser) {
    try {
        # Get all group eligibilities for the user
        $eligibilities = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '$($LowPrivUser.Id)'" -ErrorAction Stop
        
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
                Write-Host "[+] Removed PIM eligibility for user" -ForegroundColor Green
            } catch {
                Write-Host "[-] Failed to remove PIM eligibility: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } catch {
        # Expected if running without PIM admin permissions
        Write-Host "[-] Cannot access PIM eligibilities (requires PIM admin permissions)" -ForegroundColor Yellow
        Write-Host "    PIM eligibilities will be cleaned up when user is deleted" -ForegroundColor Yellow
    }
}

Write-Host "Cleaning up service principal ownership relationships..." -ForegroundColor Cyan

$LegacySP = Get-MgServicePrincipal -Filter "displayName eq '$LegacyAutomationAppName'" -ErrorAction SilentlyContinue
$DataSyncSP = Get-MgServicePrincipal -Filter "displayName eq '$DataSyncAppName'" -ErrorAction SilentlyContinue
$DataSyncApp = Get-MgApplication -Filter "displayName eq '$DataSyncAppName'" -ErrorAction SilentlyContinue

if ($LegacySP -and $DataSyncSP) {
    try {
        $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $DataSyncSP.Id
        $legacyOwner = $owners | Where-Object { $_.Id -eq $LegacySP.Id }
        if ($legacyOwner) {
            Remove-MgServicePrincipalOwnerByRef -ServicePrincipalId $DataSyncSP.Id -DirectoryObjectId $LegacySP.Id
            Write-Host "[+] Removed Legacy SP ownership of DataSync SP" -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Failed to remove SP ownership: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($LegacySP -and $DataSyncApp) {
    try {
        $appOwners = Get-MgApplicationOwner -ApplicationId $DataSyncApp.Id
        $legacyAppOwner = $appOwners | Where-Object { $_.Id -eq $LegacySP.Id }
        if ($legacyAppOwner) {
            Remove-MgApplicationOwnerByRef -ApplicationId $DataSyncApp.Id -DirectoryObjectId $LegacySP.Id
            Write-Host "[+] Removed Legacy SP ownership of DataSync Application" -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Failed to remove Application ownership: $($_.Exception.Message)" -ForegroundColor Red
    }
}
#endregion

# Cleanup Users
Write-Host "Removing users..." -ForegroundColor Cyan

foreach ($UserUPN in @($LowPrivUPN, $AdminUPN) + $dummyUserUPNs) {
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

# Cleanup SPs and Apps
Write-Host "Removing service principals and application registrations..." -ForegroundColor Cyan

foreach ($AppName in @($LegacyAutomationAppName, $DataSyncAppName, $OrgConfigAppName)) {
    $App = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue
    
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
        }

        # Delete app registration
        try {
            Remove-MgApplication -ApplicationId $App.Id -Confirm:$false
            Write-Host "[+] Deleted application: $AppName" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to delete application: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] Application not found: $AppName" -ForegroundColor Yellow
    }
}

# Clean up CBA configurations
Write-Host "Checking for CBA configurations..." -ForegroundColor Cyan
try {
    $authPolicy = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "X509Certificate"
    if ($authPolicy -and $authPolicy.State -eq "enabled") {
        Write-Host "[!] CBA is enabled - disabling it..." -ForegroundColor Yellow
        
        try {
            $updateParams = @{
                State = "disabled"
                "@odata.type" = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
            }
            
            Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
                -AuthenticationMethodConfigurationId "X509Certificate" `
                -BodyParameter $updateParams
            
            Write-Host "[+] CBA has been disabled" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to disable CBA: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[*] CBA is not enabled" -ForegroundColor Gray
    }
} catch {
    Write-Host "[-] Could not check CBA configuration: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Clean up any malicious root CAs
Write-Host "Checking for malicious root CAs..." -ForegroundColor Cyan
Write-Host "Checking for any *EntraGoat* / *Evil* root CAs to avoid deletion of legitimate ones." -ForegroundColor Cyan
Write-Host "IMPORTANT: if you used a different Subject field please edit this section for proper cleanup or remove it manually " -ForegroundColor Cyan

try {
    $configs = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/organization/$($Organization.Id)/certificateBasedAuthConfiguration"
    
    if ($configs.value -and $configs.value.Count -gt 0) {
        foreach ($config in $configs.value) {
            if ($config.certificateAuthorities -and $config.certificateAuthorities.Count -gt 0) {
                $legitimateCAs = @()
                $removedCount = 0
                
                foreach ($ca in $config.certificateAuthorities) {
                    try {
                        $certBytes = [Convert]::FromBase64String($ca.certificate)
                        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                        
                        # Check for malicious certificate subjects (case-insensitive)
                        if ($cert.Subject -match "(?i)(EntraGoat|Evil)") {
                            Write-Host "[!] Found malicious CA: $($cert.Subject)" -ForegroundColor Red
                            $removedCount++
                        } else {
                            $legitimateCAs += $ca
                            Write-Host "[*] Keeping legitimate CA: $($cert.Subject)" -ForegroundColor Gray
                        }
                    } catch {
                        Write-Host "[-] Could not parse certificate, removing it as suspicious" -ForegroundColor Yellow
                        $removedCount++
                    }
                }
                
                if ($removedCount -gt 0) {
                    if ($legitimateCAs.Count -gt 0) {
                        # Update configuration with only legitimate CAs
                        $updateBody = @{
                            certificateAuthorities = $legitimateCAs
                        } | ConvertTo-Json -Depth 10
                        
                        Invoke-MgGraphRequest -Method PATCH `
                            -Uri "https://graph.microsoft.com/v1.0/organization/$($Organization.Id)/certificateBasedAuthConfiguration/$($config.id)" `
                            -Body $updateBody -ContentType "application/json"
                        
                        Write-Host "[+] Removed $removedCount malicious CA(s), kept $($legitimateCAs.Count) legitimate CA(s)" -ForegroundColor Green
                    } else {
                        # Delete entire configuration if no legitimate CAs remain
                        Invoke-MgGraphRequest -Method DELETE `
                            -Uri "https://graph.microsoft.com/v1.0/organization/$($Organization.Id)/certificateBasedAuthConfiguration/$($config.id)"
                        
                        Write-Host "[+] Removed entire CBA configuration (contained only malicious CAs)" -ForegroundColor Green
                    }
                } else {
                    Write-Host "[*] No malicious certificate authorities found in this configuration" -ForegroundColor Gray
                }
            }
        }
    } else {
        Write-Host "[*] No certificate-based auth configurations found" -ForegroundColor Gray
    }
} catch {
    Write-Host "[-] Failed to check/remove certificate authorities: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[!] Manual CA cleanup required via Entra admin center" -ForegroundColor Yellow
}

# Wait until all target objects are truly deleted
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
            Write-Host "[+] Confirmed inexistence of $UPN and $AppName" 
            return
        }
        Start-Sleep -Seconds 3
    }
    Write-Host "[-] Warning: Timed out waiting for deletion of $UPN or $AppName." -ForegroundColor Yellow
}

Write-Host "Waiting for all objects to be fully purged..." -ForegroundColor Cyan
Wait-ForDeletion -UPN $LowPrivUPN -AppName $LegacyAutomationAppName
Wait-ForDeletion -UPN $AdminUPN -AppName $DataSyncAppName
Wait-ForDeletion -UPN $AdminUPN -AppName $OrgConfigAppName

Write-Host "`nCleanup process complete." -ForegroundColor Cyan
Write-Host ""
Write-Host "[!] Important notes:" -ForegroundColor Yellow
Write-Host "    - CBA configuration has been checked and disabled if it was enabled" -ForegroundColor White
Write-Host "    - Certificate authorities have been checked for suspicious entries" -ForegroundColor White
Write-Host "    - Manually review any remaining certificate authorities for legitimacy" -ForegroundColor White
Write-Host ""

Disconnect-MgGraph -ErrorAction SilentlyContinue