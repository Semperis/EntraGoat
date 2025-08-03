<#
.SYNOPSIS
EntraGoat Scenario 6: Cleanup Script
Removes all resources created for Scenario 6

.DESCRIPTION
Cleans up:
- Users (low-priv-user-s6, admin-user-s6)
- Application registrations and service principals (Legacy and DataSync)
- Any CBA configurations that may have been added
- Any malicious root CAs that may have been added
#>

# Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $null
)

# Configuration
$LegacyAutomationAppName = "Automation-SP-Legacy"
$DataSyncAppName = "DataSync-SP-Prod"
$AuthPolicyAdminAppName = "AuthPolicy-Admin-SP"

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
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "            ENTRAGOAT SCENARIO 6 - CLEANUP PROCESS              " -ForegroundColor Cyan
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
$LowPrivUPN = "terence.mckenna@$TenantDomain"
$AdminUPN = "EntraGoat-admin-s6@$TenantDomain"

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

# Cleanup SPs and Apps
Write-Host "Removing service principals and application registrations..." -ForegroundColor Cyan

foreach ($AppName in @($LegacyAutomationAppName, $DataSyncAppName, $AuthPolicyAdminAppName)) {
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
Write-Host "Checking for any *Entra* / *Evil* root CAs to avoid deletion of legitimate ones." -ForegroundColor Cyan
Write-Host "IMPORTANT: if you used a different Subject field please edit this section for proper cleanup or remove it manually " -ForegroundColor Cyan


# try {
#     $org = Get-MgOrganization
#     $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization/$($org.Id)/certificateBasedAuthConfiguration"
#     if ($response.certificateAuthorities) {
#         $evilCAs = $response.certificateAuthorities | Where-Object {
#             $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($_.certificate))
#             $cert.Subject -match "EntraGoat|Evil"
#         }
#         if ($evilCAs) {
#             # Remove only the evil CAs, keep legitimate ones
#             $legitimateCAs = $response.certificateAuthorities | Where-Object {
#                 $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($_.certificate))
#                 $cert.Subject -notmatch "EntraGoat|Evil"
#             }
#             $body = @{
#                 certificateAuthorities = $legitimateCAs
#             } | ConvertTo-Json -Depth 10
#             
#             Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/organization/$($org.Id)/certificateBasedAuthConfiguration" -Body $body
#             Write-Host "[+] Removed malicious CAs while preserving legitimate ones" -ForegroundColor Green
#         }
#     }
# } catch {
#     Write-Host "[-] Manual CA cleanup required: $($_.Exception.Message)" -ForegroundColor Red
# }

try {
    $org = Get-MgOrganization
    if ($org.CertificateBasedAuthConfiguration -and $org.CertificateBasedAuthConfiguration.Count -gt 0) {
        Write-Host "[!] Found certificate-based auth configurations - removing..." -ForegroundColor Yellow
        
        # Look for any CAs that might have been added during exploitation
        $suspiciousCAs = $org.CertificateBasedAuthConfiguration | Where-Object {
            $_.CertificateAuthorities | Where-Object {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($_.Certificate))
                $cert.Subject -like "*EntraGoat*" -or $cert.Subject -like "*Evil*" # this can be adjusted based on your naming convention
            }
        }
        
        if ($suspiciousCAs) {
            # Remove the entire certificate configuration
            try {
                Update-MgOrganization -OrganizationId $org.Id -CertificateBasedAuthConfiguration @()
                Write-Host "[+] Removed certificate-based auth configurations" -ForegroundColor Green
            } catch {
                Write-Host "[-] Failed to remove certificate configurations: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "[!] Manual cleanup required - check organization certificate authorities" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[*] No suspicious certificate authorities found" -ForegroundColor Gray
            Write-Host "[!] Note: Review existing CAs manually to ensure they are legitimate" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[*] No certificate-based auth configurations found" -ForegroundColor Gray
    }
} catch {
    Write-Host "[-] Manual CA cleanup required." -ForegroundColor Red
    Write-Host "[-] Could not check certificate authorities: $($_.Exception.Message)" -ForegroundColor Yellow
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
Wait-ForDeletion -UPN $AdminUPN -AppName $AuthPolicyAdminAppName

Write-Host "`nCleanup process complete." -ForegroundColor Cyan
Write-Host ""
Write-Host "[!] Important notes:" -ForegroundColor Yellow
Write-Host "    - CBA configuration has been checked and disabled if it was enabled" -ForegroundColor White
Write-Host "    - Certificate authorities have been checked for suspicious entries" -ForegroundColor White
Write-Host "    - If CBA was used in production, review settings before re-enabling" -ForegroundColor White
Write-Host "    - Manually review any remaining certificate authorities for legitimacy" -ForegroundColor White
Write-Host ""

# Disconnect session
# Disconnect-MgGraph -ErrorAction SilentlyContinue