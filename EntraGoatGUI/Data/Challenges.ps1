function Get-EntraGoatChallenges {
    # ------------------------------------------------------------------------
    # EntraGoat challenge metadata for the PowerShell GUI.
    #
    # IMPORTANT: This data is duplicated from frontend/src/App.js (lines ~16-180).
    # Pick ONE GUI per session (web OR PowerShell) and stick with it - completion
    # state is NOT shared between them. If you change challenge data in App.js,
    # update this file as well (or vice versa).
    # ------------------------------------------------------------------------
    $Challenges = @(
        @{
            Id          = 1
            Title       = "Misowned and Dangerous - Owner's Manual to Global Admin"
            Description = "After weeks of OSINT and phishing attempts, your payload finally hit home. David Martinez, a distracted financial analyst, clicked the link and entered his corporate credentials. Now you're in. Time to see how far these Finance creds can take you. Escalate privileges and sign in as the Global Administrator to retrieve the flag."
            Difficulty  = 'Beginner'
            Flag        = 'EntraGoat{SP_0wn3rsh1p_Pr1v_Esc@l@t10n_Congratz!}'
            StartingCredentials = [ordered]@{
                Username = 'david.martinez@yourtenant.onmicrosoft.com'
                Password = 'GoatAccess!123'
            }
            Hints = @(
                'First rule of post-exploitation: enumerate everything.'
                'Ownership has its privileges. What do you really own?'
                'Authentication admins love to delegate. Maybe too much.'
                'Service principals with privileged roles present interesting opportunities.'
                'Privileged Authentication Administrator can set and reset authentication method information for any user in the tenant.'
            )
        }
        @{
            Id          = 2
            Title       = 'Graph Me the Crown (and Role)'
            Description = "The credentials dump you bought on BreachForums turned out to be gold - Jennifer Clark's password from a recent breach still works. She's a dev who pushes to prod from half-baked CI/CD scripts. While inspecting her DevOps logs, you found an exposed PFX in the logs! Use what you've got, escalate what you need, and work the Graph API chain to reach Global Admin privileges."
            Difficulty  = 'Beginner'
            Flag        = 'EntraGoat{4P1_P37mission_4bus3_Succ3ss!}'
            StartingCredentials = [ordered]@{
                Username    = 'jennifer.clark@yourtenant.onmicrosoft.com'
                Password    = 'GoatAccess!123'
                Certificate = '[PROVIDED_DURING_SETUP]'
            }
            Hints = @(
                'Investigate any leaked credentials or certificates.'
                'Review the Graph permissions granted to the app.'
                'Permission chaining is your path to the crown'
                'AppRoleAssignment.ReadWrite.All allows granting additional permissions'
                'RoleManagement.ReadWrite.Directory is the key to (ANY) directory roles'
            )
        }
        @{
            Id          = 3
            Title       = 'Group MemberShipwreck - Sailed into Admin Waters'
            Description = 'Access obtained for Michael Chen, an overworked IT Support Specialist. He manages a few security groups with role assignments - and one of them just might be your VIP pass to the admin seats. Chain group memberships and escalate through service principal entanglements to authenticate as the admin user to capture the flag.'
            Difficulty  = 'Beginner'
            Flag        = 'EntraGoat{Gr0up_Ch@1n_Pr1v_Esc@l@t10n!}'
            StartingCredentials = [ordered]@{
                Username = 'michael.chen@yourtenant.onmicrosoft.com'
                Password = 'GoatAccess!123'
            }
            Hints = @(
                "Owning a group isn't harmless, right?"
                'Groups can have role assignments.'
                'Application Administrators can manage service principals, but how?'
                'Service principals can be members of groups too.'
                'Privileged Authentication Administrator can set and reset authentication method information for any user in the tenant.'
            )
        }
        @{
            Id          = 4
            Title       = 'I (Eligibly) Own That'
            Description = "You landed inside an Entra ID account that looks... promising. Somewhere between group memberships and role assignments, something feels elevated. The catch? Nothing's active by default. Explore your standing in Privileged Identity Management, activate the right access, and chain your way into Global Admin territory."
            Difficulty  = 'Intermediate'
            Flag        = 'EntraGoat{PIM_Gr0up_Pr1v_Esc@l@t10n_2025!}'
            StartingCredentials = [ordered]@{
                Username = 'woody.chen@yourtenant.onmicrosoft.com'
                Password = 'GoatAccess!123'
            }
            Hints = @(
                'Group owners can manage group memberships (and even add themselves..)'
                'Check your PIM assignments, either through the CLI, Azure portal or Entra admin center. You might be more eligible than you think.'
                'Group-based role eligibility can create interesting chains.'
                'Combine activated access and clever targeting.'
                'Global Administrators are.. well.. Global Administrators. They can reset any password (and MFA).'
            )
        }
        @{
            Id          = 5
            Title       = 'Department of Escalations - AU Ready for This?'
            Description = "You're embedded in a stealthy APT crew - each unit plays a role: credential harvesting, infrastructure recon, privilege escalation, persistence, and data exfiltration for diplomatic leverage. You're on the escalation arm. The access team just tossed you credentials for Sarah Connor, an HR team lead with permissions subtle enough to evade scrutiny, but strong enough to be weaponized. Your mission? Poison profile attributes, slip through a dynamic AU like a ghost in the directory, and punch a Global Admin backdoor for the persistence team. Time's tight, negotiations won't wait."
            Difficulty  = 'Advanced'
            Flag        = 'EntraGoat{Dyn@m1c_AU_P01s0n1ng_FTW!}'
            StartingCredentials = [ordered]@{
                Username = 'sarah.connor@yourtenant.onmicrosoft.com'
                Password = 'GoatAccess!123'
            }
            Hints = @(
                'Basic update permissions can have big impact.'
                'Check your PIM assignments, either through the CLI, Azure portal or Entra admin center. You might be more eligible than you think.'
                'A little profile poisoning goes a long way in dynamic AUs.'
                'Administrative Unit role assignments may be scoped but still powerful.'
                'Privileged Authentication Administrator can set and reset authentication method information for any user in the tenant.'
            )
        }
        @{
            Id          = 6
            Title       = 'CBA (Certificate Bypass Authority) - Root Access Granted'
            Description = "While rummaging through a neglected PowerShell repo, you hit the jackpot: hardcoded client secrets for a forgotten automation SP. Turns out it's still trusted (and still dangerous) - use it to explore other service principals, abuse authentication method permissions, and sneak your own certificate authority into the tenant. Chain service principal (mis)configurations to pierce the trust boundary, impersonate the admin without touching a password, and enjoy passwordless admin access, permanently."
            Difficulty  = 'Advanced'
            Flag        = 'EntraGoat{C3rt_Byp@ss_R00t3d_4dm1n}'
            StartingCredentials = [ordered]@{
                Username     = 'terence.mckenna@yourtenant.onmicrosoft.com'
                Password     = 'TheGoatAccess!123'
                ClientId     = '[PROVIDED_DURING_SETUP]'
                ClientSecret = '[PROVIDED_DURING_SETUP]'
            }
            Hints = @(
                'Leaked creds? Time to check what legacy automation SP can still do.'
                'Ownership = privilges. SPs managing other SPs is a red flag.'
                'Service principals with Policy.* and Org.* permissions are dangerous (like really dangerous)'
                'Authentication Policy Administrator role allows enabling CBA when it is granted to a user (or to a group..)'
                'Try enabling CBA with one SP, then use another to upload a trusted root CA and forge your way in. No password? No problem.'
            )
        }
        @{
            Id          = 7
            Title       = 'Legacy Loophole - When MFA Forgot the Side Door'
            Description = "Raj Patel runs the messaging stack and remembers every helpdesk shortcut the team ever cut. The tenant rolled out a 'Require MFA for All Users' Conditional Access policy last quarter, but the messaging admin account still answers IMAP and SMTP AUTH for an old line-of-business mailbox. Find the gap in the policy, ride a legacy-auth path past MFA, and lift the flag from the admin's profile."
            Difficulty  = 'Beginner'
            Flag        = 'EntraGoat{L3g@cy_4uth_C0nd1t10n@l_Byp@ss_Pwn3d!}'
            StartingCredentials = [ordered]@{
                Username = 'raj.patel@yourtenant.onmicrosoft.com'
                Password = 'GoatAccess!123'
            }
            Hints = @(
                'Conditional Access scopes "client app types" as an allow-list. Look at what is actually scoped.'
                'Modern auth and legacy auth are NOT the same channel for CA evaluation.'
                'ROPC, IMAP, POP, SMTP AUTH and ActiveSync are all "legacy" - any of them will do.'
                'Helpdesk reset passwords have a habit of sticking around.'
                'Microsoft publishes a "Block legacy authentication" CA template for a reason.'
            )
        }
    )
    @{ Challenges = $Challenges }
}
