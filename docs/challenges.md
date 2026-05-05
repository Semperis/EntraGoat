# Challenges

EntraGoat ships with 6 privilege escalation scenarios of increasing difficulty. Each drops you into a realistic breach with a low-privilege starting identity and challenges you to escalate to Global Admin.

## Overview

| # | Title | Difficulty | Attack Vector |
|---|-------|-----------|---------------|
| 1 | Misowned and Dangerous — Owner's Manual to Global Admin | Beginner | Service principal ownership abuse |
| 2 | Graph Me the Crown (and Role) | Beginner | App-only Graph API permission exploitation |
| 3 | Group MemberShipwreck — Sailed into Admin Waters | Beginner | Group membership escalation chain |
| 4 | The Eligible Menace — PIM Path to Power | Intermediate | Privileged Identity Management abuse |
| 5 | AU to Admin — The Restricted Path | Advanced | Administrative Unit boundary escape |
| 6 | Certificate of Insanity — Trusting the Wrong Authority | Advanced | Certificate-based authentication impersonation |
| 7 | Legacy Loophole — When MFA Forgot the Side Door | Beginner | Conditional Access bypass via legacy authentication |

## How to play

1. Run the **setup script** for the scenario you want to attempt
2. Sign in with the **starting credentials** shown in the GUI (or terminal output)
3. Enumerate, discover the misconfiguration, exploit the attack path
4. Escalate to Global Admin and retrieve the **flag** (typically from `extensionAttribute1`)
5. Submit the flag in the GUI to mark the challenge complete
6. Run the **cleanup script** when done

## Difficulty guide

| Level | Expected knowledge |
|-------|-------------------|
| **Beginner** | Basic Entra ID concepts, Graph API enumeration |
| **Intermediate** | Service principals, app registrations, role assignments |
| **Advanced** | PIM, administrative units, certificate auth, multi-step chains |

## Solutions

⚠️ **Spoiler alert** — Solution scripts are in the `solutions/` directory.

Published walkthroughs:
- [Scenario 1: Service Principal Ownership Abuse](https://www.semperis.com/blog/service-principal-ownership-abuse-in-entra-id/)
- [Scenario 2: Exploiting App-Only Graph Permissions](https://www.semperis.com/blog/exploiting-app-only-graph-permissions-in-entra-id/)
- [Scenario 6: Certificate-Based Authentication Abuse](https://www.semperis.com/blog/exploiting-certificate-based-authentication-in-entra-id/)
