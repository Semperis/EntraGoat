import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import HomePage from './components/HomePage';
import ChallengePage from './components/ChallengePage';
import './App.css';

function App() {
  // Load initial state from localStorage or use default
  const getInitialChallenges = () => {
    const savedChallenges = localStorage.getItem('entragoat-challenges');
    if (savedChallenges) {
      return JSON.parse(savedChallenges);
    }
    
    // Default challenges data
    return [
    {
      id: 1,
      title: 'Misowned and Dangerous - Owner\'s Manual to Global Admin',
      description: 'After weeks of OSINT and phishing attempts, your payload finally hit home. David Martinez, a distracted financial analyst, clicked the link and entered his corporate credentials. Now you\'re in. Time to see how far these Finance creds can take you. Escalate privileges and sign in as the Global Administrator to retrieve the flag.',
      difficulty: 'Beginner',
      flag: 'EntraGoat{SP_0wn3rsh1p_Pr1v_Esc@l@t10n_Congratz!}',
      startingCredentials: {
        username: 'david.martinez@yourtenant.onmicrosoft.com',
        password: 'GoatAccess!123'
      },
      hints: [
        'First rule of post-exploitation: enumerate everything.',
        'Ownership has its privileges. What do you really own?',
        'Authentication admins love to delegate. Maybe too much.',
        'Service principals with privileged roles present interesting opportunities.',
        'Privileged Authentication Administrator can set and reset authentication method information for any user in the tenant.',
      ],
      completed: false
    },
    {
      id: 2,
      title: 'Graph Me the Crown (and Role)',
      description: 'The credentials dump you bought on BreachForums turned out to be gold - Jennifer Clark\'s password from a recent breach still works. She\'s a dev who pushes to prod from half-baked CI/CD scripts. While inspecting her DevOps logs, you found an exposed PFX in the logs! Use what you\'ve got, escalate what you need, and work the Graph API chain to reach Global Admin privileges.',
      difficulty: 'Beginner',
      flag: 'EntraGoat{4P1_P37mission_4bus3_Succ3ss!}',
      startingCredentials: {
        username: 'jennifer.clark@yourtenant.onmicrosoft.com',
        password: 'GoatAccess!123',
        certificate: '[PROVIDED_DURING_SETUP]' // Placeholder for the certificate used in the challenge
      },
      hints: [
        'Investigate any leaked credentials or certificates.',
        'Review the Graph permissions granted to the app.',
        'Permission chaining is your path to the crown',
        'AppRoleAssignment.ReadWrite.All allows granting additional permissions',
        'RoleManagement.ReadWrite.Directory is the key to (ANY) directory roles'
      ],
      completed: false
    },
    {
      id: 3,
      title: 'Group MemberShipwreck - Sailed into Admin Waters',
      description: 'Access obtained for Michael Chen, an overworked IT Support Specialist. He manages a few security groups with role assignments - and one of them just might be your VIP pass to the admin seats. Chain group memberships and escalate through service principal entanglements to authenticate as the admin user to capture the flag.',
      difficulty: 'Beginner',
      flag: 'EntraGoat{Gr0up_Ch@1n_Pr1v_Esc@l@t10n!}',
      startingCredentials: {
        username: 'michael.chen@yourtenant.onmicrosoft.com',
        password: 'GoatAccess!123'
      },
      hints: [
        'Owning a group isn\'t harmless, right?',
        'Groups can have role assignments.',
        'Application Administrators can manage service principals, but how?',
        'Service principals can be members of groups too.',
        'Privileged Authentication Administrator can set and reset authentication method information for any user in the tenant.',
      ],
      completed: false
    },
    {
      id: 4,
      title: 'I (Eligibly) Own That',
      description: 'You landed inside an Entra ID account that looks... promising. Somewhere between group memberships and role assignments, something feels elevated. The catch? Nothing\'s active by default. Explore your standing in Privileged Identity Management, activate the right access, and chain your way into Global Admin territory.',
      difficulty: 'Intermediate',
      flag: 'EntraGoat{PIM_Gr0up_Pr1v_Esc@l@t10n_2025!}',
      startingCredentials: {
        username: 'woody.chen@yourtenant.onmicrosoft.com',
        password: 'GoatAccess!123'
      },
      hints: [
        'Group owners can manage group memberships (and even add themselves..)',
        'Check your PIM assignments, either through the CLI, Azure portal or Entra admin center. You might be more eligible than you think.',
        'Group-based role eligibility can create interesting chains.',
        'Combine activated access and clever targeting.',
        'Global Administrators are.. well.. Global Administrators. They can reset any password (and MFA).'
      ],
      completed: false
    },
    {
      id: 5,
      title: 'Department of Escalations - AU Ready for This?',
      description: 'You\'re embedded in a stealthy APT crew - each unit plays a role: credential harvesting, infrastructure recon, privilege escalation, persistence, and data exfiltration for diplomatic leverage. You\'re on the escalation arm. The access team just tossed you credentials for Sarah Connor, an HR team lead with permissions subtle enough to evade scrutiny, but strong enough to be weaponized. Your mission? Poison profile attributes, slip through a dynamic AU like a ghost in the directory, and punch a Global Admin backdoor for the persistence team. Time\'s tight, negotiations won\'t wait.',
      difficulty: 'Advanced',
      flag: 'EntraGoat{Dyn@m1c_AU_P01s0n1ng_FTW!}',
      startingCredentials: {
        username: 'sarah.connor@yourtenant.onmicrosoft.com',
        password: 'GoatAccess!123'
      },
      hints: [
        'Basic update permissions can have big impact.',
        'Check your PIM assignments, either through the CLI, Azure portal or Entra admin center. You might be more eligible than you think.',
        'A little profile poisoning goes a long way in dynamic AUs.',
        'Administrative Unit role assignments may be scoped but still powerful.',
        'Privileged Authentication Administrator can set and reset authentication method information for any user in the tenant.',
      ],
      completed: false
    },
    {
      id: 6,
      title: 'CBA (Certificate Bypass Authority) - Root Access Granted',
      description: 'While rummaging through a neglected PowerShell repo, you hit the jackpot: hardcoded client secrets for a forgotten automation SP. Turns out it\'s still trusted (and still dangerous) - use it to explore other service principals, abuse authentication method permissions, and sneak your own certificate authority into the tenant. Chain service principal (mis)configurations to pierce the trust boundary, impersonate the admin without touching a password, and enjoy passwordless admin access, permanently.',
      difficulty: 'Advanced',
      flag: 'EntraGoat{C3rt_Byp@ss_R00t3d_4dm1n}',
      startingCredentials: {
        username: 'terence.mckenna@yourtenant.onmicrosoft.com',
        password: 'TheGoatAccess!123',
        clientId: '[PROVIDED_DURING_SETUP]', // Placeholder
        clientSecret: '[PROVIDED_DURING_SETUP]' // Placeholder
      },
      hints: [
        'Leaked creds? Time to check what legacy automation SP can still do.',
        'Ownership = privilges. SPs managing other SPs is a red flag.',
        'Service principals with Policy.* and Org.* permissions are dangerous (like really dangerous)',
        'Authentication Policy Administrator role allows enabling CBA when it is granted to a user (or to a group..)',
        'Try enabling CBA with one SP, then use another to upload a trusted root CA and forge your way in. No password? No problem.'
      ],
      completed: false
    }
  ];
  };

  const [challenges, setChallenges] = useState(getInitialChallenges);

  // Save to localStorage whenever challenges change
  useEffect(() => {
    localStorage.setItem('entragoat-challenges', JSON.stringify(challenges));
  }, [challenges]);

  // Function to mark challenge as completed
  const completeChallenge = (id) => {
    setChallenges(
      challenges.map(challenge => 
        challenge.id === id ? { ...challenge, completed: true } : challenge
      )
    );
  };

  return (
    <Router>
      <div className="app">
        <Routes>
          <Route 
            path="/" 
            element={<HomePage challenges={challenges} onChallengeComplete={completeChallenge} />} 
          />
          <Route 
            path="/challenge/:id" 
            element={<ChallengePage challenges={challenges} completeChallenge={completeChallenge} />} 
          />
        </Routes>
      </div>
    </Router>
  );
}

export default App;