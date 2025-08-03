import React, { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import ChallengeModal from './ChallengeModal';
import '../styles/HomePage.css';

function HomePage({ challenges, onChallengeComplete }) {
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedChallenge, setSelectedChallenge] = useState(null);

  // Calculate stats
  const stats = useMemo(() => {
    const completed = challenges.filter(c => c.completed).length;
    const total = challenges.length;
    const difficulties = challenges.reduce((acc, challenge) => {
      acc[challenge.difficulty.toLowerCase()] = (acc[challenge.difficulty.toLowerCase()] || 0) + 1;
      return acc;
    }, {});

    return {
      completed,
      total,
      percentage: total > 0 ? Math.round((completed / total) * 100) : 0,
      difficulties
    };
  }, [challenges]);

  const openModal = (challenge) => {
    setSelectedChallenge(challenge);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setSelectedChallenge(null);
  };

  const handleChallengeComplete = (challengeId) => {
    // Update the challenge state in the parent component
    const updatedChallenges = challenges.map(challenge => 
      challenge.id === challengeId ? { ...challenge, completed: true } : challenge
    );
    // Since we can't directly update the parent state from here,
    // we'll need to pass this function from the parent
    console.log('Challenge completed:', challengeId);
  };

  const getDifficultyClass = (difficulty) => {
    return `difficulty-badge difficulty-${difficulty.toLowerCase()}`;
  };

  return (
    <div className="home-container">
      {/* Logo/Title Section */}
      <div className="logo-container">
        <img src="/assets/logoEntra.png" alt="Entra Goat Logo" />
      </div>
      
      <h1 className="title">ENTRA GOAT</h1>
      <p className="subtitle">
        Master Microsoft Entra ID Security Through Realistic Attack Scenarios. 
        Test your skills, escalate privileges, and discover the hidden vulnerabilities 
        in Azure Active Directory configurations.
      </p>

      {/* Stats Section */}
      <div className="stats-section">
        <div className="stat-card">
          <span className="stat-number">{stats.completed}</span>
          <span className="stat-label">Completed</span>
        </div>
        <div className="stat-card">
          <span className="stat-number">{stats.total}</span>
          <span className="stat-label">Total Challenges</span>
        </div>
        <div className="stat-card">
          <span className="stat-number">{stats.percentage}%</span>
          <span className="stat-label">Progress</span>
        </div>
      </div>
      
      {/* Challenges Grid */}
      <div className="challenges-grid">
        {challenges.map((challenge, index) => (
          <div 
            key={challenge.id} 
            className={`challenge-card ${challenge.completed ? 'completed' : ''}`}
            onClick={() => openModal(challenge)}
          >
            <div className="challenge-index">{challenge.id}</div>
            
            <div className="challenge-header">
              <h2 className="challenge-title">{challenge.title}</h2>
              <p className="challenge-description">{challenge.description}</p>
            </div>
            
            <div className="challenge-meta">
              <span className={getDifficultyClass(challenge.difficulty)}>
                {challenge.difficulty}
              </span>
              
              {challenge.completed && (
                <div className="completed-badge">
                  [OK] COMPLETED
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Modal */}
      {modalOpen && selectedChallenge && (
        <ChallengeModal 
          challenge={selectedChallenge} 
          onClose={closeModal}
          onChallengeComplete={onChallengeComplete}
        />
      )}
    </div>
  );
}

export default HomePage;