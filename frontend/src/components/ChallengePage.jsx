import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import SetupFileModal from './SetupFileModal';
import '../styles/ChallengePage.css';

function ChallengePage({ challenges, completeChallenge }) {
  const { id } = useParams();
  const [flagInput, setFlagInput] = useState('');
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');
  const [showHints, setShowHints] = useState([]);
  const [showSetupModal, setShowSetupModal] = useState(false);
  const [setupModalType, setSetupModalType] = useState('setup');
  
  // Find the current challenge
  const challenge = challenges.find(c => c.id === parseInt(id)) || challenges[0];

  // Initialize hint visibility state based on the number of hints
  useEffect(() => {
    setShowHints(Array(challenge.hints.length).fill(false));
  }, [challenge]);

  const handleFlagSubmit = (e) => {
    e.preventDefault();
    if (flagInput.trim() === challenge.flag) {
      completeChallenge(challenge.id);
      setMessage('🎉 Correct flag! Challenge completed!');
      setMessageType('success');
      setFlagInput('');
    } else {
      setMessage('[ERROR] Incorrect flag. Try again!');
      setMessageType('error');
    }
  };

  const toggleHint = (index) => {
    setShowHints(prevHints => {
      const newHints = [...prevHints];
      newHints[index] = !newHints[index];
      return newHints;
    });
  };

  const renderCredentials = () => {
    const { startingCredentials } = challenge;
    
    return (
      <div className="starting-credentials">
        <h3>Starting Credentials</h3>
        
        {startingCredentials.username && (
          <p>
            <strong>Username:</strong>
            <span className="credential-value">{startingCredentials.username}</span>
          </p>
        )}
        
        {startingCredentials.password && (
          <p>
            <strong>Password:</strong>
            <span className="credential-value">{startingCredentials.password}</span>
          </p>
        )}
        
        {startingCredentials.certificate && (
          <p>
            <strong>Certificate:</strong>
            <span className="credential-value">{startingCredentials.certificate}</span>
          </p>
        )}
        
        {startingCredentials.clientId && (
          <p>
            <strong>Client ID:</strong>
            <span className="credential-value">{startingCredentials.clientId}</span>
          </p>
        )}
        
        {startingCredentials.clientSecret && (
          <p>
            <strong>Client Secret:</strong>
            <span className="credential-value">{startingCredentials.clientSecret}</span>
          </p>
        )}
        
        {startingCredentials.servicePrincipalName && (
          <p>
            <strong>Service Principal:</strong>
            <span className="credential-value">{startingCredentials.servicePrincipalName}</span>
          </p>
        )}
        
        {startingCredentials.appId && (
          <p>
            <strong>App ID:</strong>
            <span className="credential-value">{startingCredentials.appId}</span>
          </p>
        )}
        
        {startingCredentials.appName && (
          <p>
            <strong>App Name:</strong>
            <span className="credential-value">{startingCredentials.appName}</span>
          </p>
        )}
      </div>
    );
  };

  const getDifficultyClass = (difficulty) => {
    return `difficulty-badge difficulty-${difficulty.toLowerCase()}`;
  };

  // Navigation to next/previous challenges
  const currentIndex = challenges.findIndex(c => c.id === challenge.id);
  const nextChallenge = challenges[currentIndex + 1];
  const prevChallenge = challenges[currentIndex - 1];

  return (
    <div className="challenge-page">
      <div className="page-header">
        <Link to="/" className="back-button">
          ← Back to Home
        </Link>
        
        <div className="challenge-navigation">
          {prevChallenge && (
            <Link to={`/challenge/${prevChallenge.id}`} className="nav-button prev">
              ← Challenge {prevChallenge.id}
            </Link>
          )}
          {nextChallenge && (
            <Link to={`/challenge/${nextChallenge.id}`} className="nav-button next">
              Challenge {nextChallenge.id} ->
            </Link>
          )}
        </div>
      </div>
      
      <div className={`challenge-container ${challenge.completed ? 'completed' : ''}`}>
        <div className="challenge-header">
          <div className="challenge-meta-info">
            <div className="challenge-id">Challenge #{challenge.id}</div>
            <span className={getDifficultyClass(challenge.difficulty)}>
              {challenge.difficulty}
            </span>
            {challenge.completed && (
              <div className="completed-status">
                [OK] COMPLETED
              </div>
            )}
          </div>
          
          <h1>{challenge.title}</h1>
          
          <div className="challenge-description">
            {challenge.description}
          </div>
        </div>
        
        {renderCredentials()}
        
        <div className="tools-section">
          <h3>Challenge Resources</h3>
          <div className="setup-section">
            <button 
              className="setup-file-btn"
              onClick={() => {
                setSetupModalType('setup');
                setShowSetupModal(true);
              }}
            >
              ⚙️ View Setup Script
            </button>
            <button 
              className="cleanup-file-btn"
              onClick={() => {
                setSetupModalType('cleanup');
                setShowSetupModal(true);
              }}
            >
              🧹 View Cleanup Script
            </button>
          </div>
        </div>
        
        {challenge.completed ? (
          <div className="success-message">
            <h2>Challenge Completed!</h2>
            <p>Congratulations! You've successfully completed this challenge.</p>
            <p><strong>Flag:</strong> <code>{challenge.flag}</code></p>
            <div className="completion-actions">
              {nextChallenge && (
                <Link to={`/challenge/${nextChallenge.id}`} className="next-challenge-btn">
                  Next Challenge ->
                </Link>
              )}
              <Link to="/" className="home-btn">
                View All Challenges
              </Link>
            </div>
          </div>
        ) : (
          <>
            <div className="flag-submission">
              <h3>Submit Flag</h3>
              <form onSubmit={handleFlagSubmit}>
                <input
                  type="text"
                  placeholder="EntraGoat{your_flag_here}"
                  value={flagInput}
                  onChange={(e) => setFlagInput(e.target.value)}
                  autoComplete="off"
                  spellCheck="false"
                />
                <button type="submit">Submit Flag</button>
              </form>
              
              {message && (
                <div className={`message ${messageType}`}>
                  {message}
                </div>
              )}
            </div>
            
            <div className="hints-section">
              <h3>Hints & Guidance</h3>
              <div className="hints-grid">
                {challenge.hints.map((hint, index) => (
                  <div key={index} className="hint">
                    <button 
                      type="button"
                      className={showHints[index] ? 'open' : ''}
                      onClick={() => toggleHint(index)}
                    >
                      <span className="hint-title">Hint {index + 1}</span>
                      <span className="hint-icon">{showHints[index] ? '−' : '+'}</span>
                    </button>
                    {showHints[index] && (
                      <div className="hint-content">
                        <p>{hint}</p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
      
      <SetupFileModal 
        isOpen={showSetupModal}
        onClose={() => setShowSetupModal(false)}
        challengeId={challenge.id}
        challengeTitle={challenge.title}
        scriptType={setupModalType}
      />
    </div>
  );
}

export default ChallengePage;