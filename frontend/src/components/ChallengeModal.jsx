import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import '../styles/ChallengeModal.css';

function ChallengeModal({ challenge, onClose, onChallengeComplete }) {
  const [flagInput, setFlagInput] = useState('');
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState('');

  const handleFlagSubmit = (e) => {
    e.preventDefault();
    if (flagInput.trim() === challenge.flag) {
      onChallengeComplete(challenge.id);
      setMessage('🎉 Correct flag! Challenge completed!');
      setMessageType('success');
      setFlagInput('');
    } else {
      setMessage('[ERROR] Incorrect flag. Try again!');
      setMessageType('error');
    }
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

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="modal-backdrop" onClick={handleBackdropClick}>
      <div className="modal-content">
        <button className="close-button" onClick={onClose} aria-label="Close modal">
          ×
        </button>
        
        <h2>{challenge.title}</h2>
        
        <div className="challenge-info">
          <p><strong>Description:</strong> {challenge.description}</p>
          <div className="difficulty-info">
            <strong>Difficulty:</strong>
            <span className={`difficulty-badge difficulty-${challenge.difficulty.toLowerCase()}`}>
              {challenge.difficulty}
            </span>
          </div>
        </div>
        
        {challenge.completed ? (
          <div className="success-message">
            <h3>🎉 Challenge Completed!</h3>
            <p>Congratulations! You've successfully completed this challenge.</p>
            <p><strong>Flag:</strong> <code>{challenge.flag}</code></p>
          </div>
        ) : (
          <div className="flag-submission">
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
        )}
        
        <Link to={`/challenge/${challenge.id}`} className="view-full-link">
          View Full Challenge Details ->
        </Link>
      </div>
    </div>
  );
}

export default ChallengeModal;