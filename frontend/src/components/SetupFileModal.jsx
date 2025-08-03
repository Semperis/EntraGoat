import React, { useState, useEffect } from 'react';
import '../styles/SetupFileModal.css';

const SetupFileModal = ({ isOpen, onClose, challengeId, challengeTitle, scriptType = 'setup' }) => {
  const [copied, setCopied] = useState(false);
  const [scriptContent, setScriptContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const filename = `entragoat-challenge${challengeId}-${scriptType}.ps1`;
  const scriptPath = `/scripts/challenge${challengeId}/${scriptType}.ps1`;

  useEffect(() => {
    if (isOpen && challengeId) {
      fetchScript();
    }
  }, [isOpen, challengeId, scriptType]);

  const fetchScript = async () => {
    setLoading(true);
    setError('');
    
    try {
      const response = await fetch(scriptPath);
      if (!response.ok) {
        throw new Error(`Script not found: ${response.status}`);
      }
      const content = await response.text();
      setScriptContent(content);
    } catch (err) {
      console.error('Error fetching script:', err);
      setError('Failed to load script file. Please ensure the script exists in the public/scripts folder.');
      setScriptContent(`# Error loading script
# Please check that the file exists at: public${scriptPath}
# 
# Expected file structure:
# public/
#   scripts/
#     challenge${challengeId}/
#       ${scriptType}.ps1`);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(scriptContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy: ', err);
    }
  };

  const downloadFile = () => {
    const blob = new Blob([scriptContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  if (!isOpen) return null;

  const modalTitle = scriptType === 'setup' ? 'Setup Script' : 'Cleanup Script';
  const modalIcon = scriptType === 'setup' ? '⚙️' : '🧹';

  return (
    <div className="setup-modal-backdrop" onClick={handleBackdropClick}>
      <div className="setup-modal-content">
        <div className="setup-modal-header">
          <h2>{modalIcon} {modalTitle}</h2>
          <p>{challengeTitle}</p>
          <button className="close-button" onClick={onClose}>×</button>
        </div>

        <div className="setup-modal-body">
          <div className="file-header">
            <span className="filename">{filename}</span>
            <div className="file-actions">
              <button 
                className="copy-btn" 
                onClick={copyToClipboard}
                title="Copy to clipboard"
                disabled={loading}
              >
                {copied ? '[OK] Copied!' : '📋 Copy'}
              </button>
              <button 
                className="download-btn" 
                onClick={downloadFile}
                title="Download as .ps1 file"
                disabled={loading}
              >
                📥 Download
              </button>
            </div>
          </div>

          <div className="code-container">
            {loading ? (
              <div className="loading-container">
                <div className="loading-spinner"></div>
                <p>Loading script...</p>
              </div>
            ) : error ? (
              <div className="error-container">
                <p className="error-message">⚠️ {error}</p>
                <pre className="code-block">
                  <code className="powershell">{scriptContent}</code>
                </pre>
              </div>
            ) : (
              <pre className="code-block">
                <code className="powershell">{scriptContent}</code>
              </pre>
            )}
          </div>
        </div>

        <div className="setup-modal-footer">
          <p className="setup-note">
            {scriptType === 'setup' 
              ? '💡 Run this script in PowerShell with appropriate permissions to set up the challenge environment.'
              : '🧹 Run this script to clean up the challenge environment and remove created resources.'
            }
          </p>
        </div>
      </div>
    </div>
  );
};

export default SetupFileModal;
