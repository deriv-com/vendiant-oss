'use client';

import React from 'react';
import { signOut } from '../lib/user-context';

interface LogoutConfirmationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
}

const LogoutConfirmationModal: React.FC<LogoutConfirmationModalProps> = ({
  isOpen,
  onClose,
  onConfirm
}) => {
  if (!isOpen) return null;

  const handleConfirm = async () => {
    try {
      signOut();
      onConfirm();
    } catch (error) {
      console.error('Sign out error:', error);
      window.location.href = '/';
    }
  };

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="logout-modal-overlay" onClick={handleOverlayClick}>
      <div className="logout-modal">
        <div className="logout-modal-header">
          <div className="logout-modal-icon">
            <i className="fas fa-sign-out-alt"></i>
          </div>
          <h3>Sign Out</h3>
        </div>
        
        <div className="logout-modal-body">
          <p>Are you sure you want to sign out?</p>
          <p className="logout-modal-subtitle">You will need to sign in again to access your dashboard.</p>
        </div>
        
        <div className="logout-modal-footer">
          <button 
            className="logout-modal-cancel-btn"
            onClick={onClose}
          >
            Cancel
          </button>
          <button 
            className="logout-modal-confirm-btn"
            onClick={handleConfirm}
          >
            <i className="fas fa-sign-out-alt"></i>
            Sign Out
          </button>
        </div>
      </div>
    </div>
  );
};

export default LogoutConfirmationModal;
