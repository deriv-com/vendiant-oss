'use client';

import React, { useState, useEffect } from 'react';

interface ConfirmationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  type?: 'danger' | 'warning' | 'info';
  loading?: boolean;
}

const ConfirmationModal: React.FC<ConfirmationModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  type = 'danger',
  loading = false
}) => {
  // Dark mode hook
  const useDarkMode = () => {
    const [isDarkMode, setIsDarkMode] = useState(false);

    useEffect(() => {
      const checkDarkMode = () => {
        setIsDarkMode(document.body.classList.contains('dark-mode'));
      };

      checkDarkMode();
      const observer = new MutationObserver(checkDarkMode);
      observer.observe(document.body, {
        attributes: true,
        attributeFilter: ['class']
      });

      return () => observer.disconnect();
    }, []);

    return isDarkMode;
  };

  const isDarkMode = useDarkMode();

  const getTypeConfig = () => {
    switch (type) {
      case 'danger':
        return {
          iconClass: 'fas fa-exclamation-triangle',
          iconColor: '#ef4444',
          iconBg: '#fef2f2',
          confirmBg: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
          confirmShadow: '0 2px 8px rgba(239, 68, 68, 0.3)'
        };
      case 'warning':
        return {
          iconClass: 'fas fa-exclamation-circle',
          iconColor: '#f59e0b',
          iconBg: '#fffbeb',
          confirmBg: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
          confirmShadow: '0 2px 8px rgba(245, 158, 11, 0.3)'
        };
      case 'info':
        return {
          iconClass: 'fas fa-info-circle',
          iconColor: '#3b82f6',
          iconBg: '#eff6ff',
          confirmBg: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
          confirmShadow: '0 2px 8px rgba(59, 130, 246, 0.3)'
        };
      default:
        return {
          iconClass: 'fas fa-exclamation-triangle',
          iconColor: '#ef4444',
          iconBg: '#fef2f2',
          confirmBg: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
          confirmShadow: '0 2px 8px rgba(239, 68, 68, 0.3)'
        };
    }
  };

  const typeConfig = getTypeConfig();

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1100, // Higher than other modals
      padding: '1rem'
    }}>
      <div style={{
        backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
        borderRadius: '12px',
        padding: '2rem',
        width: '100%',
        maxWidth: '500px',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        border: isDarkMode ? '1px solid var(--border-color)' : 'none'
      }}>
        {/* Icon and Title */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          marginBottom: '1rem'
        }}>
          <div style={{
            backgroundColor: isDarkMode ? 'rgba(239, 68, 68, 0.1)' : typeConfig.iconBg,
            borderRadius: '50%',
            padding: '0.75rem',
            marginRight: '1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <i className={typeConfig.iconClass} style={{
              color: typeConfig.iconColor,
              fontSize: '1.25rem'
            }}></i>
          </div>
          <h3 style={{
            margin: 0,
            fontSize: '1.125rem',
            fontWeight: '600',
            color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
          }}>
            {title}
          </h3>
        </div>

        {/* Message */}
        <div style={{
          marginBottom: '2rem',
          paddingLeft: '3.5rem' // Align with title
        }}>
          <p style={{
            margin: 0,
            fontSize: '0.875rem',
            lineHeight: '1.5',
            color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
            whiteSpace: 'pre-line' // Preserve line breaks
          }}>
            {message}
          </p>
        </div>

        {/* Actions */}
        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          gap: '0.75rem'
        }}>
          <button
            onClick={onClose}
            disabled={loading}
            style={{
              padding: '0.75rem 1.5rem',
              background: isDarkMode ? 'var(--bg-secondary)' : '#f3f4f6',
              color: isDarkMode ? 'var(--text-primary)' : '#374151',
              border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db',
              borderRadius: '8px',
              fontSize: '0.875rem',
              fontWeight: '600',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={(e) => {
              if (!loading) {
                const target = e.target as HTMLButtonElement;
                target.style.backgroundColor = isDarkMode ? 'var(--bg-primary)' : '#e5e7eb';
              }
            }}
            onMouseLeave={(e) => {
              const target = e.target as HTMLButtonElement;
              target.style.backgroundColor = isDarkMode ? 'var(--bg-secondary)' : '#f3f4f6';
            }}
          >
            {cancelText}
          </button>
          <button
            onClick={onConfirm}
            disabled={loading}
            style={{
              padding: '0.75rem 1.5rem',
              background: loading ? '#9ca3af' : typeConfig.confirmBg,
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              fontSize: '0.875rem',
              fontWeight: '600',
              cursor: loading ? 'not-allowed' : 'pointer',
              boxShadow: loading ? 'none' : typeConfig.confirmShadow,
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={(e) => {
              if (!loading) {
                const target = e.target as HTMLButtonElement;
                target.style.transform = 'translateY(-1px)';
                target.style.boxShadow = typeConfig.confirmShadow.replace('0.3)', '0.4)');
              }
            }}
            onMouseLeave={(e) => {
              if (!loading) {
                const target = e.target as HTMLButtonElement;
                target.style.transform = 'translateY(0)';
                target.style.boxShadow = typeConfig.confirmShadow;
              }
            }}
          >
            {loading ? (
              <>
                <i className="fas fa-spinner fa-spin" style={{ marginRight: '0.5rem' }}></i>
                Processing...
              </>
            ) : (
              confirmText
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmationModal;
