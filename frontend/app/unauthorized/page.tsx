'use client';

import { useUser, signOut } from '../../lib/user-context';
import Link from 'next/link';
import styles from '../../styles/auth.module.css';

export default function Unauthorized() {
  const { email, role, groups } = useUser();

  const handleSignOut = () => {
    signOut();
  };

  return (
    <div className={styles.unauthorizedContainer}>
      <div className={styles.authCard}>
        <div className={styles.logoContainer}>
          <div className={styles.unauthorizedIcon}>
            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 0h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
        </div>
        
        <h2 className={styles.title}>
          Access Restricted
        </h2>
        <p className={styles.subtitle}>
          You don&apos;t have permission to access this resource
        </p>
        
        <div className={styles.formSection}>
          <div className={styles.errorAlert}>
            <div className={styles.errorContent}>
              <svg className={styles.errorIcon} viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <div className={styles.errorText}>
                <h3 className={styles.errorTitle}>
                  Insufficient Permissions
                </h3>
                <div className={styles.errorMessage}>
                  <p>This resource requires administrator privileges. Your current role ({role || 'unknown'}) does not have access to this area.</p>
                </div>
              </div>
            </div>
          </div>
          
          {role && (
            <div className={styles.errorAlert} style={{background: 'linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%)', border: '1px solid #d1d5db'}}>
              <div className={styles.errorContent}>
                <svg className={styles.errorIcon} style={{color: '#6b7280'}} viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
                <div className={styles.errorText}>
                  <h3 className={styles.errorTitle} style={{color: '#374151'}}>
                    Current Session Info:
                  </h3>
                  <div className={styles.errorMessage} style={{color: '#4b5563'}}>
                    <p><strong>Email:</strong> {email}</p>
                    <p><strong>Role:</strong> {role}</p>
                    <p><strong>Groups:</strong> {groups?.join(', ') || 'None'}</p>
                  </div>
                </div>
              </div>
            </div>
          )}
          
          <div className={styles.actionButtons}>
            <Link
              href="/"
              className={styles.primaryButton}
            >
              <svg className={styles.buttonIcon} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
              </svg>
              Return to Dashboard
            </Link>
            
            <button
              onClick={handleSignOut}
              className={styles.secondaryButton}
            >
              <svg className={styles.buttonIcon} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
              Sign Out
            </button>
          </div>
          
          <div className={styles.disclaimer}>
            <p className={styles.disclaimerText}>
              If you believe you should have access to this resource, please contact your administrator.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
