'use client';

import React from 'react';
import { useUser } from '../lib/user-context';
import { Permission, ROLE_PERMISSIONS } from '../lib/rbac';
import '../styles/profile-modal.css';

interface ProfileSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const ProfileSettingsModal: React.FC<ProfileSettingsModalProps> = ({ isOpen, onClose }) => {
  const { email, name, role: userRole, groups } = useUser();

  if (!isOpen || !userRole) return null;
  const userPermissions = ROLE_PERMISSIONS[userRole] || [];

  // Permission descriptions for better UX
  const permissionDescriptions: Record<Permission, string> = {
    'view_vendors': 'View vendor list and details',
    'view_security_scans': 'View and access security scan results',
    'manage_vendors': 'Add, edit, and manage vendor information',
    'delete_vendors': 'Remove vendors from the system',
    'add_vendors': 'Add new vendors to the system',
    'run_full_scans': 'Execute comprehensive security scans',
    'check_all_certifications': 'View and verify all vendor certifications',
    'view_certifications': 'View vendor certifications',
    'view_incidents': 'View news and security incidents',
    'view_pwn_monitor': 'View Pwn Monitor breach listings',
    'view_admin_features': 'Access administrative features and settings',
    'manage_access_management': 'Create and modify Access Management roles',
    'manage_additional_domains': 'Add and manage additional domains',
    'view_subdomains': 'View subdomain information',
    'add_subdomains': 'Add subdomains to existing domains',
    'exclude_subdomains': 'Exclude specific subdomains from scans',
    'view_vendor_reports': 'View vendor security reports',
    'export_vendor_reports': 'Export and download vendor reports',
    'view_internal_breaches': 'Access internal breach data and reports',
    'query_internal_breaches': 'Run Breach Monitor queries',
    'view_audit_logs': 'Access and view system audit logs',
    'view_portfolios': 'View portfolios',
    'create_portfolios': 'Create new portfolios',
    'manage_portfolios': 'Manage existing portfolios',
    'delete_portfolios': 'Delete portfolios',
    'view_api_keys': 'View API keys',
    'manage_api_keys': 'Manage API keys and access credentials'
  };

  // Role descriptions
  const roleDescriptions: Record<string, string> = {
    'admin': 'Full system administrator with all permissions',
    'vendor-management': 'Can add, edit, and delete vendors, and manage subdomain add/exclude',
    'user': 'Standard user with basic viewing permissions',
    'user-basic': 'Basic user with limited access (no internal breaches)',
    'user-extended': 'Extended user with access to internal breaches'
  };

  const handleOverlayClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="profile-modal-overlay" onClick={handleOverlayClick}>
      <div className="profile-modal">
        <div className="profile-modal-header">
          <h2>
            <i className="fas fa-user-circle"></i>
            Profile Settings
          </h2>
          <button className="profile-modal-close" onClick={onClose}>
            <i className="fas fa-times"></i>
          </button>
        </div>

        <div className="profile-modal-content">
          {/* User Information Section */}
          <div className="profile-section">
            <h3>
              <i className="fas fa-user"></i>
              User Information
            </h3>
            <div className="profile-info-grid">
              <div className="profile-info-item">
                <label>Name:</label>
                <span>{name || 'Not provided'}</span>
              </div>
              <div className="profile-info-item">
                <label>Email:</label>
                <span>{email || 'Not provided'}</span>
              </div>
            </div>
          </div>

          {/* Role Information Section */}
          <div className="profile-section">
            <h3>
              <i className="fas fa-shield-alt"></i>
              Role & Access Level
            </h3>
            <div className="role-info">
              <div className="role-badge">
                <i className={`fas ${userRole === 'admin' ? 'fa-crown' : 'fa-user'}`}></i>
                {userRole === 'admin' ? 'Administrator' : 
                 userRole === 'vendor-management' ? 'Vendor Management' :
                 userRole === 'user-basic' ? 'Basic User' :
                 userRole === 'user-extended' ? 'Extended User' : 'Standard User'}
              </div>
              <p className="role-description">
                {roleDescriptions[userRole] || 'Standard user access'}
              </p>
            </div>
          </div>


          {/* Permissions Section */}
          <div className="profile-section">
            <h3>
              <i className="fas fa-key"></i>
              Permissions ({userPermissions.length})
            </h3>
            <div className="permissions-list">
              {userPermissions.length > 0 ? (
                userPermissions.map((permission, index) => (
                  <div key={index} className="permission-item">
                    <div className="permission-header">
                      <i className="fas fa-check-circle permission-icon"></i>
                      <span className="permission-name">
                        {permission.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </span>
                    </div>
                    <p className="permission-description">
                      {permissionDescriptions[permission] || 'Permission description not available'}
                    </p>
                  </div>
                ))
              ) : (
                <div className="no-permissions">
                  <i className="fas fa-info-circle"></i>
                  <p>No specific permissions assigned to this role.</p>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="profile-modal-footer">
          <button className="btn-close" onClick={onClose}>
            <i className="fas fa-times"></i>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default ProfileSettingsModal;
