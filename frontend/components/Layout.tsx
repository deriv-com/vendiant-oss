'use client';

import React, { useState, useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useUser } from '../lib/user-context';
import { usePermission } from '../lib/rbac';
import { ADMIN_GROUPS, hasGroupAccess } from '../lib/auth-config';
import ProfileSettingsModal from './ProfileSettingsModal';
import LogoutConfirmationModal from './LogoutConfirmationModal';

interface NotificationProps {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: number;
  persistent?: boolean;
  domain?: string;
  scanType?: string;
}

/**
 * Two-letter initials for the avatar.
 * Prefers the display name ("Dev User" -> "DU"), falls back to the email
 * local part ("jane.doe@example.com" -> "JD"), then to a single letter.
 * Returns '' when there is nothing usable, so the caller can show an icon.
 */
export function getUserInitials(name?: string, email?: string): string {
  // Only alphanumeric runs count as tokens, so padding, punctuation and
  // separators can never leak into the initials.
  const tokens = (value: string): string[] =>
    value.split(/[^A-Za-z0-9]+/).filter(Boolean);

  const fromName = tokens(name || '');
  if (fromName.length >= 2) {
    return (fromName[0][0] + fromName[fromName.length - 1][0]).toUpperCase();
  }
  if (fromName.length === 1) {
    return fromName[0].slice(0, 2).toUpperCase();
  }

  const fromEmail = tokens((email || '').split('@')[0]);
  if (fromEmail.length >= 2) return (fromEmail[0][0] + fromEmail[1][0]).toUpperCase();
  if (fromEmail.length === 1) return fromEmail[0].slice(0, 2).toUpperCase();
  return '';
}

interface LayoutProps {
  children: React.ReactNode;
  activeSection?: string;
  onSectionChange?: (section: string) => void;
  notifications?: NotificationProps[];
  onRemoveNotification?: (id: string) => void;
  onClearAllNotifications?: () => void;
  onOpenSecurityScanModal?: () => void;
}

const Layout: React.FC<LayoutProps> = ({ 
  children, 
  activeSection = 'dashboard', 
  onSectionChange,
  notifications = [],
  onRemoveNotification,
  onClearAllNotifications,
  onOpenSecurityScanModal
}) => {
  const [darkMode, setDarkMode] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [notificationDropdownOpen, setNotificationDropdownOpen] = useState(false);
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const [profileModalOpen, setProfileModalOpen] = useState(false);
  const [logoutModalOpen, setLogoutModalOpen] = useState(false);

  const [currentSection, setCurrentSection] = useState(activeSection);
  const router = useRouter();
  const pathname = usePathname() || '/';
  const { email, name, role, groups } = useUser();
  const canViewVendors = usePermission('view_vendors');
  const canViewSecurityScans = usePermission('view_security_scans');
  const canViewInternalBreaches = usePermission('view_internal_breaches');
  const canViewPortfolios = usePermission('view_portfolios');
  const canViewCertifications = usePermission('view_certifications');
  const canViewIncidents = usePermission('view_incidents');
  const canViewPwnMonitor = usePermission('view_pwn_monitor');
  const canViewAdminFeatures = usePermission('view_admin_features');
  const canViewAuditLogs = usePermission('view_audit_logs');
  const canViewApiKeys = usePermission('view_api_keys');
  const canManageApiKeys = usePermission('manage_api_keys');
  const isSsoAdmin = role === 'admin' && hasGroupAccess(groups, ADMIN_GROUPS);
  // Access Management UI: SSO admin group AND Access Management admin features
  const canAccessAdminConsole = isSsoAdmin && canViewAdminFeatures;

  // Update current section based on pathname
  useEffect(() => {
    if (pathname === '/critical-alerts') {
      setCurrentSection('critical-alerts');
    } else if (pathname === '/portfolio-management') {
      setCurrentSection('portfolio-management');
    } else if (pathname === '/analytics') {
      setCurrentSection('analytics');
    } else if (pathname === '/vendor-comparison') {
      setCurrentSection('vendor-comparison');
    } else if (pathname === '/admin') {
      setCurrentSection('admin');
    } else if (pathname === '/settings') {
      setCurrentSection('settings');
    } else if (pathname === '/audit-logs') {
      setCurrentSection('audit-logs');
    } else if (pathname === '/') {
      setCurrentSection(activeSection);
    }
  }, [pathname, activeSection]);

  // Load cached notifications


  // Format timestamp for display
  const formatTimestamp = (timestamp: number) => {
    const now = Date.now();
    const diff = now - timestamp;
    
    if (diff < 60000) { // Less than 1 minute
      return 'Just now';
    } else if (diff < 3600000) { // Less than 1 hour
      const minutes = Math.floor(diff / 60000);
      return `${minutes}m ago`;
    } else if (diff < 86400000) { // Less than 1 day
      const hours = Math.floor(diff / 3600000);
      return `${hours}h ago`;
    } else {
      const days = Math.floor(diff / 86400000);
      return `${days}d ago`;
    }
  };

  // Initialize theme
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      setDarkMode(true);
      document.body.classList.add('dark-mode');
    } else {
      setDarkMode(false);
      document.body.classList.remove('dark-mode');
    }
  }, []);

  // Mirror the pre-paint sidebar state into React (see the inline script in
  // app/layout.tsx). The attribute is already correct on first paint; this
  // only syncs the toggle button's label, and re-asserts the attribute if the
  // inline script was blocked.
  useEffect(() => {
    const collapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    setSidebarCollapsed(collapsed);
    document.documentElement.setAttribute(
      'data-sidebar', collapsed ? 'collapsed' : 'expanded',
    );
  }, []);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Element;
      
      // Close notification dropdown
      if (notificationDropdownOpen && !target.closest('.notification-dropdown')) {
        setNotificationDropdownOpen(false);
      }
      
      // Close user dropdown
      if (userDropdownOpen && !target.closest('.user-dropdown')) {
        setUserDropdownOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [notificationDropdownOpen, userDropdownOpen]);



  const toggleTheme = () => {
    const newTheme = !darkMode;
    setDarkMode(newTheme);
    
    if (newTheme) {
      document.body.classList.add('dark-mode');
      localStorage.setItem('theme', 'dark');
    } else {
      document.body.classList.remove('dark-mode');
      localStorage.setItem('theme', 'light');
    }
  };

  const initials = getUserInitials(name, email);

  const toggleSidebarCollapsed = () => {
    const next = !sidebarCollapsed;
    setSidebarCollapsed(next);
    document.documentElement.setAttribute('data-sidebar', next ? 'collapsed' : 'expanded');
    localStorage.setItem('sidebarCollapsed', String(next));
  };

  // Navigation function - handles both internal sections and separate pages
  const navigateToSection = (sectionId: string) => {
    if (sectionId === 'portfolio-management' && !canViewPortfolios) return;
    if (sectionId === 'admin' && !canAccessAdminConsole) return;
    if (sectionId === 'audit-logs' && !canViewAuditLogs) return;
    if (sectionId === 'settings' && !(canViewApiKeys || canManageApiKeys)) return;
    if (sectionId === 'vendors' && !canViewVendors) return;
    if (sectionId === 'security-scans' && !canViewSecurityScans) return;
    if (sectionId === 'certifications' && !canViewCertifications) return;
    if (sectionId === 'incidents' && !canViewIncidents) return;
    if (sectionId === 'vendor-breaches' && !canViewPwnMonitor) return;
    if (sectionId === 'breach-monitor' && !canViewInternalBreaches) return;

    setCurrentSection(sectionId);
    setSidebarOpen(false); // Close sidebar on mobile after navigation
    
    // Check if this is a separate page route
    const separatePages = [
      'critical-alerts',
      'portfolio-management',
      'analytics',
      'settings',
      'audit-logs',
      'admin',
    ];
    
    if (separatePages.includes(sectionId)) {
      // Navigate to separate page using Next.js router
      router.push(`/${sectionId}`);
    } else {
      // Handle internal section change via callback
      if (onSectionChange) {
        onSectionChange(sectionId);
      } else {
        // If no callback provided, navigate to main dashboard with section
        router.push(`/?section=${sectionId}`);
      }
    }
  };

  // Handle user dropdown actions
  const handleProfileSettings = () => {
    console.log('Profile Settings clicked');
    setProfileModalOpen(true);
    setUserDropdownOpen(false);
  };

  const handleSignOut = async () => {
    console.log('Sign Out clicked');
    setLogoutModalOpen(true);
    setUserDropdownOpen(false);
  };

  // Navigation items with section IDs matching the original
  const baseNavigationItems = [
    {
      title: 'Overview',
      items: [
        { id: 'dashboard', icon: 'fas fa-tachometer-alt', label: 'Dashboard' },
        { id: 'analytics', icon: 'fas fa-chart-line', label: 'Analytics' },
        { id: 'vendor-comparison', icon: 'fas fa-chart-bar', label: 'Vendor Comparison' },
        { id: 'portfolio-management', icon: 'fas fa-briefcase', label: 'Portfolios', permission: 'view_portfolios' }
      ]
    },
    {
      title: 'Vendor Risks',
      items: [
        { id: 'vendors', icon: 'fas fa-building', label: 'Vendor Management', permission: 'view_vendors' },
        { id: 'security-scans', icon: 'fas fa-shield-alt', label: 'Security Scans', permission: 'view_security_scans' },
        { id: 'certifications', icon: 'fas fa-certificate', label: 'Certifications', permission: 'view_certifications' },
        { id: 'incidents', icon: 'fas fa-newspaper', label: 'News & Incidents', permission: 'view_incidents' },
        { id: 'vendor-breaches', icon: 'fas fa-chess-pawn', label: 'Pwn Monitor', permission: 'view_pwn_monitor' }
      ]
    },
    {
      title: 'Internal Breaches',
      items: [
        { id: 'breach-monitor', icon: 'fas fa-database', label: 'Breach Monitor', permission: 'view_internal_breaches' }
      ]
    },
    {
      title: 'Admin Management',
      items: [
        { id: 'audit-logs', icon: 'fas fa-history', label: 'Audit Logs', permission: 'view_audit_logs' },
        { id: 'settings', icon: 'fas fa-key', label: 'API Keys', permission: 'view_api_keys' },
        { id: 'admin', icon: 'fas fa-user-shield', label: 'Access Management', permission: 'view_admin_features' },
      ]
    }
  ];

  // Filter navigation items based on user permissions
  const navigationItems = baseNavigationItems.map(section => ({
    ...section,
    items: section.items.filter(item => {
      if (item.permission === 'view_vendors') {
        return canViewVendors;
      }
      if (item.permission === 'view_security_scans') {
        return canViewSecurityScans;
      }
      if (item.permission === 'view_certifications') {
        return canViewCertifications;
      }
      if (item.permission === 'view_incidents') {
        return canViewIncidents;
      }
      if (item.permission === 'view_pwn_monitor') {
        return canViewPwnMonitor;
      }
      if (item.permission === 'view_internal_breaches') {
        return canViewInternalBreaches;
      }
      if (item.permission === 'view_portfolios') {
        return canViewPortfolios;
      }
      if (item.permission === 'view_audit_logs') {
        return canViewAuditLogs;
      }
      if (item.permission === 'view_api_keys') {
        return canViewApiKeys || canManageApiKeys;
      }
      if (item.permission === 'view_admin_features') {
        return canAccessAdminConsole;
      }
      return true;
    })
  })).filter(section => section.items.length > 0);

  return (
    <div className="main-container">
      {/* Top Navigation */}
      <nav className="top-nav" role="navigation" aria-label="Main navigation">
        <div className="nav-left">
          <div 
            className="logo" 
            style={{ cursor: 'pointer' }}
            onClick={() => navigateToSection('dashboard')}
          >
            <i className="fas fa-shield-alt"></i>
            <span>Vendiant</span>
          </div>
        </div>
        
        {/* Updated header right section */}
        <div className="header-right">
          <button className="theme-toggle" aria-label="Toggle dark mode" onClick={toggleTheme}>
            <i className={`fas ${darkMode ? 'fa-sun' : 'fa-moon'}`}></i>
          </button>
          
          {/* Critical Alerts Button */}
          <button 
            className="critical-alerts-button"
            onClick={() => {
              // Navigate to critical alerts page
              router.push('/critical-alerts');
            }}
            title="View Critical Security Alerts"
          >
            <i className="fas fa-exclamation-triangle"></i>
            <span className="critical-alerts-text">Alerts</span>
          </button>
          
          <div className="notification-dropdown">
            <div 
              className="notification-icon" 
              onClick={() => setNotificationDropdownOpen(!notificationDropdownOpen)}
            >
              <i className="fas fa-bell"></i>
              {notifications.length > 0 && (
                <span className="notification-badge">{notifications.length}</span>
              )}
            </div>
            
            {notificationDropdownOpen && (
              <div className="notification-dropdown-menu">
                <div className="notification-dropdown-header">
                  <h4>Notifications ({notifications.length})</h4>
                  <div className="notification-header-actions">
                    {notifications.length > 0 && onClearAllNotifications && (
                      <button 
                        className="clear-all-btn"
                        onClick={onClearAllNotifications}
                        title="Clear all notifications"
                      >
                        <i className="fas fa-trash-alt"></i>
                        Clear All
                      </button>
                    )}
                    <button 
                      className="close-dropdown"
                      onClick={() => setNotificationDropdownOpen(false)}
                    >
                      <i className="fas fa-times"></i>
                    </button>
                  </div>
                </div>
                <div className="notification-dropdown-list">
                  {notifications.length === 0 ? (
                    <div className="no-notifications">
                      <i className="fas fa-bell-slash"></i>
                      <p>No notifications</p>
                    </div>
                  ) : (
                    notifications.map((notification) => (
                      <div key={notification.id} className={`notification-dropdown-item ${notification.type}`}>
                        <div className="notification-icon-type">
                          <i className={`fas ${
                            notification.type === 'success' ? 'fa-check-circle' :
                            notification.type === 'error' ? 'fa-exclamation-circle' :
                            notification.type === 'warning' ? 'fa-exclamation-triangle' :
                            'fa-info-circle'
                          }`}></i>
                        </div>
                        <div className="notification-content">
                          <div className="notification-title">{notification.title}</div>
                          <div className="notification-message">{notification.message}</div>
                          {notification.domain && (
                            <div className="notification-meta">
                              <span className="notification-domain">{notification.domain}</span>
                            </div>
                          )}
                        </div>
                        {onRemoveNotification && (
                          <button 
                            className="remove-notification"
                            onClick={(e) => {
                              e.stopPropagation();
                              onRemoveNotification(notification.id);
                            }}
                          >
                            <i className="fas fa-times"></i>
                          </button>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
          
          {/* Enhanced user dropdown */}
          <div className={`user-dropdown ${userDropdownOpen ? 'open' : ''}`}>
            <div className="user-info" onClick={() => setUserDropdownOpen(!userDropdownOpen)}>
              <div className="user-avatar" title={email || 'User'}>
                {initials
                  ? <span className="user-initials">{initials}</span>
                  : <i className="fas fa-user"></i>}
              </div>
              <div className="user-details">
                <div className="user-name">{name || email || 'User'}</div>
                <div className="user-role">{role === 'admin' ? 'Administrator' : role === 'vendor-management' ? 'Vendor Management' : 'User'}</div>
              </div>
              <i className="fas fa-chevron-down dropdown-arrow"></i>
            </div>
            
            <div className={`dropdown-menu ${userDropdownOpen ? '' : 'hidden'}`}>
              <button className="dropdown-item" onClick={handleProfileSettings}>
                <i className="fas fa-user"></i>
                Profile Settings
              </button>
              <div className="dropdown-divider"></div>
              <button className="dropdown-item" onClick={handleSignOut}>
                <i className="fas fa-sign-out-alt"></i>
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Sidebar */}
      <aside
        className={`sidebar ${sidebarOpen ? 'open' : ''} ${sidebarCollapsed ? 'collapsed' : ''}`}
        role="complementary"
      >
        <button 
          className="sidebar-toggle" 
          aria-label="Toggle sidebar"
          onClick={() => setSidebarOpen(!sidebarOpen)}
        >
          <i className="fas fa-bars"></i>
        </button>
        <button
          className="sidebar-collapse-btn"
          aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!sidebarCollapsed}
          title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          onClick={toggleSidebarCollapsed}
        >
          <i className="fas fa-chevron-left"></i>
        </button>
        <nav className="sidebar-nav">
          <ul>
            {navigationItems.map((section, sectionIndex) => (
              <li key={sectionIndex} className="nav-section">
                <span className="section-title" aria-hidden={sidebarCollapsed}>
                  {section.title}
                </span>
                <ul>
                  {section.items.map((item) => (
                    <li key={item.id}>
                      <a
                        href={`#${item.id}`}
                        className={`sidebar-link ${currentSection === item.id ? 'active' : ''}`}
                        data-label={item.label}
                        title={sidebarCollapsed ? item.label : undefined}
                        onClick={(e) => {
                          e.preventDefault();
                          navigateToSection(item.id);
                        }}
                      >
                        <i className={item.icon}></i>
                        <span className="sidebar-link-label">{item.label}</span>
                      </a>
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {children}
      </main>

      {/* Profile Settings Modal */}
      <ProfileSettingsModal
        isOpen={profileModalOpen}
        onClose={() => setProfileModalOpen(false)}
      />

      {/* Logout Confirmation Modal */}
      <LogoutConfirmationModal
        isOpen={logoutModalOpen}
        onClose={() => setLogoutModalOpen(false)}
        onConfirm={() => setLogoutModalOpen(false)}
      />

    </div>
  );
};

export default Layout; 