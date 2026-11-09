'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Layout from '../../components/Layout';
import { usePermission } from '../../lib/rbac';
import { logUserAction, apiRequest } from '../../lib/api-client';
import { logger } from '../../lib/logger';

interface APIKey {
  id: number;
  credential_hash: string;
  name: string;
  description: string;
  request_limit: number;
  is_enabled: boolean;
  created_at: string;
  expires_at: string | null;
  created_by: string;
  group_name: string;
  finegrained_scopes: string[];
  last_accessed: string | null;
}

interface PermissionGroup {
  name: string;
  description: string;
}

interface Scope {
  key: string;
  description: string;
}

interface AuditStats {
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  success_rate: number;
  unique_credentials: number;
  unique_ips: number;
  unique_endpoints: number;
}

const SettingsPage: React.FC = () => {
  const router = useRouter();
  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [includeDisabled, setIncludeDisabled] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showKeyDisplayModal, setShowKeyDisplayModal] = useState(false);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [createdApiKey, setCreatedApiKey] = useState<string>('');
  const [selectedKeyId, setSelectedKeyId] = useState<number | null>(null);
  const [selectedKeyDetails, setSelectedKeyDetails] = useState<APIKey | null>(null);
  const [revokeAction, setRevokeAction] = useState<'revoke' | 'unrevoke'>('revoke');
  
  // Dark mode detection
  const [isDarkMode, setIsDarkMode] = useState(false);
  
  useEffect(() => {
    const checkDarkMode = () => {
      setIsDarkMode(document.body.classList.contains('dark-mode'));
    };
    
    checkDarkMode();
    
    const observer = new MutationObserver(checkDarkMode);
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
    
    return () => observer.disconnect();
  }, []);
  
  // Create API Key form state
  const [keyName, setKeyName] = useState('');
  const [keyDescription, setKeyDescription] = useState('');
  const [permissionMode, setPermissionMode] = useState<'group' | 'finegrained' | ''>('');
  const [selectedGroup, setSelectedGroup] = useState('');
  const [availableGroups, setAvailableGroups] = useState<PermissionGroup[]>([]);
  const [availableScopes, setAvailableScopes] = useState<Scope[]>([]);
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
  const [accessType, setAccessType] = useState<'temporary' | 'permanent' | ''>('');
  const [expiryDays, setExpiryDays] = useState<number>(90);
  
  // Edit modal state
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingKey, setEditingKey] = useState<APIKey | null>(null);
  const [editKeyName, setEditKeyName] = useState('');
  const [editKeyDescription, setEditKeyDescription] = useState('');
  const [editPermissionMode, setEditPermissionMode] = useState<'group' | 'finegrained' | ''>('');
  const [editSelectedGroup, setEditSelectedGroup] = useState('');
  const [editSelectedScopes, setEditSelectedScopes] = useState<string[]>([]);
  const [editAccessType, setEditAccessType] = useState<'temporary' | 'permanent' | ''>('');
  const [editExpiryDays, setEditExpiryDays] = useState<number>(90);

  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [formKey, setFormKey] = useState(0); // Force form re-render

  const canViewApiKeys = usePermission('view_api_keys');
  const canManageApiKeys = usePermission('manage_api_keys');

  useEffect(() => {
    loadAPIKeys();
    loadAvailableGroups();
    loadAvailableScopes();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [includeDisabled]);

  useEffect(() => {
    if (!canViewApiKeys && !canManageApiKeys) {
      router.replace('/');
    }
  }, [canViewApiKeys, canManageApiKeys, router]);

  // Reset form whenever modal opens
  useEffect(() => {
    if (showCreateModal) {
      setKeyName('');
      setKeyDescription('');
      setPermissionMode('');
      setSelectedGroup('');
      setSelectedScopes([]);
      setAccessType('');
      setExpiryDays(90);
      setError(null);
      setFormKey(prev => prev + 1);
    }
  }, [showCreateModal]);

  const loadAPIKeys = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await apiRequest(`/api/api-keys/list?include_disabled=${includeDisabled}`);
      const data = await response.json();
      
      if (data.success) {
        setApiKeys(data.keys);
      } else {
        setError('Failed to load API keys');
      }
    } catch (err) {
      console.error('Error loading API keys:', err);
      setError('Error loading API keys');
    } finally {
      setLoading(false);
    }
  };

  const loadAvailableGroups = async () => {
    try {
      const response = await apiRequest('/api/api-keys/available-groups');
      const data = await response.json();
      if (data.success) {
        setAvailableGroups(data.groups);
      }
    } catch (err) {
      console.error('Error loading available groups:', err);
    }
  };

  const loadAvailableScopes = async () => {
    try {
      const response = await apiRequest('/api/api-keys/scopes');
      const data = await response.json();
      if (data.success) {
        setAvailableScopes(data.scopes);
      }
    } catch (err) {
      console.error('Error loading available scopes:', err);
    }
  };

  const WEBHOOK_SCOPE = 'webhook';

  const operationalScopes = availableScopes.filter(s => s.key !== WEBHOOK_SCOPE);

  const toggleScope = (key: string) => {
    if (key === WEBHOOK_SCOPE) {
      setSelectedScopes(prev => (prev.includes(WEBHOOK_SCOPE) ? [] : [WEBHOOK_SCOPE]));
      return;
    }
    setSelectedScopes(prev => {
      const base = prev.filter(s => s !== WEBHOOK_SCOPE);
      return base.includes(key) ? base.filter(s => s !== key) : [...base, key];
    });
  };

  const toggleEditScope = (key: string) => {
    if (key === WEBHOOK_SCOPE) {
      setEditSelectedScopes(prev => (prev.includes(WEBHOOK_SCOPE) ? [] : [WEBHOOK_SCOPE]));
      return;
    }
    setEditSelectedScopes(prev => {
      const base = prev.filter(s => s !== WEBHOOK_SCOPE);
      return base.includes(key) ? base.filter(s => s !== key) : [...base, key];
    });
  };

  const applyWebhookOnlyPreset = () => {
    setPermissionMode('finegrained');
    setSelectedGroup('');
    setSelectedScopes([WEBHOOK_SCOPE]);
  };

  const handleCreateAPIKey = async () => {
    try {
      setError(null);

      if (!keyName.trim()) {
        setError('API Key name is required');
        return;
      }

      if (!permissionMode) {
        setError('Permission type is required');
        return;
      }

      if (permissionMode === 'group' && !selectedGroup) {
        setError('Select a permission group (Read-only or Admin)');
        return;
      }

      if (permissionMode === 'finegrained' && selectedScopes.length === 0) {
        setError('Select at least one scope for a fine-grained key');
        return;
      }

      if (
        permissionMode === 'finegrained' &&
        selectedScopes.includes(WEBHOOK_SCOPE) &&
        selectedScopes.length > 1
      ) {
        setError('The webhook scope cannot be combined with other scopes');
        return;
      }

      if (!accessType) {
        setError('Access type is required');
        return;
      }

      const body: Record<string, unknown> = {
        name: keyName,
        description: keyDescription,
        permission_mode: permissionMode,
        expires_days: accessType === 'permanent' ? null : expiryDays,
      };

      if (permissionMode === 'group') {
        body.group_name = selectedGroup;
      } else {
        body.finegrained_scopes = selectedScopes;
      }

      const response = await apiRequest('/api/api-keys/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (data.success) {
        setCreatedApiKey(data.api_key);
        setShowCreateModal(false);
        setShowKeyDisplayModal(true);
        setKeyName('');
        setKeyDescription('');
        setPermissionMode('');
        setSelectedGroup('');
        setSelectedScopes([]);
        setAccessType('');
        setExpiryDays(90);
        await loadAPIKeys();
      } else {
        setError(data.detail || 'Failed to create API key');
      }
    } catch (err) {
      console.error('Error creating API key:', err);
      setError('Error creating API key');
    }
  };

  const handleRevokeAPIKey = async (action: 'revoke' | 'unrevoke' = 'revoke') => {
    if (!selectedKeyId) return;

    try {
      setError(null);
      
      const response = await apiRequest('/api/api-keys/revoke', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          key_id: selectedKeyId,
          action: action
        }),
      });

      const data = await response.json();

      if (data.success) {
        setSuccessMessage(data.message);
        setShowRevokeModal(false);
        setSelectedKeyId(null);
        
        // Reload API keys list
        await loadAPIKeys();
        
        setTimeout(() => setSuccessMessage(null), 3000);
      } else {
        setError(data.detail || `Failed to ${action} API key`);
      }
    } catch (err) {
      console.error(`Error ${action}ing API key:`, err);
      setError(`Error ${action}ing API key`);
    }
  };

  const handleDeleteAPIKey = async () => {
    if (!selectedKeyId) return;

    try {
      setError(null);
      
      const response = await apiRequest(`/api/api-keys/delete/${selectedKeyId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        }
      });

      const data = await response.json();

      if (data.success) {
        setSuccessMessage(data.message);
        setShowDeleteModal(false);
        setSelectedKeyId(null);
        
        // Reload API keys list
        await loadAPIKeys();
        
        setTimeout(() => setSuccessMessage(null), 3000);
      } else {
        setError(data.detail || 'Failed to delete API key');
      }
    } catch (err) {
      console.error('Error deleting API key:', err);
      setError('Error deleting API key');
    }
  };


  const openEditModal = (key: APIKey) => {
    setEditingKey(key);
    setEditKeyName(key.name);
    setEditKeyDescription(key.description || '');
    setEditAccessType(key.expires_at ? 'temporary' : 'permanent');
    setEditExpiryDays(90);
    if (key.group_name === 'finegrained') {
      setEditPermissionMode('finegrained');
      setEditSelectedGroup('');
      setEditSelectedScopes(key.finegrained_scopes || []);
    } else {
      setEditPermissionMode('group');
      setEditSelectedGroup(key.group_name);
      setEditSelectedScopes([]);
    }
    setError(null);
    setShowEditModal(true);
  };

  const handleUpdateAPIKey = async () => {
    if (!editingKey) return;
    try {
      setError(null);

      if (!editKeyName.trim()) { setError('API key name is required'); return; }
      if (editPermissionMode === 'group' && !editSelectedGroup) { setError('Select a permission group'); return; }
      if (editPermissionMode === 'finegrained' && editSelectedScopes.length === 0) { setError('Select at least one scope'); return; }
      if (
        editPermissionMode === 'finegrained' &&
        editSelectedScopes.includes(WEBHOOK_SCOPE) &&
        editSelectedScopes.length > 1
      ) {
        setError('The webhook scope cannot be combined with other scopes');
        return;
      }
      if (!editAccessType) { setError('Access type is required'); return; }
      if (editAccessType === 'temporary' && (!editExpiryDays || editExpiryDays < 1)) { setError('Enter a valid expiry (minimum 1 day)'); return; }

      const body: Record<string, unknown> = {
        name: editKeyName.trim(),
        description: editKeyDescription.trim(),
        permission_mode: editPermissionMode,
        access_type: editAccessType,
        expires_days: editAccessType === 'temporary' ? editExpiryDays : null,
      };
      if (editPermissionMode === 'group') {
        body.group_name = editSelectedGroup;
      } else {
        body.finegrained_scopes = editSelectedScopes;
      }

      const response = await apiRequest(`/api/api-keys/update/${editingKey.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (data.success) {
        setSuccessMessage('API key updated successfully');
        setShowEditModal(false);
        setEditingKey(null);
        await loadAPIKeys();
        setTimeout(() => setSuccessMessage(null), 3000);
      } else {
        setError(data.detail || 'Failed to update API key');
      }
    } catch (err) {
      console.error('Error updating API key:', err);
      setError('Error updating API key');
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccessMessage('Copied to clipboard!');
    setTimeout(() => setSuccessMessage(null), 2000);
  };

  if (!canViewApiKeys && !canManageApiKeys) {
    return (
      <Layout activeSection="settings">
        <div className="flex items-center justify-center h-screen">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-red-600 mb-4">Access Denied</h2>
            <p className="text-gray-600">You dont have permission to view API keys.</p>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout activeSection="settings">
      <div className="p-6">
        {/* Header - Matching vendor management page */}
        <div className="page-header" style={{ marginBottom: '2rem' }}>
          <div>
            <h1 style={{ 
              fontSize: '2.5rem', 
              fontWeight: 'bold', 
              marginBottom: '0.5rem',
              color: isDarkMode ? 'var(--text-primary)' : '#111827'
            }}>API Key Manager</h1>
            <p style={{ 
              color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', 
              fontSize: '1rem' 
            }}>Manage API keys and access credentials</p>
          </div>
          
          {/* Action Button - Create API Key */}
          {canManageApiKeys && (
          <div className="page-actions">
            <button 
              onClick={() => setShowCreateModal(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.75rem 1.5rem',
                fontSize: '0.95rem',
                fontWeight: '600',
                borderRadius: '8px',
                transition: 'all 0.2s ease',
                border: `1px solid ${isDarkMode ? '#047857' : '#10b981'}`,
                backgroundColor: isDarkMode ? '#047857' : '#10b981',
                color: 'white',
                boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
                cursor: 'pointer'
              }}
              onMouseEnter={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#065f46' : '#059669'}
              onMouseLeave={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#047857' : '#10b981'}
            >
              <i className="fas fa-plus"></i>
              Create API Key
            </button>
          </div>
          )}
        </div>

        {/* Success/Error Messages */}
        {successMessage && (
          <div style={{
            marginBottom: '1.5rem',
            padding: '1rem 1.5rem',
            backgroundColor: isDarkMode ? 'rgba(14, 200, 138, 0.1)' : '#d1fae5',
            border: `1px solid ${isDarkMode ? 'rgba(16, 185, 129, 0.3)' : '#059669'}`,
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: isDarkMode ? '#34d399' : '#065f46',
            fontWeight: '500'
          }}>
            <i className="fas fa-check-circle" style={{ fontSize: '1.25rem', color: isDarkMode ? '#34d399' : '#059669' }}></i>
            <span>{successMessage}</span>
          </div>
        )}
        {error && (
          <div style={{
            marginBottom: '1.5rem',
            padding: '1rem 1.5rem',
            backgroundColor: isDarkMode ? 'rgba(220, 38, 38, 0.1)' : '#fee2e2',
            border: `1px solid ${isDarkMode ? 'rgba(220, 38, 38, 0.3)' : '#dc2626'}`,
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: isDarkMode ? '#f87171' : '#991b1b',
            fontWeight: '500'
          }}>
            <i className="fas fa-exclamation-circle" style={{ fontSize: '1.25rem', color: isDarkMode ? '#f87171' : '#dc2626' }}></i>
            <span>{error}</span>
          </div>
        )}

        {/* Filters */}
        <div style={{
          marginBottom: '1.5rem',
          padding: '1rem 1.5rem',
          backgroundColor: isDarkMode ? 'var(--bg-secondary)' : '#f9fafb',
          border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
          borderRadius: '8px',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem'
        }}>
          <label style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            cursor: 'pointer',
            fontSize: '0.95rem',
            fontWeight: '500',
            color: isDarkMode ? 'var(--text-primary)' : '#374151'
          }}>
            <input
              type="checkbox"
              checked={includeDisabled}
              onChange={(e) => setIncludeDisabled(e.target.checked)}
              style={{
                width: '1.125rem',
                height: '1.125rem',
                cursor: 'pointer'
              }}
            />
            <span>Include Revoked Keys</span>
          </label>
        </div>

        {/* API Keys Table */}
        <div style={{
          backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
          borderRadius: '12px',
          boxShadow: isDarkMode ? '0 4px 6px -1px rgba(0, 0, 0, 0.3)' : '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          overflow: 'hidden',
          border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
        }}>
          <div style={{ overflowX: 'auto', maxWidth: '100%' }}>
            <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: 0, minWidth: '900px' }}>
            <thead style={{ backgroundColor: isDarkMode ? 'var(--bg-primary)' : '#f9fafb' }}>
              <tr>
                <th style={{
                  padding: '1rem 1.5rem',
                  textAlign: 'left',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
                }}>Name</th>
                <th style={{
                  padding: '1rem 1.5rem',
                  textAlign: 'left',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
                }}>Group</th>
                <th style={{
                  padding: '1rem 1.5rem',
                  textAlign: 'left',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
                }}>Status</th>
                <th style={{
                  padding: '1rem 1.5rem',
                  textAlign: 'left',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
                }}>Created</th>
                <th style={{
                  padding: '1rem 1.5rem',
                  textAlign: 'left',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
                }}>Expires</th>
                <th style={{
                  padding: '1rem 1.5rem',
                  textAlign: 'left',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
                }}>Actions</th>
              </tr>
            </thead>
            <tbody style={{ backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white' }}>
              {loading ? (
                <tr>
                  <td colSpan={6} style={{ padding: '3rem', textAlign: 'center' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
                      <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: '#3b82f6' }}></i>
                      <span style={{ color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '1rem' }}>Loading API keys...</span>
                    </div>
                  </td>
                </tr>
              ) : apiKeys.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: '4rem 2rem', textAlign: 'center' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
                      <i className="fas fa-key" style={{ fontSize: '4rem', color: isDarkMode ? 'var(--border-color)' : '#d1d5db' }}></i>
                      <p style={{ color: isDarkMode ? 'var(--text-primary)' : '#6b7280', fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>No API keys found</p>
                      <p style={{ color: isDarkMode ? 'var(--text-secondary)' : '#9ca3af', fontSize: '0.875rem', margin: 0 }}>Create your first API key to get started</p>
                    </div>
                  </td>
                </tr>
              ) : (
                apiKeys.map((key) => (
                  <tr key={key.id} style={{ backgroundColor: !key.is_enabled ? (isDarkMode ? 'var(--bg-primary)' : '#f9fafb') : (isDarkMode ? 'var(--bg-secondary)' : 'white') }}>
                    {/* Name */}
                    <td style={{ padding: '1rem 1.5rem', whiteSpace: 'nowrap', fontSize: '0.875rem', fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : '#111827', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      {key.name}
                    </td>
                    
                    {/* Group */}
                    <td style={{ padding: '1rem 1.5rem', whiteSpace: 'nowrap', fontSize: '0.875rem', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      <span style={{
                        padding: '0.25rem 0.75rem',
                        borderRadius: '9999px',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        backgroundColor: key.group_name.toLowerCase().includes('admin') ? (isDarkMode ? 'rgba(124, 58, 237, 0.4)' : '#f3e8ff') : (isDarkMode ? 'rgba(37, 99, 235, 0.4)' : '#dbeafe'),
                        color: key.group_name.toLowerCase().includes('admin') ? (isDarkMode ? '#9333ea' : '#7c3aed') : (isDarkMode ? '#3b82f6' : '#2563eb')
                      }}>
                        {key.group_name}
                      </span>
                    </td>
                    
                    {/* Status */}
                    <td style={{ padding: '1rem 1.5rem', whiteSpace: 'nowrap', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      <span style={{
                        padding: '0.25rem 0.75rem',
                        display: 'inline-flex',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        borderRadius: '9999px',
                        backgroundColor: key.is_enabled ? (isDarkMode ? 'rgba(16, 185, 129, 0.4)' : '#d1fae5') : (isDarkMode ? 'rgba(220, 38, 38, 0.4)' : '#fee2e2'),
                        color: key.is_enabled ? (isDarkMode ? '#059669' : '#065f46') : (isDarkMode ? '#f87171' : '#991b1b')
                      }}>
                        {key.is_enabled ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    
                    {/* Created */}
                    <td style={{ padding: '1rem 1.5rem', whiteSpace: 'nowrap', fontSize: '0.875rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      {formatDate(key.created_at)}
                    </td>
                    
                    {/* Expires */}
                    <td style={{ padding: '1rem 1.5rem', whiteSpace: 'nowrap', fontSize: '0.875rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      {formatDate(key.expires_at) || 'Never'}
                    </td>
                    
                    {/* Actions */}
                    <td style={{ padding: '1rem 1.5rem', whiteSpace: 'nowrap', fontSize: '0.875rem', fontWeight: '500', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        {/* View Details Icon */}
                        <button
                          onClick={() => {
                            setSelectedKeyDetails(key);
                            setShowDetailsModal(true);
                          }}
                          style={{
                            padding: '0.5rem',
                            fontSize: '0.875rem',
                            color: isDarkMode ? 'white' : '#3b82f6',
                            backgroundColor: isDarkMode ? '#3b82f6' : '#eff6ff',
                            border: 'none',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            transition: 'all 0.2s ease',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            width: '36px',
                            height: '36px'
                          }}
                          onMouseEnter={(e) => {
                            if (isDarkMode) {
                              e.currentTarget.style.backgroundColor = '#2563eb';
                            } else {
                              e.currentTarget.style.backgroundColor = '#3b82f6';
                              e.currentTarget.style.color = 'white';
                            }
                          }}
                          onMouseLeave={(e) => {
                            if (isDarkMode) {
                              e.currentTarget.style.backgroundColor = '#3b82f6';
                            } else {
                              e.currentTarget.style.backgroundColor = '#eff6ff';
                              e.currentTarget.style.color = '#3b82f6';
                            }
                          }}
                          title="View Details"
                        >
                          <i className="fas fa-eye"></i>
                        </button>
                        
                        {/* Edit Permissions Button */}
                        <button
                          onClick={() => openEditModal(key)}
                          style={{
                            padding: '0.5rem',
                            fontSize: '0.875rem',
                            color: isDarkMode ? 'white' : '#d97706',
                            backgroundColor: isDarkMode ? '#d97706' : '#fffbeb',
                            border: 'none',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            transition: 'all 0.2s ease',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            width: '36px',
                            height: '36px'
                          }}
                          onMouseEnter={(e) => {
                            if (isDarkMode) {
                              e.currentTarget.style.backgroundColor = '#b45309';
                            } else {
                              e.currentTarget.style.backgroundColor = '#d97706';
                              e.currentTarget.style.color = 'white';
                            }
                          }}
                          onMouseLeave={(e) => {
                            if (isDarkMode) {
                              e.currentTarget.style.backgroundColor = '#d97706';
                            } else {
                              e.currentTarget.style.backgroundColor = '#fffbeb';
                              e.currentTarget.style.color = '#d97706';
                            }
                          }}
                          title="Edit Permissions"
                        >
                          <i className="fas fa-pencil-alt"></i>
                        </button>

                        {/* Revoke/Activate Button */}
                        <button
                          onClick={() => {
                            setSelectedKeyId(key.id);
                            setRevokeAction(key.is_enabled ? 'revoke' : 'unrevoke');
                            setShowRevokeModal(true);
                          }}
                          style={{
                            padding: '0.5rem',
                            fontSize: '0.875rem',
                            color: isDarkMode ? 'white' : (key.is_enabled ? '#dc2626' : '#059669'),
                            backgroundColor: isDarkMode ? (key.is_enabled ? '#dc2626' : '#059669') : (key.is_enabled ? '#fee2e2' : '#d1fae5'),
                            border: 'none',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            transition: 'all 0.2s ease',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            width: '36px',
                            height: '36px'
                          }}
                          onMouseEnter={(e) => {
                            if (isDarkMode) {
                              e.currentTarget.style.backgroundColor = key.is_enabled ? '#b91c1c' : '#047857';
                            } else {
                              e.currentTarget.style.backgroundColor = key.is_enabled ? '#dc2626' : '#059669';
                              e.currentTarget.style.color = 'white';
                            }
                          }}
                          onMouseLeave={(e) => {
                            if (isDarkMode) {
                              e.currentTarget.style.backgroundColor = key.is_enabled ? '#dc2626' : '#059669';
                            } else {
                              e.currentTarget.style.backgroundColor = key.is_enabled ? '#fee2e2' : '#d1fae5';
                              e.currentTarget.style.color = key.is_enabled ? '#dc2626' : '#059669';
                            }
                          }}
                          title={key.is_enabled ? "Revoke Key" : "Activate Key"}
                        >
                          <i className={key.is_enabled ? "fas fa-ban" : "fas fa-check-circle"}></i>
                        </button>
                        
                        {/* Delete Button */}
                        <button
                          onClick={() => {
                            setSelectedKeyId(key.id);
                            setShowDeleteModal(true);
                          }}
                          style={{
                            padding: '0.5rem',
                            fontSize: '0.875rem',
                            color: isDarkMode ? 'white' : '#991b1b',
                            backgroundColor: isDarkMode ? '#991b1b' : '#fef2f2',
                            border: 'none',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            transition: 'all 0.2s ease',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            width: '36px',
                            height: '36px'
                          }}
                          onMouseEnter={(e) => {
                            if (isDarkMode) {
                              e.currentTarget.style.backgroundColor = '#7f1d1d';
                            } else {
                              e.currentTarget.style.backgroundColor = '#991b1b';
                              e.currentTarget.style.color = 'white';
                            }
                          }}
                          onMouseLeave={(e) => {
                            if (isDarkMode) {
                              e.currentTarget.style.backgroundColor = '#991b1b';
                            } else {
                              e.currentTarget.style.backgroundColor = '#fef2f2';
                              e.currentTarget.style.color = '#991b1b';
                            }
                          }}
                          title="Delete Key"
                        >
                          <i className="fas fa-trash"></i>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          </div>
        </div>

        {/* Create API Key Modal */}
        {showCreateModal && (
          <div 
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 9999,
              padding: '1rem'
            }}
            onClick={() => {
              setShowCreateModal(false);
              setError(null);
              setKeyName('');
              setKeyDescription('');
              setPermissionMode('');
              setSelectedGroup('');
              setSelectedScopes([]);
              setAccessType('');
              setExpiryDays(90);
            }}
          >
            <div
              key={formKey}
              style={{
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
                borderRadius: '14px',
                boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.4), 0 10px 10px -5px rgba(0, 0, 0, 0.2)',
                maxWidth: '640px',
                width: '100%',
                maxHeight: '90vh',
                overflow: 'auto',
                position: 'relative',
                border: isDarkMode ? `1px solid var(--border-color)` : 'none'
              }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header — coloured banner */}
              <div style={{
                background: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)',
                padding: '1.5rem 2rem',
                borderRadius: '14px 14px 0 0',
                display: 'flex',
                alignItems: 'center',
                gap: '1rem'
              }}>
                <div style={{
                  width: '44px', height: '44px',
                  backgroundColor: 'rgba(255,255,255,0.18)',
                  borderRadius: '10px',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0
                }}>
                  <i className="fas fa-key" style={{ color: 'white', fontSize: '1.1rem' }}></i>
                </div>
                <div style={{ flex: 1 }}>
                  <h2 style={{ color: 'white', margin: 0, fontSize: '1.2rem', fontWeight: '700', letterSpacing: '-0.01em' }}>
                    Create New API Key
                  </h2>
                  <p style={{ color: 'rgba(255,255,255,0.7)', margin: 0, fontSize: '0.8rem', marginTop: '0.15rem' }}>
                    Configure permissions and expiry for this key
                  </p>
                </div>
                <button
                  onClick={() => {
                    setShowCreateModal(false);
                    setError(null);
                    setKeyName('');
                    setKeyDescription('');
                    setPermissionMode('');
                    setSelectedGroup('');
                    setSelectedScopes([]);
                    setAccessType('');
                    setExpiryDays(90);
                  }}
                  style={{
                    background: 'rgba(255,255,255,0.15)',
                    border: 'none',
                    borderRadius: '8px',
                    color: 'white',
                    width: '32px', height: '32px',
                    cursor: 'pointer',
                    fontSize: '1.1rem',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                    transition: 'background 0.15s'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.25)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.15)'}
                >
                  ×
                </button>
              </div>

              {/* Form Content */}
              <div style={{ padding: '1.75rem 2rem 2rem' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  {/* Name Field */}
                  <div>
                    <label style={{
                      display: 'block',
                      fontSize: '0.9375rem',
                      fontWeight: '500',
                      color: isDarkMode ? 'var(--text-primary)' : '#374151',
                      marginBottom: '0.5rem'
                    }}>
                      API Key Name: <span style={{ color: '#ef4444' }}>*</span>
                    </label>
                    <input
                      type="text"
                      value={keyName}
                      onChange={(e) => setKeyName(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '0.625rem 0.875rem',
                        fontSize: '0.9375rem',
                        border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`,
                        borderRadius: '6px',
                        outline: 'none',
                        transition: 'border-color 0.15s ease',
                        backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
                        color: isDarkMode ? 'var(--text-primary)' : '#111827'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#3b82f6'}
                      onBlur={(e) => e.target.style.borderColor = '#d1d5db'}
                    />
                  </div>

                  {/* Description Field */}
                  <div>
                    <label style={{
                      display: 'block',
                      fontSize: '0.9375rem',
                      fontWeight: '500',
                      color: isDarkMode ? 'var(--text-primary)' : '#374151',
                      marginBottom: '0.5rem'
                    }}>
                      Description:
                    </label>
                    <textarea
                      value={keyDescription}
                      onChange={(e) => setKeyDescription(e.target.value)}
                      rows={3}
                      style={{
                        width: '100%',
                        padding: '0.625rem 0.875rem',
                        fontSize: '0.9375rem',
                        border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`,
                        borderRadius: '6px',
                        outline: 'none',
                        transition: 'border-color 0.15s ease',
                        resize: 'vertical',
                        fontFamily: 'inherit',
                        backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
                        color: isDarkMode ? 'var(--text-primary)' : '#111827'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#3b82f6'}
                      onBlur={(e) => e.target.style.borderColor = isDarkMode ? 'var(--border-color)' : '#d1d5db'}
                    />
                  </div>


                  {/* Permission Type */}
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                      {permissionMode === 'group' && (
                        <button
                          type="button"
                          onClick={() => { setPermissionMode(''); setSelectedGroup(''); }}
                          style={{
                            background: 'none', border: 'none', padding: '0 0.25rem',
                            cursor: 'pointer', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                            fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.25rem'
                          }}
                        >
                          <i className="fas fa-chevron-left" style={{ fontSize: '0.7rem' }}></i> Back
                        </button>
                      )}
                      <label style={{
                        display: 'block',
                        fontSize: '0.9375rem',
                        fontWeight: '500',
                        color: isDarkMode ? 'var(--text-primary)' : '#374151',
                        margin: 0
                      }}>
                        {permissionMode === 'group' ? 'Select Group:' : 'Permission Type:'}{' '}
                        <span style={{ color: '#ef4444' }}>*</span>
                      </label>
                    </div>

                    {/* Step 1: Group vs Fine-grained — hidden once Group is chosen */}
                    {permissionMode !== 'group' && (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                        <div
                          onClick={() => setPermissionMode('group')}
                          style={{
                            padding: '1rem', borderRadius: '8px', cursor: 'pointer',
                            border: `2px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                            backgroundColor: isDarkMode ? 'var(--bg-primary)' : '#f9fafb',
                            transition: 'border-color 0.15s, background-color 0.15s'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <div style={{
                              width: '14px', height: '14px', borderRadius: '50%', flexShrink: 0,
                              border: `2px solid #9ca3af`, backgroundColor: 'transparent'
                            }} />
                            <span style={{ fontWeight: '600', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>Group</span>
                          </div>
                          <p style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', margin: 0 }}>
                            Predefined role: Admin or Read-only
                          </p>
                        </div>

                        <div
                          onClick={() => setPermissionMode('finegrained')}
                          style={{
                            padding: '1rem', borderRadius: '8px', cursor: 'pointer',
                            border: `2px solid ${permissionMode === 'finegrained' ? '#dc2626' : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                            backgroundColor: permissionMode === 'finegrained'
                              ? (isDarkMode ? 'rgba(220,38,38,0.1)' : '#fff1f2')
                              : (isDarkMode ? 'var(--bg-primary)' : '#f9fafb'),
                            transition: 'border-color 0.15s, background-color 0.15s'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <div style={{
                              width: '14px', height: '14px', borderRadius: '50%', flexShrink: 0,
                              border: `2px solid ${permissionMode === 'finegrained' ? '#dc2626' : '#9ca3af'}`,
                              backgroundColor: permissionMode === 'finegrained' ? '#dc2626' : 'transparent'
                            }} />
                            <span style={{ fontWeight: '600', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>Fine-grained</span>
                          </div>
                          <p style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', margin: 0 }}>
                            Pick specific scopes manually
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Step 2: Read-Only / Admin — replaces the cards above when Group is chosen */}
                    {permissionMode === 'group' && (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                        {[
                          {
                            value: 'read_only',
                            label: 'Read-Only',
                            desc: 'List vendors, read vendor scores & reports',
                            scopes: ['vendors:list', 'vendors:read', 'reports:read'],
                          },
                          {
                            value: 'admin',
                            label: 'Admin',
                            desc: 'Full access — all operations (excludes webhook)',
                            scopes: operationalScopes.map(s => s.key),
                          },
                        ].map(({ value, label, desc, scopes }) => (
                          <div
                            key={value}
                            onClick={() => setSelectedGroup(value)}
                            style={{
                              padding: '1rem', borderRadius: '8px', cursor: 'pointer',
                              border: `2px solid ${selectedGroup === value ? '#dc2626' : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                              backgroundColor: selectedGroup === value
                                ? (isDarkMode ? 'rgba(220,38,38,0.1)' : '#fff1f2')
                                : (isDarkMode ? 'var(--bg-primary)' : '#f9fafb'),
                              transition: 'border-color 0.15s, background-color 0.15s'
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                              <div style={{
                                width: '14px', height: '14px', borderRadius: '50%', flexShrink: 0,
                                border: `2px solid ${selectedGroup === value ? '#dc2626' : '#9ca3af'}`,
                                backgroundColor: selectedGroup === value ? '#dc2626' : 'transparent'
                              }} />
                              <span style={{ fontWeight: '600', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>{label}</span>
                            </div>
                            <p style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', margin: '0 0 0.6rem' }}>{desc}</p>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                              {scopes.map(scope => (
                                <span key={scope} style={{
                                  fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: '600',
                                  padding: '0.15rem 0.45rem', borderRadius: '4px',
                                  backgroundColor: isDarkMode ? 'rgba(255,255,255,0.08)' : '#f3f4f6',
                                  color: isDarkMode ? '#d1d5db' : '#374151',
                                  border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.12)' : '#e5e7eb'}`
                                }}>
                                  {scope}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Fine-grained scope checklist */}
                    {permissionMode === 'finegrained' && (
                      <div style={{ marginTop: '0.75rem' }}>
                        <button
                          type="button"
                          onClick={applyWebhookOnlyPreset}
                          style={{
                            display: 'block',
                            width: '100%',
                            marginBottom: '0.75rem',
                            padding: '0.85rem 1rem',
                            textAlign: 'left',
                            borderRadius: '8px',
                            cursor: 'pointer',
                            border: `2px solid ${selectedScopes.length === 1 && selectedScopes[0] === WEBHOOK_SCOPE ? '#dc2626' : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                            backgroundColor: selectedScopes.length === 1 && selectedScopes[0] === WEBHOOK_SCOPE
                              ? (isDarkMode ? 'rgba(220,38,38,0.1)' : '#fff1f2')
                              : (isDarkMode ? 'var(--bg-primary)' : '#f9fafb'),
                          }}
                        >
                          <span style={{ fontWeight: '600', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>
                            Breach Monitor webhook only
                          </span>
                          <p style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', margin: '0.35rem 0 0' }}>
                            POST /vendiant/webhooks/breach-monitor only — cannot access vendors, scans, or reports
                          </p>
                        </button>
                        {/* Header row with Clear All */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                          <span style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                            {selectedScopes.length} scope{selectedScopes.length !== 1 ? 's' : ''} selected
                          </span>
                          {selectedScopes.length > 0 && (
                            <button
                              type="button"
                              onClick={() => setSelectedScopes([])}
                              style={{
                                display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
                                padding: '0.35rem 0.75rem',
                                fontSize: '0.78rem', fontWeight: '600',
                                color: '#dc2626',
                                backgroundColor: isDarkMode ? 'rgba(220,38,38,0.12)' : '#fff1f2',
                                border: `1px solid ${isDarkMode ? 'rgba(220,38,38,0.35)' : '#fca5a5'}`,
                                borderRadius: '6px', cursor: 'pointer',
                                transition: 'all 0.15s'
                              }}
                              onMouseEnter={(e) => {
                                e.currentTarget.style.backgroundColor = '#dc2626';
                                e.currentTarget.style.color = 'white';
                                e.currentTarget.style.borderColor = '#dc2626';
                              }}
                              onMouseLeave={(e) => {
                                e.currentTarget.style.backgroundColor = isDarkMode ? 'rgba(220,38,38,0.12)' : '#fff1f2';
                                e.currentTarget.style.color = '#dc2626';
                                e.currentTarget.style.borderColor = isDarkMode ? 'rgba(220,38,38,0.35)' : '#fca5a5';
                              }}
                            >
                              <i className="fas fa-times" style={{ fontSize: '0.65rem' }}></i>
                              Clear all
                            </button>
                          )}
                        </div>
                      <div style={{
                        border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                        borderRadius: '8px',
                        overflow: 'hidden'
                      }}>
                        {availableScopes.map((scope, i) => {
                          const webhookLocked = selectedScopes.includes(WEBHOOK_SCOPE) && scope.key !== WEBHOOK_SCOPE;
                          const otherScopesLocked = selectedScopes.some(s => s !== WEBHOOK_SCOPE) && scope.key === WEBHOOK_SCOPE;
                          const disabled = webhookLocked || otherScopesLocked;
                          return (
                          <div
                            key={scope.key}
                            onClick={() => !disabled && toggleScope(scope.key)}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.75rem',
                              padding: '0.75rem 1rem',
                              cursor: disabled ? 'not-allowed' : 'pointer',
                              opacity: disabled ? 0.45 : 1,
                              borderTop: i > 0 ? `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` : 'none',
                              backgroundColor: selectedScopes.includes(scope.key)
                                ? (isDarkMode ? 'rgba(220,38,38,0.07)' : '#fff1f2')
                                : 'transparent',
                              transition: 'background-color 0.1s'
                            }}
                          >
                            <div style={{
                              width: '16px', height: '16px', borderRadius: '4px', flexShrink: 0,
                              border: `2px solid ${selectedScopes.includes(scope.key) ? '#dc2626' : (isDarkMode ? '#6b7280' : '#d1d5db')}`,
                              backgroundColor: selectedScopes.includes(scope.key) ? '#dc2626' : 'transparent',
                              display: 'flex', alignItems: 'center', justifyContent: 'center'
                            }}>
                              {selectedScopes.includes(scope.key) && (
                                <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                                  <path d="M1 4L3.5 6.5L9 1" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                                </svg>
                              )}
                            </div>
                            <div>
                              <span style={{ fontSize: '0.875rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#111827', fontFamily: 'monospace' }}>
                                {scope.key}
                              </span>
                              <span style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', marginLeft: '0.5rem' }}>
                                — {scope.description}
                              </span>
                            </div>
                          </div>
                        );})}
                      </div>
                      </div>
                    )}
                  </div>

                  {/* Access Type — two-card selection */}
                  <div>
                    <label style={{
                      display: 'block',
                      fontSize: '0.9375rem',
                      fontWeight: '500',
                      color: isDarkMode ? 'var(--text-primary)' : '#374151',
                      marginBottom: '0.75rem'
                    }}>
                      Access Type: <span style={{ color: '#ef4444' }}>*</span>
                    </label>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                      {[
                        { value: 'temporary' as const, label: 'Temporary', desc: 'Expires after a set number of days' },
                        { value: 'permanent' as const, label: 'Permanent', desc: 'Never expires' },
                      ].map(({ value, label, desc }) => (
                        <div
                          key={value}
                          onClick={() => setAccessType(value)}
                          style={{
                            padding: '1rem',
                            borderRadius: '8px',
                            border: `2px solid ${accessType === value ? '#dc2626' : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                            backgroundColor: accessType === value
                              ? (isDarkMode ? 'rgba(220,38,38,0.1)' : '#fff1f2')
                              : (isDarkMode ? 'var(--bg-primary)' : '#f9fafb'),
                            cursor: 'pointer',
                            transition: 'border-color 0.15s, background-color 0.15s'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <div style={{
                              width: '14px', height: '14px', borderRadius: '50%',
                              border: `2px solid ${accessType === value ? '#dc2626' : '#9ca3af'}`,
                              backgroundColor: accessType === value ? '#dc2626' : 'transparent',
                              flexShrink: 0
                            }} />
                            <span style={{ fontWeight: '600', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>
                              {label}
                            </span>
                          </div>
                          <p style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', margin: 0 }}>
                            {desc}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Expiry Days Field (only show if Temporary) */}
                  {accessType === 'temporary' && (
                    <div>
                      <label style={{
                        display: 'block',
                        fontSize: '0.9375rem',
                        fontWeight: '500',
                        color: isDarkMode ? 'var(--text-primary)' : '#374151',
                        marginBottom: '0.75rem'
                      }}>
                        Expiry Days: <span style={{ color: '#ef4444' }}>*</span>
                      </label>

                      {/* Preset quick-select pills */}
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
                        {[30, 90, 180].map((days) => (
                          <button
                            key={days}
                            type="button"
                            onClick={() => setExpiryDays(days)}
                            style={{
                              padding: '0.6rem 0',
                              borderRadius: '8px',
                              border: `2px solid ${expiryDays === days ? '#dc2626' : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                              backgroundColor: expiryDays === days
                                ? (isDarkMode ? 'rgba(220,38,38,0.12)' : '#fff1f2')
                                : (isDarkMode ? 'var(--bg-primary)' : '#f9fafb'),
                              color: expiryDays === days ? '#dc2626' : (isDarkMode ? 'var(--text-secondary)' : '#6b7280'),
                              fontWeight: '600',
                              fontSize: '0.875rem',
                              cursor: 'pointer',
                              transition: 'all 0.15s'
                            }}
                          >
                            {days} days
                          </button>
                        ))}
                      </div>

                      {/* Always-editable custom number input */}
                      <div style={{ position: 'relative' }}>
                        <input
                          type="number"
                          value={expiryDays}
                          onChange={(e) => {
                            const v = parseInt(e.target.value);
                            if (!isNaN(v) && v > 0) setExpiryDays(v);
                            else if (e.target.value === '') setExpiryDays(1);
                          }}
                          min="1"
                          placeholder="Custom days…"
                          style={{
                            width: '100%',
                            padding: '0.625rem 3.5rem 0.625rem 0.875rem',
                            fontSize: '0.9375rem',
                            border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`,
                            borderRadius: '6px',
                            outline: 'none',
                            transition: 'border-color 0.15s ease',
                            backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
                            color: isDarkMode ? 'var(--text-primary)' : '#111827',
                            boxSizing: 'border-box'
                          }}
                          onFocus={(e) => e.target.style.borderColor = '#dc2626'}
                          onBlur={(e) => e.target.style.borderColor = isDarkMode ? 'var(--border-color)' : '#d1d5db'}
                        />
                        <span style={{
                          position: 'absolute', right: '0.875rem', top: '50%',
                          transform: 'translateY(-50%)',
                          color: isDarkMode ? 'var(--text-secondary)' : '#9ca3af',
                          fontSize: '0.8rem', pointerEvents: 'none', userSelect: 'none'
                        }}>
                          days
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                {error && (
                  <div style={{
                    marginTop: '1.5rem',
                    padding: '0.75rem 1rem',
                    backgroundColor: isDarkMode ? 'rgba(220, 38, 38, 0.1)' : '#fee2e2',
                    borderLeft: `4px solid ${isDarkMode ? '#f87171' : '#ef4444'}`,
                    borderRadius: '0 4px 4px 0',
                    color: isDarkMode ? '#f87171' : '#991b1b',
                    fontSize: '0.875rem'
                  }}>
                    {error}
                  </div>
                )}

                {/* Buttons */}
                <div style={{ 
                  marginTop: '2rem',
                  display: 'flex',
                  gap: '0.75rem',
                  justifyContent: 'flex-end'
                }}>
                  <button
                    onClick={() => {
                      setShowCreateModal(false);
                      setError(null);
                      setKeyName('');
                      setKeyDescription('');
                      setPermissionMode('');
                      setSelectedGroup('');
                      setSelectedScopes([]);
                      setAccessType('');
                      setExpiryDays(90);
                    }}
                    style={{
                      padding: '0.625rem 1.5rem',
                      fontSize: '0.9375rem',
                      fontWeight: '500',
                      color: isDarkMode ? '#e5e7eb' : '#374151',
                      backgroundColor: isDarkMode ? '#374151' : '#f3f4f6',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#4b5563' : '#e5e7eb'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#374151' : '#f3f4f6'}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreateAPIKey}
                    style={{
                      padding: '0.625rem 1.5rem',
                      fontSize: '0.9375rem',
                      fontWeight: '500',
                      color: 'white',
                      backgroundColor: '#dc2626',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#b91c1c'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#dc2626'}
                  >
                    Create API Key
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Key Display Modal (One-time display) */}
        {showKeyDisplayModal && (
          <div 
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 9999,
              padding: '1rem'
            }}
          >
            <div 
              style={{
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
                borderRadius: '12px',
                boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2)',
                padding: '2rem',
                maxWidth: '600px',
                width: '100%',
                border: isDarkMode ? `1px solid var(--border-color)` : 'none'
              }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header with Success Icon */}
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '1rem',
                marginBottom: '1.5rem'
              }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  backgroundColor: isDarkMode ? 'rgba(16, 185, 129, 0.2)' : '#d1fae5',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <i className="fas fa-check" style={{ 
                    color: '#10b981', 
                    fontSize: '1.25rem' 
                  }}></i>
                </div>
                <h2 style={{ 
                  fontSize: '1.5rem', 
                  fontWeight: '600', 
                  color: '#10b981',
                  margin: 0
                }}>API Key Created Successfully!</h2>
              </div>
              
              {/* Warning Message */}
              <div style={{ 
                marginBottom: '1.5rem',
                padding: '1rem',
                backgroundColor: isDarkMode ? 'rgba(245, 158, 11, 0.1)' : '#fef3c7',
                borderLeft: `4px solid ${isDarkMode ? '#fbbf24' : '#f59e0b'}`,
                borderRadius: '0 6px 6px 0'
              }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                  <i className="fas fa-exclamation-triangle" style={{ 
                    color: isDarkMode ? '#fbbf24' : '#d97706',
                    fontSize: '1rem',
                    marginTop: '0.125rem'
                  }}></i>
                  <div>
                    <p style={{ 
                      color: isDarkMode ? '#fbbf24' : '#92400e',
                      fontWeight: '600',
                      margin: '0 0 0.25rem 0',
                      fontSize: '0.875rem'
                    }}>Important Security Notice</p>
                    <p style={{ 
                      color: isDarkMode ? 'var(--text-primary)' : '#78350f',
                      margin: 0,
                      fontSize: '0.875rem',
                      lineHeight: '1.5'
                    }}>
                      This is the <strong>only time</strong> you will see this API key. Please copy it now and store it securely.
                    </p>
                  </div>
                </div>
              </div>

              {/* API Key Display */}
              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ 
                  display: 'block',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: isDarkMode ? '#10b981' : '#6b7280',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginBottom: '0.5rem'
                }}>
                  Your API Key
                </label>
                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '0.75rem',
                  padding: '1rem',
                  backgroundColor: isDarkMode ? '#374151' : '#f3f4f6',
                  borderRadius: '8px',
                  border: `2px solid ${isDarkMode ? '#4b5563' : '#d1d5db'}`
                }}>
                  <code style={{ 
                    flex: 1,
                    fontSize: '0.875rem',
                    fontFamily: 'monospace',
                    wordBreak: 'break-all',
                    color: isDarkMode ? '#e5e7eb' : '#111827',
                    backgroundColor: isDarkMode ? '#1f2937' : '#e5e7eb',
                    padding: '0.75rem',
                    borderRadius: '6px',
                    border: `1px solid ${isDarkMode ? '#4b5563' : '#9ca3af'}`
                  }}>
                    {createdApiKey}
                  </code>
                  <button
                    onClick={() => copyToClipboard(createdApiKey)}
                    style={{
                      padding: '0.75rem 1.25rem',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      color: 'white',
                      backgroundColor: '#3b82f6',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      whiteSpace: 'nowrap'
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.backgroundColor = '#2563eb';
                      e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.2)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.backgroundColor = '#3b82f6';
                      e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1)';
                    }}
                  >
                    <i className="fas fa-copy"></i>
                    Copy
                  </button>
                </div>
              </div>

              {/* Close Button */}
              <div style={{ 
                display: 'flex',
                justifyContent: 'flex-end'
              }}>
                <button
                  onClick={() => {
                    setShowKeyDisplayModal(false);
                    setCreatedApiKey('');
                  }}
                  style={{
                    padding: '0.75rem 1.5rem',
                    fontSize: '0.9375rem',
                    fontWeight: '500',
                    color: 'white',
                    backgroundColor: '#6b7280',
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#4b5563'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#6b7280'}
                >
                  <i className="fas fa-times"></i>
                  Close
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Revoke Confirmation Modal */}
        {showRevokeModal && (
          <div 
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 9999,
              padding: '1rem'
            }}
            onClick={() => {
              setShowRevokeModal(false);
              setSelectedKeyId(null);
            }}
          >
            <div 
              style={{
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
                borderRadius: '12px',
                boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2)',
                padding: '2rem',
                maxWidth: '500px',
                width: '100%',
                border: isDarkMode ? `1px solid var(--border-color)` : 'none'
              }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header with Icon */}
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '1rem',
                marginBottom: '1.5rem'
              }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  backgroundColor: isDarkMode ? (revokeAction === 'revoke' ? 'rgba(220, 38, 38, 0.2)' : 'rgba(16, 185, 129, 0.2)') : (revokeAction === 'revoke' ? '#fee2e2' : '#d1fae5'),
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <i className={revokeAction === 'revoke' ? "fas fa-exclamation-triangle" : "fas fa-check-circle"} style={{ 
                    color: isDarkMode ? (revokeAction === 'revoke' ? '#f87171' : '#34d399') : (revokeAction === 'revoke' ? '#dc2626' : '#059669'), 
                    fontSize: '1.25rem' 
                  }}></i>
                </div>
                <h2 style={{ 
                  fontSize: '1.5rem', 
                  fontWeight: '600', 
                  color: isDarkMode ? (revokeAction === 'revoke' ? '#f87171' : '#34d399') : (revokeAction === 'revoke' ? '#dc2626' : '#059669'),
                  margin: 0
                }}>{revokeAction === 'revoke' ? 'Revoke' : 'Activate'} API Key</h2>
              </div>
              
              {/* Warning Message */}
              <div style={{ 
                marginBottom: '2rem',
                padding: '1rem',
                backgroundColor: isDarkMode ? (revokeAction === 'revoke' ? 'rgba(220, 38, 38, 0.1)' : 'rgba(16, 185, 129, 0.1)') : (revokeAction === 'revoke' ? '#fef2f2' : '#d1fae5'),
                borderLeft: `4px solid ${isDarkMode ? (revokeAction === 'revoke' ? '#f87171' : '#34d399') : (revokeAction === 'revoke' ? '#dc2626' : '#059669')}`,
                borderRadius: '0 6px 6px 0'
              }}>
                <p style={{ 
                  color: isDarkMode ? 'var(--text-primary)' : '#374151',
                  margin: 0,
                  lineHeight: '1.5'
                }}>
                  {revokeAction === 'revoke' 
                    ? 'Are you sure you want to revoke this API key?' 
                    : 'Are you sure you want to Activate this API key?'
                  }
                </p>
                <p style={{ 
                  color: isDarkMode ? (revokeAction === 'revoke' ? '#f87171' : '#34d399') : (revokeAction === 'revoke' ? '#dc2626' : '#059669'),
                  fontWeight: '600',
                  marginTop: '0.75rem',
                  marginBottom: 0
                }}>
                  {revokeAction === 'revoke' 
                    ? 'This will immediately disable the key, but it can be reactivated later.' 
                    : 'This will Enable the Key.'
                  }
                </p>
              </div>

              {/* Action Buttons */}
              <div style={{ 
                display: 'flex', 
                gap: '0.75rem',
                justifyContent: 'flex-end'
              }}>
                <button
                  onClick={() => {
                    setShowRevokeModal(false);
                    setSelectedKeyId(null);
                  }}
                  style={{
                    padding: '0.75rem 1.5rem',
                    fontSize: '0.9375rem',
                    fontWeight: '500',
                    color: isDarkMode ? '#e5e7eb' : '#374151',
                    backgroundColor: isDarkMode ? '#374151' : '#f3f4f6',
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#4b5563' : '#e5e7eb'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#374151' : '#f3f4f6'}
                >
                  Cancel
                </button>
                <button
                  onClick={() => handleRevokeAPIKey(revokeAction)}
                  style={{
                    padding: '0.75rem 1.5rem',
                    fontSize: '0.9375rem',
                    fontWeight: '500',
                    color: 'white',
                    backgroundColor: revokeAction === 'revoke' ? '#dc2626' : '#059669',
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = revokeAction === 'revoke' ? '#b91c1c' : '#047857';
                    e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.2)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = revokeAction === 'revoke' ? '#dc2626' : '#059669';
                    e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1)';
                  }}
                >
                  <i className={revokeAction === 'revoke' ? "fas fa-ban" : "fas fa-check-circle"}></i>
                  {revokeAction === 'revoke' ? 'Revoke Key' : 'Activate Key'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Delete Confirmation Modal */}
        {showDeleteModal && (
          <div 
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 9999,
              padding: '1rem'
            }}
            onClick={() => {
              setShowDeleteModal(false);
              setSelectedKeyId(null);
            }}
          >
            <div 
              style={{
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
                borderRadius: '12px',
                boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2)',
                padding: '2rem',
                maxWidth: '500px',
                width: '100%',
                border: isDarkMode ? `1px solid var(--border-color)` : 'none'
              }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header with Icon */}
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '1rem',
                marginBottom: '1.5rem'
              }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  backgroundColor: isDarkMode ? 'rgba(220, 38, 38, 0.2)' : '#fee2e2',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <i className="fas fa-trash-alt" style={{ 
                    color: isDarkMode ? '#f87171' : '#dc2626', 
                    fontSize: '1.25rem' 
                  }}></i>
                </div>
                <h2 style={{ 
                  fontSize: '1.5rem', 
                  fontWeight: '600', 
                  color: isDarkMode ? '#f87171' : '#dc2626',
                  margin: 0
                }}>Delete API Key</h2>
              </div>
              
              {/* Warning Message */}
              <div style={{ 
                marginBottom: '2rem',
                padding: '1rem',
                backgroundColor: isDarkMode ? 'rgba(220, 38, 38, 0.1)' : '#fef2f2',
                borderLeft: `4px solid ${isDarkMode ? '#f87171' : '#dc2626'}`,
                borderRadius: '0 6px 6px 0'
              }}>
                <p style={{ 
                  color: isDarkMode ? 'var(--text-primary)' : '#374151',
                  margin: 0,
                  lineHeight: '1.5'
                }}>
                  Are you sure you want to permanently delete this API key?
                </p>
                <p style={{ 
                  color: isDarkMode ? '#f87171' : '#dc2626',
                  fontWeight: '600',
                  marginTop: '0.75rem',
                  marginBottom: 0
                }}>
                  This action cannot be undone and will permanently remove the key from the database.
                </p>
              </div>

              {/* Action Buttons */}
              <div style={{ 
                display: 'flex', 
                gap: '0.75rem',
                justifyContent: 'flex-end'
              }}>
                <button
                  onClick={() => {
                    setShowDeleteModal(false);
                    setSelectedKeyId(null);
                  }}
                  style={{
                    padding: '0.75rem 1.5rem',
                    fontSize: '0.9375rem',
                    fontWeight: '500',
                    color: isDarkMode ? '#e5e7eb' : '#374151',
                    backgroundColor: isDarkMode ? '#374151' : '#f3f4f6',
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#4b5563' : '#e5e7eb'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#374151' : '#f3f4f6'}
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeleteAPIKey}
                  style={{
                    padding: '0.75rem 1.5rem',
                    fontSize: '0.9375rem',
                    fontWeight: '500',
                    color: 'white',
                    backgroundColor: '#991b1b',
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = '#7f1d1d';
                    e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.2)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = '#991b1b';
                    e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1)';
                  }}
                >
                  <i className="fas fa-trash"></i>
                  Delete Key
                </button>
              </div>
            </div>
          </div>
        )}

        {/* API Key Details Modal */}
        {showDetailsModal && selectedKeyDetails && (
          <div
            style={{
              position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
              backgroundColor: 'rgba(0,0,0,0.6)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              zIndex: 9999, padding: '1rem'
            }}
            onClick={() => { setShowDetailsModal(false); setSelectedKeyDetails(null); }}
          >
            <div
              style={{
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
                borderRadius: '14px',
                boxShadow: '0 25px 50px -12px rgba(0,0,0,0.45)',
                maxWidth: '620px', width: '100%',
                maxHeight: '90vh', overflowY: 'auto',
                border: isDarkMode ? `1px solid var(--border-color)` : 'none'
              }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Fancy red-gradient header */}
              <div style={{
                background: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)',
                padding: '1.5rem 2rem',
                borderRadius: '14px 14px 0 0',
                display: 'flex', alignItems: 'center', gap: '1rem'
              }}>
                <div style={{
                  width: '44px', height: '44px',
                  backgroundColor: 'rgba(255,255,255,0.18)', borderRadius: '10px',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
                }}>
                  <i className="fas fa-key" style={{ color: 'white', fontSize: '1.1rem' }}></i>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <h2 style={{ color: 'white', margin: 0, fontSize: '1.15rem', fontWeight: '700', letterSpacing: '-0.01em', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {selectedKeyDetails.name}
                  </h2>
                  <p style={{ color: 'rgba(255,255,255,0.7)', margin: 0, fontSize: '0.78rem', marginTop: '0.15rem' }}>
                    ID #{selectedKeyDetails.id} · API Key Details
                  </p>
                </div>
                <button
                  onClick={() => { setShowDetailsModal(false); setSelectedKeyDetails(null); }}
                  style={{
                    background: 'rgba(255,255,255,0.15)', border: 'none', borderRadius: '8px',
                    color: 'white', width: '32px', height: '32px', cursor: 'pointer',
                    fontSize: '1.1rem', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0, transition: 'background 0.15s'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.28)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.15)'}
                >×</button>
              </div>

              {/* Content */}
              <div style={{ padding: '1.75rem 2rem 2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                {/* Description */}
                {selectedKeyDetails.description && (
                  <p style={{ margin: 0, fontSize: '0.9rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontStyle: 'italic' }}>
                    {selectedKeyDetails.description}
                  </p>
                )}

                {/* Timeline grid */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.875rem' }}>
                    <i className="fas fa-clock" style={{ color: isDarkMode ? '#6b7280' : '#9ca3af', fontSize: '0.85rem' }}></i>
                    <span style={{ fontSize: '0.8rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.06em', color: isDarkMode ? '#6b7280' : '#9ca3af' }}>Timeline</span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    {[
                      { label: 'Created', value: formatDate(selectedKeyDetails.created_at) },
                      { label: 'Created By', value: selectedKeyDetails.created_by },
                      { label: 'Expires', value: selectedKeyDetails.expires_at ? formatDate(selectedKeyDetails.expires_at) : null, highlight: true },
                      { label: 'Last Accessed', value: selectedKeyDetails.last_accessed ? formatDate(selectedKeyDetails.last_accessed) : 'Never' },
                    ].map(({ label, value, highlight }) => (
                      <div key={label} style={{
                        padding: '0.875rem 1rem', borderRadius: '8px',
                        backgroundColor: isDarkMode ? 'rgba(255,255,255,0.04)' : '#f9fafb',
                        border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}`
                      }}>
                        <p style={{ margin: '0 0 0.25rem', fontSize: '0.72rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.05em', color: isDarkMode ? '#6b7280' : '#9ca3af' }}>{label}</p>
                        {highlight && !value
                          ? <p style={{ margin: 0, fontSize: '0.875rem', fontWeight: '700', color: '#10b981' }}>Never (Permanent)</p>
                          : <p style={{ margin: 0, fontSize: '0.875rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>{value}</p>
                        }
                      </div>
                    ))}
                  </div>
                </div>

                {/* Access & Security */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.875rem' }}>
                    <i className="fas fa-shield-alt" style={{ color: isDarkMode ? '#6b7280' : '#9ca3af', fontSize: '0.85rem' }}></i>
                    <span style={{ fontSize: '0.8rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.06em', color: isDarkMode ? '#6b7280' : '#9ca3af' }}>Access &amp; Security</span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem', marginBottom: '1rem' }}>
                    {/* Group */}
                    <div style={{ padding: '0.875rem 1rem', borderRadius: '8px', backgroundColor: isDarkMode ? 'rgba(255,255,255,0.04)' : '#f9fafb', border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      <p style={{ margin: '0 0 0.4rem', fontSize: '0.72rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.05em', color: isDarkMode ? '#6b7280' : '#9ca3af' }}>Group</p>
                      <span style={{
                        padding: '0.2rem 0.65rem', borderRadius: '9999px', fontSize: '0.75rem', fontWeight: '600',
                        backgroundColor: selectedKeyDetails.group_name === 'admin' ? (isDarkMode ? 'rgba(124,58,237,0.35)' : '#f3e8ff') : selectedKeyDetails.group_name === 'finegrained' ? (isDarkMode ? 'rgba(245,158,11,0.35)' : '#fef3c7') : (isDarkMode ? 'rgba(37,99,235,0.35)' : '#dbeafe'),
                        color: selectedKeyDetails.group_name === 'admin' ? (isDarkMode ? '#a78bfa' : '#7c3aed') : selectedKeyDetails.group_name === 'finegrained' ? (isDarkMode ? '#fbbf24' : '#92400e') : (isDarkMode ? '#60a5fa' : '#1d4ed8')
                      }}>
                        {selectedKeyDetails.group_name}
                      </span>
                    </div>
                    {/* Status */}
                    <div style={{ padding: '0.875rem 1rem', borderRadius: '8px', backgroundColor: isDarkMode ? 'rgba(255,255,255,0.04)' : '#f9fafb', border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      <p style={{ margin: '0 0 0.4rem', fontSize: '0.72rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.05em', color: isDarkMode ? '#6b7280' : '#9ca3af' }}>Status</p>
                      <span style={{
                        padding: '0.2rem 0.65rem', borderRadius: '9999px', fontSize: '0.75rem', fontWeight: '600',
                        backgroundColor: selectedKeyDetails.is_enabled ? (isDarkMode ? 'rgba(16,185,129,0.35)' : '#d1fae5') : (isDarkMode ? 'rgba(220,38,38,0.35)' : '#fee2e2'),
                        color: selectedKeyDetails.is_enabled ? (isDarkMode ? '#34d399' : '#065f46') : (isDarkMode ? '#f87171' : '#991b1b')
                      }}>
                        {selectedKeyDetails.is_enabled ? 'Active' : 'Disabled'}
                      </span>
                    </div>
                    {/* Rate limit */}
                    <div style={{ padding: '0.875rem 1rem', borderRadius: '8px', backgroundColor: isDarkMode ? 'rgba(255,255,255,0.04)' : '#f9fafb', border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      <p style={{ margin: '0 0 0.25rem', fontSize: '0.72rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.05em', color: isDarkMode ? '#6b7280' : '#9ca3af' }}>Rate Limit</p>
                      <p style={{ margin: 0, fontSize: '0.875rem', fontWeight: '700', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>{selectedKeyDetails.request_limit} req/min</p>
                    </div>
                  </div>

                  {/* Scopes section */}
                  <div style={{ padding: '1rem', borderRadius: '8px', backgroundColor: isDarkMode ? 'rgba(255,255,255,0.04)' : '#f9fafb', border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                    <p style={{ margin: '0 0 0.6rem', fontSize: '0.72rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.05em', color: isDarkMode ? '#6b7280' : '#9ca3af' }}>Permissions</p>
                    {selectedKeyDetails.group_name === 'admin' ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{
                          display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
                          padding: '0.3rem 0.75rem', borderRadius: '6px', fontSize: '0.8rem', fontWeight: '600',
                          backgroundColor: isDarkMode ? 'rgba(124,58,237,0.2)' : '#f3e8ff',
                          color: isDarkMode ? '#a78bfa' : '#7c3aed',
                          border: `1px solid ${isDarkMode ? 'rgba(124,58,237,0.4)' : '#ddd6fe'}`
                        }}>
                          <i className="fas fa-star" style={{ fontSize: '0.65rem' }}></i>
                          Full access — all scopes enabled
                        </span>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                        {(selectedKeyDetails.group_name === 'finegrained'
                          ? (selectedKeyDetails.finegrained_scopes || [])
                          : ['vendors:list', 'vendors:read', 'reports:read']
                        ).map(scope => (
                          <span key={scope} style={{
                            fontSize: '0.75rem', fontFamily: 'monospace', fontWeight: '600',
                            padding: '0.25rem 0.6rem', borderRadius: '5px',
                            backgroundColor: isDarkMode ? 'rgba(255,255,255,0.08)' : '#f3f4f6',
                            color: isDarkMode ? '#d1d5db' : '#374151',
                            border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.14)' : '#e5e7eb'}`
                          }}>
                            {scope}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Credential hash */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.6rem' }}>
                    <i className="fas fa-fingerprint" style={{ color: isDarkMode ? '#6b7280' : '#9ca3af', fontSize: '0.85rem' }}></i>
                    <span style={{ fontSize: '0.8rem', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.06em', color: isDarkMode ? '#6b7280' : '#9ca3af' }}>Credential Hash</span>
                  </div>
                  <div style={{
                    padding: '0.75rem 1rem', borderRadius: '8px', fontFamily: 'monospace', fontSize: '0.78rem',
                    backgroundColor: isDarkMode ? 'rgba(255,255,255,0.04)' : '#f9fafb',
                    border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                    color: isDarkMode ? '#9ca3af' : '#6b7280',
                    wordBreak: 'break-all'
                  }}>
                    {selectedKeyDetails.credential_hash}
                  </div>
                </div>

              </div>
                  
            </div>
          </div>
        )}

        {/* Edit API Key Modal */}
        {showEditModal && editingKey && (
          <div
            style={{
              position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
              backgroundColor: 'rgba(0,0,0,0.6)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              zIndex: 9999, padding: '1rem'
            }}
            onClick={() => { setShowEditModal(false); setEditingKey(null); setError(null); }}
          >
            <div
              onClick={e => e.stopPropagation()}
              style={{
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
                borderRadius: '14px',
                boxShadow: '0 25px 50px -12px rgba(0,0,0,0.4)',
                maxWidth: '640px', width: '100%',
                maxHeight: '90vh', overflowY: 'auto',
                border: isDarkMode ? `1px solid var(--border-color)` : 'none'
              }}
            >
              {/* Fancy header */}
              <div style={{
                background: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)',
                padding: '1.5rem 2rem', borderRadius: '14px 14px 0 0',
                display: 'flex', alignItems: 'center', gap: '1rem'
              }}>
                <div style={{
                  width: '44px', height: '44px', backgroundColor: 'rgba(255,255,255,0.18)',
                  borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
                }}>
                  <i className="fas fa-pencil-alt" style={{ color: 'white', fontSize: '1.1rem' }}></i>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <h2 style={{ color: 'white', margin: 0, fontSize: '1.2rem', fontWeight: '700', letterSpacing: '-0.01em' }}>Edit API Key</h2>
                  <p style={{ color: 'rgba(255,255,255,0.7)', margin: 0, fontSize: '0.8rem', marginTop: '0.15rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {editingKey.name}
                  </p>
                </div>
                <button
                  onClick={() => { setShowEditModal(false); setEditingKey(null); setError(null); }}
                  style={{
                    background: 'rgba(255,255,255,0.15)', border: 'none', borderRadius: '8px',
                    color: 'white', width: '32px', height: '32px', cursor: 'pointer',
                    fontSize: '1.1rem', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.25)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.15)'}
                >×</button>
              </div>

              {/* Form body */}
              <div style={{ padding: '1.75rem 2rem 2rem' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                  {error && (
                    <div style={{
                      padding: '0.75rem 1rem', borderRadius: '8px',
                      backgroundColor: isDarkMode ? 'rgba(220,38,38,0.12)' : '#fee2e2',
                      borderLeft: `4px solid #ef4444`,
                      color: isDarkMode ? '#f87171' : '#991b1b', fontSize: '0.875rem'
                    }}>{error}</div>
                  )}

                  {/* Name */}
                  <div>
                    <label style={{ display: 'block', fontSize: '0.9375rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#374151', marginBottom: '0.5rem' }}>
                      API Key Name: <span style={{ color: '#ef4444' }}>*</span>
                    </label>
                    <input
                      type="text"
                      value={editKeyName}
                      onChange={(e) => setEditKeyName(e.target.value)}
                      style={{
                        width: '100%', padding: '0.625rem 0.875rem', fontSize: '0.9375rem',
                        border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`,
                        borderRadius: '6px', outline: 'none',
                        backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
                        color: isDarkMode ? 'var(--text-primary)' : '#111827', boxSizing: 'border-box'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#dc2626'}
                      onBlur={(e) => e.target.style.borderColor = isDarkMode ? 'var(--border-color)' : '#d1d5db'}
                    />
                  </div>

                  {/* Description */}
                  <div>
                    <label style={{ display: 'block', fontSize: '0.9375rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#374151', marginBottom: '0.5rem' }}>
                      Description:
                    </label>
                    <textarea
                      value={editKeyDescription}
                      onChange={(e) => setEditKeyDescription(e.target.value)}
                      rows={2}
                      style={{
                        width: '100%', padding: '0.625rem 0.875rem', fontSize: '0.9375rem',
                        border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`,
                        borderRadius: '6px', outline: 'none', resize: 'vertical',
                        backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
                        color: isDarkMode ? 'var(--text-primary)' : '#111827', boxSizing: 'border-box'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#dc2626'}
                      onBlur={(e) => e.target.style.borderColor = isDarkMode ? 'var(--border-color)' : '#d1d5db'}
                    />
                  </div>

                  {/* Step 1: Permission Type — only shown when nothing chosen yet */}
                  {!editPermissionMode && (
                    <div>
                      <label style={{ display: 'block', fontSize: '0.9375rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#374151', marginBottom: '0.75rem' }}>
                        Permission Type: <span style={{ color: '#ef4444' }}>*</span>
                      </label>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                        {(['group', 'finegrained'] as const).map(mode => (
                          <div key={mode} onClick={() => { setEditPermissionMode(mode); setError(null); }} style={{
                            padding: '1rem', borderRadius: '8px', cursor: 'pointer',
                            border: `2px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                            backgroundColor: isDarkMode ? 'var(--bg-primary)' : '#f9fafb',
                            transition: 'border-color 0.15s'
                          }}
                          onMouseEnter={(e) => e.currentTarget.style.borderColor = '#dc2626'}
                          onMouseLeave={(e) => e.currentTarget.style.borderColor = isDarkMode ? 'var(--border-color)' : '#e5e7eb'}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                              <div style={{ width: '14px', height: '14px', borderRadius: '50%', flexShrink: 0, border: `2px solid #9ca3af` }} />
                              <span style={{ fontWeight: '600', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>{mode === 'group' ? 'Group' : 'Fine-grained'}</span>
                            </div>
                            <p style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', margin: 0 }}>
                              {mode === 'group' ? 'Predefined role: Admin or Read-only' : 'Pick specific scopes manually'}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Step 2a: Group cards — replaces type picker when Group chosen */}
                  {editPermissionMode === 'group' && (
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                        <label style={{ fontSize: '0.9375rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#374151' }}>
                          Permission Group: <span style={{ color: '#ef4444' }}>*</span>
                        </label>
                        <button type="button" onClick={() => { setEditPermissionMode(''); setEditSelectedGroup(''); setError(null); }} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.78rem', fontWeight: '500', color: isDarkMode ? '#9ca3af' : '#6b7280', background: 'none', border: 'none', cursor: 'pointer', padding: '0.2rem 0.4rem', borderRadius: '4px' }}
                          onMouseEnter={(e) => e.currentTarget.style.color = '#dc2626'}
                          onMouseLeave={(e) => e.currentTarget.style.color = isDarkMode ? '#9ca3af' : '#6b7280'}
                        >
                          <i className="fas fa-arrow-left" style={{ fontSize: '0.65rem' }}></i> Change type
                        </button>
                      </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                      {[
                        { value: 'read_only', label: 'Read-Only', desc: 'List vendors, read vendor scores & reports', scopes: ['vendors:list', 'vendors:read', 'reports:read'] },
                        { value: 'admin',     label: 'Admin',     desc: 'Full access — all operations (excludes webhook)', scopes: operationalScopes.map(s => s.key) },
                      ].map(({ value, label, desc, scopes }) => (
                        <div key={value} onClick={() => setEditSelectedGroup(value)} style={{
                          padding: '1rem', borderRadius: '8px', cursor: 'pointer',
                          border: `2px solid ${editSelectedGroup === value ? '#dc2626' : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                          backgroundColor: editSelectedGroup === value ? (isDarkMode ? 'rgba(220,38,38,0.1)' : '#fff1f2') : (isDarkMode ? 'var(--bg-primary)' : '#f9fafb'),
                          transition: 'border-color 0.15s'
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <div style={{ width: '14px', height: '14px', borderRadius: '50%', flexShrink: 0, border: `2px solid ${editSelectedGroup === value ? '#dc2626' : '#9ca3af'}`, backgroundColor: editSelectedGroup === value ? '#dc2626' : 'transparent' }} />
                            <span style={{ fontWeight: '600', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>{label}</span>
                          </div>
                          <p style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', margin: '0 0 0.6rem' }}>{desc}</p>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                            {scopes.map(scope => (
                              <span key={scope} style={{ fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: '600', padding: '0.15rem 0.45rem', borderRadius: '4px', backgroundColor: isDarkMode ? 'rgba(255,255,255,0.08)' : '#f3f4f6', color: isDarkMode ? '#d1d5db' : '#374151', border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.12)' : '#e5e7eb'}` }}>
                                {scope}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  )}

                  {/* Step 2b: Fine-grained scope checklist — replaces type picker when Fine-grained chosen */}
                  {editPermissionMode === 'finegrained' && (
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                        <span style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                          {editSelectedScopes.length} scope{editSelectedScopes.length !== 1 ? 's' : ''} selected
                        </span>
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                          <button type="button" onClick={() => { setEditPermissionMode(''); setEditSelectedScopes([]); setError(null); }} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.78rem', fontWeight: '500', color: isDarkMode ? '#9ca3af' : '#6b7280', background: 'none', border: 'none', cursor: 'pointer', padding: '0.2rem 0.4rem', borderRadius: '4px' }}
                            onMouseEnter={(e) => e.currentTarget.style.color = '#dc2626'}
                            onMouseLeave={(e) => e.currentTarget.style.color = isDarkMode ? '#9ca3af' : '#6b7280'}
                          >
                            <i className="fas fa-arrow-left" style={{ fontSize: '0.65rem' }}></i> Change type
                          </button>
                          {editSelectedScopes.length > 0 && (
                            <button type="button" onClick={() => setEditSelectedScopes([])} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', padding: '0.35rem 0.75rem', fontSize: '0.78rem', fontWeight: '600', color: '#dc2626', backgroundColor: isDarkMode ? 'rgba(220,38,38,0.12)' : '#fff1f2', border: `1px solid ${isDarkMode ? 'rgba(220,38,38,0.35)' : '#fca5a5'}`, borderRadius: '6px', cursor: 'pointer' }}>
                              <i className="fas fa-times" style={{ fontSize: '0.65rem' }}></i> Clear all
                            </button>
                          )}
                        </div>
                      </div>
                      <div style={{ border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, borderRadius: '8px', overflow: 'hidden' }}>
                        {availableScopes.map((scope, i) => {
                          const webhookLocked = editSelectedScopes.includes(WEBHOOK_SCOPE) && scope.key !== WEBHOOK_SCOPE;
                          const otherScopesLocked = editSelectedScopes.some(s => s !== WEBHOOK_SCOPE) && scope.key === WEBHOOK_SCOPE;
                          const disabled = webhookLocked || otherScopesLocked;
                          return (
                          <div key={scope.key} onClick={() => !disabled && toggleEditScope(scope.key)} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 1rem', cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.45 : 1, borderTop: i > 0 ? `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` : 'none', backgroundColor: editSelectedScopes.includes(scope.key) ? (isDarkMode ? 'rgba(220,38,38,0.07)' : '#fff1f2') : 'transparent', transition: 'background-color 0.1s' }}>
                            <div style={{ width: '16px', height: '16px', borderRadius: '4px', flexShrink: 0, border: `2px solid ${editSelectedScopes.includes(scope.key) ? '#dc2626' : (isDarkMode ? '#6b7280' : '#d1d5db')}`, backgroundColor: editSelectedScopes.includes(scope.key) ? '#dc2626' : 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                              {editSelectedScopes.includes(scope.key) && <svg width="10" height="8" viewBox="0 0 10 8" fill="none"><path d="M1 4L3.5 6.5L9 1" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                            </div>
                            <div>
                              <span style={{ fontSize: '0.875rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#111827', fontFamily: 'monospace' }}>{scope.key}</span>
                              <span style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', marginLeft: '0.5rem' }}>— {scope.description}</span>
                            </div>
                          </div>
                        );})}
                      </div>
                    </div>
                  )}

                  {/* Access Type */}
                  <div>
                    <label style={{ display: 'block', fontSize: '0.9375rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#374151', marginBottom: '0.75rem' }}>
                      Access Type: <span style={{ color: '#ef4444' }}>*</span>
                    </label>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                      {([
                        { value: 'temporary' as const, label: 'Temporary', desc: 'Expires after a set number of days' },
                        { value: 'permanent' as const, label: 'Permanent', desc: 'Never expires' },
                      ]).map(({ value, label, desc }) => (
                        <div key={value} onClick={() => setEditAccessType(value)} style={{
                          padding: '1rem', borderRadius: '8px', cursor: 'pointer',
                          border: `2px solid ${editAccessType === value ? '#dc2626' : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                          backgroundColor: editAccessType === value ? (isDarkMode ? 'rgba(220,38,38,0.1)' : '#fff1f2') : (isDarkMode ? 'var(--bg-primary)' : '#f9fafb'),
                          transition: 'border-color 0.15s'
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                            <div style={{ width: '14px', height: '14px', borderRadius: '50%', flexShrink: 0, border: `2px solid ${editAccessType === value ? '#dc2626' : '#9ca3af'}`, backgroundColor: editAccessType === value ? '#dc2626' : 'transparent' }} />
                            <span style={{ fontWeight: '600', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-primary)' : '#111827' }}>{label}</span>
                          </div>
                          <p style={{ fontSize: '0.8rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', margin: 0 }}>{desc}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Expiry Days */}
                  {editAccessType === 'temporary' && (
                    <div>
                      <label style={{ display: 'block', fontSize: '0.9375rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#374151', marginBottom: '0.75rem' }}>
                        Expiry Days: <span style={{ color: '#ef4444' }}>*</span>
                      </label>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
                        {[30, 90, 180].map((days) => (
                          <button key={days} type="button" onClick={() => setEditExpiryDays(days)} style={{
                            padding: '0.6rem 0', borderRadius: '8px',
                            border: `2px solid ${editExpiryDays === days ? '#dc2626' : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                            backgroundColor: editExpiryDays === days ? (isDarkMode ? 'rgba(220,38,38,0.12)' : '#fff1f2') : (isDarkMode ? 'var(--bg-primary)' : '#f9fafb'),
                            color: editExpiryDays === days ? '#dc2626' : (isDarkMode ? 'var(--text-secondary)' : '#6b7280'),
                            fontWeight: '600', fontSize: '0.875rem', cursor: 'pointer'
                          }}>{days} days</button>
                        ))}
                      </div>
                      <input
                        type="number"
                        value={editExpiryDays}
                        min={1}
                        onChange={(e) => setEditExpiryDays(Math.max(1, parseInt(e.target.value) || 1))}
                        style={{
                          width: '100%', padding: '0.625rem 0.875rem', fontSize: '0.9375rem',
                          border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`,
                          borderRadius: '6px', outline: 'none',
                          backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
                          color: isDarkMode ? 'var(--text-primary)' : '#111827', boxSizing: 'border-box'
                        }}
                        onFocus={(e) => e.target.style.borderColor = '#dc2626'}
                        onBlur={(e) => e.target.style.borderColor = isDarkMode ? 'var(--border-color)' : '#d1d5db'}
                      />
                    </div>
                  )}

                </div>

                {/* Buttons */}
                <div style={{ marginTop: '2rem', display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
                  <button
                    onClick={() => { setShowEditModal(false); setEditingKey(null); setError(null); }}
                    style={{
                      padding: '0.625rem 1.5rem', fontSize: '0.9375rem', fontWeight: '500',
                      color: isDarkMode ? '#e5e7eb' : '#374151',
                      backgroundColor: isDarkMode ? '#374151' : '#f3f4f6',
                      border: 'none', borderRadius: '6px', cursor: 'pointer'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#4b5563' : '#e5e7eb'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = isDarkMode ? '#374151' : '#f3f4f6'}
                  >Cancel</button>
                  <button
                    onClick={handleUpdateAPIKey}
                    style={{
                      padding: '0.625rem 1.5rem', fontSize: '0.9375rem', fontWeight: '500',
                      color: 'white', backgroundColor: '#dc2626',
                      border: 'none', borderRadius: '6px', cursor: 'pointer'
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#b91c1c'}
                    onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#dc2626'}
                  >Save Changes</button>
                </div>
              </div>
            </div>
          </div>
        )}

      </div>
    </Layout>
  );
};

export default SettingsPage;

