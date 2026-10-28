'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Layout from '../../components/Layout';
import { apiRequest } from '../../lib/api-client';
import { PermissionGate, usePermission } from '../../lib/rbac';
import { formatLocalDateTime, formatTimeAgo } from '../../lib/date-utils';
import { describeAuditLog, toneStyle } from '../../lib/audit-format';

interface AuditLog {
  id: number;
  user_id?: string;
  user_name?: string;
  user_email?: string;
  user_role?: string;
  action?: string;
  resource_type?: string;
  resource_id?: string;
  details?: any;
  ip_address?: string;
  user_agent?: string;
  created_at?: string;
  // API audit log fields
  credential_id?: number;
  key_name?: string;
  client_ip?: string;
  timestamp?: string;
  response_code?: number;
  success?: boolean;
  endpoint_path?: string;
  http_method?: string;
  request_summary?: string;
  request_data?: any;
}

interface AuditStats {
  total_logs: number;
  actions_breakdown: Record<string, number>;
  resource_types_breakdown: Record<string, number>;
}

const AuditLogsPage = () => {
  const router = useRouter();
  const canViewAuditLogs = usePermission('view_audit_logs');
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [logType, setLogType] = useState<'dashboard' | 'api'>('dashboard'); // Toggle between dashboard and API logs

  useEffect(() => {
    if (!canViewAuditLogs) {
      router.replace('/');
    }
  }, [canViewAuditLogs, router]);

  // Filter states
  const [actionFilter, setActionFilter] = useState('');
  const [resourceTypeFilter, setResourceTypeFilter] = useState('');
  const [daysBack, setDaysBack] = useState(30);
  const [userNameFilter, setUserNameFilter] = useState('');

  // API logs filter states
  const [keyNameFilter, setKeyNameFilter] = useState('');
  const [endpointFilter, setEndpointFilter] = useState('');
  const [methodFilter, setMethodFilter] = useState('');
  const [successFilter, setSuccessFilter] = useState('');

  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [totalLogs, setTotalLogs] = useState(0);
  const logsPerPage = 50;

  // Expanded log details state
  const [expandedLogIds, setExpandedLogIds] = useState<Set<number>>(new Set());

  const fetchLogs = async (page: number = 1, append: boolean = false) => {
    try {
      if (!append) setLoading(true);
      setError(null);

      const params = new URLSearchParams({
        limit: logsPerPage.toString(),
        offset: ((page - 1) * logsPerPage).toString(),
        days_back: daysBack.toString(),
        _t: Date.now().toString() // Cache busting
      });

      let endpoint = '/api/audit-logs';

      if (logType === 'dashboard') {
        if (actionFilter) params.append('action_filter', actionFilter);
        if (resourceTypeFilter) params.append('resource_type_filter', resourceTypeFilter);
        if (userNameFilter) params.append('user_name_filter', userNameFilter);
      } else {
        endpoint = '/api/api-audit-logs';
        if (keyNameFilter) params.append('key_name', keyNameFilter);
        if (endpointFilter) params.append('endpoint_filter', endpointFilter);
        if (methodFilter) params.append('method_filter', methodFilter);
        if (successFilter) params.append('success_filter', successFilter);
      }

      const response = await apiRequest(`${endpoint}?${params.toString()}`);
      const data = await response.json();

      // Ensure data has the expected structure
      const logs = data?.logs || [];
      const total = data?.total || 0;

      if (append) {
        setLogs(prev => [...prev, ...logs]);
      } else {
        setLogs(logs);
      }

      setTotalLogs(total);
      setHasMore(logs.length === logsPerPage);

    } catch (err: any) {
      setError(err.message || 'Failed to fetch audit logs');
      console.error('Error fetching audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const params = new URLSearchParams({
        days_back: daysBack.toString()
      });

      const endpoint = logType === 'dashboard' ? '/api/audit-logs/stats' : '/api/api-audit-logs/stats';
      const response = await apiRequest(`${endpoint}?${params.toString()}`);
      const data = await response.json();

      // Ensure stats has the expected structure with fallbacks
      if (logType === 'dashboard') {
        setStats({
          total_logs: data?.total_logs || 0,
          actions_breakdown: data?.actions_breakdown || {},
          resource_types_breakdown: data?.resource_types_breakdown || {}
        });
      } else {
        // For API logs, we'll adapt the structure to match the dashboard format
        setStats({
          total_logs: data?.total_requests || 0,
          actions_breakdown: data?.methods_breakdown || {},
          resource_types_breakdown: data?.endpoints_breakdown || {}
        });
      }
    } catch (err: any) {
      console.error('Error fetching audit stats:', err);
    }
  };

  useEffect(() => {
    fetchLogs(1, false);
    fetchStats();
    setCurrentPage(1);
  }, [actionFilter, resourceTypeFilter, daysBack, userNameFilter, keyNameFilter, endpointFilter, methodFilter, successFilter, logType]);

  const loadMore = () => {
    const nextPage = currentPage + 1;
    setCurrentPage(nextPage);
    fetchLogs(nextPage, true);
  };

  const refreshLogs = () => {
    setCurrentPage(1);
    fetchLogs(1, false);
    fetchStats();
  };

  const toggleLogDetails = (logId: number) => {
    setExpandedLogIds(prev => {
      const newSet = new Set(prev);
      if (newSet.has(logId)) {
        newSet.delete(logId);
      } else {
        newSet.add(logId);
      }
      return newSet;
    });
  };

  return (
    <Layout>
      <PermissionGate
        permission="view_audit_logs"
        fallback={
          <div style={{
            textAlign: 'center',
            padding: '4rem 2rem',
            color: 'var(--text-secondary)'
          }}>
            <i className="fas fa-lock" style={{
              fontSize: '4rem',
              color: 'var(--coral)',
              marginBottom: '2rem'
            }}></i>
            <h2 style={{
              fontSize: '1.5rem',
              fontWeight: 'bold',
              marginBottom: '1rem',
              color: 'var(--text-primary)'
            }}>
              Access Denied
            </h2>
            <p style={{ fontSize: '1.1rem', marginBottom: '2rem' }}>
              You don&apos;t have permission to view audit logs.
            </p>
            <p style={{ fontSize: '0.9rem' }}>
              Only Vendiant Administrators can Access Audit Logs.
            </p>
          </div>
        }
      >
        <div className="audit-logs-page">
          {/* Header */}
          <div className="page-header" style={{ marginBottom: '2rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '2rem' }}>
              <div style={{ flex: 1 }}>
                <h1 style={{ fontSize: '2rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
                  <i className="fas fa-clipboard-list" style={{ marginRight: '0.75rem', color: 'var(--coral)' }}></i>
                  Audit Logs
                </h1>

              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexShrink: 0, marginLeft: 'auto' }}>
                {/* Log Type Toggle */}
                <div className="audit-logs-toggle" style={{
                  display: 'flex',
                  borderRadius: '8px',
                  padding: '4px'
                }}>
                  <button
                    onClick={() => setLogType('dashboard')}
                    style={{
                      padding: '8px 16px',
                      borderRadius: '6px',
                      border: 'none',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                      backgroundColor: logType === 'dashboard' ? '#ffffff' : 'transparent',
                      color: logType === 'dashboard' ? '#2563eb' : '#6b7280',
                      boxShadow: logType === 'dashboard' ? '0 1px 2px rgba(0, 0, 0, 0.05)' : 'none'
                    }}
                    className={logType === 'dashboard' ? 'active-toggle-btn' : ''}
                  >
                    Dashboard Logs
                  </button>
                  <button
                    onClick={() => setLogType('api')}
                    style={{
                      padding: '8px 16px',
                      borderRadius: '6px',
                      border: 'none',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                      backgroundColor: logType === 'api' ? '#ffffff' : 'transparent',
                      color: logType === 'api' ? '#2563eb' : '#6b7280',
                      boxShadow: logType === 'api' ? '0 1px 2px rgba(0, 0, 0, 0.05)' : 'none'
                    }}
                    className={logType === 'api' ? 'active-toggle-btn' : ''}
                  >
                    API Logs
                  </button>
                </div>

                <button
                  onClick={refreshLogs}
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <i className="fas fa-refresh"></i>
                  Refresh
                </button>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="widget-card" style={{ marginBottom: '2rem' }}>
            <div className="widget-header">
              <h3><i className="fas fa-filter"></i> Filters</h3>
            </div>
            <div className="widget-content">
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '1rem'
              }}>
                {logType === 'dashboard' ? (
                  <>
                    <div>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>Action</label>
                      <select
                        value={actionFilter}
                        onChange={(e) => setActionFilter(e.target.value)}
                        className="form-control"
                      >
                        <option value="">All Actions</option>
                        <option value="CREATE">CREATE</option>
                        <option value="UPDATE">UPDATE</option>
                        <option value="DELETE">DELETE</option>
                        <option value="EXCLUDE">EXCLUDE</option>
                        <option value="SCAN">SCAN</option>
                        <option value="REVOKED">REVOKED</option>
                        <option value="ACTIVATED">ACTIVATED</option>
                        <option value="ADD VENDORS">ADD VENDORS</option>
                        <option value="REMOVE VENDORS">REMOVE VENDORS</option>
                        <option value="COMPARE">COMPARE</option>
                        <option value="BREACH_MONITOR_QUERY">BREACH_MONITOR QUERY</option>
                        <option value="BREACH_MONITOR_IGNORE_LIST_ADD">BREACH_MONITOR IGNORE LIST ADD</option>
                        <option value="BREACH_MONITOR_IGNORE_LIST_REMOVE">BREACH_MONITOR IGNORE LIST REMOVE</option>
                        <option value="BREACH_MONITOR_BREACH_RESOLVE">BREACH_MONITOR BREACH RESOLVE</option>
                        <option value="BREACH_MONITOR_BREACH_UNRESOLVE">BREACH_MONITOR BREACH UNRESOLVE</option>
                        <option value="BREACH_MONITOR_BREACH_FALSE_POSITIVE">BREACH_MONITOR BREACH FALSE POSITIVE</option>
                        <option value="BREACH_MONITOR_BREACH_FALSE_POSITIVE_REMOVE">BREACH_MONITOR BREACH FALSE POSITIVE REMOVE</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>Resource Type</label>
                      <select
                        value={resourceTypeFilter}
                        onChange={(e) => setResourceTypeFilter(e.target.value)}
                        className="form-control"
                      >
                        <option value="">All Resources</option>
                        <option value="vendor">Vendor</option>
                        <option value="vulnerability">Vulnerability</option>
                        <option value="dns">DNS</option>
                        <option value="network">Network</option>
                        <option value="encryption">Encryption</option>
                        <option value="subdomain_discovery">Subdomain Discovery</option>

                        <option value="certifications">Certifications</option>
                        <option value="breach_check">Breach Check</option>
                        <option value="breach-monitor">Breach Monitor</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>User Name</label>
                      <input
                        type="text"
                        value={userNameFilter}
                        onChange={(e) => setUserNameFilter(e.target.value)}
                        placeholder="Filter by user name..."
                        className="form-control"
                      />
                    </div>
                  </>
                ) : (
                  <>
                    <div>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>Key Name</label>
                      <input
                        type="text"
                        value={keyNameFilter}
                        onChange={(e) => setKeyNameFilter(e.target.value)}
                        placeholder="Filter by API key name..."
                        className="form-control"
                      />
                    </div>

                    <div>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>Endpoint</label>
                      <input
                        type="text"
                        value={endpointFilter}
                        onChange={(e) => setEndpointFilter(e.target.value)}
                        placeholder="Filter by endpoint..."
                        className="form-control"
                      />
                    </div>

                    <div>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>HTTP Method</label>
                      <select
                        value={methodFilter}
                        onChange={(e) => setMethodFilter(e.target.value)}
                        className="form-control"
                      >
                        <option value="">All Methods</option>
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="DELETE">DELETE</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>Status</label>
                      <select
                        value={successFilter}
                        onChange={(e) => setSuccessFilter(e.target.value)}
                        className="form-control"
                      >
                        <option value="">All Status</option>
                        <option value="true">Success</option>
                        <option value="false">Failed</option>
                      </select>
                    </div>
                  </>
                )}

                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>Days Back</label>
                  <select
                    value={daysBack}
                    onChange={(e) => setDaysBack(parseInt(e.target.value))}
                    className="form-control"
                  >
                    <option value={1}>Last 24 hours</option>
                    <option value={7}>Last 7 days</option>
                    <option value={30}>Last 30 days</option>
                    <option value={90}>Last 90 days</option>
                  </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'end' }}>
                  <button
                    onClick={() => {
                      if (logType === 'dashboard') {
                        setActionFilter('');
                        setResourceTypeFilter('');
                        setUserNameFilter('');
                      } else {
                        setKeyNameFilter('');
                        setEndpointFilter('');
                        setMethodFilter('');
                        setSuccessFilter('');
                      }
                      setDaysBack(30);
                    }}
                    className="btn btn-secondary"
                    style={{ width: '100%' }}
                  >
                    Clear Filters
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="widget-card" style={{ marginBottom: '2rem' }}>
            <div className="widget-header">
              <h3>
                <i className="fas fa-list"></i>
                Audit Logs ({totalLogs.toLocaleString()} total)
              </h3>
            </div>
            <div className="widget-content">
              {error && (
                <div className="alert alert-error" style={{ marginBottom: '1rem' }}>
                  <i className="fas fa-exclamation-triangle"></i>
                  {error}
                </div>
              )}

              {loading && logs.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '2rem' }}>
                  <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)' }}></i>
                  <p style={{ marginTop: '1rem' }}>Loading audit logs...</p>
                </div>
              ) : logs.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                  <i className="fas fa-inbox" style={{ fontSize: '3rem', marginBottom: '1rem' }}></i>
                  <p>No audit logs found for the selected filters.</p>
                </div>
              ) : (
                <>
                  <div className="audit-logs-list">
                    {logs.map((log) => {
                      const isExpanded = expandedLogIds.has(log.id);
                      const described = describeAuditLog(log, logType);
                      const badge = toneStyle(described.tone);
                      const actor = logType === 'api'
                        ? (log.key_name || 'Unknown key')
                        : (log.user_name || log.user_email || 'Unknown user');
                      return (
                        <div key={log.id} className="audit-log-item clickable" style={{
                          border: '1px solid var(--border-color)',
                          borderRadius: '8px',
                          padding: '1rem',
                          marginBottom: '0.75rem',
                          backgroundColor: 'var(--bg-primary)',
                          cursor: 'pointer',
                          transition: 'all 0.2s ease'
                        }}
                          onClick={() => toggleLogDetails(log.id)}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              {/* What happened: action badge + plain-language summary */}
                              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.75rem', marginBottom: '0.4rem' }}>
                                <span style={{
                                  padding: '0.2rem 0.6rem',
                                  borderRadius: '999px',
                                  fontSize: '0.75rem',
                                  fontWeight: 600,
                                  letterSpacing: '0.01em',
                                  whiteSpace: 'nowrap',
                                  backgroundColor: badge.bg,
                                  color: badge.fg,
                                  flexShrink: 0
                                }}>
                                  {described.verb}
                                </span>
                                <span className="resource-description" style={{
                                  fontWeight: 600,
                                  fontSize: '0.95rem',
                                  color: 'var(--text-primary)',
                                  wordBreak: 'break-word'
                                }}>
                                  {described.summary}
                                </span>
                              </div>

                              {/* Key details, so the row rarely needs expanding */}
                              {described.facts.length > 0 && (
                                <div style={{
                                  display: 'flex',
                                  flexWrap: 'wrap',
                                  gap: '0.4rem',
                                  marginBottom: '0.5rem'
                                }}>
                                  {described.facts.map((fact) => (
                                    <span
                                      key={`${fact.label}-${fact.value}`}
                                      style={{
                                        display: 'inline-flex',
                                        alignItems: 'baseline',
                                        gap: '0.3rem',
                                        fontSize: '0.78rem',
                                        padding: '0.15rem 0.5rem',
                                        borderRadius: '4px',
                                        border: '1px solid var(--border-color)',
                                        backgroundColor: 'rgba(128, 128, 128, 0.05)',
                                        maxWidth: '100%'
                                      }}
                                    >
                                      <span style={{ color: 'var(--text-secondary)' }}>{fact.label}</span>
                                      <span style={{
                                        color: 'var(--text-primary)',
                                        fontWeight: 500,
                                        fontFamily: fact.mono ? 'monospace' : 'inherit',
                                        wordBreak: 'break-all'
                                      }}>
                                        {fact.value}
                                      </span>
                                    </span>
                                  ))}
                                </div>
                              )}

                              {/* Who, where, when */}
                              <div style={{
                                display: 'flex',
                                alignItems: 'center',
                                flexWrap: 'wrap',
                                gap: '0.4rem 1rem',
                                fontSize: '0.82rem',
                                color: 'var(--text-secondary)'
                              }}>
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                                  <i className={`fas ${logType === 'api' ? 'fa-key' : 'fa-user'}`}></i>
                                  <span style={{ color: 'var(--text-primary)' }}>{actor}</span>
                                  {logType === 'dashboard' && log.user_role && (
                                    <span style={{
                                      fontSize: '0.72rem',
                                      textTransform: 'uppercase',
                                      letterSpacing: '0.03em',
                                      backgroundColor: 'rgba(128, 128, 128, 0.12)',
                                      padding: '0.1rem 0.4rem',
                                      borderRadius: '3px'
                                    }}>
                                      {log.user_role}
                                    </span>
                                  )}
                                </span>
                                {logType === 'api' && (
                                  <span style={{
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '0.35rem',
                                    color: log.success === false ? '#b91c1c' : '#15803d',
                                    fontWeight: 500
                                  }}>
                                    <i className={`fas ${log.success === false ? 'fa-circle-xmark' : 'fa-circle-check'}`}></i>
                                    {log.success === false ? 'Failed' : 'Success'}
                                  </span>
                                )}
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                                  <i className="fas fa-globe"></i>
                                  <span style={{ fontFamily: 'monospace' }}>{(log.client_ip || log.ip_address) || 'Unknown IP'}</span>
                                </span>
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                                  <i className="fas fa-clock"></i>
                                  {formatTimeAgo(log.timestamp || log.created_at || '')}
                                </span>
                              </div>
                            </div>

                            {/* Exact time + expand affordance */}
                            <div style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.6rem',
                              flexShrink: 0,
                              fontSize: '0.8rem',
                              color: 'var(--text-secondary)',
                              whiteSpace: 'nowrap'
                            }}>
                              {formatLocalDateTime(log.timestamp || log.created_at)}
                              <i className={`fas fa-chevron-${isExpanded ? 'up' : 'down'}`} style={{ fontSize: '0.75rem' }}></i>
                            </div>
                          </div>

                          {/* Expanded Details */}
                          {isExpanded && (
                            <div style={{
                              marginTop: '1rem',
                              paddingTop: '1rem',
                              borderTop: '1px solid var(--border-color)',
                              backgroundColor: 'transparent'
                            }}>
                              <h4 style={{
                                fontSize: '0.9rem',
                                fontWeight: '600',
                                marginBottom: '1rem',
                                color: 'var(--text-primary)'
                              }}>
                                Additional Details
                              </h4>

                              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
                                {/* User Details */}
                                <div>
                                  <h5 style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                                    {logType === 'api' ? 'API Key Information' : 'User Information'}
                                  </h5>
                                  <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                                    {logType === 'api' ? (
                                      <>
                                        <div><strong>Key Name:</strong> {log.key_name || 'N/A'}</div>
                                        <div><strong>Credential ID:</strong> {log.credential_id || 'N/A'}</div>
                                      </>
                                    ) : (
                                      <>
                                        <div><strong>ID:</strong> {log.user_id}</div>
                                        <div><strong>Name:</strong> {log.user_name || 'N/A'}</div>
                                        <div><strong>Email:</strong> {log.user_email}</div>
                                        <div><strong>Role:</strong> {log.user_role}</div>
                                        {/* Show API key name for API key operations */}
                                        {log.resource_type === 'API Key' && log.details?.api_key_name && (
                                          <div><strong>API Key Name:</strong> {log.details.api_key_name}</div>
                                        )}
                                      </>
                                    )}
                                  </div>
                                </div>

                                {/* Resource Details */}
                                <div>
                                  <h5 style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                                    {logType === 'api' ? 'Request Information' : 'Resource Information'}
                                  </h5>
                                  <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                                    {logType === 'api' ? (
                                      <>
                                        <div><strong>Method:</strong> {log.http_method || 'N/A'}</div>
                                        <div><strong>Endpoint:</strong> {log.endpoint_path || 'N/A'}</div>
                                        <div><strong>Response Code:</strong> {log.response_code || 'N/A'}</div>
                                        <div><strong>Success:</strong> {log.success ? 'Yes' : 'No'}</div>
                                      </>
                                    ) : (
                                      <>
                                        {/* Raw stored values, kept verbatim so the trail stays auditable */}
                                        <div><strong>Recorded action:</strong> {log.action || 'N/A'}</div>
                                        <div><strong>Recorded resource type:</strong> {log.resource_type || 'not recorded'}</div>
                                        {log.resource_id && (
                                          <div style={{ wordBreak: 'break-all' }}><strong>Resource ID:</strong> {log.resource_id}</div>
                                        )}
                                        {log.details?.endpoint && (
                                          <div style={{ wordBreak: 'break-all' }}>
                                            <strong>Endpoint:</strong> {log.details.method ? `${log.details.method} ` : ''}{log.details.endpoint}
                                          </div>
                                        )}
                                      </>
                                    )}
                                  </div>
                                </div>

                                {/* Technical Details */}
                                <div style={{ gridColumn: 'span 1' }}>
                                  <h5 style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                                    Technical Information
                                  </h5>
                                  <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                                    <div style={{ marginBottom: '0.5rem' }}><strong>IP Address:</strong> {(log.client_ip || log.ip_address) || 'Unknown'}</div>
                                    <div style={{ marginBottom: '0.5rem' }}>
                                      <strong>User Agent:</strong>
                                      {log.user_agent ? (
                                        <span style={{
                                          display: 'inline-block',
                                          marginTop: '0.25rem',
                                          marginLeft: '0.5rem',
                                          padding: '0.25rem 0.5rem',
                                          backgroundColor: 'rgba(128, 128, 128, 0.05)',
                                          border: '1px solid var(--border-color)',
                                          borderRadius: '4px',
                                          wordBreak: 'break-word',
                                          fontSize: '0.75rem',
                                          color: 'var(--text-secondary)',
                                          fontFamily: 'monospace',
                                          lineHeight: '1.3',
                                          maxWidth: '100%'
                                        }}>
                                          {log.user_agent}
                                        </span>
                                      ) : (
                                        <span style={{ color: 'var(--text-secondary)' }}> Unknown</span>
                                      )}
                                    </div>
                                    <div><strong>Timestamp:</strong> {formatLocalDateTime(log.timestamp || log.created_at)}</div>
                                  </div>
                                </div>
                              </div>

                              {/* Additional Details JSON */}
                              {((logType === 'dashboard' && log.details && Object.keys(log.details).length > 0) ||
                                (logType === 'api' && log.request_data && Object.keys(log.request_data).length > 0)) && (
                                  <div style={{ marginTop: '1rem' }}>
                                    <h5 style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                                      {logType === 'api' ? 'Request Data' : 'Additional Context'}
                                    </h5>
                                    <pre style={{
                                      fontSize: '0.75rem',
                                      backgroundColor: 'transparent',
                                      border: '1px solid var(--border-color)',
                                      borderRadius: '4px',
                                      padding: '0.75rem',
                                      overflow: 'auto',
                                      maxHeight: '200px',
                                      color: 'var(--text-primary)',
                                      whiteSpace: 'pre-wrap',
                                      wordBreak: 'break-word'
                                    }}>
                                      {JSON.stringify(logType === 'api' ? log.request_data : log.details, null, 2)}
                                    </pre>
                                  </div>
                                )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* Load More Button */}
                  {hasMore && (
                    <div style={{ textAlign: 'center', marginTop: '2rem' }}>
                      <button
                        onClick={loadMore}
                        disabled={loading}
                        className="btn btn-secondary"
                        style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: '0 auto' }}
                      >
                        {loading ? (
                          <>
                            <i className="fas fa-spinner fa-spin"></i>
                            Loading...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-chevron-down"></i>
                            Load More ({Math.min(logsPerPage, totalLogs - logs.length)} more)
                          </>
                        )}
                      </button>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      </PermissionGate>
    </Layout>
  );
};

export default AuditLogsPage;
