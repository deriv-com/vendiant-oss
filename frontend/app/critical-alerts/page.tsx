'use client';

import React, { useState, useEffect } from 'react';
import Layout from '../../components/Layout';
import styles from './CriticalAlertsPage.module.css';

interface CriticalAlert {
  id: string;
  vendor_name: string;
  vendor_id: number;
  domain: string;
  subdomain: string;
  severity: string;
  vulnerability: string;
  description: string;
  scan_type: string;
  detected_at: string;
  category: string;
  source_url?: string;
  event_type?: string;
}

interface SubdomainDetail {
  subdomain: string;
  is_main_domain: boolean;
  severity_counts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  critical_vulnerabilities: Array<{
    title: string;
    description: string;
    category: string;
    detected_at: string;
  }>;
  total_vulnerabilities: number;
}

const CriticalAlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<CriticalAlert[]>([]);
  const [filteredAlerts, setFilteredAlerts] = useState<CriticalAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedScanType, setSelectedScanType] = useState('All');
  const [selectedVendor, setSelectedVendor] = useState('All');
  const [showSubdomainDetails, setShowSubdomainDetails] = useState(false);
  const [selectedVendorId, setSelectedVendorId] = useState<number | null>(null);
  const [selectedVendorName, setSelectedVendorName] = useState<string>('');
  const [subdomainDetails, setSubdomainDetails] = useState<SubdomainDetail[]>([]);
  const [subdomainLoading, setSubdomainLoading] = useState(false);
  const [subdomainError, setSubdomainError] = useState<string | null>(null);

  // Fetch critical alerts
  const fetchCriticalAlerts = async () => {
    setLoading(true);
    setError(null);
    
    try {
      console.log('Fetching critical alerts...');
      const response = await fetch('/api/critical-alerts');
      console.log('Response status:', response.status);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('Response data:', data);
      
      if (data.success) {
        setAlerts(data.critical_alerts);
        setFilteredAlerts(data.critical_alerts);
        console.log(`Loaded ${data.critical_alerts.length} critical alerts`);
      } else {
        setError(data.error || 'Failed to fetch critical alerts');
      }
    } catch (err) {
      console.error('Error fetching critical alerts:', err);
      setError(`Error fetching critical alerts: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  // Fetch subdomain details for a vendor
  const fetchSubdomainDetails = async (vendorId: number, vendorName: string) => {
    setSubdomainLoading(true);
    setSubdomainError(null);
    
    try {
      const response = await fetch(`/api/critical-alerts/subdomain-details/${vendorId}`);
      const data = await response.json();
      
      if (data.success) {
        setSubdomainDetails(data.subdomain_details);
        setSelectedVendorId(vendorId);
        setSelectedVendorName(vendorName);
        setShowSubdomainDetails(true);
      } else {
        setSubdomainError(data.error || 'Failed to fetch subdomain details');
      }
    } catch (err) {
      setSubdomainError('Error fetching subdomain details');
      console.error('Error:', err);
    } finally {
      setSubdomainLoading(false);
    }
  };

  // Filter alerts based on search and filters
  useEffect(() => {
    let filtered = alerts;

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(alert =>
        alert.vendor_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.vulnerability.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.subdomain.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.scan_type.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Scan type filter
    if (selectedScanType !== 'All') {
      filtered = filtered.filter(alert => alert.scan_type === selectedScanType);
    }

    // Vendor filter
    if (selectedVendor !== 'All') {
      filtered = filtered.filter(alert => alert.vendor_name === selectedVendor);
    }

    setFilteredAlerts(filtered);
  }, [alerts, searchTerm, selectedScanType, selectedVendor]);

  // Load alerts when component mounts
  useEffect(() => {
    fetchCriticalAlerts();
  }, []);

  // Get unique values for filters
  const uniqueScanTypes = Array.from(new Set(alerts.map(alert => alert.scan_type)));
  const uniqueVendors = Array.from(new Set(alerts.map(alert => alert.vendor_name)));

  // Format date
  const formatDate = (dateString: string, scanType?: string) => {
    if (!dateString) return 'Unknown';
    try {
      const date = new Date(dateString);
      
      // For low security score alerts, use the specific format: Sep 4, 2025, 04:49 PM
      if (scanType === 'Overall Security Score') {
        return date.toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          hour12: true
        });
      }
      
      // For other alerts, use the existing format
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return 'Unknown';
    }
  };

  // Get severity badge class
  const getSeverityClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return styles.severityCritical;
      case 'HIGH': return styles.severityHigh;
      case 'MEDIUM': return styles.severityMedium;
      case 'LOW': return styles.severityLow;
      default: return styles.severityInfo;
    }
  };

  return (
    <Layout activeSection="critical-alerts">
      <div className={styles.pageContainer}>
        <div className={styles.pageHeader}>
          <div className={styles.headerLeft}>
            <h1>
              <i className="fas fa-exclamation-triangle"></i>
              Security Alerts
            </h1>
            <p className={styles.pageDescription}>
              Critical Security Alerts, Low-scoring Domains & Critical Security Incidents
            </p>
          </div>
          <div className={styles.headerStats}>
            <div className={styles.statCard}>
              <div className={styles.statNumber}>{filteredAlerts.filter(alert => alert.scan_type !== 'Overall Security Score').length}</div>
              <div className={styles.statLabel}>Critical Issues</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statNumber}>{filteredAlerts.filter(alert => alert.scan_type === 'Overall Security Score').length}</div>
              <div className={styles.statLabel}>Low Scores</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statNumber}>{uniqueVendors.length}</div>
              <div className={styles.statLabel}>Affected Vendors</div>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className={styles.filtersSection}>
          <div className={styles.searchBox}>
            <i className="fas fa-search"></i>
            <input
              type="text"
              placeholder="Search critical alerts..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          
          <select
            value={selectedScanType}
            onChange={(e) => setSelectedScanType(e.target.value)}
            className={styles.filterSelect}
          >
            <option value="All">All Alerts</option>
            {uniqueScanTypes.map(type => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>

          <select
            value={selectedVendor}
            onChange={(e) => setSelectedVendor(e.target.value)}
            className={styles.filterSelect}
          >
            <option value="All">All Vendors</option>
            {uniqueVendors.map(vendor => (
              <option key={vendor} value={vendor}>{vendor}</option>
            ))}
          </select>

          <button 
            className={styles.refreshButton}
            onClick={fetchCriticalAlerts}
            disabled={loading}
          >
            <i className="fas fa-sync-alt"></i>
            Refresh Data
          </button>
        </div>

        {/* Content */}
        <div className={styles.contentSection}>
          {loading ? (
            <div className={styles.loading}>
              <i className="fas fa-spinner fa-spin"></i>
                              <h3>Loading Critical Alerts...</h3>
                <p>Scanning for critical vulnerabilities and low-scoring domains across all vendors</p>
            </div>
          ) : error ? (
                          <div className={styles.error}>
                <i className="fas fa-exclamation-circle"></i>
                <h3>Error Loading Alerts</h3>
                <p>{error}</p>
              </div>
          ) : filteredAlerts.length === 0 ? (
            <div className={styles.noAlerts}>
              <i className="fas fa-shield-alt"></i>
                              <h3>No Critical Alerts Found</h3>
                <p>Excellent! No critical vulnerabilities or low-scoring domains (below 600) detected across all monitored vendors.</p>
              <div className={styles.noAlertsActions}>
                <button onClick={fetchCriticalAlerts} className={styles.refreshButton}>
                  <i className="fas fa-sync-alt"></i>
                  Refresh Check
                </button>
              </div>
            </div>
          ) : (
            <div className={styles.alertsGrid}>
              {filteredAlerts.map((alert) => (
                <div key={alert.id} className={`${styles.alertCard} ${
                  alert.scan_type === 'Security Incident' ? styles.incidentAlert : ''
                }`}>
                  <div className={styles.alertCardHeader}>
                    <div className={styles.vendorInfo}>
                      <h3 className={styles.vendorName}>{alert.vendor_name}</h3>
                      <span className={styles.domainName}>{alert.domain}</span>
                    </div>
                    <div className={styles.alertMeta}>
                      <span className={`${styles.severityBadge} ${getSeverityClass(alert.severity)}`}>
                        <i className="fas fa-exclamation-triangle"></i>
                        {alert.severity}
                      </span>
                                              <span className={`${styles.scanTypeBadge} ${
                          alert.scan_type === 'Overall Security Score' ? styles.securityScore : 
                          alert.scan_type === 'Security Incident' ? styles.securityIncident : ''
                        }`}>
                          {alert.scan_type}
                        </span>
                    </div>
                  </div>
                  
                  <div className={styles.alertCardBody}>
                                          <h4 className={styles.vulnerabilityTitle}>
                        {alert.scan_type === 'Overall Security Score' && (
                          <i className="fas fa-chart-line" style={{ marginRight: '8px', color: '#dc3545' }}></i>
                        )}
                                                 {alert.scan_type === 'Security Incident' && (
                           <i className="fas fa-exclamation-circle" style={{ marginRight: '8px', color: '#dc3545' }}></i>
                         )}
                        {alert.vulnerability}
                      </h4>
                    {alert.description && (
                      <p className={styles.vulnerabilityDescription}>{alert.description}</p>
                    )}
                    
                    <div className={styles.alertDetails}>
                      <div className={styles.detailItem}>
                        <i className="fas fa-globe"></i>
                        <span>Affected: {alert.subdomain}</span>
                      </div>
                      <div className={styles.detailItem}>
                        <i className="fas fa-clock"></i>
                        <span>
                                                     {alert.scan_type === 'Overall Security Score' ? 'Last Scanned: ' : 
                            alert.scan_type === 'Security Incident' ? 'Occurred: ' : 'Detected: '}
                          {formatDate(alert.detected_at, alert.scan_type)}
                        </span>
                      </div>
                      {alert.source_url && (
                        <div className={styles.detailItem}>
                          <i className="fas fa-external-link-alt"></i>
                          <a href={alert.source_url} target="_blank" rel="noopener noreferrer" style={{ color: '#dc3545', textDecoration: 'none' }}>
                            View Source
                          </a>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  {/* Only show View Critical Subdomains button for vulnerability alerts, not low score alerts or incidents */}
                  {alert.scan_type !== 'Overall Security Score' && 
                   alert.scan_type !== 'Security Incident' && (
                    <div className={styles.alertCardFooter}>
                      <button
                        className={styles.viewDetailsButton}
                        onClick={() => fetchSubdomainDetails(alert.vendor_id, alert.vendor_name)}
                        disabled={subdomainLoading}
                      >
                        <i className="fas fa-exclamation-triangle"></i>
                        View Critical Subdomains
                      </button>
                    </div>
                  )}
                  
                  {/* For incidents, show a different footer with source link if available */}
                  {alert.scan_type === 'Security Incident' && alert.source_url && (
                    <div className={styles.alertCardFooter}>
                      <a 
                        href={alert.source_url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className={styles.viewDetailsButton}
                        style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                      >
                        <i className="fas fa-external-link-alt"></i>
                        Read Full Article
                      </a>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Subdomain Details Modal */}
        {showSubdomainDetails && (
          <div className={styles.modalOverlay} onClick={() => setShowSubdomainDetails(false)}>
            <div className={styles.modalContent} onClick={(e) => e.stopPropagation()}>
              <div className={styles.modalHeader}>
                <div className={styles.modalHeaderInfo}>
                  <h2>
                    <i className="fas fa-exclamation-triangle"></i>
                    Critical Subdomains Analysis
                  </h2>
                  <p>Subdomains with <strong>CRITICAL</strong> vulnerabilities for <strong>{selectedVendorName}</strong></p>
                </div>
                <button 
                  className={styles.modalCloseButton}
                  onClick={() => setShowSubdomainDetails(false)}
                >
                  <i className="fas fa-times"></i>
                </button>
              </div>

              <div className={styles.modalBody}>
                {subdomainLoading ? (
                  <div className={styles.loading}>
                    <i className="fas fa-spinner fa-spin"></i>
                    <h3>Analyzing Subdomains...</h3>
                    <p>Loading detailed vulnerability breakdown</p>
                  </div>
                ) : subdomainError ? (
                  <div className={styles.error}>
                    <i className="fas fa-exclamation-circle"></i>
                    <h3>Error Loading Subdomain Details</h3>
                    <p>{subdomainError}</p>
                  </div>
                ) : subdomainDetails.length === 0 ? (
                  <div className={styles.noAlerts}>
                    <i className="fas fa-shield-alt"></i>
                    <h3>No Critical Subdomains Found</h3>
                    <p>No subdomains have critical vulnerabilities for <strong>{selectedVendorName}</strong></p>
                  </div>
                ) : (
                  <div className={styles.subdomainGrid}>
                    {subdomainDetails.map((detail, index) => (
                      <div key={index} className={styles.subdomainCard}>
                        <div className={styles.subdomainCardHeader}>
                          <div className={styles.subdomainInfo}>
                            <div className={styles.subdomainName}>
                              <i className={`fas ${detail.is_main_domain ? 'fa-home' : 'fa-sitemap'}`}></i>
                              <strong>{detail.subdomain}</strong>
                              {detail.is_main_domain && (
                                <span className={styles.mainDomainBadge}>Primary Domain</span>
                              )}
                            </div>
                            <div className={styles.subdomainStats}>
                              <span className={styles.totalCount}>
                                {detail.total_vulnerabilities} Total Issues
                              </span>
                            </div>
                          </div>
                        </div>

                        <div className={styles.severityBreakdown}>
                          {detail.severity_counts.CRITICAL > 0 && (
                            <div className={`${styles.severityItem} ${styles.severityCritical}`}>
                              <span className={styles.severityCount}>{detail.severity_counts.CRITICAL}</span>
                              <span className={styles.severityLabel}>Critical</span>
                            </div>
                          )}
                          {detail.severity_counts.HIGH > 0 && (
                            <div className={`${styles.severityItem} ${styles.severityHigh}`}>
                              <span className={styles.severityCount}>{detail.severity_counts.HIGH}</span>
                              <span className={styles.severityLabel}>High</span>
                            </div>
                          )}
                          {detail.severity_counts.MEDIUM > 0 && (
                            <div className={`${styles.severityItem} ${styles.severityMedium}`}>
                              <span className={styles.severityCount}>{detail.severity_counts.MEDIUM}</span>
                              <span className={styles.severityLabel}>Medium</span>
                            </div>
                          )}
                          {detail.severity_counts.LOW > 0 && (
                            <div className={`${styles.severityItem} ${styles.severityLow}`}>
                              <span className={styles.severityCount}>{detail.severity_counts.LOW}</span>
                              <span className={styles.severityLabel}>Low</span>
                            </div>
                          )}
                        </div>

                        {detail.critical_vulnerabilities.length > 0 && (
                          <div className={styles.criticalVulnsList}>
                            <h5>
                              <i className="fas fa-exclamation-triangle"></i>
                              Critical Vulnerabilities ({detail.critical_vulnerabilities.length})
                            </h5>
                            <div className={styles.vulnList}>
                              {detail.critical_vulnerabilities.map((vuln, vIndex) => (
                                <div key={vIndex} className={styles.vulnItem}>
                                  <div className={styles.vulnHeader}>
                                    <span className={styles.vulnTitle}>{vuln.title}</span>
                                    <span className={styles.vulnCategory}>{vuln.category}</span>
                                  </div>
                                  {vuln.description && (
                                    <p className={styles.vulnDescription}>{vuln.description}</p>
                                  )}
                                  <div className={styles.vulnFooter}>
                                    <span className={styles.vulnDate}>
                                      <i className="fas fa-clock"></i>
                                      {formatDate(vuln.detected_at)}
                                    </span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default CriticalAlertsPage; 