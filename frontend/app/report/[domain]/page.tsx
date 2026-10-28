'use client';

import React, { useState, useEffect } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';
import { reportApi, subdomainApi, vendorApi, backgroundScanApi, BackgroundScanJob, certificationApi } from '../../../lib/api';
import { PermissionGate, useIsAdmin, usePermission } from '../../../lib/rbac';
import AIInsights from '../../../components/AIInsights';
import ScoreTimelineChart from '../../../components/ScoreTimelineChart';
import { logUserAction } from '../../../lib/api-client';

interface VulnerabilityReport {
  status: string;
  domain: string;
  vendor: {
    id: number;
    name: string;
    domain: string;
    overall_score: number;
    grade: string;
    last_scanned?: string;
    tier?: string;
    certifications?: {
      iso_27001: boolean;
      soc2: boolean;
      has_certifications: boolean;
      certifications: string[];
    };
  };
  summary: {
    total_vulnerabilities: number;
    categories_with_issues: number;
    total_subdomains: number;
    severity_breakdown: {
      Critical: number;
      High: number;
      Medium: number;
      Low: number;
    };
  };
  vulnerabilities_by_category: Record<string, any[]>;
  subdomains: string[];
  scores: any[];
  incidents: {
    domain: string;
    since: string;
    summary: string;
    incidents: any[];
    news: any[];
    notes: string;
  };
  generated_at: string;
}

interface ScoreCardProps {
  category: string;
  score: number;
  maxScore: number;
  description: string;
  onClick?: () => void;
}

const ScoreCard: React.FC<ScoreCardProps> = ({ category, score, maxScore, description, onClick }) => {
  const percentage = (score / maxScore) * 100;
  let scoreClass = 'score-poor';
  let riskLevel = 'Critical Risk';

  if (percentage >= 85) {
    scoreClass = 'score-excellent';
    riskLevel = 'Excellent';
  } else if (percentage >= 70) {
    scoreClass = 'score-good';
    riskLevel = 'Good';
  } else if (percentage >= 50) {
    scoreClass = 'score-fair';
    riskLevel = 'Fair';
  }

  return (
    <div 
      className={`score-card ${scoreClass}`}
      onClick={onClick}
      style={{ 
        cursor: onClick ? 'pointer' : 'default',
        transition: 'transform 0.2s ease, box-shadow 0.2s ease'
      }}
      onMouseEnter={(e) => {
        if (onClick) {
          e.currentTarget.style.transform = 'translateY(-2px)';
          e.currentTarget.style.boxShadow = '0 8px 25px rgba(0, 0, 0, 0.15)';
        }
      }}
      onMouseLeave={(e) => {
        if (onClick) {
          e.currentTarget.style.transform = 'translateY(0)';
          e.currentTarget.style.boxShadow = '';
        }
      }}
      title={onClick ? `Click to view ${category} vulnerabilities` : undefined}
    >
      <h4>{category}</h4>
      <div className="score-value">{score}/{maxScore}</div>
      <div className="score-label">{riskLevel}</div>
      <p style={{ fontSize: '0.85rem', marginTop: '0.5rem', opacity: 0.8 }}>
        {description}
      </p>
      {onClick && (
        <div style={{ 
          position: 'absolute', 
          top: '0.5rem', 
          right: '0.5rem', 
          opacity: 0.6,
          fontSize: '0.8rem'
        }}>
          <i className="fas fa-external-link-alt"></i>
        </div>
      )}
    </div>
  );
};

interface VulnerabilityStatProps {
  count: number;
  label: string;
  severity: string;
  onClick?: () => void;
}

const VulnerabilityStat: React.FC<VulnerabilityStatProps> = ({ count, label, severity, onClick }) => {
  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical': return '#7f1d1d';
      case 'high': return '#dc2626';
      case 'medium': return '#d97706';
      case 'low': return '#059669';
      default: return '#1f2937';
    }
  };

  return (
    <div 
      className="vulnerability-stat" 
      data-severity={severity.toLowerCase()}
      onClick={onClick}
      style={{
        cursor: onClick ? 'pointer' : 'default',
        transition: 'transform 0.2s ease, box-shadow 0.2s ease',
        position: 'relative'
      }}
      onMouseEnter={(e) => {
        if (onClick) {
          e.currentTarget.style.transform = 'translateY(-2px)';
          e.currentTarget.style.boxShadow = '0 8px 25px rgba(0, 0, 0, 0.15)';
        }
      }}
      onMouseLeave={(e) => {
        if (onClick) {
          e.currentTarget.style.transform = 'translateY(0)';
          e.currentTarget.style.boxShadow = '';
        }
      }}
      title={onClick ? `Click to view all ${severity.toLowerCase()} severity issues` : undefined}
    >
      <h3 style={{ color: getSeverityColor(severity) }}>{count}</h3>
      <p>{label}</p>
      {onClick && count > 0 && (
        <div style={{ 
          position: 'absolute', 
          top: '0.5rem', 
          right: '0.5rem', 
          opacity: 0.6,
          fontSize: '0.8rem',
          color: getSeverityColor(severity)
        }}>
          <i className="fas fa-search"></i>
        </div>
      )}
    </div>
  );
};

interface OverallScoreCardProps {
  score: number;
  maxScore: number;
  grade: string;
  vendorName: string;
  tier?: string;
  certifications?: {
    iso_27001: boolean;
    soc2: boolean;
    has_certifications: boolean;
    certifications: string[];
  };
}

const OverallScoreCard: React.FC<OverallScoreCardProps> = ({ 
  score, 
  maxScore, 
  grade, 
  vendorName, 
  tier,
  certifications
}) => {
  return (
    <div className="overall-score-card">
      <div className="overall-score-header">
        <div className="header-left">
          <h2>Overall Security Score</h2>
          {tier && (
            <div className="tier-badge">{tier}</div>
          )}
          <div className="vendor-name-badge">{vendorName}</div>
        </div>
      </div>
      <div className="vendor-certifications">
        {certifications?.has_certifications ? (
          <>
            {certifications.iso_27001 && (
              <span className="cert-badge cert-iso" title="ISO 27001 Certified">
                <i className="fas fa-shield-alt"></i>
                ISO 27001
              </span>
            )}
            {certifications.soc2 && (
              <span className="cert-badge cert-soc2" title="SOC 2 Certified">
                <i className="fas fa-check-circle"></i>
                SOC 2
              </span>
            )}
            {certifications.certifications?.filter(cert => !['ISO 27001', 'SOC 2'].includes(cert)).map((cert, index) => (
              <span key={index} className="cert-badge cert-other" title={cert}>
                <i className="fas fa-certificate"></i>
                {cert}
              </span>
            ))}
          </>
        ) : (
          <span className="cert-badge cert-none" title="No Certifications Found">
            <i className="fas fa-exclamation-triangle"></i>
            No Certifications
          </span>
        )}
      </div>
      <div className="overall-score-content">
        <div className="score-display">
          <div className="score-number">{score}</div>
          <div className="score-denominator">/{maxScore}</div>
        </div>
      </div>
    </div>
  );
};

interface SubdomainCardProps {
  count: number;
  activeCount: number;
  inactiveCount: number;
  onClick: () => void;
  loading?: boolean;
}

// Simple Pie Chart Component
interface PieChartProps {
  data: {
    active: number;
    inactive: number;
  };
}

const PieChart: React.FC<PieChartProps> = ({ data }) => {
  const total = data.active + data.inactive;
  const activePercentage = total > 0 ? (data.active / total) * 100 : 0;
  const inactivePercentage = total > 0 ? (data.inactive / total) * 100 : 0;

  // SVG circle parameters
  const size = 200;
  const strokeWidth = 20;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  
  // Calculate stroke offset for active percentage
  const activeStrokeOffset = circumference - (activePercentage / 100) * circumference;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
      <div style={{ position: 'relative' }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="#f1f5f9"
            strokeWidth={strokeWidth}
          />
          {/* Active portion */}
          {data.active > 0 && (
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke="#10b981"
              strokeWidth={strokeWidth}
              strokeDasharray={circumference}
              strokeDashoffset={activeStrokeOffset}
              strokeLinecap="round"
            />
          )}
          {/* Inactive portion */}
          {data.inactive > 0 && (
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke="#ef4444"
              strokeWidth={strokeWidth}
              strokeDasharray={circumference}
              strokeDashoffset={circumference - (inactivePercentage / 100) * circumference}
              strokeLinecap="round"
              transform={`rotate(${(activePercentage / 100) * 360} ${size / 2} ${size / 2})`}
            />
          )}
        </svg>
        
        {/* Center text */}
        <div style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '3rem', fontWeight: '700', color: '#1f2937', lineHeight: '1' }}>
            {total}
          </div>
          <div style={{ fontSize: '1rem', color: '#6b7280', fontWeight: '500', marginTop: '0.25rem' }}>
            Total
          </div>
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            width: '16px',
            height: '16px',
            borderRadius: '50%',
            background: '#10b981'
          }}></div>
          <span style={{ color: '#374151', fontWeight: '500' }}>Active Subdomains</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            width: '16px',
            height: '16px',
            borderRadius: '50%',
            background: '#ef4444'
          }}></div>
          <span style={{ color: '#374151', fontWeight: '500' }}>Inactive Subdomains</span>
        </div>
      </div>
    </div>
  );
};

const SubdomainCard: React.FC<SubdomainCardProps> = ({ count, activeCount, inactiveCount, onClick, loading = false }) => {
  const successRate = count > 0 ? Math.round((activeCount / count) * 100) : 0;
  
  return (
    <div 
      className="subdomain-card"
      onClick={onClick}
      style={{
        background: 'linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%)',
        border: '1px solid #cbd5e1',
        borderRadius: '12px',
        padding: '1.5rem',
        cursor: 'pointer',
        transition: 'all 0.3s ease',
        position: 'relative',
        overflow: 'hidden'
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = 'translateY(-4px)';
        e.currentTarget.style.boxShadow = '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)';
        e.currentTarget.style.borderColor = '#3b82f6';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = 'translateY(0)';
        e.currentTarget.style.boxShadow = '';
        e.currentTarget.style.borderColor = '#cbd5e1';
      }}
      title="Click to view detailed subdomain information"
    >
      {/* Background Pattern */}
      <div style={{
        position: 'absolute',
        top: 0,
        right: 0,
        width: '100px',
        height: '100px',
        background: 'linear-gradient(45deg, rgba(59, 130, 246, 0.1), rgba(99, 102, 241, 0.05))',
        borderRadius: '50%',
        transform: 'translate(30px, -30px)'
      }}></div>
      
      <div style={{ position: 'relative', zIndex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <h4 style={{ 
            margin: 0, 
            color: '#1e293b', 
            fontSize: '1.1rem', 
            fontWeight: '600',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <i className="fas fa-sitemap" style={{ color: '#ef4444' }}></i>
            Subdomain Analysis
          </h4>
          {loading ? (
            <i className="fas fa-spinner fa-spin" style={{ color: '#6b7280' }}></i>
          ) : (
            <i className="fas fa-external-link-alt" style={{ color: '#6b7280', fontSize: '0.9rem' }}></i>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem', marginBottom: '1rem' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ 
              fontSize: '2rem', 
              fontWeight: '700', 
              color: '#1e293b',
              lineHeight: '1'
            }}>
              {count}
            </div>
            <div style={{ 
              fontSize: '0.85rem', 
              color: '#64748b', 
              fontWeight: '500',
              marginTop: '0.25rem'
            }}>
              Total Subdomains
            </div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ 
              fontSize: '2rem', 
              fontWeight: '700', 
              color: successRate >= 80 ? '#059669' : successRate >= 60 ? '#d97706' : '#dc2626',
              lineHeight: '1'
            }}>
              {successRate}%
            </div>
            <div style={{ 
              fontSize: '0.85rem', 
              color: '#64748b', 
              fontWeight: '500',
              marginTop: '0.25rem'
            }}>
              Success Rate
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: '#10b981'
            }}></div>
            <span style={{ fontSize: '0.85rem', color: '#64748b' }}>
              {activeCount} Active
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: '#ef4444'
            }}></div>
            <span style={{ fontSize: '0.85rem', color: '#64748b' }}>
              {inactiveCount} Inactive
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

const ReportPage = () => {
  const params = useParams();
  const router = useRouter();
  const searchParams = useSearchParams();
  const domain = params?.domain as string;
  const isAdmin = useIsAdmin();
  const canViewVendors = usePermission('view_vendors');
  const canViewVendorReports = usePermission('view_vendor_reports');
  const canAccessReport = canViewVendors || canViewVendorReports;
  
  const [report, setReport] = useState<VulnerabilityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [darkMode, setDarkMode] = useState(false);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [noVulnerabilitiesModal, setNoVulnerabilitiesModal] = useState<{open: boolean, category: string}>({
    open: false,
    category: ''
  });
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});
  const [selectedGroup, setSelectedGroup] = useState<any>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [severityFilterModal, setSeverityFilterModal] = useState<{open: boolean, severity: string, vulnerabilities: any[]}>({
    open: false,
    severity: '',
    vulnerabilities: []
  });
  
  // Subdomain Modal State
  const [subdomainModal, setSubdomainModal] = useState(false);
  const [subdomainData, setSubdomainData] = useState<any>(null);
  const [subdomainLoading, setSubdomainLoading] = useState(false);
  const [subdomainFilter, setSubdomainFilter] = useState('active');
  const [subdomainSearchTerm, setSubdomainSearchTerm] = useState('');
  
  // Manual subdomain addition state
  const [showAddSubdomain, setShowAddSubdomain] = useState(false);
  const [newSubdomainInput, setNewSubdomainInput] = useState('');
  const [addingSubdomain, setAddingSubdomain] = useState(false);
  
  // Notification state
  const [notification, setNotification] = useState<{
    show: boolean;
    type: 'success' | 'error' | 'info';
    message: string;
    title?: string;
  }>({
    show: false,
    type: 'info',
    message: ''
  });
  const [pdfExportModal, setPdfExportModal] = useState(false);
  const [selectedSections, setSelectedSections] = useState({
    securityScores: false,
    aiInsights: false,
    riskCards: false,
    securityAnalysis: false,
    securityIncidents: false,
    securityNews: false
  });
  const [sectionFilters, setSectionFilters] = useState({
    securityScores: {
      dns: false,
      domainReputation: false,
      email: false,
      encryption: false,
      network: false,
      website: false
    },
    securityAnalysis: {
      dns: false,
      domainReputation: false,
      email: false,
      encryption: false,
      network: false,
      website: false
    }
  });
  const [pdfExporting, setPdfExporting] = useState(false);
  
  // Additional domains state
  const [addDomainModal, setAddDomainModal] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [additionalDomains, setAdditionalDomains] = useState<string[]>([]);
  const [domainLoading, setDomainLoading] = useState(false);
  const [domainError, setDomainError] = useState<string | null>(null);

  // Background Scan State for this specific domain
  const [isBackgroundScanRunning, setIsBackgroundScanRunning] = useState(false);
  const [activeBackgroundJobId, setActiveBackgroundJobId] = useState<string | null>(null);
  const [backgroundScanProgress, setBackgroundScanProgress] = useState(0);
  const [backgroundScanCurrentDomain, setBackgroundScanCurrentDomain] = useState<string>('');
  const [backgroundScanStage, setBackgroundScanStage] = useState<string>('');
  const [monitoringJobId, setMonitoringJobId] = useState<string | null>(null);

  // Certifications modal state
  const [certificationsModalOpen, setCertificationsModalOpen] = useState(false);
  const [certificationsForm, setCertificationsForm] = useState({
    iso_27001: false,
    soc2: false
  });
  const [updatingCertifications, setUpdatingCertifications] = useState(false);

  // Hook to detect dark mode
  const useDarkModeInReports = () => {
    const [isDarkMode, setIsDarkMode] = useState(false);

    useEffect(() => {
      const checkDarkMode = () => {
        setIsDarkMode(document.body.classList.contains('dark-mode'));
      };

      // Initial check
      checkDarkMode();

      // Listen for changes
      const observer = new MutationObserver(checkDarkMode);
      observer.observe(document.body, {
        attributes: true,
        attributeFilter: ['class']
      });

      return () => observer.disconnect();
    }, []);

    return isDarkMode;
  };

  const isDarkMode = useDarkModeInReports();

  // Initialize dark mode from localStorage
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const shouldUseDark = savedTheme === 'dark' || (!savedTheme && prefersDark);
    
    setDarkMode(shouldUseDark);
    if (shouldUseDark) {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
  }, []);

  // Toggle dark mode function
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

  // Subdomain Exclusion State
  const [excludingSubdomains, setExcludingSubdomains] = useState<Set<string>>(new Set());
  const [excludedSubdomains, setExcludedSubdomains] = useState<string[]>([]);
  const [showExcludedSubdomains, setShowExcludedSubdomains] = useState(false);
  const [confirmExclusionModal, setConfirmExclusionModal] = useState<{
    open: boolean;
    subdomain: string;
    state: 'confirm' | 'success' | 'error';
    message?: string;
  }>({ open: false, subdomain: '', state: 'confirm' });

  // Vulnerability grouping function (same as main dashboard)
  const groupVulnerabilitiesByType = (vulnerabilities: any[]) => {
    const groups: { [key: string]: any } = {};
    
    vulnerabilities.forEach(vuln => {
      // Use description as the grouping key, fallback to title if available
      const key = vuln.description || vuln.title || vuln.vulnerability || 'Unknown Vulnerability';
      
      if (!groups[key]) {
        groups[key] = {
          description: key,
          severity: vuln.severity,
          id: vuln.id,
          affectedDomains: [],
          vulnerabilities: []
        };
      }
      
      // Add domain to affected domains list if not already present
      const domain = vuln.subdomain || vuln.domain || 'Unknown Domain';
      if (!groups[key].affectedDomains.includes(domain)) {
        groups[key].affectedDomains.push(domain);
      }
      
      // Store the original vulnerability data
      groups[key].vulnerabilities.push(vuln);
      
      // Use highest severity if multiple instances have different severities
      const currentWeight = getSeverityWeight(vuln.severity);
      const groupWeight = getSeverityWeight(groups[key].severity);
      if (currentWeight > groupWeight) {
        groups[key].severity = vuln.severity;
      }
    });
    
    return Object.values(groups);
  };

  const getSeverityWeight = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 4;
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 0;
    }
  };

  const toggleSection = (sectionKey: string) => {
    setCollapsedSections(prev => ({
      ...prev,
      [sectionKey]: !prev[sectionKey]
    }));
  };

  const openModal = (group: any) => {
    setSelectedGroup(group);
    setModalOpen(true);
  };

  const closeModal = () => {
    setSelectedGroup(null);
    setModalOpen(false);
  };

  const expandAll = () => {
    if (!report) return;
    const allSections: Record<string, boolean> = {};
    Object.keys(report.vulnerabilities_by_category).forEach(category => {
      allSections[`category-${category}`] = false; // false means expanded
    });
    setCollapsedSections(allSections);
  };

  const collapseAll = () => {
    if (!report) return;
    const allSections: Record<string, boolean> = {};
    Object.keys(report.vulnerabilities_by_category).forEach(category => {
      allSections[`category-${category}`] = true; // true means collapsed
    });
    setCollapsedSections(allSections);
  };

  const scrollToSection = (category: string) => {
    const element = document.getElementById(`category-${category}`);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
      // Ensure the section is expanded
      setCollapsedSections(prev => ({
        ...prev,
        [`category-${category}`]: false
      }));
      // Close any no vulnerabilities modal
      setNoVulnerabilitiesModal({ open: false, category: '' });
    }
  };

  const showSeverityModal = (severity: string) => {
    if (!report) return;
    
    // Collect all vulnerabilities with the specified severity
    const allVulnerabilities: any[] = [];
    Object.values(report.vulnerabilities_by_category).forEach(vulnerabilities => {
      vulnerabilities.forEach(vuln => {
        if (vuln.severity === severity) {
          allVulnerabilities.push(vuln);
        }
      });
    });

    setSeverityFilterModal({
      open: true,
      severity,
      vulnerabilities: allVulnerabilities
    });
  };

  const closeSeverityModal = () => {
    setSeverityFilterModal({
      open: false,
      severity: '',
      vulnerabilities: []
    });
  };

  const loadSubdomainData = async () => {
    try {
      setSubdomainLoading(true);
      const data = await subdomainApi.getSubdomainsCached(domain);
      setSubdomainData(data);
      setSubdomainModal(true);
    } catch (error) {
      console.error('Error loading subdomain data:', error);
    } finally {
      setSubdomainLoading(false);
    }
  };

  const closeSubdomainModal = () => {
    setSubdomainModal(false);
    setSubdomainFilter('all');
    setSubdomainSearchTerm('');
  };

  useEffect(() => {
    if (domain) {
      loadReport();
      // Check for active background scans for this domain
      checkActiveBackgroundScans();
    }
  }, [domain]);

  const loadReport = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Load main report data first (without incidents)
      const reportData = await reportApi.getVulnerabilityReport(domain, false);
      setReport(reportData);
      setLoading(false);
      
      // Load additional domains and excluded subdomains for this vendor
      if (reportData.vendor?.id) {
        loadAdditionalDomains(reportData.vendor.id);
        loadExcludedSubdomains(reportData.vendor.id);
      }
      
      // Load incidents data asynchronously
      loadIncidents();
      
    } catch (err) {
      console.error('Error loading report:', err);
      setError('Failed to load security report. Please try again.');
      setLoading(false);
    }
  };

  const loadAdditionalDomains = async (vendorId: number) => {
    try {
      const result = await vendorApi.getAdditionalDomains(vendorId);
      if (result.status === 'success') {
        setAdditionalDomains(result.additional_domains || []);
      }
    } catch (error) {
      console.error('Error loading additional domains:', error);
    }
  };

  const loadExcludedSubdomains = async (vendorId: number) => {
    try {
      const result = await vendorApi.getExcludedSubdomains(vendorId);
      if (result.success) {
        setExcludedSubdomains(result.excluded_subdomains?.map((item: any) => item.subdomain) || []);
      }
    } catch (error) {
      console.error('Error loading excluded subdomains:', error);
    }
  };

  const handleExcludeSubdomain = (subdomain: string) => {
    if (!report?.vendor?.id || excludingSubdomains.has(subdomain)) return;
    
    // Don't allow excluding the main domain
    if (subdomain === domain) {
      alert('Cannot exclude the main domain');
      return;
    }
    
    // Show confirmation modal
    setConfirmExclusionModal({ open: true, subdomain, state: 'confirm' });
  };

  const confirmExclusion = async () => {
    const subdomain = confirmExclusionModal.subdomain;
    if (!report?.vendor?.id || !subdomain) return;
    
    try {
      setExcludingSubdomains(prev => new Set(Array.from(prev).concat(subdomain)));
      
      const result = await vendorApi.addExcludedSubdomain(report.vendor.id, subdomain);
      
      if (result.success) {
        // Log the subdomain exclusion action
        logUserAction('EXCLUDE', 'subdomain_exclusion', report.vendor.id.toString(), {
          action_type: 'exclude_subdomain',
          vendor_name: report.vendor.name,
          vendor_id: report.vendor.id,
          subdomain: subdomain,
          domain: domain,
          timestamp: new Date().toISOString()
        });
        
        // Update excluded subdomains list
        setExcludedSubdomains(prev => [...prev, subdomain]);
        
        // Refresh subdomain data to reflect changes
        if (subdomainData) {
          const updatedData = await subdomainApi.getSubdomainsCached(domain);
          setSubdomainData(updatedData);
        }
        
        // Show success state in modal
        setConfirmExclusionModal({ 
          open: true, 
          subdomain, 
          state: 'success',
          message: `Successfully excluded "${subdomain}" from future scans.`
        });
      } else {
        // Show error state in modal
        setConfirmExclusionModal({ 
          open: true, 
          subdomain, 
          state: 'error',
          message: `Failed to exclude subdomain: ${result.error || 'Unknown error'}`
        });
      }
    } catch (error) {
      console.error('Error excluding subdomain:', error);
      // Show error state in modal
      setConfirmExclusionModal({ 
        open: true, 
        subdomain, 
        state: 'error',
        message: 'Failed to exclude subdomain. Please try again.'
      });
    } finally {
      setExcludingSubdomains(prev => {
        const updated = new Set(Array.from(prev));
        updated.delete(subdomain);
        return updated;
      });
    }
  };

  const showNotification = (type: 'success' | 'error' | 'info', title: string, message: string) => {
    setNotification({
      show: true,
      type,
      title,
      message
    });
    
    // Auto-hide notification after 5 seconds
    setTimeout(() => {
      setNotification(prev => ({ ...prev, show: false }));
    }, 5000);
  };

  const handleAddManualSubdomain = async () => {
    if (!report?.vendor?.id || !newSubdomainInput.trim() || addingSubdomain) return;
    
    const subdomain = newSubdomainInput.trim().toLowerCase();
    
    // Basic validation
    if (!subdomain.includes('.')) {
      showNotification('error', 'Invalid Subdomain', 'Please enter a valid subdomain (e.g., api.example.com)');
      return;
    }
    
    try {
      setAddingSubdomain(true);
      
      const data = await subdomainApi.addManualSubdomain(report.vendor.id, subdomain, domain);
      
      if (data.status === 'success') {
        // Log the manual subdomain addition action
        logUserAction('UPDATE', 'subdomain', report.vendor.id.toString(), {
          action_type: 'add_manual_subdomain',
          vendor_name: report.vendor.name,
          vendor_id: report.vendor.id,
          subdomain: subdomain,
          domain: domain,
          timestamp: new Date().toISOString()
        });
        
        // Show success notification
        showNotification('success', 'Subdomain Added Successfully', 
          `"${subdomain}" has been added as a manual subdomain for ${report.vendor.name}.`);
        
        // Wait a moment for user to see the success message
        setTimeout(async () => {
          // Clear input and hide form
          setNewSubdomainInput('');
          setShowAddSubdomain(false);
          
          // Refresh subdomain data to show the new subdomain (force fresh data)
          if (subdomainData) {
            const updatedData = await subdomainApi.getSubdomains(domain); // Use non-cached version
            setSubdomainData(updatedData);
          }
        }, 2000);
        
      } else {
        showNotification('error', 'Failed to Add Subdomain', data.message || 'Unknown error occurred');
      }
    } catch (error) {
      console.error('Error adding manual subdomain:', error);
      showNotification('error', 'Failed to Add Subdomain', 'An unexpected error occurred. Please try again.');
    } finally {
      setAddingSubdomain(false);
    }
  };

  const handleAddDomain = async () => {
    if (!newDomain.trim() || !report?.vendor?.id) return;
    
    try {
      setDomainLoading(true);
      setDomainError(null);
      
      const result = await vendorApi.addAdditionalDomain(report.vendor.id, newDomain.trim());
      
      if (result.status === 'success') {
        // Log the additional domain addition action
        logUserAction('CREATE', 'additional_domain', report.vendor.id.toString(), {
          action_type: 'add_additional_domain',
          vendor_name: report.vendor.name,
          vendor_id: report.vendor.id,
          domain: newDomain.trim(),
          timestamp: new Date().toISOString()
        });
        
        setAdditionalDomains(result.additional_domains || []);
        setNewDomain('');
        setAddDomainModal(false);
        // Show success message (you can add a toast notification here)
        console.log('Domain added successfully:', result.message);
      } else {
        setDomainError(result.message || 'Failed to add domain');
      }
    } catch (error) {
      console.error('Error adding domain:', error);
      setDomainError('Failed to add domain. Please try again.');
    } finally {
      setDomainLoading(false);
    }
  };

  const handleRemoveDomain = async (domainToRemove: string) => {
    if (!report?.vendor?.id) return;
    
    try {
      const result = await vendorApi.removeAdditionalDomain(report.vendor.id, domainToRemove);
      
      if (result.status === 'success') {
        // Log the additional domain removal action
        logUserAction('DELETE', 'additional_domain', report.vendor.id.toString(), {
          action_type: 'remove_additional_domain',
          vendor_name: report.vendor.name,
          vendor_id: report.vendor.id,
          domain: domainToRemove,
          timestamp: new Date().toISOString()
        });
        
        setAdditionalDomains(result.additional_domains || []);
        console.log('Domain removed successfully:', result.message);
      } else {
        console.error('Failed to remove domain:', result.message);
      }
    } catch (error) {
      console.error('Error removing domain:', error);
    }
  };

  const loadIncidents = async () => {
    try {
      setIncidentsLoading(true);
      setIncidentsError(null);
      
      const incidentsData = await reportApi.getReportIncidents(domain, 36);
      
      if (incidentsData.status === 'success') {
        // Update the report with incidents data
        setReport(prevReport => {
          if (prevReport) {
            return {
              ...prevReport,
              incidents: incidentsData.incidents
            };
          }
          return prevReport;
        });
      } else {
        setIncidentsError('Failed to load incidents data');
      }
    } catch (err) {
      console.error('Error loading incidents:', err);
      setIncidentsError('Failed to load incidents and news data.');
    } finally {
      setIncidentsLoading(false);
    }
  };

  const handleBack = () => {
    // Check if we have a 'from' parameter indicating which section to return to
    const fromSection = searchParams?.get('from');
    
    if (fromSection) {
      // Build query params to restore previous state
      const params = new URLSearchParams();
      params.set('section', fromSection);
      
      // Restore search term if it was present
      const search = searchParams?.get('search');
      if (search) {
        params.set('search', search);
      }
      
      // Restore filters if they were present
      const riskFilter = searchParams?.get('riskFilter');
      if (riskFilter) {
        params.set('riskFilter', riskFilter);
      }
      
      const tierFilter = searchParams?.get('tierFilter');
      if (tierFilter) {
        params.set('tierFilter', tierFilter);
      }
      
      const portfolioFilter = searchParams?.get('portfolioFilter');
      if (portfolioFilter) {
        params.set('portfolioFilter', portfolioFilter);
      }
      
      const industryFilter = searchParams?.get('industryFilter');
      if (industryFilter) {
        params.set('industryFilter', industryFilter);
      }
      
      const scoreFilter = searchParams?.get('scoreFilter');
      if (scoreFilter) {
        params.set('scoreFilter', scoreFilter);
      }
      
      // Navigate back to the dashboard with preserved state
      router.push(`/?${params.toString()}`);
    } else {
      // Fallback: use browser back if no section specified
      router.back();
    }
  };

  const handlePdfExport = () => {
    setPdfExportModal(true);
  };

  const handleSectionToggle = (section: keyof typeof selectedSections) => {
    setSelectedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const handleFilterToggle = (section: keyof typeof sectionFilters, filter: string) => {
    setSectionFilters(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [filter]: !(prev[section] as any)[filter]
      }
    }));
  };

  const hasAnyFiltersSelected = (section: keyof typeof sectionFilters) => {
    return Object.values(sectionFilters[section]).some(Boolean);
  };

  const handleSelectAllFilters = (section: keyof typeof sectionFilters, selectAll: boolean) => {
    setSectionFilters(prev => ({
      ...prev,
      [section]: {
        dns: selectAll,
        domainReputation: selectAll,
        email: selectAll,
        encryption: selectAll,
        network: selectAll,
        website: selectAll
      }
    }));
  };

  const areAllFiltersSelected = (section: keyof typeof sectionFilters) => {
    const filters = sectionFilters[section];
    return filters.dns && filters.domainReputation && filters.email && 
           filters.encryption && filters.network && filters.website;
  };

  const handleExportPdf = async () => {
    try {
      setPdfExporting(true);
      const response = await reportApi.exportToPdf(domain, { sections: selectedSections, filters: sectionFilters });
      
      // Create blob and download
      const blob = new Blob([response], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-report-${domain}-${new Date().toISOString().split('T')[0]}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      setPdfExportModal(false);
    } catch (error) {
      console.error('Error exporting PDF:', error);
      alert('Failed to export PDF. Please try again.');
    } finally {
      setPdfExporting(false);
    }
  };

  // Background scan monitoring functions
  const checkActiveBackgroundScans = async () => {
    try {
      const response = await backgroundScanApi.listJobs();
      if (response.status === 'success' && response.jobs) {
        // Find any active jobs for this specific domain
        const activeJob = response.jobs.find(job => 
          (job.status === 'starting' || job.status === 'running') &&
          job.current_domain === domain
        );
        
        if (activeJob) {
          setIsBackgroundScanRunning(true);
          setActiveBackgroundJobId(activeJob.job_id);
          setBackgroundScanProgress(activeJob.progress || 0);
          setBackgroundScanCurrentDomain(activeJob.current_domain || domain);
          setBackgroundScanStage(activeJob.stage || '');
          
          // Start monitoring if running and not already monitoring this job
          if (activeJob.status === 'running' && monitoringJobId !== activeJob.job_id) {
            monitorBackgroundScan(activeJob.job_id);
          }
        } else {
          setIsBackgroundScanRunning(false);
          setActiveBackgroundJobId(null);
          setMonitoringJobId(null);
          setBackgroundScanProgress(0);
          setBackgroundScanCurrentDomain('');
          setBackgroundScanStage('');
        }
      }
    } catch (error) {
      console.error('Error checking active background scans:', error);
    }
  };

  const monitorBackgroundScan = async (jobId: string) => {
    try {
      // Set monitoring state to prevent duplicate monitoring
      setMonitoringJobId(jobId);
      
      const finalJob = await backgroundScanApi.monitorJob(jobId, (job: BackgroundScanJob) => {
        // Update local state
        if (job.status === 'running') {
          setIsBackgroundScanRunning(true);
          setActiveBackgroundJobId(job.job_id);
          setBackgroundScanProgress(job.progress || 0);
          setBackgroundScanCurrentDomain(job.current_domain || domain);
          setBackgroundScanStage(job.stage || '');
        } else if (['completed', 'failed', 'cancelled'].includes(job.status)) {
          setIsBackgroundScanRunning(false);
          setActiveBackgroundJobId(null);
          setBackgroundScanProgress(0);
          setBackgroundScanCurrentDomain('');
          setBackgroundScanStage('');
        }
      });
      
      // Update state when job completes
      setIsBackgroundScanRunning(false);
      setActiveBackgroundJobId(null);
      setMonitoringJobId(null);
      
      // Show notification based on final status
      if (finalJob.status === 'completed') {
        // Show completion notification only for successful completion
        showNotification('success', 'Background Scan Complete', 
          `Security scan completed for ${domain}! Report data has been updated.`);
        
        // Refresh report data after completion
        setTimeout(async () => {
          await loadReport();
        }, 2000);
      } else if (finalJob.status === 'failed') {
        // Show failure notification
        showNotification('error', 'Background Scan Failed', 
          `Security scan failed for ${domain}. Please check the logs for details.`);
      }
      // Don't show notification for 'cancelled' - it's already handled in stopBackgroundScan()
      
    } catch (error) {
      console.error('Error monitoring background scan:', error);
      // Reset state on error
      setIsBackgroundScanRunning(false);
      setActiveBackgroundJobId(null);
      setMonitoringJobId(null);
    }
  };

  // Stop/Cancel background scan
  const stopBackgroundScan = async () => {
    if (!activeBackgroundJobId) {
      showNotification('info', 'No Active Scan', 'No background scan is currently running.');
      return;
    }

    try {
      await backgroundScanApi.cancelJob(activeBackgroundJobId);
      
      // Reset state
      setIsBackgroundScanRunning(false);
      setActiveBackgroundJobId(null);
      setBackgroundScanProgress(0);
      setBackgroundScanCurrentDomain('');
      setBackgroundScanStage('');
      setMonitoringJobId(null);
      
      showNotification('success', 'Scan Stopped', 'Background scan has been cancelled successfully.');
      
      // Refresh report after a short delay
      setTimeout(async () => {
        await loadReport();
      }, 1000);
      
    } catch (error) {
      console.error('Error stopping background scan:', error);
      showNotification('error', 'Stop Failed', 'Failed to stop background scan. Please try again.');
    }
  };

  if (loading) {
    return (
      <div className="report-container">
        <div className="loading-container">
          <i className="fas fa-spinner loading-spinner"></i>
          <h3>Loading Security Report...</h3>
          <p>Analyzing security data for {domain}</p>
        </div>
      </div>
    );
  }

  if (!canAccessReport) {
    return (
      <div className="report-container">
        <div className="loading-container">
          <h3>Access denied</h3>
          <p>You do not have permission to view vendor reports.</p>
          <button className="btn btn-secondary" onClick={handleBack}>
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="report-container">
        {/* Fixed Back Button */}
        <button 
          className="back-btn-fixed" 
          onClick={handleBack}
          title="Back to Dashboard"
          style={{
            position: 'fixed',
            left: '6rem',
            top: '2rem',
            width: '48px',
            height: '48px',
            backgroundColor: 'transparent',
            border: 'none',
            color: 'var(--text-primary)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.5rem',
            transition: 'all 0.2s ease',
            zIndex: 1000
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'scale(1.2)';
            e.currentTarget.style.opacity = '0.7';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'scale(1)';
            e.currentTarget.style.opacity = '1';
          }}
        >
          <i className="fas fa-arrow-left"></i>
        </button>

        <div className="error-container">
          <i className="fas fa-exclamation-triangle"></i>
          <h2>Report Not Available</h2>
          <p>{error || 'No security report found for this domain.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="report-container">
      {/* Fixed Back Button */}
      <button 
        className="back-btn-fixed" 
        onClick={handleBack}
        title="Back to Dashboard"
        style={{
          position: 'fixed',
          left: '6rem',
          top: '2rem',
          width: '48px',
          height: '48px',
          backgroundColor: 'transparent',
          border: 'none',
          color: 'var(--text-primary)',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '1.5rem',
          transition: 'all 0.2s ease',
          zIndex: 1000
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'scale(1.2)';
          e.currentTarget.style.opacity = '0.7';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'scale(1)';
          e.currentTarget.style.opacity = '1';
        }}
      >
        <i className="fas fa-arrow-left"></i>
      </button>

      {/* Report Header */}
      <div className="report-header">
        <div className="report-title">
          <h1>Security Report</h1>
          <span className="domain-badge">{domain}</span>
        </div>
        <div className="report-actions">
          <button className="theme-toggle" aria-label="Toggle dark mode" onClick={toggleTheme}>
            <i className={`fas ${darkMode ? 'fa-sun' : 'fa-moon'}`}></i>
          </button>
          <button className="export-pdf-btn" onClick={handlePdfExport}>
            <i className="fas fa-file-pdf"></i>
            Download Report
          </button>
        </div>
      </div>

      {/* Background Scan Status Indicator */}
      {isBackgroundScanRunning && (
        <div className="background-scan-status">
          <div className="status-card">
            <div className="status-icon">
              <i className="fas fa-spinner fa-spin"></i>
            </div>
            <div className="status-content">
              <div className="status-header">
                <div className="status-title">Security Scan In Progress</div>
                <div className="status-percentage">{backgroundScanProgress}%</div>
              </div>
              <div className="status-subtitle">
                {backgroundScanCurrentDomain === domain 
                  ? `Scanning ${domain}${backgroundScanStage ? ` - ${backgroundScanStage}` : ''}`
                  : 'Security scan running in background'
                }
              </div>
              <div className="progress-bar-container">
                <div 
                  className="progress-bar-fill" 
                  style={{ width: `${backgroundScanProgress}%` }}
                ></div>
              </div>
            </div>
            <button 
              className="scan-stop-button"
              onClick={stopBackgroundScan}
              title="Stop background scan"
            >
              <i className="fas fa-stop-circle"></i>
            </button>
          </div>
        </div>
      )}

      {/* Report Content */}
      <div className="report-content">
        {/* Overall Score Display */}
        <div className="overall-score-section">
          <OverallScoreCard
            score={report.vendor.overall_score || 0}
            maxScore={950}
            grade={report.vendor.grade || 'N/A'}
            vendorName={report.vendor.name}
            tier={report.vendor.tier}
            certifications={report.vendor.certifications}
          />
          <div style={{
            marginTop: '1rem',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '0.75rem'
          }}>
            {report.vendor.last_scanned && (
              <div style={{
                padding: '0.75rem 1.5rem',
                color: 'var(--text-secondary)',
                fontSize: '0.9rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.75rem'
              }}>
                <i className="fas fa-clock" style={{ color: 'var(--primary-color)' }}></i>
                <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Last Scanned:</span>
                <span>
                {(() => {
                  const date = new Date(report.vendor.last_scanned);
                  return !isNaN(date.getTime()) 
                      ? date.toLocaleString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })
                      : 'Not Scanned';
                })()}
              </span>
              </div>
            )}
            {isAdmin && (
              <button
                onClick={() => {
                  // Initialize form with current certifications
                  setCertificationsForm({
                    iso_27001: report.vendor.certifications?.iso_27001 || false,
                    soc2: report.vendor.certifications?.soc2 || false
                  });
                  setCertificationsModalOpen(true);
                }}
                style={{
                  padding: '0.5rem 1rem',
                  backgroundColor: isDarkMode ? '#3b82f6' : '#2563eb',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontSize: '0.9rem',
                  fontWeight: 500,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  transition: 'all 0.2s ease',
                  boxShadow: isDarkMode ? '0 2px 4px rgba(59, 130, 246, 0.3)' : '0 2px 4px rgba(37, 99, 235, 0.3)'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.opacity = '0.9';
                  e.currentTarget.style.transform = 'translateY(-1px)';
                  e.currentTarget.style.boxShadow = isDarkMode ? '0 4px 8px rgba(59, 130, 246, 0.4)' : '0 4px 8px rgba(37, 99, 235, 0.4)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.opacity = '1';
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = isDarkMode ? '0 2px 4px rgba(59, 130, 246, 0.3)' : '0 2px 4px rgba(37, 99, 235, 0.3)';
                }}
              >
                <i className="fas fa-certificate"></i>
                Vendor Certifications
              </button>
            )}
          </div>
        </div>


        {/* Category Scores Section */}
        <div className="category-scores-section">
          <h3 className="section-title">Security Category Scores</h3>
          <div className="score-summary">
            {report.scores.map((scoreData, index) => (
            <ScoreCard
              key={index}
              category={scoreData.score_category || scoreData.category}
              score={scoreData.score}
              maxScore={950}
              description={`${scoreData.score_category || scoreData.category} security assessment`}
              onClick={() => {
                if (scoreData.score === 950) {
                  setNoVulnerabilitiesModal({
                    open: true,
                    category: scoreData.score_category || scoreData.category
                  });
                } else {
                  setNoVulnerabilitiesModal({ open: false, category: '' });
                  scrollToSection(scoreData.score_category || scoreData.category);
                }
              }}
            />
          ))}
          </div>
        </div>

        {/* Score Timeline Chart */}
        <div style={{ padding: '0 2rem', marginBottom: '2rem' }}>
          <ScoreTimelineChart 
            domain={domain}
            months={3}
            title="Security Score Timeline (Past 3 Months)"
          />
        </div>

        {/* Vulnerability Summary */}
        <div className="vulnerability-summary">
          <VulnerabilityStat
            count={report.summary.severity_breakdown.Critical || 0}
            label="Critical Issues"
            severity="critical"
            onClick={() => showSeverityModal('Critical')}
          />
          <VulnerabilityStat
            count={report.summary.severity_breakdown.High || 0}
            label="High Risk Issues"
            severity="high"
            onClick={() => showSeverityModal('High')}
          />
          <VulnerabilityStat
            count={report.summary.severity_breakdown.Medium || 0}
            label="Medium Risk Issues"
            severity="medium"
            onClick={() => showSeverityModal('Medium')}
          />
          <VulnerabilityStat
            count={report.summary.severity_breakdown.Low || 0}
            label="Low Risk Issues"
            severity="low"
            onClick={() => showSeverityModal('Low')}
          />
        </div>

        {/* Subdomain Analysis Card */}
        <PermissionGate permission="view_subdomains">
          <div style={{ padding: '0 2rem', marginBottom: '2rem' }}>
            <SubdomainCard
              count={subdomainData?.count?.total || report.summary.total_subdomains || 0}
              activeCount={subdomainData?.count?.alive || report.summary.total_subdomains || 0}
              inactiveCount={subdomainData ? (subdomainData.count?.total || 0) - (subdomainData.count?.alive || 0) : 0}
              onClick={loadSubdomainData}
              loading={subdomainLoading}
            />
          </div>
        </PermissionGate>

        {/* Additional Domains Management */}
        <PermissionGate permission="manage_additional_domains">
          <div style={{ padding: '0 2rem', marginBottom: '2rem' }}>
            <div className="additional-domains-card" style={{
              background: 'white',
              borderRadius: '12px',
              padding: '1.5rem',
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
              border: '1px solid #e5e7eb'
            }}>
              <div className="additional-domains-header" style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '1rem'
              }}>
                <div>
                  <h3 style={{ 
                    margin: '0 0 0.25rem 0', 
                    fontSize: '1.125rem', 
                    fontWeight: '600',
                    color: '#1f2937'
                  }}>
                    Additional Domains
                  </h3>
                  <p style={{ 
                    margin: '0', 
                    fontSize: '0.875rem', 
                    color: '#6b7280' 
                  }}>
                    Manage additional domains for {report.vendor.name}
                  </p>
                </div>
                <button
                  onClick={() => setAddDomainModal(true)}
                  className="add-domain-btn"
                  style={{
                    background: '#3b82f6',
                    color: 'white',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '0.75rem 1rem',
                    fontSize: '0.875rem',
                    fontWeight: '500',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    transition: 'background-color 0.2s'
                  }}
                >
                  <i className="fas fa-plus"></i>
                  Add Domain
                </button>
              </div>
              
              <div className="additional-domains-content">
                {additionalDomains.length > 0 ? (
                  <div className="additional-domains-list" style={{ 
                    display: 'flex', 
                    flexWrap: 'wrap', 
                    gap: '0.75rem' 
                  }}>
                    {additionalDomains.map((domain, index) => (
                      <div
                        key={index}
                        className="domain-tag"
                        style={{
                          background: isDarkMode ? 'var(--bg-primary)' : '#f8fafc',
                          border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e2e8f0'}`,
                          borderRadius: '8px',
                          padding: '0.5rem 0.75rem',
                          fontSize: '0.875rem',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                          transition: 'all 0.2s'
                        }}
                      >
                        <i className="fas fa-globe" style={{ color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.75rem' }}></i>
                        <span style={{ color: isDarkMode ? 'var(--text-primary)' : '#374151', fontWeight: '500' }}>{domain}</span>
                        <button
                          onClick={() => handleRemoveDomain(domain)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: '#ef4444',
                            cursor: 'pointer',
                            padding: '0.25rem',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            transition: 'background-color 0.2s'
                          }}
                          title="Remove domain"
                          onMouseOver={(e) => (e.target as HTMLButtonElement).style.background = isDarkMode ? 'rgba(239, 68, 68, 0.1)' : '#fee2e2'}
                          onMouseOut={(e) => (e.target as HTMLButtonElement).style.background = 'none'}
                        >
                          <i className="fas fa-times"></i>
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="no-domains-state" style={{
                    textAlign: 'center',
                    padding: '2rem',
                    color: '#6b7280'
                  }}>
                    <i className="fas fa-globe" style={{ 
                      fontSize: '2rem', 
                      marginBottom: '1rem',
                      opacity: 0.3 
                    }}></i>
                    <p style={{ 
                      margin: '0 0 0.5rem 0', 
                      fontSize: '0.875rem', 
                      fontWeight: '500' 
                    }}>
                      No additional domains configured
                    </p>
                    <p style={{ 
                      margin: '0', 
                      fontSize: '0.75rem' 
                    }}>
                      Click &quot;Add Domain&quot; to start tracking additional domains for this vendor
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </PermissionGate>

        {/* AI Analyst Insights */}
        <AIInsights
          domain={domain}
          vendorData={{
            name: report.vendor.name,
            overall_score: report.vendor.overall_score || 0,
            grade: report.vendor.grade || 'N/A'
          }}
          vulnerabilityData={{
            total_vulnerabilities: report.summary.total_vulnerabilities,
            severity_breakdown: report.summary.severity_breakdown,
            categories_with_issues: report.summary.categories_with_issues
          }}
          scoresData={report.scores}
          subdomainsCount={report.summary.total_subdomains}
        />

        {/* Security Categories Analysis */}
        <div style={{ padding: '2rem' }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center', 
            marginBottom: '1.5rem' 
          }}>
            <h2 style={{ margin: 0, color: isDarkMode ? 'var(--text-primary)' : '#1f2937' }}>
              Security Categories Analysis
            </h2>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={expandAll}
                style={{
                  background: '#3b82f6',
                  color: 'white',
                  border: 'none',
                  padding: '0.5rem 1rem',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontWeight: '500',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  transition: 'background-color 0.2s ease'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = '#2563eb';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = '#3b82f6';
                }}
              >
                <i className="fas fa-expand-arrows-alt"></i>
                Expand All
              </button>
              <button
                onClick={collapseAll}
                style={{
                  background: '#6b7280',
                  color: 'white',
                  border: 'none',
                  padding: '0.5rem 1rem',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontWeight: '500',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  transition: 'background-color 0.2s ease'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = '#4b5563';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = '#6b7280';
                }}
              >
                <i className="fas fa-compress-arrows-alt"></i>
                Collapse All
              </button>
            </div>
          </div>
          
          {Object.entries(report.vulnerabilities_by_category).map(([category, vulnerabilities]) => {
            const groupedVulns = groupVulnerabilitiesByType(vulnerabilities);
            const sectionKey = `category-${category}`;
            const isCollapsed = collapsedSections[sectionKey];
            
            return (
              <div key={category} id={`category-${category}`} style={{ marginBottom: '2rem' }}>
                <div 
                  style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'space-between',
                    padding: '1rem',
                    background: isDarkMode ? 'var(--bg-primary)' : '#f8fafc',
                    borderRadius: '8px',
                    marginBottom: '1rem',
                    cursor: 'pointer',
                    border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
                  }}
                  onClick={() => toggleSection(sectionKey)}
                >
                  <h3 style={{ margin: 0, color: isDarkMode ? 'var(--text-primary)' : '#1f2937', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <i className={`fas fa-chevron-${isCollapsed ? 'right' : 'down'}`} style={{ fontSize: '0.8rem' }}></i>
                    {category} Security
                  </h3>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <span style={{ 
                      background: '#3b82f6', 
                      color: 'white', 
                      padding: '0.25rem 0.75rem', 
                      borderRadius: '12px',
                      fontSize: '0.85rem',
                      fontWeight: '500'
                    }}>
                      {groupedVulns.length} unique
                    </span>
                    <span style={{ 
                      background: '#ef4444', 
                      color: 'white', 
                      padding: '0.25rem 0.75rem', 
                      borderRadius: '12px',
                      fontSize: '0.85rem',
                      fontWeight: '500'
                    }}>
                      {vulnerabilities.length} total
                    </span>
                  </div>
                </div>
                
                {!isCollapsed && (
                  <div className="vulnerability-table-container" style={{
                    maxHeight: '400px',
                    overflowY: 'auto',
                    border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                    borderRadius: '8px',
                    background: isDarkMode ? 'var(--bg-secondary)' : 'white'
                  }}>
                    <table className="vulnerability-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead style={{ position: 'sticky', top: 0, background: isDarkMode ? 'var(--bg-primary)' : '#f8fafc', zIndex: 10 }}>
                        <tr>
                          <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>AFFECTED</th>
                          <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>VULNERABILITY</th>
                          <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>SEVERITY</th>
                          <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>ID</th>
                        </tr>
                      </thead>
                      <tbody>
                        {groupedVulns.map((group, index) => (
                          <tr 
                            key={index}
                            style={{ 
                              cursor: 'pointer',
                              borderBottom: '1px solid #f3f4f6'
                            }}
                            onClick={() => openModal(group)}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.backgroundColor = '#f8fafc';
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.backgroundColor = 'transparent';
                            }}
                          >
                            <td style={{ padding: '1rem' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <i className="fas fa-eye" style={{ color: '#6b7280', fontSize: '0.8rem' }}></i>
                                <span style={{ fontSize: '0.85rem', color: '#6b7280' }}>
                                  {group.affectedDomains.length} affected domain{group.affectedDomains.length > 1 ? 's' : ''}
                                </span>
                              </div>
                            </td>
                            <td style={{ padding: '1rem', fontWeight: '500', color: '#1f2937' }}>
                              {group.description}
                            </td>
                            <td style={{ padding: '1rem' }}>
                              <span className={`severity-badge ${group.severity.toLowerCase()}`} style={{
                                padding: '0.25rem 0.5rem',
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                                fontWeight: '600',
                                textTransform: 'uppercase'
                              }}>
                                {group.severity}
                              </span>
                            </td>
                            <td style={{ padding: '1rem' }}>
                              <code style={{ 
                                background: '#f3f4f6', 
                                padding: '0.25rem 0.5rem', 
                                borderRadius: '4px',
                                fontSize: '0.8rem',
                                color: '#374151'
                              }}>
                                {group.id || 'Multiple'}
                              </code>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Security Incidents Section */}
        <div style={{ padding: '2rem', borderTop: '1px solid #e5e7eb' }}>
          <h2 style={{ marginBottom: '1.5rem', color: isDarkMode ? 'var(--text-primary)' : '#1f2937', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <i className="fas fa-exclamation-triangle" style={{ color: '#ef4444' }}></i>
            Security Incidents
            {incidentsLoading && (
              <i className="fas fa-spinner fa-spin" style={{ color: '#6b7280', fontSize: '1rem' }}></i>
            )}
          </h2>
          
          {incidentsLoading ? (
            <div style={{ 
              padding: '2rem', 
              textAlign: 'center', 
              background: isDarkMode ? 'var(--bg-primary)' : '#f9fafb', 
              border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, 
              borderRadius: '8px',
              color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
            }}>
              <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', marginBottom: '1rem', color: '#9ca3af' }}></i>
              <p style={{ margin: 0, fontWeight: '500' }}>Loading security incidents...</p>
            </div>
          ) : incidentsError ? (
            <div style={{ 
              padding: '2rem', 
              textAlign: 'center', 
              background: '#fef2f2', 
              border: '1px solid #fecaca', 
              borderRadius: '8px',
              color: '#dc2626'
            }}>
              <i className="fas fa-exclamation-triangle" style={{ fontSize: '2rem', marginBottom: '1rem', color: '#ef4444' }}></i>
              <p style={{ margin: 0, fontWeight: '500' }}>{incidentsError}</p>
            </div>
          ) : report?.incidents?.incidents && report.incidents.incidents.length > 0 ? (
            <div className="vulnerability-table-container" style={{
              maxHeight: '300px',
              overflowY: 'auto',
              border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
              borderRadius: '8px',
              background: isDarkMode ? 'var(--bg-secondary)' : 'white',
              marginBottom: '1rem'
            }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead style={{ position: 'sticky', top: 0, background: isDarkMode ? 'var(--bg-primary)' : '#fef2f2', zIndex: 10 }}>
                  <tr>
                    <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>DATE</th>
                    <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>TITLE</th>
                    <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>SEVERITY</th>
                    <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>SOURCE</th>
                  </tr>
                </thead>
                <tbody>
                  {report.incidents.incidents.map((incident: any, index: number) => (
                    <tr key={index} style={{ borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      <td style={{ padding: '1rem', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                        {new Date(incident.date).toLocaleDateString()}
                      </td>
                      <td style={{ padding: '1rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#1f2937' }}>
                        {incident.title}
                      </td>
                      <td style={{ padding: '1rem' }}>
                        <span className={`severity-badge ${incident.severity?.toLowerCase() || 'info'}`} style={{
                          padding: '0.25rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          textTransform: 'uppercase'
                        }}>
                          {incident.severity || 'Info'}
                        </span>
                      </td>
                      <td style={{ padding: '1rem' }}>
                        {incident.source ? (
                          <a href={incident.source} target="_blank" rel="noopener noreferrer" style={{ color: '#3b82f6', textDecoration: 'none' }}>
                            Link
                          </a>
                        ) : (
                          <span style={{ color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>N/A</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ 
              padding: '2rem', 
              textAlign: 'center', 
              background: isDarkMode ? 'var(--bg-secondary)' : '#f0fdf4', 
              border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#bbf7d0'}`, 
              borderRadius: '8px',
              color: isDarkMode ? 'var(--text-secondary)' : '#166534'
            }}>
              <i className="fas fa-shield-alt" style={{ fontSize: '2rem', marginBottom: '1rem', color: isDarkMode ? 'var(--text-secondary)' : '#22c55e' }}></i>
              <p style={{ margin: 0, fontWeight: '500' }}>No security incidents found for this domain</p>
            </div>
          )}
        </div>

        {/* Security News Section */}
        <div style={{ padding: '2rem', borderTop: '1px solid #e5e7eb' }}>
          <h2 style={{ marginBottom: '1.5rem', color: isDarkMode ? 'var(--text-primary)' : '#1f2937', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <i className="fas fa-newspaper" style={{ color: '#3b82f6' }}></i>
            Security News
            {incidentsLoading && (
              <i className="fas fa-spinner fa-spin" style={{ color: '#6b7280', fontSize: '1rem' }}></i>
            )}
          </h2>
          
          {incidentsLoading ? (
            <div style={{ 
              padding: '2rem', 
              textAlign: 'center', 
              background: isDarkMode ? 'var(--bg-primary)' : '#f9fafb', 
              border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, 
              borderRadius: '8px',
              color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
            }}>
              <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', marginBottom: '1rem', color: '#9ca3af' }}></i>
              <p style={{ margin: 0, fontWeight: '500' }}>Loading security news...</p>
            </div>
          ) : incidentsError ? (
            <div style={{ 
              padding: '2rem', 
              textAlign: 'center', 
              background: '#fef2f2', 
              border: '1px solid #fecaca', 
              borderRadius: '8px',
              color: '#dc2626'
            }}>
              <i className="fas fa-exclamation-triangle" style={{ fontSize: '2rem', marginBottom: '1rem', color: '#ef4444' }}></i>
              <p style={{ margin: 0, fontWeight: '500' }}>{incidentsError}</p>
            </div>
          ) : report?.incidents?.news && report.incidents.news.length > 0 ? (
            <div className="vulnerability-table-container" style={{
              maxHeight: '300px',
              overflowY: 'auto',
              border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
              borderRadius: '8px',
              background: isDarkMode ? 'var(--bg-secondary)' : 'white',
              marginBottom: '1rem'
            }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead style={{ position: 'sticky', top: 0, background: isDarkMode ? 'var(--bg-primary)' : '#eff6ff', zIndex: 10 }}>
                  <tr>
                    <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>DATE</th>
                    <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>TITLE</th>
                    <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>SEVERITY</th>
                    <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>SOURCE</th>
                  </tr>
                </thead>
                <tbody>
                  {report.incidents.news.map((newsItem: any, index: number) => (
                    <tr key={index} style={{ borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                      <td style={{ padding: '1rem', fontSize: '0.9rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                        {new Date(newsItem.date).toLocaleDateString()}
                      </td>
                      <td style={{ padding: '1rem', fontWeight: '500', color: isDarkMode ? 'var(--text-primary)' : '#1f2937' }}>
                        {newsItem.title}
                      </td>
                      <td style={{ padding: '1rem' }}>
                        <span className="severity-badge info" style={{
                          padding: '0.25rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          textTransform: 'uppercase'
                        }}>
                          INFO
                        </span>
                      </td>
                      <td style={{ padding: '1rem' }}>
                        {newsItem.source ? (
                          <a href={newsItem.source} target="_blank" rel="noopener noreferrer" style={{ color: '#3b82f6', textDecoration: 'none' }}>
                            Link
                          </a>
                        ) : (
                          <span style={{ color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>N/A</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ 
              padding: '2rem', 
              textAlign: 'center', 
              background: isDarkMode ? 'var(--bg-secondary)' : '#f0f9ff', 
              border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#bae6fd'}`, 
              borderRadius: '8px',
              color: isDarkMode ? 'var(--text-secondary)' : '#0c4a6e'
            }}>
              <i className="fas fa-info-circle" style={{ fontSize: '2rem', marginBottom: '1rem', color: isDarkMode ? 'var(--text-secondary)' : '#0ea5e9' }}></i>
              <p style={{ margin: 0, fontWeight: '500' }}>No recent security news found for this domain</p>
            </div>
          )}
        </div>

        {/* Report Footer */}
        <div style={{ 
          padding: '2rem',
          borderTop: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
          background: isDarkMode ? 'var(--bg-primary)' : '#f8fafc',
          borderRadius: '0 0 12px 12px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h4 style={{ margin: '0 0 0.5rem 0', color: isDarkMode ? 'var(--text-primary)' : '#1f2937' }}>Report Summary</h4>
              <p style={{ margin: 0, color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.9rem' }}>
                Generated on {new Date(report.generated_at).toLocaleString()}
              </p>
            </div>
            <div style={{ textAlign: 'right' }}>
              <p style={{ margin: 0, color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.9rem' }}>
                <strong>{report.summary.total_subdomains}</strong> subdomains analyzed<br />
                <strong>{report.summary.categories_with_issues}</strong> categories with issues<br />
                <strong>{report.summary.total_vulnerabilities}</strong> total vulnerabilities found
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerability Details Modal */}
      {modalOpen && selectedGroup && (
        <div 
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1rem'
          }}
          onClick={closeModal}
        >
          <div 
            style={{
              backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
              borderRadius: '12px',
              maxWidth: '800px',
              width: '100%',
              maxHeight: '80vh',
              overflow: 'hidden',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{
              padding: '1.5rem',
              borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <div>
                <h3 style={{ margin: 0, color: isDarkMode ? 'var(--text-primary)' : '#1f2937', fontSize: '1.25rem', fontWeight: '600' }}>
                  Vulnerability Details
                </h3>
                <p style={{ margin: '0.5rem 0 0 0', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.9rem' }}>
                  {selectedGroup.description}
                </p>
              </div>
              <button
                onClick={closeModal}
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '1.5rem',
                  color: '#6b7280',
                  cursor: 'pointer',
                  padding: '0.5rem',
                  borderRadius: '6px'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : '#f3f4f6';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                }}
              >
                <i className="fas fa-times"></i>
              </button>
            </div>

            {/* Modal Content */}
            <div style={{ padding: '1.5rem', maxHeight: 'calc(80vh - 120px)', overflowY: 'auto' }}>
              {/* Summary */}
              <div style={{ marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
                  <span className={`severity-badge ${selectedGroup.severity.toLowerCase()}`} style={{
                    padding: '0.5rem 1rem',
                    borderRadius: '6px',
                    fontSize: '0.875rem',
                    fontWeight: '600',
                    textTransform: 'uppercase'
                  }}>
                    {selectedGroup.severity}
                  </span>
                  <span style={{ color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.9rem' }}>
                    Affects {selectedGroup.affectedDomains.length} domain{selectedGroup.affectedDomains.length > 1 ? 's' : ''}
                  </span>
                </div>
                
                <div style={{ 
                  background: isDarkMode ? 'var(--bg-primary)' : '#f8fafc', 
                  padding: '1rem', 
                  borderRadius: '8px',
                  border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
                }}>
                  <h4 style={{ margin: '0 0 0.5rem 0', color: isDarkMode ? 'var(--text-primary)' : '#374151', fontSize: '0.9rem', fontWeight: '600' }}>
                    <i className="fas fa-server" style={{ marginRight: '0.5rem' }}></i>
                    Affected Domains
                  </h4>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {selectedGroup.affectedDomains.map((domain: string, index: number) => (
                      <span 
                        key={index}
                        style={{
                          background: isDarkMode ? 'rgba(59, 130, 246, 0.2)' : '#dbeafe',
                          color: isDarkMode ? '#60a5fa' : '#1e40af',
                          padding: '0.25rem 0.75rem',
                          borderRadius: '12px',
                          fontSize: '0.8rem',
                          fontWeight: '500'
                        }}
                      >
                        {domain}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* All Instances */}
              <div>
                <h4 style={{ 
                  margin: '0 0 1rem 0', 
                  color: isDarkMode ? 'var(--text-primary)' : '#374151', 
                  fontSize: '1rem', 
                  fontWeight: '600',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <i className="fas fa-list-ul"></i>
                  All Instances ({selectedGroup.vulnerabilities.length})
                </h4>
                
                <div className="vulnerability-table-container" style={{
                  maxHeight: '300px',
                  overflowY: 'auto',
                  border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                  borderRadius: '8px',
                  background: isDarkMode ? 'var(--bg-primary)' : 'white'
                }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead style={{ position: 'sticky', top: 0, background: isDarkMode ? 'var(--bg-secondary)' : '#f8fafc', zIndex: 10 }}>
                      <tr>
                        <th style={{ padding: '0.75rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', fontSize: '0.8rem', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>SUBDOMAIN</th>
                        <th style={{ padding: '0.75rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', fontSize: '0.8rem', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>SEVERITY</th>
                        <th style={{ padding: '0.75rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', fontSize: '0.8rem', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>DESCRIPTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedGroup.vulnerabilities.map((vuln: any, index: number) => (
                        <tr key={index} style={{ borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                          <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: isDarkMode ? 'var(--text-primary)' : '#1f2937', fontFamily: 'monospace' }}>
                            {vuln.subdomain || vuln.domain || 'N/A'}
                          </td>
                          <td style={{ padding: '0.75rem' }}>
                            <span className={`severity-badge ${vuln.severity.toLowerCase()}`} style={{
                              padding: '0.25rem 0.5rem',
                              borderRadius: '4px',
                              fontSize: '0.7rem',
                              fontWeight: '600',
                              textTransform: 'uppercase'
                            }}>
                              {vuln.severity}
                            </span>
                          </td>
                          <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', lineHeight: '1.4' }}>
                            {vuln.description || vuln.title || 'No description available'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
                     </div>
         </div>
       )}

       {/* Severity Filter Modal */}
       {severityFilterModal.open && (
         <div 
           style={{
             position: 'fixed',
             top: 0,
             left: 0,
             right: 0,
             bottom: 0,
             backgroundColor: 'rgba(0, 0, 0, 0.5)',
             display: 'flex',
             alignItems: 'center',
             justifyContent: 'center',
             zIndex: 1000,
             padding: '1rem'
           }}
           onClick={closeSeverityModal}
         >
           <div 
             style={{
               backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
               borderRadius: '12px',
               maxWidth: '900px',
               width: '100%',
               maxHeight: '80vh',
               overflow: 'hidden',
               boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
             }}
             onClick={(e) => e.stopPropagation()}
           >
             {/* Modal Header */}
             <div style={{
               padding: '1.5rem',
               borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb',
               display: 'flex',
               alignItems: 'center',
               justifyContent: 'space-between'
             }}>
               <div>
                 <h3 style={{ 
                   margin: 0, 
                   color: isDarkMode ? 'var(--text-primary)' : '#1f2937', 
                   fontSize: '1.25rem', 
                   fontWeight: '600' 
                 }}>
                   {severityFilterModal.severity} Severity Issues
                 </h3>
                 <p style={{ 
                   margin: '0.5rem 0 0 0', 
                   color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', 
                   fontSize: '0.9rem' 
                 }}>
                   All vulnerabilities with {severityFilterModal.severity.toLowerCase()} severity across all categories
                 </p>
               </div>
               <button
                 onClick={closeSeverityModal}
                 style={{
                   background: 'none',
                   border: 'none',
                   fontSize: '1.5rem',
                   color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                   cursor: 'pointer',
                   padding: '0.5rem',
                   borderRadius: '6px'
                 }}
                 onMouseEnter={(e) => {
                   e.currentTarget.style.backgroundColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : '#f3f4f6';
                 }}
                 onMouseLeave={(e) => {
                   e.currentTarget.style.backgroundColor = 'transparent';
                 }}
               >
                 <i className="fas fa-times"></i>
               </button>
             </div>

             {/* Modal Content */}
             <div style={{ padding: '1.5rem', maxHeight: 'calc(80vh - 120px)', overflowY: 'auto' }}>
               {/* Summary */}
               <div style={{ marginBottom: '1.5rem' }}>
                 <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
                   <span className={`severity-badge ${severityFilterModal.severity.toLowerCase()}`} style={{
                     padding: '0.5rem 1rem',
                     borderRadius: '6px',
                     fontSize: '0.875rem',
                     fontWeight: '600',
                     textTransform: 'uppercase'
                   }}>
                     {severityFilterModal.severity}
                   </span>
                   <span style={{ 
                     color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', 
                     fontSize: '0.9rem' 
                   }}>
                     {severityFilterModal.vulnerabilities.length} issue{severityFilterModal.vulnerabilities.length !== 1 ? 's' : ''} found
                   </span>
                 </div>
               </div>

               {/* All Issues Table */}
               <div>
                 <h4 style={{ 
                   margin: '0 0 1rem 0', 
                   color: isDarkMode ? 'var(--text-primary)' : '#374151', 
                   fontSize: '1rem', 
                   fontWeight: '600',
                   display: 'flex',
                   alignItems: 'center',
                   gap: '0.5rem'
                 }}>
                   <i className="fas fa-list-ul"></i>
                   All {severityFilterModal.severity} Issues ({severityFilterModal.vulnerabilities.length})
                 </h4>
                 
                 {severityFilterModal.vulnerabilities.length > 0 ? (
                   <div className="vulnerability-table-container" style={{
                     maxHeight: '400px',
                     overflowY: 'auto',
                     border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb',
                     borderRadius: '8px',
                     background: isDarkMode ? 'var(--bg-primary)' : 'white'
                   }}>
                     <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                       <thead style={{ 
                         position: 'sticky', 
                         top: 0, 
                         background: isDarkMode ? 'var(--bg-secondary)' : '#f8fafc', 
                         zIndex: 10 
                       }}>
                         <tr>
                           <th style={{ 
                             padding: '0.75rem', 
                             textAlign: 'left', 
                             borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb', 
                             fontWeight: '600', 
                             fontSize: '0.8rem',
                             color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                           }}>SUBDOMAIN</th>
                           <th style={{ 
                             padding: '0.75rem', 
                             textAlign: 'left', 
                             borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb', 
                             fontWeight: '600', 
                             fontSize: '0.8rem',
                             color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                           }}>TITLE</th>
                           <th style={{ 
                             padding: '0.75rem', 
                             textAlign: 'left', 
                             borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb', 
                             fontWeight: '600', 
                             fontSize: '0.8rem',
                             color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                           }}>DESCRIPTION</th>
                           <th style={{ 
                             padding: '0.75rem', 
                             textAlign: 'left', 
                             borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb', 
                             fontWeight: '600', 
                             fontSize: '0.8rem',
                             color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                           }}>CATEGORY</th>
                         </tr>
                       </thead>
                       <tbody>
                         {severityFilterModal.vulnerabilities.map((vuln: any, index: number) => (
                           <tr key={index} style={{ 
                             borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #f3f4f6' 
                           }}>
                             <td style={{ 
                               padding: '0.75rem', 
                               fontSize: '0.85rem', 
                               color: isDarkMode ? 'var(--text-primary)' : '#1f2937', 
                               fontFamily: 'monospace' 
                             }}>
                               {vuln.subdomain || vuln.domain || 'N/A'}
                             </td>
                             <td style={{ 
                               padding: '0.75rem', 
                               fontSize: '0.85rem', 
                               color: isDarkMode ? 'var(--text-primary)' : '#1f2937', 
                               fontWeight: '500' 
                             }}>
                               {vuln.title || 'N/A'}
                             </td>
                             <td style={{ 
                               padding: '0.75rem', 
                               fontSize: '0.85rem', 
                               color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', 
                               lineHeight: '1.4' 
                             }}>
                               {vuln.description || 'No description available'}
                             </td>
                             <td style={{ 
                               padding: '0.75rem', 
                               fontSize: '0.85rem', 
                               color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' 
                             }}>
                               {vuln.category || 'Unknown'}
                             </td>
                           </tr>
                         ))}
                       </tbody>
                     </table>
                   </div>
                 ) : (
                   <div style={{ 
                     padding: '2rem', 
                     textAlign: 'center', 
                     background: isDarkMode ? 'rgba(34, 197, 94, 0.1)' : '#f0fdf4', 
                     border: isDarkMode ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid #bbf7d0', 
                     borderRadius: '8px',
                     color: isDarkMode ? '#22c55e' : '#166534'
                   }}>
                     <i className="fas fa-shield-alt" style={{ fontSize: '2rem', marginBottom: '1rem', color: '#22c55e' }}></i>
                     <p style={{ 
                       margin: 0, 
                       fontWeight: '500',
                       color: isDarkMode ? '#22c55e' : '#166534'
                     }}>No {severityFilterModal.severity.toLowerCase()} severity issues found</p>
                   </div>
                 )}
               </div>
             </div>
           </div>
         </div>
       )}

       {/* Subdomain Details Modal */}
       {subdomainModal && (
         <div 
           style={{
             position: 'fixed',
             top: 0,
             left: 0,
             right: 0,
             bottom: 0,
             backgroundColor: 'rgba(0, 0, 0, 0.5)',
             display: 'flex',
             alignItems: 'center',
             justifyContent: 'center',
             zIndex: 1000,
             padding: '1rem'
           }}
           onClick={closeSubdomainModal}
         >
           <div 
             style={{
               backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
               borderRadius: '12px',
               maxWidth: '1000px',
               width: '100%',
               maxHeight: '90vh',
               overflow: 'hidden',
               boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
             }}
             onClick={(e) => e.stopPropagation()}
           >
             {/* Modal Header */}
             <div style={{
               padding: '1.5rem',
               borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
               display: 'flex',
               alignItems: 'center',
               justifyContent: 'space-between',
               background: isDarkMode ? 'var(--bg-primary)' : 'linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%)'
             }}>
               <div>
                 <h3 style={{ margin: 0, color: isDarkMode ? 'var(--text-primary)' : '#1f2937', fontSize: '1.5rem', fontWeight: '700' }}>
                   <i className="fas fa-sitemap" style={{ marginRight: '0.75rem', color: '#ef4444' }}></i>
                   Subdomain Analysis for {domain}
                 </h3>
                 <p style={{ margin: '0.5rem 0 0 0', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.9rem' }}>
                   Detailed subdomain discovery and status information
                 </p>
               </div>
               <button
                 onClick={closeSubdomainModal}
                 style={{
                   background: 'none',
                   border: 'none',
                   fontSize: '1.5rem',
                   color: '#6b7280',
                   cursor: 'pointer',
                   padding: '0.5rem',
                   borderRadius: '6px'
                 }}
                 onMouseEnter={(e) => {
                   e.currentTarget.style.backgroundColor = '#f3f4f6';
                 }}
                 onMouseLeave={(e) => {
                   e.currentTarget.style.backgroundColor = 'transparent';
                 }}
               >
                 <i className="fas fa-times"></i>
               </button>
             </div>

             {/* Modal Content */}
             <div style={{ maxHeight: 'calc(90vh - 120px)', overflowY: 'auto' }}>
               {subdomainData ? (
                 <>
                   {/* Statistics Section */}
                   <div style={{ padding: '1.5rem', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` }}>
                     <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginBottom: '2rem' }}>
                       {/* Left Column - Statistics Cards */}
                       <div>
                         <h3 style={{ margin: '0 0 1.5rem 0', color: isDarkMode ? 'var(--text-primary)' : '#374151', fontSize: '1.2rem', fontWeight: '600' }}>
                           Existing Subdomain Statistics
                         </h3>
                         <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                           {/* Total Subdomains */}
                           <div style={{
                             background: isDarkMode ? 'var(--bg-primary)' : 'white',
                             border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                             borderRadius: '8px',
                             padding: '1.5rem',
                             display: 'flex',
                             alignItems: 'center',
                             gap: '1rem'
                           }}>
                             <div style={{
                               background: '#ef4444',
                               borderRadius: '8px',
                               padding: '0.75rem',
                               display: 'flex',
                               alignItems: 'center',
                               justifyContent: 'center'
                             }}>
                               <i className="fas fa-sitemap" style={{ color: 'white', fontSize: '1.2rem' }}></i>
                             </div>
                             <div>
                               <div style={{ fontSize: '1.8rem', fontWeight: '700', color: isDarkMode ? 'var(--text-primary)' : '#1f2937', lineHeight: '1' }}>
                                 {subdomainData.count?.total || 0}
                               </div>
                               <div style={{ fontSize: '0.85rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontWeight: '500', marginTop: '0.25rem' }}>
                                 TOTAL SUBDOMAINS
                               </div>
                             </div>
                           </div>

                           {/* Active Subdomains */}
                           <div style={{
                             background: isDarkMode ? 'var(--bg-primary)' : 'white',
                             border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                             borderRadius: '8px',
                             padding: '1.5rem',
                             display: 'flex',
                             alignItems: 'center',
                             gap: '1rem'
                           }}>
                             <div style={{
                               background: '#10b981',
                               borderRadius: '8px',
                               padding: '0.75rem',
                               display: 'flex',
                               alignItems: 'center',
                               justifyContent: 'center'
                             }}>
                               <i className="fas fa-check-circle" style={{ color: 'white', fontSize: '1.2rem' }}></i>
                             </div>
                             <div>
                               <div style={{ fontSize: '1.8rem', fontWeight: '700', color: isDarkMode ? 'var(--text-primary)' : '#1f2937', lineHeight: '1' }}>
                                 {subdomainData.count?.alive || 0}
                               </div>
                               <div style={{ fontSize: '0.85rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontWeight: '500', marginTop: '0.25rem' }}>
                                 ACTIVE SUBDOMAINS
                               </div>
                             </div>
                           </div>

                           {/* Inactive Subdomains */}
                           <div style={{
                             background: isDarkMode ? 'var(--bg-primary)' : 'white',
                             border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                             borderRadius: '8px',
                             padding: '1.5rem',
                             display: 'flex',
                             alignItems: 'center',
                             gap: '1rem'
                           }}>
                             <div style={{
                               background: '#ef4444',
                               borderRadius: '8px',
                               padding: '0.75rem',
                               display: 'flex',
                               alignItems: 'center',
                               justifyContent: 'center'
                             }}>
                               <i className="fas fa-times-circle" style={{ color: 'white', fontSize: '1.2rem' }}></i>
                             </div>
                             <div>
                               <div style={{ fontSize: '1.8rem', fontWeight: '700', color: isDarkMode ? 'var(--text-primary)' : '#1f2937', lineHeight: '1' }}>
                                 {(subdomainData.count?.total || 0) - (subdomainData.count?.alive || 0)}
                               </div>
                               <div style={{ fontSize: '0.85rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontWeight: '500', marginTop: '0.25rem' }}>
                                 INACTIVE SUBDOMAINS
                               </div>
                             </div>
                           </div>

                           {/* Success Rate */}
                           <div style={{
                             background: isDarkMode ? 'var(--bg-primary)' : 'white',
                             border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                             borderRadius: '8px',
                             padding: '1.5rem',
                             display: 'flex',
                             alignItems: 'center',
                             gap: '1rem'
                           }}>
                             <div style={{
                               background: '#3b82f6',
                               borderRadius: '8px',
                               padding: '0.75rem',
                               display: 'flex',
                               alignItems: 'center',
                               justifyContent: 'center'
                             }}>
                               <i className="fas fa-percentage" style={{ color: 'white', fontSize: '1.2rem' }}></i>
                             </div>
                             <div>
                               <div style={{ fontSize: '1.8rem', fontWeight: '700', color: isDarkMode ? 'var(--text-primary)' : '#1f2937', lineHeight: '1' }}>
                                 {subdomainData.count?.total > 0 ? Math.round((subdomainData.count.alive / subdomainData.count.total) * 100) : 0}%
                               </div>
                               <div style={{ fontSize: '0.85rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontWeight: '500', marginTop: '0.25rem' }}>
                                 SUCCESS RATE
                               </div>
                             </div>
                           </div>
                         </div>
                       </div>

                       {/* Right Column - Pie Chart */}
                       <div>
                         <h3 style={{ margin: '0 0 1.5rem 0', color: isDarkMode ? 'var(--text-primary)' : '#374151', fontSize: '1.2rem', fontWeight: '600' }}>
                           Subdomain Status Distribution
                         </h3>
                         <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '300px' }}>
                           <PieChart
                             data={{
                               active: subdomainData.count?.alive || 0,
                               inactive: (subdomainData.count?.total || 0) - (subdomainData.count?.alive || 0)
                             }}
                           />
                         </div>
                       </div>
                     </div>
                   </div>

                   {/* Filter and Search Controls */}
                    <div style={{ padding: '1.5rem', borderBottom: '1px solid #f3f4f6' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                        <select 
                          value={subdomainFilter}
                          onChange={(e) => setSubdomainFilter(e.target.value)}
                          disabled={showExcludedSubdomains}
                          style={{
                            minWidth: '150px',
                            padding: '0.5rem',
                            border: '1px solid #d1d5db',
                            borderRadius: '6px',
                            fontSize: '0.875rem',
                            opacity: showExcludedSubdomains ? 0.5 : 1,
                            cursor: showExcludedSubdomains ? 'not-allowed' : 'pointer'
                          }}
                        >
                          <option value="all">All Subdomains</option>
                          <option value="active">Active Only</option>
                          <option value="inactive">Inactive Only</option>
                        </select>
                        
                        {/* Toggle Slider for Excluded Subdomains */}
                        <PermissionGate permission="exclude_subdomains">
                          <div style={{ 
                            display: 'flex', 
                            alignItems: 'center', 
                            gap: '0.75rem',
                            fontSize: '0.875rem',
                            color: '#374151'
                          }}>
                            <span>Show Excluded</span>
                            <div 
                              onClick={() => {
                                const newToggleState = !showExcludedSubdomains;
                                setShowExcludedSubdomains(newToggleState);
                                // Reset filter to active when turning off excluded view
                                if (!newToggleState) {
                                  setSubdomainFilter('active');
                                }
                              }}
                              style={{
                                position: 'relative',
                                width: '3rem',
                                height: '1.5rem',
                                background: showExcludedSubdomains 
                                  ? 'linear-gradient(135deg, #3b82f6, #1d4ed8)' 
                                  : '#e5e7eb',
                                borderRadius: '0.75rem',
                                cursor: 'pointer',
                                transition: 'all 0.3s ease',
                                boxShadow: showExcludedSubdomains 
                                  ? '0 2px 4px rgba(59, 130, 246, 0.3)' 
                                  : '0 1px 2px rgba(0, 0, 0, 0.1)'
                              }}
                            >
                              <div 
                                style={{
                                  position: 'absolute',
                                  top: '0.125rem',
                                  left: showExcludedSubdomains ? '1.625rem' : '0.125rem',
                                  width: '1.25rem',
                                  height: '1.25rem',
                                  background: 'white',
                                  borderRadius: '50%',
                                  transition: 'all 0.3s ease',
                                  boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
                                }}
                              />
                            </div>
                          </div>
                        </PermissionGate>
                       <input
                         type="text"
                         placeholder="Search subdomains..."
                         value={subdomainSearchTerm}
                         onChange={(e) => setSubdomainSearchTerm(e.target.value)}
                         style={{ 
                           minWidth: '200px',
                           padding: '0.5rem',
                           border: '1px solid #d1d5db',
                           borderRadius: '6px',
                           fontSize: '0.875rem',
                           flex: '1'
                         }}
                       />
                     </div>
                   </div>

                   {/* Add Manual Subdomain Section */}
                   {!showExcludedSubdomains && (
                     <PermissionGate permission="add_subdomains">
                       <div style={{ padding: '1.5rem', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}`, background: isDarkMode ? 'var(--bg-primary)' : '#fafbfc' }}>
                       <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                         <h4 style={{ margin: 0, color: isDarkMode ? 'var(--text-primary)' : '#374151', fontSize: '1rem', fontWeight: '600' }}>
                           <i className="fas fa-plus-circle" style={{ color: '#10b981', marginRight: '0.5rem' }}></i>
                           Add New Subdomain
                         </h4>
                         <button
                           onClick={() => setShowAddSubdomain(!showAddSubdomain)}
                           style={{
                             padding: '0.5rem 1rem',
                             borderRadius: '6px',
                             fontSize: '0.875rem',
                             fontWeight: '500',
                             background: showAddSubdomain 
                               ? 'linear-gradient(135deg, #ef4444, #dc2626)'
                               : 'linear-gradient(135deg, #10b981, #059669)',
                             color: 'white',
                             border: 'none',
                             cursor: 'pointer',
                             boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
                             transition: 'all 0.2s ease',
                             display: 'flex',
                             alignItems: 'center',
                             gap: '0.5rem'
                           }}
                           onMouseEnter={(e) => {
                             (e.target as HTMLButtonElement).style.transform = 'translateY(-1px)';
                             (e.target as HTMLButtonElement).style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.15)';
                           }}
                           onMouseLeave={(e) => {
                             (e.target as HTMLButtonElement).style.transform = 'translateY(0)';
                             (e.target as HTMLButtonElement).style.boxShadow = '0 2px 4px rgba(0, 0, 0, 0.1)';
                           }}
                         >
                           <i className={`fas fa-${showAddSubdomain ? 'times' : 'plus'}`}></i>
                           {showAddSubdomain ? 'Cancel' : 'Add New'}
                         </button>
                       </div>

                       {showAddSubdomain && (
                         <div style={{
                           background: isDarkMode ? 'var(--bg-secondary)' : 'white',
                           border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                           borderRadius: '8px',
                           padding: '1.5rem'
                         }}>
                           <p style={{ 
                             margin: '0 0 1rem 0', 
                             color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', 
                             fontSize: '0.875rem',
                             lineHeight: '1.5'
                           }}>
                             Add a subdomain manually. 
                             This is useful for known internal subdomains.
                           </p>
                           <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end' }}>
                             <div style={{ flex: 1 }}>
                               <label style={{
                                 display: 'block',
                                 fontSize: '0.875rem',
                                 fontWeight: '500',
                                 color: isDarkMode ? 'var(--text-primary)' : '#374151',
                                 marginBottom: '0.5rem'
                               }}>
                                 Subdomain
                               </label>
                               <input
                                 type="text"
                                 value={newSubdomainInput}
                                 onChange={(e) => setNewSubdomainInput(e.target.value)}
                                 placeholder="e.g., api.example.com"
                                 disabled={addingSubdomain}
                                 style={{
                                   width: '100%',
                                   padding: '0.75rem',
                                   border: '1px solid #d1d5db',
                                   borderRadius: '6px',
                                   fontSize: '0.875rem',
                                   fontFamily: 'monospace',
                                   background: addingSubdomain ? '#f9fafb' : 'white',
                                   color: addingSubdomain ? '#6b7280' : '#111827'
                                 }}
                                 onKeyPress={(e) => {
                                   if (e.key === 'Enter' && !addingSubdomain) {
                                     handleAddManualSubdomain();
                                   }
                                 }}
                               />
                             </div>
                             <button
                               onClick={handleAddManualSubdomain}
                               disabled={!newSubdomainInput.trim() || addingSubdomain}
                               style={{
                                 padding: '0.75rem 1.5rem',
                                 borderRadius: '6px',
                                 fontSize: '0.875rem',
                                 fontWeight: '600',
                                 background: (!newSubdomainInput.trim() || addingSubdomain)
                                   ? '#f3f4f6'
                                   : 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                                 color: (!newSubdomainInput.trim() || addingSubdomain) ? '#6b7280' : 'white',
                                 border: 'none',
                                 cursor: (!newSubdomainInput.trim() || addingSubdomain) ? 'not-allowed' : 'pointer',
                                 boxShadow: (!newSubdomainInput.trim() || addingSubdomain) 
                                   ? 'none' 
                                   : '0 2px 4px rgba(59, 130, 246, 0.3)',
                                 transition: 'all 0.2s ease',
                                 display: 'flex',
                                 alignItems: 'center',
                                 gap: '0.5rem',
                                 whiteSpace: 'nowrap'
                               }}
                               onMouseEnter={(e) => {
                                 if (!newSubdomainInput.trim() || addingSubdomain) return;
                                 (e.target as HTMLButtonElement).style.transform = 'translateY(-1px)';
                                 (e.target as HTMLButtonElement).style.boxShadow = '0 4px 8px rgba(59, 130, 246, 0.4)';
                               }}
                               onMouseLeave={(e) => {
                                 if (!newSubdomainInput.trim() || addingSubdomain) return;
                                 (e.target as HTMLButtonElement).style.transform = 'translateY(0)';
                                 (e.target as HTMLButtonElement).style.boxShadow = '0 2px 4px rgba(59, 130, 246, 0.3)';
                               }}
                             >
                               {addingSubdomain ? (
                                 <>
                                   <i className="fas fa-spinner fa-spin"></i>
                                   Adding...
                                 </>
                               ) : (
                                 <>
                                   <i className="fas fa-plus"></i>
                                   Add Subdomain
                                 </>
                               )}
                             </button>
                           </div>
                         </div>
                       )}
                     </div>
                     </PermissionGate>
                   )}

                   {/* Subdomain Table */}
                   <div style={{ padding: '1.5rem' }}>
                     <div style={{
                       maxHeight: '400px',
                       overflowY: 'auto',
                       border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                       borderRadius: '8px',
                       background: isDarkMode ? 'var(--bg-secondary)' : 'white'
                     }}>
                       <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                         <thead style={{ position: 'sticky', top: 0, background: isDarkMode ? 'var(--bg-primary)' : '#f8fafc', zIndex: 10 }}>
                           <tr>
                             <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>SUBDOMAIN</th>
                             <th style={{ padding: '1rem', textAlign: 'left', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>STATUS</th>
                             <th style={{ padding: '1rem', textAlign: 'center', borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`, fontWeight: '600', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>ACTIONS</th>
                           </tr>
                         </thead>
                         <tbody>
                           {(() => {
                             const subdomainDetails = subdomainData.subdomains?.details || [];
                             
                             // Create a combined list that always includes the main domain
                             const allSubdomains = [...subdomainDetails];
                             
                             // Check if main domain is already in the list
                             const mainDomainExists = subdomainDetails.some((sub: any) => sub.subdomain === domain);
                             
                             // If main domain doesn't exist in the list, add it
                             if (domain && !mainDomainExists) {
                               allSubdomains.unshift({
                                 subdomain: domain,
                                 status: 'Active',
                                 isMainDomain: true
                               });
                             } else {
                              // Mark the main domain in existing list
                              allSubdomains.forEach((sub: any) => {
                                if (sub.subdomain === domain) {
                                  sub.isMainDomain = true;
                                }
                              });
                            }
                            
                            // Create list of excluded subdomains for toggle mode
                            const excludedSubdomainsList = excludedSubdomains.map(excludedSubdomain => ({
                              subdomain: excludedSubdomain,
                              status: 'Excluded',
                              isExcluded: true
                            }));

                            // Apply filters
                            const filteredSubdomains = (() => {
                              if (showExcludedSubdomains) {
                                // When toggle is ON, show ONLY excluded subdomains
                                return excludedSubdomainsList.filter((subdomain: any) => {
                                  const subdomainName = subdomain.subdomain;
                                  // Apply search filter
                                  if (subdomainSearchTerm && !subdomainName.toLowerCase().includes(subdomainSearchTerm.toLowerCase())) return false;
                                  return true;
                                });
                              } else {
                                // When toggle is OFF, show active/inactive subdomains (no excluded ones)
                                return allSubdomains.filter((subdomain: any) => {
                                  const subdomainName = subdomain.subdomain;
                                  const status = subdomain.status;
                                  const isActive = status === 'Active' || status === 'active' || status === 'alive';
                                  const isExcluded = excludedSubdomains.includes(subdomainName);
                                  
                                  // Filter out excluded subdomains completely
                                  if (isExcluded) return false;
                                  
                                  // Apply status filter
                                  if (subdomainFilter === 'active' && !isActive) return false;
                                  if (subdomainFilter === 'inactive' && isActive) return false;
                                  
                                  // Apply search filter
                                  if (subdomainSearchTerm && !subdomainName.toLowerCase().includes(subdomainSearchTerm.toLowerCase())) return false;
                                  
                                  return true;
                                });
                              }
                            })();
                             
                             if (filteredSubdomains.length === 0) {
                               const emptyMessage = showExcludedSubdomains 
                                 ? 'No excluded subdomains found'
                                 : 'No subdomains found matching the current filter';
                               
                               return (
                                 <tr>
                                   <td colSpan={3} style={{ textAlign: 'center', padding: '2rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                                     {emptyMessage}
                                   </td>
                                 </tr>
                               );
                             }
                             
                             return filteredSubdomains.map((subdomain: any, index: number) => {
                               const subdomainName = subdomain.subdomain;
                               const status = subdomain.status;
                               const isActive = status === 'Active' || status === 'active' || status === 'alive';
                               const isExcluded = subdomain.isExcluded || excludedSubdomains.includes(subdomainName);
                               
                               return (
                                 <tr 
                                   key={index} 
                                   style={{ 
                                     borderBottom: `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}`,
                                     ...(subdomain.isMainDomain ? {
                                       background: isDarkMode 
                                         ? 'linear-gradient(135deg, rgba(59, 130, 246, 0.15), rgba(29, 78, 216, 0.08))'
                                         : 'linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(29, 78, 216, 0.05))',
                                       borderLeft: '4px solid #3b82f6'
                                     } : {})
                                   }}
                                 >
                                   <td style={{ padding: '1rem' }}>
                                     <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                       <i className="fas fa-globe" style={{ color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}></i>
                                       <span style={{ fontWeight: '500', fontFamily: 'monospace', color: isDarkMode ? 'var(--text-primary)' : 'inherit' }}>
                                         {subdomainName}
                                       </span>
                                       {subdomain.isMainDomain && (
                                         <span style={{
                                           background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                                           color: 'white',
                                           fontSize: '0.75rem',
                                           padding: '0.25rem 0.5rem',
                                           borderRadius: '12px',
                                           fontWeight: '500',
                                           display: 'inline-flex',
                                           alignItems: 'center',
                                           gap: '0.25rem'
                                         }}>
                                           <i className="fas fa-home" style={{ fontSize: '0.7rem' }}></i>
                                           Main Domain
                                         </span>
                                       )}
                                     </div>
                                   </td>
                                   <td style={{ padding: '1rem' }}>
                                     <span style={{
                                       padding: '0.375rem 0.75rem',
                                       borderRadius: '6px',
                                       fontSize: '0.75rem',
                                       fontWeight: '600',
                                       textTransform: 'uppercase',
                                       letterSpacing: '0.025em',
                                       background: isExcluded
                                         ? 'linear-gradient(135deg, #6b7280, #4b5563)'
                                         : isActive 
                                           ? 'linear-gradient(135deg, #10b981, #059669)' 
                                           : 'linear-gradient(135deg, #ef4444, #dc2626)',
                                       color: 'white',
                                       boxShadow: isExcluded
                                         ? '0 2px 4px rgba(107, 114, 128, 0.3)'
                                         : isActive 
                                           ? '0 2px 4px rgba(16, 185, 129, 0.3)' 
                                           : '0 2px 4px rgba(239, 68, 68, 0.3)'
                                     }}>
                                       {isExcluded ? 'EXCLUDED' : isActive ? 'ACTIVE' : 'INACTIVE'}
                                     </span>
                                   </td>
                                   <td style={{ padding: '1rem', textAlign: 'center' }}>
                                     {/* Show excluded status or exclude button */}
                                     {isExcluded ? (
                                       <span style={{
                                         padding: '0.375rem 0.75rem',
                                         borderRadius: '6px',
                                         fontSize: '0.75rem',
                                         fontWeight: '600',
                                         background: isDarkMode ? 'var(--bg-primary)' : '#f3f4f6',
                                         color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                                         border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`
                                       }}>
                                         EXCLUDED
                                       </span>
                                     ) : subdomain.isMainDomain ? (
                                       <span style={{
                                         padding: '0.375rem 0.75rem',
                                         borderRadius: '6px',
                                         fontSize: '0.75rem',
                                         fontWeight: '600',
                                         background: isDarkMode ? 'var(--bg-primary)' : '#f3f4f6',
                                         color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                                         border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`
                                       }}>
                                         MAIN DOMAIN
                                       </span>
                                     ) : (
                                       <PermissionGate 
                                         permission="exclude_subdomains"
                                         fallback={
                                           <span style={{
                                             padding: '0.375rem 0.75rem',
                                             borderRadius: '6px',
                                             fontSize: '0.75rem',
                                             fontWeight: '600',
                                             background: '#f3f4f6',
                                             color: '#6b7280',
                                             border: '1px solid #d1d5db'
                                           }}>
                                             -
                                           </span>
                                         }
                                       >
                                         <button
                                           onClick={() => handleExcludeSubdomain(subdomainName)}
                                           disabled={excludingSubdomains.has(subdomainName)}
                                           style={{
                                             padding: '0.375rem 0.75rem',
                                             borderRadius: '6px',
                                             fontSize: '0.75rem',
                                             fontWeight: '600',
                                             background: excludingSubdomains.has(subdomainName) 
                                               ? '#f3f4f6' 
                                               : 'linear-gradient(135deg, #ef4444, #dc2626)',
                                             color: excludingSubdomains.has(subdomainName) ? '#6b7280' : 'white',
                                             border: 'none',
                                             cursor: excludingSubdomains.has(subdomainName) ? 'not-allowed' : 'pointer',
                                             boxShadow: excludingSubdomains.has(subdomainName) 
                                               ? 'none' 
                                               : '0 2px 4px rgba(239, 68, 68, 0.3)',
                                             transition: 'all 0.2s ease',
                                             display: 'flex',
                                             alignItems: 'center',
                                             gap: '0.25rem',
                                             justifyContent: 'center'
                                           }}
                                           onMouseEnter={(e) => {
                                             if (!excludingSubdomains.has(subdomainName)) {
                                               (e.target as HTMLButtonElement).style.transform = 'translateY(-1px)';
                                               (e.target as HTMLButtonElement).style.boxShadow = '0 4px 8px rgba(239, 68, 68, 0.4)';
                                             }
                                           }}
                                           onMouseLeave={(e) => {
                                             if (!excludingSubdomains.has(subdomainName)) {
                                               (e.target as HTMLButtonElement).style.transform = 'translateY(0)';
                                               (e.target as HTMLButtonElement).style.boxShadow = '0 2px 4px rgba(239, 68, 68, 0.3)';
                                             }
                                           }}
                                         >
                                           {excludingSubdomains.has(subdomainName) ? (
                                             <>
                                               <i className="fas fa-spinner fa-spin"></i>
                                               EXCLUDING...
                                             </>
                                           ) : (
                                             <>
                                               <i className="fas fa-ban"></i>
                                               EXCLUDE
                                             </>
                                           )}
                                         </button>
                                       </PermissionGate>
                                     )}
                                   </td>
                                 </tr>
                               );
                             });
                           })()}
                         </tbody>
                       </table>
                     </div>
                   </div>
                 </>
               ) : (
                 <div style={{ 
                   padding: '3rem', 
                   textAlign: 'center', 
                   color: '#6b7280'
                 }}>
                   <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', marginBottom: '1rem' }}></i>
                   <p>Loading subdomain data...</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* PDF Export Modal */}
       {pdfExportModal && (
         <div className="modal-overlay" onClick={() => setPdfExportModal(false)}>
           <div className="modal-content" onClick={(e) => e.stopPropagation()}>
             <div className="modal-header">
               <h3>Download Report</h3>
               <button className="modal-close" onClick={() => setPdfExportModal(false)}>
                 <i className="fas fa-times"></i>
               </button>
             </div>
            <div className="modal-body">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <div>
                  <h4 style={{ margin: 0 }}>Choose Sections</h4>
                  <p style={{ margin: '0.25rem 0 0 0' }}>Select which sections to include in the comprehensive security report for {domain}:</p>
                </div>
                <button
                  onClick={() => {
                    const allSelected = Object.values(selectedSections).every(Boolean);
                    const newValue = !allSelected;
                    
                    // Update all sections
                    setSelectedSections({
                      securityScores: newValue,
                      aiInsights: newValue,
                      riskCards: newValue,
                      securityAnalysis: newValue,
                      securityIncidents: newValue,
                      securityNews: newValue
                    });
                    
                    // Also update all internal filters
                    setSectionFilters({
                      securityScores: {
                        dns: newValue,
                        domainReputation: newValue,
                        email: newValue,
                        encryption: newValue,
                        network: newValue,
                        website: newValue
                      },
                      securityAnalysis: {
                        dns: newValue,
                        domainReputation: newValue,
                        email: newValue,
                        encryption: newValue,
                        network: newValue,
                        website: newValue
                      }
                    });
                  }}
                  style={{
                    padding: '0.5rem 1rem',
                    fontSize: '0.875rem',
                    fontWeight: '600',
                    border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db',
                    borderRadius: '6px',
                    background: isDarkMode ? 'var(--bg-primary)' : 'white',
                    color: isDarkMode ? 'var(--text-primary)' : '#374151',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    whiteSpace: 'nowrap'
                  }}
                  onMouseEnter={(e) => {
                    (e.target as HTMLButtonElement).style.background = isDarkMode ? 'rgba(255, 255, 255, 0.05)' : '#f9fafb';
                  }}
                  onMouseLeave={(e) => {
                    (e.target as HTMLButtonElement).style.background = isDarkMode ? 'var(--bg-primary)' : 'white';
                  }}
                >
                  <i className={`fas fa-${Object.values(selectedSections).every(Boolean) ? 'times' : 'check-double'}`}></i>
                  {Object.values(selectedSections).every(Boolean) ? 'Deselect All' : 'Select All'}
                </button>
              </div>
              
              <div className="section-options">
                 <div className="section-option">
                   <div className="option-content">
                     <div className="option-icon">
                       <i className="fas fa-chart-bar"></i>
                     </div>
                     <div className="option-details">
                       <h5>Security Category Scores</h5>
                       <p>DNS, Domain Reputation, Email, Encryption, Network, Website security scores</p>
                       <div className="option-tags">
                         <span className="tag">Comprehensive</span>
                         <span className="tag">Detailed</span>
                       </div>
                       {selectedSections.securityScores && (
                         <div className="filter-options">
                           <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                             <h6 style={{ 
                               margin: 0,
                               color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                             }}>Select Scan Types:</h6>
                             <button
                               onClick={() => handleSelectAllFilters('securityScores', !areAllFiltersSelected('securityScores'))}
                               style={{
                                 padding: '0.25rem 0.75rem',
                                 fontSize: '0.75rem',
                                 fontWeight: '500',
                                 border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db',
                                 borderRadius: '4px',
                                 background: areAllFiltersSelected('securityScores') ? '#ef4444' : (isDarkMode ? 'var(--bg-primary)' : 'white'),
                                 color: areAllFiltersSelected('securityScores') ? 'white' : (isDarkMode ? 'var(--text-primary)' : '#374151'),
                                 cursor: 'pointer',
                                 transition: 'all 0.2s ease'
                               }}
                               onMouseEnter={(e) => {
                                 (e.target as HTMLButtonElement).style.transform = 'scale(1.05)';
                               }}
                               onMouseLeave={(e) => {
                                 (e.target as HTMLButtonElement).style.transform = 'scale(1)';
                               }}
                             >
                               <i className={`fas fa-${areAllFiltersSelected('securityScores') ? 'times' : 'check-double'}`} style={{ marginRight: '0.25rem' }}></i>
                               {areAllFiltersSelected('securityScores') ? 'Deselect All' : 'Select All'}
                             </button>
                           </div>
                           <div className="filter-grid">
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityScores.dns}
                                 onChange={() => handleFilterToggle('securityScores', 'dns')}
                               />
                               <span className="filter-checkmark"></span>
                               DNS Security
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityScores.domainReputation}
                                 onChange={() => handleFilterToggle('securityScores', 'domainReputation')}
                               />
                               <span className="filter-checkmark"></span>
                               Domain Reputation
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityScores.email}
                                 onChange={() => handleFilterToggle('securityScores', 'email')}
                               />
                               <span className="filter-checkmark"></span>
                               Email Security
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityScores.encryption}
                                 onChange={() => handleFilterToggle('securityScores', 'encryption')}
                               />
                               <span className="filter-checkmark"></span>
                               Encryption
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityScores.network}
                                 onChange={() => handleFilterToggle('securityScores', 'network')}
                               />
                               <span className="filter-checkmark"></span>
                               Network Security
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityScores.website}
                                 onChange={() => handleFilterToggle('securityScores', 'website')}
                               />
                               <span className="filter-checkmark"></span>
                               Website Security
                             </label>
                           </div>
                         </div>
                       )}
                     </div>
                   </div>
                   <label className="checkbox-container">
                     <input
                       type="checkbox"
                       checked={selectedSections.securityScores}
                       onChange={() => handleSectionToggle('securityScores')}
                     />
                     <span className="checkmark"></span>
                   </label>
                 </div>

                 <div className="section-option">
                   <div className="option-content">
                     <div className="option-icon">
                       <i className="fas fa-brain"></i>
                     </div>
                     <div className="option-details">
                       <h5>AI Analyst Insights</h5>
                       <p>AI-powered analysis and recommendations for security improvements</p>
                       <div className="option-tags">
                         <span className="tag">AI-Powered</span>
                         <span className="tag">Insights</span>
                       </div>
                     </div>
                   </div>
                   <label className="checkbox-container">
                     <input
                       type="checkbox"
                       checked={selectedSections.aiInsights}
                       onChange={() => handleSectionToggle('aiInsights')}
                     />
                     <span className="checkmark"></span>
                   </label>
                 </div>

                 <div className="section-option">
                   <div className="option-content">
                     <div className="option-icon">
                       <i className="fas fa-exclamation-triangle"></i>
                     </div>
                     <div className="option-details">
                       <h5>Risk Level Cards</h5>
                       <p>Summary cards showing critical, medium, and low risk counts</p>
                       <div className="option-tags">
                         <span className="tag">Summary</span>
                         <span className="tag">Risk Overview</span>
                       </div>
                     </div>
                   </div>
                   <label className="checkbox-container">
                     <input
                       type="checkbox"
                       checked={selectedSections.riskCards}
                       onChange={() => handleSectionToggle('riskCards')}
                     />
                     <span className="checkmark"></span>
                   </label>
                 </div>

                 <div className="section-option">
                   <div className="option-content">
                     <div className="option-icon">
                       <i className="fas fa-shield-alt"></i>
                     </div>
                     <div className="option-details">
                       <h5>Security Categories Analysis</h5>
                       <p>Detailed analysis for DNS, Domain Reputation, Email, Encryption, Network, Website</p>
                       <div className="option-tags">
                         <span className="tag">Detailed</span>
                         <span className="tag">Technical</span>
                       </div>
                       {selectedSections.securityAnalysis && (
                         <div className="filter-options">
                           <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                             <h6 style={{ margin: 0 }}>Select Analysis Types:</h6>
                             <button
                               onClick={() => handleSelectAllFilters('securityAnalysis', !areAllFiltersSelected('securityAnalysis'))}
                               style={{
                                 padding: '0.25rem 0.75rem',
                                 fontSize: '0.75rem',
                                 fontWeight: '500',
                                 border: '1px solid #d1d5db',
                                 borderRadius: '4px',
                                 background: areAllFiltersSelected('securityAnalysis') ? '#ef4444' : 'white',
                                 color: areAllFiltersSelected('securityAnalysis') ? 'white' : '#374151',
                                 cursor: 'pointer',
                                 transition: 'all 0.2s ease'
                               }}
                               onMouseEnter={(e) => {
                                 (e.target as HTMLButtonElement).style.transform = 'scale(1.05)';
                               }}
                               onMouseLeave={(e) => {
                                 (e.target as HTMLButtonElement).style.transform = 'scale(1)';
                               }}
                             >
                               <i className={`fas fa-${areAllFiltersSelected('securityAnalysis') ? 'times' : 'check-double'}`} style={{ marginRight: '0.25rem' }}></i>
                               {areAllFiltersSelected('securityAnalysis') ? 'Deselect All' : 'Select All'}
                             </button>
                           </div>
                           <div className="filter-grid">
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityAnalysis.dns}
                                 onChange={() => handleFilterToggle('securityAnalysis', 'dns')}
                               />
                               <span className="filter-checkmark"></span>
                               DNS Analysis
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityAnalysis.domainReputation}
                                 onChange={() => handleFilterToggle('securityAnalysis', 'domainReputation')}
                               />
                               <span className="filter-checkmark"></span>
                               Domain Reputation Analysis
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityAnalysis.email}
                                 onChange={() => handleFilterToggle('securityAnalysis', 'email')}
                               />
                               <span className="filter-checkmark"></span>
                               Email Security Analysis
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityAnalysis.encryption}
                                 onChange={() => handleFilterToggle('securityAnalysis', 'encryption')}
                               />
                               <span className="filter-checkmark"></span>
                               Encryption Analysis
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityAnalysis.network}
                                 onChange={() => handleFilterToggle('securityAnalysis', 'network')}
                               />
                               <span className="filter-checkmark"></span>
                               Network Security Analysis
                             </label>
                             <label className="filter-checkbox">
                               <input
                                 type="checkbox"
                                 checked={sectionFilters.securityAnalysis.website}
                                 onChange={() => handleFilterToggle('securityAnalysis', 'website')}
                               />
                               <span className="filter-checkmark"></span>
                               Website Security Analysis
                             </label>
                           </div>
                         </div>
                       )}
                     </div>
                   </div>
                   <label className="checkbox-container">
                     <input
                       type="checkbox"
                       checked={selectedSections.securityAnalysis}
                       onChange={() => handleSectionToggle('securityAnalysis')}
                     />
                     <span className="checkmark"></span>
                   </label>
                 </div>

                 <div className="section-option">
                   <div className="option-content">
                     <div className="option-icon">
                       <i className="fas fa-exclamation-circle"></i>
                     </div>
                     <div className="option-details">
                       <h5>Security Incidents</h5>
                       <p>Recent security incidents and breach information related to the domain</p>
                       <div className="option-tags">
                         <span className="tag">Incidents</span>
                         <span className="tag">Historical</span>
                       </div>
                     </div>
                   </div>
                   <label className="checkbox-container">
                     <input
                       type="checkbox"
                       checked={selectedSections.securityIncidents}
                       onChange={() => handleSectionToggle('securityIncidents')}
                     />
                     <span className="checkmark"></span>
                   </label>
                 </div>

                 <div className="section-option">
                   <div className="option-content">
                     <div className="option-icon">
                       <i className="fas fa-newspaper"></i>
                     </div>
                     <div className="option-details">
                       <h5>Security News</h5>
                       <p>Latest security news and updates relevant to the domain</p>
                       <div className="option-tags">
                         <span className="tag">News</span>
                         <span className="tag">Current</span>
                       </div>
                     </div>
                   </div>
                   <label className="checkbox-container">
                     <input
                       type="checkbox"
                       checked={selectedSections.securityNews}
                       onChange={() => handleSectionToggle('securityNews')}
                     />
                     <span className="checkmark"></span>
                   </label>
                 </div>
               </div>
             </div>
             <div className="modal-footer">
               <button className="btn-secondary" onClick={() => setPdfExportModal(false)}>
                 Cancel
               </button>
               <button 
                 className="btn-primary" 
                 onClick={handleExportPdf}
                 disabled={pdfExporting || !Object.values(selectedSections).some(Boolean)}
               >
                 {pdfExporting ? (
                   <>
                     <i className="fas fa-spinner fa-spin"></i>
                     Generating PDF...
                   </>
                 ) : (
                   <>
                     <i className="fas fa-download"></i>
                     Export PDF
                   </>
                 )}
               </button>
             </div>
           </div>
         </div>
       )}

      {/* Add Domain Modal */}
      {addDomainModal && (
        <div 
          className="modal-overlay" 
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}
          onClick={() => setAddDomainModal(false)}
        >
          <div 
            className="modal-content" 
            style={{
              backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
              borderRadius: '8px',
              padding: '2rem',
              maxWidth: '500px',
              width: '90%',
              maxHeight: '90vh',
              overflow: 'auto'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header" style={{ marginBottom: '1.5rem' }}>
              <h3 style={{ margin: 0, color: isDarkMode ? 'var(--text-primary)' : '#1f2937' }}>Additional Domains</h3>
              <p style={{ margin: '0.5rem 0 0 0', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.9rem' }}>
                Add Additional Domains For {report?.vendor.name}
              </p>
            </div>

            <div className="modal-body">
              <div className="form-group" style={{ marginBottom: '1rem' }}>
                <label 
                  htmlFor="newDomain" 
                  style={{ 
                    display: 'block', 
                    marginBottom: '0.5rem', 
                    fontWeight: '500',
                    color: '#374151',
                    textAlign: 'left'
                  }}
                >
                  Domain Name
                </label>
                <input
                  id="newDomain"
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="example.com"
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    fontSize: '1rem'
                  }}
                  disabled={domainLoading}
                />
              </div>

              {domainError && (
                <div 
                  className="error-message" 
                  style={{
                    color: '#ef4444',
                    fontSize: '0.875rem',
                    marginBottom: '1rem',
                    padding: '0.5rem',
                    backgroundColor: '#fef2f2',
                    border: '1px solid #fecaca',
                    borderRadius: '4px'
                  }}
                >
                  {domainError}
                </div>
              )}

              {/* Buttons directly below the form */}
              <div 
                className="modal-buttons" 
                style={{
                  display: 'flex',
                  gap: '1rem',
                  justifyContent: 'flex-end',
                  marginTop: '1rem'
                }}
              >
                <button
                  onClick={() => {
                    setAddDomainModal(false);
                    setNewDomain('');
                    setDomainError(null);
                  }}
                  style={{
                    padding: '0.75rem 1.5rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    backgroundColor: 'white',
                    color: '#374151',
                    cursor: 'pointer'
                  }}
                  disabled={domainLoading}
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddDomain}
                  style={{
                    padding: '0.75rem 1.5rem',
                    border: 'none',
                    borderRadius: '6px',
                    backgroundColor: '#ff444f',
                    color: 'white',
                    cursor: domainLoading ? 'not-allowed' : 'pointer',
                    opacity: domainLoading ? 0.6 : 1,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}
                  disabled={domainLoading || !newDomain.trim()}
                >
                  {domainLoading && <i className="fas fa-spinner fa-spin"></i>}
                  {domainLoading ? 'Adding...' : 'Add Domain'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal for Subdomain Exclusion */}
      {confirmExclusionModal.open && (
        <div 
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            backdropFilter: 'blur(4px)'
          }}
          onClick={() => setConfirmExclusionModal({ open: false, subdomain: '', state: 'confirm' })}
        >
          <div 
            style={{
              background: isDarkMode ? 'var(--bg-secondary)' : 'white',
              borderRadius: '12px',
              padding: '2rem',
              maxWidth: '500px',
              width: '90%',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
              position: 'relative'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div style={{ marginBottom: '1.5rem', textAlign: 'center' }}>
              <div style={{
                width: '4rem',
                height: '4rem',
                borderRadius: '50%',
                background: confirmExclusionModal.state === 'success' 
                  ? 'linear-gradient(135deg, #d1fae5, #10b981)' 
                  : confirmExclusionModal.state === 'error'
                  ? 'linear-gradient(135deg, #fecaca, #ef4444)'
                  : 'linear-gradient(135deg, #fef3c7, #f59e0b)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 1rem auto'
              }}>
                <i className={`fas ${
                  confirmExclusionModal.state === 'success' 
                    ? 'fa-check' 
                    : confirmExclusionModal.state === 'error'
                    ? 'fa-times'
                    : 'fa-exclamation-triangle'
                }`} style={{ 
                  fontSize: '1.5rem', 
                  color: confirmExclusionModal.state === 'success' 
                    ? '#047857' 
                    : confirmExclusionModal.state === 'error'
                    ? '#dc2626'
                    : '#d97706'
                }}></i>
              </div>
              <h3 style={{ 
                margin: 0, 
                fontSize: '1.25rem', 
                fontWeight: '600', 
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937' 
              }}>
                {confirmExclusionModal.state === 'success' 
                  ? 'Subdomain Excluded' 
                  : confirmExclusionModal.state === 'error'
                  ? 'Exclusion Failed'
                  : 'Exclude Subdomain'}
              </h3>
              <p style={{ 
                margin: '0.5rem 0 0 0', 
                color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', 
                fontSize: '0.9rem' 
              }}>
                {confirmExclusionModal.state === 'success' 
                  ? 'The subdomain has been successfully excluded from future scans'
                  : confirmExclusionModal.state === 'error'
                  ? 'There was an error excluding the subdomain'
                  : 'This action will permanently exclude the subdomain from future scans'}
              </p>
            </div>

            {/* Content */}
            <div style={{ marginBottom: '2rem' }}>
              {confirmExclusionModal.state === 'confirm' ? (
                <>
                  <p style={{ 
                    color: isDarkMode ? 'var(--text-primary)' : '#374151', 
                    fontSize: '0.95rem', 
                    lineHeight: '1.5',
                    margin: '0 0 1rem 0'
                  }}>
                    Are you sure you want to exclude <strong style={{ 
                      color: isDarkMode ? 'var(--text-primary)' : '#1f2937',
                      fontFamily: 'monospace',
                      background: isDarkMode ? 'var(--bg-primary)' : '#f3f4f6',
                      padding: '0.25rem 0.5rem',
                      borderRadius: '4px'
                    }}>{confirmExclusionModal.subdomain}</strong> from future scans?
                  </p>
                  <div style={{
                    background: isDarkMode ? 'rgba(245, 158, 11, 0.15)' : '#fef3c7',
                    border: `1px solid ${isDarkMode ? 'rgba(245, 158, 11, 0.3)' : '#f59e0b'}`,
                    borderRadius: '8px',
                    padding: '0.75rem',
                    fontSize: '0.875rem',
                    color: isDarkMode ? '#fbbf24' : '#92400e'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                      <i className="fas fa-info-circle" style={{ marginTop: '0.125rem' }}></i>
                      <div>
                        <strong>This will:</strong>
                        <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1rem' }}>
                          <li>Prevent it from being discovered in future scans</li>
                          <li>Exclude it from Security Scoring</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div style={{
                  background: confirmExclusionModal.state === 'success' 
                    ? (isDarkMode ? 'rgba(16, 185, 129, 0.15)' : '#f0fdf4')
                    : (isDarkMode ? 'rgba(239, 68, 68, 0.15)' : '#fef2f2'),
                  border: `1px solid ${confirmExclusionModal.state === 'success' ? '#10b981' : '#ef4444'}`,
                  borderRadius: '8px',
                  padding: '1rem',
                  fontSize: '0.95rem',
                  color: confirmExclusionModal.state === 'success' 
                    ? (isDarkMode ? '#34d399' : '#047857')
                    : (isDarkMode ? '#f87171' : '#dc2626'),
                  textAlign: 'center'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                    <i className={`fas ${confirmExclusionModal.state === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}`}></i>
                    <span style={{ fontWeight: '600' }}>
                      {confirmExclusionModal.message || 'Operation completed'}
                    </span>
                  </div>
                  {confirmExclusionModal.state === 'success' && (
                    <p style={{ 
                      margin: '0.75rem 0 0 0', 
                      fontSize: '0.875rem',
                      color: isDarkMode ? '#10b981' : '#065f46',
                      fontStyle: 'italic'
                    }}>
                      The subdomain will no longer appear in future scans or affect your security scores.
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Actions */}
            <div style={{ 
              display: 'flex', 
              gap: '0.75rem', 
              justifyContent: confirmExclusionModal.state === 'confirm' ? 'flex-end' : 'center'
            }}>
              {confirmExclusionModal.state === 'confirm' ? (
                <>
                  <button
                    onClick={() => setConfirmExclusionModal({ open: false, subdomain: '', state: 'confirm' })}
                    style={{
                      padding: '0.75rem 1.5rem',
                      borderRadius: '8px',
                      fontSize: '0.875rem',
                      fontWeight: '600',
                      background: isDarkMode ? 'var(--bg-primary)' : '#f3f4f6',
                      color: isDarkMode ? 'var(--text-primary)' : '#374151',
                      border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease'
                    }}
                    onMouseEnter={(e) => {
                      (e.target as HTMLButtonElement).style.background = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : '#e5e7eb';
                    }}
                    onMouseLeave={(e) => {
                      (e.target as HTMLButtonElement).style.background = isDarkMode ? 'var(--bg-primary)' : '#f3f4f6';
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmExclusion}
                    style={{
                      padding: '0.75rem 1.5rem',
                      borderRadius: '8px',
                      fontSize: '0.875rem',
                      fontWeight: '600',
                      background: 'linear-gradient(135deg, #ef4444, #dc2626)',
                      color: 'white',
                      border: 'none',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      boxShadow: '0 2px 4px rgba(239, 68, 68, 0.3)'
                    }}
                    onMouseEnter={(e) => {
                      (e.target as HTMLButtonElement).style.transform = 'translateY(-1px)';
                      (e.target as HTMLButtonElement).style.boxShadow = '0 4px 8px rgba(239, 68, 68, 0.4)';
                    }}
                    onMouseLeave={(e) => {
                      (e.target as HTMLButtonElement).style.transform = 'translateY(0)';
                      (e.target as HTMLButtonElement).style.boxShadow = '0 2px 4px rgba(239, 68, 68, 0.3)';
                    }}
                  >
                    <i className="fas fa-ban" style={{ marginRight: '0.5rem' }}></i>
                    Exclude Subdomain
                  </button>
                </>
              ) : (
                <button
                  onClick={() => setConfirmExclusionModal({ open: false, subdomain: '', state: 'confirm' })}
                  style={{
                    padding: '0.75rem 2rem',
                    borderRadius: '8px',
                    fontSize: '0.875rem',
                    fontWeight: '600',
                    background: confirmExclusionModal.state === 'success' 
                      ? 'linear-gradient(135deg, #10b981, #047857)' 
                      : 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                    color: 'white',
                    border: 'none',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                    boxShadow: confirmExclusionModal.state === 'success' 
                      ? '0 2px 4px rgba(16, 185, 129, 0.3)' 
                      : '0 2px 4px rgba(59, 130, 246, 0.3)'
                  }}
                  onMouseEnter={(e) => {
                    (e.target as HTMLButtonElement).style.transform = 'translateY(-1px)';
                    (e.target as HTMLButtonElement).style.boxShadow = confirmExclusionModal.state === 'success' 
                      ? '0 4px 8px rgba(16, 185, 129, 0.4)' 
                      : '0 4px 8px rgba(59, 130, 246, 0.4)';
                  }}
                  onMouseLeave={(e) => {
                    (e.target as HTMLButtonElement).style.transform = 'translateY(0)';
                    (e.target as HTMLButtonElement).style.boxShadow = confirmExclusionModal.state === 'success' 
                      ? '0 2px 4px rgba(16, 185, 129, 0.3)' 
                      : '0 2px 4px rgba(59, 130, 246, 0.3)';
                  }}
                >
                  {confirmExclusionModal.state === 'success' ? (
                    <>
                      <i className="fas fa-check" style={{ marginRight: '0.5rem' }}></i>
                      Got it!
                    </>
                  ) : (
                    <>
                      <i className="fas fa-redo" style={{ marginRight: '0.5rem' }}></i>
                      Try Again
                    </>
                  )}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Certifications Modal */}
      {certificationsModalOpen && (
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
          zIndex: 10000,
          padding: '1rem'
        }}
        onClick={(e) => {
          if (e.target === e.currentTarget && !updatingCertifications) {
            setCertificationsModalOpen(false);
          }
        }}
        >
          <div style={{
            backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
            borderRadius: '12px',
            padding: '2rem',
            maxWidth: '500px',
            width: '100%',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.3)',
            border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`
          }}
          onClick={(e) => e.stopPropagation()}
          >
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '1.5rem'
            }}>
              <h2 style={{
                margin: 0,
                fontSize: '1.5rem',
                fontWeight: 600,
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
              }}>
                <i className="fas fa-certificate" style={{ marginRight: '0.5rem', color: isDarkMode ? '#3b82f6' : '#2563eb' }}></i>
                Vendor Certifications
              </h2>
              <button
                onClick={() => !updatingCertifications && setCertificationsModalOpen(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '1.5rem',
                  color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                  cursor: updatingCertifications ? 'not-allowed' : 'pointer',
                  padding: '0.25rem',
                  opacity: updatingCertifications ? 0.5 : 1
                }}
                disabled={updatingCertifications}
              >
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div style={{
              marginBottom: '1.5rem',
              padding: '1rem',
              backgroundColor: isDarkMode ? 'rgba(59, 130, 246, 0.1)' : '#eff6ff',
              borderRadius: '8px',
              border: `1px solid ${isDarkMode ? 'rgba(59, 130, 246, 0.3)' : '#bfdbfe'}`
            }}>
              <p style={{
                margin: 0,
                fontSize: '0.9rem',
                color: isDarkMode ? 'var(--text-primary)' : '#374151',
                lineHeight: '1.5'
              }}>
                Select the Available Vendor Certifications.
              </p>
            </div>

            <div style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
              marginBottom: '1.5rem'
            }}>
              <label 
                htmlFor="cert-iso-27001"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  padding: '1rem',
                  borderRadius: '8px',
                  border: `2px solid ${certificationsForm.iso_27001 ? (isDarkMode ? '#3b82f6' : '#2563eb') : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                  backgroundColor: certificationsForm.iso_27001 ? (isDarkMode ? 'rgba(59, 130, 246, 0.1)' : '#eff6ff') : 'transparent',
                  cursor: updatingCertifications ? 'not-allowed' : 'pointer',
                  transition: 'all 0.2s ease',
                  width: '100%',
                  userSelect: 'none'
                }}
                onClick={(e) => {
                  if (!updatingCertifications) {
                    e.preventDefault();
                    setCertificationsForm({ ...certificationsForm, iso_27001: !certificationsForm.iso_27001 });
                  }
                }}
              >
                <input
                  id="cert-iso-27001"
                  type="checkbox"
                  checked={certificationsForm.iso_27001}
                  onChange={(e) => {
                    if (!updatingCertifications) {
                      e.stopPropagation();
                      setCertificationsForm({ ...certificationsForm, iso_27001: !certificationsForm.iso_27001 });
                    }
                  }}
                  onClick={(e) => e.stopPropagation()}
                  disabled={updatingCertifications}
                  style={{
                    width: '20px',
                    height: '20px',
                    cursor: updatingCertifications ? 'not-allowed' : 'pointer',
                    pointerEvents: updatingCertifications ? 'none' : 'auto'
                  }}
                />
                <div style={{ flex: 1, pointerEvents: 'none' }}>
                  <div style={{
                    fontWeight: 600,
                    fontSize: '1rem',
                    color: isDarkMode ? 'var(--text-primary)' : '#1f2937',
                    marginBottom: '0.25rem'
                  }}>
                    <i className="fas fa-shield-alt" style={{ marginRight: '0.5rem', color: '#3b82f6' }}></i>
                    ISO 27001
                  </div>
                  <div style={{
                    fontSize: '0.875rem',
                    color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
                  }}>
                    Information Security Management System
                  </div>
                </div>
              </label>

              <label 
                htmlFor="cert-soc2"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  padding: '1rem',
                  borderRadius: '8px',
                  border: `2px solid ${certificationsForm.soc2 ? (isDarkMode ? '#3b82f6' : '#2563eb') : (isDarkMode ? 'var(--border-color)' : '#e5e7eb')}`,
                  backgroundColor: certificationsForm.soc2 ? (isDarkMode ? 'rgba(59, 130, 246, 0.1)' : '#eff6ff') : 'transparent',
                  cursor: updatingCertifications ? 'not-allowed' : 'pointer',
                  transition: 'all 0.2s ease',
                  width: '100%',
                  userSelect: 'none'
                }}
                onClick={(e) => {
                  if (!updatingCertifications) {
                    e.preventDefault();
                    setCertificationsForm({ ...certificationsForm, soc2: !certificationsForm.soc2 });
                  }
                }}
              >
                <input
                  id="cert-soc2"
                  type="checkbox"
                  checked={certificationsForm.soc2}
                  onChange={(e) => {
                    if (!updatingCertifications) {
                      e.stopPropagation();
                      setCertificationsForm({ ...certificationsForm, soc2: !certificationsForm.soc2 });
                    }
                  }}
                  onClick={(e) => e.stopPropagation()}
                  disabled={updatingCertifications}
                  style={{
                    width: '20px',
                    height: '20px',
                    cursor: updatingCertifications ? 'not-allowed' : 'pointer',
                    pointerEvents: updatingCertifications ? 'none' : 'auto'
                  }}
                />
                <div style={{ flex: 1, pointerEvents: 'none' }}>
                  <div style={{
                    fontWeight: 600,
                    fontSize: '1rem',
                    color: isDarkMode ? 'var(--text-primary)' : '#1f2937',
                    marginBottom: '0.25rem'
                  }}>
                    <i className="fas fa-check-circle" style={{ marginRight: '0.5rem', color: '#10b981' }}></i>
                    SOC 2
                  </div>
                  <div style={{
                    fontSize: '0.875rem',
                    color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
                  }}>
                    System and Organization Controls 2
                  </div>
                </div>
              </label>
            </div>

            <div style={{
              display: 'flex',
              gap: '0.75rem',
              justifyContent: 'flex-end'
            }}>
              <button
                onClick={() => {
                  if (!updatingCertifications) {
                    setCertificationsModalOpen(false);
                  }
                }}
                disabled={updatingCertifications}
                style={{
                  padding: '0.75rem 1.5rem',
                  borderRadius: '8px',
                  fontSize: '0.875rem',
                  fontWeight: 600,
                  background: isDarkMode ? 'var(--bg-primary)' : '#f3f4f6',
                  color: isDarkMode ? 'var(--text-primary)' : '#374151',
                  border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#d1d5db'}`,
                  cursor: updatingCertifications ? 'not-allowed' : 'pointer',
                  transition: 'all 0.2s ease',
                  opacity: updatingCertifications ? 0.5 : 1
                }}
                onMouseEnter={(e) => {
                  if (!updatingCertifications) {
                    (e.target as HTMLButtonElement).style.background = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : '#e5e7eb';
                  }
                }}
                onMouseLeave={(e) => {
                  (e.target as HTMLButtonElement).style.background = isDarkMode ? 'var(--bg-primary)' : '#f3f4f6';
                }}
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  if (updatingCertifications) return;
                  
                  setUpdatingCertifications(true);
                  try {
                    await certificationApi.updateCertifications(domain, {
                      iso_27001: certificationsForm.iso_27001,
                      soc2: certificationsForm.soc2
                    });
                    
                    // Refresh the report to show updated certifications
                    const updatedReport = await reportApi.getVulnerabilityReport(domain, true);
                    setReport(updatedReport);
                    
                    setNotification({
                      show: true,
                      type: 'success',
                      title: 'Certifications Updated',
                      message: 'Vendor certifications have been updated successfully.'
                    });
                    
                    setTimeout(() => {
                      setNotification({ show: false, type: 'info', message: '' });
                    }, 3000);
                    
                    setCertificationsModalOpen(false);
                  } catch (error: any) {
                    console.error('Error updating certifications:', error);
                    setNotification({
                      show: true,
                      type: 'error',
                      title: 'Update Failed',
                      message: error?.response?.data?.detail || 'Failed to update certifications. Please try again.'
                    });
                    
                    setTimeout(() => {
                      setNotification({ show: false, type: 'info', message: '' });
                    }, 5000);
                  } finally {
                    setUpdatingCertifications(false);
                  }
                }}
                disabled={updatingCertifications}
                style={{
                  padding: '0.75rem 1.5rem',
                  borderRadius: '8px',
                  fontSize: '0.875rem',
                  fontWeight: 600,
                  background: updatingCertifications 
                    ? (isDarkMode ? '#4b5563' : '#9ca3af')
                    : (isDarkMode ? 'linear-gradient(135deg, #3b82f6, #1d4ed8)' : 'linear-gradient(135deg, #2563eb, #1e40af)'),
                  color: 'white',
                  border: 'none',
                  cursor: updatingCertifications ? 'not-allowed' : 'pointer',
                  transition: 'all 0.2s ease',
                  boxShadow: updatingCertifications ? 'none' : (isDarkMode ? '0 2px 4px rgba(59, 130, 246, 0.3)' : '0 2px 4px rgba(37, 99, 235, 0.3)'),
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}
                onMouseEnter={(e) => {
                  if (!updatingCertifications) {
                    (e.target as HTMLButtonElement).style.transform = 'translateY(-1px)';
                    (e.target as HTMLButtonElement).style.boxShadow = isDarkMode ? '0 4px 8px rgba(59, 130, 246, 0.4)' : '0 4px 8px rgba(37, 99, 235, 0.4)';
                  }
                }}
                onMouseLeave={(e) => {
                  (e.target as HTMLButtonElement).style.transform = 'translateY(0)';
                  (e.target as HTMLButtonElement).style.boxShadow = updatingCertifications ? 'none' : (isDarkMode ? '0 2px 4px rgba(59, 130, 246, 0.3)' : '0 2px 4px rgba(37, 99, 235, 0.3)');
                }}
              >
                {updatingCertifications ? (
                  <>
                    <i className="fas fa-spinner fa-spin"></i>
                    Updating...
                  </>
                ) : (
                  <>
                    <i className="fas fa-save"></i>
                    Save Certifications
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Notification Toast */}
      {notification.show && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          zIndex: 10000,
          maxWidth: '400px',
          background: 'white',
          borderRadius: '8px',
          boxShadow: '0 10px 25px rgba(0, 0, 0, 0.1)',
          border: `3px solid ${
            notification.type === 'success' ? '#10b981' : 
            notification.type === 'error' ? '#ef4444' : '#3b82f6'
          }`,
          overflow: 'hidden',
          transform: 'translateX(0)',
          transition: 'all 0.3s ease-out'
        }}>
          <div style={{
            padding: '1rem',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.75rem'
          }}>
            <div style={{
              flexShrink: 0,
              width: '24px',
              height: '24px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: notification.type === 'success' ? '#10b981' : 
                         notification.type === 'error' ? '#ef4444' : '#3b82f6',
              color: 'white',
              fontSize: '14px',
              fontWeight: '600'
            }}>
              <i className={`fas fa-${
                notification.type === 'success' ? 'check' : 
                notification.type === 'error' ? 'times' : 'info'
              }`}></i>
            </div>
            <div style={{ flex: 1 }}>
              {notification.title && (
                <h4 style={{
                  margin: '0 0 0.25rem 0',
                  fontSize: '1rem',
                  fontWeight: '600',
                  color: '#1f2937'
                }}>
                  {notification.title}
                </h4>
              )}
              <p style={{
                margin: 0,
                fontSize: '0.875rem',
                color: '#6b7280',
                lineHeight: '1.4'
              }}>
                {notification.message}
              </p>
            </div>
            <button
              onClick={() => setNotification(prev => ({ ...prev, show: false }))}
              style={{
                background: 'none',
                border: 'none',
                color: '#9ca3af',
                cursor: 'pointer',
                padding: '0.25rem',
                borderRadius: '4px',
                fontSize: '18px',
                lineHeight: '1'
              }}
              onMouseEnter={(e) => {
                (e.target as HTMLButtonElement).style.color = '#6b7280';
                (e.target as HTMLButtonElement).style.background = '#f3f4f6';
              }}
              onMouseLeave={(e) => {
                (e.target as HTMLButtonElement).style.color = '#9ca3af';
                (e.target as HTMLButtonElement).style.background = 'none';
              }}
            >
              <i className="fas fa-times"></i>
            </button>
          </div>
        </div>
      )}

      {/* No Vulnerabilities Modal */}
      {noVulnerabilitiesModal.open && (
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
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: isDarkMode ? '#1f2937' : 'white',
            borderRadius: '12px',
            padding: '2rem',
            maxWidth: '400px',
            width: '90%',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
            position: 'relative'
          }}>
            <button
              onClick={() => setNoVulnerabilitiesModal({ open: false, category: '' })}
              style={{
                position: 'absolute',
                top: '1rem',
                right: '1rem',
                background: 'none',
                border: 'none',
                fontSize: '1.2rem',
                cursor: 'pointer',
                color: isDarkMode ? '#9ca3af' : '#6b7280',
                padding: '0.5rem',
                borderRadius: '50%',
                transition: 'all 0.2s'
              }}
              onMouseEnter={(e) => {
                (e.target as HTMLButtonElement).style.color = isDarkMode ? '#ffffff' : '#374151';
                (e.target as HTMLButtonElement).style.backgroundColor = isDarkMode ? '#374151' : '#f3f4f6';
              }}
              onMouseLeave={(e) => {
                (e.target as HTMLButtonElement).style.color = isDarkMode ? '#9ca3af' : '#6b7280';
                (e.target as HTMLButtonElement).style.backgroundColor = 'transparent';
              }}
            >
              <i className="fas fa-times"></i>
            </button>

            <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
              {(() => {
                const category = noVulnerabilitiesModal.category.toLowerCase();
                let iconClass = 'fas fa-shield-alt';
                let bgColor = '#10b981';

                // Category-specific icons and colors
                if (category.includes('website') || category.includes('web')) {
                  iconClass = 'fas fa-globe';
                  bgColor = '#3b82f6';
                } else if (category.includes('dns') || category.includes('domain')) {
                  iconClass = 'fas fa-network-wired';
                  bgColor = '#8b5cf6';
                } else if (category.includes('network')) {
                  iconClass = 'fas fa-server';
                  bgColor = '#f59e0b';
                } else if (category.includes('email')) {
                  iconClass = 'fas fa-envelope';
                  bgColor = '#ef4444';
                } else if (category.includes('encryption')) {
                  iconClass = 'fas fa-lock';
                  bgColor = '#06b6d4';
                } else if (category.includes('reputation')) {
                  iconClass = 'fas fa-star';
                  bgColor = '#ec4899';
                }

                return (
                  <div style={{
                    width: '60px',
                    height: '60px',
                    borderRadius: '50%',
                    backgroundColor: bgColor,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 1rem',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)'
                  }}>
                    <i className={iconClass} style={{ color: 'white', fontSize: '1.8rem' }}></i>
                  </div>
                );
              })()}

              <h3 style={{
                margin: '0 0 0.5rem 0',
                color: isDarkMode ? '#10b981' : '#065f46',
                fontSize: '1.5rem',
                fontWeight: '600'
              }}>
                Perfect Security Score
              </h3>

              <p style={{
                margin: '0',
                color: isDarkMode ? 'var(--text-primary)' : '#374151',
                fontSize: '1rem',
                lineHeight: '1.5'
              }}>
                <strong>{noVulnerabilitiesModal.category}</strong> has no vulnerabilities - perfect score!
              </p>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
              <button
                onClick={() => setNoVulnerabilitiesModal({ open: false, category: '' })}
                style={{
                  padding: '0.75rem 1.5rem',
                  backgroundColor: isDarkMode ? '#374151' : '#e5e7eb',
                  color: isDarkMode ? 'var(--text-primary)' : '#374151',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontWeight: '500',
                  transition: 'all 0.2s'
                }}
                onMouseEnter={(e) => {
                  (e.target as HTMLButtonElement).style.backgroundColor = isDarkMode ? '#4b5563' : '#d1d5db';
                }}
                onMouseLeave={(e) => {
                  (e.target as HTMLButtonElement).style.backgroundColor = isDarkMode ? '#374151' : '#e5e7eb';
                }}
              >
                <i className="fas fa-check"></i> Great!
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportPage; 