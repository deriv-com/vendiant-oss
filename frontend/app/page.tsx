'use client';

import React, { useState, useEffect, useMemo, useCallback, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Layout from '../components/Layout';
import { usePermission, PermissionGate, useIsAdmin } from '../lib/rbac';
import { dashboardApi, vendorApi, scanApi, subdomainApi, reportApi, incidentApi, certificationApi, backgroundScanApi, cacheUtils, type DashboardStats, type Vendor, type RecentScan, type CertificationResult, type CertificationStats, type BackgroundScanJob } from '../lib/api';
import SearchableDropdown from '../components/SearchableDropdown';
import PieChart from '../components/PieChart';
import BreachChecker from '../components/BreachChecker';
import VendorComparison from '../components/VendorComparison';
import EditVendorModal from '../components/EditVendorModal';
import BreachMonitorPanel, {
  type BreachMonitorDateField,
  type BreachMonitorLeakView,
} from '../components/BreachMonitorPanel';
import { logger } from '../lib/logger';
import { logUserAction } from '../lib/api-client';
import { getVendorLogoUrl } from '../lib/vendor-utils';
import VendorLogoImage from '../components/VendorLogoImage';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
// @ts-ignore - Line is exported from react-chartjs-2 but TypeScript types may not resolve correctly
import { Line } from 'react-chartjs-2';


// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface StatCardProps {
  title: string;
  value: string | number;
  icon: string;
  iconClass: string;
  change?: string;
  changeType?: 'positive' | 'negative';
  onClick?: () => void;
}

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

const BREACH_MONITOR_QUOTA_DISPLAY_CAP = 36000;

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, iconClass, change, changeType, onClick }) => (
  <div className={`stat-card ${onClick ? 'clickable-stat-card' : ''}`} onClick={onClick}>
    <div className={`stat-icon ${iconClass}`}>
      <i className={icon}></i>
    </div>
    <div className="stat-content">
      <h3>{value}</h3>
      <p>{title}</p>
      {change && (
        <span className={`stat-change ${changeType}`}>
          <i className={`fas fa-arrow-${changeType === 'positive' ? 'up' : 'down'}`}></i>
          {change}
        </span>
      )}
    </div>
    {onClick && (
      <div className="stat-card-hover-hint">
        <i className="fas fa-arrow-right"></i>
      </div>
    )}
  </div>
);

const Dashboard = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const isAdmin = useIsAdmin();
  const canViewVendors = usePermission('view_vendors');
  const canViewSecurityScans = usePermission('view_security_scans');
  const canViewSubdomains = usePermission('view_subdomains');
  const canViewInternalBreaches = usePermission('view_internal_breaches');
  const canViewCertifications = usePermission('view_certifications');
  const canViewIncidents = usePermission('view_incidents');
  const canViewPwnMonitor = usePermission('view_pwn_monitor');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [vendors, setVendors] = useState<Vendor[]>([]);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [vendorSearchTerm, setVendorSearchTerm] = useState('');

  // Dark mode hook
  const useDarkMode = () => {
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

  const isDarkMode = useDarkMode();

  // Subdomain Discovery State
  const [selectedDomain, setSelectedDomain] = useState('');
  const [customDomain, setCustomDomain] = useState('');
  const [subdomainResults, setSubdomainResults] = useState<any>(null);
  const [subdomainLoading, setSubdomainLoading] = useState(false);
  const [existingSubdomains, setExistingSubdomains] = useState<any>(null);
  const [subdomainFilter, setSubdomainFilter] = useState('all');
  const [subdomainSearchTerm, setSubdomainSearchTerm] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [pollInterval, setPollInterval] = useState<NodeJS.Timeout | null>(null);

  // Log Viewer State
  const [showLogViewer, setShowLogViewer] = useState(false);

  // Background Scan State
  const [isBackgroundScanRunning, setIsBackgroundScanRunning] = useState(false);
  const [activeBackgroundJobId, setActiveBackgroundJobId] = useState<string | null>(null);
  const [backgroundScanProgress, setBackgroundScanProgress] = useState(0);
  const [backgroundScanCurrentDomain, setBackgroundScanCurrentDomain] = useState<string>('');
  const [backgroundScanStage, setBackgroundScanStage] = useState<string>('');
  const [monitoringJobId, setMonitoringJobId] = useState<string | null>(null); // Track which job we're monitoring
  const [showSubdomainOptionModal, setShowSubdomainOptionModal] = useState(false);
  const [scanCheckpointVendor, setScanCheckpointVendor] = useState<string>('');
  const [showCheckpointDropdown, setShowCheckpointDropdown] = useState(false);
  const [resumeInfo, setResumeInfo] = useState<any>(null);
  const [loadingResumeInfo, setLoadingResumeInfo] = useState(false);
  const [scanMode, setScanMode] = useState<'new' | 'continue' | null>(null);

  // Website Vulnerability Scans State
  const [websiteSelectedDomain, setWebsiteSelectedDomain] = useState('');
  const [websiteCustomDomain, setWebsiteCustomDomain] = useState('');
  const [vulnerabilityResults, setVulnerabilityResults] = useState<any>(null);
  const [vulnerabilityLoading, setVulnerabilityLoading] = useState(false);
  const [vulnerabilityFilter, setVulnerabilityFilter] = useState('all');
  const [vulnerabilitySearchTerm, setVulnerabilitySearchTerm] = useState('');
  const [vulnerabilityProgress, setVulnerabilityProgress] = useState(0);
  const [vulnerabilityStatus, setVulnerabilityStatus] = useState('');
  const [selectedVulnerability, setSelectedVulnerability] = useState<{ title: string, vulnerabilities: any[] } | null>(null);

  // Domain Reputation Scans State
  const [reputationSelectedDomain, setReputationSelectedDomain] = useState('');
  const [reputationCustomDomain, setReputationCustomDomain] = useState('');
  const [reputationResults, setReputationResults] = useState<any>(null);
  const [reputationLoading, setReputationLoading] = useState(false);
  const [reputationFilter, setReputationFilter] = useState('all');
  const [reputationSearchTerm, setReputationSearchTerm] = useState('');
  const [reputationProgress, setReputationProgress] = useState(0);
  const [reputationStatus, setReputationStatus] = useState('');
  const [selectedReputationIssue, setSelectedReputationIssue] = useState<{ title: string, vulnerabilities: any[] } | null>(null);

  // Network Scans State
  const [networkSelectedDomain, setNetworkSelectedDomain] = useState('');
  const [networkCustomDomain, setNetworkCustomDomain] = useState('');
  const [networkResults, setNetworkResults] = useState<any>(null);
  const [networkLoading, setNetworkLoading] = useState(false);
  const [networkFilter, setNetworkFilter] = useState('all');
  const [networkSearchTerm, setNetworkSearchTerm] = useState('');
  const [networkProgress, setNetworkProgress] = useState(0);
  const [networkStatus, setNetworkStatus] = useState('');
  const [selectedNetworkIssue, setSelectedNetworkIssue] = useState<{ title: string, vulnerabilities: any[] } | null>(null);
  const [networkScanId, setNetworkScanId] = useState<string | null>(null);

  // DNS Security Scans State
  const [dnsSelectedDomain, setDnsSelectedDomain] = useState('');
  const [dnsCustomDomain, setDnsCustomDomain] = useState('');
  const [dnsResults, setDnsResults] = useState<any>(null);
  const [dnsLoading, setDnsLoading] = useState(false);
  const [dnsFilter, setDnsFilter] = useState('all');
  const [dnsSearchTerm, setDnsSearchTerm] = useState('');
  const [dnsProgress, setDnsProgress] = useState(0);
  const [dnsStatus, setDnsStatus] = useState('');
  const [selectedDnsIssue, setSelectedDnsIssue] = useState<{ title: string, vulnerabilities: any[] } | null>(null);

  // Encryption Scans State
  const [encryptionSelectedDomain, setEncryptionSelectedDomain] = useState('');
  const [encryptionCustomDomain, setEncryptionCustomDomain] = useState('');
  const [encryptionResults, setEncryptionResults] = useState<any>(null);
  const [encryptionLoading, setEncryptionLoading] = useState(false);
  const [encryptionFilter, setEncryptionFilter] = useState('all');
  const [encryptionSearchTerm, setEncryptionSearchTerm] = useState('');
  const [encryptionProgress, setEncryptionProgress] = useState(0);
  const [encryptionStatus, setEncryptionStatus] = useState('');
  const [selectedEncryptionIssue, setSelectedEncryptionIssue] = useState<{ title: string, vulnerabilities: any[] } | null>(null);
  const [encryptionScanId, setEncryptionScanId] = useState<string | null>(null);

  // Email Scans State
  const [emailSelectedDomain, setEmailSelectedDomain] = useState('');
  const [emailCustomDomain, setEmailCustomDomain] = useState('');
  const [emailResults, setEmailResults] = useState<any>(null);
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailFilter, setEmailFilter] = useState('all');
  const [emailSearchTerm, setEmailSearchTerm] = useState('');
  const [emailProgress, setEmailProgress] = useState(0);
  const [selectedEmailIssue, setSelectedEmailIssue] = useState<{ title: string, vulnerabilities: any[] } | null>(null);
  const [emailScanId, setEmailScanId] = useState<string | null>(null);

  // News & Incidents State
  const [incidentsSelectedDomain, setIncidentsSelectedDomain] = useState('');
  const [incidentsCustomDomain, setIncidentsCustomDomain] = useState('');
  const [incidentsResults, setIncidentsResults] = useState<any>(null);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsFilter, setIncidentsFilter] = useState('all');
  const [incidentsSearchTerm, setIncidentsSearchTerm] = useState('');
  const [newsFilter, setNewsFilter] = useState('all');
  const [newsSearchTerm, setNewsSearchTerm] = useState('');
  const [incidentsMonths, setIncidentsMonths] = useState(12);


  // Certifications State
  const [certificationsData, setCertificationsData] = useState<CertificationResult | null>(null);
  const [certificationsStats, setCertificationsStats] = useState<CertificationStats | null>(null);
  const [certificationsLoading, setCertificationsLoading] = useState(false);
  const [certificationsSearchTerm, setCertificationsSearchTerm] = useState('');
  const [selectedFilters, setSelectedFilters] = useState({
    iso_27001: false,
    soc2: false,
    both_certifications: false,
    no_certifications: false
  });

  // Breach Monitor states
  const [breachMonitorBreaches, setBreachMonitorPanel] = useState<any[]>([]);
  const [breachMonitorLoading, setBreachMonitorLoading] = useState(false);
  const [breachMonitorApiCallsRemaining, setBreachMonitorApiCallsRemaining] = useState(0);
  const [breachMonitorDateFrom, setBreachMonitorDateFrom] = useState('');
  const [breachMonitorDateTo, setBreachMonitorDateTo] = useState('');
  const [breachMonitorDateField, setBreachMonitorDateField] =
    useState<BreachMonitorDateField>('ingested');
  const [breachMonitorLeakView, setBreachMonitorLeakView] = useState<BreachMonitorLeakView>('employees');

  const refreshBreachMonitorQuota = useCallback(async () => {
    if (!canViewInternalBreaches) return;
    try {
      const res = await fetch('/api/breach-monitor/quota');
      if (!res.ok) return;
      const data = await res.json();
      if (typeof data.calls_remaining === 'number') {
        setBreachMonitorApiCallsRemaining(data.calls_remaining);
      }
    } catch {
      /* ignore */
    }
  }, [canViewInternalBreaches]);

  // Card Details Modal State
  const [showCardDetailsModal, setShowCardDetailsModal] = useState(false);
  const [cardDetailsType, setCardDetailsType] = useState<'vendors' | 'subdomains' | 'vulnerabilities' | 'high-risk' | null>(null);
  const [cardDetailsData, setCardDetailsData] = useState<any>(null);
  const [cardDetailsLoading, setCardDetailsLoading] = useState(false);
  const [expandedVendors, setExpandedVendors] = useState<Set<number>>(new Set());
  const [cardDetailsSearchTerm, setCardDetailsSearchTerm] = useState('');

  const [vendorFilter, setVendorFilter] = useState<string[]>([]);
  const [tierFilter, setTierFilter] = useState<string[]>([]);
  const [portfolioFilter, setPortfolioFilter] = useState<string[]>([]);
  const [industryFilter, setIndustryFilter] = useState<string[]>([]);
  const [scoreFilter, setScoreFilter] = useState<[number, number]>([0, 950]);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  // Search states for each filter
  const [riskLevelSearch, setRiskLevelSearch] = useState('');
  const [tierSearch, setTierSearch] = useState('');
  const [portfolioSearch, setPortfolioSearch] = useState('');
  const [industrySearch, setIndustrySearch] = useState('');

  // Collapsible states for each filter section
  const [expandedSections, setExpandedSections] = useState({
    riskLevel: false,
    tier: false,
    portfolio: false,
    industry: false,
    score: false
  });

  // Restore search and filter state from URL parameters (when returning from report page)
  useEffect(() => {
    const search = searchParams?.get('search');
    const riskFilter = searchParams?.get('riskFilter');
    const tierFilterParam = searchParams?.get('tierFilter');
    const portfolioFilterParam = searchParams?.get('portfolioFilter');
    const industryFilterParam = searchParams?.get('industryFilter');
    const scoreFilterParam = searchParams?.get('scoreFilter');

    if (search) {
      setVendorSearchTerm(search);
    }

    if (riskFilter) {
      setVendorFilter(riskFilter.split(','));
    }

    if (tierFilterParam) {
      setTierFilter(tierFilterParam.split(','));
    }

    if (portfolioFilterParam) {
      setPortfolioFilter(portfolioFilterParam.split(','));
    }

    if (industryFilterParam) {
      setIndustryFilter(industryFilterParam.split(','));
    }

    if (scoreFilterParam) {
      const [min, max] = scoreFilterParam.split('-').map(Number);
      setScoreFilter([min, max]);
    }
  }, [searchParams]);

  // Close advanced filters when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Element;
      if (showAdvancedFilters && !target.closest('.advanced-filter-dropdown')) {
        setShowAdvancedFilters(false);
      }
    };

    if (showAdvancedFilters) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showAdvancedFilters]);

  // Close checkpoint dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Element;
      if (showCheckpointDropdown && !target.closest('.checkpoint-dropdown-container')) {
        setShowCheckpointDropdown(false);
      }
    };

    if (showCheckpointDropdown) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showCheckpointDropdown]);

  // Helper function to safely handle SearchableDropdown onChange
  const handleDropdownChange = (item: any, setDomain: (value: string) => void, setCustomDomain?: (value: string) => void) => {
    if (item && typeof item === 'object' && 'value' in item) {
      setDomain(item.value || '');
    } else {
      setDomain('');
    }
    if (setCustomDomain) {
      setCustomDomain('');
    }
  };

  // Helper functions for multi-select
  const toggleFilterValue = (currentValues: string[], value: string) => {
    if (currentValues.includes(value)) {
      return currentValues.filter(v => v !== value);
    } else {
      return [...currentValues, value];
    }
  };

  const clearAllVendorFilters = () => {
    // Log the filter clear action
    logUserAction('UPDATE', 'filters', undefined, {
      action_type: 'clear_all_filters',
      previous_filters: {
        vendor: vendorFilter,
        tier: tierFilter,
        portfolio: portfolioFilter,
        industry: industryFilter,
        score: scoreFilter
      },
      timestamp: new Date().toISOString()
    });

    setVendorFilter([]);
    setTierFilter([]);
    setPortfolioFilter([]);
    setIndustryFilter([]);
    setScoreFilter([0, 950]);
    setRiskLevelSearch('');
    setTierSearch('');
    setPortfolioSearch('');
    setIndustrySearch('');
    setExpandedSections({
      riskLevel: false,
      tier: false,
      portfolio: false,
      industry: false,
      score: false
    });
  };

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  // Get unique values for each filter category
  const getRiskLevels = () => ['low', 'medium', 'high', 'critical', 'unknown'];

  const getUniqueTiers = () => {
    const allTiers = vendors
      .map(v => v.tier)
      .filter((tier): tier is string => tier !== undefined && tier !== null && tier !== 'Unknown')
      .flatMap(tier => tier.split(',').map(t => t.trim())) // Split by comma and trim whitespace
      .filter(tier => tier.length > 0); // Remove empty strings

    const uniqueTiers = Array.from(new Set(allTiers)).sort();

    // Check if there are any vendors without tiers (null, undefined, or 'Unknown')
    const hasUntieredVendors = vendors.some(v =>
      !v.tier || v.tier === 'Unknown' || v.tier.trim() === ''
    );

    // Add "Untiered" option if there are vendors without tiers AND it's not already in the list
    if (hasUntieredVendors && !uniqueTiers.includes('Untiered')) {
      uniqueTiers.unshift('Untiered'); // Add at the beginning
    }

    return uniqueTiers;
  };

  const getUniquePortfolios = () => {
    const allPortfolios = vendors
      .map(v => v.portfolio)
      .filter((portfolio): portfolio is string => portfolio !== undefined && portfolio !== null && portfolio !== 'Unknown')
      .flatMap(portfolio => portfolio.split(',').map(p => p.trim())) // Split by comma and trim whitespace
      .filter(portfolio => portfolio.length > 0); // Remove empty strings

    return Array.from(new Set(allPortfolios)).sort();
  };

  const getUniqueIndustries = () => {
    const allIndustries = vendors
      .map(v => v.industry)
      .filter((industry): industry is string => industry !== undefined && industry !== null && industry !== 'Unknown')
      .flatMap(industry => industry.split(',').map(i => i.trim())) // Split by comma and trim whitespace
      .filter(industry => industry.length > 0); // Remove empty strings

    return Array.from(new Set(allIndustries)).sort();
  };

  // Filter options based on search
  const getFilteredOptions = (options: string[], searchTerm: string) => {
    return options.filter(option =>
      option.toLowerCase().includes(searchTerm.toLowerCase())
    );
  };
  const [showScanMenu, setShowScanMenu] = useState<number | null>(null);
  const [activeSection, setActiveSection] = useState('dashboard');
  const [showAddVendorModal, setShowAddVendorModal] = useState(false);
  const [showDeleteVendorModal, setShowDeleteVendorModal] = useState(false);
  const [deleteVendorData, setDeleteVendorData] = useState<{ id: number, name: string } | null>(null);
  const [showEditVendorModal, setShowEditVendorModal] = useState(false);
  const [editVendorId, setEditVendorId] = useState<number | null>(null);
  const [addVendorForm, setAddVendorForm] = useState({
    vendorName: '',
    vendorDomain: '',
    tier: '',
    portfolio: '',
    industry: ''
  });
  const [addVendorError, setAddVendorError] = useState('');
  const [isAddingVendor, setIsAddingVendor] = useState(false);
  const [notifications, setNotifications] = useState<NotificationProps[]>([]);

  // View All Recent Scans Modal State
  const [viewAllScansModal, setViewAllScansModal] = useState(false);
  const [allRecentScans, setAllRecentScans] = useState<RecentScan[]>([]);
  const [allScansLoading, setAllScansLoading] = useState(false);

  // Vulnerability Trends State
  const [trendsTimeRange, setTrendsTimeRange] = useState('7');
  const [trendsData, setTrendsData] = useState<any>(null);
  const [trendsLoading, setTrendsLoading] = useState(false);

  // Security Scan Modal State
  const [showSecurityScanModal, setShowSecurityScanModal] = useState(false);
  const [selectedScanTypes, setSelectedScanTypes] = useState({
    vulnerability: false,
    reputation: false,
    network: false,
    dns: false,
    encryption: false,
    email: false
  });
  const [scanModalDomain, setScanModalDomain] = useState('');
  const [scanModalCustomDomain, setScanModalCustomDomain] = useState('');
  const [securityScanLoading, setSecurityScanLoading] = useState(false);
  const [securityScanProgress, setSecurityScanProgress] = useState(0);
  const [securityScanStatus, setSecurityScanStatus] = useState('');

  // Scan Results State
  const [scanResults, setScanResults] = useState<{ [key: string]: any }>({});
  const [showScanResults, setShowScanResults] = useState(false);
  const [scannedDomain, setScannedDomain] = useState('');

  // Collapsible sections state
  const [collapsedSections, setCollapsedSections] = useState<{ [key: string]: boolean }>({});

  // Selected modal vulnerability state (for showing subdomains)
  const [selectedModalVuln, setSelectedModalVuln] = useState<any>(null);

  // Unified Security Scans State
  const [securityScansSelectedDomain, setSecurityScansSelectedDomain] = useState('');
  const [securityScansCustomDomain, setSecurityScansCustomDomain] = useState('');
  const [securityScansSelectedTypes, setSecurityScansSelectedTypes] = useState({
    subdomain: false,
    vulnerability: false,
    reputation: false,
    network: false,
    dns: false,
    encryption: false,
    email: false
  });
  const [securityScansLoading, setSecurityScansLoading] = useState(false);
  const [securityScansProgress, setSecurityScansProgress] = useState(0);
  const [securityScansStatus, setSecurityScansStatus] = useState('');
  const [securityScansResults, setSecurityScansResults] = useState<{ [key: string]: any }>({});
  const [securityScansCollapsed, setSecurityScansCollapsed] = useState<{ [key: string]: boolean }>({
    subdomain: false,
    vulnerability: false,
    reputation: false,
    network: false,
    dns: false,
    encryption: false,
    email: false
  });
  const [selectedSecurityScanIssue, setSelectedSecurityScanIssue] = useState<{ title: string, vulnerabilities: any[], scanType: string } | null>(null);

  // Security Scans Subdomain Table State
  const [securitySubdomainFilter, setSecuritySubdomainFilter] = useState('all');
  const [securitySubdomainSearchTerm, setSecuritySubdomainSearchTerm] = useState('');



  // Enhanced notification system with caching
  const showNotification = (
    type: 'success' | 'error' | 'warning' | 'info',
    title: string,
    message: string,
    options?: {
      persistent?: boolean;
      domain?: string;
      scanType?: string;
      duration?: number;
    }
  ) => {
    const id = Math.random().toString(36).substr(2, 9);
    const timestamp = Date.now();
    const notification: NotificationProps = {
      id,
      type,
      title,
      message,
      timestamp,
      persistent: options?.persistent || false,
      domain: options?.domain,
      scanType: options?.scanType
    };

    setNotifications(prev => [...prev, notification]);

    // Notifications are now persistent until manually dismissed
    // No auto-removal timeout
  };

  // Notifications are now persistent in memory only - no localStorage caching

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  const clearAllNotifications = () => {
    setNotifications([]);
  };

  // Special notification for full scan completion
  const showFullScanCompleteNotification = (domain: string, scanResults: {
    totalScans: number;
    successfulScans: number;
    failedScans: number;
    totalVulnerabilities?: number;
    criticalIssues?: number;
  }) => {
    const { totalScans, successfulScans, failedScans, totalVulnerabilities, criticalIssues } = scanResults;

    let title = 'Full Security Scan Complete';
    let message = `Comprehensive security assessment completed for ${domain}.`;
    let type: 'success' | 'warning' | 'error' = 'success';

    if (failedScans > 0) {
      type = failedScans === totalScans ? 'error' : 'warning';
      message += ` ${successfulScans}/${totalScans} scans completed successfully.`;
    } else {
      message += ` All ${totalScans} security checks completed successfully.`;
    }

    if (totalVulnerabilities !== undefined) {
      message += ` Found ${totalVulnerabilities} total security issues`;
      if (criticalIssues !== undefined && criticalIssues > 0) {
        message += ` (${criticalIssues} critical)`;
      }
      message += '.';
    }

    message += ' View the dashboard for detailed results.';

    showNotification(type, title, message, {
      persistent: true,
      domain: domain,
      scanType: 'full_scan',
      duration: 20000 // Show for 20 seconds
    });
  };

  // View All Recent Scans Modal Functions
  const openViewAllScansModal = async () => {
    setViewAllScansModal(true);
    setAllScansLoading(true);
    try {
      console.log('Loading ALL recent scans for modal...');
      const scansData = await dashboardApi.getRecentScans();
      console.log('ALL recent scans data received:', scansData.recent_scans?.length || 0, 'scans');
      if (scansData.recent_scans?.length > 0) {
        console.log('First scan in modal:', scansData.recent_scans[0]);
      }
      setAllRecentScans(scansData.recent_scans || []);
    } catch (error) {
      console.error('Error loading all recent scans:', error);
      showNotification('error', 'Loading Error', 'Failed to load recent scans');
    } finally {
      setAllScansLoading(false);
    }
  };

  const closeViewAllScansModal = () => {
    setViewAllScansModal(false);
    setAllRecentScans([]);
  };

  // Vulnerability Trends Functions
  const loadVulnerabilityTrends = async (timeRange: string = '7') => {
    setTrendsLoading(true);
    try {
      // Mock data for now - replace with actual API call
      const mockTrendsData = generateMockTrendsData(timeRange);
      setTrendsData(mockTrendsData);
    } catch (error) {
      console.error('Error loading vulnerability trends:', error);
      showNotification('error', 'Loading Error', 'Failed to load vulnerability trends');
    } finally {
      setTrendsLoading(false);
    }
  };

  const generateMockTrendsData = (timeRange: string) => {
    const days = parseInt(timeRange);
    const labels = [];
    const criticalData = [];
    const highData = [];
    const mediumData = [];
    const lowData = [];

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));

      // Generate mock data with some randomness
      criticalData.push(Math.floor(Math.random() * 5));
      highData.push(Math.floor(Math.random() * 15) + 5);
      mediumData.push(Math.floor(Math.random() * 25) + 10);
      lowData.push(Math.floor(Math.random() * 20) + 15);
    }

    return {
      labels,
      datasets: [
        {
          label: 'Critical',
          data: criticalData,
          borderColor: '#dc2626',
          backgroundColor: 'rgba(220, 38, 38, 0.1)',
          tension: 0.4,
          fill: true
        },
        {
          label: 'High',
          data: highData,
          borderColor: '#ea580c',
          backgroundColor: 'rgba(234, 88, 12, 0.1)',
          tension: 0.4,
          fill: true
        },
        {
          label: 'Medium',
          data: mediumData,
          borderColor: '#d97706',
          backgroundColor: 'rgba(217, 119, 6, 0.1)',
          tension: 0.4,
          fill: true
        },
        {
          label: 'Low',
          data: lowData,
          borderColor: '#059669',
          backgroundColor: 'rgba(5, 150, 105, 0.1)',
          tension: 0.4,
          fill: true
        }
      ]
    };
  };

  const handleTrendsTimeRangeChange = (newRange: string) => {
    setTrendsTimeRange(newRange);
    loadVulnerabilityTrends(newRange);
  };

  // Security Scan Modal Functions
  const openSecurityScanModal = () => {
    setShowSecurityScanModal(true);
    setScanModalDomain('');
    setScanModalCustomDomain('');
    setSecurityScanProgress(0);
    setSecurityScanStatus('');
  };

  const closeSecurityScanModal = () => {
    setShowSecurityScanModal(false);
    setSecurityScanLoading(false);
    setSecurityScanProgress(0);
    setSecurityScanStatus('');
    setScanResults({});
    setShowScanResults(false);
    setScannedDomain('');
    setCollapsedSections({});
    setSelectedModalVuln(null);
  };

  const handleScanTypeToggle = (scanType: string) => {
    setSelectedScanTypes(prev => ({
      ...prev,
      [scanType]: !prev[scanType as keyof typeof prev]
    }));
  };

  const handleSelectAllScans = () => {
    const allSelected = Object.values(selectedScanTypes).every(selected => selected);
    const newState = allSelected ?
      Object.keys(selectedScanTypes).reduce((acc, key) => ({ ...acc, [key]: false }), {}) :
      Object.keys(selectedScanTypes).reduce((acc, key) => ({ ...acc, [key]: true }), {});
    setSelectedScanTypes(newState as typeof selectedScanTypes);
  };

  // Helper functions for scan results display
  const getScanTypeIcon = (scanType: string): string => {
    const icons: { [key: string]: string } = {
      vulnerability: 'fa-bug',
      reputation: 'fa-shield-virus',
      network: 'fa-network-wired',
      dns: 'fa-server',
      encryption: 'fa-lock',
      email: 'fa-envelope-open-text'
    };
    return icons[scanType] || 'fa-shield-alt';
  };

  const getResultStatus = (result: any): string => {
    if (result.status === 'error') return 'error';
    if (result.final_score) {
      const score = result.final_score;
      const maxScore = result.max_score || 950;
      const percentage = (score / maxScore) * 100;
      if (percentage >= 80) return 'success';
      if (percentage >= 60) return 'warning';
      return 'error';
    }
    return 'success';
  };

  const getResultStatusText = (result: any): string => {
    if (result.status === 'error') return 'Failed';
    if (result.final_score) {
      const score = result.final_score;
      const maxScore = result.max_score || 950;
      const percentage = (score / maxScore) * 100;
      if (percentage >= 80) return 'Good';
      if (percentage >= 60) return 'Needs Attention';
      return 'Critical';
    }
    return 'Completed';
  };

  // Helper functions for collapsible sections and vulnerability grouping
  const toggleSectionCollapse = (scanType: string) => {
    setCollapsedSections(prev => ({
      ...prev,
      [scanType]: !prev[scanType]
    }));
  };

  const groupVulnerabilities = (vulnerabilities: any[], scanType: string) => {
    const groups: { [key: string]: any } = {};

    vulnerabilities.forEach(vuln => {
      let key: string;

      // Use scan-type specific grouping logic
      switch (scanType) {
        case 'vulnerability':
          // Website vulnerabilities: group by description, fallback to title
          key = vuln.description || vuln.title || vuln.vulnerability || 'Unknown Vulnerability';
          break;
        case 'dns':
          // DNS issues: group by description for better grouping
          key = vuln.description || vuln.title || vuln.issue_type || 'DNS Security Issue';
          break;
        case 'encryption':
          // Encryption issues: group by vulnerability name
          key = vuln.vulnerability || vuln.description || 'SSL/TLS Security Issue';
          break;
        case 'network':
          // Network issues: group by service and port
          key = `${vuln.service || 'Unknown Service'} (Port ${vuln.port || 'Unknown'})`;
          break;
        case 'email':
          // Email issues: group by title
          key = vuln.title || 'Email Security Issue';
          break;
        case 'reputation':
          // Reputation issues: group by issue type or description
          key = vuln.issue_type || vuln.description || vuln.title || 'Reputation Issue';
          break;
        default:
          // Fallback grouping
          key = vuln.title || vuln.vulnerability || vuln.description || vuln.id || 'Security Issue';
      }

      if (!groups[key]) {
        groups[key] = {
          title: key,
          severity: vuln.severity,
          description: vuln.description || key,
          subdomains: [],
          count: 0,
          affectedDomains: [],
          vulnerabilities: []
        };
      }

      // Add domain to affected domains list if not already present
      const domain = vuln.subdomain || vuln.domain || 'Unknown Domain';
      if (!groups[key].affectedDomains.includes(domain)) {
        groups[key].affectedDomains.push(domain);
      }

      groups[key].subdomains.push({
        subdomain: vuln.subdomain || vuln.domain,
        description: vuln.description
      });
      groups[key].vulnerabilities.push(vuln);
      groups[key].count++;

      // Use highest severity if multiple instances have different severities
      const currentWeight = getSeverityWeight(vuln.severity);
      const groupWeight = getSeverityWeight(groups[key].severity);
      if (currentWeight > groupWeight) {
        groups[key].severity = vuln.severity;
      }
    });

    // Convert to array and sort by severity (highest first)
    return Object.values(groups).sort((a: any, b: any) =>
      getSeverityWeight(b.severity) - getSeverityWeight(a.severity)
    );
  };

  const handleModalVulnerabilityClick = (vulnerability: any) => {
    setSelectedModalVuln(vulnerability);
  };

  const closeModalVulnerabilityModal = () => {
    setSelectedModalVuln(null);
  };

  // Card Details Modal Handlers
  const openCardDetailsModal = async (type: 'vendors' | 'subdomains' | 'vulnerabilities' | 'high-risk') => {
    setCardDetailsType(type);
    setShowCardDetailsModal(true);
    setCardDetailsLoading(true);
    setExpandedVendors(new Set());

    try {
      let data;
      switch (type) {
        case 'vendors':
          data = await dashboardApi.getVendorsWithScoresCached();
          break;
        case 'subdomains':
          data = await dashboardApi.getSubdomainsByVendorCached();
          break;
        case 'vulnerabilities':
          data = await dashboardApi.getVulnerabilitiesByVendorCached();
          break;
        case 'high-risk':
          data = await dashboardApi.getHighRiskByVendorCached();
          break;
      }
      setCardDetailsData(data);
    } catch (error) {
      console.error(`Error loading ${type} details:`, error);
      showNotification('error', 'Error', `Failed to load ${type} details`);
    } finally {
      setCardDetailsLoading(false);
    }
  };

  const closeCardDetailsModal = () => {
    setShowCardDetailsModal(false);
    setCardDetailsType(null);
    setCardDetailsData(null);
    setExpandedVendors(new Set());
    setCardDetailsSearchTerm('');
  };

  const toggleVendorExpansion = (vendorId: number) => {
    setExpandedVendors(prev => {
      const newSet = new Set(prev);
      if (newSet.has(vendorId)) {
        newSet.delete(vendorId);
      } else {
        newSet.add(vendorId);
      }
      return newSet;
    });
  };

  const startSelectedScans = async () => {
    const targetDomain = scanModalDomain || scanModalCustomDomain;

    if (!targetDomain) {
      logger.warn('ui', 'Domain selection validation failed', {
        scanModalDomain,
        scanModalCustomDomain
      });
      showNotification('warning', 'Domain Required', 'Please select a domain from the dropdown or enter a custom domain');
      return;
    }

    const selectedScans = Object.entries(selectedScanTypes).filter(([_, selected]) => selected);
    if (selectedScans.length === 0) {
      logger.warn('ui', 'No scan types selected', { selectedScanTypes });
      showNotification('warning', 'No Scans Selected', 'Please select at least one scan type to perform');
      return;
    }

    // Generate custom scan ID for detailed tracking
    const customScanId = `custom_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    try {
      logger.scanStarted('custom', targetDomain, customScanId);
      logger.info('scan', `Starting custom security scan batch`, {
        domain: targetDomain,
        scanTypes: selectedScans.map(([type]) => type),
        totalScans: selectedScans.length,
        scanId: customScanId
      }, customScanId, targetDomain);

      setSecurityScanLoading(true);
      setSecurityScanProgress(0);
      setScanResults({});
      setScannedDomain(targetDomain);
      const totalScans = selectedScans.length;
      let completedScans = 0;

      showNotification('info', 'Custom Security Scan Started',
        `Starting ${totalScans} selected security scans for ${targetDomain}. This may take several minutes.`,
        { persistent: true, domain: targetDomain, scanType: 'custom_scan' });

      // Automatically check and discover subdomains before other scans
      setSecurityScanStatus('Checking subdomains...');
      logger.scanStageProgress('custom', targetDomain, 'Checking subdomains', 5, customScanId);
      await checkAndDiscoverSubdomains(targetDomain, 'Auto Subdomain Discovery');

      // Run selected scans sequentially
      for (const [scanType, _] of selectedScans) {
        try {
          setSecurityScanStatus(`Running ${scanType} scan...`);
          const currentProgress = Math.round((completedScans / totalScans) * 100);
          logger.scanStageProgress('custom', targetDomain, `Running ${scanType} scan`, currentProgress, customScanId);
          logger.info('scan', `Starting ${scanType} scan`, {
            domain: targetDomain,
            scanType,
            progress: `${completedScans + 1}/${totalScans}`,
            percentage: currentProgress
          }, customScanId, targetDomain);

          let scanResult = null;

          switch (scanType) {
            case 'vulnerability':
              if (selectedScanTypes.vulnerability) {
                scanResult = await scanApi.startVulnerabilityScan(targetDomain);
                // Log the scan action with vendor context
                const vendor = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'vulnerability', (scanResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_vulnerability_scan',
                  domain: targetDomain,
                  vendor_name: vendor?.name || 'Unknown Vendor',
                  vendor_id: vendor?.id,
                  scan_type: 'vulnerability',
                  scan_id: (scanResult as any)?.scan_id,
                  context: 'comprehensive_scan',
                  timestamp: new Date().toISOString()
                });
              }
              break;
            case 'reputation':
              if (selectedScanTypes.reputation) {
                scanResult = await scanApi.startReputationScan(targetDomain);
                // Log the scan action with vendor context
                const vendor = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'reputation', (scanResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_reputation_scan',
                  domain: targetDomain,
                  vendor_name: vendor?.name || 'Unknown Vendor',
                  vendor_id: vendor?.id,
                  scan_type: 'reputation',
                  scan_id: (scanResult as any)?.scan_id,
                  context: 'comprehensive_scan',
                  timestamp: new Date().toISOString()
                });
              }
              break;
            case 'network':
              if (selectedScanTypes.network) {
                const networkResult = await scanApi.startNetworkScan(targetDomain);
                // Log the scan action with vendor context
                const vendor = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'network', (networkResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_network_scan',
                  domain: targetDomain,
                  vendor_name: vendor?.name || 'Unknown Vendor',
                  vendor_id: vendor?.id,
                  scan_type: 'network',
                  scan_id: (networkResult as any)?.scan_id,
                  context: 'comprehensive_scan',
                  timestamp: new Date().toISOString()
                });
                if (networkResult.scan_id) {
                  scanResult = await waitForNetworkScanCompletion(networkResult.scan_id, targetDomain);
                } else {
                  scanResult = networkResult;
                }
              }
              break;
            case 'dns':
              if (selectedScanTypes.dns) {
                const dnsStartResult = await scanApi.startDnsScan(targetDomain);
                // Log the scan action with vendor context
                const vendor = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'dns', (dnsStartResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_dns_scan',
                  domain: targetDomain,
                  vendor_name: vendor?.name || 'Unknown Vendor',
                  vendor_id: vendor?.id,
                  scan_type: 'dns',
                  scan_id: (dnsStartResult as any)?.scan_id,
                  context: 'comprehensive_scan',
                  timestamp: new Date().toISOString()
                });
                if (dnsStartResult.scan_id) {
                  scanResult = await waitForDnsScanCompletion(dnsStartResult.scan_id, targetDomain);
                } else {
                  scanResult = dnsStartResult;
                }
              }
              break;
            case 'encryption':
              if (selectedScanTypes.encryption) {
                const encryptionResult = await scanApi.startEncryptionScan(targetDomain);
                // Log the scan action with vendor context
                const vendor = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'encryption', (encryptionResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_encryption_scan',
                  domain: targetDomain,
                  vendor_name: vendor?.name || 'Unknown Vendor',
                  vendor_id: vendor?.id,
                  scan_type: 'encryption',
                  scan_id: (encryptionResult as any)?.scan_id,
                  context: 'comprehensive_scan',
                  timestamp: new Date().toISOString()
                });
                if (encryptionResult.scan_id) {
                  scanResult = await waitForEncryptionScanCompletion(encryptionResult.scan_id, targetDomain);
                } else {
                  scanResult = encryptionResult;
                }
              }
              break;
            case 'email':
              if (selectedScanTypes.email) {
                scanResult = await scanApi.startEmailScan(targetDomain);
                // Log the scan action with vendor context
                const vendor = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'email', (scanResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_email_scan',
                  domain: targetDomain,
                  vendor_name: vendor?.name || 'Unknown Vendor',
                  vendor_id: vendor?.id,
                  scan_type: 'email',
                  scan_id: (scanResult as any)?.scan_id,
                  context: 'comprehensive_scan',
                  timestamp: new Date().toISOString()
                });
              }
              break;
          }

          // Store scan result
          if (scanResult) {
            setScanResults(prev => ({
              ...prev,
              [scanType]: scanResult
            }));
            logger.success('scan', `${scanType} scan completed successfully`, {
              domain: targetDomain,
              scanType,
              score: (scanResult as any).final_score || (scanResult as any).score,
              vulnerabilities: (scanResult as any).vulnerabilities?.length || 0,
              status: (scanResult as any).status
            }, customScanId, targetDomain);
          }

          completedScans++;
          const progress = Math.round((completedScans / totalScans) * 100);
          setSecurityScanProgress(progress);

          showNotification('success', 'Scan Complete', ` ${scanType} scan completed for ${targetDomain}`);

        } catch (error) {
          logger.scanError('custom', targetDomain, error, customScanId);
          logger.error('scan', `${scanType} scan failed`, {
            domain: targetDomain,
            scanType,
            error: error instanceof Error ? error.message : 'Unknown error',
            stack: error instanceof Error ? error.stack : undefined
          }, customScanId, targetDomain);

          showNotification('warning', 'Scan Failed', `${scanType} scan failed, continuing with remaining scans.`);

          // Store error result
          setScanResults(prev => ({
            ...prev,
            [scanType]: { status: 'error', message: error instanceof Error ? error.message : 'Scan failed' }
          }));

          completedScans++;
          setSecurityScanProgress(Math.round((completedScans / totalScans) * 100));
        }
      }

      setSecurityScanStatus('All selected scans completed!');
      setShowScanResults(true);

      // Log final scan completion
      logger.scanCompleted('custom', targetDomain, {
        totalScans,
        completedScans,
        scanResults: Object.keys(scanResults),
        successfulScans: Object.values(scanResults).filter(r => r && (r as any).status !== 'error').length,
        failedScans: Object.values(scanResults).filter(r => r && (r as any).status === 'error').length
      }, customScanId);

      showNotification('success', 'Custom Scan Complete',
        `Completed ${totalScans} security scans for ${targetDomain}. Results are displayed below.`,
        { persistent: true, domain: targetDomain, scanType: 'custom_scan' });

      // Refresh dashboard data
      setTimeout(() => {
        loadDashboardData();
      }, 2000);

    } catch (error) {
      logger.error('scan', 'Critical error in custom security scan', {
        domain: targetDomain,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined
      }, customScanId || 'unknown', targetDomain);

      console.error('Error in custom security scan:', error);
      showNotification('error', 'Scan Failed', 'Failed to complete custom security scan');
    } finally {
      setSecurityScanLoading(false);
      setSecurityScanProgress(0);
      setSecurityScanStatus('');
    }
  };

  // Auto-subdomain discovery helper function
  const checkAndDiscoverSubdomains = async (domain: string, scanType: string, setProgress?: (progress: number) => void, setStatus?: (status: string) => void): Promise<boolean> => {
    try {
      // Update loading status
      if (setStatus) setStatus('Checking for existing subdomains...');
      if (setProgress) setProgress(5);

      // Check if domain has subdomains in database
      const subdomainStatus = await subdomainApi.checkStatus(domain);

      if (subdomainStatus.has_subdomains) {
        // Domain has subdomains, proceed with scan
        if (setStatus) setStatus(`Found ${subdomainStatus.subdomain_count} subdomains. Starting ${scanType} scan...`);
        if (setProgress) setProgress(15);
        showNotification('info', 'Using Existing Subdomains',
          `Found ${subdomainStatus.subdomain_count} subdomains for ${domain}. Proceeding with ${scanType} scan.`);
        return true;
      } else {
        // No subdomains found, automatically start discovery
        if (setStatus) setStatus(`Discovering subdomains for ${domain}...`);
        if (setProgress) setProgress(10);
        showNotification('info', 'Starting Subdomain Discovery',
          `No subdomains found for ${domain}. Automatically discovering subdomains for comprehensive ${scanType} scan...`);

        // Start subdomain discovery
        const discoveryResponse = await subdomainApi.discover({
          domain: domain,
          force_rediscovery: false
        });

        if (discoveryResponse.status === 'started') {
          // Poll for completion with progress updates
          return await pollSubdomainDiscoveryForScan(discoveryResponse.scan_id || '', domain, scanType, setProgress, setStatus);
        } else if (discoveryResponse.status === 'completed') {
          if (setStatus) setStatus(`Found ${discoveryResponse.statistics?.alive || 0} subdomains. Starting ${scanType} scan...`);
          if (setProgress) setProgress(25);
          showNotification('success', 'Subdomains Discovered',
            `Found ${discoveryResponse.statistics?.alive || 0} active subdomains for ${domain}. Proceeding with ${scanType} scan.`);
          return true;
        } else {
          if (setStatus) setStatus(`Subdomain discovery failed. Starting ${scanType} scan on main domain...`);
          if (setProgress) setProgress(15);
          showNotification('warning', 'Discovery Failed',
            `Subdomain discovery failed. Proceeding with ${scanType} scan on main domain only.`);
          return true;
        }
      }
    } catch (error) {
      console.error('Error checking subdomain status:', error);
      if (setStatus) setStatus(`Subdomain check failed. Starting ${scanType} scan on main domain...`);
      if (setProgress) setProgress(15);
      showNotification('warning', 'Subdomain Check Failed',
        `Could not check subdomain status. Proceeding with ${scanType} scan on main domain only.`);
      return true;
    }
  };

  const pollSubdomainDiscoveryForScan = async (scanId: string, domain: string, scanType: string, setProgress?: (progress: number) => void, setStatus?: (status: string) => void): Promise<boolean> => {
    return new Promise((resolve) => {
      let progressValue = 15; // Start from where we left off

      const pollInterval = setInterval(async () => {
        try {
          const status = await subdomainApi.discoverStatus(scanId);

          // Update progress during discovery
          if (setProgress && progressValue < 25) {
            progressValue = Math.min(progressValue + 2, 25);
            setProgress(progressValue);
          }

          if (status.status === 'completed') {
            clearInterval(pollInterval);
            const stats = status.results?.statistics || status.statistics;
            if (setStatus) setStatus(`Found ${stats?.alive || 0} subdomains. Starting ${scanType} scan...`);
            if (setProgress) setProgress(30);
            showNotification('success', 'Subdomains Discovered',
              `Found ${stats?.alive || 0} active subdomains for ${domain}. Proceeding with ${scanType} scan.`);
            resolve(true);
          } else if (status.status === 'error' || status.status === 'stopped') {
            clearInterval(pollInterval);
            if (setStatus) setStatus(`Subdomain discovery failed. Starting ${scanType} scan on main domain...`);
            if (setProgress) setProgress(20);
            showNotification('warning', 'Discovery Failed',
              `Subdomain discovery failed. Proceeding with ${scanType} scan on main domain only.`);
            resolve(true);
          } else if (status.status === 'running') {
            // Update status with current stage if available
            if (setStatus) {
              const stage = status.stage || 'running';
              const stageMessages: { [key: string]: string } = {
                'sublist3r': 'Running Sublist3r enumeration...',
                'crtsh': 'Querying certificate transparency logs...',
                'alive_check': 'Testing subdomain availability...',
                'saving': 'Saving discovered subdomains...',
                'running': 'Discovering subdomains...'
              };
              setStatus(stageMessages[stage] || `Discovering subdomains for ${domain}...`);
            }
          }
          // Continue polling if status is 'running'
        } catch (error) {
          clearInterval(pollInterval);
          console.error('Error polling subdomain discovery:', error);
          if (setStatus) setStatus(`Subdomain discovery failed. Starting ${scanType} scan on main domain...`);
          if (setProgress) setProgress(20);
          showNotification('warning', 'Discovery Failed',
            `Subdomain discovery failed. Proceeding with ${scanType} scan on main domain only.`);
          resolve(true);
        }
      }, 2000); // Poll every 2 seconds

      // Timeout after 5 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        if (setStatus) setStatus(`Subdomain discovery timed out. Starting ${scanType} scan on main domain...`);
        if (setProgress) setProgress(20);
        showNotification('warning', 'Discovery Timeout',
          `Subdomain discovery timed out. Proceeding with ${scanType} scan on main domain only.`);
        resolve(true);
      }, 300000);
    });
  };

  const loadDashboardData = async (forceFresh: boolean = false) => {
    try {
      console.log('Loading dashboard data...', forceFresh ? '(forcing fresh data)' : '(using cache)');

      let statsData, vendorsData, scansData;

      if (forceFresh) {
        // Force fresh data by calling non-cached API functions
        logger.info('cache', 'Loading fresh dashboard data (bypassing cache)', { forceFresh: true });
        [statsData, vendorsData, scansData] = await Promise.all([
          dashboardApi.getStats(),
          vendorApi.getVendors(),
          dashboardApi.getRecentScans()
        ]);
      } else {
        // Use cached versions
        [statsData, vendorsData, scansData] = await Promise.all([
          dashboardApi.getStatsCached(),
          vendorApi.getVendorsCached(),
          dashboardApi.getRecentScansCached()
        ]);
      }

      console.log('Recent scans data received:', scansData.recent_scans?.length || 0, 'scans');
      if (scansData.recent_scans?.length > 0) {
        console.log('First scan:', scansData.recent_scans[0]);
      }

      logger.info('ui', 'Dashboard data loaded successfully', {
        vendorCount: vendorsData.vendors?.length || 0,
        recentScansCount: scansData.recent_scans?.length || 0,
        forceFresh
      });

      setStats(statsData);
      setVendors(vendorsData.vendors || []);
      setRecentScans(scansData.recent_scans || []);
    } catch (error) {
      console.error('Error loading dashboard data:', error);
      logger.error('ui', 'Failed to load dashboard data', {
        error: error instanceof Error ? error.message : 'Unknown error',
        forceFresh
      });
      showNotification('error', 'Loading Error', 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const refreshDashboard = async () => {
    try {
      showNotification('info', 'Refreshing Dashboard', 'Reloading vendor data from database...');
      setLoading(true);

      // First reload vendors from database
      await vendorApi.reloadVendors();

      // Then refresh all dashboard data
      await loadDashboardData();

      showNotification('success', 'Dashboard Refreshed', 'Vendor data has been reloaded from database');
    } catch (error) {
      console.error('Error refreshing dashboard:', error);
      showNotification('error', 'Refresh Failed', 'Failed to refresh dashboard data');
    }
  };

  // Grading function to match comparison page logic
  const getGradeFromScore = (score: number): string => {
    // Use absolute score ranges based on the comparison page logic
    if (score >= 801) return 'A';  // 801-950: Low Risk
    if (score >= 601) return 'B';  // 601-800
    if (score >= 401) return 'C';  // 401-600
    if (score >= 201) return 'D';  // 201-400
    return 'F';                    // 0-200: High Risk
  };

  const getGradeColor = (grade: string): string => {
    switch (grade) {
      case 'A': return '#22c55e';  // Green - Low Risk (801-950)
      case 'B': return '#84cc16';  // Light Green (601-800)
      case 'C': return '#f59e0b';  // Yellow (401-600)
      case 'D': return '#f97316';  // Orange (201-400)
      case 'F': return '#ef4444';  // Red - High Risk (0-200)
      default: return '#6b7280';   // Gray for N/A
    }
  };

  // Subdomain Discovery Functions
  const handleDomainSelect = async (item: any) => {
    const domain = item?.value || '';
    setSelectedDomain(domain);
    setCustomDomain(''); // Clear custom domain when selecting from dropdown

    // Clear previous states when selecting a new domain
    setSubdomainResults(null);
    setExistingSubdomains(null);

    if (!domain) {
      return;
    }

    // Check for existing subdomains only if not currently loading
    if (!subdomainLoading) {
      try {
        const response = await subdomainApi.getSubdomainsCached(domain);
        if (response.count && response.count.total > 0) {
          // Ensure we have proper inactive count calculation
          const totalCount = parseInt(String(response.count.total)) || 0;
          const aliveCount = parseInt(String(response.count.alive)) || 0;
          const inactiveCount = response.count.inactive !== undefined
            ? parseInt(String(response.count.inactive)) || 0
            : totalCount - aliveCount;

          // Update the response with corrected counts
          const correctedResponse = {
            ...response,
            count: {
              ...response.count,
              total: totalCount,
              alive: aliveCount,
              inactive: inactiveCount
            }
          };

          console.log('Existing subdomains data:', correctedResponse.count);
          setExistingSubdomains(correctedResponse);
          showNotification('info', 'Existing Subdomains Found',
            `Found ${totalCount} existing subdomains for ${domain}. Active: ${aliveCount}, Inactive: ${inactiveCount}`);
        }
      } catch (error) {
        console.error('Error checking existing subdomains:', error);
      }
    }
  };

  const handleCustomDomainChange = (domain: string) => {
    setCustomDomain(domain);
    setSelectedDomain(''); // Clear selected domain when typing custom
    setExistingSubdomains(null);
  };

  const startSubdomainDiscovery = async (forceRediscovery = true) => {
    const targetDomain = selectedDomain || customDomain;

    if (!targetDomain) {
      showNotification('warning', 'Domain Required', 'Please select a domain from the dropdown or enter a custom domain');
      return;
    }

    try {
      setSubdomainLoading(true);
      setSubdomainResults(null);
      setExistingSubdomains(null); // Clear existing data when starting new scan
      setScanProgress(0);
      setScanStatus('Initializing subdomain discovery...');

      console.log('Starting subdomain discovery:', { domain: targetDomain, force_rediscovery: forceRediscovery });

      // Start the discovery scan
      const response = await subdomainApi.discover({
        domain: targetDomain,
        force_rediscovery: forceRediscovery
      });

      console.log('Subdomain discovery start response:', response);

      // Check if scan completed immediately (using existing data)
      if (response.status === 'completed') {
        // Handle immediate completion (existing data)
        const totalCount = parseInt(String(response.statistics?.total)) || 0;
        const aliveCount = parseInt(String(response.statistics?.alive)) || 0;
        const inactiveCount = response.statistics?.inactive !== undefined
          ? parseInt(String(response.statistics.inactive)) || 0
          : totalCount - aliveCount;

        const correctedResponse = {
          ...response,
          statistics: {
            ...response.statistics,
            total: totalCount,
            alive: aliveCount,
            inactive: inactiveCount,
            success_rate: totalCount > 0 ? Math.round((aliveCount / totalCount) * 100) : 0,
            from_database: response.statistics?.from_database || false
          }
        };

        setSubdomainResults(correctedResponse);
        setScanProgress(100);
        setScanStatus('Discovery completed!');

        showNotification('info', 'Using Existing Data',
          response.message || `Using ${totalCount} existing subdomains (${aliveCount} active, ${inactiveCount} inactive)`);
      } else if (response.status === 'started') {
        // Handle async scan - start polling
        const scanId = response.scan_id;
        setCurrentScanId(scanId || null);

        showNotification('info', 'Scan Started',
          `Subdomain discovery started for ${targetDomain}. This may take several minutes.`);

        // Start polling for status
        const interval = setInterval(async () => {
          try {
            const statusResponse = await subdomainApi.discoverStatus(scanId || '');
            console.log('Scan status:', statusResponse);

            // Update progress from backend
            setScanProgress(statusResponse.progress || 0);
            setScanStatus(statusResponse.stage || 'Processing...');

            // Check if completed
            if (statusResponse.status === 'completed') {
              clearInterval(interval);
              setPollInterval(null);
              setCurrentScanId(null);

              // Process final results
              const finalResults = statusResponse.results;
              const totalCount = parseInt(String(finalResults?.statistics?.total)) || 0;
              const aliveCount = parseInt(String(finalResults?.statistics?.alive)) || 0;
              const inactiveCount = finalResults?.statistics?.inactive !== undefined
                ? parseInt(String(finalResults.statistics.inactive)) || 0
                : totalCount - aliveCount;

              const correctedResponse = {
                ...finalResults,
                statistics: {
                  ...finalResults.statistics,
                  total: totalCount,
                  alive: aliveCount,
                  inactive: inactiveCount,
                  success_rate: totalCount > 0 ? Math.round((aliveCount / totalCount) * 100) : 0,
                  from_database: finalResults.statistics?.from_database || false
                }
              };

              setSubdomainResults(correctedResponse);
              setScanProgress(100);
              setScanStatus('Discovery completed!');
              setSubdomainLoading(false);

              showNotification('success', 'Discovery Complete',
                `Found ${totalCount} subdomains (${aliveCount} active, ${inactiveCount} inactive)`);
            } else if (statusResponse.status === 'error') {
              clearInterval(interval);
              setPollInterval(null);
              setCurrentScanId(null);
              setSubdomainLoading(false);

              showNotification('error', 'Discovery Failed',
                statusResponse.error || 'An error occurred during subdomain discovery');
            }
          } catch (pollError) {
            console.error('Error polling scan status:', pollError);
            // Continue polling unless it's a critical error
          }
        }, 3000); // Poll every 3 seconds

        setPollInterval(interval);

        // Don't set loading to false here - let the polling handle completion
        return;
      }

    } catch (error: any) {
      console.error('Error during subdomain discovery:', error);

      let errorMessage = 'Failed to start subdomain discovery. Please try again.';

      if (error?.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error?.message) {
        errorMessage = error.message;
      }

      showNotification('error', 'Discovery Failed', errorMessage);
      setSubdomainLoading(false);
      setScanProgress(0);
      setScanStatus('');
    }

    // Only set loading to false if we're not polling
    if (!pollInterval) {
      setSubdomainLoading(false);
      setScanProgress(0);
      setScanStatus('');
    }
  };

  const stopSubdomainDiscovery = async () => {
    if (currentScanId) {
      try {
        await subdomainApi.stopDiscovery(currentScanId);

        // Clear polling
        if (pollInterval) {
          clearInterval(pollInterval);
          setPollInterval(null);
        }

        setCurrentScanId(null);
        setSubdomainLoading(false);
        setScanProgress(0);
        setScanStatus('');

        showNotification('warning', 'Scan Stopped', 'Subdomain discovery scan has been stopped');
      } catch (error) {
        console.error('Error stopping scan:', error);
        showNotification('error', 'Stop Failed', 'Failed to stop the scan');
      }
    }
  };

  // Cleanup on component unmount
  useEffect(() => {
    return () => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [pollInterval]);

  const startWebsiteVulnerabilityScan = async () => {
    const targetDomain = websiteSelectedDomain || websiteCustomDomain;

    if (!targetDomain) {
      showNotification('warning', 'Domain Required', 'Please select a domain from the dropdown or enter a custom domain');
      return;
    }

    try {
      setVulnerabilityLoading(true);
      setVulnerabilityResults(null);
      setVulnerabilityProgress(0);

      console.log('Starting vulnerability scan:', { domain: targetDomain });

      // Check and discover subdomains if needed
      const canProceed = await checkAndDiscoverSubdomains(
        targetDomain,
        'Website Vulnerability',
        setVulnerabilityProgress,
        setVulnerabilityStatus
      );
      if (!canProceed) {
        setVulnerabilityLoading(false);
        return;
      }

      // Simulate progress during scan
      const progressInterval = setInterval(() => {
        setVulnerabilityProgress(prev => {
          if (prev >= 90) return prev;
          return prev + Math.random() * 10;
        });
      }, 1000);

      const response = await scanApi.startVulnerabilityScan(targetDomain);

      clearInterval(progressInterval);
      setVulnerabilityProgress(100);

      console.log('Vulnerability scan response:', response);

      if (response.status === 'success') {
        setVulnerabilityResults(response);
        showNotification('success', 'Scan Complete',
          `Vulnerability scan completed for ${targetDomain}. Found ${response.summary.total_vulnerabilities} vulnerabilities.`,
          { persistent: true, domain: targetDomain, scanType: 'vulnerability_scan' });

        // Refresh dashboard to update recent scans
        setTimeout(() => {
          console.log('Refreshing dashboard after vulnerability scan completion...');
          loadDashboardData();
        }, 1000);
      } else {
        showNotification('error', 'Scan Failed', response.message || 'Vulnerability scan failed');
      }

    } catch (error: any) {
      console.error('Error during vulnerability scan:', error);

      let errorMessage = 'Failed to start vulnerability scan. Please try again.';

      if (error?.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error?.message) {
        errorMessage = error.message;
      }

      showNotification('error', 'Scan Failed', errorMessage);
    } finally {
      setVulnerabilityLoading(false);
      setVulnerabilityProgress(0);
    }
  };

  const groupVulnerabilitiesByType = (vulnerabilities: any[], scanType: string) => {
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

    // Convert to array and sort by severity (highest first)
    return Object.values(groups).sort((a: any, b: any) =>
      getSeverityWeight(b.severity) - getSeverityWeight(a.severity)
    );
  };

  const getSeverityWeight = (severity: string) => {
    const weights: { [key: string]: number } = {
      'CRITICAL': 5,
      'HIGH': 4,
      'MEDIUM': 3,
      'LOW': 2,
      'INFO': 1
    };
    return weights[severity?.toUpperCase()] || 0;
  };

  const startNewVulnerabilityScan = () => {
    // Clear all results and reset state for a new scan
    setVulnerabilityResults(null);
    setWebsiteSelectedDomain('');
    setWebsiteCustomDomain('');
    setVulnerabilityFilter('all');
    setVulnerabilitySearchTerm('');
    setVulnerabilityProgress(0);
    setSelectedVulnerability(null);

    showNotification('info', 'Ready for New Scan', 'Results cleared. Select a domain to start a new vulnerability scan.');
  };

  const openVulnerabilityModal = (title: string, vulnerabilities: any[]) => {
    setSelectedVulnerability({ title, vulnerabilities });
  };

  const closeVulnerabilityModal = () => {
    setSelectedVulnerability(null);
  };

  const downloadVulnerabilityReport = () => {
    if (!vulnerabilityResults) {
      showNotification('warning', 'No Data', 'No vulnerability scan results available to download.');
      return;
    }

    try {
      // Create CSV content
      const csvContent = generateVulnerabilityCSV(vulnerabilityResults);

      // Create blob and download
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `vulnerability_report_${vulnerabilityResults.domain}_${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      showNotification('success', 'Download Complete', 'Vulnerability report downloaded successfully.');
    } catch (error) {
      console.error('Error downloading report:', error);
      showNotification('error', 'Download Failed', 'Failed to generate vulnerability report.');
    }
  };

  const generateVulnerabilityCSV = (results: any) => {
    const headers = ['Subdomain', 'Vulnerability ID', 'Description', 'Severity'];
    const rows = [headers.join(',')];

    results.vulnerabilities.forEach((vuln: any) => {
      const row = [
        `"${vuln.subdomain}"`,
        `"${vuln.id}"`,
        `"${vuln.description.replace(/"/g, '""')}"`,
        vuln.severity
      ];
      rows.push(row.join(','));
    });

    return rows.join('\n');
  };

  // Domain Reputation Functions
  const startDomainReputationScan = async () => {
    const targetDomain = reputationSelectedDomain || reputationCustomDomain;

    if (!targetDomain) {
      showNotification('warning', 'Domain Required', 'Please select a domain from the dropdown or enter a custom domain');
      return;
    }

    try {
      setReputationLoading(true);
      setReputationResults(null);
      setReputationProgress(0);

      console.log('Starting domain reputation scan:', { domain: targetDomain });

      // Simulate progress during scan
      const progressInterval = setInterval(() => {
        setReputationProgress(prev => {
          if (prev >= 90) return prev;
          return prev + Math.random() * 10;
        });
      }, 1000);

      const response = await scanApi.startReputationScan(targetDomain);

      clearInterval(progressInterval);
      setReputationProgress(100);

      console.log('Domain reputation scan response:', response);

      if (response.status === 'success') {
        setReputationResults(response);
        showNotification('success', 'Scan Complete',
          `Domain reputation scan completed for ${targetDomain}. Found ${response.summary.total_issues} issues.`,
          { persistent: true, domain: targetDomain, scanType: 'reputation_scan' });

        // Refresh dashboard to update recent scans
        setTimeout(() => {
          console.log('Refreshing dashboard after reputation scan completion...');
          loadDashboardData();
        }, 1000);
      } else {
        showNotification('error', 'Scan Failed', response.message || 'Domain reputation scan failed');
      }

    } catch (error: any) {
      console.error('Error during domain reputation scan:', error);

      let errorMessage = 'Failed to start domain reputation scan. Please try again.';

      if (error?.response?.data?.message) {
        errorMessage = error.response.data.message;
      } else if (error?.message) {
        errorMessage = error.message;
      }

      showNotification('error', 'Scan Failed', errorMessage);
    } finally {
      setReputationLoading(false);
      setReputationProgress(0);
    }
  };

  const startNewReputationScan = () => {
    // Clear all results and reset state for a new scan
    setReputationResults(null);
    setReputationSelectedDomain('');
    setReputationCustomDomain('');
    setReputationFilter('all');
    setReputationSearchTerm('');
    setReputationProgress(0);
    setSelectedReputationIssue(null);

    showNotification('info', 'Ready for New Scan', 'Results cleared. Select a domain to start a new domain reputation scan.');
  };

  const openReputationModal = (title: string, vulnerabilities: any[]) => {
    setSelectedReputationIssue({ title, vulnerabilities });
  };

  const closeReputationModal = () => {
    setSelectedReputationIssue(null);
  };

  const downloadReputationReport = () => {
    if (!reputationResults) {
      showNotification('warning', 'No Data', 'No domain reputation scan results available to download.');
      return;
    }

    try {
      // Create CSV content
      const csvContent = generateReputationCSV(reputationResults);

      // Create blob and download
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `reputation_report_${reputationResults.domain}_${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      showNotification('success', 'Download Complete', 'Domain reputation report downloaded successfully.');
    } catch (error) {
      console.error('Error downloading reputation report:', error);
      showNotification('error', 'Download Failed', 'Failed to generate domain reputation report.');
    }
  };

  const generateReputationCSV = (results: any) => {
    const headers = ['Domain', 'Issue Type', 'Description', 'Severity'];
    const rows = [headers.join(',')];

    results.vulnerabilities.forEach((issue: any) => {
      const row = [
        `"${issue.domain || issue.subdomain}"`,
        `"${issue.issue_type}"`,
        `"${issue.description.replace(/"/g, '""')}"`,
        issue.severity
      ];
      rows.push(row.join(','));
    });

    return rows.join('\n');
  };

  const groupReputationIssuesByType = (issues: any[]) => {
    const grouped = issues.reduce((acc, issue) => {
      const key = issue.issue_type || 'Unknown Issue';
      if (!acc[key]) {
        acc[key] = [];
      }
      acc[key].push(issue);
      return acc;
    }, {} as Record<string, any[]>);

    return Object.entries(grouped).map(([description, vulnerabilities]) => {
      const vulnArray = vulnerabilities as any[];
      return {
        description,
        severity: vulnArray[0]?.severity || 'Unknown',
        affectedDomains: Array.from(new Set(vulnArray.map((v: any) => v.domain || v.subdomain))),
        vulnerabilities: vulnArray,
        issue_type: vulnArray[0]?.issue_type || 'Unknown'
      };
    }).sort((a, b) => getSeverityWeight(b.severity) - getSeverityWeight(a.severity));
  };

  // Network Scan Functions
  const startNetworkScan = async () => {
    const targetDomain = networkSelectedDomain || networkCustomDomain;

    if (!targetDomain) {
      showNotification('error', 'Error', 'Please select a domain or enter a custom domain');
      return;
    }

    try {
      setNetworkLoading(true);
      setNetworkProgress(0);
      setNetworkResults(null);

      // Check and discover subdomains if needed
      const canProceed = await checkAndDiscoverSubdomains(
        targetDomain,
        'Network',
        setNetworkProgress,
        setNetworkStatus
      );
      if (!canProceed) {
        setNetworkLoading(false);
        return;
      }

      showNotification('info', 'Network Scan Started', `Starting network scan for ${targetDomain}`);

      // Start the async network scan
      const startResponse = await scanApi.startNetworkScan(targetDomain);
      const scanId = startResponse.scan_id;
      setNetworkScanId(scanId);

      // Initial progress
      setNetworkProgress(10);

      // Start polling for status
      const pollInterval = setInterval(async () => {
        try {
          const statusResponse = await scanApi.getNetworkScanStatus(scanId);
          console.log(`Network scan status:`, statusResponse);

          // Update progress based on status
          if (statusResponse.status === 'running') {
            setNetworkProgress(prev => {
              const increment = Math.random() * 15 + 5; // Random increment between 5-20
              const newProgress = Math.min(prev + increment, 85); // Cap at 85% until completion
              console.log(`Network scan progress: ${prev}% -> ${newProgress}%`);
              return newProgress;
            });
          } else if (statusResponse.status === 'completed') {
            clearInterval(pollInterval);
            setNetworkProgress(100);

            // Process the completed results
            const processedResults = {
              domain: statusResponse.domain || targetDomain,
              final_score: statusResponse.final_score || 950,
              max_score: statusResponse.max_score || 950,
              processed_subdomains: statusResponse.processed_subdomains || 0,
              vulnerabilities: statusResponse.vulnerabilities || [],
              statistics: statusResponse.statistics || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
              summary: {
                total_issues: statusResponse.vulnerabilities?.length || 0,
                by_severity: statusResponse.statistics || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
                score_breakdown: {
                  final_score: statusResponse.final_score || 950,
                  max_score: statusResponse.max_score || 950,
                  percentage: statusResponse.final_score ? Math.round((statusResponse.final_score / (statusResponse.max_score || 950)) * 100) : 100
                }
              }
            };

            setNetworkResults(processedResults);
            setNetworkLoading(false);
            setNetworkProgress(0);
            setNetworkScanId(null);
            showNotification('success', 'Network Scan Complete', `Network scan completed for ${targetDomain}`,
              { persistent: true, domain: targetDomain, scanType: 'network_scan' });

            // Refresh dashboard to update recent scans
            setTimeout(() => {
              loadDashboardData();
            }, 1000);

          } else if (statusResponse.status === 'failed' || statusResponse.status === 'error') {
            clearInterval(pollInterval);
            setNetworkLoading(false);
            setNetworkProgress(0);
            setNetworkScanId(null);
            showNotification('error', 'Scan Failed', statusResponse.message || 'Network scan failed');
          }
        } catch (pollError) {
          console.error('Error polling network scan status:', pollError);
          clearInterval(pollInterval);
          setNetworkLoading(false);
          setNetworkProgress(0);
          setNetworkScanId(null);
          showNotification('error', 'Scan Failed', 'Failed to get scan status');
        }
      }, 2000); // Poll every 2 seconds

      // Set a timeout for the scan (10 minutes)
      setTimeout(() => {
        if (pollInterval) {
          clearInterval(pollInterval);
          setNetworkLoading(false);
          setNetworkProgress(0);
          setNetworkScanId(null);
          showNotification('error', 'Scan Timeout', 'Network scan timed out');
        }
      }, 600000); // 10 minutes

    } catch (error) {
      console.error('Error starting network scan:', error);
      setNetworkLoading(false);
      setNetworkProgress(0);
      setNetworkScanId(null);
      showNotification('error', 'Scan Failed', 'Failed to start network scan');
    }
  };

  const startNewNetworkScan = () => {
    setNetworkResults(null);
    setNetworkProgress(0);
    setSelectedNetworkIssue(null);
    setNetworkScanId(null);
    showNotification('info', 'New Network Scan', 'Ready for new network scan');
  };

  const openNetworkModal = (title: string, vulnerabilities: any[]) => {
    setSelectedNetworkIssue({ title, vulnerabilities });
  };

  const closeNetworkModal = () => {
    setSelectedNetworkIssue(null);
  };

  const downloadNetworkReport = () => {
    if (!networkResults) return;

    const csvContent = generateNetworkCSV(networkResults);
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network_scan_${networkResults.domain}_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  const generateNetworkCSV = (results: any) => {
    const headers = ['Subdomain', 'Port', 'Service', 'Severity', 'Description'];
    const rows = [headers.join(',')];

    results.vulnerabilities?.forEach((issue: any) => {
      const row = [
        `"${issue.subdomain || issue.domain}"`,
        `"${issue.port}"`,
        `"${issue.service}"`,
        issue.severity,
        `"${issue.description.replace(/"/g, '""')}"`
      ];
      rows.push(row.join(','));
    });

    return rows.join('\n');
  };

  const groupNetworkIssuesByType = (issues: any[]) => {
    const grouped = issues.reduce((acc, issue) => {
      const key = `${issue.service} (Port ${issue.port})`;
      if (!acc[key]) {
        acc[key] = [];
      }
      acc[key].push(issue);
      return acc;
    }, {} as Record<string, any[]>);

    return Object.entries(grouped).map(([description, vulnerabilities]) => {
      const vulnArray = vulnerabilities as any[];
      return {
        description,
        severity: vulnArray[0]?.severity || 'Unknown',
        affectedDomains: Array.from(new Set(vulnArray.map((v: any) => v.subdomain || v.domain))),
        vulnerabilities: vulnArray,
        port: vulnArray[0]?.port || 'Unknown',
        service: vulnArray[0]?.service || 'Unknown'
      };
    }).sort((a, b) => getSeverityWeight(b.severity) - getSeverityWeight(a.severity));
  };

  // DNS Security Functions (now async like network scans)
  const startDnsSecurityScan = async () => {
    const targetDomain = dnsSelectedDomain || dnsCustomDomain;

    if (!targetDomain) {
      showNotification('error', 'Domain Required', 'Please select or enter a domain to scan');
      return;
    }

    try {
      setDnsLoading(true);
      setDnsResults(null);
      setDnsProgress(10);

      console.log('Starting DNS security scan:', { domain: targetDomain });

      // Check and discover subdomains if needed
      const canProceed = await checkAndDiscoverSubdomains(
        targetDomain,
        'DNS Security',
        setDnsProgress,
        setDnsStatus
      );
      if (!canProceed) {
        setDnsLoading(false);
        return;
      }

      // Start DNS scan (returns scan_id immediately)
      const response = await scanApi.startDnsScan(targetDomain);

      if (response.status === 'started' && response.scan_id) {
        setDnsProgress(20);
        setDnsStatus('DNS security scan started, monitoring progress...');

        // Start polling for scan status
        const pollDnsScanStatus = async (scanId: string) => {
          try {
            const statusResponse = await scanApi.getDnsScanStatus(scanId);
            const scan = statusResponse.scan;

            if (scan.status === 'completed' && scan.result) {
              setDnsProgress(100);
              setDnsResults(scan.result);
              setDnsStatus('DNS security scan completed');
              showNotification('success', 'Scan Complete',
                `DNS security scan completed for ${targetDomain}. Found ${scan.result.summary.total_issues} issues.`,
                { persistent: true, domain: targetDomain, scanType: 'dns_scan' });

              // Refresh dashboard to update recent scans
              setTimeout(() => {
                loadDashboardData();
              }, 1000);
              setDnsLoading(false);
            } else if (scan.status === 'failed') {
              setDnsProgress(0);
              setDnsStatus('DNS security scan failed');
              showNotification('error', 'Scan Failed', scan.error || 'DNS security scan failed');
              setDnsLoading(false);
            } else {
              // Still running - update progress and continue polling
              setDnsProgress(scan.progress || 20);
              setDnsStatus(scan.logs && scan.logs.length > 0 ? scan.logs[scan.logs.length - 1] : 'DNS scan in progress...');

              // Continue polling after 3 seconds
              setTimeout(() => pollDnsScanStatus(scanId), 3000);
            }
          } catch (pollError) {
            console.error('Error polling DNS scan status:', pollError);
            setDnsProgress(0);
            setDnsStatus('Failed to monitor DNS scan progress');
            showNotification('error', 'Monitoring Failed', 'Lost connection to DNS scan. Please check results manually.');
            setDnsLoading(false);
          }
        };

        // Start polling
        setTimeout(() => pollDnsScanStatus(response.scan_id), 3000);

      } else {
        showNotification('error', 'Scan Failed', response.message || 'Failed to start DNS security scan');
        setDnsLoading(false);
      }
    } catch (error: any) {
      console.error('Error during DNS security scan:', error);
      setDnsProgress(0);
      let errorMessage = 'Failed to start DNS security scan. Please try again.';

      if (error.response?.status === 500) {
        errorMessage = error.response?.data?.message || 'DNS security scan service is currently unavailable.';
      } else if (error.response?.data?.message) {
        errorMessage = error.response.data.message;
      }

      showNotification('error', 'Scan Failed', errorMessage);
      setDnsLoading(false);
    }
  };

  const startNewDnsSecurityScan = () => {
    setDnsResults(null);
    setDnsProgress(0);
    setDnsSelectedDomain('');
    setDnsCustomDomain('');
    showNotification('info', 'Ready for New Scan', 'Results cleared. Select a domain to start a new DNS security scan.');
  };

  const openDnsModal = (title: string, vulnerabilities: any[]) => {
    setSelectedDnsIssue({ title, vulnerabilities });
  };

  const closeDnsModal = () => {
    setSelectedDnsIssue(null);
  };

  const downloadDnsReport = () => {
    if (!dnsResults) {
      showNotification('warning', 'No Data', 'No DNS security scan results available to download.');
      return;
    }

    try {
      const csvContent = generateDnsCSV(dnsResults);
      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dns_security_report_${dnsResults.domain}_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      showNotification('success', 'Download Complete', 'DNS security report downloaded successfully.');
    } catch (error) {
      console.error('Error downloading DNS report:', error);
      showNotification('error', 'Download Failed', 'Failed to generate DNS security report.');
    }
  };

  const generateDnsCSV = (results: any) => {
    const headers = ['Issue Type', 'Affected Domain', 'Severity', 'Description'];
    const rows = results.vulnerabilities.map((vuln: any) => [
      vuln.title || vuln.issue_type || '',
      vuln.subdomain || vuln.domain || '',
      vuln.severity || '',
      vuln.description || ''
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map((row: string[]) => row.map(field => `"${(field || '').toString().replace(/"/g, '""')}"`).join(','))
    ].join('\n');

    return csvContent;
  };

  const groupDnsIssuesByType = (issues: any[]) => {
    const groups: { [key: string]: any } = {};

    issues.forEach(issue => {
      // Create a specific key using description for better grouping, similar to website vulnerabilities
      const key = issue.description || issue.title || issue.issue_type || 'DNS Security Issue';

      if (!groups[key]) {
        groups[key] = {
          description: key,
          title: issue.title || issue.issue_type || 'DNS Security Issue',
          severity: issue.severity,
          affectedDomains: [],
          vulnerabilities: []
        };
      }

      // Add domain to affected domains list if not already present
      const domain: string = issue.domain || issue.subdomain || 'Unknown Domain';
      if (!groups[key].affectedDomains.includes(domain)) {
        groups[key].affectedDomains.push(domain);
      }

      // Store the original issue data
      groups[key].vulnerabilities.push(issue);

      // Use highest severity if multiple instances have different severities
      const currentWeight = getSeverityWeight(issue.severity);
      const groupWeight = getSeverityWeight(groups[key].severity);
      if (currentWeight > groupWeight) {
        groups[key].severity = issue.severity;
      }
    });

    // Convert to array and sort by severity (highest first)
    return Object.values(groups).sort((a: any, b: any) =>
      getSeverityWeight(b.severity) - getSeverityWeight(a.severity)
    );
  };

  // Encryption Scan Functions
  const startEncryptionScan = async () => {
    if (!encryptionSelectedDomain && !encryptionCustomDomain) {
      showNotification('error', 'Domain Required', 'Please select a vendor or enter a custom domain');
      return;
    }

    const domain = encryptionCustomDomain || encryptionSelectedDomain;
    const scanId = `encryption_${Date.now()}`;

    try {
      setEncryptionLoading(true);
      setEncryptionProgress(5);
      setEncryptionResults(null);
      setEncryptionScanId(scanId);

      // Check and discover subdomains if needed
      const canProceed = await checkAndDiscoverSubdomains(
        domain,
        'Encryption',
        setEncryptionProgress,
        setEncryptionStatus
      );
      if (!canProceed) {
        setEncryptionLoading(false);
        return;
      }

      showNotification('info', 'Encryption Scan Started', `Analyzing SSL/TLS configuration for ${domain}. This may take several minutes...`);

      // Simulate progress during the scan
      const progressInterval = setInterval(() => {
        setEncryptionProgress(prev => {
          if (prev < 90) {
            const increment = Math.random() * 8 + 2; // Random increment between 2-10
            return Math.min(prev + increment, 90); // Cap at 90% until completion
          }
          return prev;
        });
      }, 3000); // Update every 3 seconds

      // Start the encryption scan (now returns immediately with scan_id)
      const startResult = await scanApi.startEncryptionScan(domain, scanId);

      if (startResult.scan_id) {
        // Clear the fake progress interval
        clearInterval(progressInterval);

        // Wait for scan completion with real status polling and progress updates
        const result = await waitForEncryptionScanCompletion(startResult.scan_id, domain, setEncryptionProgress);

        if (result.status === 'success' || result.final_score !== undefined) {
          setEncryptionResults(result);
          setEncryptionProgress(100);
          showNotification('success', 'Encryption Scan Complete', `Found ${result.vulnerabilities?.length || 0} SSL/TLS issues. Analysis complete!`,
            { persistent: true, domain: domain, scanType: 'encryption_scan' });

          // Refresh dashboard to update recent scans
          setTimeout(() => {
            loadDashboardData();
          }, 1000);
        } else {
          throw new Error(result.error || 'Encryption scan failed');
        }
      } else {
        // Clear the progress interval
        clearInterval(progressInterval);
        throw new Error(startResult.message || 'Failed to start encryption scan');
      }
    } catch (error: any) {
      console.error('Encryption scan error:', error);
      setEncryptionProgress(0);

      // Check if it's a timeout error
      if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
        showNotification('error', 'Scan Timeout', 'SSL/TLS scan took too long. Please try again or contact support if the issue persists.');
      } else {
        showNotification('error', 'Encryption Scan Failed', error.message || 'Failed to complete SSL/TLS scan');
      }
    } finally {
      setEncryptionLoading(false);
      setEncryptionScanId(null);
    }
  };

  const startNewEncryptionScan = () => {
    setEncryptionResults(null);
    setEncryptionProgress(0);
    setEncryptionFilter('all');
    setEncryptionSearchTerm('');
    setSelectedEncryptionIssue(null);
    setEncryptionScanId(null);
  };

  const stopEncryptionScan = async () => {
    if (!encryptionScanId) return;

    try {
      await scanApi.stopEncryptionScan(encryptionScanId);
      setEncryptionLoading(false);
      setEncryptionProgress(0);
      setEncryptionScanId(null);
      showNotification('info', 'Scan Stopped', 'SSL/TLS encryption scan has been stopped');
    } catch (error) {
      console.error('Error stopping encryption scan:', error);
      showNotification('error', 'Stop Failed', 'Failed to stop encryption scan');
    }
  };

  const openEncryptionModal = (title: string, vulnerabilities: any[]) => {
    setSelectedEncryptionIssue({ title, vulnerabilities });
  };

  const closeEncryptionModal = () => {
    setSelectedEncryptionIssue(null);
  };

  const downloadEncryptionReport = () => {
    if (!encryptionResults) {
      showNotification('error', 'No Data', 'No encryption scan results to download');
      return;
    }

    try {
      const csvContent = generateEncryptionCSV(encryptionResults);
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `encryption_scan_${encryptionResults.domain}_${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      showNotification('success', 'Download Started', 'Encryption scan report downloaded successfully');
    } catch (error) {
      console.error('Download error:', error);
      showNotification('error', 'Download Failed', 'Failed to download encryption scan report');
    }
  };

  const generateEncryptionCSV = (results: any) => {
    const headers = ['Domain', 'Vulnerability', 'Severity', 'Description', 'Category'];
    const csvRows = [headers.join(',')];

    results.vulnerabilities.forEach((vuln: any) => {
      const row = [
        vuln.domain || '',
        vuln.vulnerability || '',
        vuln.severity || '',
        (vuln.description || '').replace(/,/g, ';'),
        vuln.category || ''
      ];
      csvRows.push(row.join(','));
    });

    return csvRows.join('\n');
  };

  const groupEncryptionIssuesByType = (issues: any[]) => {
    const groups: { [key: string]: any } = {};

    issues.forEach(issue => {
      // Create a specific key using vulnerability name for grouping
      const key = issue.vulnerability || issue.description || 'SSL/TLS Security Issue';

      if (!groups[key]) {
        groups[key] = {
          description: key,
          title: issue.vulnerability || 'SSL/TLS Security Issue',
          severity: issue.severity,
          affectedDomains: [],
          vulnerabilities: []
        };
      }

      // Add domain to affected domains list if not already present
      const domain: string = issue.domain || issue.subdomain || 'Unknown Domain';
      if (!groups[key].affectedDomains.includes(domain)) {
        groups[key].affectedDomains.push(domain);
      }

      // Store the original issue data
      groups[key].vulnerabilities.push(issue);

      // Use highest severity if multiple instances have different severities
      const currentWeight = getSeverityWeight(issue.severity);
      const groupWeight = getSeverityWeight(groups[key].severity);
      if (currentWeight > groupWeight) {
        groups[key].severity = issue.severity;
      }
    });

    // Convert to array and sort by severity (highest first)
    return Object.values(groups).sort((a: any, b: any) =>
      getSeverityWeight(b.severity) - getSeverityWeight(a.severity)
    );
  };

  // Email Scan Functions
  const startEmailScan = async () => {
    if (!emailSelectedDomain && !emailCustomDomain) {
      showNotification('error', 'Domain Required', 'Please select a vendor or enter a custom domain');
      return;
    }

    const domain = emailCustomDomain || emailSelectedDomain;
    const scanId = `email_${Date.now()}`;

    try {
      setEmailLoading(true);
      setEmailProgress(5);
      setEmailResults(null);
      setEmailScanId(scanId);
      showNotification('info', 'Email Scan Started', `Analyzing email security configuration for ${domain}. This may take a few minutes...`);

      // Simulate progress during the scan
      const progressInterval = setInterval(() => {
        setEmailProgress(prev => {
          if (prev < 90) {
            const increment = Math.random() * 8 + 2; // Random increment between 2-10
            return Math.min(prev + increment, 90); // Cap at 90% until completion
          }
          return prev;
        });
      }, 3000); // Update every 3 seconds

      // Start the email scan
      const result = await scanApi.startEmailScan(domain, scanId);

      // Clear the progress interval
      clearInterval(progressInterval);

      if (result.status === 'success') {
        setEmailResults(result);
        setEmailProgress(100);
        showNotification('success', 'Email Scan Complete', `Found ${result.vulnerabilities.length} email security issues. Analysis complete!`,
          { persistent: true, domain: domain, scanType: 'email_scan' });

        // Refresh dashboard to update recent scans
        setTimeout(() => {
          loadDashboardData();
        }, 1000);
      } else {
        throw new Error(result.message || 'Email scan failed');
      }
    } catch (error: any) {
      console.error('Email scan error:', error);
      setEmailProgress(0);

      // Check if it's a timeout error
      if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
        showNotification('error', 'Scan Timeout', 'Email scan took too long. Please try again or contact support if the issue persists.');
      } else {
        showNotification('error', 'Email Scan Failed', error.message || 'Failed to complete email security scan');
      }
    } finally {
      setEmailLoading(false);
      setEmailScanId(null);
    }
  };

  const startNewEmailScan = () => {
    setEmailResults(null);
    setEmailProgress(0);
    setEmailFilter('all');
    setEmailSearchTerm('');
    setSelectedEmailIssue(null);
    setEmailScanId(null);
  };

  const stopEmailScan = async () => {
    if (!emailScanId) return;

    try {
      await scanApi.stopEmailScan(emailScanId);
      setEmailLoading(false);
      setEmailProgress(0);
      setEmailScanId(null);
      showNotification('info', 'Scan Stopped', 'Email security scan has been stopped');
    } catch (error) {
      console.error('Error stopping email scan:', error);
      showNotification('error', 'Stop Failed', 'Failed to stop email scan');
    }
  };

  const openEmailModal = (title: string, vulnerabilities: any[]) => {
    setSelectedEmailIssue({ title, vulnerabilities });
  };

  const closeEmailModal = () => {
    setSelectedEmailIssue(null);
  };

  const downloadEmailReport = () => {
    if (!emailResults) return;

    const csvContent = generateEmailCSV(emailResults);
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${emailResults.domain}_email_security_report.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  const generateEmailCSV = (results: any) => {
    const headers = ['Domain', 'Issue Type', 'Severity', 'Description', 'Category'];
    const rows = results.vulnerabilities.map((vuln: any) => [
      vuln.subdomain || results.domain,
      vuln.title || 'Email Security Issue',
      vuln.severity || 'Medium',
      vuln.description || 'Email security configuration issue',
      vuln.category || 'Email'
    ]);

    const csvContent = [headers, ...rows]
      .map(row => row.map((cell: string) => `"${cell}"`).join(','))
      .join('\n');

    return csvContent;
  };

  const groupEmailIssuesByType = (issues: any[]) => {
    const groups: { [key: string]: any } = {};

    issues.forEach(issue => {
      // Create a specific key for grouping similar email issues
      const key = issue.title || 'Email Security Issue';

      if (!groups[key]) {
        groups[key] = {
          title: key,
          description: issue.description || key,
          severity: issue.severity,
          affectedDomains: [],
          vulnerabilities: []
        };
      }

      // Add domain to affected domains list if not already present
      const domain: string = issue.subdomain || issue.domain || 'Unknown Domain';
      if (!groups[key].affectedDomains.includes(domain)) {
        groups[key].affectedDomains.push(domain);
      }

      // Store the original issue data
      groups[key].vulnerabilities.push(issue);

      // Use highest severity if multiple instances have different severities
      const currentWeight = getSeverityWeight(issue.severity);
      const groupWeight = getSeverityWeight(groups[key].severity);
      if (currentWeight > groupWeight) {
        groups[key].severity = issue.severity;
      }
    });

    // Convert to array and sort by severity (highest first)
    return Object.values(groups).sort((a: any, b: any) =>
      getSeverityWeight(b.severity) - getSeverityWeight(a.severity)
    );
  };

  // Load all news data by default when component mounts or time period changes
  useEffect(() => {
    const loadNewsDataWithTimeline = async () => {
      try {
        setIncidentsLoading(true);

        // Check if a domain is selected
        const selectedDomain = incidentsCustomDomain || incidentsSelectedDomain;

        if (selectedDomain) {
          // If domain is selected, get data for that specific domain with new timeline
          const result = await incidentApi.getAllNews(incidentsMonths, selectedDomain);

          if (result.status === 'success') {
            const processedResult = {
              ...result,
              domain: selectedDomain,
              incidents: result.incidents || [],
              news: result.news || []
            };
            setIncidentsResults(processedResult);
            console.log('Loaded domain-specific news data with timeline:', processedResult);
          }
        } else {
          // No domain selected, get all data with new timeline
          const result = await incidentApi.getAllNews(incidentsMonths);

          if (result.status === 'success') {
            const processedResult = {
              ...result,
              domain: 'All Domains',
              incidents: result.incidents || [],
              news: result.news || []
            };
            setIncidentsResults(processedResult);
            console.log('Loaded all news data with timeline:', processedResult);
          }
        }
      } catch (error) {
        console.error('Error loading news data with timeline:', error);
        // Set empty results instead of showing error
        setIncidentsResults({
          status: 'success',
          domain: incidentsCustomDomain || incidentsSelectedDomain || 'All Domains',
          incidents: [],
          news: [],
          summary: 'No data available in database',
          notes: 'Database is empty. Background scan will populate with fresh data.'
        });
      } finally {
        setIncidentsLoading(false);
      }
    };

    loadNewsDataWithTimeline();
  }, [incidentsMonths, incidentsSelectedDomain, incidentsCustomDomain]);

  // Note: Automatic news scanning is now handled by the backend scheduler (every 2 hours)
  // Manual scans can still be triggered via the "Scan All Domains" button if needed

  // Auto-apply filters when domain selection changes
  useEffect(() => {
    const domain = incidentsCustomDomain || incidentsSelectedDomain;
    if (incidentsResults) {
      applyFilters();
    }
  }, [incidentsSelectedDomain, incidentsCustomDomain]);

  // News & Incidents Functions

  // Apply filters to existing data (no API call needed)
  const applyFilters = async () => {
    const domain = incidentsCustomDomain || incidentsSelectedDomain;

    try {
      setIncidentsLoading(true);

      if (domain) {
        // Filter for specific domain
        showNotification('info', 'Applying Filter', `Filtering data for ${domain}...`);
        const result = await incidentApi.getAllNews(incidentsMonths, domain);

        if (result.status === 'success') {
          const processedResult = {
            ...result,
            domain: domain,
            incidents: result.incidents || [],
            news: result.news || []
          };
          setIncidentsResults(processedResult);
          showNotification('success', 'Filter Applied', `Showing data for ${domain}`);
        }
      } else {
        // Show all domains
        const result = await incidentApi.getAllNews(incidentsMonths);

        if (result.status === 'success') {
          const processedResult = {
            ...result,
            domain: 'All Domains',
            incidents: result.incidents || [],
            news: result.news || []
          };
          setIncidentsResults(processedResult);
          showNotification('success', 'Filter Cleared', 'Showing data for all domains');
        }
      }
    } catch (error: any) {
      console.error('Filter error:', error);
      showNotification('error', 'Filter Failed', error.message || 'Failed to apply filter');
    } finally {
      setIncidentsLoading(false);
    }
  };

  const startNewIncidentsLookup = async () => {
    // Clear filters
    setIncidentsSelectedDomain('');
    setIncidentsCustomDomain('');
    setIncidentsFilter('all');
    setIncidentsSearchTerm('');
    setNewsFilter('all');
    setNewsSearchTerm('');

    // Reload all data without filters
    try {
      setIncidentsLoading(true);
      const result = await incidentApi.getAllNews(incidentsMonths);

      if (result.status === 'success') {
        const processedResult = {
          ...result,
          domain: 'All Domains',
          incidents: result.incidents || [],
          news: result.news || []
        };
        setIncidentsResults(processedResult);
        showNotification('success', 'Filters Cleared', 'Showing all available data');
      }
    } catch (error: any) {
      console.error('Error clearing filters:', error);
    } finally {
      setIncidentsLoading(false);
    }
  };

  const downloadIncidentsReport = () => {
    if (!incidentsResults) return;

    const csvContent = generateIncidentsCSV(incidentsResults);
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${incidentsResults.domain}_incidents_news_report.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  const generateIncidentsCSV = (results: any) => {
    const headers = ['Type', 'Date', 'Title', 'Severity', 'Source', 'Description'];
    const rows: string[][] = [];

    // Add incidents
    if (results.incidents) {
      results.incidents.forEach((incident: any) => {
        rows.push([
          'Incident',
          incident.date || incident.timestamp || 'Unknown',
          incident.title || 'Incident',
          incident.severity || 'Medium',
          incident.source || 'Unknown',
          incident.description || incident.summary || 'Security incident'
        ]);
      });
    }

    // Add news
    if (results.news) {
      results.news.forEach((newsItem: any) => {
        rows.push([
          'News',
          newsItem.date || newsItem.timestamp || 'Unknown',
          newsItem.title || 'News',
          'Info', // News severity is always Info
          newsItem.source || 'Unknown',
          newsItem.description || newsItem.summary || 'Security news'
        ]);
      });
    }

    const csvContent = [headers, ...rows]
      .map(row => row.map((cell: string) => `"${cell}"`).join(','))
      .join('\n');

    return csvContent;
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return 'Unknown';
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    } catch {
      return dateString;
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      case 'info': return 'info';
      case 'informational': return 'info';
      default: return 'info';
    }
  };

  // Certifications Functions
  const loadCertificationsData = async () => {
    try {
      setCertificationsLoading(true);

      // Load statistics
      const stats = await certificationApi.getStatistics();
      setCertificationsStats(stats);

      // Load certifications with current filters
      const filters = Object.entries(selectedFilters)
        .filter(([key, value]) => value && key !== 'no_certifications')
        .reduce((acc, [key, value]) => ({ ...acc, [key]: value }), {});

      const data = await certificationApi.getCertifications(Object.keys(filters).length > 0 ? filters : undefined);

      // If no_certifications filter is selected, filter out vendors with certifications
      if (selectedFilters.no_certifications) {
        data.vendors = data.vendors.filter(vendor =>
          !vendor.certifications?.iso_27001 && !vendor.certifications?.soc2
        );
      }

      setCertificationsData(data);
    } catch (error: any) {
      console.error('Error loading certifications data:', error);
      showNotification('error', 'Load Failed', 'Failed to load certifications data');
    } finally {
      setCertificationsLoading(false);
    }
  };

  const handleFilterChange = (filterName: string, checked: boolean) => {
    setSelectedFilters(prev => ({
      ...prev,
      [filterName]: checked
    }));
  };

  const clearAllFilters = () => {
    setSelectedFilters({
      iso_27001: false,
      soc2: false,
      both_certifications: false,
      no_certifications: false
    });
  };

  const refreshCertifications = () => {
    loadCertificationsData();
    showNotification('info', 'Refreshing', 'Reloading certifications data...');
  };

  // Filter vendors based on search term
  const getFilteredVendors = () => {
    if (!certificationsData?.vendors) return [];

    if (!certificationsSearchTerm.trim()) {
      return certificationsData.vendors;
    }

    const searchTerm = certificationsSearchTerm.toLowerCase().trim();
    return certificationsData.vendors.filter(vendor =>
      vendor.name.toLowerCase().includes(searchTerm) ||
      vendor.domain.toLowerCase().includes(searchTerm)
    );
  };

  // Get score color based on score value (following analytics page color scheme)
  const getScoreColor = (score: number) => {
    if (score >= 801) return '#22c55e'; // Green - Excellent (A)
    if (score >= 601) return '#84cc16'; // Lime Green - Good (B)
    if (score >= 401) return '#fbbf24'; // Yellow - Fair (C)
    if (score >= 201) return '#f97316'; // Orange - Poor (D)
    return '#ef4444'; // Red - Critical (F)
  };

  // Get score background color for dark mode compatibility
  const getScoreBackgroundColor = (score: number, isDark: boolean) => {
    if (isDark) {
      if (score >= 801) return 'rgba(34, 197, 94, 0.2)'; // Green
      if (score >= 601) return 'rgba(132, 204, 22, 0.2)'; // Lime Green
      if (score >= 401) return 'rgba(251, 191, 36, 0.2)'; // Yellow
      if (score >= 201) return 'rgba(249, 115, 22, 0.2)'; // Orange
      return 'rgba(239, 68, 68, 0.2)'; // Red
    } else {
      if (score >= 801) return '#dcfce7'; // Green
      if (score >= 601) return '#ecfccb'; // Lime Green
      if (score >= 401) return '#fef3c7'; // Yellow
      if (score >= 201) return '#fed7aa'; // Orange
      return '#fee2e2'; // Red
    }
  };

  // Get scan status class based on score (for recent scans)
  const getScanStatusFromScore = (score: number) => {
    if (score >= 801) return 'excellent';
    if (score >= 601) return 'good';
    if (score >= 401) return 'fair';
    if (score >= 201) return 'poor';
    return 'critical';
  };

  const checkAllCertifications = async () => {
    try {
      setCertificationsLoading(true);
      showNotification('info', 'Checking Certifications', 'Running certification checks for all vendors...');

      const result = await certificationApi.checkCertifications([], true);

      // Log the certifications check action
      logUserAction('SCAN', 'certifications', undefined, {
        action_type: 'check_all_certifications',
        scan_type: 'certifications',
        vendors_updated: result.vendors_updated || 0,
        check_all: true,
        context: 'certifications_check_all',
        timestamp: new Date().toISOString()
      });

      if (result.status === 'success') {
        showNotification('success', 'Check Complete', `Updated certifications for ${result.vendors_updated} vendors`);
        await loadCertificationsData(); // Reload data after check
      } else if (result.status === 'started') {
        showNotification('success', 'Check Started', `Certification check started in background for ${result.domains_count} domains. Results will be updated automatically.`);
        // Set up periodic refresh to check for updates
        const refreshInterval = setInterval(async () => {
          await loadCertificationsData();
        }, 30000); // Refresh every 30 seconds

        // Clear interval after 10 minutes (should be enough for most checks)
        setTimeout(() => {
          clearInterval(refreshInterval);
        }, 600000);
      } else {
        throw new Error(result.message || 'Certification check failed');
      }
    } catch (error: any) {
      console.error('Error checking certifications:', error);
      showNotification('error', 'Check Failed', error.message || 'Failed to check certifications');
    } finally {
      setCertificationsLoading(false);
    }
  };

  const checkSingleDomainCertifications = async (domain: string, vendorName: string) => {
    try {
      showNotification('info', 'Checking Certifications', `Running certification check for ${vendorName}...`);

      const result = await certificationApi.checkCertifications([domain], false);

      if (result.status === 'success') {
        showNotification('success', 'Check Complete', `Updated certifications for ${vendorName}`);
        await loadCertificationsData(); // Reload data after check
      } else if (result.status === 'started') {
        showNotification('success', 'Check Started', `Certification check started in background for ${vendorName}. Results will be updated automatically.`);
        // Refresh data after a delay to catch the results
        setTimeout(async () => {
          await loadCertificationsData();
        }, 60000); // Refresh after 1 minute
      } else {
        throw new Error(result.message || 'Certification check failed');
      }
    } catch (error: any) {
      console.error('Error checking certifications for single domain:', error);
      showNotification('error', 'Check Failed', error.message || `Failed to check certifications for ${vendorName}`);
    }
  };

  const newSubdomainSearch = () => {
    setSelectedDomain('');
    setCustomDomain('');
    setSubdomainResults(null);
    setExistingSubdomains(null);
    showNotification('info', 'New Search', 'Ready for new subdomain discovery');
  };

  useEffect(() => {
    // Make logger available globally for testing and debugging
    if (typeof window !== 'undefined') {
      (window as any).logger = logger;
    }

    // Warm up caches first, then load dashboard data
    const initializeApp = async () => {
      try {
        logger.info('general', 'Initializing Vendiant Dashboard application', {
          timestamp: new Date().toISOString(),
          userAgent: typeof window !== 'undefined' ? window.navigator.userAgent : 'unknown',
          url: typeof window !== 'undefined' ? window.location.href : 'unknown'
        });



        // Warm up critical caches in parallel with dashboard loading
        await Promise.all([
          cacheUtils.warmUpCaches(),
          loadDashboardData(),
          loadVulnerabilityTrends(),
          checkActiveBackgroundScans()
        ]);

        // Check for any already-active background scans and resume monitoring them
        try {
          const jobsResponse = await backgroundScanApi.listJobs();
          const activeJob = jobsResponse.jobs?.find((job) => job.status === 'starting' || job.status === 'running');
          if (activeJob) {
            setIsBackgroundScanRunning(true);
            monitorBackgroundScan(activeJob.job_id);
          }
        } catch (e) {
          logger.warn('scan', 'Background scan status check skipped', e);
        }

        logger.success('general', 'App initialization completed successfully', {
          totalVendors: vendors?.length || 0,
          dashboardStats: stats ? Object.keys(stats) : [],
          initializationTime: Date.now()
        });


      } catch (error) {
        logger.error('general', 'App initialization failed', {
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined
        });
        // Still try to load dashboard data even if cache warm-up fails
        loadDashboardData();
        loadVulnerabilityTrends();
      }
    };

    initializeApp();
  }, []);

  // Periodically check for new scans (in case backend auto-scheduler starts one)
  useEffect(() => {
    const interval = setInterval(() => {
      if (!isBackgroundScanRunning && !monitoringJobId) {
        checkActiveBackgroundScans();
      }
    }, 20000);
    return () => clearInterval(interval);
  }, [isBackgroundScanRunning, monitoringJobId]);

  // Handle section parameter from URL
  useEffect(() => {
    if (searchParams) {
      const section = searchParams.get('section');
      if (section && [
        'dashboard', 'vendor-comparison', 'vendors', 'subdomains', 'security-scans',
        'vulnerabilities', 'reputation', 'network', 'dns', 'encryption', 'emails',
        'certifications', 'incidents', 'vendor-breaches', 'breaches', 'breach-monitor'
      ].includes(section)) {
        setActiveSection(section);
      }

      const breachMonitorView = searchParams.get('breach_monitor_view');
      if (breachMonitorView === 'clients' || breachMonitorView === 'employees') {
        setBreachMonitorLeakView(breachMonitorView);
      }
      const dateFrom = searchParams.get('date_from');
      const dateTo = searchParams.get('date_to');
      const dateField = searchParams.get('date_field');
      if (dateFrom) {
        setBreachMonitorDateFrom(dateFrom);
      }
      if (dateTo) {
        setBreachMonitorDateTo(dateTo);
      }
      if (dateField === 'ingested' || dateField === 'exposure') {
        setBreachMonitorDateField(dateField);
      }
    }
  }, [searchParams]);

  // Bounce users off sections they are not allowed to view (No Access).
  useEffect(() => {
    const denied =
      (activeSection === 'vendors' && !canViewVendors) ||
      (activeSection === 'security-scans' && !canViewSecurityScans) ||
      (activeSection === 'subdomains' && !canViewSubdomains) ||
      (activeSection === 'certifications' && !canViewCertifications) ||
      (activeSection === 'incidents' && !canViewIncidents) ||
      (activeSection === 'vendor-breaches' && !canViewPwnMonitor) ||
      (activeSection === 'breach-monitor' && !canViewInternalBreaches);
    if (denied) {
      setActiveSection('dashboard');
      router.replace('/');
    }
  }, [
    activeSection,
    canViewVendors,
    canViewSecurityScans,
    canViewSubdomains,
    canViewCertifications,
    canViewIncidents,
    canViewPwnMonitor,
    canViewInternalBreaches,
    router,
  ]);

  // Keyboard shortcuts for debugging
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Ctrl/Cmd + Shift + L to toggle log viewer
      if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'L') {
        event.preventDefault();
        setShowLogViewer(prev => !prev);
        logger.info('ui', `Log viewer ${showLogViewer ? 'closed' : 'opened'} via keyboard shortcut`);
      }

      // Ctrl/Cmd + Shift + C to clear logs
      if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'C') {
        event.preventDefault();
        logger.clearLogs();
        logger.info('general', 'Logs cleared via keyboard shortcut');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showLogViewer]);

  // Load certifications data when filters change
  useEffect(() => {
    if (activeSection === 'certifications') {
      loadCertificationsData();
    }
  }, [activeSection, selectedFilters]);

  useEffect(() => {
    if (activeSection === 'breach-monitor' && canViewInternalBreaches) {
      refreshBreachMonitorQuota();
    }
  }, [activeSection, canViewInternalBreaches, refreshBreachMonitorQuota]);

  const refreshVendorScores = async () => {
    try {
      console.log('Refreshing vendor scores...');
      showNotification('info', 'Refreshing Scores', 'Updating vendor security scores...');

      logger.info('ui', 'Starting vendor scores refresh', {
        action: 'refresh_scores',
        clearingCache: true
      });

      // Clear vendor and dashboard caches to ensure fresh data
      cacheUtils.clearVendorCaches();
      cacheUtils.clearDashboardCaches();

      logger.debug('cache', 'Cleared vendor and dashboard caches for score refresh');

      // Call the refresh scores API (which now uses unified scoring internally)
      const result = await vendorApi.refreshScores();

      if (result.status === 'success') {
        logger.success('api', 'Vendor scores refresh API completed', {
          updatedCount: result.updated_count,
          totalVendors: result.total_vendors
        });

        // Reload the vendors data with fresh data (bypassing cache)
        await loadDashboardData(true);

        const updatedVendors = result.updated_vendors || [];
        const unifiedCount = updatedVendors.filter((v: any) => v.method === 'unified').length;
        const legacyCount = updatedVendors.filter((v: any) => v.method === 'legacy').length;

        let methodInfo = '';
        if (unifiedCount > 0 && legacyCount > 0) {
          methodInfo = ` (${unifiedCount} unified, ${legacyCount} legacy)`;
        } else if (unifiedCount > 0) {
          methodInfo = ` using unified scoring`;
        } else if (legacyCount > 0) {
          methodInfo = ` using legacy method`;
        }

        logger.success('ui', 'Vendor scores refresh completed successfully', {
          updatedCount: result.updated_count,
          totalVendors: result.total_vendors,
          unifiedCount,
          legacyCount
        });

        showNotification('success', 'Scores Updated',
          `Updated scores for ${result.updated_count}/${result.total_vendors} vendors${methodInfo}`);
      } else {
        logger.error('api', 'Vendor scores refresh failed', {
          error: result.message,
          status: result.status
        });
        showNotification('error', 'Refresh Failed', result.message || 'Failed to refresh vendor scores');
      }
    } catch (error) {
      console.error('Error refreshing vendor scores:', error);
      logger.error('ui', 'Vendor scores refresh error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined
      });
      showNotification('error', 'Refresh Failed', 'Failed to refresh vendor scores');
    }
  };

  const refreshVendorScore = async (vendorId: number) => {
    try {
      console.log(`Refreshing score for vendor ${vendorId}...`);
      showNotification('info', 'Refreshing Score', 'Updating vendor security score...');

      logger.info('ui', 'Starting individual vendor score refresh', {
        vendorId,
        action: 'refresh_vendor_score',
        clearingCache: true
      });

      // Clear vendor and dashboard caches to ensure fresh data
      cacheUtils.clearVendorCaches();
      cacheUtils.clearDashboardCaches();

      logger.debug('cache', 'Cleared vendor and dashboard caches for individual score refresh', { vendorId });

      // Call the refresh score API (which now uses unified scoring internally)
      const result = await vendorApi.refreshVendorScore(vendorId);

      if (result.status === 'success') {
        logger.success('api', 'Individual vendor score refresh API completed', {
          vendorId,
          vendorName: result.vendor?.name,
          oldScore: result.old_score,
          newScore: result.new_score,
          unifiedScoringUsed: result.unified_scoring_used
        });

        // Force fresh data load (bypassing cache) to show updated score
        await loadDashboardData(true);

        const method = result.unified_scoring_used ? 'unified scoring' : 'legacy method';
        const scoreChange = result.old_score !== result.new_score ?
          ` (${result.old_score} → ${result.new_score})` : '';

        logger.success('ui', 'Individual vendor score refresh completed successfully', {
          vendorId,
          vendorName: result.vendor?.name,
          method: method,
          scoreChanged: result.old_score !== result.new_score
        });

        showNotification('success', 'Score Updated',
          `Score updated for ${result.vendor?.name || 'vendor'} using ${method}${scoreChange}`);
      } else if (result.status === 'info') {
        logger.info('api', 'Individual vendor score refresh - no update needed', {
          vendorId,
          message: result.message
        });
        showNotification('info', 'No Update', result.message || 'No scan results found for this vendor');
      } else {
        logger.error('api', 'Individual vendor score refresh failed', {
          vendorId,
          error: result.message,
          status: result.status
        });
        showNotification('error', 'Update Failed', result.message || 'Failed to update vendor score');
      }
    } catch (error) {
      console.error(`Error refreshing score for vendor ${vendorId}:`, error);
      logger.error('ui', 'Individual vendor score refresh error', {
        vendorId,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined
      });
      showNotification('error', 'Refresh Failed', 'Failed to refresh vendor score');
    }
  };

  const reloadVendors = async () => {
    try {
      console.log('Reloading vendors...');
      showNotification('info', 'Reloading Vendors', 'Fetching latest vendor data from database...');

      logger.info('ui', 'Starting vendor reload operation', {
        action: 'reload_vendors',
        clearingCache: true
      });

      // Clear vendor and dashboard caches first
      cacheUtils.clearVendorCaches();
      cacheUtils.clearDashboardCaches();

      logger.debug('cache', 'Cleared vendor and dashboard caches for vendor reload');

      // Call the reload vendors API (this will reload from Excel/database and clear backend cache)
      const result = await vendorApi.reloadVendors();

      if (result.status === 'success') {
        logger.success('api', 'Vendor reload API completed', {
          vendorCount: result.vendor_count || 0,
          message: result.message
        });

        // Force fresh data load (bypassing cache) to get the newly reloaded vendors
        await loadDashboardData(true);

        // Warm up caches with fresh data
        logger.info('cache', 'Warming up caches with fresh vendor data');
        await cacheUtils.warmUpCaches();

        logger.success('ui', 'Vendor reload completed successfully', {
          vendorCount: result.vendor_count || 0,
          source: result.source || 'database'
        });

        showNotification('success', 'Vendors Reloaded',
          `Successfully reloaded ${result.vendor_count || 'vendor'} vendors from ${result.source || 'database'}`);
      } else {
        logger.error('api', 'Vendor reload failed', {
          error: result.message,
          status: result.status
        });
        showNotification('error', 'Reload Failed', result.message || 'Failed to reload vendor data');
      }
    } catch (error) {
      console.error('Error reloading vendors:', error);
      logger.error('ui', 'Vendor reload error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined
      });
      showNotification('error', 'Reload Failed', 'Failed to reload vendor data');
    }
  };

  const openAddVendorModal = () => {
    setAddVendorForm({ vendorName: '', vendorDomain: '', tier: '', portfolio: '', industry: '' });
    setAddVendorError('');
    setShowAddVendorModal(true);
  };

  const closeAddVendorModal = () => {
    setShowAddVendorModal(false);
    setAddVendorForm({ vendorName: '', vendorDomain: '', tier: '', portfolio: '', industry: '' });
    setAddVendorError('');
    setIsAddingVendor(false);
  };

  const openDeleteVendorModal = (vendor: Vendor) => {
    setDeleteVendorData({ id: vendor.id, name: vendor.name });
    setShowDeleteVendorModal(true);
  };

  const closeDeleteVendorModal = () => {
    setShowDeleteVendorModal(false);
    setDeleteVendorData(null);
  };

  const openEditVendorModal = (vendor: Vendor) => {
    setEditVendorId(vendor.id);
    setShowEditVendorModal(true);
  };

  const closeEditVendorModal = () => {
    setShowEditVendorModal(false);
    setEditVendorId(null);
  };

  const handleEditVendorSuccess = async (updatedVendor: any) => {
    try {
      // Log the vendor update action
      logUserAction('UPDATE', 'vendor', updatedVendor?.id?.toString(), {
        action_type: 'update_vendor',
        vendor_name: updatedVendor?.name,
        vendor_id: updatedVendor?.id,
        timestamp: new Date().toISOString()
      });

      // Clear frontend cache and force fresh data load
      cacheUtils.clearVendorCaches();
      await loadDashboardData(true);
      showNotification('success', 'Vendor Updated', `Vendor "${updatedVendor.name}" has been updated successfully`);
    } catch (error) {
      console.error('Error refreshing data after vendor update:', error);
      showNotification('warning', 'Vendor Updated', 'Vendor updated but failed to refresh data. Please reload the page.');
    }
  };

  const handleEditVendorError = (error: string) => {
    showNotification('error', 'Update Failed', error);
  };

  // Helper function to extract domain from URL or domain input
  const extractDomainFromInput = (input: string): string | null => {
    try {
      const trimmed = input.trim().toLowerCase();

      // If it already looks like a clean domain, return as-is (supports second-level domains like .co.uk)
      const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}\.)?[a-zA-Z]{2,}$/;
      if (domainPattern.test(trimmed)) {
        // Strip leading www. if present
        return trimmed.replace(/^www\./, '');
      }

      // If it looks like a URL, extract domain (supports second-level domains like .co.uk)
      const urlPattern = /^https?:\/\/([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}\.)?[a-zA-Z]{2,})(\/.*)?$/;
      const urlMatch = trimmed.match(urlPattern);
      if (urlMatch) {
        // Strip leading www. if present
        return urlMatch[1].replace(/^www\./, '');
      }

      // Try to parse as URL (handles cases without protocol)
      let urlToParse = trimmed;
      if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
        urlToParse = 'https://' + trimmed;
      }

      const url = new URL(urlToParse);
      let domain = url.hostname;

      // Remove www. prefix if present
      if (domain.startsWith('www.')) {
        domain = domain.substring(4);
      }

      // Validate the extracted domain
      if (domainPattern.test(domain)) {
        return domain;
      }

      return null;
    } catch (error) {
      return null;
    }
  };

  const handleAddVendor = async () => {
    const { vendorName, vendorDomain, tier, portfolio } = addVendorForm;

    if (!vendorName.trim() || !vendorDomain.trim()) {
      setAddVendorError('Vendor name and domain are required');
      return;
    }

    if (!tier.trim()) {
      setAddVendorError('Tier is required');
      return;
    }

    if (!portfolio.trim()) {
      setAddVendorError('Portfolio is required');
      return;
    }

    // Extract domain from URL or domain input
    const cleanDomain = extractDomainFromInput(vendorDomain);

    if (!cleanDomain) {
      setAddVendorError('Invalid domain format. Please enter a valid domain (e.g., example.com) or URL (e.g., https://example.com).');
      return;
    }

    setIsAddingVendor(true);
    setAddVendorError('');

    try {
      const response = await vendorApi.addVendor({
        vendor_name: vendorName.trim(),
        domain: cleanDomain,
        tier: tier.trim(),
        portfolio: portfolio.trim(),
        industry: addVendorForm.industry.trim() || null
      });
      if (response.success) {
        // Log the vendor addition action
        logUserAction('CREATE', 'vendor', response.vendor?.id?.toString(), {
          action_type: 'add_vendor',
          vendor_name: vendorName.trim(),
          domain: vendorDomain.trim(),
          tier: tier.trim(),
          portfolio: portfolio.trim(),
          industry: addVendorForm.industry.trim() || null,
          timestamp: new Date().toISOString(),
          auto_scan_started: response.auto_scan_started || false,
          scan_job_id: response.scan_job_id || null
        });

        closeAddVendorModal();
        // Clear frontend cache and force fresh data load
        cacheUtils.clearVendorCaches();
        await loadDashboardData(true);

        // Show enhanced success notification and redirect to report page
        if (response.auto_scan_started && response.scan_job_id) {
          showNotification('success', 'Vendor Added & Scan Started',
            `Vendor "${vendorName}" has been added successfully! Redirecting to report page to monitor scan progress...`);

          // Redirect to the vendor's report page after a brief delay
          setTimeout(() => {
            router.push(`/report/${encodeURIComponent(cleanDomain)}?from=${activeSection}`);
          }, 2000);
        } else if (response.auto_scan_started === false && response.scan_error) {
          showNotification('warning', 'Vendor Added - Scan Issue',
            `Vendor "${vendorName}" has been added successfully, but the automatic security scan could not be started. Redirecting to report page...`);

          // Still redirect to report page even if scan failed to start
          setTimeout(() => {
            router.push(`/report/${encodeURIComponent(cleanDomain)}`);
          }, 2000);
        } else {
          showNotification('success', 'Vendor Added', `Vendor "${vendorName}" has been added successfully! Redirecting to report page...`);

          // Redirect to report page
          setTimeout(() => {
            router.push(`/report/${encodeURIComponent(cleanDomain)}`);
          }, 2000);
        }
      } else {
        // Handle non-successful responses with specific error messages
        let errorMessage = 'Failed to add vendor';

        if (response.error) {
          if (response.error.includes('already exists')) {
            if (response.error.includes('domain')) {
              errorMessage = `A vendor with this domain already exists. Please use a different domain.`;
            } else if (response.error.includes('name')) {
              errorMessage = `A vendor with this name already exists. Please use a different vendor name.`;
            } else {
              errorMessage = `A vendor with this information already exists. Please check your input.`;
            }
          } else if (response.error.includes('Invalid domain format')) {
            errorMessage = 'Invalid domain format. Please enter a valid domain (e.g., example.com) without protocol or trailing slash.';
          } else {
            errorMessage = response.error;
          }
        }

        setAddVendorError(errorMessage);
      }
    } catch (error: any) {
      console.error('Error adding vendor:', error);
      console.error('Error response:', error?.response);
      console.error('Error status:', error?.response?.status);
      console.error('Error data:', error?.response?.data);

      // Handle different types of errors with specific messages
      let errorMessage = 'Failed to add vendor. Please try again.';

      // Check for HTTP status codes first
      if (error?.response?.status === 409) {
        errorMessage = 'A vendor with this domain already exists. Please use a different domain.';
      } else if (error?.response?.status === 400) {
        errorMessage = 'Invalid input data. Please check all fields and try again.';
      } else if (error?.response?.status === 500) {
        errorMessage = 'Server error occurred. Please try again later.';
      } else if (error?.response?.data?.detail) {
        const detail = error.response.data.detail;

        // Handle specific error cases
        if (detail === 'Invalid domain format') {
          errorMessage = 'Invalid domain format. Please enter a valid domain (e.g., example.com) without protocol or trailing slash.';
        } else if (detail === 'Vendor name is required') {
          errorMessage = 'Vendor name is required.';
        } else if (detail === 'Domain is required') {
          errorMessage = 'Domain is required.';
        } else if (detail === 'Tier is required') {
          errorMessage = 'Tier is required.';
        } else if (detail === 'Portfolio is required') {
          errorMessage = 'Portfolio is required.';
        } else if (detail.includes('already exists')) {
          if (detail.includes('domain')) {
            errorMessage = `A vendor with this domain already exists. Please use a different domain.`;
          } else if (detail.includes('name')) {
            errorMessage = `A vendor with this name already exists. Please use a different vendor name.`;
          } else {
            errorMessage = `A vendor with this information already exists. Please check your input.`;
          }
        } else if (detail === 'No JSON data provided') {
          errorMessage = 'Invalid request data. Please try again.';
        } else {
          // Use the specific error message from the backend
          errorMessage = detail;
        }
      } else if (error?.message) {
        errorMessage = error.message;
      }

      setAddVendorError(errorMessage);
    } finally {
      setIsAddingVendor(false);
    }
  };

  const confirmDeleteVendor = async () => {
    if (!deleteVendorData) return;

    try {
      await vendorApi.deleteVendor(deleteVendorData.id);

      // Log the vendor deletion action
      logUserAction('DELETE', 'vendor', deleteVendorData.id.toString(), {
        action_type: 'delete_vendor',
        vendor_name: deleteVendorData.name,
        vendor_id: deleteVendorData.id,
        timestamp: new Date().toISOString()
      });

      // Clear frontend cache and force fresh data load
      cacheUtils.clearVendorCaches();
      await loadDashboardData(true);
      closeDeleteVendorModal();
      showNotification('success', 'Vendor Deleted', `Vendor "${deleteVendorData.name}" has been deleted successfully`);
    } catch (error) {
      console.error('Error deleting vendor:', error);
      showNotification('error', 'Delete Failed', 'Failed to delete vendor');
    }
  };

  const deleteVendor = async (vendorId: number) => {
    try {
      await vendorApi.deleteVendor(vendorId);
      setVendors(vendors.filter(v => v.id !== vendorId));
      showNotification('success', 'Vendor Deleted', 'Vendor has been deleted successfully');
    } catch (error) {
      console.error('Error deleting vendor:', error);
      showNotification('error', 'Delete Failed', 'Failed to delete vendor');
    }
  };

  // Comprehensive scan functions for all types
  const startVulnerabilityScan = async (domain: string) => {
    try {
      console.log(`Starting vulnerability scan for ${domain}`);
      const response = await scanApi.startVulnerabilityScan(domain);

      // Log the scan action with vendor context
      const vendor = findVendorByDomain(domain);
      logUserAction('SCAN', 'vulnerability', (response as any).scan_id || domain, {
        action_type: 'start_vulnerability_scan',
        domain: domain,
        vendor_name: vendor?.name || 'Unknown Vendor',
        vendor_id: vendor?.id,
        scan_type: 'vulnerability',
        scan_id: (response as any).scan_id,
        timestamp: new Date().toISOString()
      });

      console.log('Vulnerability scan started:', response);
      alert(`Vulnerability scan started for ${domain}. Check back in a few minutes for results.`);
      setTimeout(() => loadDashboardData(), 2000);
      setShowScanMenu(null);
    } catch (error) {
      console.error('Error starting vulnerability scan:', error);
      alert(`Failed to start vulnerability scan for ${domain}. Please try again.`);
    }
  };





  const startDnsScan = async (domain: string) => {
    try {
      console.log(`Starting DNS scan for ${domain}`);
      const response = await scanApi.startDnsScan(domain);

      // Log the scan action with vendor context
      const vendor = findVendorByDomain(domain);
      logUserAction('SCAN', 'dns', (response as any).scan_id || domain, {
        action_type: 'start_dns_scan',
        domain: domain,
        vendor_name: vendor?.name || 'Unknown Vendor',
        vendor_id: vendor?.id,
        scan_type: 'dns',
        scan_id: (response as any).scan_id,
        timestamp: new Date().toISOString()
      });

      console.log('DNS scan started:', response);
      alert(`DNS scan started for ${domain}. Check back in a few minutes for results.`);
      setTimeout(() => loadDashboardData(), 2000);
      setShowScanMenu(null);
    } catch (error) {
      console.error('Error starting DNS scan:', error);
      alert(`Failed to start DNS scan for ${domain}. Please try again.`);
    }
  };

  const startEmailScanOld = async (domain: string) => {
    try {
      console.log(`Starting email security scan for ${domain}`);
      const response = await scanApi.startEmailScan(domain);

      // Log the scan action with vendor context
      const vendor = findVendorByDomain(domain);
      logUserAction('SCAN', 'email', (response as any).scan_id || domain, {
        action_type: 'start_email_scan',
        domain: domain,
        vendor_name: vendor?.name || 'Unknown Vendor',
        vendor_id: vendor?.id,
        scan_type: 'email',
        scan_id: (response as any).scan_id,
        timestamp: new Date().toISOString()
      });

      console.log('Email scan started:', response);
      alert(`Email security scan started for ${domain}. Check back in a few minutes for results.`);
      setTimeout(() => loadDashboardData(), 2000);
      setShowScanMenu(null);
    } catch (error) {
      console.error('Error starting email scan:', error);
      alert(`Failed to start email scan for ${domain}. Please try again.`);
    }
  };

  const startSubdomainScan = async (domain: string) => {
    try {
      console.log(`Starting subdomain discovery for ${domain}`);
      const response = await subdomainApi.discover({ domain });

      // Log the subdomain discovery action with vendor context
      const vendor = findVendorByDomain(domain);
      logUserAction('SCAN', 'subdomain_discovery', (response as any)?.scan_id || domain, {
        action_type: 'start_subdomain_discovery',
        domain: domain,
        vendor_name: vendor?.name || 'Unknown Vendor',
        vendor_id: vendor?.id,
        scan_type: 'subdomain_discovery',
        scan_id: (response as any)?.scan_id,
        subdomains_found: response.statistics?.total || 0,
        timestamp: new Date().toISOString()
      });

      console.log('Subdomain discovery completed:', response);
      showNotification('success', 'Discovery Complete',
        `Subdomain discovery completed for ${domain}. Found ${response.statistics?.total || 0} subdomains.`);
      setTimeout(() => loadDashboardData(), 2000);
      setShowScanMenu(null);
    } catch (error) {
      console.error('Error starting subdomain discovery:', error);
      showNotification('error', 'Discovery Failed', `Failed to discover subdomains for ${domain}. Please try again.`);
    }
  };



  // Full scan function for comprehensive vendor risk assessment
  const startFullScan = async (domain: string) => {
    try {
      showNotification('info', 'Full Scan Started',
        `Starting comprehensive security scan for ${domain}. This will run in the background.`,
        { persistent: true, domain, scanType: 'full_scan' }
      );

      // Start background scan for single domain
      const response = await backgroundScanApi.startSingleDomainScan(domain);

      if (response.status === 'success' && response.job_id) {
        // Log the full scan action with vendor context
        const vendor = findVendorByDomain(domain);
        logUserAction('SCAN', 'full_scan', response.job_id || domain, {
          action_type: 'start_full_scan',
          domain: domain,
          vendor_name: vendor?.name || 'Unknown Vendor',
          vendor_id: vendor?.id,
          scan_type: 'full_scan',
          job_id: response.job_id,
          context: 'single_domain',
          timestamp: new Date().toISOString()
        });

        showNotification('success', 'Background Scan Started',
          `Background scan started for ${domain}.`,
          { domain, scanType: 'full_scan' }
        );

        // Start monitoring the job
        monitorBackgroundScan(response.job_id);
      } else {
        throw new Error(response.message || 'Failed to start background scan');
      }

    } catch (error) {
      console.error('Error starting full scan:', error);
      showNotification('error', 'Full Scan Failed',
        `Failed to start background scan for ${domain}. Please try again.`,
        { domain, scanType: 'full_scan' }
      );
    }
  };

  // Show subdomain option popup for full scan all domains or filtered scan
  const startFullScanAllDomains = () => {
    const totalVendors = vendors.length;
    const filteredVendorCount = filteredVendors.length;

    if (totalVendors === 0) {
      showNotification('warning', 'No Vendors', 'No vendors available to scan.');
      return;
    }

    // Check if filters are applied
    const hasFilters = vendorSearchTerm ||
      vendorFilter.length > 0 ||
      tierFilter.length > 0 ||
      portfolioFilter.length > 0 ||
      industryFilter.length > 0;

    if (hasFilters && filteredVendorCount === 0) {
      showNotification('warning', 'No Matching Vendors', 'No vendors match the current filters.');
      return;
    }

    // Fetch resume info only for full scans (not filtered)
    if (!hasFilters) {
      fetchResumeInfo();
    }

    // Show the subdomain option modal
    setShowSubdomainOptionModal(true);
  };

  // Fetch resume info for full scan
  const fetchResumeInfo = async () => {
    setLoadingResumeInfo(true);
    try {
      const response = await backgroundScanApi.getResumeInfo();
      setResumeInfo(response);
    } catch (error) {
      console.error('Error fetching resume info:', error);
      setResumeInfo({ can_resume: false, message: 'Unable to fetch resume information' });
    } finally {
      setLoadingResumeInfo(false);
    }
  };

  // Execute full scan with subdomain option
  const executeFullScanAllDomains = async (includeSubdomains: boolean, continueFromLast: boolean = false) => {
    try {
      const totalVendors = vendors.length;
      const filteredVendorCount = filteredVendors.length;

      // Check if filters are applied
      const hasFilters = vendorSearchTerm ||
        vendorFilter.length > 0 ||
        tierFilter.length > 0 ||
        portfolioFilter.length > 0 ||
        industryFilter.length > 0;

      let checkpointVendor = '';
      let response;

      if (hasFilters) {
        // Filtered scan - no checkpoint support
        logger.info('scan', `Starting background filtered scan for ${filteredVendorCount} vendors with subdomains: ${includeSubdomains}`);

        // Prepare vendor filters for backend
        const vendorFilters = {
          search_term: vendorSearchTerm,
          risk_levels: vendorFilter,
          tiers: tierFilter,
          portfolios: portfolioFilter,
          industries: industryFilter
        };

        const scanDescription = includeSubdomains
          ? `Starting comprehensive security scan for ${filteredVendorCount} filtered vendors including all subdomains. This runs on the backend and will continue even if you close the frontend.`
          : `Starting comprehensive security scan for ${filteredVendorCount} filtered vendors (main domains only). This runs on the backend and will continue even if you close the frontend.`;

        showNotification('info', 'Background Filtered Scan Started', scanDescription,
          { persistent: true, scanType: 'background_filtered_scan' });

        // Start filtered scan on backend
        response = await backgroundScanApi.startFilteredScan(includeSubdomains, vendorFilters);
      } else {
        // Full scan - checkpoint support available
        // If continuing from last scan, use the resume info
        if (continueFromLast && resumeInfo?.can_resume) {
          checkpointVendor = resumeInfo.resume_from_domain || '';
        }

        logger.info('scan', `Starting background full scan for ${totalVendors} vendors with subdomains: ${includeSubdomains}, checkpoint: ${checkpointVendor || 'none'}, continue: ${continueFromLast}`);

        let scanDescription = includeSubdomains
          ? `Starting comprehensive security scan for all ${totalVendors} vendors including all subdomains. This runs on the backend and will continue even if you close the frontend.`
          : `Starting comprehensive security scan for all ${totalVendors} vendors (main domains only). This runs on the backend and will continue even if you close the frontend.`;

        if (continueFromLast && checkpointVendor) {
          scanDescription = `Continuing scan from ${resumeInfo.resume_from_vendor} (${checkpointVendor})`;
        } else if (checkpointVendor) {
          scanDescription += ` Starting from vendor: ${checkpointVendor}`;
        }

        showNotification('info', 'Background Full Scan Started', scanDescription,
          { persistent: true, scanType: 'background_full_scan' });

        // Start background scan on backend with subdomain option and checkpoint
        response = await backgroundScanApi.startFullScan(includeSubdomains, checkpointVendor);
      }

      if (response.status === 'success' && response.job_id) {
        // Log the full scan all domains action
        logUserAction('SCAN', 'full_scan_all', response.job_id, {
          action_type: 'start_full_scan_all_domains',
          total_vendors: totalVendors,
          include_subdomains: includeSubdomains,
          checkpoint_vendor: checkpointVendor || null,
          scan_type: 'full_scan_all',
          job_id: response.job_id,
          context: 'all_domains',
          timestamp: new Date().toISOString()
        });

        logger.success('scan', 'Background full scan started successfully', {
          jobId: response.job_id,
          totalVendors: totalVendors,
          includeSubdomains: includeSubdomains
        });

        // Update state to reflect active scan
        setIsBackgroundScanRunning(true);
        setActiveBackgroundJobId(response.job_id);
        // Initialize progress state for the new scan
        setBackgroundScanProgress(0);
        setBackgroundScanCurrentDomain('');
        setBackgroundScanStage('initializing');

        const statusMessage = includeSubdomains
          ? 'Backend scan started with all subdomains. The scan will continue running even if you close this page.'
          : 'Backend scan started for main domains only. The scan will continue running even if you close this page.';

        showNotification('success', 'Background Scan Active', statusMessage,
          { persistent: true, scanType: 'background_scan_started', duration: 15000 });

        // Start monitoring the job
        monitorBackgroundScan(response.job_id);

      } else {
        throw new Error(response.message || 'Failed to start background scan');
      }

    } catch (error) {
      console.error('Error starting background full scan:', error);
      logger.error('scan', 'Failed to start background full scan', error);
      showNotification('error', 'Background Scan Failed',
        'Failed to start background full scan. Please try again.');
    }
  };

  // Check for active background scans
  const checkActiveBackgroundScans = async () => {
    try {
      const response = await backgroundScanApi.listJobs();
      if (response.status === 'success' && response.jobs) {
        // Find any active jobs (starting or running)
        const activeJob = response.jobs.find(job =>
          job.status === 'starting' || job.status === 'running'
        );

        if (activeJob) {
          setIsBackgroundScanRunning(true);
          setActiveBackgroundJobId(activeJob.job_id);
          // Update progress state with current job info
          setBackgroundScanProgress(activeJob.progress || 0);
          setBackgroundScanCurrentDomain(activeJob.current_domain || '');
          setBackgroundScanStage(activeJob.stage || '');

          logger.info('scan', 'Found active background scan job', {
            jobId: activeJob.job_id,
            status: activeJob.status,
            progress: activeJob.progress
          });

          // Start monitoring if running and not already monitoring this job
          if (activeJob.status === 'running' && monitoringJobId !== activeJob.job_id) {
            monitorBackgroundScan(activeJob.job_id);
          }
        } else {
          setIsBackgroundScanRunning(false);
          setActiveBackgroundJobId(null);
          setMonitoringJobId(null); // Clear monitoring state
          // Reset progress state
          setBackgroundScanProgress(0);
          setBackgroundScanCurrentDomain('');
          setBackgroundScanStage('');
        }
      }
    } catch (error) {
      console.error('Error checking active background scans:', error);
      logger.error('scan', 'Failed to check active background scans', error);
    }
  };

  // Monitor background scan progress
  const monitorBackgroundScan = async (jobId: string) => {
    try {
      logger.info('scan', `Starting to monitor background scan job: ${jobId}`);

      // Set monitoring state to prevent duplicate monitoring
      setMonitoringJobId(jobId);

      const finalJob = await backgroundScanApi.monitorJob(jobId, (job: BackgroundScanJob) => {
        // Update local state
        if (job.status === 'running') {
          setIsBackgroundScanRunning(true);
          setActiveBackgroundJobId(job.job_id);
          // Update progress state for the progress bar
          setBackgroundScanProgress(job.progress || 0);
          setBackgroundScanCurrentDomain(job.current_domain || '');
          setBackgroundScanStage(job.stage || '');
        } else if (['completed', 'failed', 'cancelled'].includes(job.status)) {
          setIsBackgroundScanRunning(false);
          setActiveBackgroundJobId(null);
          // Reset progress state
          setBackgroundScanProgress(0);
          setBackgroundScanCurrentDomain('');
          setBackgroundScanStage('');
        }

        // Update progress notifications
        if (job.status === 'running' && job.current_domain) {
          const progressText = `${job.progress}% - Scanning ${job.current_domain} (${job.completed_count}/${job.total_domains})`;

          logger.debug('scan', 'Background scan progress update', {
            jobId: job.job_id,
            progress: job.progress,
            currentDomain: job.current_domain,
            stage: job.stage
          });

          // Show periodic progress notifications (every 20%)
          if (job.progress > 0 && job.progress % 20 === 0) {
            showNotification('info', 'Background Scan Progress', progressText);
          }
        }
      });

      logger.success('scan', `Background scan job finished: ${jobId} - Status: ${finalJob.status}`);

      // Update state when job completes
      setIsBackgroundScanRunning(false);
      setActiveBackgroundJobId(null);
      setMonitoringJobId(null); // Clear monitoring state

      // Show notification based on final status
      if (finalJob.status === 'completed') {
        // Final completion notification - only for successful completion
        showNotification('success', 'Background Scan Complete',
          `Background full scan completed! All vendor results have been updated. Refreshing dashboard...`,
          { persistent: true, scanType: 'background_scan_complete', duration: 20000 });

        // Refresh dashboard data after completion with cache clearing
        setTimeout(async () => {
          logger.info('cache', 'Background scan completed - clearing all caches for fresh data');
          cacheUtils.clearAll(); // Clear caches BEFORE loading fresh data
          await loadDashboardData(true); // Force fresh data
          logger.success('ui', 'Dashboard refreshed with fresh data after background scan completion');
        }, 3000);
      } else if (finalJob.status === 'failed') {
        // Show failure notification
        showNotification('error', 'Background Scan Failed',
          `Background scan encountered an error. Please check the logs for details.`);
      }
      // Don't show notification for 'cancelled' - it's already handled in stopBackgroundScan()

    } catch (error) {
      console.error('Error monitoring background scan:', error);
      logger.error('scan', 'Background scan monitoring failed', { jobId, error });

      // Reset state on error
      setIsBackgroundScanRunning(false);
      setActiveBackgroundJobId(null);
      setMonitoringJobId(null); // Clear monitoring state

      showNotification('warning', 'Background Scan Status Unknown',
        'Lost connection to background scan monitoring. The scan may still be running on the backend.');
    }
  };

  // Stop/Cancel background scan
  const stopBackgroundScan = async () => {
    if (!activeBackgroundJobId) {
      showNotification('warning', 'No Active Scan', 'No background scan is currently running.');
      return;
    }

    try {
      logger.info('scan', `Attempting to cancel background scan: ${activeBackgroundJobId}`);
      await backgroundScanApi.cancelJob(activeBackgroundJobId);

      // Reset state
      setIsBackgroundScanRunning(false);
      setActiveBackgroundJobId(null);
      setBackgroundScanProgress(0);
      setBackgroundScanCurrentDomain('');
      setBackgroundScanStage('');
      setMonitoringJobId(null);

      showNotification('success', 'Scan Stopped', 'Background scan has been cancelled successfully.');
      logger.success('scan', 'Background scan cancelled successfully', { jobId: activeBackgroundJobId });

      // Refresh dashboard after a short delay
      setTimeout(async () => {
        await loadDashboardData(true);
      }, 1000);

    } catch (error) {
      console.error('Error stopping background scan:', error);
      logger.error('scan', 'Failed to stop background scan', { jobId: activeBackgroundJobId, error });
      showNotification('error', 'Stop Failed', 'Failed to stop background scan. Please try again.');
    }
  };

  // Background full scan execution
  const runFullScanInBackground = async (domain: string) => {
    try {
      // Step 1: Subdomain Discovery (Force rediscovery for full scan)
      showNotification('info', 'Full Scan Progress', `Step 1/7: Rediscovering subdomains for ${domain}...`);

      const subdomainResult = await subdomainApi.discover({
        domain: domain,
        force_rediscovery: true  // Force rediscovery for full scan
      });

      // Wait for subdomain discovery to complete if it's async
      if (subdomainResult.status === 'started') {
        await waitForSubdomainCompletion(subdomainResult.scan_id || '', domain);
      }
      showNotification('success', 'Scan Complete', ` Subdomain discovery completed for ${domain}`);

      // Step 2: Website Vulnerability Scan
      showNotification('info', 'Full Scan Progress', `Step 2/7: Scanning website vulnerabilities for ${domain}...`);
      await scanApi.startVulnerabilityScan(domain);
      showNotification('success', 'Scan Complete', ` Website Vulnerability scan completed for ${domain}`);

      // Step 3: Domain Reputation Scan
      showNotification('info', 'Full Scan Progress', `Step 3/7: Checking domain reputation for ${domain}...`);
      await scanApi.startReputationScan(domain);
      showNotification('success', 'Scan Complete', ` Domain Reputation scan completed for ${domain}`);

      // Step 4: Network Scan
      showNotification('info', 'Full Scan Progress', `Step 4/7: Scanning network ports for ${domain}...`);
      const networkResult = await scanApi.startNetworkScan(domain);
      if (networkResult.scan_id) {
        await waitForNetworkScanCompletion(networkResult.scan_id, domain);
      } else {
        showNotification('success', 'Scan Complete', ` Network Scan completed for ${domain}`);
      }

      // Step 5: DNS Security Scan
      showNotification('info', 'Full Scan Progress', `Step 5/7: Checking DNS security for ${domain}...`);
      const dnsResult = await scanApi.startDnsScan(domain);
      if (dnsResult.scan_id) {
        await waitForDnsScanCompletion(dnsResult.scan_id, domain);
      } else {
        showNotification('success', 'Scan Complete', ` DNS Security scan completed for ${domain}`);
      }

      // Step 6: Encryption Scan
      showNotification('info', 'Full Scan Progress', `Step 6/7: Analyzing SSL/TLS encryption for ${domain}...`);
      const encryptionResult = await scanApi.startEncryptionScan(domain);
      if (encryptionResult.scan_id) {
        await waitForEncryptionScanCompletion(encryptionResult.scan_id, domain);
      } else {
        showNotification('success', 'Scan Complete', ` Encryption Scan completed for ${domain}`);
      }

      // Step 7: Email Security Scan
      showNotification('info', 'Full Scan Progress', `Step 7/7: Checking Email Security for ${domain}...`);
      await scanApi.startEmailScan(domain);
      showNotification('success', 'Scan Complete', `Email Security Scan completed for ${domain}`);

      // Show completion notification with enhanced details
      showFullScanCompleteNotification(domain, {
        totalScans: 7,
        successfulScans: 7,
        failedScans: 0
      });

      // Refresh dashboard data to show updated results
      setTimeout(() => {
        loadDashboardData();
      }, 2000);

    } catch (error) {
      console.error('Error in full scan background process:', error);
      showNotification('error', 'Full Scan Error',
        `An error occurred during the full scan for ${domain}. Some scans may have completed successfully.`,
        { persistent: true, domain, scanType: 'full_scan' }
      );
    }
  };

  // Helper function to wait for subdomain discovery completion
  const waitForSubdomainCompletion = async (scanId: string, domain: string): Promise<void> => {
    return new Promise((resolve) => {
      const pollInterval = setInterval(async () => {
        try {
          const status = await subdomainApi.discoverStatus(scanId);

          if (status.status === 'completed') {
            clearInterval(pollInterval);
            const stats = status.results?.statistics || status.statistics;
            showNotification('success', 'Subdomains Discovered',
              `Found ${stats?.alive || 0} active subdomains for ${domain}.`);
            resolve();
          } else if (status.status === 'error' || status.status === 'stopped') {
            clearInterval(pollInterval);
            showNotification('warning', 'Subdomain Discovery Failed',
              `Subdomain discovery failed for ${domain}, continuing with other scans.`);
            resolve();
          }
        } catch (error) {
          clearInterval(pollInterval);
          console.error('Error polling subdomain discovery:', error);
          resolve();
        }
      }, 3000); // Poll every 3 seconds

      // Timeout after 10 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        resolve();
      }, 600000);
    });
  };

  // Helper function to wait for DNS scan completion
  const waitForDnsScanCompletion = async (scanId: string, domain: string, updateProgress?: (progress: number) => void): Promise<any> => {
    logger.info('scan', 'Starting DNS scan polling', { scanId, domain });

    return new Promise((resolve) => {
      let pollCount = 0;
      const pollInterval = setInterval(async () => {
        try {
          pollCount++;
          const status = await scanApi.getDnsScanStatus(scanId);

          logger.debug('scan', `DNS scan poll #${pollCount}`, {
            scanId,
            domain,
            status: status.scan?.status,
            progress: status.scan?.progress
          });

          if (updateProgress && status.scan?.progress) {
            updateProgress(status.scan.progress);
          }

          if (status.scan?.status === 'completed' && status.scan?.result) {
            clearInterval(pollInterval);
            logger.success('scan', 'DNS scan completed successfully', {
              scanId,
              domain,
              finalScore: status.scan.result.final_score,
              totalIssues: status.scan.result.summary?.total_issues
            });
            resolve(status.scan.result);
          } else if (status.scan?.status === 'failed') {
            clearInterval(pollInterval);
            logger.error('scan', 'DNS scan failed', {
              scanId,
              domain,
              error: status.scan.error
            });
            resolve({ status: 'failed', error: status.scan.error });
          }

          // Timeout after 10 minutes (200 polls at 3 second intervals)
          if (pollCount >= 200) {
            clearInterval(pollInterval);
            logger.warn('scan', 'DNS scan polling timeout', { scanId, domain, pollCount });
            resolve({ status: 'timeout', message: 'DNS scan polling timed out' });
          }
        } catch (error) {
          logger.error('scan', 'DNS scan polling error', { scanId, domain, error, pollCount });
          // Don't clear interval on error, keep trying
        }
      }, 3000); // Poll every 3 seconds
    });
  };

  // Helper function to wait for encryption scan completion
  const waitForEncryptionScanCompletion = async (scanId: string, domain: string, updateProgress?: (progress: number) => void): Promise<any> => {
    logger.info('scan', 'Starting encryption scan polling', { scanId, domain });

    return new Promise((resolve) => {
      let pollCount = 0;
      const pollInterval = setInterval(async () => {
        try {
          pollCount++;
          const status = await scanApi.getEncryptionScanStatus(scanId);

          logger.debug('scan', `Encryption scan poll #${pollCount}`, {
            scanId,
            domain,
            status: status.status,
            progress: status.progress
          });

          // Update progress if callback provided (for sidebar)
          if (updateProgress && status.progress !== undefined) {
            updateProgress(status.progress);
          }

          if (status.status === 'completed') {
            clearInterval(pollInterval);
            logger.success('scan', 'Encryption scan completed via polling', {
              scanId,
              domain,
              pollCount,
              finalScore: status.results?.final_score
            });
            // Notification handled by calling function
            resolve(status.results);
          } else if (status.status === 'failed' || status.status === 'error') {
            clearInterval(pollInterval);
            logger.error('scan', 'Encryption scan failed via polling', {
              scanId,
              domain,
              pollCount,
              error: status.error
            });
            showNotification('error', 'Encryption Scan Failed',
              status.error || `Encryption scan failed for ${domain}`);
            resolve({ status: 'failed', error: status.error });
          } else if (status.status === 'stopped') {
            clearInterval(pollInterval);
            logger.info('scan', 'Encryption scan was stopped', { scanId, domain });
            showNotification('warning', 'Encryption Scan Stopped',
              `Encryption scan was stopped for ${domain}`);
            resolve({ status: 'stopped' });
          }

          // Timeout after 30 minutes (180 polls * 10 seconds)
          if (pollCount > 180) {
            clearInterval(pollInterval);
            logger.error('scan', 'Encryption scan polling timeout', {
              scanId,
              domain,
              pollCount
            });
            showNotification('error', 'Encryption Scan Timeout',
              `Encryption scan timed out for ${domain}. The scan may still be running in the background.`);
            resolve({ status: 'timeout' });
          }
        } catch (error) {
          logger.error('scan', 'Error polling encryption scan status', {
            scanId,
            domain,
            pollCount,
            error
          });
          // Continue polling on error, but limit retries
          if (pollCount > 10) {
            clearInterval(pollInterval);
            showNotification('error', 'Encryption Scan Error',
              `Failed to get encryption scan status for ${domain}`);
            resolve({ status: 'error', error: error });
          }
        }
      }, 10000); // Poll every 10 seconds
    });
  };

  // Helper function to wait for subdomain scan completion
  const waitForSubdomainScanCompletion = async (scanId: string, domain: string): Promise<any> => {
    logger.info('scan', 'Starting subdomain scan polling', { scanId, domain });

    return new Promise((resolve) => {
      let pollCount = 0;
      const pollInterval = setInterval(async () => {
        try {
          pollCount++;
          const status = await subdomainApi.discoverStatus(scanId);

          logger.debug('scan', `Subdomain scan poll #${pollCount}`, {
            scanId,
            domain,
            status: status.status,
            progress: status.progress
          });

          if (status.status === 'completed') {
            clearInterval(pollInterval);
            logger.success('scan', 'Subdomain scan completed via polling', {
              scanId,
              domain,
              pollCount,
              results: status.results
            });
            resolve(status.results || status);
          } else if (status.status === 'failed' || status.status === 'error') {
            clearInterval(pollInterval);
            logger.error('scan', 'Subdomain scan failed via polling', {
              scanId,
              domain,
              pollCount,
              error: status.error || 'Unknown error'
            });
            resolve({ status: 'error', error: status.error || 'Subdomain scan failed' });
          }

          // Timeout after 10 minutes (120 polls at 5-second intervals)
          if (pollCount >= 120) {
            clearInterval(pollInterval);
            logger.warn('scan', 'Subdomain scan polling timeout', {
              scanId,
              domain,
              pollCount
            });
            resolve({ status: 'timeout', error: 'Subdomain scan timed out' });
          }
        } catch (error) {
          logger.error('scan', 'Error during subdomain scan polling', {
            scanId,
            domain,
            pollCount,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }, 5000); // Poll every 5 seconds
    });
  };

  // Helper function to wait for network scan completion
  const waitForNetworkScanCompletion = async (scanId: string, domain: string): Promise<any> => {
    logger.info('scan', 'Starting network scan polling', { scanId, domain });

    return new Promise((resolve) => {
      let pollCount = 0;
      const pollInterval = setInterval(async () => {
        try {
          pollCount++;
          const status = await scanApi.getNetworkScanStatus(scanId);

          logger.debug('scan', `Network scan poll #${pollCount}`, {
            scanId,
            domain,
            status: status.status,
            progress: status.progress
          });

          if (status.status === 'completed') {
            clearInterval(pollInterval);
            logger.success('scan', 'Network scan completed via polling', {
              scanId,
              domain,
              pollCount,
              finalScore: status.final_score
            });
            // Notification handled by calling function
            resolve(status);
          } else if (status.status === 'failed' || status.status === 'error') {
            clearInterval(pollInterval);
            logger.error('scan', 'Network scan failed via polling', {
              scanId,
              domain,
              pollCount,
              error: status.error || 'Unknown error'
            });
            showNotification('warning', 'Network Scan Failed',
              `Network scan failed for ${domain}, continuing with other scans.`);
            resolve({ status: 'error', message: 'Network scan failed' });
          }
        } catch (error) {
          clearInterval(pollInterval);
          logger.error('scan', 'Error polling network scan status', {
            scanId,
            domain,
            pollCount,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          console.error('Error polling network scan:', error);
          resolve({ status: 'error', message: 'Polling failed' });
        }
      }, 3000); // Poll every 3 seconds

      // Timeout after 10 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        logger.warn('scan', 'Network scan polling timeout', {
          scanId,
          domain,
          pollCount,
          timeoutMinutes: 10
        });
        resolve({ status: 'timeout', message: 'Scan timed out' });
      }, 600000);
    });
  };

  // Helper function to find vendor by domain
  const findVendorByDomain = (domain: string) => {
    return vendors.find(v => v.domain === domain || (v as any).additional_domains?.includes(domain));
  };

  // Navigate to vendor report page
  const viewVendorReport = (domain: string) => {
    // Build query params to preserve current state
    const params = new URLSearchParams();
    params.set('from', activeSection);

    // Preserve search term if exists
    if (vendorSearchTerm) {
      params.set('search', vendorSearchTerm);
    }

    // Preserve filters if they exist
    if (vendorFilter.length > 0) {
      params.set('riskFilter', vendorFilter.join(','));
    }
    if (tierFilter.length > 0) {
      params.set('tierFilter', tierFilter.join(','));
    }
    if (portfolioFilter.length > 0) {
      params.set('portfolioFilter', portfolioFilter.join(','));
    }
    if (industryFilter.length > 0) {
      params.set('industryFilter', industryFilter.join(','));
    }
    if (scoreFilter[0] > 0 || scoreFilter[1] < 950) {
      params.set('scoreFilter', `${scoreFilter[0]}-${scoreFilter[1]}`);
    }

    router.push(`/report/${domain}?${params.toString()}`);
  };

  // Toggle scan menu for individual vendors
  const toggleScanMenu = (vendorId: number) => {
    setShowScanMenu(showScanMenu === vendorId ? null : vendorId);
  };

  // Handle section changes from layout
  const handleSectionChange = (section: string) => {
    if (section === 'vendors' && !canViewVendors) return;
    if (section === 'security-scans' && !canViewSecurityScans) return;
    if (section === 'subdomains' && !canViewSubdomains) return;
    if (section === 'certifications' && !canViewCertifications) return;
    if (section === 'incidents' && !canViewIncidents) return;
    if (section === 'vendor-breaches' && !canViewPwnMonitor) return;
    if (section === 'breach-monitor' && !canViewInternalBreaches) return;
    setActiveSection(section);
  };

  const getRiskBadgeClass = (riskLevel: string) => {
    switch (riskLevel?.toLowerCase()) {
      case 'low': return 'risk-badge low';
      case 'medium': return 'risk-badge medium';
      case 'high': return 'risk-badge high';
      case 'critical': return 'risk-badge critical';
      default: return 'risk-badge medium';
    }
  };

  const getScoreBadgeClass = (score: number) => {
    if (score >= 800) return 'good';
    if (score >= 600) return 'average';
    return 'poor';
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'complete': case 'clean': return 'status-badge success';
      case 'warning': case 'issues': return 'status-badge warning';
      case 'error': case 'failed': return 'status-badge error';
      default: return 'status-badge info';
    }
  };

  const filteredVendors = vendors.filter(vendor => {
    const matchesSearch = vendor.name.toLowerCase().includes(vendorSearchTerm.toLowerCase()) ||
      vendor.domain.toLowerCase().includes(vendorSearchTerm.toLowerCase());
    const matchesRiskLevel = vendorFilter.length === 0 || vendorFilter.includes(vendor.riskLevel);
    const matchesTier = tierFilter.length === 0 ||
      tierFilter.some(selectedTier => {
        // Handle "Untiered" filter - show vendors without tiers OR explicitly marked as Untiered
        if (selectedTier === 'Untiered') {
          return !vendor.tier || vendor.tier === 'Unknown' || vendor.tier.trim() === '' || vendor.tier === 'Untiered';
        }
        // Handle regular tier filters
        return (vendor.tier || 'Unknown').split(',').map(t => t.trim()).includes(selectedTier);
      });
    const matchesPortfolio = portfolioFilter.length === 0 ||
      portfolioFilter.some(selectedPortfolio =>
        (vendor.portfolio || 'Unknown').split(',').map(p => p.trim()).includes(selectedPortfolio)
      );
    const matchesIndustry = industryFilter.length === 0 ||
      industryFilter.some(selectedIndustry =>
        (vendor.industry || 'Unknown').split(',').map(i => i.trim()).includes(selectedIndustry)
      );
    const vendorScore = vendor.scores?.current || 0;
    const matchesScore = vendorScore >= scoreFilter[0] && vendorScore <= scoreFilter[1];
    return matchesSearch && matchesRiskLevel && matchesTier && matchesPortfolio && matchesIndustry && matchesScore;
  });

  // Render different content based on active section
  const renderSectionContent = () => {
    switch (activeSection) {
      case 'dashboard':
        return renderDashboardContent();
      case 'vendor-comparison':
        return renderVendorComparisonContent();
      case 'vendors':
        return (
          <PermissionGate
            permission="view_vendors"
            fallback={
              <div className="content-section active">
                <div className="page-header">
                  <h1>Vendor Management</h1>
                </div>
                <p>You do not have permission to view vendor management.</p>
              </div>
            }
          >
            {renderVendorsContent()}
          </PermissionGate>
        );
      case 'subdomains':
        return (
          <PermissionGate
            permission="view_subdomains"
            fallback={
              <div className="content-section active">
                <div className="page-header">
                  <h1>Subdomains</h1>
                </div>
                <p>You do not have permission to view subdomains.</p>
              </div>
            }
          >
            {renderSubdomainsContent()}
          </PermissionGate>
        );
      case 'security-scans':
        return (
          <PermissionGate
            permission="view_security_scans"
            fallback={
              <div className="content-section active">
                <div className="page-header">
                  <h1>Security Scans</h1>
                </div>
                <p>You do not have permission to view security scans.</p>
              </div>
            }
          >
            {renderSecurityScansContent()}
          </PermissionGate>
        );
      case 'vulnerabilities':
        return renderVulnerabilitiesContent();
      case 'reputation':
        return renderReputationContent();
      case 'network':
        return renderNetworkContent();
      case 'dns':
        return renderDnsContent();
      case 'encryption':
        return renderEncryptionContent();
      case 'emails':
        return renderEmailsContent();
      case 'certifications':
        return (
          <PermissionGate
            permission="view_certifications"
            fallback={
              <div className="content-section active">
                <div className="page-header">
                  <h1>Certifications</h1>
                </div>
                <p>You do not have permission to view certifications.</p>
              </div>
            }
          >
            {renderCertificationsContent()}
          </PermissionGate>
        );
      case 'incidents':
        return (
          <PermissionGate
            permission="view_incidents"
            fallback={
              <div className="content-section active">
                <div className="page-header">
                  <h1>News & Incidents</h1>
                </div>
                <p>You do not have permission to view news and incidents.</p>
              </div>
            }
          >
            {renderIncidentsContent()}
          </PermissionGate>
        );
      case 'vendor-breaches':
        return (
          <PermissionGate
            permission="view_pwn_monitor"
            fallback={
              <div className="content-section active">
                <div className="page-header">
                  <h1>Pwn Monitor</h1>
                </div>
                <p>You do not have permission to view Pwn Monitor.</p>
              </div>
            }
          >
            {renderVendorBreachesContent()}
          </PermissionGate>
        );
      case 'breach-monitor':
        return (
          <PermissionGate
            permission="view_internal_breaches"
            fallback={
              <div className="content-section active">
                <div className="page-header">
                  <h1>Breach Monitor Breach Intelligence</h1>
                </div>
                <p>You do not have permission to view internal breach data.</p>
              </div>
            }
          >
            {renderBreachMonitorContent()}
          </PermissionGate>
        );
      case 'analytics':
        return renderAnalyticsContent();
      default:
        return renderDashboardContent();
    }
  };

  const renderDashboardContent = () => (
    <div id="dashboard-content" className="content-section active">
      <div className="page-header">
        <h1>Security Dashboard</h1>
        <div className="page-actions">
          <button className="btn btn-secondary" onClick={refreshDashboard}>
            <i className="fas fa-sync-alt"></i>
            Refresh Dashboard
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner">
            <i className="fas fa-spinner fa-spin"></i>
          </div>
          <p>Loading dashboard data...</p>
        </div>
      ) : (
        <>
          {/* Top Stats Row */}
          <div className="dashboard-stats">
            <StatCard
              title="Active Vendors"
              value={stats?.active_vendors || 0}
              icon="fas fa-building"
              iconClass="stat-icon-green"
              change="425 loaded"
              changeType="positive"
              onClick={() => openCardDetailsModal('vendors')}
            />
            <StatCard
              title="Subdomains Monitored"
              value={stats?.subdomains_monitored || 0}
              icon="fas fa-sitemap"
              iconClass="stat-icon-blue"
              change="+156 this week"
              changeType="positive"
              onClick={() => openCardDetailsModal('subdomains')}
            />
            <StatCard
              title="Vulnerabilities Found"
              value={stats?.vulnerabilities_found || 0}
              icon="fas fa-shield-alt"
              iconClass="stat-icon-orange"
              change="Requires Attention"
              changeType="negative"
              onClick={() => openCardDetailsModal('vulnerabilities')}
            />
            <StatCard
              title="High Risk Issues"
              value={stats?.high_risk_issues || 0}
              icon="fas fa-exclamation-circle"
              iconClass="stat-icon-red"
              change="Immediate Attention"
              changeType="negative"
              onClick={() => openCardDetailsModal('high-risk')}
            />
          </div>

          {/* Middle Row - Overall Score and Recent Scans */}
          <div className="dashboard-middle-row">
            {/* Overall Security Score */}
            <div className="dashboard-widget security-score-widget">
              <div className="widget-header">
                <h3>Overall Security Score</h3>
                <button className="widget-refresh-btn" onClick={() => loadDashboardData(true)}>
                  <i className="fas fa-sync-alt"></i>
                </button>
              </div>
              <div className="security-score-content">
                <div className="score-display">
                  <div className="score-number">{stats?.overall_score || 0}</div>
                  <div className="score-max">/950</div>
                </div>
                <div className="score-grade">
                  <span
                    className="grade-badge"
                    style={{
                      backgroundColor: getGradeColor(getGradeFromScore(stats?.overall_score || 0)),
                      color: 'white'
                    }}
                  >
                    {getGradeFromScore(stats?.overall_score || 0)}
                  </span>
                </div>
              </div>
              <div className="risk-breakdown">
                <div className="risk-item">
                  <span className="risk-label">Low Risk Vendors</span>
                  <span className="risk-count">
                    {stats?.risk_distribution?.low || 0}
                    {stats && stats.active_vendors && stats.active_vendors > 0 ?
                      ` (${Math.round(((stats?.risk_distribution?.low || 0) / stats.active_vendors) * 100)}%)` :
                      ' (0%)'
                    }
                  </span>
                </div>
                <div className="risk-item">
                  <span className="risk-label">Medium Risk Vendors</span>
                  <span className="risk-count">
                    {stats?.risk_distribution?.medium || 0}
                    {stats && stats.active_vendors && stats.active_vendors > 0 ?
                      ` (${Math.round(((stats?.risk_distribution?.medium || 0) / stats.active_vendors) * 100)}%)` :
                      ' (0%)'
                    }
                  </span>
                </div>
                <div className="risk-item">
                  <span className="risk-label">High Risk Vendors</span>
                  <span className="risk-count">
                    {stats?.risk_distribution?.high || 0}
                    {stats && stats.active_vendors && stats.active_vendors > 0 ?
                      ` (${Math.round(((stats?.risk_distribution?.high || 0) / stats.active_vendors) * 100)}%)` :
                      ' (0%)'
                    }
                  </span>
                </div>
                <div className="risk-item">
                  <span className="risk-label">Critical Risk Vendors</span>
                  <span className="risk-count">
                    {stats?.risk_distribution?.critical || 0}
                    {stats && stats.active_vendors && stats.active_vendors > 0 ?
                      ` (${Math.round(((stats?.risk_distribution?.critical || 0) / stats.active_vendors) * 100)}%)` :
                      ' (0%)'
                    }
                  </span>
                </div>
              </div>
            </div>

            {/* Recent Scans */}
            <div className="dashboard-widget recent-scans-widget">
              <div className="widget-header">
                <h3>Recent Scans</h3>
                <div className="widget-actions">
                  <button onClick={() => loadDashboardData(true)} className="btn btn-sm btn-secondary" title="Refresh Recent Scans">
                    <i className="fas fa-sync-alt"></i>
                  </button>
                  <button
                    className="btn btn-sm btn-primary"
                    title="View All Scans"
                    onClick={openViewAllScansModal}
                  >
                    View All
                  </button>
                </div>
              </div>
              <div className="recent-scans-list">
                {recentScans.length > 0 ? (
                  recentScans.slice(0, 4).map((scan, index) => (
                    <div key={index} className="scan-item">
                      <div className="scan-info">
                        <div className="scan-domain">{scan.vendor_name || scan.domain}</div>
                        <div className="scan-type">{scan.scan_type?.toUpperCase() || 'UNKNOWN'}</div>
                      </div>
                      <div className="scan-result">
                        <span className={`result-badge ${getScanStatusFromScore(scan.score || 0)}`}>
                          {scan.result || 'Unknown'} ({scan.score || 0})
                        </span>
                        <div className="scan-time">{scan.time_ago || 'Unknown'}</div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="no-scans">
                    <i className="fas fa-search"></i>
                    <p>No recent scans available</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Bottom Row - Vulnerability Trends and Vendor Security Scores */}
          <div className="dashboard-bottom-row">
            {/* Vulnerability Trends Chart */}
            <div className="dashboard-widget trends-widget">
              <div className="widget-header">
                <h3>Vulnerability Trends</h3>
                <select
                  className="trend-selector"
                  value={trendsTimeRange}
                  onChange={(e) => handleTrendsTimeRangeChange(e.target.value)}
                >
                  <option value="7">Last 7 Days</option>
                  <option value="30">Last 30 Days</option>
                  <option value="90">Last 3 Months</option>
                </select>
              </div>
              <div className="chart-container">
                {trendsLoading ? (
                  <div className="chart-placeholder">
                    <div className="chart-info">
                      <i className="fas fa-spinner fa-spin"></i>
                      <p>Loading trends data...</p>
                    </div>
                  </div>
                ) : trendsData ? (
                  <Line
                    data={trendsData}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: {
                        legend: {
                          position: 'top' as const,
                        },
                        title: {
                          display: false,
                        },
                      },
                      scales: {
                        y: {
                          beginAtZero: true,
                          ticks: {
                            stepSize: 1,
                          },
                        },
                      },
                      interaction: {
                        mode: 'index' as const,
                        intersect: false,
                      },
                    }}
                  />
                ) : (
                  <div className="chart-placeholder">
                    <div className="chart-info">
                      <i className="fas fa-chart-line"></i>
                      <p>No trends data available</p>
                      <small>Run some scans to see vulnerability trends</small>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Vendor Security Scores Table */}
            <div className="dashboard-widget vendor-scores-widget">
              <div className="widget-header">
                <h3>Vendor Security Scores</h3>
                <div className="vendor-search">
                  <input
                    type="text"
                    placeholder="Search vendors..."
                    value={vendorSearchTerm}
                    onChange={(e) => setVendorSearchTerm(e.target.value)}
                    className="search-input"
                  />
                </div>
              </div>
              <div className="vendor-scores-table">
                <div className="table-header">
                  <div className="header-vendor">VENDOR</div>
                  <div className="header-domain">DOMAIN</div>
                  <div className="header-score">SCORE</div>
                </div>
                <div className="table-body scrollable-vendor-list">
                  {vendors
                    .filter(vendor =>
                      vendor.name.toLowerCase().includes(vendorSearchTerm.toLowerCase()) ||
                      vendor.domain.toLowerCase().includes(vendorSearchTerm.toLowerCase())
                    )
                    .map((vendor) => (
                      <div key={vendor.id} className="vendor-row">
                        <div className="vendor-info">
                          <div className="vendor-logo">
                            <VendorLogoImage
                              domain={vendor.domain}
                              vendorName={vendor.name}
                              fallbackLogo={vendor.logo}
                            />
                          </div>
                          <div className="vendor-name">{vendor.name}</div>
                        </div>
                        <div className="vendor-domain">{vendor.domain}</div>
                        <div className="vendor-score">
                          <span className={`score-badge ${(vendor.scores?.current || 0) >= 800 ? 'score-excellent' :
                              (vendor.scores?.current || 0) >= 600 ? 'score-good' :
                                (vendor.scores?.current || 0) >= 400 ? 'score-fair' : 'score-poor'
                            }`}>
                            {vendor.scores?.current || 0}
                          </span>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );

  const renderSubdomainsContent = () => {
    // Prepare dropdown items for vendors
    const dropdownItems = vendors.map(vendor => ({
      value: vendor.domain,
      text: `${vendor.name} (${vendor.domain})`,
      data: vendor
    }));

    // Get subdomain data for display
    const getSubdomainData = () => {
      if (!subdomainResults) return [];

      // Handle different response formats
      if (subdomainResults.subdomains?.details) {
        return subdomainResults.subdomains.details;
      } else if (subdomainResults.subdomains?.alive && subdomainResults.subdomains?.inactive) {
        // Combine alive and inactive arrays
        const aliveSubdomains = subdomainResults.subdomains.alive.map((sub: string) => ({
          subdomain: sub,
          status: 'alive'
        }));
        const inactiveSubdomains = subdomainResults.subdomains.inactive.map((sub: string) => ({
          subdomain: sub,
          status: 'inactive'
        }));
        return [...aliveSubdomains, ...inactiveSubdomains];
      } else if (Array.isArray(subdomainResults.subdomains)) {
        return subdomainResults.subdomains;
      }
      return [];
    };

    // Filter subdomains based on search and filter
    const filteredSubdomains = getSubdomainData().filter((subdomain: any) => {
      const subdomainName = typeof subdomain === 'string' ? subdomain : subdomain.subdomain;
      const status = typeof subdomain === 'string' ? 'alive' : subdomain.status;

      // Apply status filter
      if (subdomainFilter === 'active' && !(status === 'alive' || status === 'Active')) return false;
      if (subdomainFilter === 'inactive' && (status === 'alive' || status === 'Active')) return false;

      // Apply search filter
      if (subdomainSearchTerm && !subdomainName.toLowerCase().includes(subdomainSearchTerm.toLowerCase())) return false;

      return true;
    });

    return (
      <div id="subdomains-content" className="content-section active">
        <div className="page-header">
          <h1>Subdomain Discovery</h1>
          <div className="page-actions">
            <button className="btn btn-primary" onClick={newSubdomainSearch}>
              <i className="fas fa-plus"></i>
              New Subdomain Search
            </button>
          </div>
        </div>

        <div className="subdomain-controls">
          <div className="widget-card">
            <div className="widget-content">
              <div className="form-group">
                <label htmlFor="domainSelect">Select Domain</label>
                <SearchableDropdown
                  placeholder="Select a domain..."
                  items={dropdownItems}
                  value={selectedDomain}
                  onChange={handleDomainSelect}
                  disabled={!!customDomain}
                />
              </div>
              <div className="form-group">
                <label htmlFor="customDomain">Enter Custom Domain</label>
                <input
                  type="text"
                  id="customDomain"
                  value={customDomain}
                  onChange={(e) => handleCustomDomainChange(e.target.value)}
                  placeholder={selectedDomain ? "Clear dropdown selection to use custom domain" : "example.com"}
                  disabled={!!selectedDomain}
                  className="form-control"
                  style={{
                    backgroundColor: selectedDomain ? '#f8f9fa' : '',
                  }}
                />
              </div>
              <div className="form-actions">
                <button
                  className="btn btn-primary"
                  onClick={() => startSubdomainDiscovery(true)}
                  disabled={subdomainLoading || (!selectedDomain && !customDomain)}
                >
                  <i className="fas fa-sitemap"></i>
                  Start New Discovery
                </button>
              </div>
            </div>
          </div>
        </div>

        {existingSubdomains && !subdomainResults && !subdomainLoading && (
          <div className="existing-subdomains-notice">
            <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
              {/* Existing Discovery Statistics */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Existing Subdomain Statistics</h3>
                </div>
                <div className="widget-content">
                  <div className="subdomain-stats-grid">
                    <div className="subdomain-stat-card">
                      <div className="stat-icon">
                        <i className="fas fa-sitemap"></i>
                      </div>
                      <div className="stat-info">
                        <div className="stat-number">
                          {parseInt(String(existingSubdomains.count.total || 0))}
                        </div>
                        <div className="stat-label">Total Subdomains</div>
                      </div>
                    </div>
                    <div className="subdomain-stat-card active">
                      <div className="stat-icon">
                        <i className="fas fa-check-circle"></i>
                      </div>
                      <div className="stat-info">
                        <div className="stat-number">
                          {parseInt(String(existingSubdomains.count.alive || 0))}
                        </div>
                        <div className="stat-label">Active Subdomains</div>
                      </div>
                    </div>
                    <div className="subdomain-stat-card inactive">
                      <div className="stat-icon">
                        <i className="fas fa-times-circle"></i>
                      </div>
                      <div className="stat-info">
                        <div className="stat-number">
                          {parseInt(String(existingSubdomains.count.inactive || 0))}
                        </div>
                        <div className="stat-label">Inactive Subdomains</div>
                      </div>
                    </div>
                    <div className="subdomain-stat-card success">
                      <div className="stat-icon">
                        <i className="fas fa-percentage"></i>
                      </div>
                      <div className="stat-info">
                        <div className="stat-number">
                          {(() => {
                            const total = parseInt(String(existingSubdomains.count.total || 0));
                            const alive = parseInt(String(existingSubdomains.count.alive || 0));
                            return total > 0 ? Math.round((alive / total) * 100) : 0;
                          })()}%
                        </div>
                        <div className="stat-label">Success Rate</div>
                      </div>
                    </div>
                  </div>
                  <div className="form-actions" style={{ marginTop: '1rem' }}>
                    <button
                      className="btn btn-primary"
                      onClick={() => startSubdomainDiscovery(true)}
                      disabled={subdomainLoading}
                    >
                      <i className="fas fa-redo"></i>
                      Run New Scan
                    </button>
                  </div>
                </div>
              </div>

              {/* Existing Subdomain Status Distribution */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Subdomain Status Distribution</h3>
                </div>
                <div className="widget-content">
                  <PieChart
                    data={{
                      active: parseInt(String(existingSubdomains.count.alive || 0)),
                      inactive: parseInt(String(existingSubdomains.count.inactive || 0))
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Existing Subdomains Table */}
            <div className="widget-card table-widget" style={{ marginTop: '2rem' }}>
              <div className="widget-header">
                <h3>Existing Subdomains</h3>
                <div className="widget-actions">
                  <select
                    className="filter-select"
                    style={{ marginRight: '1rem' }}
                    value={subdomainFilter}
                    onChange={(e) => setSubdomainFilter(e.target.value)}
                  >
                    <option value="all">All Subdomains</option>
                    <option value="active">Active Only</option>
                    <option value="inactive">Inactive Only</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Search subdomains..."
                    className="search-input"
                    style={{ marginRight: '1rem', width: '200px' }}
                    value={subdomainSearchTerm}
                    onChange={(e) => setSubdomainSearchTerm(e.target.value)}
                  />
                </div>
              </div>
              <div className="widget-content">
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>SUBDOMAIN</th>
                        <th>STATUS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(() => {
                        const currentDomain = selectedDomain || customDomain;
                        const subdomainDetails = existingSubdomains.subdomains?.details || [];

                        // Create a combined list that always includes the main domain
                        const allSubdomains = [...subdomainDetails];

                        // Check if main domain is already in the list
                        const mainDomainExists = subdomainDetails.some((sub: any) => sub.subdomain === currentDomain);

                        // If main domain doesn't exist in the list, add it
                        if (currentDomain && !mainDomainExists) {
                          allSubdomains.unshift({
                            subdomain: currentDomain,
                            status: 'Active', // Assume main domain is active
                            isMainDomain: true
                          });
                        } else {
                          // Mark the main domain in existing list
                          allSubdomains.forEach((sub: any) => {
                            if (sub.subdomain === currentDomain) {
                              sub.isMainDomain = true;
                            }
                          });
                        }

                        // Apply filters
                        const filteredSubdomains = allSubdomains.filter((subdomain: any) => {
                          const subdomainName = subdomain.subdomain;
                          const status = subdomain.status;

                          // Apply status filter
                          if (subdomainFilter === 'active' && status !== 'Active') return false;
                          if (subdomainFilter === 'inactive' && status === 'Active') return false;

                          // Apply search filter
                          if (subdomainSearchTerm && !subdomainName.toLowerCase().includes(subdomainSearchTerm.toLowerCase())) return false;

                          return true;
                        });

                        if (filteredSubdomains.length === 0) {
                          return (
                            <tr>
                              <td colSpan={2} style={{ textAlign: 'center', padding: '2rem', color: '#6b7280' }}>
                                No subdomain details available
                              </td>
                            </tr>
                          );
                        }

                        return filteredSubdomains.map((subdomain: any, index: number) => (
                          <tr key={index} className={subdomain.isMainDomain ? 'main-domain-row' : ''}>
                            <td>
                              <div className="subdomain-cell">
                                <span className="subdomain-name">
                                  {subdomain.subdomain}
                                </span>
                                {subdomain.isMainDomain && (
                                  <span className="main-domain-badge">
                                    <i className="fas fa-home"></i>
                                    Main Domain
                                  </span>
                                )}
                              </div>
                            </td>
                            <td>
                              <span className={`status-badge ${subdomain.status === 'Active' ? 'success' : 'danger'}`}>
                                {subdomain.status === 'Active' ? 'ACTIVE' : 'INACTIVE'}
                              </span>
                            </td>
                          </tr>
                        ));
                      })()}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {subdomainLoading && (
          <div className="subdomain-loading">
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)', marginBottom: '1rem' }}></i>
                <h3>Enhanced subdomain discovery for {selectedDomain || customDomain}</h3>
                <p>Using Sublist3r + crt.sh for comprehensive results...</p>

                {/* Progress Bar */}
                <div style={{ margin: '1.5rem auto', maxWidth: '400px' }}>
                  <div style={{
                    background: '#e5e7eb',
                    borderRadius: '8px',
                    height: '8px',
                    overflow: 'hidden',
                    marginBottom: '0.5rem'
                  }}>
                    <div style={{
                      background: 'var(--coral)',
                      height: '100%',
                      width: `${scanProgress}%`,
                      transition: 'width 0.3s ease',
                      borderRadius: '8px'
                    }}></div>
                  </div>
                  <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                    {scanProgress}% • {scanStatus}
                  </div>
                </div>

                <p><small>This process can take 5-10 minutes for thorough enumeration</small></p>
                <p><small style={{ color: 'var(--text-secondary)' }}>
                  Please keep this page open while the scan is running
                </small></p>

                {currentScanId && (
                  <button
                    onClick={stopSubdomainDiscovery}
                    style={{
                      marginTop: '1rem',
                      padding: '0.5rem 1rem',
                      background: 'var(--danger-red)',
                      color: 'white',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '0.9rem'
                    }}
                  >
                    <i className="fas fa-stop"></i> Stop Scan
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {subdomainResults && (
          <div className="subdomain-results">
            <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
              {/* Enhanced Discovery Statistics */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Discovery Statistics</h3>
                </div>
                <div className="widget-content">
                  <div className="subdomain-stats-grid">
                    <div className="subdomain-stat-card">
                      <div className="stat-icon">
                        <i className="fas fa-sitemap"></i>
                      </div>
                      <div className="stat-info">
                        <div className="stat-number">
                          {parseInt(String(subdomainResults.statistics?.total || subdomainResults.count?.total || 0))}
                        </div>
                        <div className="stat-label">Total Subdomains</div>
                      </div>
                    </div>
                    <div className="subdomain-stat-card active">
                      <div className="stat-icon">
                        <i className="fas fa-check-circle"></i>
                      </div>
                      <div className="stat-info">
                        <div className="stat-number">
                          {parseInt(String(subdomainResults.statistics?.alive || subdomainResults.count?.alive || 0))}
                        </div>
                        <div className="stat-label">Active Subdomains</div>
                      </div>
                    </div>
                    <div className="subdomain-stat-card inactive">
                      <div className="stat-icon">
                        <i className="fas fa-times-circle"></i>
                      </div>
                      <div className="stat-info">
                        <div className="stat-number">
                          {parseInt(String(subdomainResults.statistics?.inactive || subdomainResults.count?.inactive || 0))}
                        </div>
                        <div className="stat-label">Inactive Subdomains</div>
                      </div>
                    </div>
                    <div className="subdomain-stat-card success">
                      <div className="stat-icon">
                        <i className="fas fa-percentage"></i>
                      </div>
                      <div className="stat-info">
                        <div className="stat-number">
                          {(() => {
                            const successRate = subdomainResults.statistics?.success_rate;
                            if (successRate !== undefined && !isNaN(successRate)) {
                              return Math.round(successRate);
                            }
                            const total = parseInt(String(subdomainResults.statistics?.total || subdomainResults.count?.total || 0));
                            const alive = parseInt(String(subdomainResults.statistics?.alive || subdomainResults.count?.alive || 0));
                            return total > 0 ? Math.round((alive / total) * 100) : 0;
                          })()}%
                        </div>
                        <div className="stat-label">Success Rate</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Subdomain Status Distribution - Pie Chart */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Subdomain Status Distribution</h3>
                </div>
                <div className="widget-content">
                  <PieChart
                    data={{
                      active: parseInt(String(subdomainResults.statistics?.alive || subdomainResults.count?.alive || 0)),
                      inactive: parseInt(String(subdomainResults.statistics?.inactive || subdomainResults.count?.inactive || 0))
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Discovered Subdomains Table */}
            <div className="widget-card table-widget" style={{ marginTop: '2rem' }}>
              <div className="widget-header">
                <h3>Discovered Subdomains</h3>
                <div className="widget-actions">
                  <select
                    className="filter-select"
                    style={{ marginRight: '1rem' }}
                    value={subdomainFilter}
                    onChange={(e) => setSubdomainFilter(e.target.value)}
                  >
                    <option value="all">All Subdomains</option>
                    <option value="active">Active Only</option>
                    <option value="inactive">Inactive Only</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Search subdomains..."
                    className="search-input"
                    style={{ marginRight: '1rem', width: '200px' }}
                    value={subdomainSearchTerm}
                    onChange={(e) => setSubdomainSearchTerm(e.target.value)}
                  />
                  <button className="btn-icon" title="Download Results">
                    <i className="fas fa-download"></i>
                  </button>
                </div>
              </div>
              <div className="widget-content">
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>SUBDOMAIN</th>
                        <th>STATUS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredSubdomains.map((subdomain: any, index: number) => {
                        const subdomainName = typeof subdomain === 'string' ? subdomain : subdomain.subdomain;
                        const status = typeof subdomain === 'string' ? 'alive' : subdomain.status;
                        return (
                          <tr key={index}>
                            <td>{subdomainName}</td>
                            <td>
                              <span className={`status-badge ${status === 'alive' || status === 'Active' ? 'success' : 'danger'}`}>
                                {status === 'alive' || status === 'Active' ? 'ACTIVE' : 'INACTIVE'}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                      {filteredSubdomains.length === 0 && (
                        <tr>
                          <td colSpan={2} style={{ textAlign: 'center', padding: '2rem', color: '#6b7280' }}>
                            {subdomainSearchTerm ? 'No subdomains match your search criteria' : 'No subdomains found'}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderVendorComparisonContent = () => (
    <div id="vendor-comparison-content" className="content-section active">
      <VendorComparison />
    </div>
  );

  const renderVendorsContent = () => (
    <div id="vendors-content" className="content-section active">
      <div className="page-header">
        <h1>Vendor Management</h1>
        <div className="page-actions">
          <button className="btn btn-secondary" onClick={reloadVendors}>
            <i className="fas fa-sync-alt"></i>
            Reload Vendors
          </button>
          <button className="btn btn-secondary" onClick={refreshVendorScores}>
            <i className="fas fa-chart-bar"></i>
            Refresh Scores
          </button>
          <PermissionGate permission="run_full_scans">
            <button
              className={`btn btn-warning ${isBackgroundScanRunning ? 'btn-disabled' : ''}`}
              onClick={isBackgroundScanRunning ? undefined : startFullScanAllDomains}
              disabled={isBackgroundScanRunning}
              title={isBackgroundScanRunning
                ? `Background scan is running`
                : (() => {
                  const hasFilters = vendorSearchTerm ||
                    vendorFilter.length > 0 ||
                    tierFilter.length > 0 ||
                    portfolioFilter.length > 0 ||
                    industryFilter.length > 0 ||
                    (scoreFilter[0] > 0 || scoreFilter[1] < 950);
                  const count = hasFilters ? filteredVendors.length : vendors.length;
                  const scanType = hasFilters ? 'filtered' : 'all';
                  return `Start comprehensive security scan for ${scanType} ${count} domains`;
                })()
              }
            >
              <i className={`fas ${isBackgroundScanRunning ? 'fa-spinner fa-spin' : 'fa-shield-alt'}`}></i>
              {isBackgroundScanRunning ? 'Background Scan Running...' : (() => {
                const hasFilters = vendorSearchTerm ||
                  vendorFilter.length > 0 ||
                  tierFilter.length > 0 ||
                  portfolioFilter.length > 0 ||
                  industryFilter.length > 0 ||
                  (scoreFilter[0] > 0 || scoreFilter[1] < 950);
                const count = hasFilters ? filteredVendors.length : vendors.length;
                const scanType = hasFilters ? 'Filtered' : 'Full';
                return `${scanType} Scan ${hasFilters ? `(${count})` : 'All Domains'}`;
              })()}
            </button>
          </PermissionGate>
          <PermissionGate permission="add_vendors">
            <button className="btn btn-primary" onClick={openAddVendorModal}>
              <i className="fas fa-plus"></i>
              Add Vendor
            </button>
          </PermissionGate>
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
                <div className="status-title">Background Scan Active</div>
                <div className="status-percentage">{backgroundScanProgress}%</div>
              </div>
              <div className="status-subtitle">
                {backgroundScanCurrentDomain
                  ? `Scanning ${backgroundScanCurrentDomain}${backgroundScanStage ? ` - ${backgroundScanStage}` : ''}`
                  : 'Full security scan running in background'
                }
              </div>
              <div className="progress-bar-container">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${backgroundScanProgress}%` }}
                ></div>
              </div>
            </div>
            <PermissionGate permission="run_full_scans">
              <button
                className="scan-stop-button"
                onClick={stopBackgroundScan}
                title="Stop background scan"
              >
                <i className="fas fa-stop-circle"></i>
              </button>
            </PermissionGate>
          </div>
        </div>
      )}

      <div className="filters">
        <input
          type="text"
          placeholder="Search vendors by name or domain..."
          value={vendorSearchTerm}
          onChange={(e) => setVendorSearchTerm(e.target.value)}
          className="search-input"
        />

        <div className="advanced-filter-dropdown">
          <button
            className={`advanced-filter-button ${showAdvancedFilters ? 'active' : ''}`}
            onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
          >
            <i className="fas fa-filter"></i>
            Advanced Filters
            {(vendorFilter.length > 0 || tierFilter.length > 0 || portfolioFilter.length > 0 || industryFilter.length > 0 || (scoreFilter[0] > 0 || scoreFilter[1] < 950)) && (
              <span className="filter-active-indicator">●</span>
            )}
            <i className={`fas fa-chevron-${showAdvancedFilters ? 'up' : 'down'}`}></i>
          </button>

          {showAdvancedFilters && (
            <div className="advanced-filter-panel">
              {/* Risk Level Filter */}
              <div className="filter-section collapsible">
                <div
                  className="filter-header"
                  onClick={() => toggleSection('riskLevel')}
                >
                  <span className="filter-title">
                    <i className="fas fa-exclamation-triangle"></i>
                    Risk Level
                    {vendorFilter.length > 0 && (
                      <span className="selected-count">({vendorFilter.length} selected)</span>
                    )}
                  </span>
                  <i className={`fas fa-chevron-${expandedSections.riskLevel ? 'up' : 'down'} collapse-icon`}></i>
                </div>
                {expandedSections.riskLevel && (
                  <div className="multi-select-dropdown">
                    <input
                      type="text"
                      placeholder="Search risk levels..."
                      value={riskLevelSearch}
                      onChange={(e) => setRiskLevelSearch(e.target.value)}
                      className="filter-search-input"
                    />
                    <div className="options-container">
                      {getFilteredOptions(getRiskLevels(), riskLevelSearch).map((level, index) => (
                        <label key={`risk-${index}-${level}`} className="option-item">
                          <input
                            type="checkbox"
                            checked={vendorFilter.includes(level)}
                            onChange={() => setVendorFilter(toggleFilterValue(vendorFilter, level))}
                          />
                          <span className="option-text">{level.charAt(0).toUpperCase() + level.slice(1)} Risk</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Tier Filter */}
              <div className="filter-section collapsible">
                <div
                  className="filter-header"
                  onClick={() => toggleSection('tier')}
                >
                  <span className="filter-title">
                    <i className="fas fa-layer-group"></i>
                    Tier
                    {tierFilter.length > 0 && (
                      <span className="selected-count">({tierFilter.length} selected)</span>
                    )}
                  </span>
                  <i className={`fas fa-chevron-${expandedSections.tier ? 'up' : 'down'} collapse-icon`}></i>
                </div>
                {expandedSections.tier && (
                  <div className="multi-select-dropdown">
                    <input
                      type="text"
                      placeholder="Search tiers..."
                      value={tierSearch}
                      onChange={(e) => setTierSearch(e.target.value)}
                      className="filter-search-input"
                    />
                    <div className="options-container">
                      {getFilteredOptions(getUniqueTiers(), tierSearch).map((tier, index) => (
                        <label key={`tier-${index}-${tier}`} className="option-item">
                          <input
                            type="checkbox"
                            checked={tierFilter.includes(tier)}
                            onChange={() => setTierFilter(toggleFilterValue(tierFilter, tier))}
                          />
                          <span className="option-text">{tier}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Portfolio Filter */}
              <div className="filter-section collapsible">
                <div
                  className="filter-header"
                  onClick={() => toggleSection('portfolio')}
                >
                  <span className="filter-title">
                    <i className="fas fa-briefcase"></i>
                    Portfolio
                    {portfolioFilter.length > 0 && (
                      <span className="selected-count">({portfolioFilter.length} selected)</span>
                    )}
                  </span>
                  <i className={`fas fa-chevron-${expandedSections.portfolio ? 'up' : 'down'} collapse-icon`}></i>
                </div>
                {expandedSections.portfolio && (
                  <div className="multi-select-dropdown">
                    <input
                      type="text"
                      placeholder="Search portfolios..."
                      value={portfolioSearch}
                      onChange={(e) => setPortfolioSearch(e.target.value)}
                      className="filter-search-input"
                    />
                    <div className="options-container">
                      {getFilteredOptions(getUniquePortfolios(), portfolioSearch).map((portfolio, index) => (
                        <label key={`portfolio-${index}-${portfolio}`} className="option-item">
                          <input
                            type="checkbox"
                            checked={portfolioFilter.includes(portfolio)}
                            onChange={() => setPortfolioFilter(toggleFilterValue(portfolioFilter, portfolio))}
                          />
                          <span className="option-text">{portfolio}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Industry Filter */}
              <div className="filter-section collapsible">
                <div
                  className="filter-header"
                  onClick={() => toggleSection('industry')}
                >
                  <span className="filter-title">
                    <i className="fas fa-industry"></i>
                    Industry
                    {industryFilter.length > 0 && (
                      <span className="selected-count">({industryFilter.length} selected)</span>
                    )}
                  </span>
                  <i className={`fas fa-chevron-${expandedSections.industry ? 'up' : 'down'} collapse-icon`}></i>
                </div>
                {expandedSections.industry && (
                  <div className="multi-select-dropdown">
                    <input
                      type="text"
                      placeholder="Search industries..."
                      value={industrySearch}
                      onChange={(e) => setIndustrySearch(e.target.value)}
                      className="filter-search-input"
                    />
                    <div className="options-container">
                      {getFilteredOptions(getUniqueIndustries(), industrySearch).map((industry, index) => (
                        <label key={`industry-${index}-${industry}`} className="option-item">
                          <input
                            type="checkbox"
                            checked={industryFilter.includes(industry)}
                            onChange={() => setIndustryFilter(toggleFilterValue(industryFilter, industry))}
                          />
                          <span className="option-text">{industry}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Score Filter */}
              <div className="filter-section collapsible">
                <div
                  className="filter-header"
                  onClick={() => toggleSection('score')}
                >
                  <span className="filter-title">
                    <i className="fas fa-chart-line"></i>
                    Score
                    {(scoreFilter[0] > 0 || scoreFilter[1] < 950) && (
                      <span className="selected-count">({scoreFilter[0]} - {scoreFilter[1]})</span>
                    )}
                  </span>
                  <i className={`fas fa-chevron-${expandedSections.score ? 'up' : 'down'} collapse-icon`}></i>
                </div>
                {expandedSections.score && (
                  <div className="score-filter-container">
                    <div className="score-range-display">
                      <span className="score-filter-value">{scoreFilter[0]}</span>
                      <span className="score-separator">-</span>
                      <span className="score-filter-value">{scoreFilter[1]}</span>
                    </div>
                    <div className="dual-range-slider">
                      <input
                        type="range"
                        min="0"
                        max="950"
                        value={scoreFilter[0]}
                        onChange={(e) => {
                          const newMin = parseInt(e.target.value);
                          if (newMin <= scoreFilter[1]) {
                            setScoreFilter([newMin, scoreFilter[1]]);
                          }
                        }}
                        className="range-slider range-min"
                      />
                      <input
                        type="range"
                        min="0"
                        max="950"
                        value={scoreFilter[1]}
                        onChange={(e) => {
                          const newMax = parseInt(e.target.value);
                          if (newMax >= scoreFilter[0]) {
                            setScoreFilter([scoreFilter[0], newMax]);
                          }
                        }}
                        className="range-slider range-max"
                      />
                    </div>
                    <button
                      className="btn btn-sm btn-outline reset-score-btn"
                      onClick={() => setScoreFilter([0, 950])}
                    >
                      <i className="fas fa-undo"></i>
                      Reset
                    </button>
                  </div>
                )}
              </div>

              <div className="filter-actions">
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={clearAllVendorFilters}
                >
                  <i className="fas fa-undo"></i>
                  Clear All
                </button>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => setShowAdvancedFilters(false)}
                >
                  <i className="fas fa-check"></i>
                  Apply
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Vendor Count Display */}
      {(vendorSearchTerm || vendorFilter.length > 0 || tierFilter.length > 0 || portfolioFilter.length > 0 || industryFilter.length > 0 || (scoreFilter[0] > 0 || scoreFilter[1] < 950)) && (
        <div className="vendor-count-display">
          <i className="fas fa-filter"></i>
          Showing <strong>{filteredVendors.length}</strong> out of <strong>{vendors.length}</strong> vendors
        </div>
      )}

      <div className="vendors-grid">
        {filteredVendors.length > 0 ? filteredVendors.map((vendor) => (
          <div key={vendor.id} className="vendor-card">
            <div className="vendor-card-header">
              <div className="vendor-info">
                <VendorLogoImage domain={vendor.domain} vendorName={vendor.name} fallbackLogo={vendor.logo} className="vendor-logo" />
                <div className="vendor-details">
                  <h3 className="vendor-name">{vendor.name}</h3>
                  <p className="vendor-domain">{vendor.domain}</p>
                  <div className="vendor-tier-container">
                    {vendor.tier && vendor.tier !== 'Unknown' && vendor.tier !== 'Untiered' && vendor.tier.trim() !== '' ? (
                      <span className="vendor-tier-badge" title={`Tier: ${vendor.tier}`}>
                        {vendor.tier}
                      </span>
                    ) : (
                      <span className="vendor-tier-badge-placeholder"></span>
                    )}
                  </div>
                </div>
              </div>
              <span className={getRiskBadgeClass(vendor.riskLevel)}>{vendor.riskLevel}</span>
              <PermissionGate permission="manage_vendors">
                <button
                  className="vendor-edit-btn"
                  title="Edit Vendor"
                  onClick={(e) => {
                    e.stopPropagation();
                    openEditVendorModal(vendor);
                  }}
                >
                  <i className="fas fa-edit"></i>
                </button>
              </PermissionGate>
              <PermissionGate permission="delete_vendors">
                <button
                  className="vendor-delete-btn"
                  title="Delete Vendor"
                  onClick={(e) => {
                    e.stopPropagation();
                    openDeleteVendorModal(vendor);
                  }}
                >
                  <i className="fas fa-trash"></i>
                </button>
              </PermissionGate>
            </div>

            <div className="vendor-score-section">
              <div className="score-display">
                <span className="score-value">{vendor.scores?.current || 0}</span>
                <span className="score-max">/950</span>
              </div>
            </div>

            <div className="vendor-actions">
              <button
                className="btn btn-outline"
                onClick={() => refreshVendorScore(vendor.id)}
              >
                <i className="fas fa-sync-alt"></i> Refresh Score
              </button>
              <PermissionGate permission="run_full_scans">
                <button
                  className="btn btn-secondary"
                  onClick={() => startFullScan(vendor.domain)}
                >
                  <i className="fas fa-play"></i> Full Scan
                </button>
              </PermissionGate>
              <button
                className="btn btn-primary"
                onClick={() => viewVendorReport(vendor.domain)}
              >
                <i className="fas fa-eye"></i> View Details
              </button>
            </div>
          </div>
        )) : (
          <div className="no-vendors-message">
            <i className="fas fa-building" style={{ fontSize: '3rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}></i>
            <h3>No vendors found</h3>
            <p>No vendors match your current search criteria.</p>
          </div>
        )}
      </div>

      {/* Add Vendor Modal */}
      {showAddVendorModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2>Add New Vendor</h2>
            <div>
              <div className="form-group">
                <label>Vendor Name: <span style={{ color: 'red' }}>*</span></label>
                <input
                  type="text"
                  value={addVendorForm.vendorName}
                  onChange={(e) => setAddVendorForm({ ...addVendorForm, vendorName: e.target.value })}
                  className="form-control"
                  required
                />
              </div>
              <div className="form-group">
                <label>Vendor Domain:<span style={{ color: 'red' }}>*</span></label>
                <input
                  type="text"
                  value={addVendorForm.vendorDomain}
                  onChange={(e) => setAddVendorForm({ ...addVendorForm, vendorDomain: e.target.value })}
                  className="form-control"
                  required
                />
                {addVendorForm.vendorDomain && extractDomainFromInput(addVendorForm.vendorDomain) && (
                  <small className="text-muted">
                    Domain Stored: <strong>{extractDomainFromInput(addVendorForm.vendorDomain)}</strong>
                  </small>
                )}
              </div>
              <div className="form-group">
                <label>Tier: <span style={{ color: 'red' }}>*</span></label>
                <SearchableDropdown
                  placeholder="Select tier..."
                  items={getUniqueTiers().map(tier => ({ text: tier, value: tier }))}
                  value={addVendorForm.tier}
                  onChange={(item) => setAddVendorForm({ ...addVendorForm, tier: item?.value || '' })}
                />
              </div>
              <div className="form-group">
                <label>Portfolio: <span style={{ color: 'red' }}>*</span></label>
                <SearchableDropdown
                  placeholder="Select portfolio..."
                  items={getUniquePortfolios().map(portfolio => ({ text: portfolio, value: portfolio }))}
                  value={addVendorForm.portfolio}
                  onChange={(item) => setAddVendorForm({ ...addVendorForm, portfolio: item?.value || '' })}
                />
              </div>
              <div className="form-group">
                <label>Industry:</label>
                <SearchableDropdown
                  placeholder="Select industry (optional)..."
                  items={getUniqueIndustries().map(industry => ({ text: industry, value: industry }))}
                  value={addVendorForm.industry}
                  onChange={(item) => setAddVendorForm({ ...addVendorForm, industry: item?.value || '' })}
                />
              </div>
              {addVendorError && <p className="error-message">{addVendorError}</p>}
              <div className="modal-actions">
                <button type="button" className="btn btn-primary" onClick={handleAddVendor} disabled={isAddingVendor}>
                  {isAddingVendor ? 'Adding...' : 'Add Vendor'}
                </button>
                <button type="button" className="btn btn-secondary" onClick={closeAddVendorModal}>
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Vendor Modal */}
      {showDeleteVendorModal && deleteVendorData && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2>Confirm Deletion</h2>
            <p>Are you sure you want to delete <strong>{deleteVendorData.name}</strong>?</p>
            <div className="modal-actions">
              <button className="btn btn-danger" onClick={confirmDeleteVendor}>
                Delete
              </button>
              <button className="btn btn-secondary" onClick={closeDeleteVendorModal}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Vendor Modal */}
      {showEditVendorModal && editVendorId && (
        <EditVendorModal
          vendorId={editVendorId}
          isOpen={showEditVendorModal}
          onClose={closeEditVendorModal}
          onSuccess={handleEditVendorSuccess}
          onError={handleEditVendorError}
          tierOptions={getUniqueTiers()}
          portfolioOptions={getUniquePortfolios()}
          industryOptions={getUniqueIndustries()}
        />
      )}
    </div>
  );

  // Unified Security Scans Component
  const renderSecurityScansContent = () => {
    const targetDomain = securityScansSelectedDomain || securityScansCustomDomain;

    // Start unified security scans
    const startUnifiedSecurityScans = async () => {
      if (!targetDomain) {
        showNotification('warning', 'Domain Required', 'Please select a domain from the dropdown or enter a custom domain');
        return;
      }

      const selectedScans = Object.entries(securityScansSelectedTypes).filter(([_, selected]) => selected);
      if (selectedScans.length === 0) {
        showNotification('warning', 'No Scans Selected', 'Please select at least one scan type to perform');
        return;
      }

      const scanId = `unified_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      try {
        setSecurityScansLoading(true);
        setSecurityScansProgress(0);
        setSecurityScansStatus('Initializing scans...');

        const totalScans = selectedScans.length;
        let completedScans = 0;
        const results: { [key: string]: any } = {};

        // Starting scans - no notification needed

        // Check subdomains first if needed
        setSecurityScansStatus('Checking subdomains...');
        let subdomains = [];
        try {
          const subdomainResponse = await fetch(`/api/subdomains/${targetDomain}`);
          if (subdomainResponse.ok) {
            const subdomainData = await subdomainResponse.json();
            subdomains = subdomainData.subdomains || [];
          }
        } catch (error) {
          console.log('Could not fetch subdomains, continuing with main domain only');
        }

        // Execute each selected scan
        for (const [scanType] of selectedScans) {
          setSecurityScansStatus(`Running ${scanType} scan...`);

          // Get proper scan type name for notification
          const getScanTypeName = (type: string) => {
            switch (type) {
              case 'subdomain': return 'Subdomain Discovery';
              case 'vulnerability': return 'Website Scan';
              case 'reputation': return 'Domain Reputation';
              case 'network': return 'Network Scan';
              case 'dns': return 'DNS Scan';
              case 'encryption': return 'Encryption Scan';
              case 'email': return 'Email Scan';
              default: return type.charAt(0).toUpperCase() + type.slice(1) + ' Scan';
            }
          };

          try {
            let scanResult;

            switch (scanType) {
              case 'subdomain':
                const subdomainResponse = await fetch(`/api/subdomains/discover-async`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                  },
                  body: JSON.stringify({
                    domain: targetDomain,
                    force_rediscovery: true
                  }),
                });
                const subdomainStart = await subdomainResponse.json();
                // Log the subdomain discovery action with vendor context
                const vendor0 = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'subdomain_discovery', subdomainStart.scan_id || targetDomain, {
                  action_type: 'start_subdomain_discovery',
                  domain: targetDomain,
                  vendor_name: vendor0?.name || 'Unknown Vendor',
                  vendor_id: vendor0?.id,
                  scan_type: 'subdomain_discovery',
                  scan_id: subdomainStart.scan_id,
                  context: 'security_scans_section',
                  timestamp: new Date().toISOString()
                });
                if (subdomainStart.scan_id) {
                  scanResult = await waitForSubdomainScanCompletion(subdomainStart.scan_id, targetDomain);
                } else {
                  scanResult = subdomainStart;
                }
                break;
              case 'vulnerability':
                scanResult = await scanApi.startVulnerabilityScan(targetDomain);
                // Log the scan action with vendor context
                const vendor = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'vulnerability', (scanResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_vulnerability_scan',
                  domain: targetDomain,
                  vendor_name: vendor?.name || 'Unknown Vendor',
                  vendor_id: vendor?.id,
                  scan_type: 'vulnerability',
                  scan_id: (scanResult as any)?.scan_id,
                  context: 'security_scans_section',
                  timestamp: new Date().toISOString()
                });
                break;
              case 'reputation':
                scanResult = await scanApi.startReputationScan(targetDomain);
                // Log the scan action with vendor context
                const vendor2 = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'reputation', (scanResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_reputation_scan',
                  domain: targetDomain,
                  vendor_name: vendor2?.name || 'Unknown Vendor',
                  vendor_id: vendor2?.id,
                  scan_type: 'reputation',
                  scan_id: (scanResult as any)?.scan_id,
                  context: 'security_scans_section',
                  timestamp: new Date().toISOString()
                });
                break;
              case 'network':
                const networkResult = await scanApi.startNetworkScan(targetDomain);
                // Log the scan action with vendor context
                const vendor3 = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'network', (networkResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_network_scan',
                  domain: targetDomain,
                  vendor_name: vendor3?.name || 'Unknown Vendor',
                  vendor_id: vendor3?.id,
                  scan_type: 'network',
                  scan_id: (networkResult as any)?.scan_id,
                  context: 'security_scans_section',
                  timestamp: new Date().toISOString()
                });
                if (networkResult.scan_id) {
                  scanResult = await waitForNetworkScanCompletion(networkResult.scan_id, targetDomain);
                } else {
                  scanResult = networkResult;
                }
                break;
              case 'dns':
                const dnsStartResult = await scanApi.startDnsScan(targetDomain);
                // Log the scan action with vendor context
                const vendor4 = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'dns', (dnsStartResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_dns_scan',
                  domain: targetDomain,
                  vendor_name: vendor4?.name || 'Unknown Vendor',
                  vendor_id: vendor4?.id,
                  scan_type: 'dns',
                  scan_id: (dnsStartResult as any)?.scan_id,
                  context: 'security_scans_section',
                  timestamp: new Date().toISOString()
                });
                if (dnsStartResult.scan_id) {
                  scanResult = await waitForDnsScanCompletion(dnsStartResult.scan_id, targetDomain);
                } else {
                  scanResult = dnsStartResult;
                }
                break;
              case 'encryption':
                const encryptionResult = await scanApi.startEncryptionScan(targetDomain);
                // Log the scan action with vendor context
                const vendor5 = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'encryption', (encryptionResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_encryption_scan',
                  domain: targetDomain,
                  vendor_name: vendor5?.name || 'Unknown Vendor',
                  vendor_id: vendor5?.id,
                  scan_type: 'encryption',
                  scan_id: (encryptionResult as any)?.scan_id,
                  context: 'security_scans_section',
                  timestamp: new Date().toISOString()
                });
                if (encryptionResult.scan_id) {
                  scanResult = await waitForEncryptionScanCompletion(encryptionResult.scan_id, targetDomain);
                } else {
                  scanResult = encryptionResult;
                }
                break;
              case 'email':
                scanResult = await scanApi.startEmailScan(targetDomain);
                // Log the scan action with vendor context
                const vendor6 = findVendorByDomain(targetDomain);
                logUserAction('SCAN', 'email', (scanResult as any)?.scan_id || targetDomain, {
                  action_type: 'start_email_scan',
                  domain: targetDomain,
                  vendor_name: vendor6?.name || 'Unknown Vendor',
                  vendor_id: vendor6?.id,
                  scan_type: 'email',
                  scan_id: (scanResult as any)?.scan_id,
                  context: 'security_scans_section',
                  timestamp: new Date().toISOString()
                });
                break;
            }

            if (scanResult && scanResult.success !== false) {
              results[scanType] = scanResult;

              showNotification('success', `${getScanTypeName(scanType)} Completed`,
                `${getScanTypeName(scanType)} completed for ${targetDomain}`,
                { persistent: true, domain: targetDomain, scanType: `${scanType}_scan` });
            } else {
              console.error(`${scanType} scan failed:`, scanResult);
              showNotification('error', `${getScanTypeName(scanType)} Failed`,
                `${getScanTypeName(scanType)} failed for ${targetDomain}`);
            }
          } catch (error) {
            console.error(`Error in ${scanType} scan:`, error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
            showNotification('error', 'Scan Error', `Error during ${getScanTypeName(scanType)}: ${errorMessage}`);
          }

          completedScans++;
          const progress = Math.round((completedScans / totalScans) * 100);
          setSecurityScansProgress(progress);
        }

        setSecurityScansResults(results);
        setSecurityScansStatus('All selected scans completed!');

      } catch (error) {
        console.error('Error in unified security scans:', error);
        showNotification('error', 'Scan Failed', 'Failed to complete security scans');
      } finally {
        setSecurityScansLoading(false);
      }
    };

    // Toggle collapse state for scan sections
    const toggleScanSection = (scanType: string) => {
      setSecurityScansCollapsed(prev => ({
        ...prev,
        [scanType]: !prev[scanType]
      }));
    };

    // Render scan results table for a specific scan type
    const renderScanResultsTable = (scanType: string, results: any) => {
      if (!results || !securityScansSelectedTypes[scanType as keyof typeof securityScansSelectedTypes]) {
        return null;
      }

      const isCollapsed = securityScansCollapsed[scanType as keyof typeof securityScansCollapsed];
      const hasData = scanType === 'subdomain'
        ? (results.subdomains && results.subdomains.length > 0)
        : (results.vulnerabilities && results.vulnerabilities.length > 0);

      return (
        <div key={scanType} className="widget-card" style={{ marginBottom: '1.5rem' }}>
          <div
            className={`widget-header scan-section-header ${isCollapsed ? 'collapsed' : ''}`}
            style={{ cursor: 'pointer', userSelect: 'none' }}
            onClick={() => toggleScanSection(scanType)}
          >
            <h3>
              <i className={`fas ${isCollapsed ? 'fa-chevron-right' : 'fa-chevron-down'}`}
                style={{ marginRight: '0.75rem', fontSize: '0.9rem', color: '#ef4444' }}></i>
              <i className={`fas ${scanType === 'subdomain' ? 'fa-sitemap' :
                  scanType === 'vulnerability' ? 'fa-laptop-code' :
                    scanType === 'reputation' ? 'fa-search' :
                      scanType === 'network' ? 'fa-network-wired' :
                        scanType === 'dns' ? 'fa-globe' :
                          scanType === 'encryption' ? 'fa-lock' :
                            'fa-envelope'
                }`} style={{ marginRight: '0.75rem', color: '#dc2626' }}></i>
              {scanType.charAt(0).toUpperCase() + scanType.slice(1)} Security Scan
              {(results.summary || results.subdomains) && (
                <span style={{
                  marginLeft: '1rem',
                  fontSize: '0.9rem',
                  color: '#6b7280',
                  fontWeight: '500'
                }}>
                  {scanType === 'subdomain'
                    ? `(${results.subdomains?.length || 0} subdomains found)`
                    : `(${results.summary?.total_vulnerabilities || results.summary?.total_issues || 0} issues found)`
                  }
                </span>
              )}
            </h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              {results.final_score && (
                <span className={`score-badge ${results.final_score >= 800 ? 'excellent' :
                    results.final_score >= 600 ? 'good' :
                      results.final_score >= 400 ? 'fair' : 'poor'
                  }`}>
                  <i className="fas fa-shield-alt" style={{ marginRight: '0.5rem' }}></i>
                  {results.final_score}
                </span>
              )}
            </div>
          </div>

          {!isCollapsed && (
            <div className="widget-content">
              {hasData ? (
                <div className="vulnerability-table-container">
                  {scanType === 'subdomain' ? (
                    // Subdomain Discovery Results
                    <div>
                      {/* Filter and Search Controls */}
                      <div className="widget-header" style={{
                        background: 'transparent',
                        padding: '0 0 1rem 0',
                        marginBottom: '1rem',
                        borderBottom: '1px solid #e5e7eb'
                      }}>
                        <div className="widget-actions" style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '1rem',
                          flexWrap: 'wrap'
                        }}>
                          <select
                            className="filter-select"
                            value={securitySubdomainFilter}
                            onChange={(e) => setSecuritySubdomainFilter(e.target.value)}
                            style={{
                              minWidth: '150px',
                              padding: '0.5rem',
                              border: '1px solid #d1d5db',
                              borderRadius: '6px',
                              fontSize: '0.875rem'
                            }}
                          >
                            <option value="all">All Subdomains</option>
                            <option value="active">Active Only</option>
                            <option value="inactive">Inactive Only</option>
                          </select>
                          <input
                            type="text"
                            placeholder="Search subdomains..."
                            className="search-input"
                            value={securitySubdomainSearchTerm}
                            onChange={(e) => setSecuritySubdomainSearchTerm(e.target.value)}
                            style={{
                              minWidth: '150px',
                              padding: '0.5rem',
                              border: '1px solid #d1d5db',
                              borderRadius: '6px',
                              fontSize: '0.875rem'
                            }}
                          />
                        </div>
                      </div>

                      <table className="vulnerability-table">
                        <thead>
                          <tr>
                            <th>SUBDOMAIN</th>
                            <th>STATUS</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(() => {
                            const targetDomain = securityScansSelectedDomain || securityScansCustomDomain;
                            const subdomainList = results.subdomains || [];

                            // Create a combined list that always includes the main domain
                            const allSubdomains = [...subdomainList];

                            // Check if main domain is already in the list
                            const mainDomainExists = subdomainList.some((sub: any) =>
                              (sub.subdomain || sub.domain) === targetDomain
                            );

                            // If main domain doesn't exist in the list, add it
                            if (targetDomain && !mainDomainExists) {
                              allSubdomains.unshift({
                                subdomain: targetDomain,
                                domain: targetDomain,
                                status: 'Active', // Assume main domain is active
                                isMainDomain: true
                              });
                            } else {
                              // Mark the main domain in existing list
                              allSubdomains.forEach((sub: any) => {
                                if ((sub.subdomain || sub.domain) === targetDomain) {
                                  sub.isMainDomain = true;
                                }
                              });
                            }

                            // Apply filters
                            const filteredSubdomains = allSubdomains.filter((subdomain: any) => {
                              const subdomainName = subdomain.subdomain || subdomain.domain;
                              const status = subdomain.status || 'Active';
                              const isActive = status === 'Active' || status === 'active' || status === 'alive';

                              // Apply status filter
                              if (securitySubdomainFilter === 'active' && !isActive) return false;
                              if (securitySubdomainFilter === 'inactive' && isActive) return false;

                              // Apply search filter
                              if (securitySubdomainSearchTerm && !subdomainName.toLowerCase().includes(securitySubdomainSearchTerm.toLowerCase())) return false;

                              return true;
                            });

                            if (filteredSubdomains.length === 0) {
                              return (
                                <tr>
                                  <td colSpan={2} style={{ textAlign: 'center', padding: '2rem', color: '#6b7280' }}>
                                    No subdomains found matching the current filter
                                  </td>
                                </tr>
                              );
                            }

                            return filteredSubdomains.map((subdomain: any, index: number) => {
                              const subdomainName = subdomain.subdomain || subdomain.domain;
                              const status = subdomain.status || 'Active';
                              const isActive = status === 'Active' || status === 'active' || status === 'alive';

                              return (
                                <tr key={index} className={`vulnerability-group-row ${subdomain.isMainDomain ? 'main-domain-row' : ''}`}>
                                  <td>
                                    <div className="subdomain-cell" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                      <i className="fas fa-globe" style={{ color: '#6b7280' }}></i>
                                      <span className="subdomain-name" style={{ fontWeight: '500' }}>
                                        {subdomainName}
                                      </span>
                                      {subdomain.isMainDomain && (
                                        <span className="main-domain-badge" style={{
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
                                  <td>
                                    <span className={`status-badge ${isActive ? 'success' : 'danger'}`} style={{
                                      padding: '0.375rem 0.75rem',
                                      borderRadius: '6px',
                                      fontSize: '0.75rem',
                                      fontWeight: '600',
                                      textTransform: 'uppercase',
                                      letterSpacing: '0.025em',
                                      background: isActive
                                        ? 'linear-gradient(135deg, #10b981, #059669)'
                                        : 'linear-gradient(135deg, #ef4444, #dc2626)',
                                      color: 'white',
                                      boxShadow: isActive
                                        ? '0 2px 4px rgba(16, 185, 129, 0.3)'
                                        : '0 2px 4px rgba(239, 68, 68, 0.3)'
                                    }}>
                                      {isActive ? 'ACTIVE' : 'INACTIVE'}
                                    </span>
                                  </td>
                                </tr>
                              );
                            });
                          })()}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    // Vulnerability/Security Results
                    <table className="vulnerability-table">
                      <thead>
                        <tr>
                          <th>AFFECTED SUBDOMAIN</th>
                          <th>ISSUE TYPE</th>
                          <th>SEVERITY</th>
                          <th>DESCRIPTION</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(() => {
                          // Group vulnerabilities by type for better display
                          const grouped = groupVulnerabilitiesByType(results.vulnerabilities, scanType);
                          return grouped.map((group, index) => (
                            <tr
                              key={index}
                              className="vulnerability-group-row"
                              onClick={() => setSelectedSecurityScanIssue({
                                title: group.title,
                                vulnerabilities: group.vulnerabilities,
                                scanType: scanType.charAt(0).toUpperCase() + scanType.slice(1)
                              })}
                              style={{ cursor: 'pointer' }}
                              title="Click to view affected domains"
                            >
                              <td>
                                <div className="vulnerability-group-header">
                                  <i className="fas fa-eye vulnerability-view-icon" style={{ marginRight: '0.5rem', color: '#ef4444' }}></i>
                                  <span className="affected-count">
                                    {group.affectedDomains.length} affected domain{group.affectedDomains.length > 1 ? 's' : ''}
                                  </span>
                                </div>
                              </td>
                              <td>
                                <span style={{
                                  color: '#dc2626',
                                  fontWeight: '600',
                                  textTransform: 'capitalize'
                                }}>
                                  {scanType}
                                </span>
                              </td>
                              <td>
                                <span className={`severity-badge ${group.severity.toLowerCase()}`}>
                                  {group.severity}
                                </span>
                              </td>
                              <td>
                                <div style={{ fontWeight: '500', marginBottom: '0.25rem' }}>{group.title}</div>
                                <div style={{ fontSize: '0.9rem', color: '#6b7280' }}>{group.description}</div>
                              </td>
                            </tr>
                          ));
                        })()}
                      </tbody>
                    </table>
                  )}
                </div>
              ) : (
                <div className="no-vulnerabilities-found">
                  <div className="empty-state">
                    <i className={`fas ${scanType === 'subdomain' ? 'fa-sitemap' : 'fa-shield-alt'}`}
                      style={{ fontSize: '2rem', color: 'var(--success-green)', marginBottom: '1rem' }}></i>
                    <h4>{scanType === 'subdomain' ? 'No Subdomains Found' : 'No Vulnerabilities Found'}</h4>
                    <p>{scanType === 'subdomain'
                      ? 'No subdomains were discovered for this domain.'
                      : `No security issues were discovered during the ${scanType} scan.`}
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      );
    };

    return (
      <div id="security-scans-content" className="content-section active">
        <div className="page-header">
          <h1>Security Scans</h1>
        </div>

        <div className="section-content">
          {/* Scanner Controls */}
          <div className="widget-card">
            <div className="widget-content">
              {/* Domain Selection */}
              <div style={{ marginBottom: '2rem' }}>
                <div className="form-group">
                  <label htmlFor="security-domain-select">Select Domain:</label>
                  <SearchableDropdown
                    items={vendors.map(vendor => ({
                      text: `${vendor.name} (${vendor.domain})`,
                      value: vendor.domain
                    }))}
                    value={securityScansSelectedDomain}
                    onChange={(item) => handleDropdownChange(item, setSecurityScansSelectedDomain, setSecurityScansCustomDomain)}
                    placeholder="Search vendors..."
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="security-custom-domain">Custom Domain:</label>
                  <input
                    type="text"
                    id="security-custom-domain"
                    placeholder="Enter domain (e.g., example.com)"
                    value={securityScansCustomDomain}
                    onChange={(e) => {
                      setSecurityScansCustomDomain(e.target.value);
                      setSecurityScansSelectedDomain('');
                    }}
                    className="form-control"
                  />
                </div>
              </div>

              {/* Scan Type Selection */}
              <div style={{ marginBottom: '2rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <h4 style={{ margin: 0 }}>Select Scan Types:</h4>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      type="button"
                      onClick={() => {
                        const allSelected = Object.values(securityScansSelectedTypes).every(v => v);
                        setSecurityScansSelectedTypes({
                          subdomain: !allSelected,
                          vulnerability: !allSelected,
                          reputation: !allSelected,
                          network: !allSelected,
                          dns: !allSelected,
                          encryption: !allSelected,
                          email: !allSelected
                        });
                      }}
                      className="btn btn-secondary select-all-button"
                      style={{
                        fontSize: '0.9rem',
                        padding: '0.75rem 1.5rem',
                        background: Object.values(securityScansSelectedTypes).every(v => v)
                          ? 'linear-gradient(135deg, #ef4444, #dc2626)'
                          : 'linear-gradient(135deg, #6b7280, #4b5563)',
                        borderColor: Object.values(securityScansSelectedTypes).every(v => v) ? '#dc2626' : '#6b7280',
                        color: 'white',
                        fontWeight: '600',
                        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)'
                      }}
                    >
                      <i className={`fas ${Object.values(securityScansSelectedTypes).every(v => v) ? 'fa-times' : 'fa-check-double'}`}
                        style={{ marginRight: '0.5rem' }}></i>
                      {Object.values(securityScansSelectedTypes).every(v => v) ? 'Deselect All' : 'Select All'}
                    </button>
                  </div>
                </div>
                <div className="scan-types-grid" style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(3, 1fr)',
                  gap: '1.5rem',
                  maxWidth: '100%'
                }}>
                  {[
                    { key: 'subdomain', label: 'Subdomain Discovery', icon: 'fas fa-sitemap', description: 'Discover subdomains and endpoints' },
                    { key: 'vulnerability', label: 'Website Scans', icon: 'fas fa-laptop-code', description: 'Scan for web vulnerabilities' },
                    { key: 'reputation', label: 'Domain Reputation', icon: 'fas fa-search', description: 'Check domain reputation' },
                    { key: 'network', label: 'Network Scanning', icon: 'fas fa-network-wired', description: 'Scan network ports and services' },
                    { key: 'dns', label: 'DNS Security', icon: 'fas fa-globe', description: 'Check DNS configuration' },
                    { key: 'encryption', label: 'Encryption Checks', icon: 'fas fa-lock', description: 'Analyze SSL/TLS security' },
                    { key: 'email', label: 'Email Security', icon: 'fas fa-envelope', description: 'Check email security settings' }
                  ].map(scanType => (
                    <label
                      key={scanType.key}
                      className={`scan-type-option ${securityScansSelectedTypes[scanType.key as keyof typeof securityScansSelectedTypes] ? 'selected' : ''}`}
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        padding: '2rem 1.5rem',
                        textAlign: 'center',
                        minHeight: '180px',
                        width: '100%'
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={securityScansSelectedTypes[scanType.key as keyof typeof securityScansSelectedTypes]}
                        onChange={(e) => setSecurityScansSelectedTypes(prev => ({
                          ...prev,
                          [scanType.key]: e.target.checked
                        }))}
                        style={{
                          marginBottom: '1rem',
                          transform: 'scale(1.3)',
                          accentColor: '#ef4444'
                        }}
                      />
                      <div className="scan-icon" style={{ marginBottom: '1rem' }}>
                        <i className={scanType.icon}></i>
                      </div>
                      <div>
                        <div style={{
                          fontWeight: '600',
                          marginBottom: '0.75rem',
                          fontSize: '1.1rem',
                          color: '#1f2937',
                          lineHeight: '1.3'
                        }}>
                          {scanType.label}
                        </div>
                        <div style={{
                          fontSize: '0.9rem',
                          color: '#6b7280',
                          lineHeight: '1.4',
                          textAlign: 'center'
                        }}>
                          {scanType.description}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="form-actions" style={{ marginTop: '2rem', textAlign: 'center' }}>
                {(() => {
                  const hasSelectedDomain = securityScansSelectedDomain || securityScansCustomDomain;
                  const hasSelectedScans = Object.values(securityScansSelectedTypes).some(v => v);
                  const isDisabled = securityScansLoading || !hasSelectedDomain || !hasSelectedScans;

                  return (
                    <button
                      className={`btn ${isDisabled ? 'btn-disabled' : 'btn-primary'}`}
                      onClick={startUnifiedSecurityScans}
                      disabled={isDisabled}
                      style={{
                        padding: '0.75rem 2rem',
                        fontSize: '1rem',
                        fontWeight: '600',
                        background: isDisabled
                          ? 'linear-gradient(135deg, #d1d5db, #9ca3af)'
                          : 'linear-gradient(135deg, #ef4444, #dc2626)',
                        borderColor: isDisabled ? '#9ca3af' : '#dc2626',
                        color: 'white',
                        cursor: isDisabled ? 'not-allowed' : 'pointer',
                        opacity: isDisabled ? 0.6 : 1,
                        transition: 'all 0.3s ease',
                        boxShadow: isDisabled ? 'none' : '0 4px 15px rgba(239, 68, 68, 0.3)',
                        minWidth: '160px'
                      }}
                    >
                      <i className={`fas ${securityScansLoading ? 'fa-spinner fa-spin' : 'fa-play'}`}
                        style={{ marginRight: '0.5rem' }}></i>
                      {securityScansLoading ? 'Scanning...' : 'Start Scan'}
                    </button>
                  );
                })()}
              </div>
            </div>
          </div>

          {/* Loading State */}
          {securityScansLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <div className="loading-spinner" style={{ marginBottom: '1rem' }}>
                  <i className="fas fa-spinner fa-spin" style={{ fontSize: '3rem', color: 'var(--primary-teal)' }}></i>
                </div>
                <h3>Running Security Scans for {targetDomain}</h3>
                <p>{securityScansStatus}</p>

                {/* Progress Bar */}
                <div style={{ margin: '1.5rem auto', maxWidth: '400px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '0.5rem',
                    fontSize: '0.9rem',
                    color: 'var(--text-secondary)'
                  }}>
                    <span>Progress</span>
                    <span>{Math.round(securityScansProgress)}%</span>
                  </div>
                  <div style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: '#e5e7eb',
                    borderRadius: '4px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${securityScansProgress}%`,
                      height: '100%',
                      backgroundColor: 'var(--coral)',
                      borderRadius: '4px',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Results Display */}
          {Object.keys(securityScansResults).length > 0 && !securityScansLoading && (
            <>

              {/* Action Buttons Section */}
              <div className="widget-card" style={{ marginBottom: '2rem' }}>
                <div className="widget-header">
                  <h3 style={{ margin: 0, color: '#374151' }}>Scan Results For {targetDomain}</h3>
                  <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <button
                      className="btn btn-secondary"
                      onClick={() => {
                        const allCollapsed = Object.values(securityScansCollapsed).every(v => v);
                        const newState = Object.keys(securityScansCollapsed).reduce((acc, key) => {
                          acc[key] = !allCollapsed;
                          return acc;
                        }, {} as { [key: string]: boolean });
                        setSecurityScansCollapsed(newState);
                      }}
                    >
                      <i className={`fas ${Object.values(securityScansCollapsed).every(v => v) ? 'fa-expand-alt' : 'fa-compress-alt'}`}></i>
                      {Object.values(securityScansCollapsed).every(v => v) ? 'Expand All' : 'Collapse All'}
                    </button>
                    <button
                      className="btn btn-primary"
                      onClick={() => {
                        // Clear results and progress
                        setSecurityScansResults({});
                        setSecurityScansProgress(0);
                        setSecurityScansStatus('');

                        // Clear domain selections
                        setSecurityScansSelectedDomain('');
                        setSecurityScansCustomDomain('');

                        // Deselect all scan types
                        setSecurityScansSelectedTypes({
                          subdomain: false,
                          vulnerability: false,
                          reputation: false,
                          network: false,
                          dns: false,
                          encryption: false,
                          email: false
                        });

                        // Reset subdomain table filters
                        setSecuritySubdomainFilter('all');
                        setSecuritySubdomainSearchTerm('');
                      }}
                      style={{
                        padding: '0.5rem 1rem',
                        fontSize: '0.9rem',
                        background: 'linear-gradient(135deg, #ef4444, #dc2626)',
                        borderColor: '#dc2626',
                        color: 'white',
                        boxShadow: '0 2px 8px rgba(239, 68, 68, 0.3)',
                        fontWeight: '600'
                      }}
                    >
                      <i className="fas fa-plus" style={{ marginRight: '0.5rem' }}></i>
                      New Security Scan
                    </button>
                  </div>
                </div>
              </div>

              {/* Individual Scan Results */}
              {Object.entries(securityScansResults).map(([scanType, results]) =>
                renderScanResultsTable(scanType, results)
              )}
            </>
          )}

          {/* No Results State */}
          {Object.keys(securityScansResults).length === 0 && !securityScansLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-shield-alt" style={{ fontSize: '3rem', marginBottom: '1rem', color: 'var(--text-secondary)' }}></i>
                <h3>Security Scans</h3>
                <p>Select a domain and scan types to run comprehensive security scans.</p>
              </div>
            </div>
          )}

          {/* Security Scan Issue Details Modal */}
          {selectedSecurityScanIssue && (
            <div className="modal-overlay" onClick={() => setSelectedSecurityScanIssue(null)}>
              <div className="modal-content security-scans-modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                  <h2>
                    <i className={`fas ${selectedSecurityScanIssue.scanType.toLowerCase() === 'subdomain' ? 'fa-sitemap' :
                        selectedSecurityScanIssue.scanType.toLowerCase() === 'vulnerability' ? 'fa-laptop-code' :
                          selectedSecurityScanIssue.scanType.toLowerCase() === 'reputation' ? 'fa-search' :
                            selectedSecurityScanIssue.scanType.toLowerCase() === 'network' ? 'fa-network-wired' :
                              selectedSecurityScanIssue.scanType.toLowerCase() === 'dns' ? 'fa-globe' :
                                selectedSecurityScanIssue.scanType.toLowerCase() === 'encryption' ? 'fa-lock' :
                                  'fa-envelope'
                      }`} style={{ marginRight: '0.75rem' }}></i>
                    {selectedSecurityScanIssue.scanType} Security Issue
                  </h2>
                  <button className="modal-close" onClick={() => setSelectedSecurityScanIssue(null)}>
                    <i className="fas fa-times"></i>
                  </button>
                </div>
                <div className="modal-body">
                  <div className="vulnerability-details">
                    <div className="vulnerability-info">
                      <h4 style={{ color: '#dc2626', marginBottom: '1rem' }}>Issue Details</h4>
                      <div style={{
                        padding: '1rem',
                        backgroundColor: isDarkMode ? 'rgba(220, 38, 38, 0.1)' : '#fef2f2',
                        borderRadius: '8px',
                        borderLeft: '4px solid #ef4444',
                        marginBottom: '1.5rem'
                      }}>
                        <h5 style={{ margin: '0 0 0.5rem 0', color: isDarkMode ? 'var(--text-primary)' : '#1f2937' }}>{selectedSecurityScanIssue.title}</h5>
                        <p style={{ margin: 0, color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.95rem' }}>
                          Found in {selectedSecurityScanIssue.scanType} Security Scan
                        </p>
                      </div>
                    </div>

                    <div className="affected-domains-section">
                      <h4 style={{ color: '#dc2626', marginBottom: '1rem' }}>
                        Affected Domains ({selectedSecurityScanIssue.vulnerabilities.length})
                      </h4>
                      <div className="affected-domains-list" style={{
                        maxHeight: '400px',
                        overflowY: 'auto',
                        border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
                        borderRadius: '8px'
                      }}>
                        {selectedSecurityScanIssue.vulnerabilities.map((vuln, index) => (
                          <div key={index} className="domain-item" style={{
                            padding: '1rem',
                            borderBottom: index < selectedSecurityScanIssue.vulnerabilities.length - 1 ? `1px solid ${isDarkMode ? 'var(--border-color)' : '#f3f4f6'}` : 'none',
                            backgroundColor: isDarkMode ? 'var(--bg-secondary)' : '#ffffff'
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                <i className="fas fa-globe" style={{ color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', fontSize: '0.9rem' }}></i>
                                <strong style={{ color: isDarkMode ? 'var(--text-primary)' : '#1f2937', fontSize: '1rem' }}>
                                  {vuln.domain || vuln.subdomain || 'Unknown Domain'}
                                </strong>
                              </div>
                              <span className={`severity-badge ${(vuln.severity || 'info').toLowerCase()}`}>
                                {vuln.severity || 'Info'}
                              </span>
                            </div>
                            <div style={{ marginLeft: '1.5rem' }}>
                              <p style={{
                                margin: '0 0 0.5rem 0',
                                color: isDarkMode ? 'var(--text-secondary)' : '#4b5563',
                                fontSize: '0.9rem',
                                lineHeight: '1.5'
                              }}>
                                {vuln.description || vuln.vulnerability || 'No description available'}
                              </p>
                              {vuln.port && (
                                <div style={{ fontSize: '0.85rem', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                                  <i className="fas fa-network-wired" style={{ marginRight: '0.5rem' }}></i>
                                  Port: {vuln.port}
                                  {vuln.service && ` (${vuln.service})`}
                                </div>
                              )}
                              {vuln.issue_type && (
                                <div style={{ fontSize: '0.85rem', color: '#6b7280', marginTop: '0.25rem' }}>
                                  <i className="fas fa-tag" style={{ marginRight: '0.5rem' }}></i>
                                  Type: {vuln.issue_type}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="modal-footer">
                  <button
                    className="btn btn-secondary"
                    onClick={() => setSelectedSecurityScanIssue(null)}
                    style={{
                      background: 'linear-gradient(135deg, #ef4444, #dc2626)',
                      borderColor: '#dc2626',
                      color: 'white'
                    }}
                  >
                    <i className="fas fa-times" style={{ marginRight: '0.5rem' }}></i>
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Placeholder content for other sections

  const renderVulnerabilitiesContent = () => {
    return renderWebsiteScansContent();
  };

  const renderReputationContent = () => {
    // Filter and group reputation issues for display
    const filteredReputationIssues = reputationResults ? (() => {
      const grouped = groupReputationIssuesByType(reputationResults.vulnerabilities || []);

      return grouped.filter(group => {
        const matchesSeverity = reputationFilter === 'all' || group.severity.toLowerCase() === reputationFilter;
        const matchesSearch = !reputationSearchTerm ||
          group.description.toLowerCase().includes(reputationSearchTerm.toLowerCase()) ||
          group.affectedDomains.some(domain => domain.toLowerCase().includes(reputationSearchTerm.toLowerCase()));

        return matchesSeverity && matchesSearch;
      });
    })() : [];

    return (
      <div id="reputation-content" className="content-section active">
        <div className="page-header">
          <h1>Domain Reputation</h1>
        </div>

        <div className="section-content">
          {/* Domain Selection */}
          <div className="widget-card">
            <div className="widget-content">
              <div className="form-group">
                <label htmlFor="reputation-domain-select">Select Domain:</label>
                <SearchableDropdown
                  items={vendors.map(vendor => ({
                    text: `${vendor.name} (${vendor.domain})`,
                    value: vendor.domain
                  }))}
                  placeholder="Choose a vendor domain..."
                  onChange={(item) => handleDropdownChange(item, setReputationSelectedDomain, setReputationCustomDomain)}
                  value={reputationSelectedDomain}
                />
              </div>

              <div className="form-group">
                <label htmlFor="reputation-custom-domain">Custom Domain:</label>
                <input
                  type="text"
                  id="reputation-custom-domain"
                  placeholder="Enter domain (e.g., example.com)"
                  value={reputationCustomDomain}
                  onChange={(e) => {
                    setReputationCustomDomain(e.target.value);
                    setReputationSelectedDomain('');
                  }}
                  className="form-control"
                />
              </div>

              <div className="form-actions">
                <button
                  onClick={startDomainReputationScan}
                  disabled={reputationLoading}
                  className="btn btn-primary"
                >
                  <i className="fas fa-search"></i>
                  {reputationLoading ? 'Scanning...' : 'Start Reputation Scan'}
                </button>

                {reputationResults && !reputationLoading && (
                  <button
                    onClick={startNewReputationScan}
                    className="btn btn-secondary"
                    style={{ marginLeft: '1rem' }}
                  >
                    <i className="fas fa-plus"></i> New Reputation Scan
                  </button>
                )}

                {reputationLoading && (
                  <button
                    onClick={() => setReputationLoading(false)}
                    className="btn btn-secondary"
                    style={{ marginLeft: '1rem' }}
                  >
                    <i className="fas fa-times"></i> Cancel
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Loading State */}
          {reputationLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)', marginBottom: '1rem' }}></i>
                <h3>Scanning domain reputation for {reputationSelectedDomain || reputationCustomDomain}</h3>
                <p>Checking reputation databases and blacklists...</p>

                {/* Progress Bar */}
                <div style={{ margin: '1.5rem auto', maxWidth: '400px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '0.5rem',
                    fontSize: '0.9rem',
                    color: 'var(--text-secondary)'
                  }}>
                    <span>Progress</span>
                    <span>{Math.round(reputationProgress)}%</span>
                  </div>
                  <div style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: '#e5e7eb',
                    borderRadius: '4px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${reputationProgress}%`,
                      height: '100%',
                      backgroundColor: 'var(--coral)',
                      borderRadius: '4px',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                </div>

                <p><small>This may take a few minutes to check all reputation sources</small></p>
              </div>
            </div>
          )}

          {/* Results Display */}
          {reputationResults && !reputationLoading && (
            <>
              {/* Score Cards */}
              <div className="vulnerability-summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
                {/* Reputation Score */}
                <div className={`widget-card ${reputationResults.final_score >= 800 ? 'score-excellent' :
                    reputationResults.final_score >= 600 ? 'score-good' :
                      reputationResults.final_score >= 400 ? 'score-fair' : 'score-poor'
                  }`}>
                  <div className="widget-content" style={{ textAlign: 'center' }}>
                    <h3 style={{ marginBottom: '1rem' }}>Domain Reputation Score</h3>
                    <div className="score-display">
                      <div className="score-circle">
                        <span className="score-value">{reputationResults.final_score}</span>
                        <span className="score-max">/{reputationResults.max_score}</span>
                      </div>
                    </div>
                    <div className="score-details" style={{ marginTop: '1rem' }}>
                      <div className="score-item">
                        <span>Percentage: </span>
                        <span style={{ color: 'var(--success-green)', fontWeight: 'bold' }}>
                          {reputationResults.summary.score_breakdown.percentage}%
                        </span>
                      </div>
                      <div className="score-item">
                        <span>Domain Analyzed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{reputationResults.domain}</span>
                      </div>
                      <div className="score-item">
                        <span>Total Issues: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{reputationResults.summary.total_issues}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Issue Summary */}
                <div className="widget-card">
                  <div className="widget-header">
                    <h3>Reputation Issues</h3>
                  </div>
                  <div className="widget-content">
                    <div className="severity-grid">
                      <div className="severity-item critical">
                        <span className="severity-label">Critical</span>
                        <span className="severity-count">
                          {reputationResults.vulnerabilities?.filter((v: any) => v.severity === 'Critical').length || 0}
                        </span>
                      </div>
                      <div className="severity-item high">
                        <span className="severity-label">High</span>
                        <span className="severity-count">
                          {reputationResults.vulnerabilities?.filter((v: any) => v.severity === 'High').length || 0}
                        </span>
                      </div>
                      <div className="severity-item medium">
                        <span className="severity-label">Medium</span>
                        <span className="severity-count">
                          {reputationResults.vulnerabilities?.filter((v: any) => v.severity === 'Medium').length || 0}
                        </span>
                      </div>
                      <div className="severity-item low">
                        <span className="severity-label">Low</span>
                        <span className="severity-count">
                          {reputationResults.vulnerabilities?.filter((v: any) => v.severity === 'Low').length || 0}
                        </span>
                      </div>
                      <div className="severity-item info">
                        <span className="severity-label">Info</span>
                        <span className="severity-count">
                          {reputationResults.vulnerabilities?.filter((v: any) => v.severity === 'Info').length || 0}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Discovered Issues Table */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Discovered Reputation Issues</h3>
                  <div className="widget-controls" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <select
                      value={reputationFilter}
                      onChange={(e) => setReputationFilter(e.target.value)}
                      className="form-control"
                      style={{ minWidth: '150px' }}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                    <div style={{ position: 'relative', minWidth: '250px' }}>
                      <input
                        type="text"
                        placeholder="Search issues..."
                        value={reputationSearchTerm}
                        onChange={(e) => setReputationSearchTerm(e.target.value)}
                        className="form-control"
                        style={{ paddingRight: '2.5rem' }}
                      />
                      {reputationSearchTerm && (
                        <button
                          onClick={() => setReputationSearchTerm('')}
                          style={{
                            position: 'absolute',
                            right: '0.5rem',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                    <button
                      onClick={downloadReputationReport}
                      className="btn btn-secondary"
                      title="Download Reputation Report"
                    >
                      <i className="fas fa-download"></i>
                    </button>
                  </div>
                </div>
                <div className="widget-content">
                  {filteredReputationIssues.length > 0 ? (
                    <div className="vulnerability-table-container">
                      <table className="vulnerability-table">
                        <thead>
                          <tr>
                            <th>AFFECTED DOMAIN</th>
                            <th>ISSUE TYPE</th>
                            <th>SEVERITY</th>
                            <th>DESCRIPTION</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredReputationIssues.map((group, index) => (
                            <tr
                              key={index}
                              className="vulnerability-group-row"
                              onClick={() => openReputationModal(group.description, group.vulnerabilities)}
                              style={{ cursor: 'pointer' }}
                              title="Click to view affected domains"
                            >
                              <td>
                                <div className="vulnerability-group-header">
                                  <i className="fas fa-eye vulnerability-view-icon"></i>
                                  <span className="affected-count">
                                    {group.affectedDomains.length} affected domain{group.affectedDomains.length > 1 ? 's' : ''}
                                  </span>
                                </div>
                              </td>
                              <td className="vulnerability-desc vulnerability-title">
                                {group.issue_type}
                              </td>
                              <td>
                                <span className={`severity-badge ${group.severity.toLowerCase()}`}>
                                  {group.severity}
                                </span>
                              </td>
                              <td>
                                <span className="vulnerability-description">{group.description}</span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                      {reputationSearchTerm || reputationFilter !== 'all'
                        ? 'No reputation issues match your search criteria'
                        : 'No reputation issues found'
                      }
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {/* No Results State */}
          {!reputationResults && !reputationLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-search" style={{ fontSize: '3rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}></i>
                <h3>No Scan Results</h3>
                <p>Select a domain and start a reputation scan to view results</p>
              </div>
            </div>
          )}

          {/* Reputation Details Modal */}
          {selectedReputationIssue && (
            <div className="modal-overlay" onClick={closeReputationModal}>
              <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                  <h3>{selectedReputationIssue.title}</h3>
                  <button onClick={closeReputationModal} className="modal-close">
                    <i className="fas fa-times"></i>
                  </button>
                </div>
                <div className="modal-body">
                  <h4>Affected Domains ({selectedReputationIssue.vulnerabilities.length})</h4>
                  <div className="affected-subdomains-list">
                    {selectedReputationIssue.vulnerabilities.map((issue, index) => (
                      <div key={index} className="subdomain-item">
                        <div className="subdomain-info">
                          <strong>{issue.domain || issue.subdomain}</strong>
                          <span className={`severity-badge ${issue.severity.toLowerCase()}`}>
                            {issue.severity}
                          </span>
                        </div>
                        <p className="vulnerability-description">{issue.description}</p>
                        {issue.issue_type && (
                          <code className="vuln-id">{issue.issue_type}</code>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="modal-footer">
                  <button onClick={closeReputationModal} className="btn btn-primary">
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderNetworkContent = () => {
    // Filter and search grouped vulnerabilities
    const filteredNetworkGroups = networkResults ?
      groupNetworkIssuesByType(networkResults.vulnerabilities || []).filter(group => {
        const matchesSearch = networkSearchTerm === '' ||
          group.description.toLowerCase().includes(networkSearchTerm.toLowerCase()) ||
          group.service.toLowerCase().includes(networkSearchTerm.toLowerCase()) ||
          group.port.toLowerCase().includes(networkSearchTerm.toLowerCase());

        const matchesFilter = networkFilter === 'all' ||
          group.severity.toLowerCase() === networkFilter.toLowerCase();

        return matchesSearch && matchesFilter;
      }) : [];

    return (
      <div id="network-content" className="content-section active">
        <div className="page-header">
          <h1>Network Port Scans</h1>
        </div>

        <div className="section-content">
          {/* Scanner Controls */}
          <div className="widget-card">
            <div className="widget-content">
              <div className="form-group">
                <label htmlFor="network-domain-select">Select Domain:</label>
                <SearchableDropdown
                  items={vendors.map(vendor => ({
                    text: `${vendor.name} (${vendor.domain})`,
                    value: vendor.domain
                  }))}
                  value={networkSelectedDomain}
                  onChange={(item) => handleDropdownChange(item, setNetworkSelectedDomain, setNetworkCustomDomain)}
                  placeholder="Search vendors..."
                />
              </div>

              <div className="form-group">
                <label htmlFor="network-custom-domain">Custom Domain:</label>
                <input
                  type="text"
                  id="network-custom-domain"
                  placeholder="Enter domain (e.g., example.com)"
                  value={networkCustomDomain}
                  onChange={(e) => {
                    setNetworkCustomDomain(e.target.value);
                    setNetworkSelectedDomain('');
                  }}
                  className="form-control"
                />
              </div>

              <div className="form-actions">
                <button
                  className="btn btn-primary"
                  onClick={startNetworkScan}
                  disabled={networkLoading || (!networkSelectedDomain && !networkCustomDomain)}
                >
                  <i className="fas fa-search"></i>
                  {networkLoading ? 'Scanning...' : 'Start Network Scan'}
                </button>

                {networkResults && (
                  <button
                    className="btn btn-secondary"
                    onClick={startNewNetworkScan}
                  >
                    <i className="fas fa-plus"></i>
                    New Network Scan
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Loading State */}
          {networkLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <div className="loading-spinner" style={{ marginBottom: '1rem' }}>
                  <i className="fas fa-spinner fa-spin" style={{ fontSize: '3rem', color: 'var(--primary-teal)' }}></i>
                </div>
                <h3>Scanning network ports for {networkSelectedDomain || networkCustomDomain}</h3>
                <p>Discovering open ports and services...</p>

                {/* Progress Bar */}
                <div style={{ margin: '1.5rem auto', maxWidth: '400px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '0.5rem',
                    fontSize: '0.9rem',
                    color: 'var(--text-secondary)'
                  }}>
                    <span>Progress</span>
                    <span>{Math.round(networkProgress)}%</span>
                  </div>
                  <div style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: '#e5e7eb',
                    borderRadius: '4px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${networkProgress}%`,
                      height: '100%',
                      backgroundColor: 'var(--coral)',
                      borderRadius: '4px',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                </div>

                {/* Stop Scan Button */}
                {networkScanId && (
                  <button
                    className="btn btn-secondary"
                    onClick={async () => {
                      if (networkScanId) {
                        try {
                          await scanApi.stopNetworkScan(networkScanId);
                          setNetworkLoading(false);
                          setNetworkProgress(0);
                          setNetworkScanId(null);
                          showNotification('info', 'Scan Stopped', 'Network scan has been stopped');
                        } catch (error) {
                          console.error('Error stopping scan:', error);
                          showNotification('error', 'Error', 'Failed to stop scan');
                        }
                      }
                    }}
                    style={{ marginTop: '1rem' }}
                  >
                    <i className="fas fa-stop"></i>
                    Stop Scan
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Results Display */}
          {networkResults && !networkLoading && (
            <>
              {/* Score Cards */}
              <div className="vulnerability-summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
                {/* Network Scan Score */}
                <div className={`widget-card ${networkResults.final_score >= 800 ? 'score-excellent' :
                    networkResults.final_score >= 600 ? 'score-good' :
                      networkResults.final_score >= 400 ? 'score-fair' : 'score-poor'
                  }`}>
                  <div className="widget-content" style={{ textAlign: 'center' }}>
                    <h3 style={{ marginBottom: '1rem' }}>Network Security Score</h3>
                    <div className="score-display">
                      <div className="score-circle">
                        <span className="score-value">{networkResults.final_score}</span>
                        <span className="score-max">/{networkResults.max_score}</span>
                      </div>
                    </div>
                    <div className="score-details" style={{ marginTop: '1rem' }}>
                      <div className="score-item">
                        <span>Percentage: </span>
                        <span style={{ color: 'var(--success-green)', fontWeight: 'bold' }}>
                          {networkResults.summary.score_breakdown.percentage}%
                        </span>
                      </div>
                      <div className="score-item">
                        <span>Domain Analyzed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{networkResults.domain}</span>
                      </div>
                      <div className="score-item">
                        <span>Subdomains Processed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{networkResults.processed_subdomains}</span>
                      </div>
                      <div className="score-item">
                        <span>Total Issues: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{networkResults.summary.total_issues}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Vulnerability Breakdown */}
                <div className="widget-card">
                  <div className="widget-header">
                    <h3>Network Issues Summary</h3>
                  </div>
                  <div className="widget-content">
                    <div className="severity-grid">
                      <div className="severity-item critical">
                        <span className="severity-label">Critical</span>
                        <span className="severity-count">{networkResults.summary.by_severity.CRITICAL || 0}</span>
                      </div>
                      <div className="severity-item high">
                        <span className="severity-label">High</span>
                        <span className="severity-count">{networkResults.summary.by_severity.HIGH || 0}</span>
                      </div>
                      <div className="severity-item medium">
                        <span className="severity-label">Medium</span>
                        <span className="severity-count">{networkResults.summary.by_severity.MEDIUM || 0}</span>
                      </div>
                      <div className="severity-item low">
                        <span className="severity-label">Low</span>
                        <span className="severity-count">{networkResults.summary.by_severity.LOW || 0}</span>
                      </div>
                      <div className="severity-item info">
                        <span className="severity-label">Info</span>
                        <span className="severity-count">{networkResults.summary.by_severity.INFO || 0}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Discovered Network Issues Table */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Discovered Network Issues</h3>
                  <div className="widget-controls" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <select
                      value={networkFilter}
                      onChange={(e) => setNetworkFilter(e.target.value)}
                      className="form-control"
                      style={{ minWidth: '150px' }}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                    <div style={{ position: 'relative', minWidth: '250px' }}>
                      <input
                        type="text"
                        placeholder="Search network issues..."
                        value={networkSearchTerm}
                        onChange={(e) => setNetworkSearchTerm(e.target.value)}
                        className="form-control"
                        style={{ paddingRight: '2.5rem' }}
                      />
                      {networkSearchTerm && (
                        <button
                          onClick={() => setNetworkSearchTerm('')}
                          style={{
                            position: 'absolute',
                            right: '0.5rem',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                    <button
                      onClick={downloadNetworkReport}
                      className="btn btn-secondary"
                      title="Download Network Report"
                    >
                      <i className="fas fa-download"></i>
                    </button>
                  </div>
                </div>
                <div className="widget-content">

                  {/* Issues Table */}
                  {filteredNetworkGroups.length > 0 ? (
                    <div className="vulnerability-table-container">
                      <table className="vulnerability-table">
                        <thead>
                          <tr>
                            <th>AFFECTED SUBDOMAIN</th>
                            <th>SERVICE & PORT</th>
                            <th>SEVERITY</th>
                            <th>DESCRIPTION</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredNetworkGroups.map((group, index) => (
                            <tr
                              key={index}
                              className="vulnerability-group-row"
                              onClick={() => openNetworkModal(group.description, group.vulnerabilities)}
                              style={{ cursor: 'pointer' }}
                              title="Click to view affected subdomains"
                            >
                              <td>
                                <div className="vulnerability-group-header">
                                  <i className="fas fa-eye vulnerability-view-icon"></i>
                                  <span className="affected-count">
                                    {group.affectedDomains.length} affected subdomain{group.affectedDomains.length > 1 ? 's' : ''}
                                  </span>
                                </div>
                              </td>
                              <td>
                                <div className="vulnerability-info">
                                  <strong>{group.service}</strong>
                                  <div className="vulnerability-meta">Port {group.port}</div>
                                </div>
                              </td>
                              <td>
                                <span className={`severity-badge ${group.severity.toLowerCase()}`}>
                                  {group.severity}
                                </span>
                              </td>
                              <td>
                                <div className="vulnerability-description">
                                  {group.description}
                                  <div className="vulnerability-count">
                                    {group.vulnerabilities.length} issue{group.vulnerabilities.length > 1 ? 's' : ''}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="no-vulnerabilities-found">
                      <div className="empty-state">
                        <i className="fas fa-shield-alt" style={{ fontSize: '3rem', color: 'var(--success-green)', marginBottom: '1rem' }}></i>
                        <h3>No Network Issues Found</h3>
                        <p>
                          {networkSearchTerm || networkFilter !== 'all'
                            ? 'No issues match your current search and filter criteria.'
                            : 'No network security issues were discovered during the scan.'}
                        </p>
                        {(networkSearchTerm || networkFilter !== 'all') && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => {
                              setNetworkSearchTerm('');
                              setNetworkFilter('all');
                            }}
                          >
                            Clear Filters
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {/* Network Details Modal */}
          {selectedNetworkIssue && (
            <div className="modal-overlay" onClick={closeNetworkModal}>
              <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                  <h3>Network Issue Details</h3>
                  <button className="modal-close" onClick={closeNetworkModal}>
                    <i className="fas fa-times"></i>
                  </button>
                </div>
                <div className="modal-body">
                  <h4>{selectedNetworkIssue.title}</h4>
                  <div className="affected-subdomains-list">
                    <h5>Affected Subdomains ({selectedNetworkIssue.vulnerabilities.length})</h5>
                    {selectedNetworkIssue.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="subdomain-item">
                        <div className="subdomain-info">
                          <strong>{vuln.subdomain || vuln.domain}</strong>
                          <span className={`severity-badge ${vuln.severity.toLowerCase()}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <div className="vulnerability-description">
                          <strong>Service:</strong> {vuln.service} (Port {vuln.port})<br />
                          <strong>Description:</strong> {vuln.description}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="modal-footer">
                  <button className="btn btn-secondary" onClick={closeNetworkModal}>
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderDnsContent = () => {
    return (
      <div id="dns-content" className="content-section active">
        <div className="page-header">
          <h1>DNS Security Check</h1>
        </div>

        <div className="section-content">
          {/* Domain Selection */}
          <div className="widget-card">
            <div className="widget-content">
              <div className="form-group">
                <label>Select Domain:</label>
                <SearchableDropdown
                  items={vendors.map(vendor => ({
                    value: vendor.domain,
                    text: `${vendor.name} (${vendor.domain})`
                  }))}
                  value={dnsSelectedDomain}
                  onChange={(item) => handleDropdownChange(item, setDnsSelectedDomain, setDnsCustomDomain)}
                  placeholder="Search vendors..."
                />
              </div>

              <div className="form-group">
                <label>Enter custom domain:</label>
                <input
                  type="text"
                  value={dnsCustomDomain}
                  onChange={(e) => {
                    setDnsCustomDomain(e.target.value);
                    setDnsSelectedDomain('');
                  }}
                  placeholder="example.com"
                  className="form-control"
                />
              </div>

              <div className="form-actions">
                <button
                  onClick={startDnsSecurityScan}
                  disabled={dnsLoading}
                  className="btn btn-primary"
                >
                  <i className="fas fa-globe"></i>
                  {dnsLoading ? 'Scanning...' : 'Start DNS Scan'}
                </button>

                {dnsResults && !dnsLoading && (
                  <button
                    onClick={startNewDnsSecurityScan}
                    className="btn btn-secondary"
                  >
                    <i className="fas fa-plus"></i>
                    New DNS Scan
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Loading State */}
          {dnsLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)', marginBottom: '1rem' }}></i>
                <h3>Scanning DNS security for {dnsSelectedDomain || dnsCustomDomain}</h3>
                <p>Checking DNS records and configuration...</p>

                {/* Progress Bar */}
                <div style={{ margin: '1.5rem auto', maxWidth: '400px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '0.5rem',
                    fontSize: '0.9rem',
                    color: 'var(--text-secondary)'
                  }}>
                    <span>Progress</span>
                    <span>{Math.round(dnsProgress)}%</span>
                  </div>
                  <div style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: '#e5e7eb',
                    borderRadius: '4px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${dnsProgress}%`,
                      height: '100%',
                      backgroundColor: 'var(--coral)',
                      borderRadius: '4px',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                </div>

                <p><small>This may take a few minutes depending on DNS configuration</small></p>
              </div>
            </div>
          )}

          {/* Results */}
          {dnsResults && !dnsLoading && (
            <>
              {/* Score Cards */}
              <div className="vulnerability-summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
                {/* DNS Security Score */}
                <div className={`widget-card ${dnsResults.final_score >= 800 ? 'score-excellent' :
                    dnsResults.final_score >= 600 ? 'score-good' :
                      dnsResults.final_score >= 400 ? 'score-fair' : 'score-poor'
                  }`}>
                  <div className="widget-content" style={{ textAlign: 'center' }}>
                    <h3 style={{ marginBottom: '1rem' }}>DNS Security Score</h3>
                    <div className="score-display">
                      <div className="score-circle">
                        <span className="score-value">{dnsResults.final_score}</span>
                        <span className="score-max">/{dnsResults.max_score}</span>
                      </div>
                    </div>
                    <div className="score-details" style={{ marginTop: '1rem' }}>
                      <div className="score-item">
                        <span>Percentage: </span>
                        <span style={{ color: 'var(--success-green)', fontWeight: 'bold' }}>
                          {dnsResults.summary.score_breakdown.percentage}%
                        </span>
                      </div>
                      <div className="score-item">
                        <span>Domain Analyzed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{dnsResults.domain}</span>
                      </div>
                      <div className="score-item">
                        <span>Subdomains Processed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{dnsResults.statistics.subdomains_processed}</span>
                      </div>
                      <div className="score-item">
                        <span>Total Issues: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{dnsResults.summary.total_issues}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* DNS Issue Breakdown */}
                <div className="widget-card">
                  <div className="widget-header">
                    <h3>DNS Issue Breakdown</h3>
                  </div>
                  <div className="widget-content">
                    <div className="severity-grid">
                      <div className="severity-item critical">
                        <span className="severity-label">Critical</span>
                        <span className="severity-count">{dnsResults.summary.by_severity.CRITICAL || 0}</span>
                      </div>
                      <div className="severity-item high">
                        <span className="severity-label">High</span>
                        <span className="severity-count">{dnsResults.summary.by_severity.HIGH || 0}</span>
                      </div>
                      <div className="severity-item medium">
                        <span className="severity-label">Medium</span>
                        <span className="severity-count">{dnsResults.summary.by_severity.MEDIUM || 0}</span>
                      </div>
                      <div className="severity-item low">
                        <span className="severity-label">Low</span>
                        <span className="severity-count">{dnsResults.summary.by_severity.LOW || 0}</span>
                      </div>
                      <div className="severity-item info">
                        <span className="severity-label">Info</span>
                        <span className="severity-count">{dnsResults.summary.by_severity.INFO || 0}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Discovered DNS Issues Table */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Discovered DNS Issues</h3>
                  <div className="widget-controls" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <select
                      value={dnsFilter}
                      onChange={(e) => setDnsFilter(e.target.value)}
                      className="form-control"
                      style={{ minWidth: '150px' }}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                    <div style={{ position: 'relative', minWidth: '250px' }}>
                      <input
                        type="text"
                        placeholder="Search DNS issues..."
                        value={dnsSearchTerm}
                        onChange={(e) => setDnsSearchTerm(e.target.value)}
                        className="form-control"
                        style={{ paddingRight: '2.5rem' }}
                      />
                      {dnsSearchTerm && (
                        <button
                          onClick={() => setDnsSearchTerm('')}
                          style={{
                            position: 'absolute',
                            right: '0.5rem',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                    <button
                      onClick={downloadDnsReport}
                      className="btn btn-secondary"
                      title="Download DNS Report"
                    >
                      <i className="fas fa-download"></i>
                    </button>
                  </div>
                </div>
                <div className="widget-content">
                  {/* Issues Table */}
                  <div className="vulnerability-table-container">
                    {dnsResults.vulnerabilities && dnsResults.vulnerabilities.length > 0 ? (
                      <table className="vulnerability-table">
                        <thead>
                          <tr>
                            <th>AFFECTED SUBDOMAIN</th>
                            <th>ISSUE TYPE</th>
                            <th>SEVERITY</th>
                            <th>DESCRIPTION</th>
                          </tr>
                        </thead>
                        <tbody>
                          {groupDnsIssuesByType(dnsResults.vulnerabilities || []).filter(group => {
                            const matchesFilter = dnsFilter === 'all' || group.severity.toLowerCase() === dnsFilter.toLowerCase();
                            const matchesSearch = dnsSearchTerm === '' ||
                              group.description.toLowerCase().includes(dnsSearchTerm.toLowerCase()) ||
                              group.affectedDomains.some((domain: string) => domain.toLowerCase().includes(dnsSearchTerm.toLowerCase()));
                            return matchesFilter && matchesSearch;
                          }).map((group, index) => (
                            <tr
                              key={index}
                              className="vulnerability-group-row"
                              onClick={() => openDnsModal(group.description, group.vulnerabilities)}
                            >
                              <td>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                  <i className="fas fa-eye vulnerability-view-icon"></i>
                                  <span>{group.affectedDomains[0]}</span>
                                  {group.affectedDomains.length > 1 && (
                                    <span className="affected-count">+{group.affectedDomains.length - 1}</span>
                                  )}
                                </div>
                              </td>
                              <td>{group.title}</td>
                              <td>
                                <span className={`severity-badge ${group.severity.toLowerCase()}`}>
                                  {group.severity}
                                </span>
                              </td>
                              <td>
                                {group.description}
                                {group.vulnerabilities.length > 1 && ` (${group.vulnerabilities.length} issues)`}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div style={{
                        textAlign: 'center',
                        padding: '3rem',
                        color: 'var(--text-secondary)'
                      }}>
                        <i className="fas fa-shield-alt" style={{
                          fontSize: '3rem',
                          marginBottom: '1rem',
                          color: 'var(--success-green)'
                        }}></i>
                        <h3>No DNS Issues Found</h3>
                        <p>
                          {dnsFilter === 'all' && dnsSearchTerm === ''
                            ? 'Great! No DNS security issues were detected for this domain.'
                            : 'No DNS issues match your current filter or search criteria.'
                          }
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </>
          )}

          {/* No Results State */}
          {!dnsResults && !dnsLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-globe" style={{ fontSize: '3rem', marginBottom: '1rem', color: 'var(--text-secondary)' }}></i>
                <h3>DNS Security Check</h3>
                <p>Select a domain and start a DNS security scan to view results</p>
              </div>
            </div>
          )}

          {/* DNS Issue Details Modal */}
          {selectedDnsIssue && (
            <div className="modal-overlay" onClick={closeDnsModal}>
              <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                  <h3>DNS Issue Details</h3>
                  <button className="modal-close" onClick={closeDnsModal}>×</button>
                </div>
                <div className="modal-body">
                  <h4>Affected Domains ({selectedDnsIssue.vulnerabilities.length})</h4>
                  <div className="affected-subdomains-list">
                    {selectedDnsIssue.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="subdomain-item">
                        <div className="subdomain-info">
                          <strong>{vuln.domain || vuln.subdomain}</strong>
                          <span className={`severity-badge ${vuln.severity.toLowerCase()}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <div className="vulnerability-description">
                          {vuln.description}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="modal-footer">
                  <button className="btn btn-secondary" onClick={closeDnsModal}>
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderEncryptionContent = () => {
    return (
      <div id="encryption-content" className="content-section active">
        <div className="page-header">
          <h1>SSL/TLS Encryption Checks</h1>
        </div>

        <div className="section-content">
          {/* Domain Selection */}
          <div className="widget-card">
            <div className="widget-content">
              <div className="form-group">
                <label>Select Domain:</label>
                <SearchableDropdown
                  items={vendors.map(vendor => ({
                    value: vendor.domain,
                    text: `${vendor.name} (${vendor.domain})`
                  }))}
                  value={encryptionSelectedDomain}
                  onChange={(item) => handleDropdownChange(item, setEncryptionSelectedDomain, setEncryptionCustomDomain)}
                  placeholder="Search vendors..."
                />
              </div>

              <div className="form-group">
                <label>Enter custom domain:</label>
                <input
                  type="text"
                  value={encryptionCustomDomain}
                  onChange={(e) => {
                    setEncryptionCustomDomain(e.target.value);
                    setEncryptionSelectedDomain('');
                  }}
                  placeholder="example.com"
                  className="form-control"
                />
              </div>

              <div className="form-actions">
                <button
                  onClick={startEncryptionScan}
                  disabled={encryptionLoading}
                  className="btn btn-primary"
                >
                  <i className="fas fa-lock"></i>
                  {encryptionLoading ? 'Scanning...' : 'Start SSL/TLS Scan'}
                </button>

                {encryptionResults && !encryptionLoading && (
                  <button
                    onClick={startNewEncryptionScan}
                    className="btn btn-secondary"
                  >
                    <i className="fas fa-plus"></i>
                    New SSL/TLS Scan
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Loading State */}
          {encryptionLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)', marginBottom: '1rem' }}></i>
                <h3>Scanning SSL/TLS security for {encryptionSelectedDomain || encryptionCustomDomain}</h3>
                <p>Analyzing encryption configuration and vulnerabilities...</p>

                {/* Progress Bar */}
                <div style={{ margin: '1.5rem auto', maxWidth: '400px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '0.5rem',
                    fontSize: '0.9rem',
                    color: 'var(--text-secondary)'
                  }}>
                    <span>Progress</span>
                    <span>{Math.round(encryptionProgress)}%</span>
                  </div>
                  <div style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: '#e5e7eb',
                    borderRadius: '4px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${encryptionProgress}%`,
                      height: '100%',
                      backgroundColor: 'var(--coral)',
                      borderRadius: '4px',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                </div>

                {/* Stop Button */}
                {encryptionScanId && (
                  <button
                    onClick={stopEncryptionScan}
                    className="btn btn-secondary"
                    style={{ marginTop: '1rem' }}
                  >
                    <i className="fas fa-stop"></i>
                    Stop Scan
                  </button>
                )}
              </div>
            </div>
          )}

          {encryptionResults && !encryptionLoading && (
            <>
              <div className="vulnerability-summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
                {/* SSL/TLS Security Score */}
                <div className={`widget-card ${encryptionResults.final_score >= 800 ? 'score-excellent' :
                    encryptionResults.final_score >= 600 ? 'score-good' :
                      encryptionResults.final_score >= 400 ? 'score-fair' : 'score-poor'
                  }`}>
                  <div className="widget-content" style={{ textAlign: 'center' }}>
                    <h3 style={{ marginBottom: '1rem' }}>SSL/TLS Security Score</h3>
                    <div className="score-display">
                      <div className="score-circle">
                        <span className="score-value">{encryptionResults.final_score}</span>
                        <span className="score-max">/{encryptionResults.max_score}</span>
                      </div>
                    </div>
                    <div className="score-details" style={{ marginTop: '1rem' }}>
                      <div className="score-item">
                        <span>Percentage: </span>
                        <span style={{ color: 'var(--success-green)', fontWeight: 'bold' }}>
                          {encryptionResults.summary.score_breakdown.percentage}%
                        </span>
                      </div>
                      <div className="score-item">
                        <span>Domain Analyzed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{encryptionResults.domain}</span>
                      </div>
                      <div className="score-item">
                        <span>Subdomains Processed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{encryptionResults.subdomains_processed}</span>
                      </div>
                      <div className="score-item">
                        <span>Total Vulnerabilities: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{encryptionResults.summary.total_vulnerabilities}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* SSL/TLS Issue Breakdown */}
                <div className="widget-card">
                  <div className="widget-header">
                    <h3>SSL/TLS Issue Breakdown</h3>
                  </div>
                  <div className="widget-content">
                    <div className="severity-grid">
                      <div className="severity-item critical">
                        <span className="severity-label">Critical</span>
                        <span className="severity-count">{encryptionResults.summary.by_severity.CRITICAL || 0}</span>
                      </div>
                      <div className="severity-item high">
                        <span className="severity-label">High</span>
                        <span className="severity-count">{encryptionResults.summary.by_severity.HIGH || 0}</span>
                      </div>
                      <div className="severity-item medium">
                        <span className="severity-label">Medium</span>
                        <span className="severity-count">{encryptionResults.summary.by_severity.MEDIUM || 0}</span>
                      </div>
                      <div className="severity-item low">
                        <span className="severity-label">Low</span>
                        <span className="severity-count">{encryptionResults.summary.by_severity.LOW || 0}</span>
                      </div>
                      <div className="severity-item info">
                        <span className="severity-label">Info</span>
                        <span className="severity-count">{encryptionResults.summary.by_severity.INFO || 0}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Discovered SSL/TLS Issues */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Discovered SSL/TLS Issues</h3>
                  <div className="widget-controls" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <select
                      value={encryptionFilter}
                      onChange={(e) => setEncryptionFilter(e.target.value)}
                      className="form-control"
                      style={{ minWidth: '150px' }}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                    <div style={{ position: 'relative', minWidth: '250px' }}>
                      <input
                        type="text"
                        placeholder="Search SSL/TLS issues..."
                        value={encryptionSearchTerm}
                        onChange={(e) => setEncryptionSearchTerm(e.target.value)}
                        className="form-control"
                        style={{ paddingRight: '2.5rem' }}
                      />
                      {encryptionSearchTerm && (
                        <button
                          onClick={() => setEncryptionSearchTerm('')}
                          style={{
                            position: 'absolute',
                            right: '0.5rem',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                    <button
                      onClick={downloadEncryptionReport}
                      className="btn btn-secondary"
                      title="Download SSL/TLS Report"
                    >
                      <i className="fas fa-download"></i>
                    </button>
                  </div>
                </div>
                <div className="widget-content">
                  {(() => {
                    const grouped = groupEncryptionIssuesByType(encryptionResults.vulnerabilities || []);
                    const filtered = grouped.filter(group => {
                      const matchesFilter = encryptionFilter === 'all' || group.severity.toLowerCase() === encryptionFilter.toLowerCase();
                      const matchesSearch = encryptionSearchTerm === '' ||
                        group.description.toLowerCase().includes(encryptionSearchTerm.toLowerCase()) ||
                        group.affectedDomains.some((domain: string) => domain.toLowerCase().includes(encryptionSearchTerm.toLowerCase()));
                      return matchesFilter && matchesSearch;
                    });

                    return filtered.length > 0 ? (
                      <div className="vulnerability-table-container">
                        <table className="vulnerability-table">
                          <thead>
                            <tr>
                              <th>AFFECTED SUBDOMAIN</th>
                              <th>VULNERABILITY</th>
                              <th>SEVERITY</th>
                              <th>CATEGORY</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filtered.map((group, index) => (
                              <tr
                                key={index}
                                className="vulnerability-group-row"
                                onClick={() => openEncryptionModal(group.description, group.vulnerabilities)}
                                style={{ cursor: 'pointer' }}
                                title="Click to view affected subdomains"
                              >
                                <td>
                                  <div className="vulnerability-group-header">
                                    <i className="fas fa-eye vulnerability-view-icon"></i>
                                    <span className="affected-count">
                                      {group.affectedDomains.length} affected domain{group.affectedDomains.length > 1 ? 's' : ''}
                                    </span>
                                  </div>
                                </td>
                                <td>{group.title}</td>
                                <td>
                                  <span className={`severity-badge ${group.severity.toLowerCase()}`}>
                                    {group.severity}
                                  </span>
                                </td>
                                <td>Encryption</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div style={{
                        textAlign: 'center',
                        padding: '3rem',
                        color: 'var(--text-secondary)'
                      }}>
                        <i className="fas fa-shield-alt" style={{ fontSize: '3rem', marginBottom: '1rem', opacity: 0.5 }}></i>
                        <h3>No SSL/TLS Issues Found</h3>
                        <p>
                          {encryptionFilter !== 'all' || encryptionSearchTerm
                            ? 'No issues match your current search criteria.'
                            : 'Great! Your SSL/TLS configuration appears to be secure.'}
                        </p>
                      </div>
                    );
                  })()}
                </div>
              </div>
            </>
          )}

          {/* SSL/TLS Issue Details Modal */}
          {selectedEncryptionIssue && (
            <div className="modal-overlay" onClick={closeEncryptionModal}>
              <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                  <h3>SSL/TLS Issue Details</h3>
                  <button className="modal-close" onClick={closeEncryptionModal}>
                    <i className="fas fa-times"></i>
                  </button>
                </div>
                <div className="modal-body">
                  <div className="modal-section">
                    <h4>Issue Type</h4>
                    <p>{selectedEncryptionIssue.title}</p>
                  </div>
                  <div className="modal-section">
                    <h4>Affected Domains ({selectedEncryptionIssue.vulnerabilities.length})</h4>
                    <div className="affected-domains-list">
                      {selectedEncryptionIssue.vulnerabilities.map((vuln: any, index: number) => (
                        <div key={index} className="domain-item">
                          <div className="domain-info">
                            <strong>{vuln.domain}</strong>
                            <span className={`severity-badge ${vuln.severity.toLowerCase()}`}>
                              {vuln.severity}
                            </span>
                          </div>
                          <p>{vuln.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderEmailsContent = () => {
    return (
      <div id="emails-content" className="content-section active">
        <div className="page-header">
          <h1>Email Security Checks</h1>
        </div>

        <div className="section-content">
          {/* Domain Selection */}
          <div className="widget-card">
            <div className="widget-content">
              <div className="form-group">
                <label>Select Domain:</label>
                <SearchableDropdown
                  items={vendors.map(vendor => ({
                    value: vendor.domain,
                    text: `${vendor.name} (${vendor.domain})`
                  }))}
                  value={emailSelectedDomain}
                  onChange={(item) => handleDropdownChange(item, setEmailSelectedDomain, setEmailCustomDomain)}
                  placeholder="Search vendors..."
                />
              </div>

              <div className="form-group">
                <label>Enter custom domain:</label>
                <input
                  type="text"
                  value={emailCustomDomain}
                  onChange={(e) => {
                    setEmailCustomDomain(e.target.value);
                    setEmailSelectedDomain('');
                  }}
                  placeholder="example.com"
                  className="form-control"
                />
              </div>

              <div className="form-actions">
                <button
                  onClick={startEmailScan}
                  disabled={emailLoading}
                  className="btn btn-primary"
                >
                  <i className="fas fa-envelope"></i>
                  {emailLoading ? 'Scanning...' : 'Start Email Scan'}
                </button>

                {emailResults && !emailLoading && (
                  <button
                    onClick={startNewEmailScan}
                    className="btn btn-secondary"
                  >
                    <i className="fas fa-plus"></i>
                    New Email Scan
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Loading State */}
          {emailLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)', marginBottom: '1rem' }}></i>
                <h3>Scanning email security for {emailSelectedDomain || emailCustomDomain}</h3>
                <p>Analyzing email configuration and security settings...</p>

                {/* Progress Bar */}
                <div style={{ margin: '1.5rem auto', maxWidth: '400px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '0.5rem',
                    fontSize: '0.9rem',
                    color: 'var(--text-secondary)'
                  }}>
                    <span>Progress</span>
                    <span>{Math.round(emailProgress)}%</span>
                  </div>
                  <div style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: '#e5e7eb',
                    borderRadius: '4px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${emailProgress}%`,
                      height: '100%',
                      backgroundColor: 'var(--coral)',
                      borderRadius: '4px',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                </div>

                {/* Stop Button */}
                {emailScanId && (
                  <button
                    onClick={stopEmailScan}
                    className="btn btn-secondary"
                    style={{ marginTop: '1rem' }}
                  >
                    <i className="fas fa-stop"></i>
                    Stop Scan
                  </button>
                )}
              </div>
            </div>
          )}

          {emailResults && !emailLoading && (
            <>
              <div className="vulnerability-summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
                {/* Email Security Score */}
                <div className={`widget-card ${emailResults.final_score >= 800 ? 'score-excellent' :
                    emailResults.final_score >= 600 ? 'score-good' :
                      emailResults.final_score >= 400 ? 'score-fair' : 'score-poor'
                  }`}>
                  <div className="widget-content" style={{ textAlign: 'center' }}>
                    <h3 style={{ marginBottom: '1rem' }}>Email Security Score</h3>
                    <div className="score-display">
                      <div className="score-circle">
                        <span className="score-value">{emailResults.final_score}</span>
                        <span className="score-max">/{emailResults.max_score}</span>
                      </div>
                    </div>
                    <div className="score-details" style={{ marginTop: '1rem' }}>
                      <div className="score-item">
                        <span>Percentage: </span>
                        <span style={{ color: 'var(--success-green)', fontWeight: 'bold' }}>
                          {emailResults.summary.score_breakdown.percentage}%
                        </span>
                      </div>
                      <div className="score-item">
                        <span>Domain Analyzed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{emailResults.domain}</span>
                      </div>
                      <div className="score-item">
                        <span>Domains Processed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{emailResults.subdomains_processed}</span>
                      </div>
                      <div className="score-item">
                        <span>Total Issues: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{emailResults.summary.total_vulnerabilities}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Email Issue Breakdown */}
                <div className="widget-card">
                  <div className="widget-header">
                    <h3>Email Issue Breakdown</h3>
                  </div>
                  <div className="widget-content">
                    <div className="severity-grid">
                      <div className="severity-item critical">
                        <span className="severity-label">Critical</span>
                        <span className="severity-count">{emailResults.summary.by_severity.Critical || 0}</span>
                      </div>
                      <div className="severity-item high">
                        <span className="severity-label">High</span>
                        <span className="severity-count">{emailResults.summary.by_severity.High || 0}</span>
                      </div>
                      <div className="severity-item medium">
                        <span className="severity-label">Medium</span>
                        <span className="severity-count">{emailResults.summary.by_severity.Medium || 0}</span>
                      </div>
                      <div className="severity-item low">
                        <span className="severity-label">Low</span>
                        <span className="severity-count">{emailResults.summary.by_severity.Low || 0}</span>
                      </div>
                      <div className="severity-item info">
                        <span className="severity-label">Info</span>
                        <span className="severity-count">{emailResults.summary.by_severity.Info || 0}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Discovered Email Issues */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Discovered Email Issues</h3>
                  <div className="widget-controls" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <select
                      value={emailFilter}
                      onChange={(e) => setEmailFilter(e.target.value)}
                      className="form-control"
                      style={{ minWidth: '150px' }}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                    <div style={{ position: 'relative', minWidth: '250px' }}>
                      <input
                        type="text"
                        placeholder="Search email issues..."
                        value={emailSearchTerm}
                        onChange={(e) => setEmailSearchTerm(e.target.value)}
                        className="form-control"
                        style={{ paddingRight: '2.5rem' }}
                      />
                      {emailSearchTerm && (
                        <button
                          onClick={() => setEmailSearchTerm('')}
                          style={{
                            position: 'absolute',
                            right: '0.5rem',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                    <button
                      onClick={downloadEmailReport}
                      className="btn btn-secondary"
                      title="Download Email Report"
                    >
                      <i className="fas fa-download"></i>
                    </button>
                  </div>
                </div>
                <div className="widget-content">
                  {(() => {
                    const grouped = groupEmailIssuesByType(emailResults.vulnerabilities || []);
                    const filtered = grouped.filter(group => {
                      const matchesFilter = emailFilter === 'all' || group.severity.toLowerCase() === emailFilter.toLowerCase();
                      const matchesSearch = emailSearchTerm === '' ||
                        group.description.toLowerCase().includes(emailSearchTerm.toLowerCase()) ||
                        group.affectedDomains.some((domain: string) => domain.toLowerCase().includes(emailSearchTerm.toLowerCase()));
                      return matchesFilter && matchesSearch;
                    });

                    return filtered.length > 0 ? (
                      <div className="vulnerability-table-container">
                        <table className="vulnerability-table">
                          <thead>
                            <tr>
                              <th>AFFECTED DOMAIN</th>
                              <th>EMAIL ISSUE</th>
                              <th>SEVERITY</th>
                              <th>CATEGORY</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filtered.map((group, index) => (
                              <tr
                                key={index}
                                className="vulnerability-group-row"
                                onClick={() => openEmailModal(group.title, group.vulnerabilities)}
                                style={{ cursor: 'pointer' }}
                                title="Click to view affected domains"
                              >
                                <td>
                                  <div className="vulnerability-group-header">
                                    <i className="fas fa-eye vulnerability-view-icon"></i>
                                    <span className="affected-count">
                                      {group.affectedDomains.length} affected domain{group.affectedDomains.length > 1 ? 's' : ''}
                                    </span>
                                  </div>
                                </td>
                                <td>{group.title}</td>
                                <td>
                                  <span className={`severity-badge ${group.severity.toLowerCase()}`}>
                                    {group.severity}
                                  </span>
                                </td>
                                <td>Email</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div style={{
                        textAlign: 'center',
                        padding: '3rem',
                        color: 'var(--text-secondary)'
                      }}>
                        <i className="fas fa-shield-alt" style={{ fontSize: '3rem', marginBottom: '1rem', opacity: 0.5 }}></i>
                        <h3>No Email Issues Found</h3>
                        <p>
                          {emailFilter !== 'all' || emailSearchTerm
                            ? 'No issues match your current search criteria.'
                            : 'All email security configurations appear to be properly configured.'}
                        </p>
                      </div>
                    );
                  })()}
                </div>
              </div>
            </>
          )}

          {/* Email Issue Details Modal */}
          {selectedEmailIssue && (
            <div className="modal-overlay">
              <div className="modal-content">
                <div className="modal-header">
                  <h2>{selectedEmailIssue.title}</h2>
                  <button className="modal-close" onClick={closeEmailModal}>
                    <i className="fas fa-times"></i>
                  </button>
                </div>
                <div className="modal-body">
                  <h3>Affected Domains ({selectedEmailIssue.vulnerabilities.length})</h3>
                  <div className="affected-domains-list">
                    {selectedEmailIssue.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="affected-domain-item">
                        <div className="domain-header">
                          <span className="domain-name">{vuln.subdomain || vuln.domain}</span>
                          <span className={`severity-badge ${vuln.severity.toLowerCase()}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <p>{vuln.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderCertificationsContent = () => (
    <div id="certifications-content" className="content-section active">
      <div className="page-header">
        <h1>Vendor Certifications</h1>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <button
            onClick={refreshCertifications}
            disabled={certificationsLoading}
            className="btn btn-primary"
          >
            <i className="fas fa-sync-alt"></i>
            Refresh
          </button>
          <PermissionGate permission="check_all_certifications">
            <button
              onClick={checkAllCertifications}
              disabled={certificationsLoading}
              className="btn btn-secondary"
              style={{ fontSize: '0.9rem', padding: '0.5rem 1rem' }}
            >
              <i className="fas fa-search"></i>
              Check All
            </button>
          </PermissionGate>
        </div>
      </div>

      <div className="section-content">
        {/* Statistics Cards */}
        {certificationsStats && (
          <div style={{
            display: 'flex',
            gap: '1.5rem',
            marginBottom: '2rem',
            flexWrap: 'wrap'
          }}>
            <div className="widget-card" style={{ borderLeft: '4px solid #6b7280', flex: '1', minWidth: '200px' }}>
              <div className="widget-content" style={{ textAlign: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '1rem' }}>
                  <div style={{
                    width: '60px',
                    height: '60px',
                    borderRadius: '12px',
                    backgroundColor: '#f3f4f6',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <i className="fas fa-building" style={{ fontSize: '1.5rem', color: '#6b7280' }}></i>
                  </div>
                </div>
                <h2 style={{ fontSize: '2rem', margin: '0 0 0.5rem 0', color: '#1f2937' }}>
                  {certificationsStats.total_vendors}
                </h2>
                <p style={{ color: '#6b7280', margin: 0 }}>
                  Total<br />Vendors
                </p>
              </div>
            </div>

            <div className="widget-card" style={{ borderLeft: '4px solid #10b981', flex: '1', minWidth: '200px' }}>
              <div className="widget-content" style={{ textAlign: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '1rem' }}>
                  <div style={{
                    width: '60px',
                    height: '60px',
                    borderRadius: '12px',
                    backgroundColor: '#d1fae5',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <i className="fas fa-award" style={{ fontSize: '1.5rem', color: '#10b981' }}></i>
                  </div>
                </div>
                <h2 style={{ fontSize: '2rem', margin: '0 0 0.5rem 0', color: '#1f2937' }}>
                  {(certificationsStats.iso_27001_count || 0) + (certificationsStats.both_certifications || 0)}
                </h2>
                <p style={{ color: '#6b7280', margin: 0 }}>
                  ISO 27001<br />Certified
                </p>
              </div>
            </div>

            <div className="widget-card" style={{ borderLeft: '4px solid #3b82f6', flex: '1', minWidth: '200px' }}>
              <div className="widget-content" style={{ textAlign: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '1rem' }}>
                  <div style={{
                    width: '60px',
                    height: '60px',
                    borderRadius: '12px',
                    backgroundColor: '#dbeafe',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <i className="fas fa-shield-alt" style={{ fontSize: '1.5rem', color: '#3b82f6' }}></i>
                  </div>
                </div>
                <h2 style={{ fontSize: '2rem', margin: '0 0 0.5rem 0', color: '#1f2937' }}>
                  {(certificationsStats.soc2_count || 0) + (certificationsStats.both_certifications || 0)}
                </h2>
                <p style={{ color: '#6b7280', margin: 0 }}>
                  SOC 2<br />Certified
                </p>
              </div>
            </div>

            <div className="widget-card" style={{ borderLeft: '4px solid #f59e0b', flex: '1', minWidth: '200px' }}>
              <div className="widget-content" style={{ textAlign: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '1rem' }}>
                  <div style={{
                    width: '60px',
                    height: '60px',
                    borderRadius: '12px',
                    backgroundColor: '#fef3c7',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <i className="fas fa-users" style={{ fontSize: '1.5rem', color: '#f59e0b' }}></i>
                  </div>
                </div>
                <h2 style={{ fontSize: '2rem', margin: '0 0 0.5rem 0', color: '#1f2937' }}>
                  {certificationsStats.both_certifications || 0}
                </h2>
                <p style={{ color: '#6b7280', margin: 0 }}>
                  Both<br />Certifications
                </p>
              </div>
            </div>

            <div className="widget-card" style={{ borderLeft: '4px solid #ef4444', flex: '1', minWidth: '200px' }}>
              <div className="widget-content" style={{ textAlign: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '1rem' }}>
                  <div style={{
                    width: '60px',
                    height: '60px',
                    borderRadius: '12px',
                    backgroundColor: '#fee2e2',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <i className="fas fa-chart-line" style={{ fontSize: '1.5rem', color: '#ef4444' }}></i>
                  </div>
                </div>
                <h2 style={{ fontSize: '2rem', margin: '0 0 0.5rem 0', color: '#1f2937' }}>
                  {certificationsStats.certification_rate ? certificationsStats.certification_rate.toFixed(1) : '0.0'}%
                </h2>
                <p style={{ color: '#6b7280', margin: 0 }}>
                  Certification<br />Rate
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Filter Section */}
        <div className="widget-card" style={{ marginBottom: '2rem' }}>
          <div className="widget-header">
            <h3><i className="fas fa-filter"></i> Filter by Certifications</h3>
            <button
              onClick={clearAllFilters}
              className="btn btn-primary"
              style={{ fontSize: '0.9rem', padding: '0.5rem 1rem' }}
            >
              <i className="fas fa-times"></i>
              Clear Filters
            </button>
          </div>
          <div className="widget-content">
            <div style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '1rem',
              justifyContent: 'space-between'
            }}>
              <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', minWidth: '200px' }}>
                <input
                  type="checkbox"
                  checked={selectedFilters.iso_27001}
                  onChange={(e) => handleFilterChange('iso_27001', e.target.checked)}
                  style={{ marginRight: '0.75rem', transform: 'scale(1.2)' }}
                />
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: '#10b981',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginRight: '0.5rem'
                }}>
                  <i className="fas fa-award" style={{ color: 'white', fontSize: '0.8rem' }}></i>
                </div>
                <span style={{ fontSize: '1rem', fontWeight: '500' }}>ISO 27001 Certified</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', minWidth: '200px' }}>
                <input
                  type="checkbox"
                  checked={selectedFilters.soc2}
                  onChange={(e) => handleFilterChange('soc2', e.target.checked)}
                  style={{ marginRight: '0.75rem', transform: 'scale(1.2)' }}
                />
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: '#3b82f6',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginRight: '0.5rem'
                }}>
                  <i className="fas fa-shield-alt" style={{ color: 'white', fontSize: '0.8rem' }}></i>
                </div>
                <span style={{ fontSize: '1rem', fontWeight: '500' }}>SOC 2 Certified</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', minWidth: '200px' }}>
                <input
                  type="checkbox"
                  checked={selectedFilters.both_certifications}
                  onChange={(e) => handleFilterChange('both_certifications', e.target.checked)}
                  style={{ marginRight: '0.75rem', transform: 'scale(1.2)' }}
                />
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: '#f59e0b',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginRight: '0.5rem'
                }}>
                  <i className="fas fa-users" style={{ color: 'white', fontSize: '0.8rem' }}></i>
                </div>
                <span style={{ fontSize: '1rem', fontWeight: '500' }}>Both Certifications</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', minWidth: '200px' }}>
                <input
                  type="checkbox"
                  checked={selectedFilters.no_certifications}
                  onChange={(e) => handleFilterChange('no_certifications', e.target.checked)}
                  style={{ marginRight: '0.75rem', transform: 'scale(1.2)' }}
                />
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: '#ef4444',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginRight: '0.5rem'
                }}>
                  <i className="fas fa-times" style={{ color: 'white', fontSize: '0.8rem' }}></i>
                </div>
                <span style={{ fontSize: '1rem', fontWeight: '500' }}>No Certifications</span>
              </label>
            </div>
          </div>
        </div>

        {/* Search Section */}
        <div className="widget-card" style={{ marginBottom: '2rem' }}>
          <div className="widget-content">
            <div style={{ position: 'relative' }}>
              <input
                type="text"
                placeholder="Search by vendor name or domain..."
                value={certificationsSearchTerm}
                onChange={(e) => setCertificationsSearchTerm(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem 0.75rem 3rem',
                  border: '1px solid #d1d5db',
                  borderRadius: '8px',
                  fontSize: '1rem',
                  backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
                  color: isDarkMode ? 'var(--text-primary)' : 'inherit',
                  outline: 'none',
                  transition: 'border-color 0.2s ease'
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = 'var(--coral)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = '#d1d5db';
                }}
              />
              <i
                className="fas fa-search"
                style={{
                  position: 'absolute',
                  left: '1rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: '#6b7280',
                  fontSize: '1rem'
                }}
              ></i>
              {certificationsSearchTerm && (
                <button
                  onClick={() => setCertificationsSearchTerm('')}
                  style={{
                    position: 'absolute',
                    right: '1rem',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    color: '#6b7280',
                    cursor: 'pointer',
                    fontSize: '1rem',
                    padding: '0.25rem'
                  }}
                >
                  <i className="fas fa-times"></i>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Loading State - Only show during initial load or refresh, not during filtering */}
        {certificationsLoading && !certificationsData && (
          <div className="widget-card">
            <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
              <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)', marginBottom: '1rem' }}></i>
              <h3>Loading Certifications Data...</h3>
              <p>Retrieving vendor certification information...</p>
            </div>
          </div>
        )}

        {/* Results Counter */}
        {certificationsData && certificationsSearchTerm && (
          <div style={{ marginBottom: '1rem', padding: '0.75rem 1rem', backgroundColor: isDarkMode ? 'var(--bg-secondary)' : '#f8fafc', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
            <p style={{ margin: 0, color: isDarkMode ? 'var(--text-secondary)' : '#64748b', fontSize: '0.9rem' }}>
              <i className="fas fa-info-circle" style={{ marginRight: '0.5rem' }}></i>
              Showing {getFilteredVendors().length} of {certificationsData.vendors.length} vendors
              {certificationsSearchTerm && (
                <span> matching &quot;{certificationsSearchTerm}&quot;</span>
              )}
            </p>
          </div>
        )}

        {/* Vendors Grid */}
        {certificationsData && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))',
            gap: '1.5rem'
          }}>
            {getFilteredVendors().map((vendor, index) => (
              <div
                key={vendor.id}
                className="widget-card"
                style={{
                  borderLeft: vendor.certifications?.iso_27001 && vendor.certifications?.soc2
                    ? '4px solid #f59e0b'  // Both - Orange
                    : vendor.certifications?.iso_27001
                      ? '4px solid #10b981'  // ISO only - Green  
                      : vendor.certifications?.soc2
                        ? '4px solid #3b82f6'  // SOC2 only - Blue
                        : '4px solid #ef4444'  // None - Red
                }}
              >
                <div className="widget-content">
                  <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                    <VendorLogoImage
                      domain={vendor.domain}
                      vendorName={vendor.name}
                      fallbackLogo={vendor.logo}
                      className="vendor-logo"
                      style={{
                        width: '60px',
                        height: '60px',
                        borderRadius: '12px',
                        marginRight: '1rem',
                        objectFit: 'cover'
                      }}
                    />
                    <div style={{ flex: 1 }}>
                      <h3 style={{
                        margin: '0 0 0.25rem 0',
                        fontSize: '1.25rem',
                        color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                      }}>{vendor.name}</h3>
                      <p style={{
                        margin: 0,
                        color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                        fontSize: '0.9rem'
                      }}>{vendor.domain}</p>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                    <span style={{
                      backgroundColor: getScoreBackgroundColor(vendor.scores?.current || 0, isDarkMode),
                      color: getScoreColor(vendor.scores?.current || 0),
                      padding: '0.25rem 0.75rem',
                      borderRadius: '12px',
                      fontSize: '0.85rem',
                      fontWeight: '500'
                    }}>
                      {vendor.scores?.current || 'N/A'}
                    </span>
                  </div>

                  <div style={{ marginBottom: '1rem' }}>
                    {vendor.certifications?.iso_27001 && vendor.certifications?.soc2 ? (
                      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                        <span style={{
                          backgroundColor: isDarkMode ? 'rgba(5, 150, 105, 0.2)' : '#d1fae5',
                          color: isDarkMode ? '#34d399' : '#059669',
                          padding: '0.5rem 1rem',
                          borderRadius: '20px',
                          fontSize: '0.9rem',
                          fontWeight: '500',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem'
                        }}>
                          🏆 ISO 27001
                        </span>
                        <span style={{
                          backgroundColor: isDarkMode ? 'rgba(59, 130, 246, 0.2)' : '#dbeafe',
                          color: isDarkMode ? '#60a5fa' : '#2563eb',
                          padding: '0.5rem 1rem',
                          borderRadius: '20px',
                          fontSize: '0.9rem',
                          fontWeight: '500',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem'
                        }}>
                          🛡️ SOC 2
                        </span>
                      </div>
                    ) : vendor.certifications?.iso_27001 ? (
                      <span style={{
                        backgroundColor: isDarkMode ? 'rgba(5, 150, 105, 0.2)' : '#d1fae5',
                        color: isDarkMode ? '#34d399' : '#059669',
                        padding: '0.5rem 1rem',
                        borderRadius: '20px',
                        fontSize: '0.9rem',
                        fontWeight: '500',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                        marginBottom: '0.5rem'
                      }}>
                        🏆 ISO 27001
                      </span>
                    ) : vendor.certifications?.soc2 ? (
                      <span style={{
                        backgroundColor: isDarkMode ? 'rgba(59, 130, 246, 0.2)' : '#dbeafe',
                        color: isDarkMode ? '#60a5fa' : '#2563eb',
                        padding: '0.5rem 1rem',
                        borderRadius: '20px',
                        fontSize: '0.9rem',
                        fontWeight: '500',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                        marginBottom: '0.5rem'
                      }}>
                        🛡️ SOC 2
                      </span>
                    ) : (
                      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                        <span style={{
                          backgroundColor: isDarkMode ? '#374151' : '#f3f4f6',
                          color: isDarkMode ? '#d1d5db' : '#6b7280',
                          padding: '0.5rem 1rem',
                          borderRadius: '20px',
                          fontSize: '0.9rem',
                          fontWeight: '500',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                          border: isDarkMode ? '1px solid #4b5563' : 'none'
                        }}>
                          ❌ NO ISO 27001
                        </span>
                        <span style={{
                          backgroundColor: isDarkMode ? '#374151' : '#f3f4f6',
                          color: isDarkMode ? '#d1d5db' : '#6b7280',
                          padding: '0.5rem 1rem',
                          borderRadius: '20px',
                          fontSize: '0.9rem',
                          fontWeight: '500',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                          border: isDarkMode ? '1px solid #4b5563' : 'none'
                        }}>
                          ❌ NO SOC 2
                        </span>
                      </div>
                    )}

                    {vendor.certifications?.iso_27001 && vendor.certifications?.soc2 ? (
                      <p style={{
                        margin: 0,
                        color: isDarkMode ? '#34d399' : '#059669',
                        fontSize: '0.9rem',
                        fontWeight: '500',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem'
                      }}>
                        ✅ Fully Certified
                      </p>
                    ) : vendor.certifications?.iso_27001 || vendor.certifications?.soc2 ? (
                      <p style={{
                        margin: 0,
                        color: isDarkMode ? '#fbbf24' : '#d97706',
                        fontSize: '0.9rem',
                        fontWeight: '500',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem'
                      }}>
                        ✅ Partially Certified
                      </p>
                    ) : (
                      <p style={{
                        margin: 0,
                        color: isDarkMode ? '#f87171' : '#dc2626',
                        fontSize: '0.9rem',
                        fontWeight: '500',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem'
                      }}>
                        ⚠️ No Certifications Found
                      </p>
                    )}
                  </div>

                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    {isAdmin && (
                      <button
                        className="btn btn-primary"
                        onClick={() => checkSingleDomainCertifications(vendor.domain, vendor.name)}
                        style={{ fontSize: '0.85rem', padding: '0.4rem 0.8rem' }}
                      >
                        <i className="fas fa-search"></i>
                        Check
                      </button>
                    )}
                    <button
                      className="btn btn-secondary"
                      onClick={() => router.push(`/report/${vendor.domain}?from=${activeSection}`)}
                      style={{ fontSize: '0.85rem', padding: '0.4rem 0.8rem' }}
                    >
                      <i className="fas fa-eye"></i>
                      Report
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* No Results */}
        {certificationsData && (certificationsData.vendors.length === 0 || getFilteredVendors().length === 0) && (
          <div className="widget-card">
            <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
              <i className="fas fa-certificate" style={{ fontSize: '3rem', color: '#d1d5db', marginBottom: '1rem' }}></i>
              <h3>No Vendors Found</h3>
              <p>
                {certificationsData.vendors.length === 0
                  ? 'No vendors match the selected certification filters.'
                  : 'No vendors match your search criteria. Try adjusting your search term or filters.'
                }
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  const renderIncidentsContent = () => {
    return (
      <div id="incidents-content" className="content-section active">
        <div className="page-header">
          <h1>News & Incidents</h1>
          <p>Monitor security incidents and recent news related to your vendors</p>
        </div>

        <div className="section-content">
          {/* Filters and Controls */}
          <div className="widget-card">
            <div className="widget-content">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem', alignItems: 'end' }}>
                <div className="form-group">
                  <label>Filter by Domain (Optional):</label>
                  <SearchableDropdown
                    items={vendors.map(vendor => ({
                      value: vendor.domain,
                      text: `${vendor.name} (${vendor.domain})`
                    }))}
                    value={incidentsSelectedDomain}
                    onChange={(item) => handleDropdownChange(item, setIncidentsSelectedDomain, setIncidentsCustomDomain)}
                    placeholder="All domains"
                  />
                </div>



                <div className="form-group">
                  <label>Time Period: {incidentsMonths} months</label>
                  <input
                    type="range"
                    min="3"
                    max="12"
                    step="3"
                    value={incidentsMonths}
                    onChange={(e) => setIncidentsMonths(parseInt(e.target.value))}
                    className="form-control-range red-slider"
                    style={{
                      width: '100%',
                      height: '6px',
                      borderRadius: '3px',
                      background: '#ffcccb',
                      outline: 'none',
                      opacity: '0.8',
                      transition: 'opacity 0.2s',
                      cursor: 'pointer',
                      WebkitAppearance: 'none',
                      appearance: 'none'
                    }}
                    onMouseOver={(e) => e.currentTarget.style.opacity = '1'}
                    onMouseOut={(e) => e.currentTarget.style.opacity = '0.8'}
                  />
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: '0.8rem',
                    color: 'var(--text-secondary)',
                    marginTop: '0.5rem'
                  }}>
                    <span>3 months</span>
                    <span>6 months</span>
                    <span>12 months</span>
                  </div>
                </div>

              </div>

              <div className="form-actions" style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                  <button
                    onClick={applyFilters}
                    disabled={incidentsLoading}
                    className="btn btn-secondary"
                  >
                    <i className="fas fa-filter"></i>
                    Apply Filters
                  </button>

                  {incidentsResults && !incidentsLoading && (
                    <>
                      <button
                        onClick={startNewIncidentsLookup}
                        className="btn btn-secondary"
                      >
                        <i className="fas fa-refresh"></i>
                        Clear Filters
                      </button>

                      <button
                        onClick={downloadIncidentsReport}
                        className="btn btn-secondary"
                        title="Download Incidents & News Report"
                      >
                        <i className="fas fa-download"></i>
                        Download Report
                      </button>
                    </>
                  )}
                </div>

                {/* Last Scan Information - inline with buttons, positioned right */}
                {incidentsResults && (
                  <div className="last-scan-info" style={{
                    padding: '0.5rem 0.75rem',
                    backgroundColor: '#f8f9fa',
                    borderRadius: '6px',
                    border: '1px solid #e9ecef',
                    fontSize: '0.8rem',
                    color: '#6c757d',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                    flexShrink: 0
                  }}>
                    {incidentsResults.last_scan && (
                      <span><strong>Last scan:</strong> {new Date(incidentsResults.last_scan).toLocaleString()}</span>
                    )}
                  </div>
                )}
              </div>


            </div>
          </div>

          {/* Loading State */}
          {incidentsLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)', marginBottom: '1rem' }}></i>
                <h3>Searching for incidents and news for {incidentsSelectedDomain || incidentsCustomDomain}</h3>
                <p>Analyzing security incidents and news mentions...</p>
              </div>
            </div>
          )}

          {incidentsResults && !incidentsLoading && (
            <>
              {/* Summary Statistics */}
              <div className="vulnerability-summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
                <div className="widget-card">
                  <div className="widget-content" style={{ textAlign: 'center' }}>
                    <h3 style={{ marginBottom: '1rem' }}>Incidents Found</h3>
                    <div className="score-display">
                      <div className="score-circle">
                        <span className="score-value" style={{ color: 'var(--danger-red)' }}>{incidentsResults.incidents?.length || 0}</span>
                      </div>
                    </div>
                    <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>Security Incidents</p>
                  </div>
                </div>

                <div className="widget-card">
                  <div className="widget-content" style={{ textAlign: 'center' }}>
                    <h3 style={{ marginBottom: '1rem' }}>News Items</h3>
                    <div className="score-display">
                      <div className="score-circle">
                        <span className="score-value" style={{ color: 'var(--info-blue)' }}>{incidentsResults.news?.length || 0}</span>
                      </div>
                    </div>
                    <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>News Articles</p>
                  </div>
                </div>
              </div>



              {/* Security Incidents Table */}
              <div className="widget-card" style={{ marginBottom: '2rem' }}>
                <div className="widget-header">
                  <h3>Security Incidents ({incidentsResults.incidents?.length || 0})</h3>
                  <div className="widget-controls" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <select
                      value={incidentsFilter}
                      onChange={(e) => setIncidentsFilter(e.target.value)}
                      className="form-control"
                      style={{ minWidth: '150px' }}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                    <div style={{ position: 'relative', minWidth: '250px' }}>
                      <input
                        type="text"
                        placeholder="Search incidents..."
                        value={incidentsSearchTerm}
                        onChange={(e) => setIncidentsSearchTerm(e.target.value)}
                        className="form-control"
                        style={{ paddingRight: '2.5rem' }}
                      />
                      {incidentsSearchTerm && (
                        <button
                          onClick={() => setIncidentsSearchTerm('')}
                          style={{
                            position: 'absolute',
                            right: '0.5rem',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                  </div>
                </div>
                <div className="widget-content">
                  {(() => {
                    const incidents = incidentsResults.incidents || [];
                    const filtered = incidents.filter((incident: any) => {
                      const matchesFilter = incidentsFilter === 'all' ||
                        (incident.severity && incident.severity.toLowerCase() === incidentsFilter.toLowerCase());
                      const matchesSearch = incidentsSearchTerm === '' ||
                        (incident.title && incident.title.toLowerCase().includes(incidentsSearchTerm.toLowerCase())) ||
                        (incident.description && incident.description.toLowerCase().includes(incidentsSearchTerm.toLowerCase())) ||
                        (incident.source && incident.source.toLowerCase().includes(incidentsSearchTerm.toLowerCase()));
                      return matchesFilter && matchesSearch;
                    });

                    return filtered.length > 0 ? (
                      <div className="vulnerability-table-container">
                        <table className="vulnerability-table">
                          <thead>
                            <tr>
                              <th>DATE</th>
                              <th>TITLE</th>
                              <th>DOMAIN</th>
                              <th>SEVERITY</th>
                              <th>SOURCE</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filtered.map((incident: any, index: number) => (
                              <tr key={index}>
                                <td>{formatDate(incident.date || incident.timestamp)}</td>
                                <td>
                                  <div style={{ maxWidth: '300px' }}>
                                    <strong>{incident.title || 'Security Incident'}</strong>
                                    {incident.description && (
                                      <p style={{
                                        margin: '0.25rem 0 0 0',
                                        fontSize: '0.9rem',
                                        color: 'var(--text-secondary)',
                                        overflow: 'hidden',
                                        textOverflow: 'ellipsis',
                                        display: '-webkit-box',
                                        WebkitLineClamp: 2,
                                        WebkitBoxOrient: 'vertical'
                                      }}>
                                        {incident.description}
                                      </p>
                                    )}
                                  </div>
                                </td>
                                <td>
                                  <span style={{
                                    fontSize: '0.9rem',
                                    color: 'var(--text-primary)',
                                    fontFamily: 'monospace',
                                    background: '#f3f4f6',
                                    padding: '0.25rem 0.5rem',
                                    borderRadius: '4px'
                                  }}>
                                    {incident.domain || 'N/A'}
                                  </span>
                                </td>
                                <td>
                                  <span className={`severity-badge ${getSeverityBadgeClass(incident.severity || 'Medium')}`}>
                                    {incident.severity || 'Medium'}
                                  </span>
                                </td>
                                <td>
                                  {incident.source && incident.source !== 'Unknown' ? (
                                    <a
                                      href={incident.source}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      style={{
                                        color: 'var(--primary-blue)',
                                        textDecoration: 'none',
                                        borderBottom: '1px solid var(--primary-blue)'
                                      }}
                                      onMouseOver={(e) => e.currentTarget.style.textDecoration = 'underline'}
                                      onMouseOut={(e) => e.currentTarget.style.textDecoration = 'none'}
                                    >
                                      Link
                                      <i className="fas fa-external-link-alt" style={{ marginLeft: '0.5rem', fontSize: '0.8rem' }}></i>
                                    </a>
                                  ) : (
                                    'Unknown'
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div style={{
                        textAlign: 'center',
                        padding: '3rem',
                        color: 'var(--text-secondary)'
                      }}>
                        <i className="fas fa-shield-alt" style={{ fontSize: '3rem', marginBottom: '1rem', opacity: 0.5 }}></i>
                        <h3>No Security Incidents Found</h3>
                        <p>
                          {incidentsFilter !== 'all' || incidentsSearchTerm
                            ? 'No incidents match your current search criteria.'
                            : 'No security incidents found for this domain in the specified time period.'}
                        </p>
                      </div>
                    );
                  })()}
                </div>
              </div>

              {/* News Table */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Security News ({incidentsResults.news?.length || 0})</h3>
                  <div className="widget-controls" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <div style={{ position: 'relative', minWidth: '250px' }}>
                      <input
                        type="text"
                        placeholder="Search news..."
                        value={newsSearchTerm}
                        onChange={(e) => setNewsSearchTerm(e.target.value)}
                        className="form-control"
                        style={{ paddingRight: '2.5rem' }}
                      />
                      {newsSearchTerm && (
                        <button
                          onClick={() => setNewsSearchTerm('')}
                          style={{
                            position: 'absolute',
                            right: '0.5rem',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                  </div>
                </div>
                <div className="widget-content">
                  {(() => {
                    const news = incidentsResults.news || [];
                    console.log('Rendering news section - raw news data:', news);
                    console.log('News count in render:', news.length);
                    const filtered = news.filter((newsItem: any) => {
                      const matchesSearch = newsSearchTerm === '' ||
                        (newsItem.title && newsItem.title.toLowerCase().includes(newsSearchTerm.toLowerCase())) ||
                        (newsItem.description && newsItem.description.toLowerCase().includes(newsSearchTerm.toLowerCase())) ||
                        (newsItem.source && newsItem.source.toLowerCase().includes(newsSearchTerm.toLowerCase()));
                      return matchesSearch;
                    });

                    return filtered.length > 0 ? (
                      <div className="vulnerability-table-container">
                        <table className="vulnerability-table">
                          <thead>
                            <tr>
                              <th>DATE</th>
                              <th>TITLE</th>
                              <th>DOMAIN</th>
                              <th>SEVERITY</th>
                              <th>SOURCE</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filtered.map((newsItem: any, index: number) => (
                              <tr key={index}>
                                <td>{formatDate(newsItem.date || newsItem.timestamp)}</td>
                                <td>
                                  <div style={{ maxWidth: '300px' }}>
                                    <strong>{newsItem.title || 'Security News'}</strong>
                                    {newsItem.description && (
                                      <p style={{
                                        margin: '0.25rem 0 0 0',
                                        fontSize: '0.9rem',
                                        color: 'var(--text-secondary)',
                                        overflow: 'hidden',
                                        textOverflow: 'ellipsis',
                                        display: '-webkit-box',
                                        WebkitLineClamp: 2,
                                        WebkitBoxOrient: 'vertical'
                                      }}>
                                        {newsItem.description}
                                      </p>
                                    )}
                                  </div>
                                </td>
                                <td>
                                  <span style={{
                                    fontSize: '0.9rem',
                                    color: 'var(--text-primary)',
                                    fontFamily: 'monospace',
                                    background: '#f3f4f6',
                                    padding: '0.25rem 0.5rem',
                                    borderRadius: '4px'
                                  }}>
                                    {newsItem.domain || 'N/A'}
                                  </span>
                                </td>
                                <td>
                                  <span className="severity-badge info">
                                    Info
                                  </span>
                                </td>
                                <td>
                                  {newsItem.source && newsItem.source !== 'Unknown' ? (
                                    <a
                                      href={newsItem.source}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      style={{
                                        color: 'var(--primary-blue)',
                                        textDecoration: 'none',
                                        borderBottom: '1px solid var(--primary-blue)'
                                      }}
                                      onMouseOver={(e) => e.currentTarget.style.textDecoration = 'underline'}
                                      onMouseOut={(e) => e.currentTarget.style.textDecoration = 'none'}
                                    >
                                      Link
                                      <i className="fas fa-external-link-alt" style={{ marginLeft: '0.5rem', fontSize: '0.8rem' }}></i>
                                    </a>
                                  ) : (
                                    'Unknown'
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div style={{
                        textAlign: 'center',
                        padding: '3rem',
                        color: 'var(--text-secondary)'
                      }}>
                        <i className="fas fa-newspaper" style={{ fontSize: '3rem', marginBottom: '1rem', opacity: 0.5 }}></i>
                        <h3>No Security News Found</h3>
                        <p>
                          {newsSearchTerm
                            ? 'No news articles match your current search criteria.'
                            : 'No security-related news found for this domain in the specified time period.'}
                        </p>
                      </div>
                    );
                  })()}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    );
  };

  const renderWebsiteScansContent = () => {
    const groupedVulnerabilities = vulnerabilityResults ? groupVulnerabilitiesByType(vulnerabilityResults.vulnerabilities, 'website') : [];

    // Filter vulnerabilities based on search and severity filter
    const filteredVulnerabilities = groupedVulnerabilities.filter(group => {
      const matchesSearch = vulnerabilitySearchTerm === '' ||
        group.description.toLowerCase().includes(vulnerabilitySearchTerm.toLowerCase()) ||
        group.affectedDomains.some((domain: string) => domain.toLowerCase().includes(vulnerabilitySearchTerm.toLowerCase()));

      const matchesFilter = vulnerabilityFilter === 'all' ||
        group.severity.toLowerCase() === vulnerabilityFilter.toLowerCase();

      return matchesSearch && matchesFilter;
    });

    return (
      <div id="vulnerabilities-content" className="content-section active">
        <div className="page-header">
          <h1>HTTP Header Scans</h1>
        </div>

        <div className="section-content">
          {/* Scanner Controls */}
          <div className="widget-card">
            <div className="widget-content">
              <div className="form-group">
                <label htmlFor="website-domain-select">Select Domain:</label>
                <SearchableDropdown
                  items={vendors.map(vendor => ({
                    text: `${vendor.name} (${vendor.domain})`,
                    value: vendor.domain
                  }))}
                  value={websiteSelectedDomain}
                  onChange={(item) => {
                    setWebsiteSelectedDomain(item?.value || '');
                    setWebsiteCustomDomain('');
                  }}
                  placeholder="Search vendors..."
                />
              </div>

              <div className="form-group">
                <label htmlFor="website-custom-domain">Custom Domain:</label>
                <input
                  type="text"
                  id="website-custom-domain"
                  value={websiteCustomDomain}
                  onChange={(e) => {
                    setWebsiteCustomDomain(e.target.value);
                    setWebsiteSelectedDomain('');
                  }}
                  placeholder="example.com"
                  className="form-control"
                />
              </div>

              <div className="form-actions">
                <button
                  onClick={startWebsiteVulnerabilityScan}
                  disabled={vulnerabilityLoading}
                  className="btn btn-primary"
                >
                  <i className="fas fa-shield-alt"></i>
                  {vulnerabilityLoading ? 'Scanning...' : 'Start Scan'}
                </button>

                {vulnerabilityResults && !vulnerabilityLoading && (
                  <button
                    onClick={startNewVulnerabilityScan}
                    className="btn btn-secondary"
                    style={{ marginLeft: '1rem' }}
                  >
                    <i className="fas fa-plus"></i> New Network Scan
                  </button>
                )}

                {vulnerabilityLoading && (
                  <button
                    onClick={() => setVulnerabilityLoading(false)}
                    className="btn btn-secondary"
                    style={{ marginLeft: '1rem' }}
                  >
                    <i className="fas fa-times"></i> Cancel
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Loading State */}
          {vulnerabilityLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: 'var(--coral)', marginBottom: '1rem' }}></i>
                <h3>Scanning HTTP headers for {websiteSelectedDomain || websiteCustomDomain}</h3>
                <p>Analyzing security headers and configurations...</p>

                {/* Progress Bar */}
                <div style={{ margin: '1.5rem auto', maxWidth: '400px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '0.5rem',
                    fontSize: '0.9rem',
                    color: 'var(--text-secondary)'
                  }}>
                    <span>Progress</span>
                    <span>{Math.round(vulnerabilityProgress)}%</span>
                  </div>
                  <div style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: '#e5e7eb',
                    borderRadius: '4px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${vulnerabilityProgress}%`,
                      height: '100%',
                      backgroundColor: 'var(--coral)',
                      borderRadius: '4px',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                </div>

                <p><small>This may take a few minutes depending on the number of subdomains</small></p>
              </div>
            </div>
          )}

          {/* Results Display */}
          {vulnerabilityResults && !vulnerabilityLoading && (
            <>
              {/* Score Cards */}
              <div className="vulnerability-summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
                {/* Vulnerability Scan Score */}
                <div className={`widget-card ${vulnerabilityResults.final_score >= 800 ? 'score-excellent' :
                    vulnerabilityResults.final_score >= 600 ? 'score-good' :
                      vulnerabilityResults.final_score >= 400 ? 'score-fair' : 'score-poor'
                  }`}>
                  <div className="widget-content" style={{ textAlign: 'center' }}>
                    <h3 style={{ marginBottom: '1rem' }}>Vulnerability Scan Score</h3>
                    <div className="score-display">
                      <div className="score-circle">
                        <span className="score-value">{vulnerabilityResults.final_score}</span>
                        <span className="score-max">/{vulnerabilityResults.max_score}</span>
                      </div>
                    </div>
                    <div className="score-details" style={{ marginTop: '1rem' }}>
                      <div className="score-item">
                        <span>Percentage: </span>
                        <span style={{ color: 'var(--success-green)', fontWeight: 'bold' }}>
                          {vulnerabilityResults.summary.score_breakdown.percentage}%
                        </span>
                      </div>
                      <div className="score-item">
                        <span>Domain Analyzed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{vulnerabilityResults.domain}</span>
                      </div>
                      <div className="score-item">
                        <span>Subdomains Processed: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{vulnerabilityResults.subdomains_processed}</span>
                      </div>
                      <div className="score-item">
                        <span>Total Vulnerabilities: </span>
                        <span style={{ color: '#333', fontWeight: '500' }}>{vulnerabilityResults.summary.total_vulnerabilities}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Vulnerability Breakdown */}
                <div className="widget-card">
                  <div className="widget-header">
                    <h3>Vulnerability Breakdown</h3>
                  </div>
                  <div className="widget-content">
                    <div className="severity-grid">
                      <div className="severity-item critical">
                        <span className="severity-label">Critical</span>
                        <span className="severity-count">{vulnerabilityResults.summary.by_severity.CRITICAL || 0}</span>
                      </div>
                      <div className="severity-item high">
                        <span className="severity-label">High</span>
                        <span className="severity-count">{vulnerabilityResults.summary.by_severity.HIGH || 0}</span>
                      </div>
                      <div className="severity-item medium">
                        <span className="severity-label">Medium</span>
                        <span className="severity-count">{vulnerabilityResults.summary.by_severity.MEDIUM || 0}</span>
                      </div>
                      <div className="severity-item low">
                        <span className="severity-label">Low</span>
                        <span className="severity-count">{vulnerabilityResults.summary.by_severity.LOW || 0}</span>
                      </div>
                      <div className="severity-item info">
                        <span className="severity-label">Info</span>
                        <span className="severity-count">{vulnerabilityResults.summary.by_severity.INFO || 0}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Discovered Vulnerabilities Table */}
              <div className="widget-card">
                <div className="widget-header">
                  <h3>Discovered Vulnerabilities</h3>
                  <div className="widget-controls" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <select
                      value={vulnerabilityFilter}
                      onChange={(e) => setVulnerabilityFilter(e.target.value)}
                      className="form-control"
                      style={{ minWidth: '150px' }}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                    <div style={{ position: 'relative', minWidth: '250px' }}>
                      <input
                        type="text"
                        placeholder="Search vulnerabilities..."
                        value={vulnerabilitySearchTerm}
                        onChange={(e) => setVulnerabilitySearchTerm(e.target.value)}
                        className="form-control"
                        style={{ paddingRight: '2.5rem' }}
                      />
                      {vulnerabilitySearchTerm && (
                        <button
                          onClick={() => setVulnerabilitySearchTerm('')}
                          style={{
                            position: 'absolute',
                            right: '0.5rem',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: '1.2rem',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                    <button
                      onClick={downloadVulnerabilityReport}
                      className="btn btn-secondary"
                      title="Download Vulnerability Report"
                    >
                      <i className="fas fa-download"></i>
                    </button>
                  </div>
                </div>
                <div className="widget-content">
                  {filteredVulnerabilities.length > 0 ? (
                    <div className="vulnerability-table-container">
                      <table className="vulnerability-table">
                        <thead>
                          <tr>
                            <th>AFFECTED SUBDOMAIN</th>
                            <th>VULNERABILITY</th>
                            <th>SEVERITY</th>
                            <th>ID</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredVulnerabilities.map((group, index) => (
                            <tr
                              key={index}
                              className="vulnerability-group-row"
                              onClick={() => openVulnerabilityModal(group.description, group.vulnerabilities)}
                              style={{ cursor: 'pointer' }}
                              title="Click to view affected subdomains"
                            >
                              <td>
                                <div className="vulnerability-group-header">
                                  <i className="fas fa-eye vulnerability-view-icon"></i>
                                  <span className="affected-count">
                                    {group.affectedDomains.length} affected domain{group.affectedDomains.length > 1 ? 's' : ''}
                                  </span>
                                </div>
                              </td>
                              <td className="vulnerability-desc vulnerability-title">
                                {group.description}
                              </td>
                              <td>
                                <span className={`severity-badge ${group.severity.toLowerCase()}`}>
                                  {group.severity}
                                </span>
                              </td>
                              <td>
                                <code className="vuln-id">{group.id || 'Multiple'}</code>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                      {vulnerabilitySearchTerm || vulnerabilityFilter !== 'all'
                        ? 'No vulnerabilities match your search criteria'
                        : 'No vulnerabilities found'
                      }
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {/* No Results State */}
          {!vulnerabilityResults && !vulnerabilityLoading && (
            <div className="widget-card">
              <div className="widget-content" style={{ textAlign: 'center', padding: '3rem' }}>
                <i className="fas fa-shield-alt" style={{ fontSize: '3rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}></i>
                <h3>No Scan Results</h3>
                <p>Select a domain and start a vulnerability scan to view results</p>
              </div>
            </div>
          )}

          {/* Vulnerability Details Modal */}
          {selectedVulnerability && (
            <div className="modal-overlay" onClick={closeVulnerabilityModal}>
              <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                  <h3>{selectedVulnerability.title}</h3>
                  <button onClick={closeVulnerabilityModal} className="modal-close">
                    <i className="fas fa-times"></i>
                  </button>
                </div>
                <div className="modal-body">
                  <h4>Affected Subdomains ({selectedVulnerability.vulnerabilities.length})</h4>
                  <div className="affected-subdomains-list">
                    {selectedVulnerability.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="subdomain-item">
                        <div className="subdomain-info">
                          <strong>{vuln.subdomain}</strong>
                          <span className={`severity-badge ${vuln.severity.toLowerCase()}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <p className="vulnerability-description">{vuln.description}</p>
                        {vuln.id && (
                          <code className="vuln-id">{vuln.id}</code>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="modal-footer">
                  <button onClick={closeVulnerabilityModal} className="btn btn-primary">
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderVendorBreachesContent = () => (
    <div id="vendor-breaches-content" className="content-section active">
      <div className="page-header" style={{ display: 'block' }}>
        <h1>Pwn Monitor</h1>
        <div style={{ marginTop: '0.5rem' }}>
          <p style={{ margin: '0.25rem 0' }}>Monitor your vendors against known data breaches using HaveIBeenPwned database.</p>
          <p className="text-sm text-gray-600" style={{ marginTop: '0.5rem' }}>Source: <a href="https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">HaveIBeenPwned Feed</a></p>
        </div>
      </div>
      <div className="section-content">
        <BreachChecker />
      </div>
    </div>
  );

  const renderAnalyticsContent = () => (
    <div id="analytics-content" className="content-section active">
      <div className="page-header">
        <h1>Analytics</h1>
        <p>View security analytics and trends</p>
      </div>
      <div className="section-content">
        <p>Analytics functionality will be implemented here.</p>
      </div>
    </div>
  );

  const loadBreachMonitorData = useCallback(async () => {
    if (!canViewInternalBreaches) return;
    try {
      setBreachMonitorLoading(true);
      const params = new URLSearchParams();
      if (breachMonitorDateFrom.trim()) params.set('date_from', breachMonitorDateFrom.trim());
      if (breachMonitorDateTo.trim()) params.set('date_to', breachMonitorDateTo.trim());
      if (breachMonitorDateFrom.trim() || breachMonitorDateTo.trim()) {
        params.set('date_field', breachMonitorDateField);
      }
      const qs = params.toString();
      const result = await fetch(qs ? `/api/breach-monitor?${qs}` : '/api/breach-monitor', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        }
      });

      if (!result.ok) {
        throw new Error('Failed to fetch Breach Monitor data');
      }

      const data = await result.json();
      if (data.data && data.data.results) {
        setBreachMonitorPanel(data.data.results);
      } else {
        setBreachMonitorPanel([]);
      }
    } catch (error: any) {
      console.error('Error loading Breach Monitor data:', error);
      showNotification('error', 'Load failed', error.message || 'Failed to load Breach Monitor breach records');
      setBreachMonitorPanel([]);
    } finally {
      setBreachMonitorLoading(false);
      refreshBreachMonitorQuota();
    }
  }, [
    canViewInternalBreaches,
    refreshBreachMonitorQuota,
    breachMonitorDateFrom,
    breachMonitorDateTo,
    breachMonitorDateField,
  ]);

  const notifyBreachMonitorDomainSynced = useCallback(() => {
    showNotification(
      'success',
      'Breach Monitor refreshed',
      'Breach data was synced from the API for your configured domains.'
    );
  }, [showNotification]);

  useEffect(() => {
    if (activeSection === 'breach-monitor' && canViewInternalBreaches) {
      loadBreachMonitorData();
    }
  }, [activeSection, canViewInternalBreaches, loadBreachMonitorData]);

  const renderBreachMonitorContent = () => {
    const breachMonitorUsed = Math.max(
      0,
      BREACH_MONITOR_QUOTA_DISPLAY_CAP - breachMonitorApiCallsRemaining
    );
    return (
      <div id="breach-monitor-content" className="content-section active">
        <div className="page-header" style={{ display: 'block' }}>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '0.75rem',
              width: '100%',
            }}
          >
            <h1 style={{ margin: 0 }}>Breach Monitor Breach Intelligence</h1>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                flexShrink: 0,
                marginLeft: 'auto',
              }}
            >
              <div
                className="dashboard-segment-toggle dashboard-segment-toggle--sm"
                role="tablist"
                aria-label="Breach Monitor leak view"
              >
                <button
                  type="button"
                  role="tab"
                  className={breachMonitorLeakView === 'employees' ? 'active' : ''}
                  onClick={() => setBreachMonitorLeakView('employees')}
                  aria-selected={breachMonitorLeakView === 'employees'}
                >
                  Employee
                </button>
                <button
                  type="button"
                  role="tab"
                  className={breachMonitorLeakView === 'clients' ? 'active' : ''}
                  onClick={() => setBreachMonitorLeakView('clients')}
                  aria-selected={breachMonitorLeakView === 'clients'}
                >
                  Clients
                </button>
              </div>
              {isAdmin && (
                <span
                  style={{
                    color: 'var(--text-secondary)',
                    fontSize: '0.875rem',
                    fontWeight: 500,
                    whiteSpace: 'nowrap',
                  }}
                >
                  Limit{' '}
                  <strong style={{ color: 'var(--text-primary)' }}>{breachMonitorUsed.toLocaleString()}</strong>
                  {' / '}
                  <strong style={{ color: 'var(--text-primary)' }}>{BREACH_MONITOR_QUOTA_DISPLAY_CAP.toLocaleString()}</strong>
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="section-content">
          <BreachMonitorPanel
            breaches={breachMonitorBreaches}
            loading={breachMonitorLoading}
            leakView={breachMonitorLeakView}
            onQuotaRefresh={refreshBreachMonitorQuota}
            onBreachesReload={loadBreachMonitorData}
            onDomainRefreshSuccess={notifyBreachMonitorDomainSynced}
            dateFrom={breachMonitorDateFrom}
            dateTo={breachMonitorDateTo}
            onDateFromChange={setBreachMonitorDateFrom}
            onDateToChange={setBreachMonitorDateTo}
            dateField={breachMonitorDateField}
            onDateFieldChange={setBreachMonitorDateField}
          />
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <Layout
        activeSection={activeSection}
        onSectionChange={handleSectionChange}
        notifications={notifications}
        onRemoveNotification={removeNotification}
        onClearAllNotifications={clearAllNotifications}
        onOpenSecurityScanModal={openSecurityScanModal}
      >
        <div className="loading">
          <div className="spinner"></div>
          <span>Loading dashboard...</span>
        </div>
      </Layout>
    );
  }

  return (
    <Layout
      activeSection={activeSection}
      onSectionChange={handleSectionChange}
      notifications={notifications}
      onRemoveNotification={removeNotification}
      onClearAllNotifications={clearAllNotifications}
      onOpenSecurityScanModal={openSecurityScanModal}
    >
      {/* Alert Banners */}
      <div className="alert-container">
        {/* Alerts will be populated dynamically */}
      </div>

      {/* Render active section content */}
      {renderSectionContent()}

      {/* View All Recent Scans Modal */}
      {viewAllScansModal && (
        <div
          className="modal-overlay"
          onClick={closeViewAllScansModal}
        >
          <div
            className="modal-content view-all-scans-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <h2>All Recent Scans</h2>
              <button
                className="modal-close-btn"
                onClick={closeViewAllScansModal}
              >
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body">
              {allScansLoading ? (
                <div className="loading-state">
                  <i className="fas fa-spinner fa-spin"></i>
                  <p>Loading recent scans...</p>
                </div>
              ) : allRecentScans.length > 0 ? (
                <div className="all-scans-list">
                  {allRecentScans.map((scan, index) => (
                    <div key={index} className="scan-item-modal">
                      <div className="scan-info">
                        <div className="scan-domain">{scan.vendor_name || scan.domain}</div>
                        <div className="scan-type">{scan.scan_type?.toUpperCase() || 'UNKNOWN'}</div>
                        <div className="scan-time">{scan.time_ago || 'Unknown'}</div>
                      </div>
                      <div className="scan-result">
                        <span className={`result-badge ${getScanStatusFromScore(scan.score || 0)}`}>
                          {scan.result || 'Unknown'} ({scan.score || 0})
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="no-scans-modal">
                  <i className="fas fa-search"></i>
                  <p>No recent scans available</p>
                  <small>Run some security scans to see them here</small>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={closeViewAllScansModal}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Security Scan Modal */}
      {showSecurityScanModal && (
        <div className="modal-overlay" onClick={closeSecurityScanModal}>
          <div className="modal-content large-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Custom Security Scan</h2>
              <button className="modal-close" onClick={closeSecurityScanModal}>
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body">
              {showScanResults ? (
                /* Scan Results Display - Replaces entire modal content */
                <div className="scan-results-container">
                  <div className="scan-results-header">
                    <h3>
                      <i className="fas fa-chart-line"></i>
                      Security Scan Results for {scannedDomain}
                    </h3>
                    <p className="scan-results-subtitle">
                      Comprehensive security analysis completed. Review detailed findings below.
                    </p>
                  </div>

                  <div className="scan-results-content">
                    {Object.entries(scanResults).map(([scanType, result]) => {
                      const isCollapsed = collapsedSections[scanType];
                      const groupedVulns = result.vulnerabilities && Array.isArray(result.vulnerabilities) ?
                        groupVulnerabilities(result.vulnerabilities, scanType) : [];

                      return (
                        <div key={scanType} className="scan-type-section">
                          <div
                            className="scan-type-header clickable"
                            onClick={() => toggleSectionCollapse(scanType)}
                          >
                            <div className="scan-type-icon">
                              <i className={`fas ${getScanTypeIcon(scanType)}`}></i>
                            </div>
                            <div className="scan-type-info">
                              <h4>{scanType.charAt(0).toUpperCase() + scanType.slice(1)} Security Scan</h4>
                              <div className="scan-type-summary">
                                <span className={`scan-status ${getResultStatus(result)}`}>
                                  {getResultStatusText(result)}
                                </span>
                                {result.final_score && (
                                  <span className="scan-score">
                                    Score: {result.final_score}/{result.max_score || 950}
                                    ({Math.round((result.final_score / (result.max_score || 950)) * 100)}%)
                                  </span>
                                )}
                                {result.vulnerabilities && Array.isArray(result.vulnerabilities) && result.vulnerabilities.length > 0 && (
                                  <span className="vulnerability-count">
                                    {result.vulnerabilities.length} {result.vulnerabilities.length === 1 ? 'Issue' : 'Issues'}
                                  </span>
                                )}
                              </div>
                            </div>
                            <div className="collapse-indicator">
                              <i className={`fas fa-chevron-${isCollapsed ? 'down' : 'up'}`}></i>
                            </div>
                          </div>

                          {!isCollapsed && (
                            <div className="vulnerabilities-section">
                              {result.status === 'error' ? (
                                <div className="scan-error">
                                  <i className="fas fa-exclamation-triangle"></i>
                                  <p>Scan failed: {result.message}</p>
                                </div>
                              ) : groupedVulns.length > 0 ? (
                                <>
                                  <div className="vulnerabilities-header">
                                    <h5>
                                      <i className="fas fa-bug"></i>
                                      Vulnerabilities Found ({groupedVulns.length} {groupedVulns.length === 1 ? 'type' : 'types'})
                                    </h5>
                                  </div>
                                  <div className="vulnerabilities-list">
                                    {groupedVulns.map((groupedVuln: any, index: number) => (
                                      <div
                                        key={index}
                                        className={`vulnerability-item severity-${groupedVuln.severity?.toLowerCase() || 'medium'} clickable-vuln`}
                                        onClick={() => handleModalVulnerabilityClick(groupedVuln)}
                                      >
                                        <div className="vulnerability-header">
                                          <div className="vulnerability-title">
                                            <span className={`severity-badge severity-${groupedVuln.severity?.toLowerCase() || 'medium'}`}>
                                              {groupedVuln.severity || 'MEDIUM'}
                                            </span>
                                            <h6>{groupedVuln.title}</h6>
                                          </div>
                                          <div className="vulnerability-meta">
                                            <span className="affected-count">
                                              <i className="fas fa-sitemap"></i>
                                              {groupedVuln.count} {groupedVuln.count === 1 ? 'subdomain' : 'subdomains'}
                                            </span>
                                            <span className="click-hint">
                                              <i className="fas fa-external-link-alt"></i>
                                              Click to view details
                                            </span>
                                          </div>
                                        </div>
                                        <div className="vulnerability-description">
                                          <p>{groupedVuln.description || 'No description available'}</p>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </>
                              ) : (
                                <div className="no-vulnerabilities">
                                  <i className="fas fa-shield-check"></i>
                                  <p>No vulnerabilities found in this scan</p>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  <div className="scan-results-actions">
                    <button
                      className="btn btn-secondary"
                      onClick={() => {
                        setShowScanResults(false);
                        setScanResults({});
                      }}
                    >
                      <i className="fas fa-arrow-left"></i>
                      Run New Scan
                    </button>
                    <button
                      className="btn btn-primary"
                      onClick={() => {
                        closeSecurityScanModal();
                        loadDashboardData();
                      }}
                    >
                      <i className="fas fa-chart-bar"></i>
                      View in Dashboard
                    </button>
                  </div>
                </div>
              ) : !securityScanLoading ? (
                <>
                  {/* Domain Selection - Moved higher */}
                  <div className="widget-card domain-selection-card">
                    <div className="widget-header compact-header">
                      <h3>
                        <i className="fas fa-globe"></i>
                        Select Target Domain
                      </h3>
                    </div>
                    <div className="widget-content compact-content">
                      <div className="domain-selection-grid">
                        <div className="domain-input-group">
                          <label>Select from vendors:</label>
                          <div className="dropdown-container">
                            <SearchableDropdown
                              items={vendors.map(vendor => ({
                                text: `${vendor.name} (${vendor.domain})`,
                                value: vendor.domain
                              }))}
                              placeholder="Search vendors..."
                              onChange={(item: any) => {
                                setScanModalDomain(item?.value || '');
                                setScanModalCustomDomain('');
                              }}
                              value={scanModalDomain}
                            />
                          </div>
                        </div>
                        <div className="domain-input-group">
                          <label>Or enter custom domain:</label>
                          <input
                            type="text"
                            placeholder="example.com"
                            value={scanModalCustomDomain}
                            onChange={(e) => {
                              setScanModalCustomDomain(e.target.value);
                              setScanModalDomain('');
                            }}
                            className="form-input domain-input"
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Scan Type Selection */}
                  <div className="widget-card">
                    <div className="widget-header">
                      <h3>
                        <i className="fas fa-shield-alt"></i>
                        Select Scan Types
                      </h3>
                      <div className="widget-actions">
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={handleSelectAllScans}
                        >
                          <i className="fas fa-check-double"></i>
                          {Object.values(selectedScanTypes).every(selected => selected) ? 'Deselect All' : 'Select All'}
                        </button>
                      </div>
                    </div>
                    <div className="widget-content">
                      <div className="scan-types-grid">
                        <div className={`scan-type-card ${selectedScanTypes.vulnerability ? 'selected' : ''}`}
                          onClick={() => handleScanTypeToggle('vulnerability')}>
                          <div className="scan-type-icon">
                            <i className="fas fa-bug"></i>
                          </div>
                          <div className="scan-type-content">
                            <h4>Vulnerability Scan</h4>
                            <p>Scan for website vulnerabilities</p>
                          </div>
                          <div className="scan-type-checkbox" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedScanTypes.vulnerability}
                              onChange={() => handleScanTypeToggle('vulnerability')}
                              onClick={(e) => e.stopPropagation()}
                            />
                          </div>
                        </div>

                        <div className={`scan-type-card ${selectedScanTypes.reputation ? 'selected' : ''}`}
                          onClick={() => handleScanTypeToggle('reputation')}>
                          <div className="scan-type-icon">
                            <i className="fas fa-shield-virus"></i>
                          </div>
                          <div className="scan-type-content">
                            <h4>Domain Reputation</h4>
                            <p>Check domain reputation and blacklists</p>
                          </div>
                          <div className="scan-type-checkbox" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedScanTypes.reputation}
                              onChange={() => handleScanTypeToggle('reputation')}
                              onClick={(e) => e.stopPropagation()}
                            />
                          </div>
                        </div>

                        <div className={`scan-type-card ${selectedScanTypes.network ? 'selected' : ''}`}
                          onClick={() => handleScanTypeToggle('network')}>
                          <div className="scan-type-icon">
                            <i className="fas fa-network-wired"></i>
                          </div>
                          <div className="scan-type-content">
                            <h4>Network Scan</h4>
                            <p>Scan open ports and services</p>
                          </div>
                          <div className="scan-type-checkbox" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedScanTypes.network}
                              onChange={() => handleScanTypeToggle('network')}
                              onClick={(e) => e.stopPropagation()}
                            />
                          </div>
                        </div>

                        <div className={`scan-type-card ${selectedScanTypes.dns ? 'selected' : ''}`}
                          onClick={() => handleScanTypeToggle('dns')}>
                          <div className="scan-type-icon">
                            <i className="fas fa-server"></i>
                          </div>
                          <div className="scan-type-content">
                            <h4>DNS Security</h4>
                            <p>Analyze DNS configuration security</p>
                          </div>
                          <div className="scan-type-checkbox" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedScanTypes.dns}
                              onChange={() => handleScanTypeToggle('dns')}
                              onClick={(e) => e.stopPropagation()}
                            />
                          </div>
                        </div>

                        <div className={`scan-type-card ${selectedScanTypes.encryption ? 'selected' : ''}`}
                          onClick={() => handleScanTypeToggle('encryption')}>
                          <div className="scan-type-icon">
                            <i className="fas fa-lock"></i>
                          </div>
                          <div className="scan-type-content">
                            <h4>SSL/TLS Encryption</h4>
                            <p>Test SSL/TLS configuration</p>
                          </div>
                          <div className="scan-type-checkbox" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedScanTypes.encryption}
                              onChange={() => handleScanTypeToggle('encryption')}
                              onClick={(e) => e.stopPropagation()}
                            />
                          </div>
                        </div>

                        <div className={`scan-type-card ${selectedScanTypes.email ? 'selected' : ''}`}
                          onClick={() => handleScanTypeToggle('email')}>
                          <div className="scan-type-icon">
                            <i className="fas fa-envelope-open-text"></i>
                          </div>
                          <div className="scan-type-content">
                            <h4>Email Security</h4>
                            <p>Check email security configuration</p>
                          </div>
                          <div className="scan-type-checkbox" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedScanTypes.email}
                              onChange={() => handleScanTypeToggle('email')}
                              onClick={(e) => e.stopPropagation()}
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="modal-actions">
                    <button className="btn btn-secondary" onClick={closeSecurityScanModal}>
                      <i className="fas fa-times"></i>
                      Cancel
                    </button>
                    <button
                      className={`btn ${(!scanModalDomain && !scanModalCustomDomain) ||
                          Object.values(selectedScanTypes).filter(Boolean).length === 0
                          ? 'btn-disabled'
                          : 'btn-primary'
                        }`}
                      onClick={startSelectedScans}
                      disabled={
                        (!scanModalDomain && !scanModalCustomDomain) ||
                        Object.values(selectedScanTypes).filter(Boolean).length === 0
                      }
                    >
                      <i className="fas fa-play"></i>
                      {Object.values(selectedScanTypes).filter(Boolean).length === 0
                        ? 'Select scan types to continue'
                        : `Start Selected Scans (${Object.values(selectedScanTypes).filter(Boolean).length})`
                      }
                    </button>
                  </div>
                </>
              ) : (
                /* Scanning Progress */
                <div className="scan-progress-container">
                  <div className="scan-progress-header">
                    <h3>
                      <i className="fas fa-shield-alt"></i>
                      Running Security Scans for {scanModalDomain || scanModalCustomDomain}
                    </h3>
                  </div>
                  <div className="scan-progress-content">
                    <div className="progress-container">
                      <div className="progress-bar">
                        <div
                          className="progress-fill"
                          style={{ width: `${securityScanProgress}%` }}
                        ></div>
                      </div>
                      <div className="progress-text">
                        {securityScanProgress}% Complete
                      </div>
                    </div>
                    <div className="scan-status">
                      <p>{securityScanStatus}</p>
                    </div>
                    <div className="selected-scans-summary">
                      <h4>Selected Scans:</h4>
                      <div className="scan-summary-grid">
                        {Object.entries(selectedScanTypes)
                          .filter(([_, selected]) => selected)
                          .map(([scanType, _]) => (
                            <div key={scanType} className="scan-summary-item">
                              <i className="fas fa-check-circle"></i>
                              <span>{scanType.charAt(0).toUpperCase() + scanType.slice(1)}</span>
                            </div>
                          ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Modal Vulnerability Details Modal */}
      {selectedModalVuln && (
        <div className="modal-overlay" onClick={closeModalVulnerabilityModal}>
          <div className="modal-content vulnerability-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>
                <span className={`severity-badge severity-${selectedModalVuln.severity?.toLowerCase() || 'medium'}`}>
                  {selectedModalVuln.severity || 'MEDIUM'}
                </span>
                {selectedModalVuln.title}
              </h2>
              <button className="modal-close" onClick={closeModalVulnerabilityModal}>
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body">
              <div className="vulnerability-details">
                <div className="vulnerability-info">
                  <h4>Description</h4>
                  <p>{selectedModalVuln.description || 'No description available'}</p>
                </div>

                <div className="affected-subdomains">
                  <h4>
                    <i className="fas fa-sitemap"></i>
                    Affected Subdomains ({selectedModalVuln.affectedDomains?.length || selectedModalVuln.subdomains?.length || 0})
                  </h4>
                  <div className="subdomains-list">
                    {(selectedModalVuln.vulnerabilities || selectedModalVuln.subdomains || []).map((item: any, index: number) => (
                      <div key={index} className="subdomain-item">
                        <div className="subdomain-header">
                          <span className="subdomain-name">
                            <i className="fas fa-globe"></i>
                            {item.subdomain || item.domain || 'Unknown subdomain'}
                          </span>
                        </div>
                        {item.description && item.description !== selectedModalVuln.description && (
                          <div className="subdomain-description">
                            <p>{item.description}</p>
                          </div>
                        )}
                      </div>
                    )) || (
                        <div className="no-subdomains">
                          <p>No subdomain details available</p>
                        </div>
                      )}
                  </div>
                </div>
              </div>
            </div>

            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={closeModalVulnerabilityModal}>
                <i className="fas fa-times"></i>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Log Viewer for debugging - Ctrl/Cmd + Shift + L to toggle */}

      {/* Subdomain Option Modal */}
      {showSubdomainOptionModal && (
        <div className="modal-overlay" onClick={() => setShowSubdomainOptionModal(false)}>
          <div className="modal-content subdomain-option-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{(() => {
                const hasFilters = vendorSearchTerm ||
                  vendorFilter.length > 0 ||
                  tierFilter.length > 0 ||
                  portfolioFilter.length > 0 ||
                  industryFilter.length > 0;
                return hasFilters ? 'Filtered Scan Options' : 'Full Scan Options';
              })()}</h2>
              <button
                className="modal-close-btn"
                onClick={() => setShowSubdomainOptionModal(false)}
              >
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body">
              <div className="scan-option-container">
                <div className="option-description">
                  <h3>{(() => {
                    const hasFilters = vendorSearchTerm ||
                      vendorFilter.length > 0 ||
                      tierFilter.length > 0 ||
                      portfolioFilter.length > 0 ||
                      industryFilter.length > 0;
                    if (hasFilters) {
                      const count = filteredVendors.length;
                      return `Scan ${count} Filtered Vendor${count !== 1 ? 's' : ''}`;
                    }
                    return 'Choose Scan Mode';
                  })()}</h3>
                  {(() => {
                    const hasFilters = vendorSearchTerm ||
                      vendorFilter.length > 0 ||
                      tierFilter.length > 0 ||
                      portfolioFilter.length > 0 ||
                      industryFilter.length > 0;
                    if (hasFilters) {
                      const count = filteredVendors.length;
                      return (
                        <p style={{ color: '#666', fontSize: '0.9rem', marginTop: '0.5rem' }}>
                          You have filters applied. This will scan only the {count} vendor{count !== 1 ? 's' : ''} that match your current filters.
                          <br />
                          <strong>Note:</strong> Checkpoint/resume functionality is only available for full scans of all vendors.
                        </p>
                      );
                    }
                    return null;
                  })()}
                </div>

                {/* Loading Resume Info */}
                {loadingResumeInfo && (
                  <div style={{ textAlign: 'center', padding: '2rem' }}>
                    <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: '#667eea' }}></i>
                    <p style={{ marginTop: '1rem', color: '#666' }}>Checking for previous scan...</p>
                  </div>
                )}

                {/* Mode Selection Cards */}
                {!loadingResumeInfo && (() => {
                  const hasFilters = vendorSearchTerm ||
                    vendorFilter.length > 0 ||
                    tierFilter.length > 0 ||
                    portfolioFilter.length > 0 ||
                    industryFilter.length > 0;

                  if (hasFilters) {
                    // For filtered scans, show a single "Start Filtered Scan" option
                    return (
                      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.5rem' }}>
                        <div className="scan-mode-card" style={{
                          maxWidth: '400px',
                          background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                          borderRadius: '12px',
                          padding: '1.5rem',
                          boxShadow: '0 4px 6px rgba(5, 150, 105, 0.3)',
                          cursor: 'pointer',
                          transition: 'transform 0.2s, box-shadow 0.2s',
                        }}
                          onClick={() => {
                            setShowSubdomainOptionModal(false);
                            executeFullScanAllDomains(true, false);
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.transform = 'translateY(-4px)';
                            e.currentTarget.style.boxShadow = '0 8px 12px rgba(5, 150, 105, 0.5)';
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.transform = 'translateY(0)';
                            e.currentTarget.style.boxShadow = '0 4px 6px rgba(5, 150, 105, 0.3)';
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.75rem' }}>
                            <div style={{
                              width: '45px',
                              height: '45px',
                              borderRadius: '50%',
                              background: 'rgba(255, 255, 255, 0.2)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              marginRight: '1rem'
                            }}>
                              <i className="fas fa-filter" style={{ color: 'white', fontSize: '1.4rem' }}></i>
                            </div>
                            <div>
                              <h4 style={{ color: 'white', margin: 0, fontSize: '1.15rem' }}>Start Filtered Scan</h4>
                            </div>
                          </div>
                          <p style={{ color: 'rgba(255, 255, 255, 0.95)', margin: 0, fontSize: '0.9rem', lineHeight: '1.4' }}>
                            Scan {filteredVendors.length} filtered vendor{filteredVendors.length !== 1 ? 's' : ''} with all subdomains included
                          </p>
                        </div>
                      </div>
                    );
                  }

                  // For full scans, show both options
                  return (
                    <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem' }}>
                      {/* Start from Beginning Card */}
                      <div className="scan-mode-card" style={{
                        flex: 1,
                        background: 'linear-gradient(135deg, #475569 0%, #334155 100%)',
                        borderRadius: '12px',
                        padding: '1.5rem',
                        boxShadow: scanMode === 'new'
                          ? '0 0 0 3px rgba(71, 85, 105, 0.4)'
                          : '0 4px 6px rgba(71, 85, 105, 0.3)',
                        cursor: 'pointer',
                        transition: 'transform 0.2s, box-shadow 0.2s',
                        border: scanMode === 'new' ? '3px solid white' : 'none',
                      }}
                        onClick={() => {
                          setScanMode('new');
                          setScanCheckpointVendor('');
                          // Directly start the scan with subdomains included
                          setShowSubdomainOptionModal(false);
                          executeFullScanAllDomains(true, false);
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.transform = 'translateY(-4px)';
                          e.currentTarget.style.boxShadow = '0 8px 12px rgba(71, 85, 105, 0.5)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.transform = 'translateY(0)';
                          e.currentTarget.style.boxShadow = scanMode === 'new' ? '0 0 0 3px rgba(71, 85, 105, 0.4)' : '0 4px 6px rgba(71, 85, 105, 0.3)';
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.75rem' }}>
                          <div style={{
                            width: '45px',
                            height: '45px',
                            borderRadius: '50%',
                            background: 'rgba(255, 255, 255, 0.2)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            marginRight: '1rem'
                          }}>
                            <i className="fas fa-play-circle" style={{ color: 'white', fontSize: '1.4rem' }}></i>
                          </div>
                          <div>
                            <h4 style={{ color: 'white', margin: 0, fontSize: '1.15rem' }}>Start from Beginning</h4>
                          </div>
                        </div>
                        <p style={{ color: 'rgba(255, 255, 255, 0.95)', margin: 0, fontSize: '0.9rem', lineHeight: '1.4' }}>
                          Fresh Full Scan of All Vendors
                        </p>
                      </div>

                      {/* Continue Scan Card */}
                      <div className="scan-mode-card" style={{
                        flex: 1,
                        background: resumeInfo?.can_resume
                          ? 'linear-gradient(135deg, #0e7490 0%, #155e75 100%)'
                          : 'linear-gradient(135deg, #9CA3AF 0%, #6B7280 100%)',
                        borderRadius: '12px',
                        padding: '1.5rem',
                        boxShadow: scanMode === 'continue'
                          ? '0 0 0 3px rgba(14, 116, 144, 0.4)'
                          : '0 4px 6px rgba(14, 116, 144, 0.3)',
                        cursor: resumeInfo?.can_resume ? 'pointer' : 'not-allowed',
                        opacity: resumeInfo?.can_resume ? 1 : 0.6,
                        transition: 'transform 0.2s, box-shadow 0.2s',
                        border: scanMode === 'continue' ? '3px solid white' : 'none',
                      }}
                        onClick={() => {
                          if (resumeInfo?.can_resume) {
                            setScanMode('continue');
                            // Directly start the scan with subdomains included from checkpoint
                            setShowSubdomainOptionModal(false);
                            executeFullScanAllDomains(true, true);
                          }
                        }}
                        onMouseEnter={(e) => {
                          if (resumeInfo?.can_resume) {
                            e.currentTarget.style.transform = 'translateY(-4px)';
                            e.currentTarget.style.boxShadow = '0 8px 12px rgba(14, 116, 144, 0.5)';
                          }
                        }}
                        onMouseLeave={(e) => {
                          if (resumeInfo?.can_resume) {
                            e.currentTarget.style.transform = 'translateY(0)';
                            e.currentTarget.style.boxShadow = scanMode === 'continue' ? '0 0 0 3px rgba(14, 116, 144, 0.4)' : '0 4px 6px rgba(14, 116, 144, 0.3)';
                          }
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.75rem' }}>
                          <div style={{
                            width: '45px',
                            height: '45px',
                            borderRadius: '50%',
                            background: 'rgba(255, 255, 255, 0.2)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            marginRight: '1rem'
                          }}>
                            <i className="fas fa-forward" style={{ color: 'white', fontSize: '1.4rem' }}></i>
                          </div>
                          <div>
                            <h4 style={{ color: 'white', margin: 0, fontSize: '1.15rem' }}>Continue Scan</h4>
                          </div>
                        </div>
                        {resumeInfo?.can_resume ? (
                          <p style={{ color: 'rgba(255, 255, 255, 0.95)', margin: 0, fontSize: '0.9rem', lineHeight: '1.4' }}>
                            Resume from: <strong>{resumeInfo.resume_from_vendor}</strong>
                          </p>
                        ) : (
                          <p style={{ color: 'rgba(255, 255, 255, 0.95)', margin: 0, fontSize: '0.9rem', lineHeight: '1.4' }}>
                            {resumeInfo?.message || 'No previous scan to resume'}
                          </p>
                        )}
                      </div>
                    </div>
                  );
                })()}

                {/* Info note about background execution */}
                <div className="option-note" style={{ marginTop: '0.5rem', fontSize: '0.95rem', textAlign: 'center' }}>
                  <i className="fas fa-info-circle"></i>
                  <span>Scans Include Subdomains and Run in the Background</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Card Details Modal */}
      {showCardDetailsModal && (
        <div className="modal-overlay" onClick={closeCardDetailsModal}>
          <div className="modal-content card-details-modal large-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>
                {cardDetailsType === 'vendors' && <><i className="fas fa-building"></i> Active Vendors</>}
                {cardDetailsType === 'subdomains' && <><i className="fas fa-sitemap"></i> Vendor Subdomains</>}
                {cardDetailsType === 'vulnerabilities' && <><i className="fas fa-shield-alt"></i> Vulnerabilities</>}
                {cardDetailsType === 'high-risk' && <><i className="fas fa-exclamation-circle"></i> High Risk Vulnerabilities</>}
              </h2>
              <button className="modal-close" onClick={closeCardDetailsModal}>
                <i className="fas fa-times"></i>
              </button>
            </div>

            <div className="modal-body">
              {cardDetailsLoading ? (
                <div className="loading-state">
                  <i className="fas fa-spinner fa-spin"></i>
                  <p>Loading data...</p>
                </div>
              ) : cardDetailsData ? (
                <div className="card-details-content">
                  {/* Search Bar */}
                  <div className="modal-search-bar">
                    <i className="fas fa-search"></i>
                    <input
                      type="text"
                      placeholder="Search vendors by name or domain..."
                      value={cardDetailsSearchTerm}
                      onChange={(e) => setCardDetailsSearchTerm(e.target.value)}
                      className="modal-search-input"
                    />
                    {cardDetailsSearchTerm && (
                      <button
                        className="clear-search-icon"
                        onClick={() => setCardDetailsSearchTerm('')}
                        title="Clear search"
                      >
                        <i className="fas fa-times"></i>
                      </button>
                    )}
                  </div>

                  {/* Vendors Table View */}
                  {cardDetailsType === 'vendors' && cardDetailsData.vendors && (() => {
                    const filteredVendors = cardDetailsData.vendors.filter((vendor: any) => {
                      const searchLower = cardDetailsSearchTerm.toLowerCase();
                      return (
                        vendor.name?.toLowerCase().includes(searchLower) ||
                        vendor.domain?.toLowerCase().includes(searchLower)
                      );
                    });

                    return (
                      <div className="vendors-table-container">
                        <div className="table-info">
                          <span className="info-badge">
                            <i className="fas fa-building"></i>
                            {filteredVendors.length} of {cardDetailsData.total} Vendors
                          </span>
                        </div>
                        <div className="responsive-table">
                          <table className="vendors-detail-table">
                            <thead>
                              <tr>
                                <th>Vendor</th>
                                <th>Domain</th>
                                <th>Score</th>
                                <th>Tier</th>
                                <th>Portfolio</th>
                                <th>Industry</th>
                                <th>Last Scan</th>
                              </tr>
                            </thead>
                            <tbody>
                              {filteredVendors.map((vendor: any) => (
                                <tr
                                  key={vendor.id}
                                  className="vendor-row clickable-row"
                                  onClick={() => router.push(`/report/${vendor.domain}?from=${activeSection}`)}
                                  title="Click to view vendor report"
                                >
                                  <td>
                                    <div className="vendor-name-cell">
                                      <VendorLogoImage domain={vendor.domain} vendorName={vendor.name} fallbackLogo={vendor.logo} className="vendor-logo-tiny" />
                                      <span className="vendor-name">{vendor.name}</span>
                                    </div>
                                  </td>
                                  <td className="domain-cell">{vendor.domain}</td>
                                  <td>
                                    <span className="score-value">{vendor.score || 0}/950</span>
                                  </td>
                                  <td>
                                    <span className="tier-badge">{vendor.tier || 'N/A'}</span>
                                  </td>
                                  <td>{vendor.portfolio || 'N/A'}</td>
                                  <td>{vendor.industry || 'N/A'}</td>
                                  <td className="date-cell">
                                    {vendor.lastScan && vendor.lastScan !== 'Never'
                                      ? new Date(vendor.lastScan).toLocaleDateString()
                                      : 'Never'}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Subdomains by Vendor */}
                  {cardDetailsType === 'subdomains' && cardDetailsData.data && (() => {
                    const filteredData = cardDetailsData.data.filter((vendorData: any) => {
                      const searchLower = cardDetailsSearchTerm.toLowerCase();
                      return (
                        vendorData.vendor_name?.toLowerCase().includes(searchLower) ||
                        vendorData.domain?.toLowerCase().includes(searchLower)
                      );
                    });

                    return (
                      <div className="vendors-table-container">
                        <div className="table-info">
                          <span className="info-badge">
                            <i className="fas fa-building"></i>
                            {filteredData.length} of {cardDetailsData.total_vendors} Vendors
                          </span>
                          <span className="info-badge">
                            <i className="fas fa-sitemap"></i>
                            {filteredData.reduce((sum: number, v: any) => sum + v.subdomain_count, 0)} Alive Subdomains
                          </span>
                        </div>
                        <div className="responsive-table">
                          <table className="vendors-detail-table">
                            <thead>
                              <tr>
                                <th>Vendor</th>
                                <th>Domain</th>
                                <th>Alive Subdomains</th>
                              </tr>
                            </thead>
                            <tbody>
                              {filteredData.map((vendorData: any) => (
                                <tr
                                  key={vendorData.vendor_id}
                                  className="vendor-row clickable-row"
                                  onClick={() => router.push(`/report/${vendorData.domain}?from=${activeSection}`)}
                                  title="Click to view vendor report"
                                >
                                  <td>
                                    <div className="vendor-name-cell">
                                      <span className="vendor-name">{vendorData.vendor_name}</span>
                                    </div>
                                  </td>
                                  <td className="domain-cell">{vendorData.domain}</td>
                                  <td>
                                    <span className="subdomain-count-badge">
                                      {vendorData.subdomain_count.toLocaleString()}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Vulnerabilities by Vendor */}
                  {cardDetailsType === 'vulnerabilities' && cardDetailsData.data && (() => {
                    const filteredData = cardDetailsData.data.filter((vendorData: any) => {
                      const searchLower = cardDetailsSearchTerm.toLowerCase();
                      return (
                        vendorData.vendor_name?.toLowerCase().includes(searchLower) ||
                        vendorData.domain?.toLowerCase().includes(searchLower)
                      );
                    });

                    return (
                      <div className="vendors-table-container">
                        <div className="table-info">
                          <span className="info-badge">
                            <i className="fas fa-building"></i>
                            {filteredData.length} of {cardDetailsData.total_vendors} Vendors
                          </span>
                          <span className="info-badge">
                            <i className="fas fa-shield-alt"></i>
                            {filteredData.reduce((sum: number, v: any) => sum + v.vulnerability_count, 0)} Total Vulnerabilities
                          </span>
                        </div>
                        <div className="responsive-table">
                          <table className="vendors-detail-table">
                            <thead>
                              <tr>
                                <th>Vendor</th>
                                <th>Domain</th>
                                <th>Total</th>
                                <th>Critical</th>
                                <th>High</th>
                                <th>Medium</th>
                                <th>Low</th>
                              </tr>
                            </thead>
                            <tbody>
                              {filteredData.map((vendorData: any) => (
                                <tr
                                  key={vendorData.vendor_id}
                                  className="vendor-row clickable-row"
                                  onClick={() => router.push(`/report/${vendorData.domain}?from=${activeSection}`)}
                                  title="Click to view vendor report"
                                >
                                  <td>
                                    <div className="vendor-name-cell">
                                      <span className="vendor-name">{vendorData.vendor_name}</span>
                                    </div>
                                  </td>
                                  <td className="domain-cell">{vendorData.domain}</td>
                                  <td>
                                    <span className="vulnerability-count-badge">
                                      <i className="fas fa-exclamation-triangle"></i>
                                      {vendorData.vulnerability_count.toLocaleString()}
                                    </span>
                                  </td>
                                  <td>
                                    {vendorData.severity_breakdown.critical > 0 ? (
                                      <span className="severity-badge severity-critical">
                                        {vendorData.severity_breakdown.critical.toLocaleString()}
                                      </span>
                                    ) : (
                                      <span className="zero-count">-</span>
                                    )}
                                  </td>
                                  <td>
                                    {vendorData.severity_breakdown.high > 0 ? (
                                      <span className="severity-badge severity-high">
                                        {vendorData.severity_breakdown.high.toLocaleString()}
                                      </span>
                                    ) : (
                                      <span className="zero-count">-</span>
                                    )}
                                  </td>
                                  <td>
                                    {vendorData.severity_breakdown.medium > 0 ? (
                                      <span className="severity-badge severity-medium">
                                        {vendorData.severity_breakdown.medium.toLocaleString()}
                                      </span>
                                    ) : (
                                      <span className="zero-count">-</span>
                                    )}
                                  </td>
                                  <td>
                                    {vendorData.severity_breakdown.low > 0 ? (
                                      <span className="severity-badge severity-low">
                                        {vendorData.severity_breakdown.low.toLocaleString()}
                                      </span>
                                    ) : (
                                      <span className="zero-count">-</span>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    );
                  })()}

                  {/* High Risk Issues by Vendor */}
                  {cardDetailsType === 'high-risk' && cardDetailsData.data && (() => {
                    const filteredData = cardDetailsData.data.filter((vendorData: any) => {
                      const searchLower = cardDetailsSearchTerm.toLowerCase();
                      return (
                        vendorData.vendor_name?.toLowerCase().includes(searchLower) ||
                        vendorData.domain?.toLowerCase().includes(searchLower)
                      );
                    });

                    return (
                      <div className="vendors-table-container">
                        <div className="table-info">
                          <span className="info-badge">
                            <i className="fas fa-building"></i>
                            {filteredData.length} of {cardDetailsData.total_vendors} Vendors
                          </span>
                          <span className="info-badge critical">
                            <i className="fas fa-exclamation-circle"></i>
                            {filteredData.reduce((sum: number, v: any) => sum + v.high_risk_count, 0)} High Risk Issues
                          </span>
                        </div>
                        {filteredData.length > 0 ? (
                          <div className="responsive-table">
                            <table className="vendors-detail-table">
                              <thead>
                                <tr>
                                  <th>Vendor</th>
                                  <th>Domain</th>
                                  <th>Total High Risk</th>
                                  <th>Critical</th>
                                  <th>High</th>
                                </tr>
                              </thead>
                              <tbody>
                                {filteredData.map((vendorData: any) => (
                                  <tr
                                    key={vendorData.vendor_id}
                                    className="vendor-row high-risk-row clickable-row"
                                    onClick={() => router.push(`/report/${vendorData.domain}?from=${activeSection}`)}
                                    title="Click to view vendor report"
                                  >
                                    <td>
                                      <div className="vendor-name-cell">
                                        <span className="vendor-name">{vendorData.vendor_name}</span>
                                      </div>
                                    </td>
                                    <td className="domain-cell">{vendorData.domain}</td>
                                    <td>
                                      <span className="high-risk-count-badge">
                                        <i className="fas fa-exclamation-circle"></i>
                                        {vendorData.high_risk_count.toLocaleString()}
                                      </span>
                                    </td>
                                    <td>
                                      {vendorData.critical_count > 0 ? (
                                        <span className="severity-badge severity-critical">
                                          {vendorData.critical_count.toLocaleString()}
                                        </span>
                                      ) : (
                                        <span className="zero-count">-</span>
                                      )}
                                    </td>
                                    <td>
                                      {vendorData.high_count > 0 ? (
                                        <span className="severity-badge severity-high">
                                          {vendorData.high_count.toLocaleString()}
                                        </span>
                                      ) : (
                                        <span className="zero-count">-</span>
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <div className="no-data-message">
                            <i className="fas fa-check-circle"></i>
                            <h3>No High Risk Issues Found</h3>
                            <p>All vendors are performing well with no critical or high severity issues.</p>
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
              ) : (
                <div className="no-data-message">
                  <i className="fas fa-exclamation-triangle"></i>
                  <p>No data available</p>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={closeCardDetailsModal}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </Layout>
  );
};

// Loading component for Suspense fallback
const DashboardLoading = () => (
  <div style={{
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    height: '100vh',
    flexDirection: 'column',
    gap: '1rem'
  }}>
    <div className="loading-spinner"></div>
    <p>Loading Dashboard...</p>
  </div>
);

// Wrapper component with Suspense boundary
const DashboardPage = () => {
  return (
    <Suspense fallback={<DashboardLoading />}>
      <Dashboard />
    </Suspense>
  );
};

export default DashboardPage; 
