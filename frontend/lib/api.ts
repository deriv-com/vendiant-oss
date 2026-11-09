import axios, { InternalAxiosRequestConfig } from 'axios';
import { vendorCache, subdomainCache, dashboardCache, scanResultsCache, certificationCache } from './cache';
import { logger } from './logger';

// Extend axios config interface to include metadata
declare module 'axios' {
  interface InternalAxiosRequestConfig {
    metadata?: {
      startTime: number;
    };
  }
}

// Optimized API routing: Use nginx proxy for better performance and security
const getApiBaseUrl = () => {
  // Client-side (browser): use nginx proxy or environment-specific URL
  if (typeof window !== 'undefined') {
    // Check if NEXT_PUBLIC_API_URL is set (for deployed environments)
    if (process.env.NEXT_PUBLIC_API_URL) {
      return process.env.NEXT_PUBLIC_API_URL
    }
    
    // In production deployment, use nginx proxy (same origin)
    if (process.env.NODE_ENV === 'production') {
      // Use same origin - nginx will route /api/* to backend
      return ''
    }
    return '' // Empty string means same origin for local dev (Next.js proxy)
  }

  // Server-side (Next.js in Docker): INTERNAL_API_URL_PRODUCTION, falling back
  // to the compose service name.
  return (
    process.env.INTERNAL_API_URL_PRODUCTION ||
    (process.env.NODE_ENV === 'production' ? 'http://backend:5005' : 'http://localhost:5005')
  )
}

const API_BASE_URL = getApiBaseUrl()

console.log('API Base URL (PROXY SOLUTION):', API_BASE_URL, 'Client-side:', typeof window !== 'undefined')

// Create axios instance with proper proxy configuration
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000, // Increased to 2 minutes for long-running operations
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor with enhanced logging
api.interceptors.request.use(
  (config) => {
    const startTime = Date.now();
    config.metadata = { startTime };
    
    logger.apiRequest(
      config.method?.toUpperCase() || 'UNKNOWN',
      config.url || 'unknown',
      config.data
    );
    
    return config;
  },
  (error) => {
    logger.apiError('REQUEST', 'interceptor', error);
    return Promise.reject(error);
  }
);

// Response interceptor with enhanced logging
api.interceptors.response.use(
  (response) => {
    const endTime = Date.now();
    const startTime = response.config.metadata?.startTime || endTime;
    const duration = endTime - startTime;
    
    logger.apiResponse(
      response.config.method?.toUpperCase() || 'UNKNOWN',
      response.config.url || 'unknown',
      response.status,
      duration
    );
    
    return response;
  },
  (error) => {
    const endTime = Date.now();
    const startTime = error.config?.metadata?.startTime || endTime;
    const duration = endTime - startTime;
    
    if (error.response) {
      logger.apiResponse(
        error.config.method?.toUpperCase() || 'UNKNOWN',
        error.config.url || 'unknown',
        error.response.status,
        duration
      );
    } else {
      logger.apiError(
        error.config?.method?.toUpperCase() || 'UNKNOWN',
        error.config?.url || 'unknown',
        error
      );
    }
    
    return Promise.reject(error);
  }
);

// Type definitions matching Flask backend response structures
export interface Vendor {
  id: number;
  name: string;
  domain: string;
  category: string;
  riskLevel: string;
  scores: {
    current: number;
  };
  lastScan: string;
  logo: string;
  grade: string;
  addedAt: string;
  tier?: string;
  portfolio?: string;
  industry?: string;
  certifications?: {
    iso_27001: boolean;
    soc2: boolean;
    has_certifications: boolean;
  };
}

export interface DashboardStats {
  active_vendors: number;
  subdomains_monitored: number;
  vulnerabilities_found: number;
  high_risk_issues: number;
  overall_score: number;
  score_percentage: number;
  severity_breakdown: Record<string, number>;
  risk_distribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

export interface RecentScan {
  id?: string;
  domain: string;
  vendor_name?: string;
  scan_type: string;
  status: string;
  result?: string;
  score?: number;
  timestamp: string | number;
  time_ago?: string;
  results_summary?: string;
  score_category?: string;
}

export interface ScanResult {
  id: string;
  domain: string;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  results?: any;
  error?: string;
}

export interface SubdomainData {
  subdomain: string;
  status: string;
  id?: number;
}

export interface SubdomainDiscoveryResult {
  status: string;
  domain: string;
  method?: string;
  skipped_discovery?: boolean;
  message?: string;
  scan_id?: string; // For async scans
  statistics?: {
    total: number;
    alive: number;
    inactive: number;
    success_rate: number;
    from_database: boolean;
  };
  subdomains?: Array<{
    subdomain: string;
    status: string;
  }>;
  database_saved?: boolean;
  storage_mode?: string;
}

export interface VulnerabilityData {
  id: number;
  subdomain: string;
  title: string;
  description: string;
  severity: string;
  category: string;
}

export interface VulnerabilityScanResult {
  status: string;
  domain: string;
  final_score: number;
  max_score: number;
  subdomains_processed: number;
  vulnerabilities: Array<{
    subdomain: string;
    id: string;
    description: string;
    severity: string;
  }>;
  summary: {
    total_vulnerabilities: number;
    by_severity: {
      CRITICAL: number;
      HIGH: number;
      MEDIUM: number;
      LOW: number;
      INFO: number;
    };
    score_breakdown: {
      final_score: number;
      max_score: number;
      percentage: number;
    };
  };
  report_file?: string;
  database_status?: string;
  message?: string;
}

export interface DomainReputationResult {
  status: string;
  domain: string;
  final_score: number;
  max_score: number;
  vulnerabilities: Array<{
    domain: string;
    issue_type: string;
    description: string;
    severity: string;
  }>;
  statistics: {
    domains_processed: number;
    total_weight_deducted: number;
  };
  summary: {
    total_issues: number;
    total_weight_deducted: number;
    score_breakdown: {
      final_score: number;
      max_score: number;
      percentage: number;
    };
  };
  report_file?: string;
  database_status?: string;
  message?: string;
}

export interface DnsSecurityResult {
  status: string;
  domain: string;
  final_score: number;
  max_score: number;
  vulnerabilities: Array<{
    domain: string;
    title: string;
    description: string;
    severity: string;
  }>;
  statistics: {
    subdomains_processed: number;
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  summary: {
    total_issues: number;
    by_severity: {
      CRITICAL: number;
      HIGH: number;
      MEDIUM: number;
      LOW: number;
      INFO: number;
    };
    score_breakdown: {
      final_score: number;
      max_score: number;
      percentage: number;
    };
  };
  report_file?: string;
  database_status?: string;
  message?: string;
}

export interface NetworkScanResult {
  status: string;
  domain: string;
  final_score: number;
  max_score: number;
  processed_subdomains: number;
  vulnerabilities: Array<{
    subdomain: string;
    port: string;
    service: string;
    severity: string;
    description: string;
  }>;
  statistics: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  summary: {
    total_issues: number;
    by_severity: {
      CRITICAL: number;
      HIGH: number;
      MEDIUM: number;
      LOW: number;
      INFO: number;
    };
    score_breakdown: {
      final_score: number;
      max_score: number;
      percentage: number;
    };
  };
  db_status?: string;
  message?: string;
}

export interface EncryptionScanResult {
  status: string;
  scan_id?: string;
  message?: string;
  domain?: string;
  final_score?: number;
  max_score?: number;
  subdomains_processed?: number;
  vulnerabilities?: Array<{
    domain: string;
    vulnerability: string;
    severity: string;
    description: string;
    category: string;
  }>;
  statistics?: {
    domains_processed: number;
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  summary?: {
    total_vulnerabilities: number;
    by_severity: {
      CRITICAL: number;
      HIGH: number;
      MEDIUM: number;
      LOW: number;
      INFO: number;
    };
    score_breakdown: {
      final_score: number;
      max_score: number;
      percentage: number;
    };
  };
  report_file?: string;
  database_status?: string;
}

export interface EmailScanResult {
  status: string;
  domain: string;
  final_score: number;
  max_score: number;
  subdomains_processed: number;
  vulnerabilities: Array<{
    title: string;
    description: string;
    severity: string;
    subdomain: string;
    category: string;
  }>;
  statistics: {
    domains_processed: number;
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Info: number;
  };
  summary: {
    total_vulnerabilities: number;
    by_severity: {
      Critical: number;
      High: number;
      Medium: number;
      Low: number;
      Info: number;
    };
    score_breakdown: {
      final_score: number;
      max_score: number;
      percentage: number;
    };
  };
  database_status?: string;
  message?: string;
}

export interface IncidentResult {
  status: string;
  domain: string;
  since: string;
  summary: string;
  incidents: any[];
  news: any[];
  notes?: string;
}

export interface CertificationStats {
  total_vendors: number;
  iso_27001_count: number;
  soc2_count: number;
  both_certifications: number;
  no_certifications: number;
  certification_rate: number;
}

export interface CertificationResult {
  vendors: Vendor[];
  statistics: CertificationStats;
  filters_applied: {
    iso_27001?: boolean;
    soc2?: boolean;
    both_certifications?: boolean;
  };
}

export interface AddVendorResponse {
  success: boolean;
  message: string;
  vendor?: Vendor;
  error?: string;
  scan_job_id?: string;
  auto_scan_started?: boolean;
  scan_error?: string;
}

export interface UpdateVendorResponse {
  status: string;
  message: string;
  vendor?: Vendor;
  error?: string;
}

export interface VendorDetailsResponse {
  status: string;
  vendor: {
    id: number;
    vendor_name: string;
    domain: string;
    tier: string;
    portfolio: string;
    industry: string;
    security_score: number;
    grade: string;
    added_at?: string;
    updated_at?: string;
    logo?: string;
  };
}

export interface ValidationResponse {
  valid: boolean;
  message: string;
}

// Vendor API functions
export const vendorApi = {
  getVendors: async (): Promise<{ vendors: Vendor[] }> => {
    const response = await api.get('/api/vendors');
    return response.data;
  },

  // Cached version of getVendors
  getVendorsCached: async (): Promise<{ vendors: Vendor[] }> => {
    return vendorCache.getOrFetch('vendors', async () => {
      console.log('Fetching vendors from API (cache miss)');
      const response = await api.get('/api/vendors');
      console.log(`Cached ${response.data.vendors?.length || 0} vendors`);
      return response.data;
    });
  },

    getVendor: async (vendorId: number): Promise<{ vendor: Vendor }> => {
    const response = await api.get(`/api/vendors/${vendorId}`);
    return response.data;
  },

  addVendor: async (vendorData: { vendor_name: string; domain: string; tier?: string; portfolio?: string; industry?: string | null }): Promise<AddVendorResponse> => {
    const response = await api.post('/api/vendors/add', vendorData);
    return response.data;
  },

  deleteVendor: async (vendorId: number) => {
    const response = await api.delete(`/api/vendors/${vendorId}`);
    return response.data;
  },

  getVendorDetails: async (vendorId: number): Promise<VendorDetailsResponse> => {
    const response = await api.get(`/api/vendors/${vendorId}/details`);
    return response.data;
  },

  updateVendor: async (vendorId: number, vendorData: { vendor_name: string; domain: string; tier: string; portfolio: string; industry?: string }): Promise<UpdateVendorResponse> => {
    const response = await api.put(`/api/vendors/${vendorId}/update`, vendorData);
    return response.data;
  },

  validateDomain: async (vendorId: number, domain: string): Promise<ValidationResponse> => {
    const response = await api.get(`/api/vendors/${vendorId}/validate-domain?domain=${encodeURIComponent(domain)}`);
    return response.data;
  },

  validateName: async (vendorId: number, name: string): Promise<ValidationResponse> => {
    const response = await api.get(`/api/vendors/${vendorId}/validate-name?name=${encodeURIComponent(name)}`);
    return response.data;
  },

  reloadVendors: async () => {
    const response = await api.post('/api/vendors/reload');
    // Clear vendor and related caches when reloading
    vendorCache.clear();
    dashboardCache.clear(); // Dashboard stats may depend on vendor data
    console.log(' Cleared vendor and dashboard caches after reload');
    return response.data;
  },

  // Additional domains management
  getAdditionalDomains: async (vendorId: number) => {
    const response = await api.get(`/api/vendors/${vendorId}/additional-domains`);
    return response.data;
  },

  addAdditionalDomain: async (vendorId: number, domain: string) => {
    const response = await api.post(`/api/vendors/${vendorId}/additional-domains`, { domain });
    return response.data;
  },

  removeAdditionalDomain: async (vendorId: number, domain: string) => {
    const response = await api.delete(`/api/vendors/${vendorId}/additional-domains/${encodeURIComponent(domain)}`);
    return response.data;
  },

  // Get excluded subdomains for vendor
  getExcludedSubdomains: async (vendorId: number) => {
    const response = await api.get(`/api/vendors/${vendorId}/excluded-subdomains`);
    return response.data;
  },

  // Add subdomain to exclusion list
  addExcludedSubdomain: async (vendorId: number, subdomain: string) => {
    const response = await api.post(`/api/vendors/${vendorId}/excluded-subdomains`, {
      subdomain
    });
    return response.data;
  },

  // Remove subdomain from exclusion list
  removeExcludedSubdomain: async (vendorId: number, subdomain: string) => {
    const response = await api.delete(`/api/vendors/${vendorId}/excluded-subdomains/${encodeURIComponent(subdomain)}`);
    return response.data;
  },

  refreshScores: async () => {
    const response = await api.post('/api/vendors/refresh-scores');
    return response.data;
  },

  refreshVendorScore: async (vendorId: number) => {
    const response = await api.post(`/api/vendors/${vendorId}/refresh-score`);
    // Clear vendor and dashboard caches when refreshing individual score
    vendorCache.clear();
    dashboardCache.clear(); // Dashboard stats may depend on vendor scores
    console.log(` Cleared vendor and dashboard caches after refreshing score for vendor ${vendorId}`);
    return response.data;
  },

  calculateOverallScore: async (vendorId: number) => {
    const response = await api.post(`/api/vendors/${vendorId}/overall-score`);
    return response.data;
  },

  recalculateAllScores: async () => {
    const response = await api.post('/api/vendors/recalculate-all-scores');
    return response.data;
  }
};

// Dashboard API functions
export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    const response = await api.get('/api/dashboard/stats');
    return response.data;
  },

  // Cached version of getStats
  getStatsCached: async (): Promise<DashboardStats> => {
    return dashboardCache.getOrFetch('stats', async () => {
      console.log('Fetching dashboard stats from API (cache miss)');
      const response = await api.get('/api/dashboard/stats');
      console.log('Cached dashboard stats');
      return response.data;
    });
  },

  getRecentScans: async (): Promise<{ recent_scans: RecentScan[] }> => {
    // Add cache-busting parameter to ensure fresh data
    const timestamp = Date.now();
    const response = await api.get(`/api/dashboard/recent-scans?_t=${timestamp}`);
    return response.data;
  },

  // Cached version of getRecentScans (shorter cache time)
  getRecentScansCached: async (): Promise<{ recent_scans: RecentScan[] }> => {
    return dashboardCache.getOrFetch('recent_scans', async () => {
      console.log('Fetching recent scans from API (cache miss)');
      const response = await api.get('/api/dashboard/recent-scans');
      console.log(`Cached ${response.data.recent_scans?.length || 0} recent scans`);
      return response.data;
    });
  },

  getVendorsWithScores: async () => {
    const response = await api.get('/api/dashboard/vendors-with-scores');
    return response.data;
  },

  // Cached version of getVendorsWithScores
  getVendorsWithScoresCached: async () => {
    return dashboardCache.getOrFetch('vendors_with_scores', async () => {
      console.log('Fetching vendors with scores from API (cache miss)');
      const response = await api.get('/api/dashboard/vendors-with-scores');
      console.log(`Cached ${response.data.total || 0} vendors with scores`);
      return response.data;
    });
  },

  getSubdomainsByVendor: async () => {
    const response = await api.get('/api/dashboard/subdomains-by-vendor');
    return response.data;
  },

  // Cached version of getSubdomainsByVendor
  getSubdomainsByVendorCached: async () => {
    return dashboardCache.getOrFetch('subdomains_by_vendor', async () => {
      console.log('Fetching subdomains by vendor from API (cache miss)');
      const response = await api.get('/api/dashboard/subdomains-by-vendor');
      console.log(`Cached subdomains for ${response.data.total_vendors || 0} vendors`);
      return response.data;
    });
  },

  getVulnerabilitiesByVendor: async () => {
    const response = await api.get('/api/dashboard/vulnerabilities-by-vendor');
    return response.data;
  },

  // Cached version of getVulnerabilitiesByVendor
  getVulnerabilitiesByVendorCached: async () => {
    return dashboardCache.getOrFetch('vulnerabilities_by_vendor', async () => {
      console.log('Fetching vulnerabilities by vendor from API (cache miss)');
      const response = await api.get('/api/dashboard/vulnerabilities-by-vendor');
      console.log(`Cached ${response.data.total_vulnerabilities || 0} vulnerabilities for ${response.data.total_vendors || 0} vendors`);
      return response.data;
    });
  },

  getHighRiskByVendor: async () => {
    const response = await api.get('/api/dashboard/high-risk-by-vendor');
    return response.data;
  },

  // Cached version of getHighRiskByVendor
  getHighRiskByVendorCached: async () => {
    return dashboardCache.getOrFetch('high_risk_by_vendor', async () => {
      console.log('Fetching high-risk issues by vendor from API (cache miss)');
      const response = await api.get('/api/dashboard/high-risk-by-vendor');
      console.log(`Cached ${response.data.total_issues || 0} high-risk issues for ${response.data.total_vendors || 0} vendors`);
      return response.data;
    });
  }
};

// Subdomain API functions
export const subdomainApi = {
  discover: async (data: { domain: string; force_rediscovery?: boolean }): Promise<SubdomainDiscoveryResult> => {
    // Use the asynchronous discovery endpoint to avoid timeout issues
    const response = await api.post('/api/subdomains/discover-async', data);
    // Clear subdomain cache for this domain after discovery
    const cacheKey = subdomainCache.key('subdomains', { domain: data.domain });
    subdomainCache.delete(cacheKey);
    console.log(`Cleared subdomain cache for ${data.domain} after discovery`);
    return response.data;
  },
  
  discoverStatus: async (scanId: string) => {
    const response = await api.get(`/api/subdomains/discover-status/${scanId}`);
    return response.data;
  },
  
  stopDiscovery: async (scanId: string) => {
    const response = await api.post(`/api/subdomains/discover-stop/${scanId}`);
    return response.data;
  },

  addSubdomains: async (domain: string, subdomains: string[]) => {
    const response = await api.post('/api/subdomains/add', {
      domain,
      subdomains
    });
    // Clear subdomain cache for this domain after adding new subdomains
    const cacheKey = subdomainCache.key('subdomains', { domain });
    subdomainCache.delete(cacheKey);
    console.log(`Cleared subdomain cache for ${domain} after adding subdomains`);
    return response.data;
  },

  getSubdomains: async (domain: string) => {
    const response = await api.get(`/api/subdomains/${domain}`);
    return response.data;
  },

  // Cached version of getSubdomains
  getSubdomainsCached: async (domain: string) => {
    const cacheKey = subdomainCache.key('subdomains', { domain });
    return subdomainCache.getOrFetch(cacheKey, async () => {
      console.log(`Fetching subdomains for ${domain} from API (cache miss)`);
      const response = await api.get(`/api/subdomains/${domain}`);
      console.log(`Cached ${response.data.count?.total || 0} subdomains for ${domain}`);
      return response.data;
    });
  },

  getSubdomainsByVendor: async (vendorId: number) => {
    const response = await api.get(`/api/vendors/${vendorId}/subdomains`);
    return response.data;
  },

  // Cached version of getSubdomainsByVendor
  getSubdomainsByVendorCached: async (vendorId: number) => {
    const cacheKey = subdomainCache.key('vendor_subdomains', { vendorId });
    return subdomainCache.getOrFetch(cacheKey, async () => {
      console.log(`Fetching subdomains for vendor ${vendorId} from API (cache miss)`);
      const response = await api.get(`/api/vendors/${vendorId}/subdomains`);
      console.log(`Cached ${response.data.count || 0} subdomains for vendor ${vendorId}`);
      return response.data;
    });
  },

  checkStatus: async (domain: string) => {
    const response = await api.get(`/api/subdomains/check/${domain}`);
    return response.data;
  },

  addManualSubdomain: async (vendorId: number, subdomain: string, domain?: string) => {
    const response = await api.post(`/api/vendors/${vendorId}/subdomains/manual`, {
      subdomain
    });
    // Clear relevant caches after adding manual subdomain
    const vendorCacheKey = subdomainCache.key('vendor_subdomains', { vendorId });
    subdomainCache.delete(vendorCacheKey);
    
    // Also clear domain-specific cache if domain is provided
    if (domain) {
      const domainCacheKey = subdomainCache.key('subdomains', { domain });
      subdomainCache.delete(domainCacheKey);
      console.log(`Cleared subdomain cache for ${domain} after manual addition`);
    }
    
    console.log(`Cleared vendor subdomain cache for vendor ${vendorId} after manual addition`);
    return response.data;
  }
};

// Scan API functions
export const scanApi = {
  // Vulnerability scans
  startVulnerabilityScan: async (domain: string, scanId?: string): Promise<VulnerabilityScanResult> => {
    logger.scanStarted('vulnerability', domain, scanId);
    try {
      const response = await api.post('/api/vulnerabilities/scan', {
        domain,
        scan_id: scanId
      });
      logger.scanCompleted('vulnerability', domain, response.data, scanId);
      return response.data;
    } catch (error) {
      logger.scanError('vulnerability', domain, error, scanId);
      throw error;
    }
  },

  stopVulnerabilityScan: async (scanId: string) => {
    const response = await api.post('/api/vulnerabilities/scan/stop', {
      scan_id: scanId
    });
    return response.data;
  },

  // Reputation scans
  startReputationScan: async (domain: string, scanId?: string): Promise<DomainReputationResult> => {
    logger.scanStarted('reputation', domain, scanId);
    try {
      const response = await api.post('/api/reputation/scan', {
        domain,
        scan_id: scanId
      });
      logger.scanCompleted('reputation', domain, response.data, scanId);
      return response.data;
    } catch (error) {
      logger.scanError('reputation', domain, error, scanId);
      throw error;
    }
  },

  stopReputationScan: async (scanId: string) => {
    const response = await api.post('/api/reputation/scan/stop', {
      scan_id: scanId
    });
    return response.data;
  },

  // Network scans
  startNetworkScan: async (domain: string): Promise<{scan_id: string, status: string, message: string}> => {
    logger.scanStarted('network', domain);
    try {
      const response = await api.post('/api/network/scan', {
        domain
      });
      logger.info('scan', `Network scan initiated for ${domain}`, { scanId: response.data.scan_id });
      return response.data;
    } catch (error) {
      logger.scanError('network', domain, error);
      throw error;
    }
  },

  getNetworkScanStatus: async (scanId: string): Promise<any> => {
    const response = await api.get(`/api/network/scan/${scanId}/status`);
    return response.data;
  },

  stopNetworkScan: async (scanId: string): Promise<any> => {
    const response = await api.post(`/api/network/scan/${scanId}/stop`);
    return response.data;
  },



  // DNS scans (now async like network scans)
  startDnsScan: async (domain: string): Promise<{scan_id: string, status: string, message: string}> => {
    logger.scanStarted('dns', domain);
    try {
      const response = await api.post('/api/dns/scan', {
        domain
      });
      logger.info('scan', `DNS scan initiated for ${domain}`, { scanId: response.data.scan_id });
      return response.data;
    } catch (error) {
      logger.scanError('dns', domain, error);
      throw error;
    }
  },

  getDnsScanStatus: async (scanId: string): Promise<any> => {
    const response = await api.get(`/api/dns/scan/${scanId}/status`);
    return response.data;
  },

  stopDnsScan: async (scanId: string) => {
    const response = await api.post('/api/dns/scan/stop', {
      scan_id: scanId
    });
    return response.data;
  },

  // Encryption scans
  startEncryptionScan: async (domain: string, scanId?: string): Promise<EncryptionScanResult> => {
    // Use regular timeout since this now returns immediately with scan_id
    const response = await api.post('/api/encryption/scan', {
      domain,
      scan_id: scanId
    });
    return response.data;
  },

  getEncryptionScanStatus: async (scanId: string) => {
    const response = await api.get(`/api/encryption/scan/${scanId}/status`);
    return response.data;
  },

  stopEncryptionScan: async (scanId: string) => {
    // Use the main API instance for consistency
    const encryptionApi = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000, // Shorter timeout for stop requests
      headers: {
        'Content-Type': 'application/json',
      },
    });

    const response = await encryptionApi.post('/api/encryption/scan/stop', {
      scan_id: scanId
    });
    return response.data;
  },

  // Email scans
  startEmailScan: async (domain: string, scanId?: string): Promise<EmailScanResult> => {
    const response = await api.post('/api/email/scan', {
      domain,
      scan_id: scanId
    });
    return response.data;
  },

  stopEmailScan: async (scanId: string) => {
    const response = await api.post('/api/email/scan/stop', {
      scan_id: scanId
    });
    return response.data;
  },
};

// Report API functions
export const reportApi = {
  downloadReport: async (domain: string, type: string) => {
    const response = await api.get(`/api/reports/${domain}/download`, {
      params: { type },
      responseType: 'blob'
    });
    return response.data;
  },

  getVulnerabilityReport: async (domain: string, includeIncidents: boolean = false) => {
    const response = await api.get(`/api/vulnerabilities/report/${domain}`, {
      params: includeIncidents ? { include_incidents: 'true' } : {}
    });
    return response.data;
  },

  getReportIncidents: async (domain: string, months: number = 36) => {
    const response = await api.get(`/api/vulnerabilities/report/${domain}/incidents`, {
      params: { months }
    });
    return response.data;
  },

  exportToPdf: async (domain: string, data: any) => {
    const response = await api.post(`/api/reports/${domain}/export-pdf`, data, {
      responseType: 'blob'
    });
    return response.data;
  }
};

// Incident API functions
export const incidentApi = {
  getIncidents: async (domain: string, months: number = 12): Promise<IncidentResult> => {
    const response = await api.post('/api/incidents', {
      domain,
      months
    });
    return response.data;
  },
  
  getAllNews: async (months: number = 12, domain?: string): Promise<IncidentResult> => {
    const params = new URLSearchParams();
    params.append('months', months.toString());
    if (domain) {
      params.append('domain', domain);
    }
    
    const response = await api.get(`/api/news/all?${params.toString()}`);
    return response.data;
  },
  
  scanAllDomains: async (months: number = 12): Promise<any> => {
    // Start background scan (returns immediately with job_id)
    const response = await api.post('/api/news/scan-all', {
      months
    });
    return response.data;
  },
  
  getNewsScanStatus: async (jobId: string): Promise<any> => {
    const response = await api.get(`/api/news/scan-status/${jobId}`);
    return response.data;
  }
};

// Certification API functions
export const certificationApi = {
  getCertifications: async (filters?: {
    iso_27001?: boolean;
    soc2?: boolean;
    both_certifications?: boolean;
  }): Promise<CertificationResult> => {
    const params = new URLSearchParams();
    if (filters?.iso_27001 !== undefined) params.append('iso_27001', filters.iso_27001.toString());
    if (filters?.soc2 !== undefined) params.append('soc2', filters.soc2.toString());
    if (filters?.both_certifications !== undefined) params.append('both_certifications', filters.both_certifications.toString());
    
    const response = await api.get(`/api/certifications?${params.toString()}`);
    return response.data;
  },

  // Cached version of getCertifications
  getCertificationsCached: async (filters?: {
    iso_27001?: boolean;
    soc2?: boolean;
    both_certifications?: boolean;
  }): Promise<CertificationResult> => {
    const cacheKey = certificationCache.key('certifications', filters || {});
    
    return await certificationCache.getOrFetch(
      cacheKey,
      () => certificationApi.getCertifications(filters)
    );
  },

  getStatistics: async (): Promise<CertificationStats> => {
    const response = await api.get('/api/certifications/statistics');
    return response.data;
  },

  // Cached version of getStatistics
  getStatisticsCached: async (): Promise<CertificationStats> => {
    const cacheKey = 'certification_statistics';
    
    return await certificationCache.getOrFetch(
      cacheKey,
      () => certificationApi.getStatistics()
    );
  },

  checkCertifications: async (domains?: string[], checkAll: boolean = false) => {
    const response = await api.post('/api/certifications/check', {
      domains,
      check_all: checkAll
    });
    
    // Clear certification cache after checking/updating certifications
    certificationCache.clear('certifications');
    certificationCache.clear('certification_statistics');
    
    return response.data;
  },

  getStatus: async () => {
    const response = await api.get('/api/certifications/status');
    return response.data;
  },

  updateCertifications: async (domain: string, certifications: { iso_27001: boolean; soc2: boolean }) => {
    const response = await api.put(`/api/certifications/${encodeURIComponent(domain)}`, certifications);
    // Clear certification cache after updating
    certificationCache.clear('certifications');
    certificationCache.clear('certification_statistics');
    return response.data;
  }
};

// Utility API functions
export const utilityApi = {
  getScores: async (domain: string) => {
    const response = await api.get(`/api/scores/${domain}`);
    return response.data;
  },

  getVulnerabilitiesFromDb: async (domain: string, category?: string) => {
    const params = category ? `?category=${category}` : '';
    const response = await api.get(`/api/vulnerabilities-db/${domain}${params}`);
    return response.data;
  },

  getScoresByCategory: async (domain: string, category: string) => {
    const response = await api.get(`/api/scores/${domain}/${category}`);
    return response.data;
  },

  cleanupVulnerabilities: async (domain?: string, category?: string) => {
    const response = await api.post('/api/vulnerabilities/cleanup-duplicates', {
      domain,
      category
    });
    return response.data;
  }
};

// Breach Monitor API functions
export const breachMonitorApi = {
  getBreaches: async (limit?: number, offset?: number): Promise<any> => {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (offset) params.append('offset', offset.toString());
    
    const response = await api.get(`/api/breach-monitor?${params.toString()}`);
    return response.data;
  },

  getStats: async (): Promise<any> => {
    const response = await api.get('/api/breach-monitor/stats');
    return response.data;
  },

  queryByDomain: async (domain: string, nextId: string = ''): Promise<any> => {
    try {
      const response = await api.post('/api/breach-monitor/query', {
        type: 'domain',
        domain: domain?.trim(),
        next_id: nextId || undefined
      });
      return response.data;
    } catch (error: any) {
      const errorMessage = error?.response?.data?.detail || error?.response?.data?.message || error?.message || 'Unknown error';
      throw new Error(errorMessage);
    }
  },

  queryByEmail: async (email: string, nextId: string = ''): Promise<any> => {
    try {
      const response = await api.post('/api/breach-monitor/query', {
        type: 'email',
        email: email?.trim(),
        next_id: nextId || undefined
      });
      return response.data;
    } catch (error: any) {
      const errorMessage = error?.response?.data?.detail || error?.response?.data?.message || error?.message || 'Unknown error';
      throw new Error(errorMessage);
    }
  },

  /** Admin: sync configured domains (BREACH_MONITOR_DOMAIN_GROUPS) from Breach Monitor API; decrements quota per API call. */
  refresh: async (): Promise<any> => {
    const response = await api.get('/api/breach-monitor/refresh');
    return response.data;
  },

  search: async (email?: string, domain?: string, source?: string): Promise<any> => {
    const response = await api.post('/api/breach-monitor/search', {
      email,
      domain,
      source
    });
    return response.data;
  },

  getHealth: async (): Promise<any> => {
    const response = await api.get('/api/breach-monitor/health');
    return response.data;
  },

  getQuota: async (): Promise<{ status: number; calls_remaining: number }> => {
    const response = await api.get('/api/breach-monitor/quota');
    return response.data;
  },

  exportToExcel: async (
    params: Record<string, string | string[] | undefined>,
  ): Promise<Blob> => {
    const response = await api.post('/api/breach-monitor/export', params, {
      responseType: 'blob',
    });
    return response.data;
  },
};


export interface BreachMatch {
  vendor: {
    id: number;
    vendor_name: string;
    domain: string;
  };
  breach: {
    breach_name: string;
    description: string;
    link: string;
    pub_date: string;
    account_count?: number;
  };
  confidence: number;
  match_type: string;
  match_reasons: string[];
}
export interface BreachCheckResult {
  status: string;
  message: string;
  data: {
    total_breaches: number;
    total_vendors: number;
    matches_found: number;
    matches: BreachMatch[];
    last_checked: string;
    summary: string;
  };
}
// Breach Monitor API functions
export const breachApi = {
  checkAllBreaches: async (): Promise<BreachCheckResult> => {
    const response = await api.get('/api/breaches/check');
    return response.data;
  }
};

// Background Scan API interfaces
export interface BackgroundScanJob {
  job_id: string;
  status: 'starting' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  current_domain?: string;
  stage?: string;
  total_domains: number;
  completed_count: number;
  failed_count: number;
  runtime?: string;
  estimated_remaining?: string;
  start_time?: string;
  end_time?: string;
  error?: string;
  logs?: string[];
}

export interface BackgroundScanResponse {
  status: string;
  job_id?: string;
  message: string;
  estimated_duration?: string;
}

export interface BackgroundScanStatusResponse {
  status: string;
  job?: BackgroundScanJob;
  message?: string;
}

export interface BackgroundScanListResponse {
  status: string;
  jobs: BackgroundScanJob[];
  active_jobs: number;
}

// Background Scan API functions
export const backgroundScanApi = {
  // Start a background full scan for all domains
  startFullScan: async (includeSubdomains: boolean = true, checkpointVendor: string = ''): Promise<BackgroundScanResponse> => {
    logger.info('scan', `Starting background full scan for all domains with subdomains: ${includeSubdomains}, checkpoint: ${checkpointVendor || 'none'}`);
    try {
      const requestData: any = { include_subdomains: includeSubdomains };
      if (checkpointVendor) {
        requestData.checkpoint_vendor = checkpointVendor;
      }
      const response = await api.post('/api/background-scan/start', requestData);
      logger.success('scan', 'Background full scan started successfully', { 
        jobId: response.data.job_id,
        includeSubdomains: includeSubdomains,
        checkpointVendor: checkpointVendor || 'none'
      });
      return response.data;
    } catch (error) {
      logger.error('scan', 'Failed to start background full scan', error);
      throw error;
    }
  },

  // Start a background filtered scan for vendors matching filters
  startFilteredScan: async (includeSubdomains: boolean = true, vendorFilters: any = {}): Promise<BackgroundScanResponse> => {
    logger.info('scan', `Starting background filtered scan with subdomains: ${includeSubdomains}, filters:`, vendorFilters);
    try {
      const requestData = { 
        include_subdomains: includeSubdomains,
        vendor_filters: vendorFilters
      };
      const response = await api.post('/api/background-scan/start', requestData);
      logger.success('scan', 'Background filtered scan started successfully', { 
        jobId: response.data.job_id,
        includeSubdomains: includeSubdomains,
        filters: vendorFilters
      });
      return response.data;
    } catch (error) {
      logger.error('scan', 'Failed to start background filtered scan', error);
      throw error;
    }
  },

  // Start a background scan for a single domain
  startSingleDomainScan: async (domain: string): Promise<BackgroundScanResponse> => {
    logger.info('scan', `Starting background scan for domain: ${domain}`);
    try {
      const response = await api.post('/api/background-scan/start', { domain });
      logger.success('scan', 'Background single domain scan started successfully', { 
        jobId: response.data.job_id,
        domain: domain
      });
      return response.data;
    } catch (error) {
      logger.error('scan', `Failed to start background scan for ${domain}`, error);
      throw error;
    }
  },

  // Get status of a specific background scan job
  getJobStatus: async (jobId: string): Promise<BackgroundScanStatusResponse> => {
    const response = await api.get(`/api/background-scan/status/${jobId}`);
    return response.data;
  },

  // List all background scan jobs
  listJobs: async (): Promise<BackgroundScanListResponse> => {
    const response = await api.get('/api/background-scan/list');
    return response.data;
  },

  // Cancel a running background scan job
  cancelJob: async (jobId: string): Promise<{ status: string; message: string }> => {
    logger.warn('scan', `Cancelling background scan job: ${jobId}`);
    try {
      const response = await api.post(`/api/background-scan/cancel/${jobId}`);
      logger.info('scan', 'Background scan job cancelled', { jobId });
      return response.data;
    } catch (error) {
      logger.error('scan', 'Failed to cancel background scan job', { jobId, error });
      throw error;
    }
  },

  // Monitor a background scan job with polling
  monitorJob: async (
    jobId: string, 
    onUpdate: (job: BackgroundScanJob) => void,
    intervalMs: number = 5000
  ): Promise<BackgroundScanJob> => {
    return new Promise((resolve, reject) => {
      const poll = async () => {
        try {
          const response = await backgroundScanApi.getJobStatus(jobId);
          if (response.status === 'success' && response.job) {
            const job = response.job;
            onUpdate(job);
            
            // Check if job is finished
            if (['completed', 'failed', 'cancelled'].includes(job.status)) {
              resolve(job);
              return;
            }
            
            // Continue polling
            setTimeout(poll, intervalMs);
          } else {
            reject(new Error(response.message || 'Failed to get job status'));
          }
        } catch (error) {
          reject(error);
        }
      };
      
      poll();
    });
  },

  // Get resume information for continuing a full scan
  getResumeInfo: async (): Promise<any> => {
    try {
      const response = await api.get('/api/background-scan/resume-info');
      return response.data;
    } catch (error) {
      logger.error('scan', 'Failed to get resume info', error);
      throw error;
    }
  }
};


// Cache management utilities
export const cacheUtils = {
  // Clear all caches
  clearAll: () => {
    vendorCache.clear();
    subdomainCache.clear();
    dashboardCache.clear();
    scanResultsCache.clear();
    certificationCache.clear();
    console.log('Cleared all caches');
  },

  // Clear vendor-related caches
  clearVendorCaches: () => {
    vendorCache.clear();
    console.log('Cleared vendor caches');
  },

  // Clear certification caches
  clearCertificationCaches: () => {
    certificationCache.clear();
    console.log('Cleared certification caches');
  },

  // Clear subdomain caches for a specific domain
  clearSubdomainCache: (domain: string) => {
    const cacheKey = subdomainCache.key('subdomains', { domain });
    subdomainCache.delete(cacheKey);
    console.log(`Cleared subdomain cache for ${domain}`);
  },

  // Clear dashboard caches
  clearDashboardCaches: () => {
    dashboardCache.clear();
    console.log('Cleared dashboard caches');
  },

  // Clear specific modal data caches
  clearModalDataCaches: () => {
    dashboardCache.delete('vendors_with_scores');
    dashboardCache.delete('subdomains_by_vendor');
    dashboardCache.delete('vulnerabilities_by_vendor');
    dashboardCache.delete('high_risk_by_vendor');
    console.log('Cleared modal data caches');
  },

  // Get cache statistics
  getCacheStats: () => {
    return {
      vendor: vendorCache.getStats(),
      subdomain: subdomainCache.getStats(),
      dashboard: dashboardCache.getStats(),
      scanResults: scanResultsCache.getStats(),
      certification: certificationCache.getStats()
    };
  },

  // Warm up critical caches
  warmUpCaches: async () => {
    console.log('Warming up caches...');
    try {
      await Promise.all([
        vendorApi.getVendorsCached(),
        dashboardApi.getStatsCached(),
        dashboardApi.getRecentScansCached(),
        certificationApi.getStatisticsCached()
      ]);
      console.log('Cache warm-up completed');
    } catch (error) {
      console.error('Cache warm-up failed:', error);
    }
  }
};

export default api; 