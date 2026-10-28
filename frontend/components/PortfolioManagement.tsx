'use client';

import React, { useEffect, useState } from 'react';
import CreatePortfolioModal from './CreatePortfolioModal';
import ManagePortfolioModal from './ManagePortfolioModal';
import ConfirmationModal from './ConfirmationModal';
import { usePermission } from '../lib/rbac';
import { apiRequest } from '../lib/api-client';

interface PortfolioStats {
  portfolio: string;
  vendor_count: number;
  avg_score: number;
  min_score?: number;
  max_score?: number;
  vendors: string[];
  domains: string[];
  scores: number[];
}

interface CommonVendor {
  vendor_name: string;
  domain: string;
  score1: number;
  score2: number;
  avg_score: number;
}

interface ComparisonData {
  portfolio1: string;
  portfolio2: string;
  common_vendors: CommonVendor[];
  common_count: number;
  timestamp: string;
}

interface PortfolioData {
  portfolios: PortfolioStats[];
  total_portfolios: number;
  timestamp: string;
}

const PortfolioManagement: React.FC = () => {
  const [portfolioData, setPortfolioData] = useState<PortfolioData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedPortfolio, setExpandedPortfolio] = useState<string | null>(null);
  
  // Permission checks
  const canViewPortfolios = usePermission('view_portfolios');
  const canCreatePortfolios = usePermission('create_portfolios');
  const canManagePortfolios = usePermission('manage_portfolios');
  const canDeletePortfolios = usePermission('delete_portfolios');
  
  // Filter and sort states
  const [sortBy, setSortBy] = useState<'portfolio' | 'avg_score' | 'vendor_count'>('avg_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [expandedSearchTerms, setExpandedSearchTerms] = useState<{[key: string]: string}>({});

  // Comparison states
  const [showComparison, setShowComparison] = useState(false);
  const [selectedPortfolio1, setSelectedPortfolio1] = useState<string>('');
  const [selectedPortfolio2, setSelectedPortfolio2] = useState<string>('');

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
  const [comparisonData, setComparisonData] = useState<ComparisonData | null>(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);

  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showManageModal, setShowManageModal] = useState(false);
  const [selectedPortfolioForManagement, setSelectedPortfolioForManagement] = useState<string>('');
  
  // Delete confirmation modal states
  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  const [portfolioToDelete, setPortfolioToDelete] = useState<string>('');
  const [deleteLoading, setDeleteLoading] = useState(false);

  useEffect(() => {
    if (canViewPortfolios) {
      fetchPortfolioData();
    } else {
      setLoading(false);
    }
  }, [canViewPortfolios]);

  const fetchPortfolioData = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await apiRequest('/api/portfolios/stats');
      
      if (!response.ok) {
        throw new Error(`Failed to fetch portfolio data: ${response.statusText}`);
      }

      const data = await response.json();
      setPortfolioData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load portfolio data');
      console.error('Error fetching portfolio data:', err);
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 800) return '#10b981'; // Green
    if (score >= 600) return '#f59e0b'; // Yellow
    if (score >= 400) return '#f97316'; // Orange
    return '#ef4444'; // Red
  };

  const getGradeFromScore = (score: number) => {
    if (score >= 900) return 'A+';
    if (score >= 800) return 'A';
    if (score >= 700) return 'B';
    if (score >= 600) return 'C';
    if (score >= 500) return 'D';
    return 'F';
  };

  const togglePortfolioExpansion = (portfolio: string) => {
    setExpandedPortfolio(expandedPortfolio === portfolio ? null : portfolio);
  };

  // Filter and sort portfolios
  const getFilteredAndSortedPortfolios = () => {
    if (!portfolioData) return [];

    let filtered = portfolioData.portfolios;

    // Sort portfolios
    filtered.sort((a, b) => {
      let aValue: string | number;
      let bValue: string | number;

      switch (sortBy) {
        case 'portfolio':
          aValue = a.portfolio.toLowerCase();
          bValue = b.portfolio.toLowerCase();
          break;
        case 'avg_score':
          aValue = a.avg_score;
          bValue = b.avg_score;
          break;
        case 'vendor_count':
          aValue = a.vendor_count;
          bValue = b.vendor_count;
          break;
        default:
          aValue = a.avg_score;
          bValue = b.avg_score;
      }

      if (sortOrder === 'asc') {
        return aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
      } else {
        return aValue > bValue ? -1 : aValue < bValue ? 1 : 0;
      }
    });

    return filtered;
  };

  const handleSortChange = (newSortBy: 'portfolio' | 'avg_score' | 'vendor_count') => {
    if (sortBy === newSortBy) {
      // Toggle sort order if clicking the same column
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new sort column with default desc order
      setSortBy(newSortBy);
      setSortOrder('desc');
    }
  };

  const comparePortfolios = async () => {
    if (!selectedPortfolio1 || !selectedPortfolio2) {
      alert('Please select both portfolios to compare');
      return;
    }

    if (selectedPortfolio1 === selectedPortfolio2) {
      alert('Please select different portfolios to compare');
      return;
    }

    try {
      setComparisonLoading(true);
      const response = await apiRequest('/api/portfolios/compare', {
        method: 'POST',
        body: JSON.stringify({
          portfolio1: selectedPortfolio1,
          portfolio2: selectedPortfolio2,
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to compare portfolios: ${response.statusText}`);
      }

      const data = await response.json();
      setComparisonData(data);
    } catch (err) {
      console.error('Error comparing portfolios:', err);
      alert('Failed to compare portfolios. Please try again.');
    } finally {
      setComparisonLoading(false);
    }
  };

  const clearComparison = () => {
    setSelectedPortfolio1('');
    setSelectedPortfolio2('');
    setComparisonData(null);
  };

  const handleDeletePortfolioClick = (portfolioName: string) => {
    setPortfolioToDelete(portfolioName);
    setShowDeleteConfirmation(true);
  };

  const handleDeletePortfolio = async () => {
    try {
      setDeleteLoading(true);
      
      const response = await apiRequest(`/api/portfolios/${encodeURIComponent(portfolioToDelete)}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to delete portfolio');
      }

      // Refresh portfolio data
      await fetchPortfolioData();
      
      // Clear any selections that might reference the deleted portfolio
      if (selectedPortfolio1 === portfolioToDelete) setSelectedPortfolio1('');
      if (selectedPortfolio2 === portfolioToDelete) setSelectedPortfolio2('');
      if (expandedPortfolio === portfolioToDelete) setExpandedPortfolio(null);
      
      // Close modal and reset state
      setShowDeleteConfirmation(false);
      setPortfolioToDelete('');
      
    } catch (err) {
      console.error('Error deleting portfolio:', err);
      setError(`Failed to delete portfolio: ${err instanceof Error ? err.message : 'Unknown error'}`);
      setShowDeleteConfirmation(false);
    } finally {
      setDeleteLoading(false);
    }
  };

  const handleManagePortfolio = (portfolioName: string) => {
    setSelectedPortfolioForManagement(portfolioName);
    setShowManageModal(true);
  };

  const handleModalSuccess = () => {
    fetchPortfolioData();
  };

  if (!canViewPortfolios) {
    return (
      <div className="portfolio-error-container">
        <p>You do not have permission to view portfolios.</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="portfolio-loading-container">
        <div className="animate-pulse">
          <div style={{ height: '24px', backgroundColor: '#f3f4f6', borderRadius: '4px', width: '200px', marginBottom: '1rem' }}></div>
          <div style={{ height: '300px', backgroundColor: '#f3f4f6', borderRadius: '4px' }}></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="portfolio-error-container">
        <h2 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
          Portfolios
        </h2>
        <div style={{ color: '#ef4444', textAlign: 'center', padding: '2rem' }}>
          <p>Error loading portfolio data: {error}</p>
          <button 
            onClick={fetchPortfolioData}
            style={{
              marginTop: '1rem',
              padding: '0.5rem 1rem',
              backgroundColor: '#3b82f6',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer'
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!portfolioData || portfolioData.portfolios.length === 0) {
    return (
      <div className="portfolio-empty-container">
        <h2 style={{ fontSize: '1.5rem', fontWeight: '600', color: '#1f2937', marginBottom: '1rem' }}>
          Portfolios
        </h2>
        <div style={{ color: '#6b7280', textAlign: 'center', padding: '2rem' }}>
          <p>No portfolio data available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="portfolio-main-container">
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '1rem'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem'
        }}>
          <div style={{
            background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
            borderRadius: '10px',
            padding: '0.75rem',
            boxShadow: '0 4px 12px rgba(59, 130, 246, 0.3)'
          }}>
            <i className="fas fa-briefcase" style={{ color: 'white', fontSize: '1.25rem' }}></i>
          </div>
          <h2 style={{
            margin: 0,
            fontSize: '1.5rem',
            fontWeight: '700',
            background: 'linear-gradient(135deg, #1f2937 0%, #374151 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            Portfolios
          </h2>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {canCreatePortfolios && (
            <button
              onClick={() => setShowCreateModal(true)}
              style={{
                padding: '0.75rem 1.25rem',
                background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                fontSize: '0.875rem',
                fontWeight: '600',
                cursor: 'pointer',
                boxShadow: '0 2px 8px rgba(16, 185, 129, 0.3)',
                transition: 'all 0.2s ease'
              }}
              onMouseEnter={(e) => {
                const target = e.target as HTMLButtonElement;
                target.style.transform = 'translateY(-1px)';
                target.style.boxShadow = '0 4px 12px rgba(16, 185, 129, 0.4)';
              }}
              onMouseLeave={(e) => {
                const target = e.target as HTMLButtonElement;
                target.style.transform = 'translateY(0)';
                target.style.boxShadow = '0 2px 8px rgba(16, 185, 129, 0.3)';
              }}
            >
              <i className="fas fa-plus" style={{ marginRight: '0.5rem' }}></i>
              Create Portfolio
            </button>
          )}
          <div className="portfolio-count-badge" style={{
            fontSize: '0.875rem',
            color: '#475569',
            background: 'linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%)',
            padding: '0.75rem 1.25rem',
            borderRadius: '20px',
            border: '1px solid #cbd5e1',
            boxShadow: '0 2px 8px rgba(0, 0, 0, 0.05)',
            fontWeight: '600'
          }}>
            <i className="fas fa-layer-group" style={{ marginRight: '0.5rem', color: '#3b82f6' }}></i>
            {portfolioData.total_portfolios} Portfolios
          </div>
        </div>
      </div>

      {/* Portfolio Comparison Section */}
      <div className="portfolio-comparison-section">
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1rem'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem'
          }}>
            <div style={{
              background: 'linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%)',
              borderRadius: '8px',
              padding: '0.5rem',
              boxShadow: '0 2px 8px rgba(14, 165, 233, 0.3)'
            }}>
              <i className="fas fa-balance-scale" style={{ color: 'white', fontSize: '1rem' }}></i>
            </div>
            <h3 className="portfolio-comparison-title">
              Portfolio Filtering
            </h3>
          </div>
          <button
            onClick={() => setShowComparison(!showComparison)}
            style={{
              padding: '0.5rem 1rem',
              background: showComparison ? 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)' : 'linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%)',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              fontSize: '0.875rem',
              fontWeight: '600',
              cursor: 'pointer',
              boxShadow: '0 2px 8px rgba(14, 165, 233, 0.3)',
              transition: 'all 0.2s ease'
            }}
          >
            <i className={`fas ${showComparison ? 'fa-times' : 'fa-plus'}`} style={{ marginRight: '0.5rem' }}></i>
            {showComparison ? 'Hide Filtering' : 'Filter Portfolios'}
          </button>
        </div>

        {showComparison && (
          <div>
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr auto auto',
              gap: '1rem',
              alignItems: 'end',
              marginBottom: '1rem'
            }}>
              <div>
                <label style={{
                  display: 'block',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  color: '#0c4a6e',
                  marginBottom: '0.5rem'
                }}>
                  Portfolio 1:
                </label>
                <select
                  value={selectedPortfolio1}
                  onChange={(e) => setSelectedPortfolio1(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #bae6fd',
                    borderRadius: '8px',
                    fontSize: '0.875rem',
                    background: 'white',
                    cursor: 'pointer',
                    outline: 'none',
                    color: selectedPortfolio1 ? '#374151' : '#9ca3af'
                  }}
                >
                  <option value="" disabled hidden>Select Portfolio 1</option>
                  {portfolioData?.portfolios.map(p => (
                    <option key={p.portfolio} value={p.portfolio}>
                      {p.portfolio} ({p.vendor_count} vendors)
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{
                  display: 'block',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  color: '#0c4a6e',
                  marginBottom: '0.5rem'
                }}>
                  Portfolio 2:
                </label>
                <select
                  value={selectedPortfolio2}
                  onChange={(e) => setSelectedPortfolio2(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #bae6fd',
                    borderRadius: '8px',
                    fontSize: '0.875rem',
                    background: 'white',
                    cursor: 'pointer',
                    outline: 'none',
                    color: selectedPortfolio2 ? '#374151' : '#9ca3af'
                  }}
                >
                  <option value="" disabled hidden>Select Portfolio 2</option>
                  {portfolioData?.portfolios.map(p => (
                    <option key={p.portfolio} value={p.portfolio}>
                      {p.portfolio} ({p.vendor_count} vendors)
                    </option>
                  ))}
                </select>
              </div>
              <button
                onClick={comparePortfolios}
                disabled={comparisonLoading || !selectedPortfolio1 || !selectedPortfolio2}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: comparisonLoading ? '#9ca3af' : 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                  color: 'white',
                  border: 'none',
                  borderRadius: '8px',
                  fontSize: '0.875rem',
                  fontWeight: '600',
                  cursor: comparisonLoading ? 'not-allowed' : 'pointer',
                  boxShadow: '0 2px 8px rgba(16, 185, 129, 0.3)',
                  transition: 'all 0.2s ease'
                }}
              >
                {comparisonLoading ? (
                  <>
                    <i className="fas fa-spinner fa-spin" style={{ marginRight: '0.5rem' }}></i>
                    Comparing...
                  </>
                ) : (
                  <>
                    <i className="fas fa-search" style={{ marginRight: '0.5rem' }}></i>
                    Compare
                  </>
                )}
              </button>
              <button
                onClick={clearComparison}
                disabled={comparisonLoading}
                style={{
                  padding: '0.75rem 1.25rem',
                  background: comparisonLoading ? '#9ca3af' : 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)',
                  color: 'white',
                  border: 'none',
                  borderRadius: '8px',
                  fontSize: '0.875rem',
                  fontWeight: '600',
                  cursor: comparisonLoading ? 'not-allowed' : 'pointer',
                  boxShadow: '0 2px 8px rgba(107, 114, 128, 0.3)',
                  transition: 'all 0.2s ease'
                }}
                onMouseEnter={(e) => {
                  if (!comparisonLoading) {
                    const target = e.target as HTMLButtonElement;
                    target.style.transform = 'translateY(-1px)';
                    target.style.boxShadow = '0 4px 12px rgba(107, 114, 128, 0.4)';
                  }
                }}
                onMouseLeave={(e) => {
                  const target = e.target as HTMLButtonElement;
                  target.style.transform = 'translateY(0)';
                  target.style.boxShadow = '0 2px 8px rgba(107, 114, 128, 0.3)';
                }}
              >
                <i className="fas fa-times" style={{ marginRight: '0.5rem' }}></i>
                Clear
              </button>
            </div>

            {/* Comparison Results */}
            {comparisonData && (
              <div className="portfolio-comparison-results">
                <h4 style={{
                  margin: '0 0 1rem 0',
                  fontSize: '1rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-primary)' : '#0c4a6e'
                }}>
                  Common Vendors: {comparisonData.portfolio1} vs {comparisonData.portfolio2}
                </h4>
                
                {comparisonData.common_vendors.length === 0 ? (
                  <p style={{ 
                    color: isDarkMode ? 'var(--text-secondary)' : '#6b7280', 
                    fontStyle: 'italic' 
                  }}>
                    No common vendors found between these portfolios.
                  </p>
                ) : (
                  <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                    <table style={{
                      width: '100%',
                      borderCollapse: 'separate',
                      borderSpacing: '0',
                      fontSize: '0.875rem'
                    }}>
                      <thead>
                        <tr style={{ 
                          background: isDarkMode ? 'var(--bg-primary)' : '#f8fafc', 
                          borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e2e8f0' 
                        }}>
                          <th style={{ 
                            padding: '0.75rem', 
                            textAlign: 'left', 
                            fontWeight: '600',
                            color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                          }}>Vendor</th>
                          <th style={{ 
                            padding: '0.75rem', 
                            textAlign: 'center', 
                            fontWeight: '600',
                            color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                          }}>Domain</th>
                          <th style={{ 
                            padding: '0.75rem', 
                            textAlign: 'center', 
                            fontWeight: '600',
                            color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                          }}>{comparisonData.portfolio1}</th>
                          <th style={{ 
                            padding: '0.75rem', 
                            textAlign: 'center', 
                            fontWeight: '600',
                            color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                          }}>{comparisonData.portfolio2}</th>
                          <th style={{ 
                            padding: '0.75rem', 
                            textAlign: 'center', 
                            fontWeight: '600',
                            color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                          }}>Avg Score</th>
                        </tr>
                      </thead>
                      <tbody>
                        {comparisonData.common_vendors.map((vendor, idx) => (
                          <tr key={idx} style={{
                            background: idx % 2 === 0 ? 
                              (isDarkMode ? 'var(--bg-secondary)' : 'white') : 
                              (isDarkMode ? 'var(--bg-primary)' : '#f8fafc'),
                            borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb'
                          }}>
                            <td style={{ 
                              padding: '0.75rem', 
                              fontWeight: '500',
                              color: isDarkMode ? 'var(--text-primary)' : 'inherit'
                            }}>{vendor.vendor_name}</td>
                            <td style={{ 
                              padding: '0.75rem', 
                              textAlign: 'center', 
                              color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
                            }}>{vendor.domain}</td>
                            <td style={{ padding: '0.75rem', textAlign: 'center', fontWeight: '600', color: getScoreColor(vendor.score1) }}>
                              {vendor.score1}
                            </td>
                            <td style={{ padding: '0.75rem', textAlign: 'center', fontWeight: '600', color: getScoreColor(vendor.score2) }}>
                              {vendor.score2}
                            </td>
                            <td style={{ padding: '0.75rem', textAlign: 'center', fontWeight: '600', color: getScoreColor(vendor.avg_score) }}>
                              {Math.round(vendor.avg_score)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>


      {/* Portfolio Table */}
      <div style={{ overflowX: 'auto' }}>
        <table className="portfolio-table">
          <thead className="portfolio-table-header">
            <tr>
              <th 
                                  style={{
                    padding: '1rem',
                    textAlign: 'left',
                    fontWeight: '700',
                    color: '#1e293b',
                    borderBottom: 'none',
                    cursor: 'pointer',
                    userSelect: 'none',
                    position: 'relative',
                    fontSize: '0.875rem',
                    letterSpacing: '0.025em'
                  }}
                onClick={() => handleSortChange('portfolio')}
                title="Click to sort by portfolio name"
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  Portfolio
                  {sortBy === 'portfolio' && (
                    <i className={`fas fa-sort-${sortOrder === 'asc' ? 'up' : 'down'}`} style={{ fontSize: '0.75rem' }}></i>
                  )}
                </div>
              </th>
                              <th 
                  style={{
                    padding: '1rem',
                    textAlign: 'center',
                    fontWeight: '700',
                    color: '#1e293b',
                    borderBottom: 'none',
                    cursor: 'pointer',
                    userSelect: 'none',
                    fontSize: '0.875rem',
                    letterSpacing: '0.025em'
                  }}
                  onClick={() => handleSortChange('vendor_count')}
                  title="Click to sort by vendor count"
                >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                  Vendors
                  {sortBy === 'vendor_count' && (
                    <i className={`fas fa-sort-${sortOrder === 'asc' ? 'up' : 'down'}`} style={{ fontSize: '0.75rem' }}></i>
                  )}
                </div>
              </th>
                              <th 
                  style={{
                    padding: '1rem',
                    textAlign: 'center',
                    fontWeight: '700',
                    color: '#1e293b',
                    borderBottom: 'none',
                    cursor: 'pointer',
                    userSelect: 'none',
                    fontSize: '0.875rem',
                    letterSpacing: '0.025em'
                  }}
                  onClick={() => handleSortChange('avg_score')}
                  title="Click to sort by average score"
                >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                  Avg Score
                  {sortBy === 'avg_score' && (
                    <i className={`fas fa-sort-${sortOrder === 'asc' ? 'up' : 'down'}`} style={{ fontSize: '0.75rem' }}></i>
                  )}
                </div>
              </th>
              <th style={{
                padding: '1rem',
                textAlign: 'center',
                fontWeight: '700',
                color: '#1e293b',
                borderBottom: 'none',
                fontSize: '0.875rem',
                letterSpacing: '0.025em'
              }}>
                Grade
              </th>
              <th style={{
                padding: '1rem',
                textAlign: 'center',
                fontWeight: '700',
                color: '#1e293b',
                borderBottom: 'none',
                fontSize: '0.875rem',
                letterSpacing: '0.025em'
              }}>
                Range
              </th>
              <th style={{
                padding: '1rem',
                textAlign: 'center',
                fontWeight: '700',
                color: '#1e293b',
                borderBottom: 'none',
                fontSize: '0.875rem',
                letterSpacing: '0.025em'
              }}>
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {getFilteredAndSortedPortfolios().map((portfolio, index) => (
              <React.Fragment key={portfolio.portfolio}>
                <tr className="portfolio-table-row"
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%)';
                  e.currentTarget.style.transform = 'translateY(-1px)';
                  e.currentTarget.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.1)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = '';
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = 'none';
                }}>
                  <td style={{
                    padding: '1.25rem 1rem',
                    fontWeight: '600',
                    color: '#1e293b',
                    fontSize: '0.875rem'
                  }}>
                    {portfolio.portfolio}
                  </td>
                  <td style={{
                    padding: '0.75rem 0.5rem',
                    textAlign: 'center',
                    color: '#6b7280'
                  }}>
                    {portfolio.vendor_count}
                  </td>
                  <td style={{
                    padding: '0.75rem 0.5rem',
                    textAlign: 'center'
                  }}>
                    <span style={{
                      fontWeight: '600',
                      color: getScoreColor(portfolio.avg_score)
                    }}>
                      {Math.round(portfolio.avg_score)}
                    </span>
                  </td>
                  <td style={{
                    padding: '0.75rem 0.5rem',
                    textAlign: 'center'
                  }}>
                    <span style={{
                      padding: '0.25rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontWeight: '600',
                      backgroundColor: getScoreColor(portfolio.avg_score) + '20',
                      color: getScoreColor(portfolio.avg_score)
                    }}>
                      {getGradeFromScore(Math.round(portfolio.avg_score))}
                    </span>
                  </td>
                  <td style={{
                    padding: '0.75rem 0.5rem',
                    textAlign: 'center',
                    color: '#6b7280'
                  }}>
                    {Math.min(...portfolio.scores)} - {Math.max(...portfolio.scores)}
                  </td>
                  <td style={{
                    padding: '0.75rem 0.5rem',
                    textAlign: 'center'
                  }}>
                    <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
                      <button
                        onClick={() => togglePortfolioExpansion(portfolio.portfolio)}
                        style={{
                          padding: '0.5rem 0.75rem',
                          background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
                          color: 'white',
                          border: 'none',
                          borderRadius: '6px',
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          cursor: 'pointer',
                          boxShadow: '0 2px 8px rgba(59, 130, 246, 0.3)',
                          transition: 'all 0.2s ease'
                        }}
                        onMouseEnter={(e) => {
                          const target = e.target as HTMLButtonElement;
                          target.style.transform = 'translateY(-1px)';
                          target.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.4)';
                        }}
                        onMouseLeave={(e) => {
                          const target = e.target as HTMLButtonElement;
                          target.style.transform = 'translateY(0)';
                          target.style.boxShadow = '0 2px 8px rgba(59, 130, 246, 0.3)';
                        }}
                        title="View portfolio details"
                      >
                        <i className={`fas ${expandedPortfolio === portfolio.portfolio ? 'fa-eye-slash' : 'fa-eye'}`}></i>
                      </button>
                      {canManagePortfolios && (
                        <button
                          onClick={() => handleManagePortfolio(portfolio.portfolio)}
                          style={{
                            padding: '0.5rem 0.75rem',
                            background: 'linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%)',
                            color: 'white',
                            border: 'none',
                            borderRadius: '6px',
                            fontSize: '0.75rem',
                            fontWeight: '600',
                            cursor: 'pointer',
                            boxShadow: '0 2px 8px rgba(14, 165, 233, 0.3)',
                            transition: 'all 0.2s ease'
                          }}
                          onMouseEnter={(e) => {
                            const target = e.target as HTMLButtonElement;
                            target.style.transform = 'translateY(-1px)';
                            target.style.boxShadow = '0 4px 12px rgba(14, 165, 233, 0.4)';
                          }}
                          onMouseLeave={(e) => {
                            const target = e.target as HTMLButtonElement;
                            target.style.transform = 'translateY(0)';
                            target.style.boxShadow = '0 2px 8px rgba(14, 165, 233, 0.3)';
                          }}
                          title="Manage portfolio vendors"
                        >
                          <i className="fas fa-cogs"></i>
                        </button>
                      )}
                      {canDeletePortfolios && (
                        <button
                          onClick={() => handleDeletePortfolioClick(portfolio.portfolio)}
                          style={{
                            padding: '0.5rem 0.75rem',
                            background: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                            color: 'white',
                            border: 'none',
                            borderRadius: '6px',
                            fontSize: '0.75rem',
                            fontWeight: '600',
                            cursor: 'pointer',
                            boxShadow: '0 2px 8px rgba(239, 68, 68, 0.3)',
                            transition: 'all 0.2s ease'
                          }}
                          onMouseEnter={(e) => {
                            const target = e.target as HTMLButtonElement;
                            target.style.transform = 'translateY(-1px)';
                            target.style.boxShadow = '0 4px 12px rgba(239, 68, 68, 0.4)';
                          }}
                          onMouseLeave={(e) => {
                            const target = e.target as HTMLButtonElement;
                            target.style.transform = 'translateY(0)';
                            target.style.boxShadow = '0 2px 8px rgba(239, 68, 68, 0.3)';
                          }}
                          title="Delete portfolio"
                        >
                          <i className="fas fa-trash"></i>
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
                
                {/* Expanded Details */}
                {expandedPortfolio === portfolio.portfolio && (
                  <tr>
                    <td colSpan={6} className="portfolio-expanded-details">
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                        gap: '1rem'
                      }}>
                        <div>
                          <div style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: '0.75rem'
                          }}>
                            <h4 style={{
                              margin: 0,
                              fontSize: '0.875rem',
                              fontWeight: '600',
                              color: '#374151'
                            }}>
                              Vendors in {portfolio.portfolio}
                            </h4>
                            <div style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.5rem'
                            }}>
                              <i className="fas fa-search" style={{ color: '#6b7280', fontSize: '0.75rem' }}></i>
                              <input
                                type="text"
                                placeholder="Search vendors or domains..."
                                value={expandedSearchTerms[portfolio.portfolio] || ''}
                                onChange={(e) => setExpandedSearchTerms({
                                  ...expandedSearchTerms,
                                  [portfolio.portfolio]: e.target.value
                                })}
                                style={{
                                  padding: '0.5rem',
                                  border: '1px solid #d1d5db',
                                  borderRadius: '4px',
                                  fontSize: '0.75rem',
                                  outline: 'none',
                                  width: '200px'
                                }}
                                onFocus={(e) => e.target.style.borderColor = '#3b82f6'}
                                onBlur={(e) => e.target.style.borderColor = '#d1d5db'}
                              />
                            </div>
                          </div>
                          <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                            {portfolio.vendors
                              .map((vendor, idx) => ({ vendor, domain: portfolio.domains[idx], score: portfolio.scores[idx] }))
                              .filter(item => {
                                const searchTerm = expandedSearchTerms[portfolio.portfolio]?.toLowerCase() || '';
                                return (
                                  item.vendor.toLowerCase().includes(searchTerm) ||
                                  item.domain.toLowerCase().includes(searchTerm)
                                );
                              })
                              .map((item, idx) => (
                              <div key={idx} className="portfolio-vendor-item">
                                <div>
                                  <div style={{ fontWeight: '500', color: '#1f2937' }}>
                                    {item.vendor}
                                  </div>
                                  <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                                    {item.domain}
                                  </div>
                                </div>
                                <div style={{
                                  fontWeight: '600',
                                  color: getScoreColor(item.score)
                                }}>
                                  {Math.round(item.score)}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="portfolio-footer">
        Last updated: {new Date(portfolioData.timestamp).toLocaleString()}
      </div>

      {/* Modals */}
      {canCreatePortfolios && (
        <CreatePortfolioModal
          isOpen={showCreateModal}
          onClose={() => setShowCreateModal(false)}
          onSuccess={handleModalSuccess}
        />
      )}
      
      {canManagePortfolios && (
        <ManagePortfolioModal
          isOpen={showManageModal}
          onClose={() => setShowManageModal(false)}
          onSuccess={handleModalSuccess}
          portfolioName={selectedPortfolioForManagement}
        />
      )}

      {/* Delete Confirmation Modal */}
      {canDeletePortfolios && (
        <ConfirmationModal
          isOpen={showDeleteConfirmation}
          onClose={() => {
            setShowDeleteConfirmation(false);
            setPortfolioToDelete('');
          }}
          onConfirm={handleDeletePortfolio}
          title="Delete Portfolio"
          message={`Are you sure you want to delete the Portfolio ${portfolioToDelete}?`}
          confirmText="Delete Portfolio"
          cancelText="Cancel"
          type="danger"
          loading={deleteLoading}
        />
      )}
    </div>
  );
};

export default PortfolioManagement; 