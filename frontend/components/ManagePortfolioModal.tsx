'use client';

import React, { useState, useEffect } from 'react';
import ConfirmationModal from './ConfirmationModal';
import { apiRequest } from '../lib/api-client';

interface Vendor {
  id: number;
  vendor_name: string;
  domain: string;
  score: number;
  grade: string;
  tier: string;
  industry: string;
  current_portfolios: string;
}

interface PortfolioVendor {
  id: number;
  vendor_name: string;
  domain: string;
  score: number;
  grade: string;
  tier: string;
  industry: string;
}

interface ManagePortfolioModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  portfolioName: string;
}

const ManagePortfolioModal: React.FC<ManagePortfolioModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
  portfolioName
}) => {
  const [portfolioVendors, setPortfolioVendors] = useState<PortfolioVendor[]>([]);
  const [availableVendors, setAvailableVendors] = useState<Vendor[]>([]);
  const [selectedToAdd, setSelectedToAdd] = useState<number[]>([]);
  const [selectedToRemove, setSelectedToRemove] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [vendorsLoading, setVendorsLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState<'current' | 'add'>('current');
  const [error, setError] = useState<string | null>(null);
  
  // Confirmation modal states
  const [showRemoveConfirmation, setShowRemoveConfirmation] = useState(false);
  const [vendorsToRemove, setVendorsToRemove] = useState<number[]>([]);

  // Dark mode hook
  const useDarkMode = () => {
    const [isDarkMode, setIsDarkMode] = useState(false);

    useEffect(() => {
      const checkDarkMode = () => {
        setIsDarkMode(document.body.classList.contains('dark-mode'));
      };

      checkDarkMode();
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

  useEffect(() => {
    if (isOpen && portfolioName) {
      fetchPortfolioData();
      setSelectedToAdd([]);
      setSelectedToRemove([]);
      setSearchTerm('');
      setError(null);
      setActiveTab('current');
    }
  }, [isOpen, portfolioName]);

  const fetchPortfolioData = async () => {
    try {
      setVendorsLoading(true);
      
      // Fetch current portfolio vendors and all available vendors in parallel
      const [portfolioResponse, availableResponse] = await Promise.all([
        apiRequest(`/api/portfolios/${encodeURIComponent(portfolioName)}/vendors`),
        apiRequest('/api/vendors/available')
      ]);

      if (!portfolioResponse.ok) {
        throw new Error(`Failed to fetch portfolio vendors: ${portfolioResponse.statusText}`);
      }

      if (!availableResponse.ok) {
        throw new Error(`Failed to fetch available vendors: ${availableResponse.statusText}`);
      }

      const [portfolioData, availableData] = await Promise.all([
        portfolioResponse.json(),
        availableResponse.json()
      ]);

      setPortfolioVendors(portfolioData.vendors || []);
      
      // Filter out vendors that are already in this portfolio
      const portfolioVendorIds = new Set((portfolioData.vendors || []).map((v: PortfolioVendor) => v.id));
      const availableForAddition = (availableData.vendors || []).filter(
        (vendor: Vendor) => !portfolioVendorIds.has(vendor.id)
      );
      setAvailableVendors(availableForAddition);
      
    } catch (err) {
      console.error('Error fetching portfolio data:', err);
      setError('Failed to load portfolio data');
    } finally {
      setVendorsLoading(false);
    }
  };

  const handleAddVendors = async () => {
    if (selectedToAdd.length === 0) return;

    try {
      setLoading(true);
      setError(null);

      const response = await apiRequest(`/api/portfolios/${encodeURIComponent(portfolioName)}/vendors/add`, {
        method: 'POST',
        body: JSON.stringify({
          vendor_ids: selectedToAdd,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to add vendors');
      }

      // Refresh data and reset selections
      await fetchPortfolioData();
      setSelectedToAdd([]);
      setActiveTab('current');
      onSuccess();
      
    } catch (err) {
      console.error('Error adding vendors:', err);
      setError(err instanceof Error ? err.message : 'Failed to add vendors');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveVendorsClick = () => {
    if (selectedToRemove.length === 0) return;
    setVendorsToRemove(selectedToRemove);
    setShowRemoveConfirmation(true);
  };

  const getVendorNamesForConfirmation = () => {
    const vendorNames = portfolioVendors
      .filter(vendor => vendorsToRemove.includes(vendor.id))
      .map(vendor => vendor.vendor_name);
    
    if (vendorNames.length <= 3) {
      return vendorNames.join(', ');
    } else {
      return `${vendorNames.slice(0, 3).join(', ')} and ${vendorNames.length - 3} more`;
    }
  };

  const handleRemoveVendors = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await apiRequest(`/api/portfolios/${encodeURIComponent(portfolioName)}/vendors/remove`, {
        method: 'POST',
        body: JSON.stringify({
          vendor_ids: vendorsToRemove,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to remove vendors');
      }

      // Refresh data and reset selections
      await fetchPortfolioData();
      setSelectedToRemove([]);
      setVendorsToRemove([]);
      setShowRemoveConfirmation(false);
      onSuccess();
      
    } catch (err) {
      console.error('Error removing vendors:', err);
      setError(err instanceof Error ? err.message : 'Failed to remove vendors');
      setShowRemoveConfirmation(false);
    } finally {
      setLoading(false);
    }
  };

  const handleVendorToggle = (vendorId: number, type: 'add' | 'remove') => {
    if (type === 'add') {
      setSelectedToAdd(prev => 
        prev.includes(vendorId) 
          ? prev.filter(id => id !== vendorId)
          : [...prev, vendorId]
      );
    } else {
      setSelectedToRemove(prev => 
        prev.includes(vendorId) 
          ? prev.filter(id => id !== vendorId)
          : [...prev, vendorId]
      );
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 800) return '#10b981';
    if (score >= 600) return '#f59e0b';
    if (score >= 400) return '#f97316';
    return '#ef4444';
  };

  const getFilteredVendors = (vendors: (Vendor | PortfolioVendor)[], searchTerm: string) => {
    return vendors.filter(vendor =>
      vendor.vendor_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vendor.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vendor.tier.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vendor.industry.toLowerCase().includes(searchTerm.toLowerCase())
    );
  };

  const handleSelectAllCurrent = () => {
    const filteredVendors = getFilteredVendors(portfolioVendors, searchTerm);
    const allSelected = filteredVendors.every(vendor => selectedToRemove.includes(vendor.id));
    
    if (allSelected) {
      // Deselect all filtered vendors
      setSelectedToRemove(prev => prev.filter(id => !filteredVendors.some(v => v.id === id)));
    } else {
      // Select all filtered vendors
      const newSelections = filteredVendors.map(v => v.id);
      setSelectedToRemove(prev => {
        const combined = [...prev, ...newSelections];
        return Array.from(new Set(combined));
      });
    }
  };

  const handleSelectAllAvailable = () => {
    const filteredVendors = getFilteredVendors(availableVendors, searchTerm);
    const allSelected = filteredVendors.every(vendor => selectedToAdd.includes(vendor.id));
    
    if (allSelected) {
      // Deselect all filtered vendors
      setSelectedToAdd(prev => prev.filter(id => !filteredVendors.some(v => v.id === id)));
    } else {
      // Select all filtered vendors
      const newSelections = filteredVendors.map(v => v.id);
      setSelectedToAdd(prev => {
        const combined = [...prev, ...newSelections];
        return Array.from(new Set(combined));
      });
    }
  };

  if (!isOpen) return null;

  const filteredPortfolioVendors = getFilteredVendors(portfolioVendors, searchTerm);
  const filteredAvailableVendors = getFilteredVendors(availableVendors, searchTerm);

  return (
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
      zIndex: 1000,
      padding: '1rem'
    }}>
      <div style={{
        backgroundColor: isDarkMode ? 'var(--bg-primary)' : 'white',
        borderRadius: '12px',
        padding: '2rem',
        width: '100%',
        maxWidth: '900px',
        maxHeight: '90vh',
        overflowY: 'auto',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        border: isDarkMode ? '1px solid var(--border-color)' : 'none'
      }}>
        {/* Header */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1.5rem',
          borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb',
          paddingBottom: '1rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              background: 'linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%)',
              borderRadius: '8px',
              padding: '0.5rem',
              boxShadow: '0 2px 8px rgba(14, 165, 233, 0.3)'
            }}>
              <i className="fas fa-cogs" style={{ color: 'white', fontSize: '1rem' }}></i>
            </div>
            <h2 style={{
              margin: 0,
              fontSize: '1.25rem',
              fontWeight: '700',
              color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
            }}>
              Manage Portfolio: {portfolioName}
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              fontSize: '1.5rem',
              cursor: 'pointer',
              color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
              padding: '0.25rem'
            }}
          >
            ×
          </button>
        </div>

        {/* Tabs */}
        <div style={{
          display: 'flex',
          borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb',
          marginBottom: '1.5rem'
        }}>
          <button
            onClick={() => setActiveTab('current')}
            style={{
              padding: '0.75rem 1.5rem',
              background: 'none',
              border: 'none',
              borderBottom: activeTab === 'current' ? '2px solid #3b82f6' : '2px solid transparent',
              color: activeTab === 'current' 
                ? (isDarkMode ? 'var(--text-primary)' : '#3b82f6')
                : (isDarkMode ? 'var(--text-secondary)' : '#6b7280'),
              fontWeight: activeTab === 'current' ? '600' : '500',
              cursor: 'pointer',
              fontSize: '0.875rem'
            }}
          >
            Current Vendors ({portfolioVendors.length})
          </button>
          <button
            onClick={() => setActiveTab('add')}
            style={{
              padding: '0.75rem 1.5rem',
              background: 'none',
              border: 'none',
              borderBottom: activeTab === 'add' ? '2px solid #3b82f6' : '2px solid transparent',
              color: activeTab === 'add' 
                ? (isDarkMode ? 'var(--text-primary)' : '#3b82f6')
                : (isDarkMode ? 'var(--text-secondary)' : '#6b7280'),
              fontWeight: activeTab === 'add' ? '600' : '500',
              cursor: 'pointer',
              fontSize: '0.875rem'
            }}
          >
            Add Vendors ({availableVendors.length})
          </button>
        </div>

        {/* Search */}
        <div style={{ marginBottom: '1rem' }}>
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search vendors by name, domain, tier, or industry..."
            style={{
              width: '100%',
              padding: '0.75rem',
              border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db',
              borderRadius: '8px',
              fontSize: '0.875rem',
              outline: 'none',
              backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
              color: isDarkMode ? 'var(--text-primary)' : '#374151'
            }}
            onFocus={(e) => e.target.style.borderColor = '#3b82f6'}
            onBlur={(e) => e.target.style.borderColor = isDarkMode ? 'var(--border-color)' : '#d1d5db'}
          />
        </div>

        {/* Content */}
        <div style={{ marginBottom: '1.5rem' }}>
          {activeTab === 'current' && (
            <div>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '1rem'
              }}>
                <h3 style={{
                  margin: 0,
                  fontSize: '1rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-primary)' : '#374151'
                }}>
                  Current Vendors ({selectedToRemove.length} selected for removal)
                </h3>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                  <button
                    onClick={handleSelectAllCurrent}
                    disabled={loading || filteredPortfolioVendors.length === 0}
                    style={{
                      padding: '0.5rem 0.75rem',
                      background: loading || filteredPortfolioVendors.length === 0 
                        ? '#9ca3af' 
                        : 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      fontSize: '0.75rem',
                      fontWeight: '600',
                      cursor: loading || filteredPortfolioVendors.length === 0 ? 'not-allowed' : 'pointer'
                    }}
                  >
                    {filteredPortfolioVendors.length > 0 && filteredPortfolioVendors.every(vendor => selectedToRemove.includes(vendor.id)) 
                      ? 'Deselect All' 
                      : 'Select All'} Filtered
                  </button>
                  {selectedToRemove.length > 0 && (
                    <button
                      onClick={handleRemoveVendorsClick}
                      disabled={loading}
                      style={{
                        padding: '0.5rem 1rem',
                        background: loading ? '#9ca3af' : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                        color: 'white',
                        border: 'none',
                        borderRadius: '6px',
                        fontSize: '0.875rem',
                        fontWeight: '600',
                        cursor: loading ? 'not-allowed' : 'pointer'
                      }}
                    >
                      <i className="fas fa-trash" style={{ marginRight: '0.5rem' }}></i>
                      Remove Selected
                    </button>
                  )}
                </div>
              </div>

              <div style={{
                border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db',
                borderRadius: '8px',
                maxHeight: '400px',
                overflowY: 'auto',
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : '#f9fafb'
              }}>
                {vendorsLoading ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                    <i className="fas fa-spinner fa-spin" style={{ marginRight: '0.5rem' }}></i>
                    Loading vendors...
                  </div>
                ) : filteredPortfolioVendors.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                    No vendors found in this portfolio
                  </div>
                ) : (
                  filteredPortfolioVendors.map((vendor) => (
                    <div
                      key={vendor.id}
                      onClick={() => handleVendorToggle(vendor.id, 'remove')}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        padding: '0.75rem',
                        borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb',
                        cursor: 'pointer',
                        backgroundColor: selectedToRemove.includes(vendor.id) 
                          ? (isDarkMode ? 'rgba(239, 68, 68, 0.1)' : '#fef2f2')
                          : 'transparent'
                      }}
                      onMouseEnter={(e) => {
                        if (!selectedToRemove.includes(vendor.id)) {
                          e.currentTarget.style.backgroundColor = isDarkMode ? 'var(--bg-primary)' : '#f3f4f6';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (!selectedToRemove.includes(vendor.id)) {
                          e.currentTarget.style.backgroundColor = 'transparent';
                        }
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={selectedToRemove.includes(vendor.id)}
                        onChange={(e) => {
                          e.stopPropagation();
                          handleVendorToggle(vendor.id, 'remove');
                        }}
                        onClick={(e) => e.stopPropagation()}
                        style={{ marginRight: '0.75rem', cursor: 'pointer' }}
                      />
                      <div style={{ flex: 1, pointerEvents: 'none' }}>
                        <div style={{
                          fontWeight: '500',
                          color: isDarkMode ? 'var(--text-primary)' : '#1f2937',
                          marginBottom: '0.25rem'
                        }}>
                          {vendor.vendor_name}
                        </div>
                        <div style={{
                          fontSize: '0.75rem',
                          color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
                        }}>
                          {vendor.domain} • {vendor.tier} • {vendor.industry}
                        </div>
                      </div>
                      <div style={{
                        fontWeight: '600',
                        color: getScoreColor(vendor.score),
                        marginLeft: '0.5rem',
                        pointerEvents: 'none'
                      }}>
                        {vendor.score}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {activeTab === 'add' && (
            <div>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '1rem'
              }}>
                <h3 style={{
                  margin: 0,
                  fontSize: '1rem',
                  fontWeight: '600',
                  color: isDarkMode ? 'var(--text-primary)' : '#374151'
                }}>
                  Available Vendors ({selectedToAdd.length} selected to add)
                </h3>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                  <button
                    onClick={handleSelectAllAvailable}
                    disabled={loading || filteredAvailableVendors.length === 0}
                    style={{
                      padding: '0.5rem 0.75rem',
                      background: loading || filteredAvailableVendors.length === 0 
                        ? '#9ca3af' 
                        : 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      fontSize: '0.75rem',
                      fontWeight: '600',
                      cursor: loading || filteredAvailableVendors.length === 0 ? 'not-allowed' : 'pointer'
                    }}
                  >
                    {filteredAvailableVendors.length > 0 && filteredAvailableVendors.every(vendor => selectedToAdd.includes(vendor.id)) 
                      ? 'Deselect All' 
                      : 'Select All'} Filtered
                  </button>
                  {selectedToAdd.length > 0 && (
                    <button
                      onClick={handleAddVendors}
                      disabled={loading}
                      style={{
                        padding: '0.5rem 1rem',
                        background: loading ? '#9ca3af' : 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                        color: 'white',
                        border: 'none',
                        borderRadius: '6px',
                        fontSize: '0.875rem',
                        fontWeight: '600',
                        cursor: loading ? 'not-allowed' : 'pointer'
                      }}
                    >
                      {loading ? (
                        <>
                          <i className="fas fa-spinner fa-spin" style={{ marginRight: '0.5rem' }}></i>
                          Adding...
                        </>
                      ) : (
                        <>
                          <i className="fas fa-plus" style={{ marginRight: '0.5rem' }}></i>
                          Add Selected
                        </>
                      )}
                    </button>
                  )}
                </div>
              </div>

              <div style={{
                border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db',
                borderRadius: '8px',
                maxHeight: '400px',
                overflowY: 'auto',
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : '#f9fafb'
              }}>
                {vendorsLoading ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                    <i className="fas fa-spinner fa-spin" style={{ marginRight: '0.5rem' }}></i>
                    Loading vendors...
                  </div>
                ) : filteredAvailableVendors.length === 0 ? (
                  <div style={{ padding: '2rem', textAlign: 'center', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                    No vendors available to add
                  </div>
                ) : (
                  filteredAvailableVendors.map((vendor) => (
                    <div
                      key={vendor.id}
                      onClick={() => handleVendorToggle(vendor.id, 'add')}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        padding: '0.75rem',
                        borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb',
                        cursor: 'pointer',
                        backgroundColor: selectedToAdd.includes(vendor.id) 
                          ? (isDarkMode ? 'rgba(59, 130, 246, 0.1)' : '#eff6ff')
                          : 'transparent'
                      }}
                      onMouseEnter={(e) => {
                        if (!selectedToAdd.includes(vendor.id)) {
                          e.currentTarget.style.backgroundColor = isDarkMode ? 'var(--bg-primary)' : '#f3f4f6';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (!selectedToAdd.includes(vendor.id)) {
                          e.currentTarget.style.backgroundColor = 'transparent';
                        }
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={selectedToAdd.includes(vendor.id)}
                        onChange={(e) => {
                          e.stopPropagation();
                          handleVendorToggle(vendor.id, 'add');
                        }}
                        onClick={(e) => e.stopPropagation()}
                        style={{ marginRight: '0.75rem', cursor: 'pointer' }}
                      />
                      <div style={{ flex: 1, pointerEvents: 'none' }}>
                        <div style={{
                          fontWeight: '500',
                          color: isDarkMode ? 'var(--text-primary)' : '#1f2937',
                          marginBottom: '0.25rem'
                        }}>
                          {vendor.vendor_name}
                        </div>
                        <div style={{
                          fontSize: '0.75rem',
                          color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
                        }}>
                          {vendor.domain} • {vendor.tier} • {vendor.industry}
                        </div>
                        {'current_portfolios' in vendor && vendor.current_portfolios && (
                          <div style={{
                            fontSize: '0.75rem',
                            color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                            fontStyle: 'italic'
                          }}>
                            Current portfolios: {vendor.current_portfolios}
                          </div>
                        )}
                      </div>
                      <div style={{
                        fontWeight: '600',
                        color: getScoreColor(vendor.score),
                        marginLeft: '0.5rem',
                        pointerEvents: 'none'
                      }}>
                        {vendor.score}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div style={{
            padding: '0.75rem',
            backgroundColor: isDarkMode ? 'rgba(239, 68, 68, 0.1)' : '#fef2f2',
            border: isDarkMode ? '1px solid #ef4444' : '1px solid #fecaca',
            borderRadius: '8px',
            color: isDarkMode ? '#fca5a5' : '#dc2626',
            fontSize: '0.875rem',
            marginBottom: '1.5rem'
          }}>
            <i className="fas fa-exclamation-triangle" style={{ marginRight: '0.5rem' }}></i>
            {error}
          </div>
        )}

        {/* Actions */}
        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          gap: '0.75rem',
          paddingTop: '1rem',
          borderTop: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb'
        }}>
          <button
            onClick={onClose}
            disabled={loading}
            style={{
              padding: '0.75rem 1.5rem',
              background: isDarkMode ? 'var(--bg-secondary)' : '#f3f4f6',
              color: isDarkMode ? 'var(--text-primary)' : '#374151',
              border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db',
              borderRadius: '8px',
              fontSize: '0.875rem',
              fontWeight: '600',
              cursor: loading ? 'not-allowed' : 'pointer'
            }}
          >
            Close
          </button>
        </div>

        {/* Confirmation Modal */}
        <ConfirmationModal
          isOpen={showRemoveConfirmation}
          onClose={() => {
            setShowRemoveConfirmation(false);
            setVendorsToRemove([]);
          }}
          onConfirm={handleRemoveVendors}
          title="Remove Vendors from Portfolio"
          message={`Are you sure you want to remove the following vendor${vendorsToRemove.length === 1 ? '' : 's'} from the ${portfolioName} portfolio?\nThis action cannot be undone.`}
          confirmText="Remove Vendors"
          cancelText="Cancel"
          type="danger"
          loading={loading}
        />
      </div>
    </div>
  );
};

export default ManagePortfolioModal;
