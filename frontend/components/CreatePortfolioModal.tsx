'use client';

import React, { useState, useEffect } from 'react';
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

interface CreatePortfolioModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const CreatePortfolioModal: React.FC<CreatePortfolioModalProps> = ({
  isOpen,
  onClose,
  onSuccess
}) => {
  const [portfolioName, setPortfolioName] = useState('');
  const [selectedVendors, setSelectedVendors] = useState<number[]>([]);
  const [availableVendors, setAvailableVendors] = useState<Vendor[]>([]);
  const [loading, setLoading] = useState(false);
  const [vendorsLoading, setVendorsLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isPortfolioNameTaken, setIsPortfolioNameTaken] = useState(false);

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
    if (isOpen) {
      fetchAvailableVendors();
      setPortfolioName('');
      setSelectedVendors([]);
      setSearchTerm('');
      setError(null);
      setIsPortfolioNameTaken(false);
    }
  }, [isOpen]);

  const fetchAvailableVendors = async () => {
    try {
      setVendorsLoading(true);
      const response = await apiRequest('/api/vendors/available');
      
      if (!response.ok) {
        throw new Error(`Failed to fetch vendors: ${response.statusText}`);
      }

      const data = await response.json();
      setAvailableVendors(data.vendors || []);
    } catch (err) {
      console.error('Error fetching vendors:', err);
      setError('Failed to load vendors');
    } finally {
      setVendorsLoading(false);
    }
  };

  const handleVendorToggle = (vendorId: number) => {
    setSelectedVendors(prev => 
      prev.includes(vendorId) 
        ? prev.filter(id => id !== vendorId)
        : [...prev, vendorId]
    );
  };

  const handleSelectAll = () => {
    const filteredVendors = getFilteredVendors();
    const allSelected = filteredVendors.every(vendor => selectedVendors.includes(vendor.id));
    
    if (allSelected) {
      // Deselect all filtered vendors
      setSelectedVendors(prev => prev.filter(id => !filteredVendors.some(v => v.id === id)));
    } else {
      // Select all filtered vendors
      const newSelections = filteredVendors.map(v => v.id);
      setSelectedVendors(prev => {
        const combined = [...prev, ...newSelections];
        return Array.from(new Set(combined));
      });
    }
  };

  const getFilteredVendors = () => {
    return availableVendors.filter(vendor =>
      vendor.vendor_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vendor.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vendor.tier.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vendor.industry.toLowerCase().includes(searchTerm.toLowerCase())
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!portfolioName.trim()) {
      setError('Portfolio name is required');
      return;
    }

    if (selectedVendors.length === 0) {
      setError('Please select at least one vendor');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await apiRequest('/api/portfolios/create', {
        method: 'POST',
        body: JSON.stringify({
          portfolio_name: portfolioName.trim(),
          vendor_ids: selectedVendors,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        // Handle specific error cases
        if (response.status === 409) {
          // Portfolio already exists
          setIsPortfolioNameTaken(true);
          throw new Error(`A portfolio named "${portfolioName.trim()}" already exists. Please choose a different name.`);
        }
        throw new Error(data.detail || 'Failed to create portfolio');
      }

      onSuccess();
      onClose();
    } catch (err) {
      console.error('Error creating portfolio:', err);
      setError(err instanceof Error ? err.message : 'Failed to create portfolio');
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 800) return '#10b981';
    if (score >= 600) return '#f59e0b';
    if (score >= 400) return '#f97316';
    return '#ef4444';
  };

  if (!isOpen) return null;

  const filteredVendors = getFilteredVendors();
  const allFilteredSelected = filteredVendors.length > 0 && filteredVendors.every(vendor => selectedVendors.includes(vendor.id));

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
        maxWidth: '800px',
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
              background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
              borderRadius: '8px',
              padding: '0.5rem',
              boxShadow: '0 2px 8px rgba(59, 130, 246, 0.3)'
            }}>
              <i className="fas fa-plus" style={{ color: 'white', fontSize: '1rem' }}></i>
            </div>
            <h2 style={{
              margin: 0,
              fontSize: '1.25rem',
              fontWeight: '700',
              color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
            }}>
              Create New Portfolio
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

        <form onSubmit={handleSubmit}>
          {/* Portfolio Name */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{
              display: 'block',
              fontSize: '0.875rem',
              fontWeight: '500',
              color: isDarkMode ? 'var(--text-primary)' : '#374151',
              marginBottom: '0.5rem'
            }}>
              Portfolio Name *
            </label>
            <input
              type="text"
              value={portfolioName}
              onChange={(e) => {
                setPortfolioName(e.target.value);
                // Clear the error state when user starts typing a new name
                if (isPortfolioNameTaken && e.target.value.trim() !== portfolioName.trim()) {
                  setIsPortfolioNameTaken(false);
                  setError(null);
                }
              }}
              placeholder="Enter portfolio name"
              style={{
                width: '100%',
                padding: '0.75rem',
                border: isPortfolioNameTaken 
                  ? '2px solid #ef4444' 
                  : (isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db'),
                borderRadius: '8px',
                fontSize: '0.875rem',
                outline: 'none',
                backgroundColor: isDarkMode ? 'var(--bg-secondary)' : 'white',
                color: isDarkMode ? 'var(--text-primary)' : '#374151'
              }}
              onFocus={(e) => {
                if (!isPortfolioNameTaken) {
                  e.target.style.borderColor = '#3b82f6';
                }
              }}
              onBlur={(e) => {
                if (!isPortfolioNameTaken) {
                  e.target.style.borderColor = isDarkMode ? 'var(--border-color)' : '#d1d5db';
                }
              }}
            />
            {isPortfolioNameTaken && (
              <div style={{
                marginTop: '0.5rem',
                fontSize: '0.75rem',
                color: isDarkMode ? '#fca5a5' : '#ef4444',
                display: 'flex',
                alignItems: 'center'
              }}>
                <i className="fas fa-info-circle" style={{ marginRight: '0.25rem' }}></i>
                Try a different name or add a suffix like &quot;v2&quot; or &quot;2024&quot;
              </div>
            )}
          </div>

          {/* Vendor Selection */}
          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '0.75rem'
            }}>
              <label style={{
                fontSize: '0.875rem',
                fontWeight: '500',
                color: isDarkMode ? 'var(--text-primary)' : '#374151'
              }}>
                Select Vendors * ({selectedVendors.length} selected)
              </label>
              <button
                type="button"
                onClick={handleSelectAll}
                style={{
                  padding: '0.5rem 0.75rem',
                  background: 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                {allFilteredSelected ? 'Deselect All' : 'Select All'} Filtered
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

            {/* Vendor List */}
            <div style={{
              border: isDarkMode ? '1px solid var(--border-color)' : '1px solid #d1d5db',
              borderRadius: '8px',
              maxHeight: '300px',
              overflowY: 'auto',
              backgroundColor: isDarkMode ? 'var(--bg-secondary)' : '#f9fafb'
            }}>
              {vendorsLoading ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                  <i className="fas fa-spinner fa-spin" style={{ marginRight: '0.5rem' }}></i>
                  Loading vendors...
                </div>
              ) : filteredVendors.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: isDarkMode ? 'var(--text-secondary)' : '#6b7280' }}>
                  No vendors found matching your search
                </div>
              ) : (
                filteredVendors.map((vendor) => (
                  <div
                    key={vendor.id}
                    onClick={() => handleVendorToggle(vendor.id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      padding: '0.75rem',
                      borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb',
                      cursor: 'pointer',
                      backgroundColor: selectedVendors.includes(vendor.id) 
                        ? (isDarkMode ? 'rgba(59, 130, 246, 0.1)' : '#eff6ff')
                        : 'transparent'
                    }}
                    onMouseEnter={(e) => {
                      if (!selectedVendors.includes(vendor.id)) {
                        e.currentTarget.style.backgroundColor = isDarkMode ? 'var(--bg-primary)' : '#f3f4f6';
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!selectedVendors.includes(vendor.id)) {
                        e.currentTarget.style.backgroundColor = 'transparent';
                      }
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={selectedVendors.includes(vendor.id)}
                      onChange={(e) => {
                        e.stopPropagation();
                        handleVendorToggle(vendor.id);
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
                      {vendor.current_portfolios && (
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

          {/* Error Message */}
          {error && (
            <div style={{
              padding: '0.75rem',
              backgroundColor: isDarkMode 
                ? (isPortfolioNameTaken ? 'rgba(239, 68, 68, 0.1)' : 'rgba(239, 68, 68, 0.1)')
                : (isPortfolioNameTaken ? '#fef2f2' : '#fef2f2'),
              border: isPortfolioNameTaken 
                ? '2px solid #ef4444' 
                : (isDarkMode ? '1px solid #ef4444' : '1px solid #fecaca'),
              borderRadius: '8px',
              color: isDarkMode ? '#fca5a5' : '#dc2626',
              fontSize: '0.875rem',
              marginBottom: '1.5rem',
              boxShadow: isPortfolioNameTaken ? '0 2px 8px rgba(239, 68, 68, 0.2)' : 'none'
            }}>
              <i className={`fas ${isPortfolioNameTaken ? 'fa-exclamation-circle' : 'fa-exclamation-triangle'}`} style={{ marginRight: '0.5rem' }}></i>
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
              type="button"
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
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || selectedVendors.length === 0 || !portfolioName.trim()}
              style={{
                padding: '0.75rem 1.5rem',
                background: loading || selectedVendors.length === 0 || !portfolioName.trim() 
                  ? '#9ca3af' 
                  : 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                fontSize: '0.875rem',
                fontWeight: '600',
                cursor: loading || selectedVendors.length === 0 || !portfolioName.trim() 
                  ? 'not-allowed' 
                  : 'pointer',
                boxShadow: '0 2px 8px rgba(59, 130, 246, 0.3)'
              }}
            >
              {loading ? (
                <>
                  <i className="fas fa-spinner fa-spin" style={{ marginRight: '0.5rem' }}></i>
                  Creating...
                </>
              ) : (
                <>
                  <i className="fas fa-plus" style={{ marginRight: '0.5rem' }}></i>
                  Create Portfolio
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreatePortfolioModal;
