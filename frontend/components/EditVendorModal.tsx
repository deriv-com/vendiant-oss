'use client';

import React, { useState, useEffect } from 'react';
import { vendorApi, VendorDetailsResponse, UpdateVendorResponse } from '../lib/api';

interface EditVendorModalProps {
  vendorId: number;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (updatedVendor: any) => void;
  onError: (error: string) => void;
  tierOptions?: string[];
  portfolioOptions?: string[];
  industryOptions?: string[];
}

interface VendorFormData {
  vendor_name: string;
  domain: string;
  tier: string;
  portfolio: string;
  industry: string;
}

const EditVendorModal: React.FC<EditVendorModalProps> = ({
  vendorId,
  isOpen,
  onClose,
  onSuccess,
  onError,
  tierOptions = [],
  portfolioOptions = [],
  industryOptions = []
}) => {
  const [formData, setFormData] = useState<VendorFormData>({
    vendor_name: '',
    domain: '',
    tier: '',
    portfolio: '',
    industry: ''
  });
  const [loading, setLoading] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [validationErrors, setValidationErrors] = useState<{[key: string]: string}>({});
  const [originalData, setOriginalData] = useState<VendorFormData | null>(null);

  // Use provided options or fallback to default values
  const defaultTierOptions = ['Tier 1', 'Tier 2', 'Tier 3', 'Untiered'];
  const defaultPortfolioOptions = ['PSP', 'Banks', 'LCNC', 'Supplier','Temp_Risk Assessment'];
  const defaultIndustryOptions = ['Technology', 'Finance', 'Healthcare', 'Manufacturing', 'Retail', 'Other'];
  
  const finalTierOptions = tierOptions.length > 0 ? tierOptions : defaultTierOptions;
  const finalPortfolioOptions = portfolioOptions.length > 0 ? portfolioOptions : defaultPortfolioOptions;
  const finalIndustryOptions = industryOptions.length > 0 ? industryOptions : defaultIndustryOptions;

  // Load vendor details when modal opens
  useEffect(() => {
    if (isOpen && vendorId) {
      loadVendorDetails();
    }
  }, [isOpen, vendorId]);

  // Reset form when modal closes
  useEffect(() => {
    if (!isOpen) {
      setFormData({
        vendor_name: '',
        domain: '',
        tier: '',
        portfolio: '',
        industry: ''
      });
      setValidationErrors({});
      setOriginalData(null);
    }
  }, [isOpen]);

  const loadVendorDetails = async () => {
    setLoadingDetails(true);
    try {
      const response: VendorDetailsResponse = await vendorApi.getVendorDetails(vendorId);
      
      if (response.status === 'success' && response.vendor) {
        const vendorData: VendorFormData = {
          vendor_name: response.vendor.vendor_name,
          domain: response.vendor.domain,
          tier: response.vendor.tier,
          portfolio: response.vendor.portfolio,
          industry: response.vendor.industry || ''
        };
        
        setFormData(vendorData);
        setOriginalData(vendorData);
      } else {
        onError('Failed to load vendor details');
        onClose();
      }
    } catch (error: any) {
      console.error('Error loading vendor details:', error);
      onError(error.response?.data?.detail || 'Failed to load vendor details');
      onClose();
    } finally {
      setLoadingDetails(false);
    }
  };

  const validateForm = (): boolean => {
    const errors: {[key: string]: string} = {};

    if (!formData.vendor_name.trim()) {
      errors.vendor_name = 'Vendor name is required';
    }

    if (!formData.domain.trim()) {
      errors.domain = 'Domain is required';
    } else {
      // Enhanced domain validation to support second-level domains (e.g., .co.uk, .org.uk)
      const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}\.)?[a-zA-Z]{2,}$/;
      if (!domainPattern.test(formData.domain.trim())) {
        errors.domain = 'Invalid domain format. Supported formats: example.com, example.co.uk, etc.';
      }
    }

    if (!formData.tier.trim()) {
      errors.tier = 'Tier is required';
    }

    if (!formData.portfolio.trim()) {
      errors.portfolio = 'Portfolio is required';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const extractDomainFromInput = (input: string): string => {
    if (!input) return '';
    
    // Remove protocol
    let domain = input.replace(/^https?:\/\//, '');
    
    // Remove www
    domain = domain.replace(/^www\./, '');
    
    // Remove path and query parameters
    domain = domain.split('/')[0];
    domain = domain.split('?')[0];
    
    return domain.toLowerCase();
  };

  const handleInputChange = (field: keyof VendorFormData, value: string) => {
    let processedValue = value;
    
    // Special processing for domain field
    if (field === 'domain') {
      processedValue = extractDomainFromInput(value);
    }
    
    setFormData(prev => ({
      ...prev,
      [field]: processedValue
    }));

    // Clear validation error for this field
    if (validationErrors[field]) {
      setValidationErrors(prev => ({
        ...prev,
        [field]: ''
      }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setLoading(true);
    
    try {
      const response: UpdateVendorResponse = await vendorApi.updateVendor(vendorId, {
        vendor_name: formData.vendor_name.trim(),
        domain: formData.domain.trim(),
        tier: formData.tier.trim(),
        portfolio: formData.portfolio.trim(),
        industry: formData.industry.trim()
      });

      if (response.status === 'success') {
        onSuccess(response.vendor);
        onClose();
      } else {
        onError(response.error || 'Failed to update vendor');
      }
    } catch (error: any) {
      console.error('Error updating vendor:', error);
      onError(error.response?.data?.detail || 'Failed to update vendor');
    } finally {
      setLoading(false);
    }
  };

  const hasChanges = (): boolean => {
    if (!originalData) return false;
    
    return (
      formData.vendor_name !== originalData.vendor_name ||
      formData.domain !== originalData.domain ||
      formData.tier !== originalData.tier ||
      formData.portfolio !== originalData.portfolio ||
      formData.industry !== originalData.industry
    );
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Edit Vendor</h2>
          <button 
            type="button" 
            className="close-btn" 
            onClick={onClose}
            disabled={loading}
          >
            <i className="fas fa-times"></i>
          </button>
        </div>

        {loadingDetails ? (
          <div className="loading-container" style={{ padding: '2rem', textAlign: 'center' }}>
            <i className="fas fa-spinner fa-spin" style={{ fontSize: '2rem', color: '#6366f1' }}></i>
            <p style={{ marginTop: '1rem', color: '#6b7280' }}>Loading vendor details...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="vendor_name">
                Vendor Name: <span style={{color: 'red'}}>*</span>
              </label>
              <input
                id="vendor_name"
                type="text"
                value={formData.vendor_name}
                onChange={(e) => handleInputChange('vendor_name', e.target.value)}
                className={`form-control ${validationErrors.vendor_name ? 'error' : ''}`}
                required
                disabled={loading}
              />
              {validationErrors.vendor_name && (
                <small className="error-message">{validationErrors.vendor_name}</small>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="domain">
                Vendor Domain: <span style={{color: 'red'}}>*</span>
              </label>
              <input
                id="domain"
                type="text"
                value={formData.domain}
                onChange={(e) => handleInputChange('domain', e.target.value)}
                className={`form-control ${validationErrors.domain ? 'error' : ''}`}
                required
                disabled={loading}
                placeholder="example.com"
              />
              {formData.domain && extractDomainFromInput(formData.domain) && (
                <small className="text-muted">
                  Domain Stored: <strong>{extractDomainFromInput(formData.domain)}</strong>
                </small>
              )}
              {validationErrors.domain && (
                <small className="error-message">{validationErrors.domain}</small>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="tier">
                Tier: <span style={{color: 'red'}}>*</span>
              </label>
              <select
                id="tier"
                value={formData.tier}
                onChange={(e) => handleInputChange('tier', e.target.value)}
                className={`form-control ${validationErrors.tier ? 'error' : ''}`}
                required
                disabled={loading}
              >
                <option value="">Select tier...</option>
                {finalTierOptions.map(tier => (
                  <option key={tier} value={tier}>{tier}</option>
                ))}
              </select>
              {validationErrors.tier && (
                <small className="error-message">{validationErrors.tier}</small>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="portfolio">
                Portfolio: <span style={{color: 'red'}}>*</span>
              </label>
              <select
                id="portfolio"
                value={formData.portfolio}
                onChange={(e) => handleInputChange('portfolio', e.target.value)}
                className={`form-control ${validationErrors.portfolio ? 'error' : ''}`}
                required
                disabled={loading}
              >
                <option value="">Select portfolio...</option>
                {finalPortfolioOptions.map(portfolio => (
                  <option key={portfolio} value={portfolio}>{portfolio}</option>
                ))}
              </select>
              {validationErrors.portfolio && (
                <small className="error-message">{validationErrors.portfolio}</small>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="industry">Industry:</label>
              <select
                id="industry"
                value={formData.industry}
                onChange={(e) => handleInputChange('industry', e.target.value)}
                className="form-control"
                disabled={loading}
              >
                <option value="">Select industry (optional)...</option>
                {finalIndustryOptions.map(industry => (
                  <option key={industry} value={industry}>{industry}</option>
                ))}
              </select>
            </div>

            <div className="modal-actions">
              <button 
                type="button" 
                className="btn btn-secondary" 
                onClick={onClose}
                disabled={loading}
              >
                Cancel
              </button>
              <button 
                type="submit" 
                className="btn btn-primary" 
                disabled={loading || !hasChanges()}
              >
                {loading ? (
                  <>
                    <i className="fas fa-spinner fa-spin"></i>
                    Updating...
                  </>
                ) : (
                  'Update Vendor'
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default EditVendorModal;
