'use client';

import React, { useState, useEffect } from 'react';
import { vendorApi, type Vendor } from '../lib/api';
import VendorLogoImage from './VendorLogoImage';

interface VendorScore {
  category: string;
  score: number;
  maxScore: number;
  grade: string;
}

interface VendorComparisonData {
  vendor: Vendor;
  scores: VendorScore[];
  overallScore: number;
}

const VendorComparison: React.FC = () => {
  const [vendors, setVendors] = useState<Vendor[]>([]);
  const [selectedVendors, setSelectedVendors] = useState<VendorComparisonData[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showVendorDialog, setShowVendorDialog] = useState(false);
  const [dialogVendors, setDialogVendors] = useState<Vendor[]>([]);
  const [searchTerm, setSearchTerm] = useState('');

  // Security scan categories as row headers - matching the image
  const scanCategories = [
    'Website',
    'Encryption',
    'Network',
    'DNS Security',
    'Domain Reputation',
    'Email'
  ];

  useEffect(() => {
    loadVendors();
  }, []);

  const loadVendors = async () => {
    try {
      setLoading(true);
      const response = await vendorApi.getVendors();
      setVendors(response.vendors || []);
    } catch (err) {
      setError('Failed to load vendors');
      console.error('Error loading vendors:', err);
    } finally {
      setLoading(false);
    }
  };

  const openVendorDialog = () => {
    // Filter out already selected vendors
    const availableVendors = vendors.filter(v => !selectedVendors.find(sv => sv.vendor.id === v.id));
    setDialogVendors(availableVendors);
    setShowVendorDialog(true);
    setSearchTerm('');
  };

  const clearComparison = () => {
    setSelectedVendors([]);
    setError(null);
  };

  const closeVendorDialog = () => {
    setShowVendorDialog(false);
    setDialogVendors([]);
    setSearchTerm('');
  };

  const addVendor = async (vendor: Vendor) => {
    if (selectedVendors.length >= 4) {
      alert('Maximum 4 vendors can be compared at once');
      return;
    }

    try {
      setLoading(true);
      
      // Fetch real scores from the API
      const response = await fetch('/api/vendors/comparison-scores', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          vendor_ids: [vendor.id]
        })
      });

      if (!response.ok) {
        throw new Error('Failed to fetch vendor scores');
      }

      const data = await response.json();
      
      if (data.status === 'success' && data.vendors.length > 0) {
        const vendorData = data.vendors[0];
        
        // Map the scores to our expected format
        const scores: VendorScore[] = scanCategories.map(category => {
          // Map frontend category names to backend category names (exact match from API)
          const categoryMapping: { [key: string]: string } = {
            'Website': 'Website',
            'Encryption': 'Encryption', 
            'Network': 'Network',
            'DNS Security': 'DNS',
            'Domain Reputation': 'Domain Reputation',
            'Email': 'Email'
          };
          
          const backendCategory = categoryMapping[category] || category;
          const categoryScore = vendorData.scores?.[backendCategory];
          
          if (categoryScore && categoryScore.score) {
            return {
              category,
              score: categoryScore.score,
              maxScore: categoryScore.max_score || 950,
              grade: getGradeFromScore(categoryScore.score, categoryScore.max_score || 950)
            };
          }
          
          // Default values if no score found - use N/A to indicate no data
          return {
            category,
            score: 0,
            maxScore: 950,
            grade: 'N/A'
          };
        });

        const vendorComparisonData: VendorComparisonData = {
          vendor,
          scores,
          overallScore: vendorData.overall_score || vendor.scores?.current || 0
        };

        setSelectedVendors(prev => [...prev, vendorComparisonData]);
        closeVendorDialog();
      } else {
        throw new Error('No vendor data received');
      }
    } catch (error) {
      console.error('Error adding vendor:', error);
      // Show a less intrusive error - just log it for now
      // The user can try again if needed
    } finally {
      setLoading(false);
    }
  };

  const removeVendor = (vendorId: number) => {
    setSelectedVendors(prev => prev.filter(v => v.vendor.id !== vendorId));
  };

  const getGradeFromScore = (score: number, maxScore: number = 950): string => {
    // Use absolute score ranges based on the image logic
    if (score >= 801) return 'A';  // 801-950: Low Risk
    if (score >= 601) return 'B';  // 601-800
    if (score >= 401) return 'C';  // 401-600
    if (score >= 201) return 'D';  // 201-400
    return 'F';                    // 0-200: High Risk
  };

  const getScoreColor = (score: number, maxScore: number): string => {
    const percentage = (score / maxScore) * 100;
    if (percentage >= 80) return '#22c55e'; // Green
    if (percentage >= 60) return '#f59e0b'; // Yellow
    if (percentage >= 40) return '#f97316'; // Orange
    return '#ef4444'; // Red
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

  // Filter vendors based on search term
  const filteredVendors = dialogVendors.filter(vendor =>
    vendor.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    vendor.domain.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="vendor-comparison-container">
      {/* Header Section */}
      <div className="comparison-header">
        <h2>Vendor Security Comparison</h2>
        <p>Compare security scores across multiple vendors to make informed decisions</p>
      </div>

      {/* Vendor Selection Header */}
      <div className="vendor-selection-header">
        <div className="selection-info">
          <h3>Selected Vendors ({selectedVendors.length}/4)</h3>
          <p>Choose up to 4 vendors to compare their security scores</p>
        </div>
        <button 
          className="refresh-btn"
          onClick={clearComparison}
          disabled={selectedVendors.length === 0}
        >
          <i className="fas fa-trash-alt"></i>
          Clear
        </button>
      </div>

      {/* Comparison Table - Always show the matrix */}
      <div className="comparison-table-container">
        <table className="comparison-table">
          <thead>
            <tr>
              <th className="category-header">
                <div className="overall-score-header">Overall score</div>
              </th>
              {/* Always show 4 columns for vendors */}
              {[0, 1, 2, 3].map((columnIndex) => {
                const vendorData = selectedVendors[columnIndex];
                return (
                  <th key={columnIndex} className="vendor-header">
                    {vendorData ? (
                      <div className="vendor-header-content">
                        <div className="vendor-info">
                          <div className="overall-score-display">
                            <span 
                              className="grade-circle"
                              style={{ backgroundColor: getGradeColor(getGradeFromScore(vendorData.overallScore, 950)) }}
                            >
                              {getGradeFromScore(vendorData.overallScore, 950)}
                            </span>
                            <span 
                              className="score-number"
                              style={{ color: getGradeColor(getGradeFromScore(vendorData.overallScore, 950)) }}
                            >
                              {vendorData.overallScore}
                            </span>
                          </div>
                          <div className="vendor-details-with-logo">
                            <div className="vendor-logo-header">
                              <VendorLogoImage
                                domain={vendorData.vendor.domain}
                                vendorName={vendorData.vendor.name}
                                fallbackLogo={vendorData.vendor.logo}
                                className="vendor-header-logo"
                              />
                            </div>
                            <div className="vendor-text-info">
                              <div className="vendor-name">{vendorData.vendor.name}</div>
                              <div className="vendor-domain">{vendorData.vendor.domain}</div>
                            </div>
                          </div>
                        </div>
                        <button 
                          className="remove-vendor-btn"
                          onClick={() => removeVendor(vendorData.vendor.id)}
                          title="Remove vendor"
                        >
                          <i className="fas fa-times"></i>
                        </button>
                      </div>
                    ) : (
                      <div className="empty-vendor-column">
                        <button 
                          className="add-vendor-column-btn"
                          onClick={openVendorDialog}
                        >
                          <i className="fas fa-search"></i>
                        </button>
                        <div className="add-vendor-text">Add vendor</div>
                      </div>
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>



            {/* Security Categories */}
            {scanCategories.map((category, categoryIndex) => (
              <tr key={category} className="category-row">
                <td className="category-cell">
                  <div className="category-name">{category}</div>
                </td>
                                 {[0, 1, 2, 3].map((columnIndex) => {
                   const vendorData = selectedVendors[columnIndex];
                   if (vendorData) {
                     const categoryScore = vendorData.scores && Array.isArray(vendorData.scores) 
                       ? vendorData.scores.find(s => s.category === category)
                       : null;
                     
                     // Check if we have actual score data
                     if (categoryScore && categoryScore.score > 0) {
                       return (
                         <td key={`${columnIndex}-${category}`} className="score-cell">
                           <div className="score-display">
                             <span 
                               className="grade-circle small"
                               style={{ backgroundColor: getGradeColor(categoryScore.grade) }}
                             >
                               {categoryScore.grade}
                             </span>
                             <span className="score-number">{categoryScore.score}</span>
                           </div>
                         </td>
                       );
                     } else {
                       // Show N/A for missing scores
                       return (
                         <td key={`${columnIndex}-${category}`} className="score-cell">
                           <div className="score-display">
                             <span 
                               className="grade-circle small na"
                               style={{ backgroundColor: '#9ca3af' }}
                             >
                               N/A
                             </span>
                             <span className="score-number">0</span>
                           </div>
                         </td>
                       );
                     }
                   } else {
                     return (
                       <td key={`empty-${columnIndex}-${category}`} className="score-cell">
                         <div className="empty-cell"></div>
                       </td>
                     );
                   }
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Vendor Selection Dialog */}
      {showVendorDialog && (
        <div className="modal-overlay">
          <div className="vendor-dialog">
            <div className="dialog-header">
              <h3>Select Vendor to Compare</h3>
              <button className="close-btn" onClick={closeVendorDialog}>
                <i className="fas fa-times"></i>
              </button>
            </div>
            
            <div className="dialog-content">
              <div className="search-container">
                <div className="search-input-wrapper">
                  <input
                    type="text"
                    placeholder="Search vendors by name or domain..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="search-input"
                  />
                </div>
              </div>

              <div className="vendor-list">
                {filteredVendors.length > 0 ? (
                  filteredVendors.map(vendor => (
                    <div 
                      key={vendor.id} 
                      className="vendor-item"
                      onClick={() => addVendor(vendor)}
                    >
                      <div className="vendor-item-content">
                        <div className="vendor-item-logo">
                          <VendorLogoImage
                            domain={vendor.domain}
                            vendorName={vendor.name}
                            fallbackLogo={vendor.logo}
                          />
                        </div>
                        <div className="vendor-item-info">
                          <div className="vendor-item-name">{vendor.name}</div>
                          <div className="vendor-item-domain">{vendor.domain}</div>
                        </div>
                                                 <div className="vendor-item-score">
                           <span 
                             className="score"
                             style={{ color: getGradeColor(getGradeFromScore(vendor.scores?.current || 0, 950)) }}
                           >
                             {vendor.scores?.current || 0}
                           </span>
                           <span className="grade" style={{ color: getGradeColor(getGradeFromScore(vendor.scores?.current || 0, 950)) }}>
                             {getGradeFromScore(vendor.scores?.current || 0, 950)}
                           </span>
                         </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="no-results">
                    <i className="fas fa-search"></i>
                    <p>No vendors found matching &quot;{searchTerm}&quot;</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}


    </div>
  );
};

const getCategoryIcon = (category: string): string => {
  const icons: { [key: string]: string } = {
    'Website': 'fa-globe',
    'Network': 'fa-network-wired',
    'Encryption': 'fa-lock',
    'DNS Security': 'fa-server',
    'Email': 'fa-envelope',
    'Domain Reputation': 'fa-shield-alt'
  };
  return icons[category] || 'fa-shield-alt';
};

export default VendorComparison; 