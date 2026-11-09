'use client';

import React, { useState, useEffect } from 'react';
import Layout from '../../components/Layout';

interface AnalyticsData {
  riskLevels: string[];
  riskRanges: string[];
  tiers: string[];
  data: number[][];
  totalDomains: number;
}

interface VendorPerformance {
  id: number;
  name: string;
  score: number;
  tier: string;
  trend: number;
}

interface VendorInCell {
  id: number;
  name: string;
  domain: string;
  score: number;
  tier: string;
}

/** Same L-axis as Font Awesome fa-chart-line; trend line slopes downward left-to-right. */
const ChartLineDownIcon = ({ color = '#ef4444' }: { color?: string }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 512 512"
    width="1em"
    height="1em"
    fill="currentColor"
    style={{ color, flexShrink: 0 }}
    aria-hidden
  >
    <path d="M64 400C64 408.8 71.16 416 80 416H480C497.7 416 512 430.3 512 448C512 465.7 497.7 480 480 480H80C35.82 480 0 444.2 0 400V64C0 46.33 14.33 32 32 32C49.67 32 64 46.33 64 64V400z" />
    {/* Slight inset from axes — scale from bottom-left corner of plot area */}
    <g transform="translate(72, 408) scale(0.945) translate(-72, -408)">
      <g transform="translate(0, 512) scale(1, -1)">
        <path d="M342.6 278.6C330.1 291.1 309.9 291.1 297.4 278.6L240 221.3L150.6 310.6C138.1 323.1 117.9 323.1 105.4 310.6C92.88 298.1 92.88 277.9 105.4 265.4L217.4 153.4C229.9 140.9 250.1 140.9 262.6 153.4L320 210.7L425.4 105.4C437.9 92.88 458.1 92.88 470.6 105.4C483.1 117.9 483.1 138.1 470.6 150.6L342.6 278.6z" />
      </g>
    </g>
  </svg>
);

const Analytics = () => {
  const [analyticsData, setAnalyticsData] = useState<AnalyticsData | null>(null);
  const [vendorPerformance, setVendorPerformance] = useState<{
    highest: VendorPerformance[];
    lowest: VendorPerformance[];
    improvement: VendorPerformance[];
    decline: VendorPerformance[];
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Modal state
  const [showVendorModal, setShowVendorModal] = useState(false);
  const [selectedCellVendors, setSelectedCellVendors] = useState<VendorInCell[]>([]);
  const [modalTitle, setModalTitle] = useState('');
  const [loadingVendors, setLoadingVendors] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Helper function to get rating badge class
  const getRatingBadgeClass = (score: number) => {
    if (score >= 800) return 'analytics-rating-badge-a';
    if (score >= 600) return 'analytics-rating-badge-b';
    if (score >= 400) return 'analytics-rating-badge-c';
    if (score >= 200) return 'analytics-rating-badge-d';
    return 'analytics-rating-badge-f';
  };

  // Helper function to get rating letter
  const getRatingLetter = (score: number) => {
    if (score >= 800) return 'A';
    if (score >= 600) return 'B';
    if (score >= 400) return 'C';
    if (score >= 200) return 'D';
    return 'F';
  };

  const fetchAnalyticsData = async () => {
    try {
      setLoading(true);
      
      // Fetch heatmap data
      const heatmapResponse = await fetch('/api/analytics/domain-distribution');
      if (!heatmapResponse.ok) {
        throw new Error('Failed to fetch analytics data');
      }
      const heatmapData = await heatmapResponse.json();
      setAnalyticsData(heatmapData);
      
      // Fetch vendor performance data
      const performanceResponse = await fetch('/api/analytics/vendor-performance');
      if (!performanceResponse.ok) {
        throw new Error('Failed to fetch vendor performance data');
      }
      const performanceData = await performanceResponse.json();
      // Extract data if wrapped in status object, otherwise use directly
      const vendorData = performanceData.status ? {
        highest: performanceData.highest || [],
        lowest: performanceData.lowest || [],
        improvement: performanceData.improvement || [],
        decline: performanceData.decline || []
      } : performanceData;
      setVendorPerformance(vendorData);
      
    } catch (error) {
      console.error('Error fetching analytics data:', error);
      setError('Failed to load analytics data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyticsData();
  }, []);

  // Function to fetch vendors for a specific cell
  const fetchVendorsForCell = async (riskLevel: string, riskRange: string, tierName: string) => {
    try {
      setLoadingVendors(true);
      const response = await fetch(`/api/analytics/vendors-by-cell?riskLevel=${riskLevel}&riskRange=${encodeURIComponent(riskRange)}&tier=${encodeURIComponent(tierName)}`);
      if (!response.ok) {
        throw new Error('Failed to fetch vendors');
      }
      const data = await response.json();
      return data.vendors || [];
    } catch (error) {
      console.error('Error fetching vendors for cell:', error);
      return [];
    } finally {
      setLoadingVendors(false);
    }
  };

  // Handle cell click
  const handleCellClick = async (riskLevel: string, riskRange: string, tierName: string, count: number) => {
    if (count === 0) return;
    
    setModalTitle(`${riskLevel} (${riskRange}) - ${tierName}`);
    setShowVendorModal(true);
    setSelectedCellVendors([]);
    setSearchQuery(''); // Reset search when opening modal
    
    const vendors = await fetchVendorsForCell(riskLevel, riskRange, tierName);
    setSelectedCellVendors(vendors);
  };

  // Filter vendors based on search query
  const filteredVendors = selectedCellVendors.filter(vendor => 
    vendor.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    vendor.domain.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <Layout activeSection="analytics">
        <div className="content-section active">
          <div className="page-header">
            <h1>Analytics</h1>
            <p>Domain distribution analysis across score ranges and tiers</p>
          </div>
          <div className="loading-container" style={{ textAlign: 'center', padding: '50px' }}>
            <i className="fas fa-spinner fa-spin fa-2x"></i>
            <p>Loading analytics data...</p>
          </div>
        </div>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout activeSection="analytics">
        <div className="content-section active">
          <div className="page-header">
            <h1>Analytics</h1>
            <p>Domain distribution analysis across score ranges and tiers</p>
          </div>
          <div className="error-container" style={{ textAlign: 'center', padding: '50px' }}>
            <i className="fas fa-exclamation-triangle fa-2x text-danger"></i>
            <p className="text-danger">{error}</p>
            <button className="btn btn-primary" onClick={fetchAnalyticsData}>
              Retry
            </button>
          </div>
        </div>
      </Layout>
    );
  }

  // Risk levels and their properties
  const riskLevels = [
    { level: 'A', range: '801-950', color: '#22c55e', label: 'High' },
    { level: 'B', range: '601-800', color: '#84cc16', label: '' },
    { level: 'C', range: '401-600', color: '#fbbf24', label: '' },
    { level: 'D', range: '201-400', color: '#f97316', label: '' },
    { level: 'F', range: '0-200', color: '#ef4444', label: 'Low' }
  ];

  // Tiers and their properties (must match backend order: Tier 1, Tier 2, Tier 3, Untiered)
  const tiers = [
    { name: 'Tier 1', number: '1', impact: '' },
    { name: 'Tier 2', number: '2', impact: '' },
    { name: 'Tier 3', number: '3', impact: 'Low' },
    { name: 'Untiered', number: '', impact: 'High' }
  ];

  return (
    <Layout activeSection="analytics">
      <div className="content-section active">
        <div className="page-header">
          <h1>Analytics</h1>
        </div>

        <div className="section-content">
          <div className="analytics-heatmap-container">
            
            {/* Chart Title */}
            <h2 className="analytics-section-title">
              Vendor Security Ratings by Business Impact
            </h2>

            {/* Heatmap Grid */}
            <div style={{ position: 'relative' }}>
              
              {/* Y-axis label */}
              <div className="analytics-axis-label" style={{
                position: 'absolute',
                left: '-40px',
                top: '50%',
                transform: 'rotate(-90deg) translateY(-50%)',
                transformOrigin: 'center'
              }}>
                Risk Levels
              </div>

                             {/* Main grid container */}
               <div style={{
                 display: 'grid',
                 gridTemplateColumns: '200px repeat(4, 1fr)',
                 gridTemplateRows: 'repeat(5, 80px) auto auto',
                 gap: '8px',
                 marginLeft: '60px'
               }}>

                {/* Risk level rows */}
                                 {riskLevels.map((risk, riskIndex) => (
                   <React.Fragment key={risk.level}>
                     {/* Risk level label */}
                     <div style={{
                       display: 'flex',
                       alignItems: 'center',
                       padding: '0 20px'
                     }}>
                     <div className="analytics-axis-label" style={{
                        width: '40px',
                        textAlign: 'left'
                      }}>
                        {riskIndex === 0 ? risk.label : ''}
                      </div>
                       <div style={{
                         width: '40px',
                         height: '40px',
                         borderRadius: '50%',
                         backgroundColor: risk.color,
                         color: 'white',
                         display: 'flex',
                         alignItems: 'center',
                         justifyContent: 'center',
                         fontSize: '18px',
                         fontWeight: '700',
                         margin: '0 16px',
                         flexShrink: 0
                       }}>
                         {risk.level}
                       </div>
                      <div className="analytics-risk-label">
                        {risk.range}
                      </div>
                     </div>

                    {/* Data cells for this risk level */}
                    {tiers.map((tier, tierIndex) => {
                      const value = analyticsData?.data?.[riskIndex]?.[tierIndex] || 0;
                      const hasValue = value > 0;
                      
                      return (
                        <div
                          key={`${risk.level}-${tier.name}`}
                          className={hasValue ? '' : 'analytics-empty-cell'}
                          style={{
                            backgroundColor: hasValue ? risk.color : undefined,
                            borderRadius: '12px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: hasValue ? '24px' : '16px',
                            fontWeight: hasValue ? '700' : '400',
                            color: hasValue ? 'white' : '#9ca3af',
                            cursor: hasValue ? 'pointer' : 'default',
                            transition: 'all 0.2s ease',
                            border: hasValue ? 'none' : undefined,
                            minHeight: '60px'
                          }}
                          title={`${risk.level} (${risk.range}) - ${tier.name}: ${value} domains`}
                          onClick={() => hasValue && handleCellClick(risk.level, risk.range, tier.name, value)}
                          onMouseEnter={(e) => {
                            if (hasValue) {
                              e.currentTarget.style.transform = 'scale(1.05)';
                              e.currentTarget.style.boxShadow = '0 8px 25px rgba(0, 0, 0, 0.15)';
                            }
                          }}
                          onMouseLeave={(e) => {
                            if (hasValue) {
                              e.currentTarget.style.transform = 'scale(1)';
                              e.currentTarget.style.boxShadow = 'none';
                            }
                          }}
                        >
                          {hasValue ? value : ''}
                        </div>
                      );
                    })}
                  </React.Fragment>
                ))}

                                 {/* Tier headers at bottom */}
                 <div style={{
                   display: 'flex',
                   alignItems: 'center',
                   justifyContent: 'flex-start',
                   paddingLeft: '20px'
                 }}>
                   <span className="analytics-axis-label">
                     {riskLevels[4].label}
                   </span>
                 </div>

                 {tiers.map((tier, index) => (
                   <div key={`tier-${index}-${tier.name}`} style={{
                     display: 'flex',
                     flexDirection: 'column',
                     alignItems: 'center',
                     justifyContent: 'center',
                     padding: '10px'
                   }}>
                     {tier.number && (
                       <div style={{
                         width: '32px',
                         height: '32px',
                         borderRadius: '50%',
                         backgroundColor: '#3b82f6',
                         color: 'white',
                         display: 'flex',
                         alignItems: 'center',
                         justifyContent: 'center',
                         fontSize: '16px',
                         fontWeight: '600',
                         marginBottom: '8px',
                         flexShrink: 0
                       }}>
                         {tier.number}
                       </div>
                     )}
                      {!tier.number && (
                        <div style={{
                          width: '32px',
                          height: '32px',
                          borderRadius: '50%',
                          backgroundColor: '#3b82f6',
                          color: 'white',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '16px',
                          fontWeight: '600',
                          marginBottom: '8px',
                          flexShrink: 0
                        }}>U</div>
                      )}
                     <div className="analytics-tier-name">
                       {tier.name}
                     </div>
                   </div>
                 ))}

                                 {/* Business Impact labels */}
                 <div></div>
                 <div style={{
                   display: 'flex',
                   alignItems: 'center',
                   justifyContent: 'center'
                 }}>
                   <span className="analytics-axis-label">
                     Low
                   </span>
                 </div>
                 <div></div>
                 <div></div>
                 <div style={{
                   display: 'flex',
                   alignItems: 'center',
                   justifyContent: 'center'
                 }}>
                   <span className="analytics-axis-label">
                     High
                   </span>
                 </div>

                 {/* Business Impact main label */}
                 <div></div>
                 <div style={{
                   gridColumn: '2 / -1',
                   display: 'flex',
                   alignItems: 'center',
                   justifyContent: 'center',
                   marginTop: '10px'
                 }}>
                   <span className="analytics-business-impact-label">
                     Business Impact
                   </span>
                 </div>
                             </div>
             </div>
           </div>

           {/* Vendor Performance Tables */}
          {vendorPerformance && (
            <div style={{ marginTop: '40px' }}>
              <h2 className="analytics-performance-title">
                Highest And Lowest Rated Vendors
              </h2>

               <div style={{ 
                 display: 'grid', 
                 gridTemplateColumns: '1fr 1fr',
                 gap: '30px',
                 marginBottom: '40px'
               }}>
                 {/* Highest Rated Vendors */}
                <div className="analytics-vendor-card">
                  <div style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    marginBottom: '20px',
                    gap: '8px'
                  }}>
                    <i className="fas fa-chart-line" style={{ color: '#22c55e' }}></i>
                    <h3 className="analytics-vendor-card-title">
                      Highest rated vendors
                    </h3>
                  </div>

                   <div style={{ overflowX: 'auto' }}>
                     <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                       <thead>
                         <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
                           <th className="analytics-table-header"></th>
                           <th className="analytics-table-header">Rating</th>
                           <th className="analytics-table-header">Vendor</th>
                           <th className="analytics-table-header" style={{ textAlign: 'center' }}>Tier</th>
                         </tr>
                       </thead>
                       <tbody>
                         {vendorPerformance.highest.map((vendor, index) => (
                           <tr key={vendor.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                             <td className="analytics-table-cell-secondary">
                               {index + 1}
                             </td>
                             <td style={{ padding: '12px 8px' }}>
                               <div className="analytics-rating-badge analytics-rating-badge-a">
                                 <span style={{ fontSize: '12px' }}>A</span>
                                 {vendor.score}
                               </div>
                             </td>
                             <td className="analytics-table-cell">
                               {vendor.name}
                             </td>
                             <td style={{ padding: '12px 8px', textAlign: 'center' }}>
                               <div style={{
                                 width: '24px',
                                 height: '24px',
                                 borderRadius: '50%',
                                 backgroundColor: '#3b82f6',
                                 color: 'white',
                                 display: 'flex',
                                 alignItems: 'center',
                                 justifyContent: 'center',
                                 fontSize: '12px',
                                 fontWeight: '600',
                                 margin: '0 auto'
                               }}>
                                 {vendor?.tier === 'Untiered' ? 'U' : vendor?.tier?.replace('Tier ', '') || ''}
                               </div>
                             </td>
                           </tr>
                         ))}
                       </tbody>
                     </table>
                   </div>
                 </div>

                 {/* Greatest Improvement */}
                <div className="analytics-vendor-card">
                  <div style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    marginBottom: '20px',
                    gap: '8px'
                  }}>
                    <i className="fas fa-chart-line" style={{ color: '#22c55e' }}></i>
                    <h3 className="analytics-vendor-card-title">
                      Greatest Improvement (last 30 days)
                    </h3>
                  </div>

                   <div style={{ overflowX: 'auto' }}>
                     <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                       <thead>
                         <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}></th>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Rating</th>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Vendor</th>
                           <th style={{ padding: '12px 8px', textAlign: 'center', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Tier</th>
                           <th style={{ padding: '12px 8px', textAlign: 'right', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Trend</th>
                         </tr>
                       </thead>
                       <tbody>
                         {vendorPerformance.improvement && vendorPerformance.improvement.length > 0 ? (
                           vendorPerformance.improvement.map((vendor, index) => (
                           <tr key={vendor.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                             <td style={{ padding: '12px 8px', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>
                               {index + 1}
                             </td>
                             <td style={{ padding: '12px 8px' }}>
                               <div className={`analytics-rating-badge ${getRatingBadgeClass(vendor.score)}`}>
                                 <span style={{ fontSize: '12px' }}>
                                   {getRatingLetter(vendor.score)}
                                 </span>
                                 {vendor.score}
                               </div>
                             </td>
                             <td className="analytics-table-cell">
                               {vendor.name}
                             </td>
                             <td style={{ padding: '12px 8px', textAlign: 'center' }}>
                               <div style={{
                                 width: '24px',
                                 height: '24px',
                                 borderRadius: '50%',
                                 backgroundColor: vendor?.tier === 'Untiered' ? '#e5e7eb' : '#3b82f6',
                                 color: vendor?.tier === 'Untiered' ? '#6b7280' : 'white',
                                 display: 'flex',
                                 alignItems: 'center',
                                 justifyContent: 'center',
                                 fontSize: '12px',
                                 fontWeight: '600',
                                 margin: '0 auto'
                               }}>
                                 {vendor?.tier === 'Untiered' ? 'U' : vendor?.tier?.replace('Tier ', '') || ''}
                               </div>
                             </td>
                             <td style={{ padding: '12px 8px', textAlign: 'right' }}>
                               <div style={{
                                 display: 'inline-flex',
                                 alignItems: 'center',
                                 color: '#22c55e',
                                 fontSize: '14px',
                                 fontWeight: '500',
                                 gap: '2px'
                               }}>
                                 ▲{vendor.trend}
                               </div>
                             </td>
                           </tr>
                           ))
                         ) : (
                           <tr>
                             <td colSpan={5} style={{ padding: '20px', textAlign: 'center', color: '#6b7280' }}>
                               No data available
                             </td>
                           </tr>
                         )}
                       </tbody>
                     </table>
                   </div>
                 </div>
               </div>

               <div style={{ 
                 display: 'grid', 
                 gridTemplateColumns: '1fr 1fr',
                 gap: '30px'
               }}>
                 {/* Lowest Rated Vendors */}
                <div className="analytics-vendor-card">
                  <div style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    marginBottom: '20px',
                    gap: '8px'
                  }}>
                    <ChartLineDownIcon />
                    <h3 className="analytics-vendor-card-title">
                      Lowest rated vendors
                    </h3>
                  </div>

                   <div style={{ overflowX: 'auto' }}>
                     <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                       <thead>
                         <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}></th>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Rating</th>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Vendor</th>
                           <th style={{ padding: '12px 8px', textAlign: 'center', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Tier</th>
                         </tr>
                       </thead>
                       <tbody>
                         {vendorPerformance.lowest.map((vendor, index) => (
                           <tr key={vendor.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                             <td style={{ padding: '12px 8px', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>
                               {index + 1}
                             </td>
                             <td style={{ padding: '12px 8px' }}>
                               <div className={`analytics-rating-badge ${getRatingBadgeClass(vendor.score)}`}>
                                 <span style={{ fontSize: '12px' }}>
                                   {getRatingLetter(vendor.score)}
                                 </span>
                                 {vendor.score}
                               </div>
                             </td>
                             <td className="analytics-table-cell">
                               {vendor.name}
                             </td>
                             <td style={{ padding: '12px 8px', textAlign: 'center' }}>
                               <div style={{
                                 width: '24px',
                                 height: '24px',
                                 borderRadius: '50%',
                                 backgroundColor: vendor?.tier === 'Untiered' ? '#e5e7eb' : '#3b82f6',
                                 color: vendor?.tier === 'Untiered' ? '#6b7280' : 'white',
                                 display: 'flex',
                                 alignItems: 'center',
                                 justifyContent: 'center',
                                 fontSize: '12px',
                                 fontWeight: '600',
                                 margin: '0 auto'
                               }}>
                                 {vendor?.tier === 'Untiered' ? 'U' : vendor?.tier?.replace('Tier ', '') || ''}
                               </div>
                             </td>
                           </tr>
                         ))}
                       </tbody>
                     </table>
                   </div>
                 </div>

                 {/* Greatest Decline */}
                <div className="analytics-vendor-card">
                  <div style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    marginBottom: '20px',
                    gap: '8px'
                  }}>
                    <ChartLineDownIcon />
                    <h3 className="analytics-vendor-card-title">
                      Greatest Decline (last 30 days)
                    </h3>
                  </div>

                   <div style={{ overflowX: 'auto' }}>
                     <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                       <thead>
                         <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}></th>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Rating</th>
                           <th style={{ padding: '12px 8px', textAlign: 'left', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Vendor</th>
                           <th style={{ padding: '12px 8px', textAlign: 'center', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Tier</th>
                           <th style={{ padding: '12px 8px', textAlign: 'right', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>Trend</th>
                         </tr>
                       </thead>
                       <tbody>
                         {vendorPerformance.decline && vendorPerformance.decline.length > 0 ? (
                           vendorPerformance.decline.map((vendor, index) => (
                           <tr key={vendor.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                             <td style={{ padding: '12px 8px', fontSize: '14px', fontWeight: '500', color: '#6b7280' }}>
                               {index + 1}
                             </td>
                             <td style={{ padding: '12px 8px' }}>
                               <div className={`analytics-rating-badge ${getRatingBadgeClass(vendor.score)}`}>
                                 <span style={{ fontSize: '12px' }}>
                                   {getRatingLetter(vendor.score)}
                                 </span>
                                 {vendor.score}
                               </div>
                             </td>
                             <td className="analytics-table-cell">
                               {vendor.name}
                             </td>
                             <td style={{ padding: '12px 8px', textAlign: 'center' }}>
                               <div style={{
                                 width: '24px',
                                 height: '24px',
                                 borderRadius: '50%',
                                 backgroundColor: vendor?.tier === 'Untiered' ? '#e5e7eb' : '#3b82f6',
                                 color: vendor?.tier === 'Untiered' ? '#6b7280' : 'white',
                                 display: 'flex',
                                 alignItems: 'center',
                                 justifyContent: 'center',
                                 fontSize: '12px',
                                 fontWeight: '600',
                                 margin: '0 auto'
                               }}>
                                 {vendor?.tier === 'Untiered' ? 'U' : vendor?.tier?.replace('Tier ', '') || ''}
                               </div>
                             </td>
                             <td style={{ padding: '12px 8px', textAlign: 'right' }}>
                               <div style={{
                                 display: 'inline-flex',
                                 alignItems: 'center',
                                 color: '#ef4444',
                                 fontSize: '14px',
                                 fontWeight: '500',
                                 gap: '2px'
                               }}>
                                 ▼{Math.abs(vendor.trend)}
                               </div>
                             </td>
                           </tr>
                           ))
                         ) : (
                           <tr>
                             <td colSpan={5} style={{ padding: '20px', textAlign: 'center', color: '#6b7280' }}>
                               No data available
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
      </div>

      {/* Vendor List Modal */}
      {showVendorModal && (
        <div 
          className="modal-overlay" 
          onClick={() => setShowVendorModal(false)}
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
        >
          <div 
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            style={{
              backgroundColor: 'white',
              borderRadius: '12px',
              padding: '24px',
              maxWidth: '600px',
              width: '90%',
              maxHeight: '80vh',
              overflow: 'auto',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h2 style={{ margin: 0, fontSize: '20px', fontWeight: '600' }}>{modalTitle}</h2>
              <button
                onClick={() => setShowVendorModal(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '24px',
                  cursor: 'pointer',
                  color: '#6b7280',
                  padding: '0',
                  width: '32px',
                  height: '32px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                ×
              </button>
            </div>

            {loadingVendors ? (
              <div style={{ textAlign: 'center', padding: '40px' }}>
                <i className="fas fa-spinner fa-spin fa-2x" style={{ color: '#3b82f6' }}></i>
                <p style={{ marginTop: '16px', color: '#6b7280' }}>Loading vendors...</p>
              </div>
            ) : selectedCellVendors.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                No vendors found
              </div>
            ) : (
              <div>
                {/* Search Bar */}
                <div style={{ marginBottom: '16px' }}>
                  <div style={{ position: 'relative' }}>
                    <input
                      type="text"
                      placeholder="Search vendors or domains..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '10px 40px 10px 40px',
                        border: '1px solid #d1d5db',
                        borderRadius: '8px',
                        fontSize: '14px',
                        outline: 'none',
                        transition: 'border-color 0.2s'
                      }}
                      onFocus={(e) => e.currentTarget.style.borderColor = '#3b82f6'}
                      onBlur={(e) => e.currentTarget.style.borderColor = '#d1d5db'}
                    />
                    <i 
                      className="fas fa-search" 
                      style={{
                        position: 'absolute',
                        left: '14px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        color: '#9ca3af',
                        fontSize: '14px'
                      }}
                    ></i>
                    {searchQuery && (
                      <button
                        onClick={() => setSearchQuery('')}
                        style={{
                          position: 'absolute',
                          right: '10px',
                          top: '50%',
                          transform: 'translateY(-50%)',
                          background: 'none',
                          border: 'none',
                          color: '#9ca3af',
                          cursor: 'pointer',
                          padding: '4px',
                          fontSize: '16px'
                        }}
                      >
                        ×
                      </button>
                    )}
                  </div>
                </div>

                <p style={{ marginBottom: '16px', color: '#6b7280', fontSize: '14px' }}>
                  {filteredVendors.length} of {selectedCellVendors.length} vendor{selectedCellVendors.length !== 1 ? 's' : ''}
                  {searchQuery && ` matching "${searchQuery}"`}
                </p>

                {filteredVendors.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                    No vendors match your search
                  </div>
                ) : (
                  <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                    {filteredVendors.map((vendor, index) => (
                    <div
                      key={vendor.id}
                      style={{
                        padding: '16px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        cursor: 'pointer',
                        transition: 'background-color 0.2s',
                        borderRadius: '8px',
                        borderBottom: index < filteredVendors.length - 1 ? '1px solid rgba(255, 255, 255, 0.1)' : 'none'
                      }}
                      onMouseEnter={(e) => {
                        // Check if dark mode is active
                        const isDarkMode = document.documentElement.classList.contains('dark-mode') || 
                                          document.body.classList.contains('dark-mode');
                        e.currentTarget.style.backgroundColor = isDarkMode ? '#1e3a5f' : '#f9fafb';
                      }}
                      onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                      onClick={() => window.location.href = `/report/${vendor.domain}`}
                    >
                      <div>
                        <div style={{ fontWeight: '500', marginBottom: '4px' }}>{vendor.name}</div>
                        <div style={{ fontSize: '12px', color: '#6b7280' }}>{vendor.domain}</div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{
                          width: '24px',
                          height: '24px',
                          borderRadius: '50%',
                          backgroundColor: vendor.tier === 'Untiered' ? '#e5e7eb' : '#3b82f6',
                          color: vendor.tier === 'Untiered' ? '#6b7280' : 'white',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '12px',
                          fontWeight: '600'
                        }}>
                          {vendor.tier === 'Untiered' ? 'U' : vendor.tier.replace('Tier ', '')}
                        </div>
                        <div style={{
                          backgroundColor: vendor.score >= 800 ? '#10b981' : 
                                         vendor.score >= 600 ? '#84cc16' :
                                         vendor.score >= 400 ? '#f59e0b' :
                                         vendor.score >= 200 ? '#ef4444' : '#dc2626',
                          color: 'white',
                          padding: '4px 12px',
                          borderRadius: '6px',
                          fontSize: '14px',
                          fontWeight: '600',
                          minWidth: '60px',
                          textAlign: 'center'
                        }}>
                          {vendor.score}
                        </div>
                      </div>
                      </div>
                    ))}
                    </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </Layout>
  );
};

export default Analytics;