'use client';

import React, { useState, useEffect } from 'react';
import styles from './AIInsights.module.css';

// Hook to detect dark mode
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

interface AIInsightsProps {
  domain: string;
  vendorData: {
    name: string;
    overall_score: number;
    grade: string;
  };
  vulnerabilityData: {
    total_vulnerabilities: number;
    severity_breakdown: {
      Critical?: number;
      High?: number;
      Medium?: number;
      Low?: number;
    };
    categories_with_issues: number;
  };
  scoresData: any[];
  subdomainsCount: number;
}

interface AIInsightsData {
  vendor_overview: string;
  overall_security_posture: string;
  next_steps: string[];
  sources: {
    domains: number;
    ip_addresses: number;
    risks: number;
    documents: number;
    questionnaires: number;
  };
  last_generated: string;
}

const AIInsights: React.FC<AIInsightsProps> = ({
  domain,
  vendorData,
  vulnerabilityData,
  scoresData,
  subdomainsCount
}) => {
  const [insights, setInsights] = useState<AIInsightsData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [noVulnerabilities, setNoVulnerabilities] = useState(false);
  const isDarkMode = useDarkMode();

  useEffect(() => {
    generateInsights();
  }, [domain, vulnerabilityData.total_vulnerabilities]);

  const generateInsights = async (forceRefresh = false) => {
    try {
      setLoading(true);
      setError(null);
      setNoVulnerabilities(false);

      const response = await fetch('/api/ai-insights/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          domain,
          vendor: vendorData,
          vulnerabilities: vulnerabilityData,
          scores: scoresData,
          subdomains_count: subdomainsCount,
          force_refresh: forceRefresh
        })
      });

      if (!response.ok) {
        throw new Error('Failed to generate AI insights');
      }

      const data = await response.json();
      if (data.status === 'success') {
        if (data.no_vulnerabilities) {
          // No vulnerabilities found - show appropriate message
          setInsights(null);
          setError(null);
          setNoVulnerabilities(true);
        } else {
          setInsights(data.insights);
          setNoVulnerabilities(false);
          
          // Log cache status for debugging
          if (data.cached) {
            console.log(`AI Insights loaded from cache for ${domain}`);
          } else if (forceRefresh) {
            console.log(`AI Insights generated new insights for ${domain}`);
          } else {
            console.log(`AI Insights generated new insights for ${domain}`);
          }
        }
      } else {
        throw new Error(data.message || 'Failed to generate insights');
      }
    } catch (err) {
      console.error('Error generating AI insights:', err);
      setError('Failed to generate AI insights. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const refreshInsights = () => {
    generateInsights(true); // Force refresh - bypass cache
  };

  if (loading) {
    return (
      <div style={{
        background: isDarkMode ? 'var(--bg-secondary)' : 'white',
        borderRadius: '12px',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
        margin: '2rem 0',
        overflow: 'hidden'
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '1.5rem 2rem',
          borderBottom: '1px solid #e5e7eb'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem'
          }}>
            <div style={{
              width: '32px',
              height: '32px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 50%, #7c3aed 100%)',
              borderRadius: '8px',
              position: 'relative'
            }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L15.09 8.26L22 9L17 14.74L18.18 22L12 18.77L5.82 22L7 14.74L2 9L8.91 8.26L12 2Z" 
                      fill="white" 
                      fillOpacity="0.9"/>
                <circle cx="12" cy="12" r="3" fill="white" fillOpacity="0.7"/>
                <path d="M12 7L13.5 10.5L17 12L13.5 13.5L12 17L10.5 13.5L7 12L10.5 10.5L12 7Z" 
                      fill="white"/>
              </svg>
            </div>
            <h3 style={{
              margin: 0,
              fontSize: '1.25rem',
              fontWeight: 600,
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
            }}>AI Analyst insights</h3>
          </div>
        </div>
        <div style={{
          padding: '3rem 2rem',
          textAlign: 'center',
                color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
        }}>
          <i className="fas fa-spinner fa-spin" style={{
            fontSize: '2rem',
            marginBottom: '1rem',
            display: 'block'
          }}></i>
          <p>Generating AI insights...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        background: isDarkMode ? 'var(--bg-secondary)' : 'white',
        borderRadius: '12px',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
        margin: '2rem 0',
        overflow: 'hidden'
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '1.5rem 2rem',
          borderBottom: '1px solid #e5e7eb'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem'
          }}>
            <div style={{
              width: '32px',
              height: '32px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 50%, #7c3aed 100%)',
              borderRadius: '8px',
              position: 'relative'
            }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L15.09 8.26L22 9L17 14.74L18.18 22L12 18.77L5.82 22L7 14.74L2 9L8.91 8.26L12 2Z" 
                      fill="white" 
                      fillOpacity="0.9"/>
                <circle cx="12" cy="12" r="3" fill="white" fillOpacity="0.7"/>
                <path d="M12 7L13.5 10.5L17 12L13.5 13.5L12 17L10.5 13.5L7 12L10.5 10.5L12 7Z" 
                      fill="white"/>
              </svg>
            </div>
            <h3 style={{
              margin: 0,
              fontSize: '1.25rem',
              fontWeight: 600,
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
            }}>AI Analyst insights</h3>
          </div>
          <button 
            style={{
              background: 'none',
              border: 'none',
                color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
              cursor: 'pointer',
              padding: '0.5rem',
              borderRadius: '6px',
              transition: 'all 0.2s'
            }}
            onClick={refreshInsights}
            title="Generate New AI insights"
            onMouseOver={(e) => {
              e.currentTarget.style.background = '#f3f4f6';
              e.currentTarget.style.color = '#374151';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.background = 'none';
              e.currentTarget.style.color = '#6b7280';
            }}
          >
            <i className="fas fa-sync-alt"></i>
          </button>
        </div>
        <div style={{
          padding: '3rem 2rem',
          textAlign: 'center',
                color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
        }}>
          <i className="fas fa-exclamation-triangle" style={{
            fontSize: '2rem',
            marginBottom: '1rem',
            display: 'block'
          }}></i>
          <p>{error}</p>
          <button 
            style={{
              background: '#3b82f6',
              color: 'white',
              border: 'none',
              padding: '0.5rem 1rem',
              borderRadius: '6px',
              cursor: 'pointer',
              marginTop: '1rem'
            }}
            onClick={refreshInsights}
            title="Generate New AI insights"
            onMouseOver={(e) => {
              e.currentTarget.style.background = '#2563eb';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.background = '#3b82f6';
            }}
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  if (noVulnerabilities) {
    return (
      <div style={{
        background: isDarkMode ? 'var(--bg-secondary)' : 'white',
        borderRadius: '12px',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
        margin: '2rem 0',
        overflow: 'hidden'
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '1.5rem 2rem',
          borderBottom: isDarkMode ? '1px solid var(--border-color)' : '1px solid #e5e7eb'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: '32px',
              height: '32px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'linear-gradient(135deg, #10b981 0%, #059669 50%, #047857 100%)',
              borderRadius: '8px',
              position: 'relative'
            }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" 
                      stroke="white" 
                      strokeWidth="2" 
                      strokeLinecap="round" 
                      strokeLinejoin="round"/>
              </svg>
            </div>
            <h3 style={{
              margin: 0,
              fontSize: '1.25rem',
              fontWeight: 600,
              color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
            }}>AI Analyst Insights</h3>
          </div>
        </div>
        <div style={{
          padding: '3rem 2rem',
          textAlign: 'center',
          color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
        }}>
          <div style={{
            width: '64px',
            height: '64px',
            margin: '0 auto 1.5rem',
            background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <i className="fas fa-shield-alt" style={{
              fontSize: '1.5rem',
              color: 'white'
            }}></i>
          </div>
          <h4 style={{
            margin: '0 0 1rem 0',
            fontSize: '1.125rem',
            fontWeight: 600,
            color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
          }}>
            No Security Issues Found
          </h4>
          <p style={{
            margin: '0 0 1.5rem 0',
            fontSize: '0.875rem',
            lineHeight: 1.6
          }}>
            Great news! No vulnerabilities have been detected for this vendor yet. 
            AI insights will be generated automatically once the security scan completes and identifies any potential issues.
          </p>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1rem',
            background: isDarkMode ? 'var(--bg-tertiary)' : '#f9fafb',
            borderRadius: '8px',
            fontSize: '0.75rem',
            color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
          }}>
            <i className="fas fa-info-circle"></i>
            <span>AI analysis will run when vulnerabilities are found</span>
          </div>
        </div>
      </div>
    );
  }

  if (!insights) {
    return null;
  }

    return (
    <div style={{
      background: 'white',
      borderRadius: '12px',
      boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
      margin: '2rem 0',
      overflow: 'hidden'
    }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '1.5rem 2rem',
        borderBottom: '1px solid #e5e7eb'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem'
        }}>
          <div style={{
            width: '32px',
            height: '32px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 50%, #7c3aed 100%)',
            borderRadius: '8px',
            position: 'relative'
          }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L15.09 8.26L22 9L17 14.74L18.18 22L12 18.77L5.82 22L7 14.74L2 9L8.91 8.26L12 2Z" 
                    fill="white" 
                    fillOpacity="0.9"/>
              <circle cx="12" cy="12" r="3" fill="white" fillOpacity="0.7"/>
              <path d="M12 7L13.5 10.5L17 12L13.5 13.5L12 17L10.5 13.5L7 12L10.5 10.5L12 7Z" 
                    fill="white"/>
            </svg>
          </div>
          <h3 style={{
            margin: 0,
            fontSize: '1.25rem',
            fontWeight: 600,
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
          }}>AI Analyst insights</h3>
        </div>
        <button 
          style={{
            background: 'none',
            border: 'none',
                color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
            cursor: 'pointer',
            padding: '0.5rem',
            borderRadius: '6px',
            transition: 'all 0.2s'
          }}
          onClick={refreshInsights} 
          title="Refresh insights"
          onMouseOver={(e) => {
            e.currentTarget.style.background = '#f3f4f6';
            e.currentTarget.style.color = '#374151';
          }}
          onMouseOut={(e) => {
            e.currentTarget.style.background = 'none';
            e.currentTarget.style.color = '#6b7280';
          }}
        >
          <i className="fas fa-sync-alt"></i>
        </button>
      </div>

      <div className={styles.aiInsightsResponsive}>
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '1.5rem'
        }}>
          <div>
            <h4 style={{
              margin: '0 0 0.75rem 0',
              fontSize: '1rem',
              fontWeight: 600,
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
            }}>Vendor overview</h4>
            <p style={{
              margin: 0,
              lineHeight: 1.7,
              color: '#4b5563',
              fontSize: '0.95rem'
            }}>{insights.vendor_overview}</p>
          </div>

          <div style={{ marginTop: '2rem' }}>
            <h4 style={{
              margin: '0 0 0.75rem 0',
              fontSize: '1rem',
              fontWeight: 600,
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
            }}>Overall security posture</h4>
            <p style={{
              margin: 0,
              lineHeight: 1.7,
              color: '#4b5563',
              fontSize: '0.95rem',
              textAlign: 'justify'
            }}>{insights.overall_security_posture}</p>
          </div>

          <div style={{ marginTop: '2rem' }}>
            <h4 style={{
              margin: '0 0 0.75rem 0',
              fontSize: '1rem',
              fontWeight: 600,
              color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
            }}>Next steps</h4>
            <ul style={{
              margin: 0,
              paddingLeft: '1.25rem',
              color: isDarkMode ? 'var(--text-secondary)' : '#4b5563'
            }}>
              {insights.next_steps.map((step, index) => (
                <li key={index} style={{
                  marginBottom: '0.75rem',
                  lineHeight: 1.7,
                  fontSize: '0.95rem',
                  color: isDarkMode ? 'var(--text-secondary)' : '#4b5563'
                }}>{step}</li>
              ))}
            </ul>
          </div>

          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            paddingTop: '1rem',
            borderTop: '1px solid #e5e7eb',
            marginTop: '1rem'
          }}>
            <span style={{
              fontSize: '0.875rem',
                color: isDarkMode ? 'var(--text-secondary)' : '#6b7280'
            }}>
              Last generated on {insights.last_generated}
            </span>
            <button 
              style={{
                background: 'none',
                border: 'none',
                color: '#3b82f6',
                cursor: 'pointer',
                fontSize: '0.875rem',
                textDecoration: 'underline'
              }}
              onClick={refreshInsights}
              onMouseOver={(e) => {
                e.currentTarget.style.color = '#2563eb';
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.color = '#3b82f6';
              }}
            >
              Refresh
            </button>
          </div>
        </div>

        <div style={{
          background: isDarkMode ? 'var(--bg-primary)' : '#f9fafb',
          padding: '1.5rem',
          borderRadius: '8px'
        }}>
          <h4 style={{
            margin: '0 0 1rem 0',
            fontSize: '1rem',
            fontWeight: 600,
            color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
          }}>Sources</h4>
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <span style={{
                fontWeight: 600,
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
              }}>{insights.sources.domains}</span>
              <span style={{
                color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                fontSize: '0.875rem'
              }}>Domains</span>
            </div>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <span style={{
                fontWeight: 600,
                color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
              }}>{insights.sources.risks}</span>
              <span style={{
                color: isDarkMode ? 'var(--text-secondary)' : '#6b7280',
                fontSize: '0.875rem'
              }}>Risks</span>
            </div>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
            </div>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIInsights; 