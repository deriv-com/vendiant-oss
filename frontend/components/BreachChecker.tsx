import React, { useState, useEffect } from 'react';
import { breachApi, type BreachCheckResult, type BreachMatch } from '../lib/api';
import { logUserAction } from '../lib/api-client';

interface BreachCheckerProps {
  onBreachesFound?: (count: number) => void;
}

const BreachChecker: React.FC<BreachCheckerProps> = ({ onBreachesFound }) => {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<BreachCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<string | null>(null);

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'text-red-600 font-bold';
    if (confidence >= 0.7) return 'text-orange-600 font-semibold';
    return 'text-yellow-600';
  };

  const checkBreaches = async (isManual: boolean = false) => {
    setLoading(true);
    setError(null);
    
    try {
      const result = await breachApi.checkAllBreaches();
      
      // Only log audit entry for manual user actions, not automatic component initialization
      if (isManual) {
        logUserAction('SCAN', 'breach_check', undefined, {
          action_type: 'start_breach_check',
          scan_type: 'breach_check',
          total_vendors: result.data?.total_vendors || 0,
          matches_found: result.data?.matches_found || 0,
          timestamp: new Date().toISOString()
        });
      }
      
      setResults(result);
      setLastChecked(new Date().toISOString());
      
      if (result.data && onBreachesFound) {
        onBreachesFound(result.data.matches_found);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check breaches');
    } finally {
      setLoading(false);
    }
  };

  // Auto-check on component mount
  useEffect(() => {
    checkBreaches();
  }, []);

  return (
    <div className="breach-checker-container">
      <div className="scan-section">
        <div className="scan-header">
          <div className="scan-icon">
            <i className="fas fa-chess-pawn"></i>
          </div>
          <div className="scan-info">
            <h3>Pwn Monitor</h3>
          </div>
        </div>
        <button
          onClick={() => checkBreaches(true)}
          disabled={loading}
          className={`scan-button ${loading ? 'loading' : ''}`}
        >
          {loading ? (
            <span>
              <i className="fas fa-spinner fa-spin mr-2"></i>
              Scanning...
            </span>
          ) : (
            <span>
              <i className="fas fa-search mr-2"></i>
              Start Scan
            </span>
          )}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4 mb-4">
          <div className="flex">
            <i className="fas fa-exclamation-triangle text-red-400 mr-2 mt-1"></i>
            <div>
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {results && results.status === 'success' && results.data && (
        <>
          {/* Summary Stats */}
          <div className="stats-horizontal-container mb-4">
            <div className="stats-card-small">
              <div className="stat-icon stat-icon-blue">
                <i className="fas fa-database"></i>
              </div>
              <div className="stat-content">
                <div className="stat-number">{results.data.total_breaches}</div>
                <div className="stat-label">Recent Breaches Scanned</div>
              </div>
            </div>
            
            <div className="stats-card-small">
              <div className="stat-icon stat-icon-orange">
                <i className="fas fa-building"></i>
              </div>
              <div className="stat-content">
                <div className="stat-number">
                  {Array.from(new Set(results.data.matches.map((match: BreachMatch) => match.vendor.id))).length}
                </div>
                <div className="stat-label">Vendors Found in Breaches</div>
              </div>
            </div>
            
            <div className="stats-card-small">
              <div className={`stat-icon ${
                results.data.matches_found > 0 ? 'stat-icon-red' : 'stat-icon-gray'
              }`}>
                <i className="fas fa-exclamation-triangle"></i>
              </div>
              <div className="stat-content">
                <div className="stat-number">{results.data.matches_found}</div>
                <div className="stat-label">Total Breach Matches</div>
              </div>
            </div>
          </div>

          {/* Breach Matches */}
          {results.data.matches.length > 0 && (
            <>
              {/* Last Checked - positioned above breach matches */}
              {lastChecked && (
                <div className="text-center text-sm text-gray-500 mb-4 px-2">
                  <i className="fas fa-clock mr-1"></i>
                  Last checked: {formatDate(lastChecked)}
                </div>
              )}
              
              <div className="breach-matches">
                <h3 className="text-lg font-semibold text-gray-800 mb-4">
                  <i className="fas fa-warning mr-2 text-red-600"></i>
                  Potential Vendor Breaches
                </h3>
              
              <div className="space-y-4">
                {results.data.matches.map((match: BreachMatch, index: number) => (
                  <div
                    key={index}
                    className="border border-gray-200 rounded-lg p-4 bg-white shadow-sm hover:shadow-md transition-shadow"
                  >
                    <div className="flex justify-between items-start mb-3">
                      <div>
                        <h4 className="text-lg font-semibold text-gray-800">
                          {match.vendor.vendor_name}
                          <span className="text-sm text-gray-500 ml-2">
                            ({match.vendor.domain})
                          </span>
                        </h4>
                        <p className="text-red-600 font-medium">
                          Potential match with: {match.breach.breach_name}
                        </p>
                      </div>
                      <div className="text-right">
                        <div className={`text-sm ${getConfidenceColor(match.confidence)}`}>
                          {Math.round(match.confidence * 100)}% confidence
                        </div>
                        <div className="text-xs text-gray-500">
                          {match.match_type} match
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-gray-50 rounded-md p-3 mb-3">
                      <p className="text-sm text-gray-700">
                        <strong>Breach Details:</strong> {match.breach.description}
                      </p>
                      {match.breach.account_count && (
                        <p className="text-sm text-red-600 mt-1">
                          <strong>Affected Accounts:</strong> {match.breach.account_count.toLocaleString()}
                        </p>
                      )}
                    </div>
                    
                    <div className="flex justify-between items-center text-sm text-gray-500">
                      <span>Published: {formatDate(match.breach.pub_date)}</span>
                      <a
                        href={match.breach.link}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:text-blue-800"
                      >
                        View Details <i className="fas fa-external-link-alt ml-1"></i>
                      </a>
                    </div>
                  </div>
                ))}
              </div>
              </div>
            </>
          )}

          {results.data.matches.length === 0 && (
            <>
              {/* Last Checked - positioned above All Clear */}
              {lastChecked && (
                <div className="text-center text-sm text-gray-500 mb-4 px-2">
                  <i className="fas fa-clock mr-1"></i>
                  Last checked: {formatDate(lastChecked)}
                </div>
              )}
              
              <div className="all-clear-section">
                <div className="all-clear-content">
                  <i className="fas fa-shield-check text-green-500 text-4xl mb-4"></i>
                  <h3 className="text-xl font-semibold text-gray-800 mb-3">All Clear!</h3>
                  <p className="text-gray-600 mb-3 max-w-md">
                    No Vendor Breaches Found
                  </p>
                  <p className="text-sm text-gray-500">
                  </p>
                </div>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
};

export default BreachChecker; 