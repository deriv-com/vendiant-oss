'use client';

import React, { useState, useEffect, useRef } from 'react';
import { logger, LogEntry, LogLevel, LogCategory } from '../lib/logger';

interface LogViewerProps {
  isOpen: boolean;
  onClose: () => void;
}

const LogViewer: React.FC<LogViewerProps> = ({ isOpen, onClose }) => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<LogEntry[]>([]);
  const [levelFilter, setLevelFilter] = useState<LogLevel | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<LogCategory | 'all'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const [isFollowing, setIsFollowing] = useState(true);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Update logs every second
  useEffect(() => {
    if (!isOpen) return;

    const updateLogs = () => {
      const allLogs = logger.getLogs();
      setLogs(allLogs);
    };

    updateLogs(); // Initial load
    const interval = setInterval(updateLogs, 1000);

    return () => clearInterval(interval);
  }, [isOpen]);

  // Filter logs based on criteria
  useEffect(() => {
    let filtered = logs;

    if (levelFilter !== 'all') {
      filtered = filtered.filter(log => log.level === levelFilter);
    }

    if (categoryFilter !== 'all') {
      filtered = filtered.filter(log => log.category === categoryFilter);
    }

    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(log => 
        log.message.toLowerCase().includes(term) ||
        log.domain?.toLowerCase().includes(term) ||
        log.scanId?.toLowerCase().includes(term) ||
        JSON.stringify(log.data || {}).toLowerCase().includes(term)
      );
    }

    setFilteredLogs(filtered);
  }, [logs, levelFilter, categoryFilter, searchTerm]);

  // Auto scroll to bottom
  useEffect(() => {
    if (autoScroll && isFollowing && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [filteredLogs, autoScroll, isFollowing]);

  const getLevelColor = (level: LogLevel): string => {
    switch (level) {
      case 'debug': return 'text-cyan-400';
      case 'info': return 'text-blue-400';
      case 'warn': return 'text-yellow-400';
      case 'error': return 'text-red-400';
      case 'success': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const getLevelIcon = (level: LogLevel): string => {
    switch (level) {
      case 'debug': return '🔍';
      case 'info': return 'ℹ️';
      case 'warn': return '⚠️';
      case 'error': return '❌';
      case 'success': return '✅';
      default: return '📝';
    }
  };

  const getCategoryIcon = (category: LogCategory): string => {
    switch (category) {
      case 'api': return '🌐';
      case 'cache': return '💾';
      case 'scan': return '🔄';
      case 'ui': return '🖥️';
      case 'network': return '📡';
      case 'auth': return '🔐';
      default: return 'ℹ️';
    }
  };

  const formatTimestamp = (timestamp: string): string => {
    return new Date(timestamp).toLocaleTimeString('en-US', { 
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const clearLogs = () => {
    logger.clearLogs();
    setLogs([]);
    setFilteredLogs([]);
  };

  const exportLogs = () => {
    const dataStr = logger.exportLogs();
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vendiant-logs-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const stats = logger.getStats();

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <div className="bg-gray-900 text-white rounded-lg shadow-2xl w-11/12 h-5/6 flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <div className="flex items-center gap-4">
            <h2 className="text-xl font-bold">Frontend Logs</h2>
            <div className="text-sm text-gray-400">
              Total: {stats.totalLogs} | Active Scans: {stats.activeScanCount}
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white text-xl font-bold"
          >
            ✕
          </button>
        </div>

        {/* Controls */}
        <div className="p-4 border-b border-gray-700 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Level Filter */}
          <div>
            <label className="block text-sm font-medium mb-1">Level</label>
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value as LogLevel | 'all')}
              className="w-full px-3 py-1 bg-gray-800 border border-gray-600 rounded text-sm"
            >
              <option value="all">All Levels</option>
              <option value="debug">🔍 Debug</option>
              <option value="info">ℹ️ Info</option>
              <option value="warn">⚠️ Warning</option>
              <option value="error">❌ Error</option>
              <option value="success">✅ Success</option>
            </select>
          </div>

          {/* Category Filter */}
          <div>
            <label className="block text-sm font-medium mb-1">Category</label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as LogCategory | 'all')}
              className="w-full px-3 py-1 bg-gray-800 border border-gray-600 rounded text-sm"
            >
              <option value="all">All Categories</option>
              <option value="api">🌐 API</option>
              <option value="cache">💾 Cache</option>
              <option value="scan">🔄 Scan</option>
              <option value="ui">🖥️ UI</option>
              <option value="network">📡 Network</option>
              <option value="auth">🔐 Auth</option>
              <option value="general">📝 General</option>
            </select>
          </div>

          {/* Search */}
          <div>
            <label className="block text-sm font-medium mb-1">Search</label>
            <input
              type="text"
              placeholder="Search logs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-3 py-1 bg-gray-800 border border-gray-600 rounded text-sm"
            />
          </div>

          {/* Actions */}
          <div>
            <label className="block text-sm font-medium mb-1">Actions</label>
            <div className="flex gap-2">
              <button
                onClick={clearLogs}
                className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-sm"
              >
                Clear
              </button>
              <button
                onClick={exportLogs}
                className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm"
              >
                Export
              </button>
            </div>
          </div>
        </div>

        {/* Options */}
        <div className="px-4 py-2 border-b border-gray-700 flex items-center gap-4 text-sm">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded"
            />
            Auto Scroll
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={isFollowing}
              onChange={(e) => setIsFollowing(e.target.checked)}
              className="rounded"
            />
            Follow Logs
          </label>
          <div className="text-gray-400">
            Showing {filteredLogs.length} of {logs.length} logs
          </div>
        </div>

        {/* Logs Container */}
        <div 
          ref={logContainerRef}
          className="flex-1 overflow-auto p-4 font-mono text-sm"
          onScroll={(e) => {
            const element = e.target as HTMLDivElement;
            const isAtBottom = element.scrollHeight - element.scrollTop === element.clientHeight;
            setIsFollowing(isAtBottom);
          }}
        >
          {filteredLogs.length === 0 ? (
            <div className="text-gray-500 text-center py-8">
              {logs.length === 0 ? 'No logs available' : 'No logs match the current filters'}
            </div>
          ) : (
            filteredLogs.map((log, index) => (
              <div key={index} className="mb-2 p-2 bg-gray-800 rounded border-l-4 border-gray-600">
                <div className="flex items-start gap-3">
                  {/* Timestamp */}
                  <span className="text-gray-400 text-xs whitespace-nowrap">
                    {formatTimestamp(log.timestamp)}
                  </span>
                  
                  {/* Level */}
                  <span className={`${getLevelColor(log.level)} font-medium whitespace-nowrap`}>
                    {getLevelIcon(log.level)} {log.level.toUpperCase()}
                  </span>
                  
                  {/* Category */}
                  <span className="text-gray-300 whitespace-nowrap">
                    {getCategoryIcon(log.category as LogCategory)} {log.category.toUpperCase()}
                  </span>
                  
                  {/* Message */}
                  <span className="flex-1 text-white break-words">
                    {log.message}
                  </span>
                </div>
                
                {/* Additional Info */}
                {(log.domain || log.scanId) && (
                  <div className="mt-1 text-xs text-gray-400 flex gap-4">
                    {log.domain && <span>🌐 {log.domain}</span>}
                    {log.scanId && <span>🔄 {log.scanId}</span>}
                  </div>
                )}
                
                {/* Data */}
                {log.data && (
                  <details className="mt-2">
                    <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-300">
                      Data
                    </summary>
                    <pre className="mt-1 text-xs text-gray-300 bg-gray-900 p-2 rounded overflow-auto max-h-40">
                      {JSON.stringify(log.data, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            ))
          )}
        </div>

        {/* Footer Stats */}
        <div className="p-2 border-t border-gray-700 text-xs text-gray-400 grid grid-cols-2 md:grid-cols-5 gap-2">
          <div>Debug: {stats.logsByLevel.debug || 0}</div>
          <div>Info: {stats.logsByLevel.info || 0}</div>
          <div>Warn: {stats.logsByLevel.warn || 0}</div>
          <div>Error: {stats.logsByLevel.error || 0}</div>
          <div>Success: {stats.logsByLevel.success || 0}</div>
        </div>
      </div>
    </div>
  );
};

export default LogViewer; 