// Frontend logging service with console output, scan monitoring, and error tracking

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  category: string;
  message: string;
  data?: any;
  scanId?: string;
  domain?: string;
}

type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'success';
type LogCategory = 'api' | 'cache' | 'scan' | 'ui' | 'network' | 'auth' | 'general';

interface LoggerConfig {
  enableConsole: boolean;
  enableStorage: boolean;
  maxStoredLogs: number;
  logLevel: LogLevel;
  enableColors: boolean;
  enableTimestamps: boolean;
}

class Logger {
  private config: LoggerConfig;
  private logs: LogEntry[] = [];
  private scanProgress: Map<string, any> = new Map();
  
  // ANSI color codes for terminal output
  private colors = {
    debug: '\x1b[36m',    // Cyan
    info: '\x1b[34m',     // Blue
    warn: '\x1b[33m',     // Yellow
    error: '\x1b[31m',    // Red
    success: '\x1b[32m',  // Green
    reset: '\x1b[0m',     // Reset
    bold: '\x1b[1m',      // Bold
    dim: '\x1b[2m'        // Dim
  };

  // Emoji icons for better visual identification
  private icons = {
    debug: '🔍',
    info: 'ℹ️ ',
    warn: '⚠️ ',
    error: '❌',
    success: '✅',
    scan: '🔄',
    cache: '💾',
    api: '🌐',
    network: '📡',
    ui: '🖥️ ',
    auth: '🔐'
  };

  constructor(config: Partial<LoggerConfig> = {}) {
    this.config = {
      enableConsole: true,
      enableStorage: true,
      maxStoredLogs: 1000,
      logLevel: 'info',
      enableColors: true,
      enableTimestamps: true,
      ...config
    };

    // Initialize with welcome message
    this.info('general', 'Logger initialized', { config: this.config });
  }

  private shouldLog(level: LogLevel): boolean {
    const levels = ['debug', 'info', 'warn', 'error', 'success'];
    const currentLevelIndex = levels.indexOf(this.config.logLevel);
    const messageLevelIndex = levels.indexOf(level);
    return messageLevelIndex >= currentLevelIndex;
  }

  private formatTimestamp(): string {
    return new Date().toISOString().replace('T', ' ').replace('Z', '');
  }

  private colorize(text: string, color: keyof typeof this.colors): string {
    if (!this.config.enableColors) return text;
    return `${this.colors[color]}${text}${this.colors.reset}`;
  }

  private formatMessage(level: LogLevel, category: string, message: string, data?: any): string {
    let formattedMessage = '';
    
    // Add timestamp
    if (this.config.enableTimestamps) {
      formattedMessage += this.colorize(`[${this.formatTimestamp()}]`, 'dim') + ' ';
    }

    // Add level with icon and color
    const levelIcon = this.icons[level] || '';
    const levelText = this.colorize(`${levelIcon}${level.toUpperCase()}`, level);
    formattedMessage += `${levelText} `;

    // Add category with icon
    const categoryIcon = this.icons[category as keyof typeof this.icons] || this.icons.info;
    const categoryText = this.colorize(`[${categoryIcon}${category.toUpperCase()}]`, 'bold');
    formattedMessage += `${categoryText} `;

    // Add main message
    formattedMessage += message;

    // Add data if present
    if (data !== undefined) {
      if (typeof data === 'object') {
        formattedMessage += '\n' + this.colorize(JSON.stringify(data, null, 2), 'dim');
      } else {
        formattedMessage += ` ${this.colorize(String(data), 'dim')}`;
      }
    }

    return formattedMessage;
  }

  private log(level: LogLevel, category: LogCategory, message: string, data?: any, scanId?: string, domain?: string): void {
    if (!this.shouldLog(level)) return;

    const logEntry: LogEntry = {
      timestamp: this.formatTimestamp(),
      level,
      category,
      message,
      data,
      scanId,
      domain
    };

    // Store log entry
    if (this.config.enableStorage) {
      this.logs.push(logEntry);
      if (this.logs.length > this.config.maxStoredLogs) {
        this.logs.shift();
      }
    }

    // Output to both browser console and terminal with identical formatting
    const formattedMessage = this.formatMessage(level, category, message, data);
    
    if (this.config.enableConsole) {
      console.log(formattedMessage);
    }

    // Mirror the exact same formatted message to terminal
    this.mirrorToTerminal(level, formattedMessage, data, scanId, domain);
  }

  private mirrorToTerminal(level: LogLevel, formattedMessage: string, data?: any, scanId?: string, domain?: string): void {
    // Strip ANSI color codes for terminal compatibility while keeping the exact same format
    const cleanMessage = formattedMessage.replace(/\x1b\[[0-9;]*m/g, '');
    
    // Add context if available
    let contextualMessage = cleanMessage;
    if (domain) {
      contextualMessage += ` (${domain})`;
    }
    if (scanId) {
      contextualMessage += ` [ID: ${scanId}]`;
    }

    // Use appropriate console method based on level to match browser console exactly
    switch (level) {
      case 'error':
        console.error(contextualMessage);
        break;
      case 'warn':
        console.warn(contextualMessage);
        break;
      case 'debug':
        console.debug(contextualMessage);
        break;
      default:
        console.log(contextualMessage);
        break;
    }
  }

  // Public logging methods
  debug(category: LogCategory, message: string, data?: any, scanId?: string, domain?: string): void {
    this.log('debug', category, message, data, scanId, domain);
  }

  info(category: LogCategory, message: string, data?: any, scanId?: string, domain?: string): void {
    this.log('info', category, message, data, scanId, domain);
  }

  warn(category: LogCategory, message: string, data?: any, scanId?: string, domain?: string): void {
    this.log('warn', category, message, data, scanId, domain);
  }

  error(category: LogCategory, message: string, data?: any, scanId?: string, domain?: string): void {
    this.log('error', category, message, data, scanId, domain);
  }

  success(category: LogCategory, message: string, data?: any, scanId?: string, domain?: string): void {
    this.log('success', category, message, data, scanId, domain);
  }

  // Specialized scan monitoring methods
  scanStarted(scanType: string, domain: string, scanId?: string): void {
    const message = `Starting ${scanType} scan for ${domain}`;
    this.info('scan', message, { scanType, domain, scanId }, scanId, domain);
    
    if (scanId) {
      this.scanProgress.set(scanId, {
        scanType,
        domain,
        startTime: Date.now(),
        status: 'started',
        stages: []
      });
    }
  }

  scanStageProgress(scanType: string, domain: string, stage: string, progress?: number, scanId?: string): void {
    const message = `${scanType} scan - ${stage}`;
    const data = { scanType, domain, stage, progress };
    this.info('scan', message, data, scanId, domain);
    
    if (scanId && this.scanProgress.has(scanId)) {
      const scanData = this.scanProgress.get(scanId);
      scanData.stages.push({ stage, progress, timestamp: Date.now() });
      scanData.currentStage = stage;
      if (progress !== undefined) {
        scanData.progress = progress;
      }
    }
  }

  scanCompleted(scanType: string, domain: string, result: any, scanId?: string): void {
    const message = `${scanType} scan completed for ${domain}`;
    this.success('scan', message, { 
      scanType, 
      domain, 
      score: result.final_score || result.score,
      vulnerabilities: result.vulnerabilities?.length || 0 
    }, scanId, domain);
    
    if (scanId && this.scanProgress.has(scanId)) {
      const scanData = this.scanProgress.get(scanId);
      scanData.status = 'completed';
      scanData.endTime = Date.now();
      scanData.duration = scanData.endTime - scanData.startTime;
      scanData.result = result;
    }
  }

  scanError(scanType: string, domain: string, error: any, scanId?: string): void {
    const message = `${scanType} scan failed for ${domain}`;
    this.error('scan', message, { 
      scanType, 
      domain, 
      error: error instanceof Error ? error.message : error 
    }, scanId, domain);
    
    if (scanId && this.scanProgress.has(scanId)) {
      const scanData = this.scanProgress.get(scanId);
      scanData.status = 'error';
      scanData.endTime = Date.now();
      scanData.duration = scanData.endTime - scanData.startTime;
      scanData.error = error;
    }
  }

  // Cache monitoring methods
  cacheHit(cacheType: string, key: string, data?: any): void {
    this.debug('cache', `Cache HIT: ${cacheType}`, { key, dataSize: JSON.stringify(data || {}).length });
  }

  cacheMiss(cacheType: string, key: string): void {
    this.debug('cache', `Cache MISS: ${cacheType}`, { key });
  }

  cacheSet(cacheType: string, key: string, ttl?: number): void {
    this.debug('cache', `Cache SET: ${cacheType}`, { key, ttl });
  }

  cacheCleared(cacheType: string, key?: string): void {
    this.info('cache', `Cache CLEARED: ${cacheType}`, { key: key || 'ALL' });
  }

  // API monitoring methods
  apiRequest(method: string, url: string, data?: any): void {
    this.debug('api', `${method} ${url}`, data ? { requestData: data } : undefined);
  }

  apiResponse(method: string, url: string, status: number, responseTime?: number): void {
    const level = status >= 400 ? 'error' : status >= 300 ? 'warn' : 'debug';
    this.log(level, 'api', `${method} ${url} → ${status}`, { 
      status, 
      responseTime: responseTime ? `${responseTime}ms` : undefined 
    });
  }

  apiError(method: string, url: string, error: any): void {
    this.error('api', `${method} ${url} failed`, { 
      error: error instanceof Error ? error.message : error 
    });
  }

  // Network monitoring methods
  networkRequest(url: string, method: string = 'GET'): void {
    this.debug('network', `${method} request to ${url}`);
  }

  networkError(url: string, error: any): void {
    this.error('network', `Network error for ${url}`, { 
      error: error instanceof Error ? error.message : error 
    });
  }

  // UI monitoring methods
  uiEvent(event: string, data?: any): void {
    this.debug('ui', `UI Event: ${event}`, data);
  }

  uiError(component: string, error: any): void {
    this.error('ui', `UI Error in ${component}`, { 
      error: error instanceof Error ? error.message : error 
    });
  }

  // Utility methods
  getScanProgress(scanId: string): any {
    return this.scanProgress.get(scanId);
  }

  getAllScanProgress(): Map<string, any> {
    return new Map(this.scanProgress);
  }

  getLogs(filter?: { level?: LogLevel; category?: LogCategory; scanId?: string }): LogEntry[] {
    if (!filter) return [...this.logs];
    
    return this.logs.filter(log => {
      if (filter.level && log.level !== filter.level) return false;
      if (filter.category && log.category !== filter.category) return false;
      if (filter.scanId && log.scanId !== filter.scanId) return false;
      return true;
    });
  }

  getStats(): {
    totalLogs: number;
    logsByLevel: Record<LogLevel, number>;
    logsByCategory: Record<string, number>;
    activeScanCount: number;
  } {
    const logsByLevel = this.logs.reduce((acc, log) => {
      acc[log.level] = (acc[log.level] || 0) + 1;
      return acc;
    }, {} as Record<LogLevel, number>);

    const logsByCategory = this.logs.reduce((acc, log) => {
      acc[log.category] = (acc[log.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalLogs: this.logs.length,
      logsByLevel,
      logsByCategory,
      activeScanCount: this.scanProgress.size
    };
  }

  clearLogs(): void {
    this.logs = [];
    this.scanProgress.clear();
    this.info('general', 'Logs and scan progress cleared');
  }

  // Export logs as JSON for debugging
  exportLogs(): string {
    return JSON.stringify({
      logs: this.logs,
      scanProgress: Array.from(this.scanProgress.entries()),
      stats: this.getStats(),
      exportedAt: new Date().toISOString()
    }, null, 2);
  }
}

// Create singleton logger instance
export const logger = new Logger({
  enableConsole: true,
  enableStorage: true,
  maxStoredLogs: 2000,
  logLevel: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
  enableColors: true,
  enableTimestamps: true
});

// Export logger class for custom instances
export default Logger;

// Export types for TypeScript support
export type { LogEntry, LogLevel, LogCategory, LoggerConfig }; 