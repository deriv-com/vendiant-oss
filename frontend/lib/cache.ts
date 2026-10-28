// Frontend caching service with memory and localStorage support
import { logger } from './logger';

interface CacheItem<T> {
  data: T;
  timestamp: number;
  expiresAt: number;
}

interface CacheConfig {
  defaultTTL: number; // Time to live in milliseconds
  maxMemorySize: number; // Maximum number of items in memory cache
  enablePersistence: boolean; // Whether to use localStorage
}

class CacheService {
  private memoryCache = new Map<string, CacheItem<any>>();
  private config: CacheConfig;

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = {
      defaultTTL: 5 * 60 * 1000, // 5 minutes default
      maxMemorySize: 100,
      enablePersistence: true,
      ...config
    };
  }

  private isExpired(item: CacheItem<any>): boolean {
    return Date.now() > item.expiresAt;
  }

  private generateKey(prefix: string, params?: Record<string, any>): string {
    if (!params) return prefix;
    const paramString = Object.keys(params)
      .sort()
      .map(key => `${key}=${params[key]}`)
      .join('&');
    return `${prefix}:${paramString}`;
  }

  private cleanupMemoryCache(): void {
    // Remove expired items
    const entries = Array.from(this.memoryCache.entries());
    for (const [key, item] of entries) {
      if (this.isExpired(item)) {
        this.memoryCache.delete(key);
      }
    }

    // If still over limit, remove oldest items
    if (this.memoryCache.size > this.config.maxMemorySize) {
      const remainingEntries = Array.from(this.memoryCache.entries())
        .sort((a, b) => a[1].timestamp - b[1].timestamp);
      
      const toRemove = remainingEntries.slice(0, this.memoryCache.size - this.config.maxMemorySize);
      toRemove.forEach(([key]) => this.memoryCache.delete(key));
    }
  }

  private saveToLocalStorage(key: string, item: CacheItem<any>): void {
    if (!this.config.enablePersistence || typeof window === 'undefined') return;
    
    try {
      localStorage.setItem(`cache_${key}`, JSON.stringify(item));
    } catch (error) {
      console.warn('Failed to save to localStorage:', error);
    }
  }

  private loadFromLocalStorage(key: string): CacheItem<any> | null {
    if (!this.config.enablePersistence || typeof window === 'undefined') return null;
    
    try {
      const stored = localStorage.getItem(`cache_${key}`);
      if (!stored) return null;
      
      const item: CacheItem<any> = JSON.parse(stored);
      return this.isExpired(item) ? null : item;
    } catch (error) {
      console.warn('Failed to load from localStorage:', error);
      return null;
    }
  }

  set<T>(key: string, data: T, ttl?: number): void {
    const actualTTL = ttl || this.config.defaultTTL;
    const item: CacheItem<T> = {
      data,
      timestamp: Date.now(),
      expiresAt: Date.now() + actualTTL
    };

    // Store in memory
    this.memoryCache.set(key, item);
    this.cleanupMemoryCache();

    // Store in localStorage
    this.saveToLocalStorage(key, item);
    
    logger.cacheSet('cache', key, actualTTL);
  }

  get<T>(key: string): T | null {
    // Check memory cache first
    const memoryItem = this.memoryCache.get(key);
    if (memoryItem && !this.isExpired(memoryItem)) {
      logger.cacheHit('memory', key, memoryItem.data);
      return memoryItem.data;
    }

    // Check localStorage
    const persistedItem = this.loadFromLocalStorage(key);
    if (persistedItem) {
      // Restore to memory cache
      this.memoryCache.set(key, persistedItem);
      logger.cacheHit('localStorage', key, persistedItem.data);
      return persistedItem.data;
    }

    logger.cacheMiss('all', key);
    return null;
  }

  has(key: string): boolean {
    return this.get(key) !== null;
  }

  delete(key: string): void {
    this.memoryCache.delete(key);
    if (typeof window !== 'undefined') {
      localStorage.removeItem(`cache_${key}`);
    }
  }

  clear(prefix?: string): void {
    if (prefix) {
      // Clear specific prefix
      const keys = Array.from(this.memoryCache.keys());
      for (const key of keys) {
        if (key.startsWith(prefix)) {
          this.memoryCache.delete(key);
        }
      }

      if (typeof window !== 'undefined') {
        const keysToRemove: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key && key.startsWith(`cache_${prefix}`)) {
            keysToRemove.push(key);
          }
        }
        keysToRemove.forEach(key => localStorage.removeItem(key));
      }
      
      logger.cacheCleared('cache', prefix);
    } else {
      // Clear all
      this.memoryCache.clear();
      if (typeof window !== 'undefined') {
        const keysToRemove: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key && key.startsWith('cache_')) {
            keysToRemove.push(key);
          }
        }
        keysToRemove.forEach(key => localStorage.removeItem(key));
      }
      
      logger.cacheCleared('cache');
    }
  }

  // Utility methods for common cache patterns
  async getOrFetch<T>(
    key: string,
    fetchFn: () => Promise<T>,
    ttl?: number
  ): Promise<T> {
    const cached = this.get<T>(key);
    if (cached !== null) {
      return cached;
    }

    const data = await fetchFn();
    this.set(key, data, ttl);
    return data;
  }

  // Generate cache key with parameters
  key(prefix: string, params?: Record<string, any>): string {
    return this.generateKey(prefix, params);
  }

  // Get cache statistics
  getStats(): {
    memorySize: number;
    memoryKeys: string[];
    persistedKeys: string[];
  } {
    const persistedKeys: string[] = [];
    if (typeof window !== 'undefined') {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('cache_')) {
          persistedKeys.push(key.replace('cache_', ''));
        }
      }
    }

    return {
      memorySize: this.memoryCache.size,
      memoryKeys: Array.from(this.memoryCache.keys()),
      persistedKeys
    };
  }
}

// Create different cache instances for different data types
export const vendorCache = new CacheService({
  defaultTTL: 60 * 60 * 1000, // 60 minutes for vendors (stable data)
  maxMemorySize: 100,
  enablePersistence: true
});

export const subdomainCache = new CacheService({
  defaultTTL: 15 * 60 * 1000, // 15 minutes for subdomains
  maxMemorySize: 200,
  enablePersistence: true
});

export const dashboardCache = new CacheService({
  defaultTTL: 2 * 60 * 1000, // 2 minutes for dashboard stats
  maxMemorySize: 20,
  enablePersistence: false // Dashboard stats change frequently
});

export const scanResultsCache = new CacheService({
  defaultTTL: 30 * 60 * 1000, // 30 minutes for scan results
  maxMemorySize: 100,
  enablePersistence: true
});

export const certificationCache = new CacheService({
  defaultTTL: 24 * 60 * 60 * 1000, // 24 hours for certifications (very stable data)
  maxMemorySize: 500,
  enablePersistence: true
});

// Export the main cache service class
export default CacheService; 