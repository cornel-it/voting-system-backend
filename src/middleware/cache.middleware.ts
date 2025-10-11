// backend/src/middleware/cache.middleware.ts

import { Request, Response, NextFunction } from 'express';
import { redis } from '../config/redis';
import { AuthRequest } from './auth.middleware';
import crypto from 'crypto';

export interface CacheOptions {
  ttl: number; // Time to live in seconds
  keyPrefix?: string;
  varyBy?: string[]; // Headers/query params to vary cache by
  skipAuth?: boolean; // Whether to skip authentication for caching
  skipCache?: (req: Request) => boolean; // Function to determine if cache should be skipped
  transform?: (data: any) => any; // Transform data before caching
}

// Default cache options
const defaultCacheOptions: CacheOptions = {
  ttl: 300, // 5 minutes
  keyPrefix: 'cache',
  varyBy: [],
  skipAuth: false
};

// Generate cache key
const generateCacheKey = (req: AuthRequest, options: CacheOptions): string => {
  const components = [
    options.keyPrefix,
    req.originalUrl,
    req.method
  ];

  // Add user-specific component if not skipping auth
  if (!options.skipAuth && req.user) {
    components.push(req.user.id);
  }

  // Add varying components
  if (options.varyBy) {
    for (const varyParam of options.varyBy) {
      if (varyParam.startsWith('header:')) {
        const headerName = varyParam.replace('header:', '');
        components.push(req.headers[headerName] as string || '');
      } else if (varyParam.startsWith('query:')) {
        const queryParam = varyParam.replace('query:', '');
        components.push(req.query[queryParam] as string || '');
      } else {
        components.push(req.query[varyParam] as string || '');
      }
    }
  }

  // Create hash of components
  const keyString = components.filter(Boolean).join(':');
  return crypto.createHash('md5').update(keyString).digest('hex');
};

// Main cache middleware
export const cacheMiddleware = (options: Partial<CacheOptions> = {}) => {
  const opts = { ...defaultCacheOptions, ...options };

  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      // Skip cache if function returns true
      if (opts.skipCache && opts.skipCache(req)) {
        return next();
      }

      // Skip cache for non-GET requests
      if (req.method !== 'GET') {
        return next();
      }

      const cacheKey = generateCacheKey(req, opts);

      // Try to get from cache
      const cachedData = await redis.get(cacheKey);

      if (cachedData) {
        const parsed = JSON.parse(cachedData);

        // Set cache headers
        res.setHeader('X-Cache', 'HIT');
        res.setHeader('X-Cache-Key', cacheKey);

        return res.status(parsed.statusCode || 200).json(parsed.data);
      }

      // Store original res.json to intercept response
      const originalJson = res.json;
      res.json = function(body: any) {
        // Cache successful responses only
        if (res.statusCode >= 200 && res.statusCode < 300) {
          const dataToCache = {
            statusCode: res.statusCode,
            data: opts.transform ? opts.transform(body) : body,
            timestamp: new Date().toISOString()
          };

          // Cache asynchronously
          redis.setex(cacheKey, opts.ttl, JSON.stringify(dataToCache)).catch(error => {
            console.error('Cache set error:', error);
          });
        }

        // Set cache miss header
        res.setHeader('X-Cache', 'MISS');
        res.setHeader('X-Cache-Key', cacheKey);

        return originalJson.call(this, body);
      };

      next();
    } catch (error) {
      console.error('Cache middleware error:', error);
      next(); // Continue without caching on error
    }
  };
};

// Elections cache (short TTL for live updates)
export const electionsCache = cacheMiddleware({
  ttl: 60, // 1 minute
  keyPrefix: 'elections',
  varyBy: ['status', 'type', 'page', 'limit']
});

// Results cache (longer TTL for completed elections)
export const resultsCache = cacheMiddleware({
  ttl: 1800, // 30 minutes
  keyPrefix: 'results',
  varyBy: ['electionId'],
  skipAuth: true // Results can be public
});

// Candidates cache
export const candidatesCache = cacheMiddleware({
  ttl: 300, // 5 minutes
  keyPrefix: 'candidates',
  varyBy: ['electionId', 'positionId', 'status']
});

// User profile cache
export const profileCache = cacheMiddleware({
  ttl: 600, // 10 minutes
  keyPrefix: 'profile',
  skipCache: (req) => req.method !== 'GET'
});

// Statistics cache (longer TTL)
export const statisticsCache = cacheMiddleware({
  ttl: 3600, // 1 hour
  keyPrefix: 'stats',
  varyBy: ['period', 'groupBy']
});

// Public data cache (very long TTL)
export const publicDataCache = cacheMiddleware({
  ttl: 7200, // 2 hours
  keyPrefix: 'public',
  skipAuth: true
});

// Cache invalidation middleware
export const invalidateCache = (patterns: string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Store original res.json to invalidate after successful operations
    const originalJson = res.json;
    res.json = function(body: any) {
      // Only invalidate on successful operations
      if (res.statusCode >= 200 && res.statusCode < 300) {
        // Invalidate cache patterns asynchronously
        Promise.all(
          patterns.map(pattern => invalidateCachePattern(pattern))
        ).catch(error => {
          console.error('Cache invalidation error:', error);
        });
      }

      return originalJson.call(this, body);
    };

    next();
  };
};

// Invalidate cache by pattern
const invalidateCachePattern = async (pattern: string): Promise<void> => {
  try {
    const keys = await redis.keys(`*${pattern}*`);
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  } catch (error) {
    console.error(`Failed to invalidate cache pattern ${pattern}:`, error);
  }
};

// Tag-based cache invalidation
export const taggedCache = (tags: string[], options: Partial<CacheOptions> = {}) => {
  const opts = { ...defaultCacheOptions, ...options };

  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (req.method !== 'GET') {
        return next();
      }

      const cacheKey = generateCacheKey(req, opts);

      // Store cache-to-tag mapping
      for (const tag of tags) {
        await redis.sadd(`tag:${tag}`, cacheKey);
        await redis.expire(`tag:${tag}`, opts.ttl + 300); // Expire tag set 5 minutes after cache
      }

      // Check cache
      const cachedData = await redis.get(cacheKey);

      if (cachedData) {
        const parsed = JSON.parse(cachedData);
        res.setHeader('X-Cache', 'HIT');
        res.setHeader('X-Cache-Tags', tags.join(','));
        return res.status(parsed.statusCode || 200).json(parsed.data);
      }

      // Store original res.json
      const originalJson = res.json;
      res.json = function(body: any) {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          const dataToCache = {
            statusCode: res.statusCode,
            data: body,
            timestamp: new Date().toISOString()
          };

          redis.setex(cacheKey, opts.ttl, JSON.stringify(dataToCache)).catch(error => {
            console.error('Tagged cache set error:', error);
          });
        }

        res.setHeader('X-Cache', 'MISS');
        res.setHeader('X-Cache-Tags', tags.join(','));
        return originalJson.call(this, body);
      };

      next();
    } catch (error) {
      console.error('Tagged cache middleware error:', error);
      next();
    }
  };
};

// Invalidate by tag
export const invalidateByTag = async (tag: string): Promise<void> => {
  try {
    const cacheKeys = await redis.smembers(`tag:${tag}`);
    if (cacheKeys.length > 0) {
      await redis.del(...cacheKeys);
      await redis.del(`tag:${tag}`);
    }
  } catch (error) {
    console.error(`Failed to invalidate tag ${tag}:`, error);
  }
};

// Cache warming middleware
export const cacheWarmup = (routes: string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Warm up cache in background
    setImmediate(async () => {
      for (const route of routes) {
        try {
          // Simulate request to warm cache
          // This would need to be implemented based on your app structure
          console.log(`Warming cache for route: ${route}`);
        } catch (error) {
          console.error(`Cache warmup failed for ${route}:`, error);
        }
      }
    });

    next();
  };
};

// ETag middleware for client-side caching
export const etagMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const originalJson = res.json;

  res.json = function(body: any) {
    // Generate ETag based on content
    const etag = crypto.createHash('md5').update(JSON.stringify(body)).digest('hex');

    res.setHeader('ETag', `"${etag}"`);

    // Check if client has cached version
    const clientETag = req.headers['if-none-match'];

    if (clientETag === `"${etag}"`) {
      return res.status(304).end();
    }

    return originalJson.call(this, body);
  };

  next();
};

// Cache statistics middleware
export const cacheStats = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const info = await redis.info('memory');
    const keyspace = await redis.info('keyspace');

    res.setHeader('X-Cache-Memory', info.split('\n').find(line => line.startsWith('used_memory_human'))?.split(':')[1]?.trim() || 'unknown');
    res.setHeader('X-Cache-Keys', keyspace.split('\n').find(line => line.startsWith('db0'))?.split('keys=')[1]?.split(',')[0] || '0');

    next();
  } catch (error) {
    console.error('Cache stats error:', error);
    next();
  }
};

// Conditional cache middleware
export const conditionalCache = (condition: (req: AuthRequest) => boolean, options: Partial<CacheOptions> = {}) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (condition(req)) {
      return cacheMiddleware(options)(req, res, next);
    }
    return next();
  };
};

// Cache prefetch middleware
export const cachePrefetch = (keys: string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Prefetch related cache keys
      const prefetchPromises = keys.map(key => redis.get(key));
      await Promise.all(prefetchPromises);

      next();
    } catch (error) {
      console.error('Cache prefetch error:', error);
      next();
    }
  };
};

export default {
  cacheMiddleware,
  electionsCache,
  resultsCache,
  candidatesCache,
  profileCache,
  statisticsCache,
  publicDataCache,
  invalidateCache,
  taggedCache,
  invalidateByTag,
  cacheWarmup,
  etagMiddleware,
  cacheStats,
  conditionalCache,
  cachePrefetch
};