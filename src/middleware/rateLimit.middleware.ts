// backend/src/middleware/rateLimit.middleware.ts

import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { redis } from '../config/redis';
import { AppError } from '../utils/errors';

// General API rate limiting
export const generalRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later',
    retryAfter: 15 * 60
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use IP address for unauthenticated requests, user ID for authenticated
    return (req as any).user?.id || req.ip;
  }
});

// Authentication rate limiting (stricter for login attempts)
export const authRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: {
    success: false,
    error: 'Too many authentication attempts, please try again later',
    retryAfter: 15 * 60
  },
  skipSuccessfulRequests: true,
  keyGenerator: (req) => `auth:${req.ip}:${req.body.identifier || req.body.email}`
});

// Registration rate limiting
export const registrationRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 registration attempts per hour
  message: {
    success: false,
    error: 'Too many registration attempts, please try again later',
    retryAfter: 60 * 60
  },
  keyGenerator: (req) => `register:${req.ip}`
});

// Password reset rate limiting
export const passwordResetRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 password reset attempts per hour
  message: {
    success: false,
    error: 'Too many password reset attempts, please try again later',
    retryAfter: 60 * 60
  },
  keyGenerator: (req) => `reset:${req.ip}:${req.body.email}`
});

// Voting rate limiting (prevent vote spamming)
export const votingRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // limit each user to 10 voting actions per 5 minutes
  message: {
    success: false,
    error: 'Too many voting attempts, please slow down',
    retryAfter: 5 * 60
  },
  keyGenerator: (req) => `vote:${(req as any).user?.id || req.ip}`
});

// Two-factor authentication rate limiting
export const twoFactorRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each user to 10 2FA attempts per 15 minutes
  message: {
    success: false,
    error: 'Too many 2FA attempts, please try again later',
    retryAfter: 15 * 60
  },
  keyGenerator: (req) => `2fa:${(req as any).user?.id || req.ip}`
});

// File upload rate limiting
export const uploadRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // limit each user to 20 file uploads per hour
  message: {
    success: false,
    error: 'Too many file uploads, please try again later',
    retryAfter: 60 * 60
  },
  keyGenerator: (req) => `upload:${(req as any).user?.id || req.ip}`
});

// Admin actions rate limiting
export const adminRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 60 * 1000, // 1 minute
  max: 50, // limit admin users to 50 actions per minute
  message: {
    success: false,
    error: 'Too many admin actions, please slow down',
    retryAfter: 60
  },
  keyGenerator: (req) => `admin:${(req as any).user?.id}`
});

// Email sending rate limiting
export const emailRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // limit each user to 5 emails per hour
  message: {
    success: false,
    error: 'Too many email requests, please try again later',
    retryAfter: 60 * 60
  },
  keyGenerator: (req) => `email:${(req as any).user?.id || req.ip}`
});

// Search rate limiting
export const searchRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 60 * 1000, // 1 minute
  max: 30, // limit each user to 30 searches per minute
  message: {
    success: false,
    error: 'Too many search requests, please slow down',
    retryAfter: 60
  },
  keyGenerator: (req) => `search:${(req as any).user?.id || req.ip}`
});

// Bulk operations rate limiting
export const bulkRateLimit = rateLimit({
  store: new RedisStore({
    // @ts-expect-error - Redis typing issue with spread args
    sendCommand: (...args: string[]) => redis.call(...args),
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // limit each user to 5 bulk operations per hour
  message: {
    success: false,
    error: 'Too many bulk operations, please try again later',
    retryAfter: 60 * 60
  },
  keyGenerator: (req) => `bulk:${(req as any).user?.id}`
});

// Dynamic rate limiting based on user role
export const createDynamicRateLimit = (config: {
  [key: string]: { windowMs: number; max: number }
}) => {
  const defaultConfig = config.DEFAULT || { windowMs: 15 * 60 * 1000, max: 100 };

  return rateLimit({
    store: new RedisStore({
      // @ts-expect-error - Redis typing issue with spread args
      sendCommand: (...args: string[]) => redis.call(...args),
    }),
    windowMs: defaultConfig.windowMs,
    max: (req) => {
      const userRole = (req as any).user?.role || 'GUEST';
      return config[userRole]?.max || defaultConfig.max;
    },
    message: {
      success: false,
      error: 'Rate limit exceeded for your user role',
    },
    keyGenerator: (req) => `dynamic:${(req as any).user?.id || req.ip}`
  });
};

// Sliding window rate limiter for more precise control
export const createSlidingWindowRateLimit = (
  windowMs: number,
  maxRequests: number,
  keyPrefix: string = 'sliding'
) => {
  return async (req: any, res: any, next: any) => {
    try {
      const key = `${keyPrefix}:${req.user?.id || req.ip}`;
      const now = Date.now();
      const windowStart = now - windowMs;

      // Remove old entries and add current request
      const pipeline = redis.pipeline();
      pipeline.zremrangebyscore(key, 0, windowStart);
      pipeline.zadd(key, now, now.toString());
      pipeline.zcount(key, windowStart, now);
      pipeline.expire(key, Math.ceil(windowMs / 1000));

      const results = await pipeline.exec();
      const requestCount = results?.[2]?.[1] as number;

      if (requestCount > maxRequests) {
        return res.status(429).json({
          success: false,
          error: 'Rate limit exceeded',
          retryAfter: Math.ceil(windowMs / 1000)
        });
      }

      next();
    } catch (error) {
      // If Redis is down, allow the request but log the error
      console.error('Rate limiting error:', error);
      next();
    }
  };
};

// Burst rate limiter (allows short bursts but enforces longer-term limits)
export const createBurstRateLimit = (
  shortWindowMs: number,
  shortMaxRequests: number,
  longWindowMs: number,
  longMaxRequests: number,
  keyPrefix: string = 'burst'
) => {
  return async (req: any, res: any, next: any) => {
    try {
      const key = `${keyPrefix}:${req.user?.id || req.ip}`;
      const now = Date.now();

      // Check short-term window
      const shortKey = `${key}:short`;
      const shortWindowStart = now - shortWindowMs;

      // Check long-term window
      const longKey = `${key}:long`;
      const longWindowStart = now - longWindowMs;

      const pipeline = redis.pipeline();

      // Short window operations
      pipeline.zremrangebyscore(shortKey, 0, shortWindowStart);
      pipeline.zadd(shortKey, now, now.toString());
      pipeline.zcount(shortKey, shortWindowStart, now);
      pipeline.expire(shortKey, Math.ceil(shortWindowMs / 1000));

      // Long window operations
      pipeline.zremrangebyscore(longKey, 0, longWindowStart);
      pipeline.zadd(longKey, now, now.toString());
      pipeline.zcount(longKey, longWindowStart, now);
      pipeline.expire(longKey, Math.ceil(longWindowMs / 1000));

      const results = await pipeline.exec();
      const shortCount = results?.[2]?.[1] as number;
      const longCount = results?.[6]?.[1] as number;

      if (shortCount > shortMaxRequests) {
        return res.status(429).json({
          success: false,
          error: 'Short-term rate limit exceeded',
          retryAfter: Math.ceil(shortWindowMs / 1000)
        });
      }

      if (longCount > longMaxRequests) {
        return res.status(429).json({
          success: false,
          error: 'Long-term rate limit exceeded',
          retryAfter: Math.ceil(longWindowMs / 1000)
        });
      }

      next();
    } catch (error) {
      console.error('Burst rate limiting error:', error);
      next();
    }
  };
};

export default {
  generalRateLimit,
  authRateLimit,
  registrationRateLimit,
  passwordResetRateLimit,
  votingRateLimit,
  twoFactorRateLimit,
  uploadRateLimit,
  adminRateLimit,
  emailRateLimit,
  searchRateLimit,
  bulkRateLimit,
  createDynamicRateLimit,
  createSlidingWindowRateLimit,
  createBurstRateLimit
};
