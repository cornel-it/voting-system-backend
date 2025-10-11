// backend/src/middleware/security.middleware.ts

import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { AuthRequest } from './auth.middleware';
import { AppError } from '../utils/errors';
import { redis } from '../config/redis';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';

// Helmet security middleware with custom configuration
export const helmetSecurity = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// XSS Protection middleware
export const xssProtection = (req: Request, res: Response, next: NextFunction) => {
  // Sanitize user input
  const sanitizeInput = (obj: any): any => {
    if (typeof obj === 'string') {
      return obj
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '');
    }

    if (Array.isArray(obj)) {
      return obj.map(sanitizeInput);
    }

    if (obj && typeof obj === 'object') {
      const sanitized: any = {};
      for (const key in obj) {
        sanitized[key] = sanitizeInput(obj[key]);
      }
      return sanitized;
    }

    return obj;
  };

  if (req.body) {
    req.body = sanitizeInput(req.body);
  }

  if (req.query) {
    req.query = sanitizeInput(req.query);
  }

  if (req.params) {
    req.params = sanitizeInput(req.params);
  }

  next();
};

// SQL Injection protection
export const sqlInjectionProtection = (req: Request, res: Response, next: NextFunction) => {
  const sqlPatterns: RegExp[] = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)|(\b(OR|AND)\b.*\b(=|>|<)\b)|(\b(1=1|1=0|\'\s*OR\s*\'|--|\#)\b)/gi,
    /('|\\')|(;|\\;)|(\)|\\\))|(\||\\|)/gi
  ];

  const checkForSQLInjection = (value: string): boolean => {
    return sqlPatterns.some((pattern: RegExp) => pattern.test(value));
  };

  const scanObject = (obj: any): boolean => {
    if (typeof obj === 'string') {
      return checkForSQLInjection(obj);
    }

    if (Array.isArray(obj)) {
      return obj.some(scanObject);
    }

    if (obj && typeof obj === 'object') {
      return Object.values(obj).some(scanObject);
    }

    return false;
  };

  // Check request body, query, and params
  const hasInjection = scanObject(req.body) || scanObject(req.query) || scanObject(req.params);

  if (hasInjection) {
    return res.status(400).json({
      success: false,
      error: 'Invalid input detected'
    });
  }

  return next();
};

// NoSQL Injection protection
export const noSQLInjectionProtection = (req: Request, res: Response, next: NextFunction) => {
  const scanForNoSQLInjection = (obj: any): boolean => {
    if (obj && typeof obj === 'object') {
      for (const key in obj) {
        // Check for MongoDB operators
        if (key.startsWith('$') && key !== '$') {
          return true;
        }

        // Check for function constructors
        if (typeof obj[key] === 'object' && obj[key].constructor && obj[key].constructor.name !== 'Object') {
          return true;
        }

        // Recursive check
        if (scanForNoSQLInjection(obj[key])) {
          return true;
        }
      }
    }

    return false;
  };

  const hasNoSQLInjection = scanForNoSQLInjection(req.body) || scanForNoSQLInjection(req.query);

  if (hasNoSQLInjection) {
    return res.status(400).json({
      success: false,
      error: 'Invalid input format detected'
    });
  }

  return next();
};

// Request size limiting middleware
export const requestSizeLimit = (maxSize: number = 10) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const contentLength = parseInt(req.headers['content-length'] || '0');
    const maxSizeBytes = maxSize * 1024 * 1024; // Convert MB to bytes

    if (contentLength > maxSizeBytes) {
      return res.status(413).json({
        success: false,
        error: `Request too large. Maximum size is ${maxSize}MB`
      });
    }

    return next();
  };
};

// IP whitelist middleware
export const ipWhitelist = (allowedIPs: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const clientIP = req.ip;

    if (process.env.NODE_ENV === 'development') {
      return next(); // Skip in development
    }

    if (clientIP && !allowedIPs.includes(clientIP)) {
      return res.status(403).json({
        success: false,
        error: 'Access denied from this IP address'
      });
    }

    return next();
  };
};

// IP blacklist middleware
export const ipBlacklist = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const clientIP = req.ip;
    const isBlacklisted = await redis.get(`blacklist:ip:${clientIP}`);

    if (isBlacklisted) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    return next();
  } catch (error) {
    // If Redis is down, allow the request but log the error
    console.error('IP blacklist check failed:', error);
    return next();
  }
};

// Device fingerprinting middleware
export const deviceFingerprint = (req: AuthRequest, res: Response, next: NextFunction) => {
  const fingerprint = generateDeviceFingerprint(req);

  // Store fingerprint in request for later use
  (req as any).deviceFingerprint = fingerprint;

  // Set fingerprint cookie for client verification
  res.cookie('device-fp', fingerprint, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  });

  next();
};

// Session hijacking protection
export const sessionHijackingProtection = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    if (!req.user?.sessionId) {
      return next();
    }

    const sessionData = await redis.get(`session:${req.user.sessionId}`);
    if (!sessionData) {
      throw new AppError('Session expired', 401);
    }

    const session = JSON.parse(sessionData);
    const currentFingerprint = generateDeviceFingerprint(req);

    // Check if fingerprint matches
    if (session.fingerprint !== currentFingerprint) {
      // Possible session hijacking
      await redis.del(`session:${req.user.sessionId}`);

      throw new AppError('Session security violation detected', 401);
    }

    // Update session last activity
    session.lastActivity = new Date().toISOString();
    await redis.setex(`session:${req.user.sessionId}`, 86400, JSON.stringify(session)); // 24 hours

    next();
  } catch (error) {
    next(error);
  }
};

// Brute force protection
export const bruteForceProtection = (identifier: string, maxAttempts: number = 5, windowMs: number = 15 * 60 * 1000) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = `brute:${identifier}:${req.ip}`;
      const attempts = await redis.get(key);

      if (attempts && parseInt(attempts) >= maxAttempts) {
        const ttl = await redis.ttl(key);
        return res.status(429).json({
          success: false,
          error: 'Too many failed attempts. Please try again later.',
          retryAfter: ttl
        });
      }

      // Store original res.json to check if request failed
      const originalJson = res.json;
      res.json = function(body: any) {
        // If authentication failed, increment attempts
        if (body.success === false && res.statusCode === 401) {
          redis.incr(key).then(() => {
            redis.expire(key, Math.ceil(windowMs / 1000));
          });
        } else if (body.success === true) {
          // If successful, clear attempts
          redis.del(key);
        }

        return originalJson.call(this, body);
      };

      return next();
    } catch (error) {
      console.error('Brute force protection error:', error);
      return next();
    }
  };
};

// Content type validation
export const validateContentType = (allowedTypes: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const contentType = req.headers['content-type'];

    // Skip for GET requests
    if (req.method === 'GET') {
      return next();
    }

    if (!contentType || !allowedTypes.some(type => contentType.includes(type))) {
      return res.status(415).json({
        success: false,
        error: 'Unsupported content type'
      });
    }

    return next();
  };
};

// User agent validation
export const validateUserAgent = (req: Request, res: Response, next: NextFunction) => {
  const userAgent = req.headers['user-agent'];

  if (!userAgent) {
    return res.status(400).json({
      success: false,
      error: 'User agent required'
    });
  }

  // Block known malicious user agents
  const maliciousPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python/i,
    /java/i,
    /php/i
  ];

  // Allow in development mode
  if (process.env.NODE_ENV === 'development') {
    return next();
  }

  const isMalicious = maliciousPatterns.some(pattern => pattern.test(userAgent));

  if (isMalicious) {
    return res.status(403).json({
      success: false,
      error: 'Access denied'
    });
  }

  return next();
};

// Generate device fingerprint
function generateDeviceFingerprint(req: Request): string {
  const components = [
    req.ip,
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.headers['accept'] || ''
  ];

  return crypto
    .createHash('sha256')
    .update(components.join('|'))
    .digest('hex');
}

// Secure headers middleware
export const secureHeaders = (req: Request, res: Response, next: NextFunction) => {
  // Remove server information
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), location=(), payment=()');

  // HTTPS only in production
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  next();
};

// Request validation middleware
export const requestValidation = (req: Request, res: Response, next: NextFunction) => {
  // Validate request has required headers
  const requiredHeaders = ['user-agent', 'accept'];

  for (const header of requiredHeaders) {
    if (!req.headers[header]) {
      return res.status(400).json({
        success: false,
        error: `Missing required header: ${header}`
      });
    }
  }

  // Validate URL length
  if (req.originalUrl.length > 2048) {
    return res.status(414).json({
      success: false,
      error: 'URL too long'
    });
  }

  // Validate query parameter count
  const queryCount = Object.keys(req.query).length;
  if (queryCount > 50) {
    return res.status(400).json({
      success: false,
      error: 'Too many query parameters'
    });
  }

  return next();
};

export default {
  helmetSecurity,
  xssProtection,
  sqlInjectionProtection,
  noSQLInjectionProtection,
  requestSizeLimit,
  ipWhitelist,
  ipBlacklist,
  deviceFingerprint,
  sessionHijackingProtection,
  bruteForceProtection,
  validateContentType,
  validateUserAgent,
  secureHeaders,
  requestValidation
};