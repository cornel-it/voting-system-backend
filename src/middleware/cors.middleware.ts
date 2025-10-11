// backend/src/middleware/cors.middleware.ts

import cors from 'cors';
import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/errors';

// Environment-based CORS configuration
const isDevelopment = process.env.NODE_ENV === 'development';
const isProduction = process.env.NODE_ENV === 'production';

// Allowed origins based on environment
const getAllowedOrigins = (): string[] => {
  const origins = [];

  if (isDevelopment) {
    // Development origins
    origins.push(
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:3001',
      'http://127.0.0.1:5173'
    );
  }

  if (isProduction) {
    // Production origins from environment variables
    const productionOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    origins.push(...productionOrigins);
  }

  // Always allow JKUAT domains
  origins.push(
    'https://jkuat.ac.ke',
    'https://www.jkuat.ac.ke',
    'https://students.jkuat.ac.ke',
    'https://portal.jkuat.ac.ke'
  );

  return origins;
};

// Default CORS configuration
const defaultCorsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = getAllowedOrigins();

    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new AppError(`Origin ${origin} not allowed by CORS`, 403));
    }
  },
  credentials: true, // Allow cookies to be sent
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-API-Key',
    'X-2FA-Token',
    'X-Device-ID',
    'X-Client-Version',
    'X-Request-ID'
  ],
  exposedHeaders: [
    'X-Total-Count',
    'X-Page-Count',
    'X-Current-Page',
    'X-Per-Page',
    'X-Rate-Limit-Remaining',
    'X-Rate-Limit-Reset',
    'X-Request-ID'
  ],
  maxAge: 86400, // 24 hours
  optionsSuccessStatus: 200 // For legacy browser support
};

// Main CORS middleware
export const corsMiddleware = cors(defaultCorsOptions);

// Restrictive CORS for admin endpoints
export const adminCorsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const adminOrigins = [
      'https://admin.jkuat-voting.ac.ke',
      'https://secure.jkuat-voting.ac.ke'
    ];

    if (isDevelopment) {
      adminOrigins.push('http://localhost:3000', 'http://localhost:3001');
    }

    if (!origin || adminOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new AppError(`Admin origin ${origin} not allowed`, 403));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-2FA-Token',
    'X-Admin-Key'
  ]
};

export const adminCorsMiddleware = cors(adminCorsOptions);

// Public API CORS (more permissive for public endpoints)
export const publicCorsOptions: cors.CorsOptions = {
  origin: true, // Allow all origins for public endpoints
  credentials: false, // No credentials for public endpoints
  methods: ['GET', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Accept',
    'X-Requested-With'
  ]
};

export const publicCorsMiddleware = cors(publicCorsOptions);

// Voting-specific CORS (strict security for voting operations)
export const votingCorsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const votingOrigins = getAllowedOrigins().filter(origin =>
      origin.includes('jkuat') || isDevelopment
    );

    if (!origin || votingOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new AppError(`Voting from origin ${origin} not allowed`, 403));
    }
  },
  credentials: true,
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-2FA-Token',
    'X-Device-ID',
    'X-Voting-Session'
  ]
};

export const votingCorsMiddleware = cors(votingCorsOptions);

// Dynamic CORS based on request path
export const dynamicCorsMiddleware = (req: Request, res: Response, next: NextFunction) => {
  let corsOptions: cors.CorsOptions;

  // Determine CORS configuration based on route
  if (req.path.startsWith('/api/admin')) {
    corsOptions = adminCorsOptions;
  } else if (req.path.startsWith('/api/voting') || req.path.startsWith('/api/elections/vote')) {
    corsOptions = votingCorsOptions;
  } else if (req.path.startsWith('/api/public')) {
    corsOptions = publicCorsOptions;
  } else {
    corsOptions = defaultCorsOptions;
  }

  // Apply the appropriate CORS middleware
  cors(corsOptions)(req, res, next);
};

// CORS preflight handler for complex requests
export const handleCorsPreflightMiddleware = (req: Request, res: Response, next: NextFunction) => {
  if (req.method === 'OPTIONS') {
    // Handle preflight request
    const origin = req.headers.origin;
    const allowedOrigins = getAllowedOrigins();

    if (!origin || allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin || '*');
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-API-Key',
        'X-2FA-Token',
        'X-Device-ID'
      ].join(', '));
      res.header('Access-Control-Max-Age', '86400');

      return res.status(200).end();
    } else {
      return res.status(403).json({
        success: false,
        error: 'CORS preflight check failed'
      });
    }
  }

  return next();
};

// Security headers middleware (works with CORS)
export const securityHeadersMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // Remove server information
  res.removeHeader('X-Powered-By');

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Content Security Policy
  const cspDirectives = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ];

  res.setHeader('Content-Security-Policy', cspDirectives.join('; '));

  // HTTPS enforcement in production
  if (isProduction) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  next();
};

// Origin validation middleware
export const validateOriginMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  const allowedOrigins = getAllowedOrigins();

  // Skip validation for non-browser requests
  if (!origin && !referer) {
    return next();
  }

  // Check origin
  if (origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({
      success: false,
      error: 'Origin not allowed'
    });
  }

  // Check referer as backup
  if (!origin && referer) {
    const refererOrigin = new URL(referer).origin;
    if (!allowedOrigins.includes(refererOrigin)) {
      return res.status(403).json({
        success: false,
        error: 'Referer not allowed'
      });
    }
  }

  next();
};

// CSRF token validation (works with CORS)
export const csrfProtectionMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // Skip CSRF for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Skip CSRF for API key authentication
  if (req.headers['x-api-key']) {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'] as string;
  const csrfCookie = req.cookies['csrf-token'];

  if (!csrfToken || !csrfCookie || csrfToken !== csrfCookie) {
    return res.status(403).json({
      success: false,
      error: 'CSRF token validation failed'
    });
  }

  next();
};

export default {
  corsMiddleware,
  adminCorsMiddleware,
  publicCorsMiddleware,
  votingCorsMiddleware,
  dynamicCorsMiddleware,
  handleCorsPreflightMiddleware,
  securityHeadersMiddleware,
  validateOriginMiddleware,
  csrfProtectionMiddleware
};