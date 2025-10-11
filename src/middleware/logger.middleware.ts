// backend/src/middleware/logger.middleware.ts

import { Request, Response, NextFunction } from 'express';
import winston from 'winston';
import { v4 as uuidv4 } from 'uuid';
import { PrismaClient, AuditCategory, AuditSeverity } from '@prisma/client';
import { AuthRequest } from './auth.middleware';

const prisma = new PrismaClient();

// Create Winston logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'jkuat-voting-system' },
  transports: [
    // Error log file
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 50 * 1024 * 1024, // 50MB
      maxFiles: 5,
      tailable: true
    }),
    // Combined log file
    new winston.transports.File({
      filename: 'logs/combined.log',
      maxsize: 100 * 1024 * 1024, // 100MB
      maxFiles: 10,
      tailable: true
    }),
    // Audit log file for security events
    new winston.transports.File({
      filename: 'logs/audit.log',
      level: 'info',
      maxsize: 50 * 1024 * 1024, // 50MB
      maxFiles: 20,
      tailable: true,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ]
});

// Console logging in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// Security events logger
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({
      filename: 'logs/security.log',
      maxsize: 50 * 1024 * 1024, // 50MB
      maxFiles: 30,
      tailable: true
    })
  ]
});

// Performance logger
const performanceLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({
      filename: 'logs/performance.log',
      maxsize: 25 * 1024 * 1024, // 25MB
      maxFiles: 5,
      tailable: true
    })
  ]
});

// Request ID middleware
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const requestId = uuidv4();
  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
};

// HTTP request logging middleware
export const httpLoggingMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
  const startTime = Date.now();
  const requestId = req.headers['x-request-id'] as string;

  // Log request
  const requestLog = {
    requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    userId: req.user?.id,
    timestamp: new Date().toISOString(),
    query: req.query,
    // Don't log sensitive data
    body: sanitizeRequestBody(req.body, req.originalUrl)
  };

  logger.info('HTTP Request', requestLog);

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(chunk?: any, encoding?: any, cb?: any): any {
    const duration = Date.now() - startTime;

    const responseLog = {
      requestId,
      statusCode: res.statusCode,
      duration,
      contentLength: res.get('content-length'),
      timestamp: new Date().toISOString()
    };

    // Log based on status code
    if (res.statusCode >= 500) {
      logger.error('HTTP Response - Server Error', responseLog);
    } else if (res.statusCode >= 400) {
      logger.warn('HTTP Response - Client Error', responseLog);
    } else {
      logger.info('HTTP Response', responseLog);
    }

    // Log slow requests
    if (duration > 5000) { // 5 seconds
      performanceLogger.warn('Slow Request', {
        ...requestLog,
        ...responseLog,
        type: 'SLOW_REQUEST'
      });
    }

    return originalEnd.call(this, chunk, encoding, cb);
  };

  next();
};

// Security event logging middleware
export const securityLoggingMiddleware = (eventType: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'MEDIUM') => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      const securityEvent = {
        eventType,
        severity,
        requestId: req.headers['x-request-id'],
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        url: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
        metadata: {
          referer: req.get('referer'),
          origin: req.get('origin'),
          sessionId: req.user?.sessionId
        }
      };

      // Log to security logger
      securityLogger.info('Security Event', securityEvent);

      // Store critical security events in database
      if (severity === 'CRITICAL' || severity === 'HIGH') {
        await prisma.auditLog.create({
          data: {
            action: eventType,
            category: AuditCategory.SECURITY,
            severity: severity as AuditSeverity,
            userId: req.user?.id,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
            metadata: securityEvent
          }
        });
      }

      next();
    } catch (error) {
      logger.error('Security logging failed', { error: error instanceof Error ? error.message : error });
      next();
    }
  };
};

// Audit logging middleware for sensitive operations
export const auditLoggingMiddleware = (action: string, category: AuditCategory = AuditCategory.USER) => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      // Store original res.json to capture response
      const originalJson = res.json;
      let responseData: any;

      res.json = function(body: any) {
        responseData = body;
        return originalJson.call(this, body);
      };

      // Continue with request
      next();

      // Log after response (in case of async operations)
      res.on('finish', async () => {
        try {
          const auditEntry = {
            action,
            category,
            severity: (res.statusCode >= 400 ? AuditSeverity.HIGH : AuditSeverity.MEDIUM) as AuditSeverity,
            userId: req.user?.id,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
            metadata: {
              requestId: req.headers['x-request-id'],
              url: req.originalUrl,
              method: req.method,
              statusCode: res.statusCode,
              requestBody: sanitizeRequestBody(req.body, req.originalUrl),
              success: res.statusCode < 400,
              timestamp: new Date().toISOString()
            }
          };

          await prisma.auditLog.create({
            data: auditEntry
          });

          logger.info('Audit Log Created', auditEntry);
        } catch (error) {
          logger.error('Audit logging failed', { error: error instanceof Error ? error.message : error });
        }
      });
    } catch (error) {
      logger.error('Audit middleware setup failed', { error: error instanceof Error ? error.message : error });
      next();
    }
  };
};

// Error logging middleware
export const errorLoggingMiddleware = (err: Error, req: AuthRequest, res: Response, next: NextFunction) => {
  const errorLog = {
    requestId: req.headers['x-request-id'],
    error: {
      name: err.name,
      message: err.message,
      stack: err.stack
    },
    request: {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      userId: req.user?.id
    },
    timestamp: new Date().toISOString()
  };

  logger.error('Application Error', errorLog);

  // Log critical errors to security log
  if (err.name === 'ValidationError' || err.message.includes('SQL') || err.message.includes('injection')) {
    securityLogger.error('Potential Security Issue', {
      ...errorLog,
      severity: 'HIGH',
      type: 'POTENTIAL_ATTACK'
    });
  }

  next(err);
};

// Database operation logging
export const databaseLoggingMiddleware = (operation: string) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const startTime = Date.now();

    // Store original res.json to measure database operation time
    const originalJson = res.json;
    res.json = function(body: any) {
      const duration = Date.now() - startTime;

      const dbLog = {
        operation,
        duration,
        requestId: req.headers['x-request-id'],
        userId: req.user?.id,
        url: req.originalUrl,
        statusCode: res.statusCode,
        timestamp: new Date().toISOString()
      };

      if (duration > 1000) { // Log slow database operations
        performanceLogger.warn('Slow Database Operation', {
          ...dbLog,
          type: 'SLOW_DB_OPERATION'
        });
      } else {
        logger.debug('Database Operation', dbLog);
      }

      return originalJson.call(this, body);
    };

    next();
  };
};

// File operation logging
export const fileLoggingMiddleware = (operation: 'UPLOAD' | 'DOWNLOAD' | 'DELETE') => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      const fileLog = {
        operation,
        requestId: req.headers['x-request-id'],
        userId: req.user?.id,
        ip: req.ip,
        fileName: req.file?.originalname,
        fileSize: req.file?.size,
        mimeType: req.file?.mimetype,
        timestamp: new Date().toISOString()
      };

      logger.info('File Operation', fileLog);

      // Store in audit log
      await prisma.auditLog.create({
        data: {
          action: `FILE_${operation}`,
          category: AuditCategory.SYSTEM,
          severity: AuditSeverity.MEDIUM,
          userId: req.user?.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          metadata: fileLog
        }
      });

      next();
    } catch (error) {
      logger.error('File logging failed', { error: error instanceof Error ? error.message : error });
      next();
    }
  };
};

// Sanitize request body to remove sensitive information
function sanitizeRequestBody(body: any, url: string): any {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const sensitive = ['password', 'token', 'secret', 'key', 'pin', 'code'];
  const sanitized = { ...body };

  // Remove sensitive fields
  for (const field of sensitive) {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  }

  // Special handling for authentication endpoints
  if (url.includes('/auth/') || url.includes('/login')) {
    sanitized.password = '[REDACTED]';
    sanitized.confirmPassword = '[REDACTED]';
  }

  return sanitized;
}

// Performance monitoring middleware
export const performanceMonitoringMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
  const startTime = process.hrtime.bigint();
  const startMemory = process.memoryUsage();

  res.on('finish', () => {
    const endTime = process.hrtime.bigint();
    const endMemory = process.memoryUsage();

    const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    const memoryDelta = endMemory.heapUsed - startMemory.heapUsed;

    const performanceLog = {
      requestId: req.headers['x-request-id'],
      url: req.originalUrl,
      method: req.method,
      duration,
      memoryDelta,
      statusCode: res.statusCode,
      timestamp: new Date().toISOString()
    };

    if (duration > 2000 || Math.abs(memoryDelta) > 10 * 1024 * 1024) { // 2s or 10MB
      performanceLogger.warn('Performance Issue', performanceLog);
    } else {
      performanceLogger.debug('Performance Metrics', performanceLog);
    }
  });

  next();
};

export {
  logger,
  securityLogger,
  performanceLogger
};

export default {
  requestIdMiddleware,
  httpLoggingMiddleware,
  securityLoggingMiddleware,
  auditLoggingMiddleware,
  errorLoggingMiddleware,
  databaseLoggingMiddleware,
  fileLoggingMiddleware,
  performanceMonitoringMiddleware,
  logger,
  securityLogger,
  performanceLogger
};