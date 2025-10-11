// backend/src/middleware/auth.middleware.ts

import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import { PrismaClient, UserRole } from '@prisma/client';
import { AppError } from '../utils/errors';
import { redis } from '../config/redis';

const prisma = new PrismaClient();

export interface AuthRequest extends Request {
  user?: {
    id: string;
    studentId: string;
    email: string;
    role: UserRole;
    permissions: string[];
    sessionId?: string;
  };
}

/**
 * Verify JWT token and attach user to request
 */
export const authenticate = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    // Extract token from header
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') 
      ? authHeader.substring(7)
      : null;

    if (!token) {
      throw new AppError('No authentication token provided', 401);
    }

    // Verify token
    let decoded: any;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET!);
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new AppError('Token has expired', 401);
      } else if (error.name === 'JsonWebTokenError') {
        throw new AppError('Invalid token', 401);
      }
      throw error;
    }

    // Check if token is blacklisted
    const isBlacklisted = await redis.get(`blacklist:${token}`);
    if (isBlacklisted) {
      throw new AppError('Token has been revoked', 401);
    }

    // Check if session is valid
    if (decoded.sessionId) {
      const session = await redis.get(`session:${decoded.sessionId}`);
      if (!session) {
        throw new AppError('Session has expired', 401);
      }
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        studentId: true,
        email: true,
        role: true,
        permissions: true,
        isActive: true,
        isVerified: true,
        twoFactorEnabled: true
      }
    });

    if (!user) {
      throw new AppError('User not found', 404);
    }

    if (!user.isActive) {
      throw new AppError('Account has been deactivated', 403);
    }

    // Attach user to request
    req.user = {
      id: user.id,
      studentId: user.studentId,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      sessionId: decoded.sessionId
    };

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Check if user has required role
 */
export const authorize = (...roles: UserRole[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(
        new AppError(
          `Access denied. Required role: ${roles.join(' or ')}`,
          403
        )
      );
    }

    next();
  };
};

/**
 * Check if user has required permissions
 */
export const checkPermission = (...permissions: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }

    // Super admins have all permissions
    if (req.user.role === 'SUPER_ADMIN') {
      return next();
    }

    const hasPermission = permissions.some(permission =>
      req.user!.permissions.includes(permission)
    );

    if (!hasPermission) {
      return next(
        new AppError(
          `Access denied. Required permission: ${permissions.join(' or ')}`,
          403
        )
      );
    }

    next();
  };
};

/**
 * Verify email is confirmed
 */
export const requireVerifiedEmail = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    if (!req.user) {
      throw new AppError('Authentication required', 401);
    }

    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { isVerified: true, emailVerified: true }
    });

    if (!user?.isVerified || !user?.emailVerified) {
      throw new AppError('Please verify your email address', 403);
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Require two-factor authentication for sensitive operations
 */
export const require2FA = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    if (!req.user) {
      throw new AppError('Authentication required', 401);
    }

    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { twoFactorEnabled: true }
    });

    // Check if 2FA is enabled for the user
    if (!user?.twoFactorEnabled) {
      return next();
    }

    // Check for 2FA verification token in header
    const twoFactorToken = req.headers['x-2fa-token'] as string;

    if (!twoFactorToken) {
      return res.status(403).json({
        success: false,
        error: '2FA_REQUIRED',
        message: 'Two-factor authentication required'
      });
    }

    // Verify 2FA token from cache
    const cachedToken = await redis.get(`2fa:${req.user.id}:${twoFactorToken}`);
    
    if (!cachedToken) {
      throw new AppError('Invalid or expired 2FA token', 403);
    }

    // Token is valid, proceed
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Optional authentication - attaches user if token is present but doesn't require it
 */
export const optionalAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ')
      ? authHeader.substring(7)
      : null;

    if (!token) {
      return next();
    }

    try {
      const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);

      // Check if token is blacklisted
      const isBlacklisted = await redis.get(`blacklist:${token}`);
      if (isBlacklisted) {
        return next();
      }

      // Get user from database
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: {
          id: true,
          studentId: true,
          email: true,
          role: true,
          permissions: true,
          isActive: true
        }
      });

      if (user && user.isActive) {
        req.user = {
          id: user.id,
          studentId: user.studentId,
          email: user.email,
          role: user.role,
          permissions: user.permissions
        };
      }
    } catch (error) {
      // Invalid token, continue without user
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Validate session fingerprint for additional security
 */
export const validateFingerprint = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    if (!req.user?.sessionId) {
      return next();
    }

    const sessionData = await redis.get(`session:${req.user.sessionId}`);
    if (!sessionData) {
      throw new AppError('Session expired', 401);
    }

    const session = JSON.parse(sessionData);
    const currentFingerprint = generateFingerprint(req);

    if (session.fingerprint !== currentFingerprint) {
      // Session hijacking attempt detected
      await redis.del(`session:${req.user.sessionId}`);
      
      // Log security event
      await prisma.auditLog.create({
        data: {
          action: 'SESSION_HIJACKING_DETECTED',
          category: 'SECURITY',
          severity: 'CRITICAL',
          userId: req.user.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          metadata: {
            sessionId: req.user.sessionId,
            expectedFingerprint: session.fingerprint,
            actualFingerprint: currentFingerprint
          }
        }
      });

      throw new AppError('Security violation detected', 401);
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Check if user owns the resource
 */
export const checkResourceOwnership = (resourceType: string) => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        throw new AppError('Authentication required', 401);
      }

      const resourceId = req.params.id;
      let isOwner = false;

      switch (resourceType) {
        case 'vote':
          const vote = await prisma.vote.findUnique({
            where: { id: resourceId },
            select: { voterId: true }
          });
          isOwner = vote?.voterId === req.user.id;
          break;

        case 'session':
          const session = await prisma.votingSession.findUnique({
            where: { id: resourceId },
            select: { voterId: true }
          });
          isOwner = session?.voterId === req.user.id;
          break;

        default:
          throw new AppError('Invalid resource type', 400);
      }

      // Admins can access any resource
      if (!isOwner && !['ADMIN', 'SUPER_ADMIN'].includes(req.user.role)) {
        throw new AppError('You do not have permission to access this resource', 403);
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Refresh token validation
 */
export const validateRefreshToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      throw new AppError('Refresh token not provided', 401);
    }

    // Verify refresh token
    let decoded: any;
    try {
      decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!);
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new AppError('Refresh token has expired', 401);
      }
      throw new AppError('Invalid refresh token', 401);
    }

    // Check if refresh token exists in database
    const storedToken = await redis.get(`refresh:${decoded.userId}:${refreshToken}`);
    if (!storedToken) {
      throw new AppError('Refresh token not found or has been revoked', 401);
    }

    // Attach user ID to request
    (req as any).userId = decoded.userId;
    (req as any).sessionId = decoded.sessionId;

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * API key authentication for external services
 */
export const apiKeyAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
      throw new AppError('API key required', 401);
    }

    // Validate API key
    const keyData = await redis.get(`apikey:${apiKey}`);
    if (!keyData) {
      throw new AppError('Invalid API key', 401);
    }

    const parsedData = JSON.parse(keyData);
    
    // Check if key is active
    if (!parsedData.active) {
      throw new AppError('API key has been deactivated', 403);
    }

    // Check rate limits
    const limitKey = `ratelimit:apikey:${apiKey}`;
    const requests = await redis.incr(limitKey);
    
    if (requests === 1) {
      await redis.expire(limitKey, 3600); // 1 hour window
    }

    if (requests > parsedData.rateLimit) {
      throw new AppError('API rate limit exceeded', 429);
    }

    // Attach API key info to request
    (req as any).apiKey = {
      id: parsedData.id,
      name: parsedData.name,
      permissions: parsedData.permissions
    };

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Generate session fingerprint
 */
function generateFingerprint(req: Request): string {
  const crypto = require('crypto');
  const components = [
    req.ip,
    req.get('user-agent'),
    req.get('accept-language'),
    req.get('accept-encoding')
  ];
  
  return crypto
    .createHash('sha256')
    .update(components.join('|'))
    .digest('hex');
}

export default {
  authenticate,
  authorize,
  checkPermission,
  requireVerifiedEmail,
  require2FA,
  optionalAuth,
  validateFingerprint,
  checkResourceOwnership,
  validateRefreshToken,
  apiKeyAuth
};