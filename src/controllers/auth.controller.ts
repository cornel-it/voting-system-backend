// backend/src/controllers/auth.controller.ts

import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { auditService } from '../services/audit.service';
import { NotificationService } from '../services/notification.service';
import { validationResult } from 'express-validator';
import { AppError } from '../utils/errors';
import { DeviceInfo, RegisterUserRequest, LoginRequest, PasswordResetRequest, PasswordResetConfirm, EmailVerificationRequest, ResendVerificationRequest, TwoFactorVerificationRequest, RefreshTokenRequest, LogoutRequest } from '../types/auth.types';
import { UserRole } from '@prisma/client';

interface AuthRequest extends Request {
  user?: {
    id: string;
    studentId: string;
    role: UserRole;
    permissions: string[];
  };
}

export class AuthController {

  /**
   * Register a new user
   */
  static async register(req: Request, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const registerRequest: RegisterUserRequest = req.body;

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.register(registerRequest, deviceInfo);

      res.status(201).json({
        success: true,
        message: 'Registration successful. Please check your email for verification.',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * User login
   */
  static async login(req: Request, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const loginRequest: LoginRequest = req.body;

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      loginRequest.deviceInfo = deviceInfo;

      const result = await authService.login(loginRequest, deviceInfo);

      // Set secure cookies
      res.cookie('refreshToken', result.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/'
      });

      res.cookie('sessionId', result.sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        path: '/'
      });

      res.json({
        success: true,
        message: result.requiresTwoFactor ? '2FA code required' : 'Login successful',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Logout user
   */
  static async logout(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const logoutRequest: LogoutRequest = {
        refreshToken: req.cookies.refreshToken,
        logoutAll: req.body.logoutAll || false
      };

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.logout(logoutRequest, req.user!.id, deviceInfo);

      // Clear cookies
      res.clearCookie('refreshToken');
      res.clearCookie('sessionId');
      res.clearCookie('accessToken');

      res.json({
        success: true,
        message: 'Logged out successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Refresh access token
   */
  static async refreshToken(req: Request, res: Response, next: NextFunction) {
    try {
      const refreshTokenRequest: RefreshTokenRequest = {
        refreshToken: req.cookies.refreshToken || req.body.refreshToken,
        deviceInfo: {
          userAgent: req.get('user-agent') || '',
          ipAddress: req.ip || req.connection.remoteAddress || '',
          platform: req.get('sec-ch-ua-platform') || undefined,
          browser: req.get('sec-ch-ua') || undefined
        }
      };

      if (!refreshTokenRequest.refreshToken) {
        throw new AppError('Refresh token not provided', 401);
      }

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.refreshTokens(refreshTokenRequest, deviceInfo);

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify email address
   */
  static async verifyEmail(req: Request, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const verificationRequest: EmailVerificationRequest = {
        token: req.params.token || req.body.token
      };

      if (!verificationRequest.token) {
        throw new AppError('Verification token not provided', 400);
      }

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.verifyEmail(verificationRequest, deviceInfo);

      res.json({
        success: true,
        message: 'Email verified successfully. You can now login.',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Request password reset
   */
  static async requestPasswordReset(req: Request, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const resetRequest: PasswordResetRequest = req.body;

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.requestPasswordReset(resetRequest, deviceInfo);

      res.json({
        success: true,
        message: 'If the email exists, a password reset link has been sent.',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Reset password
   */
  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const resetConfirm: PasswordResetConfirm = {
        token: req.params.token || req.body.token,
        newPassword: req.body.newPassword,
        confirmPassword: req.body.confirmPassword
      };

      if (!resetConfirm.token) {
        throw new AppError('Reset token not provided', 400);
      }

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.confirmPasswordReset(resetConfirm, deviceInfo);

      res.json({
        success: true,
        message: 'Password reset successfully. Please login with your new password.',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Setup 2FA
   */
  static async setup2FA(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.setupTwoFactor(userId, deviceInfo);

      res.json({
        success: true,
        message: '2FA setup initiated',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify 2FA
   */
  static async verify2FA(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const verificationRequest: TwoFactorVerificationRequest = {
        userId: req.user!.id,
        token: req.body.token,
        type: req.body.type || 'setup'
      };

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.verifyTwoFactor(verificationRequest, deviceInfo);

      res.json({
        success: true,
        message: '2FA verification successful',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Disable 2FA
   */
  static async disable2FA(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const verificationRequest: TwoFactorVerificationRequest = {
        userId: req.user!.id,
        token: req.body.token || req.body.password,
        type: 'disable'
      };

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.verifyTwoFactor(verificationRequest, deviceInfo);

      res.json({
        success: true,
        message: '2FA disabled successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get current user profile
   */
  static async getProfile(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;

      // getProfile method doesn't exist in authService - return user from token
      res.json({
        success: true,
        message: 'Profile retrieved successfully',
        data: req.user
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update user profile
   */
  static async updateProfile(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const userId = req.user!.id;
      const updates = req.body;

      // Prevent updating sensitive fields
      delete updates.password;
      delete updates.studentId;
      delete updates.email;
      delete updates.role;
      delete updates.permissions;

      // updateProfile method doesn't exist in authService yet
      res.json({
        success: true,
        message: 'Profile update functionality needs to be implemented in auth service'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Change password
   */
  static async changePassword(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const userId = req.user!.id;
      const { currentPassword, newPassword } = req.body;

      // changePassword method doesn't exist in authService yet
      res.json({
        success: true,
        message: 'Password change functionality needs to be implemented in auth service'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Resend verification email
   */
  static async resendVerificationEmail(req: Request, res: Response, next: NextFunction) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const resendRequest: ResendVerificationRequest = req.body;

      const deviceInfo: DeviceInfo = {
        userAgent: req.get('user-agent') || '',
        ipAddress: req.ip || req.connection.remoteAddress || '',
        platform: req.get('sec-ch-ua-platform') || undefined,
        browser: req.get('sec-ch-ua') || undefined
      };

      const result = await authService.resendEmailVerification(resendRequest, deviceInfo);

      res.json({
        success: true,
        message: 'If the email exists and is unverified, a verification email has been sent.',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get account status
   */
  static async getAccountStatus(req: Request, res: Response, next: NextFunction) {
    try {
      const { identifier } = req.params;

      const status = await authService.getAccountStatus(identifier);

      res.json({
        success: true,
        message: 'Account status retrieved successfully',
        data: status
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get active sessions
   */
  static async getActiveSessions(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;

      // getActiveSessions method doesn't exist in authService yet
      res.json({
        success: true,
        message: 'Active sessions functionality needs to be implemented in auth service',
        data: []
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Revoke session
   */
  static async revokeSession(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;
      const { sessionId } = req.params;

      // revokeSession method doesn't exist in authService yet
      res.json({
        success: true,
        message: 'Session revoke functionality needs to be implemented in auth service'
      });
    } catch (error) {
      next(error);
    }
  }
}