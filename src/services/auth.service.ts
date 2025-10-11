import { User, UserRole, TokenType, Prisma } from '@prisma/client';
import { prisma } from '../config/database';
import { redis, createSession, getSession, deleteSession, blacklistToken, isTokenBlacklisted, incrementRateLimit } from '../config/redis';
import { HashingService } from '../utils/hashing';
import { JWTService, JWTPayload } from '../utils/jwt';
import { encryptionService } from '../utils/encryption';
import { emailService } from '../utils/email';
import { smsService } from '../utils/sms';
import { logger } from '../utils/logger';
import {
  AppError,
  ValidationError,
  AuthenticationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
} from '../utils/errors';
import {
  RegisterUserRequest,
  RegisterUserResponse,
  LoginRequest,
  LoginResponse,
  PasswordResetRequest,
  PasswordResetConfirm,
  PasswordResetResponse,
  EmailVerificationRequest,
  EmailVerificationResponse,
  ResendVerificationRequest,
  TwoFactorSetupResponse,
  TwoFactorVerificationRequest,
  TwoFactorVerificationResponse,
  TokenPair,
  RefreshTokenRequest,
  SessionInfo,
  DeviceInfo,
  LogoutRequest,
  LogoutResponse,
  SafeUser,
  AccountStatusResponse,
  SecurityEvent,
  VerificationTokenInfo,
  AuthServiceOptions,
  UserManagementRequest,
  UserManagementResponse,
  BatchUserUpdate,
  BatchUpdateResponse,
  ExtendedJWTPayload,
} from '../types/auth.types';
import crypto from 'crypto';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

export class AuthService {
  private static instance: AuthService;
  private readonly options: Required<AuthServiceOptions>;

  private constructor(options: AuthServiceOptions = {}) {
    this.options = {
      enableTwoFactor: true,
      enableDeviceTracking: true,
      enableRateLimit: true,
      maxLoginAttempts: 5,
      lockoutDuration: 30 * 60 * 1000, // 30 minutes
      sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
      tokenRefreshThreshold: 5 * 60 * 1000, // 5 minutes
      ...options,
    };
  }

  public static getInstance(options?: AuthServiceOptions): AuthService {
    if (!AuthService.instance) {
      AuthService.instance = new AuthService(options);
    }
    return AuthService.instance;
  }

  /**
   * Register a new user with comprehensive validation
   */
  public async register(request: RegisterUserRequest, deviceInfo: DeviceInfo): Promise<RegisterUserResponse> {
    try {
      await this.validateRegistrationRequest(request);
      
      // Check rate limiting
      if (this.options.enableRateLimit) {
        await this.checkRateLimit(`register:${deviceInfo.ipAddress}`, 3, 300); // 3 attempts per 5 minutes
      }

      // Check if user already exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            { email: request.email.toLowerCase() },
            { studentId: request.studentId },
          ],
        },
      });

      if (existingUser) {
        if (existingUser.email === request.email.toLowerCase()) {
          throw new ConflictError('An account with this email already exists');
        }
        throw new ConflictError('An account with this student ID already exists');
      }

      // Hash password
      const hashedPassword = await HashingService.hashPassword(request.password);

      // Generate verification token
      const verificationToken = encryptionService.generateToken(32);

      // Create user in transaction
      const result = await prisma.$transaction(async (tx) => {
        // Create user
        const user = await tx.user.create({
          data: {
            studentId: request.studentId,
            email: request.email.toLowerCase(),
            firstName: request.firstName,
            lastName: request.lastName,
            middleName: request.middleName,
            password: hashedPassword,
            phone: request.phone,
            faculty: request.faculty,
            department: request.department,
            course: request.course,
            yearOfStudy: request.yearOfStudy,
            admissionYear: request.admissionYear,
            role: UserRole.VOTER,
            isActive: true,
            isVerified: false,
          },
        });

        // Create email verification token
        await tx.verificationToken.create({
          data: {
            token: verificationToken,
            userId: user.id,
            type: TokenType.EMAIL_VERIFICATION,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
          },
        });

        return user;
      });

      // Generate tokens
      const tokens = await JWTService.generateTokenPair(
        result,
        deviceInfo.ipAddress,
        deviceInfo.userAgent
      );

      // Send welcome and verification emails
      const emailVerificationSent = await this.sendWelcomeAndVerificationEmail(result, verificationToken);

      // Log successful registration
      await this.logSecurityEvent({
        type: 'LOGIN_SUCCESS',
        userId: result.id,
        deviceInfo,
        metadata: { action: 'register' },
        timestamp: new Date(),
      });

      // Create audit log
      await this.createAuditLog({
        userId: result.id,
        action: 'USER_REGISTERED',
        category: 'AUTH',
        severity: 'LOW',
        metadata: {
          studentId: result.studentId,
          email: result.email,
          faculty: result.faculty,
          department: result.department,
        },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
      });

      return {
        user: this.toSafeUser(result),
        tokens,
        emailVerificationSent,
      };
    } catch (error) {
      logger.error('Registration failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Registration failed', 500);
    }
  }

  /**
   * Login user with comprehensive security checks
   */
  public async login(request: LoginRequest, deviceInfo: DeviceInfo): Promise<LoginResponse> {
    try {
      const identifier = request.identifier.toLowerCase();

      // Check rate limiting
      if (this.options.enableRateLimit) {
        await this.checkRateLimit(`login:${deviceInfo.ipAddress}`, 10, 300); // 10 attempts per 5 minutes
        await this.checkRateLimit(`login:${identifier}`, 5, 900); // 5 attempts per 15 minutes per user
      }

      // Find user
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { email: identifier },
            { studentId: identifier },
          ],
        },
        include: {
          refreshTokens: {
            where: {
              revokedAt: null,
              expiresAt: { gt: new Date() },
            },
          },
        },
      });

      if (!user) {
        await this.handleFailedLogin(identifier, deviceInfo, 'User not found');
        throw new AuthenticationError('Invalid credentials');
      }

      // Check if account is locked
      await this.checkAccountLock(user);

      // Verify password
      const isPasswordValid = await HashingService.comparePassword(request.password, user.password);
      if (!isPasswordValid) {
        await this.handleFailedLogin(user.id, deviceInfo, 'Invalid password');
        throw new AuthenticationError('Invalid credentials');
      }

      // Check two-factor authentication
      if (user.twoFactorEnabled && !request.twoFactorCode) {
        return {
          user: this.toSafeUser(user),
          tokens: { accessToken: '', refreshToken: '', expiresIn: 0, tokenType: 'Bearer' },
          requiresTwoFactor: true,
          sessionId: '',
        };
      }

      if (user.twoFactorEnabled && request.twoFactorCode) {
        const is2FAValid = await this.verifyTwoFactorCode(user.id, request.twoFactorCode);
        if (!is2FAValid) {
          await this.handleFailedLogin(user.id, deviceInfo, 'Invalid 2FA code');
          throw new AuthenticationError('Invalid two-factor authentication code');
        }
      }

      // Generate tokens
      const tokens = await JWTService.generateTokenPair(
        user,
        deviceInfo.ipAddress,
        deviceInfo.userAgent
      );

      // Create session
      const sessionId = encryptionService.generateSessionToken();
      const sessionData = {
        userId: user.id,
        deviceInfo,
        loginTime: new Date(),
        lastActivity: new Date(),
      };

      await createSession(
        sessionId,
        user.id,
        sessionData,
        this.options.sessionTimeout / 1000
      );

      // Update user login info and reset login attempts
      await prisma.user.update({
        where: { id: user.id },
        data: {
          lastLogin: new Date(),
          loginAttempts: 0,
          lockedUntil: null,
        },
      });

      // Send security notification for new device
      if (this.options.enableDeviceTracking) {
        await this.handleDeviceTracking(user, deviceInfo);
      }

      // Log successful login
      await this.logSecurityEvent({
        type: 'LOGIN_SUCCESS',
        userId: user.id,
        deviceInfo,
        metadata: { sessionId },
        timestamp: new Date(),
      });

      // Create audit log
      await this.createAuditLog({
        userId: user.id,
        action: 'USER_LOGIN',
        category: 'AUTH',
        severity: 'LOW',
        metadata: {
          sessionId,
          twoFactorUsed: user.twoFactorEnabled,
        },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
      });

      return {
        user: this.toSafeUser(user),
        tokens,
        requiresTwoFactor: false,
        sessionId,
      };
    } catch (error) {
      logger.error('Login failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Login failed', 500);
    }
  }

  /**
   * Request password reset
   */
  public async requestPasswordReset(request: PasswordResetRequest, deviceInfo: DeviceInfo): Promise<PasswordResetResponse> {
    try {
      // Check rate limiting
      if (this.options.enableRateLimit) {
        await this.checkRateLimit(`password_reset:${deviceInfo.ipAddress}`, 3, 3600); // 3 attempts per hour
        await this.checkRateLimit(`password_reset:${request.email}`, 2, 3600); // 2 attempts per hour per email
      }

      const user = await prisma.user.findUnique({
        where: { email: request.email.toLowerCase() },
      });

      // Always return success to prevent email enumeration
      if (!user) {
        logger.warn('Password reset requested for non-existent email', {
          email: request.email,
          ipAddress: deviceInfo.ipAddress,
        });
        return {
          message: 'If an account with this email exists, you will receive a password reset link shortly.',
          success: true,
        };
      }

      // Generate reset token
      const resetToken = encryptionService.generateToken(32);
      const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Update user with reset token
      await prisma.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: user.id },
          data: {
            passwordResetToken: resetToken,
            passwordResetExpires: resetExpiry,
          },
        });

        await tx.verificationToken.create({
          data: {
            token: resetToken,
            userId: user.id,
            type: TokenType.PASSWORD_RESET,
            expiresAt: resetExpiry,
          },
        });
      });

      // Send password reset email
      const resetUrl = `${process.env.FRONTEND_URL}/auth/reset-password?token=${resetToken}`;
      await emailService.sendPasswordResetEmail(
        {
          email: user.email,
          firstName: user.firstName,
        },
        resetUrl
      );

      // Log password reset request
      await this.logSecurityEvent({
        type: 'PASSWORD_RESET',
        userId: user.id,
        deviceInfo,
        metadata: { action: 'request' },
        timestamp: new Date(),
      });

      // Create audit log
      await this.createAuditLog({
        userId: user.id,
        action: 'PASSWORD_RESET_REQUESTED',
        category: 'SECURITY',
        severity: 'MEDIUM',
        metadata: { requestedFrom: deviceInfo.ipAddress },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
      });

      return {
        message: 'If an account with this email exists, you will receive a password reset link shortly.',
        success: true,
      };
    } catch (error) {
      logger.error('Password reset request failed:', error);
      throw new AppError('Password reset request failed', 500);
    }
  }

  /**
   * Confirm password reset with new password
   */
  public async confirmPasswordReset(request: PasswordResetConfirm, deviceInfo: DeviceInfo): Promise<PasswordResetResponse> {
    try {
      if (request.newPassword !== request.confirmPassword) {
        throw new ValidationError('Passwords do not match');
      }

      // Find and validate reset token
      const verificationToken = await prisma.verificationToken.findUnique({
        where: {
          token: request.token,
          type: TokenType.PASSWORD_RESET,
        },
        include: { user: true },
      });

      if (!verificationToken || verificationToken.usedAt) {
        throw new ValidationError('Invalid or expired password reset token');
      }

      if (verificationToken.expiresAt < new Date()) {
        throw new ValidationError('Password reset token has expired');
      }

      // Check if new password is different from current
      const isSamePassword = await HashingService.comparePassword(
        request.newPassword,
        verificationToken.user.password
      );
      if (isSamePassword) {
        throw new ValidationError('New password must be different from current password');
      }

      // Hash new password
      const hashedPassword = await HashingService.hashPassword(request.newPassword);

      // Update password and mark token as used
      await prisma.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: verificationToken.userId },
          data: {
            password: hashedPassword,
            passwordResetToken: null,
            passwordResetExpires: null,
            loginAttempts: 0,
            lockedUntil: null,
          },
        });

        await tx.verificationToken.update({
          where: { id: verificationToken.id },
          data: { usedAt: new Date() },
        });

        // Revoke all existing refresh tokens for security
        await tx.refreshToken.updateMany({
          where: {
            userId: verificationToken.userId,
            revokedAt: null,
          },
          data: { revokedAt: new Date() },
        });
      });

      // Send password change confirmation email
      await emailService.sendEmail({
        to: verificationToken.user.email,
        subject: 'Password Changed Successfully',
        template: 'password-changed',
        data: {
          firstName: verificationToken.user.firstName,
          changeTime: new Date().toLocaleString(),
          ipAddress: deviceInfo.ipAddress,
        },
      });

      // Send SMS notification if phone is available
      if (verificationToken.user.phone) {
        await smsService.sendSecurityAlert(
          verificationToken.user.phone,
          'password_change',
          `Password changed from IP: ${deviceInfo.ipAddress}`
        );
      }

      // Log password change
      await this.logSecurityEvent({
        type: 'PASSWORD_CHANGE',
        userId: verificationToken.userId,
        deviceInfo,
        metadata: { method: 'reset' },
        timestamp: new Date(),
      });

      // Create audit log
      await this.createAuditLog({
        userId: verificationToken.userId,
        action: 'PASSWORD_RESET_COMPLETED',
        category: 'SECURITY',
        severity: 'HIGH',
        metadata: { resetFrom: deviceInfo.ipAddress },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
      });

      return {
        message: 'Password has been successfully reset. Please login with your new password.',
        success: true,
      };
    } catch (error) {
      logger.error('Password reset confirmation failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Password reset confirmation failed', 500);
    }
  }

  /**
   * Verify email address
   */
  public async verifyEmail(request: EmailVerificationRequest, deviceInfo: DeviceInfo): Promise<EmailVerificationResponse> {
    try {
      const verificationToken = await prisma.verificationToken.findUnique({
        where: {
          token: request.token,
          type: TokenType.EMAIL_VERIFICATION,
        },
        include: { user: true },
      });

      if (!verificationToken || verificationToken.usedAt) {
        throw new ValidationError('Invalid or already used verification token');
      }

      if (verificationToken.expiresAt < new Date()) {
        throw new ValidationError('Verification token has expired');
      }

      // Update user verification status
      await prisma.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: verificationToken.userId },
          data: {
            isVerified: true,
            emailVerified: new Date(),
          },
        });

        await tx.verificationToken.update({
          where: { id: verificationToken.id },
          data: { usedAt: new Date() },
        });
      });

      // Send welcome email
      await emailService.sendWelcomeEmail({
        email: verificationToken.user.email,
        firstName: verificationToken.user.firstName,
        studentId: verificationToken.user.studentId,
      });

      // Log email verification
      await this.logSecurityEvent({
        type: 'LOGIN_SUCCESS',
        userId: verificationToken.userId,
        deviceInfo,
        metadata: { action: 'email_verified' },
        timestamp: new Date(),
      });

      // Create audit log
      await this.createAuditLog({
        userId: verificationToken.userId,
        action: 'EMAIL_VERIFIED',
        category: 'AUTH',
        severity: 'LOW',
        metadata: { verifiedFrom: deviceInfo.ipAddress },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
      });

      return {
        message: 'Email has been successfully verified. Your account is now fully activated.',
        success: true,
      };
    } catch (error) {
      logger.error('Email verification failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Email verification failed', 500);
    }
  }

  /**
   * Resend email verification
   */
  public async resendEmailVerification(request: ResendVerificationRequest, deviceInfo: DeviceInfo): Promise<EmailVerificationResponse> {
    try {
      // Check rate limiting
      if (this.options.enableRateLimit) {
        await this.checkRateLimit(`email_verification:${request.email}`, 3, 3600); // 3 attempts per hour
      }

      const user = await prisma.user.findUnique({
        where: { email: request.email.toLowerCase() },
      });

      if (!user) {
        throw new NotFoundError('User not found');
      }

      if (user.isVerified && user.emailVerified) {
        return {
          message: 'Email is already verified.',
          success: true,
        };
      }

      // Generate new verification token
      const verificationToken = encryptionService.generateToken(32);

      // Invalidate old tokens and create new one
      await prisma.$transaction(async (tx) => {
        // Mark old tokens as used
        await tx.verificationToken.updateMany({
          where: {
            userId: user.id,
            type: TokenType.EMAIL_VERIFICATION,
            usedAt: null,
          },
          data: { usedAt: new Date() },
        });

        // Create new token
        await tx.verificationToken.create({
          data: {
            token: verificationToken,
            userId: user.id,
            type: TokenType.EMAIL_VERIFICATION,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
          },
        });
      });

      // Send verification email
      const verificationUrl = `${process.env.FRONTEND_URL}/auth/verify-email?token=${verificationToken}`;
      const verificationCode = verificationToken.substring(0, 8).toUpperCase();

      await emailService.sendVerificationEmail(
        {
          email: user.email,
          firstName: user.firstName,
        },
        verificationUrl,
        verificationCode
      );

      // Create audit log
      await this.createAuditLog({
        userId: user.id,
        action: 'EMAIL_VERIFICATION_RESENT',
        category: 'AUTH',
        severity: 'LOW',
        metadata: { requestedFrom: deviceInfo.ipAddress },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
      });

      return {
        message: 'Verification email has been resent. Please check your inbox.',
        success: true,
      };
    } catch (error) {
      logger.error('Resend email verification failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Failed to resend verification email', 500);
    }
  }

  /**
   * Setup two-factor authentication
   */
  public async setupTwoFactor(userId: string, deviceInfo: DeviceInfo): Promise<TwoFactorSetupResponse> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new NotFoundError('User not found');
      }

      if (user.twoFactorEnabled) {
        throw new ValidationError('Two-factor authentication is already enabled');
      }

      // Generate secret
      const secret = speakeasy.generateSecret({
        name: `JKUAT Voting (${user.email})`,
        issuer: 'JKUAT Voting System',
        length: 32,
      });

      // Generate QR code
      const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url!);

      // Generate backup codes
      const backupCodes = Array.from({ length: 8 }, () => 
        encryptionService.generateVerificationCode(8)
      );

      // Store encrypted secret and backup codes
      const encryptedSecret = encryptionService.encrypt(secret.base32);
      const encryptedBackupCodes = backupCodes.map(code => 
        encryptionService.encrypt(code)
      );

      // Temporarily store setup data in Redis (expires in 10 minutes)
      await redis.setex(
        `2fa_setup:${userId}`,
        600,
        JSON.stringify({
          secret: encryptedSecret,
          backupCodes: encryptedBackupCodes,
          setupTime: new Date().toISOString(),
        })
      );

      // Create audit log
      await this.createAuditLog({
        userId: user.id,
        action: 'TWO_FACTOR_SETUP_INITIATED',
        category: 'SECURITY',
        severity: 'MEDIUM',
        metadata: { initiatedFrom: deviceInfo.ipAddress },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
      });

      return {
        secret: secret.base32,
        qrCode: qrCodeDataUrl,
        backupCodes,
      };
    } catch (error) {
      logger.error('2FA setup failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Two-factor authentication setup failed', 500);
    }
  }

  /**
   * Verify two-factor authentication code
   */
  public async verifyTwoFactor(request: TwoFactorVerificationRequest, deviceInfo: DeviceInfo): Promise<TwoFactorVerificationResponse> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: request.userId },
      });

      if (!user) {
        throw new NotFoundError('User not found');
      }

      if (request.type === 'setup') {
        return this.completeTwoFactorSetup(request, deviceInfo);
      }

      if (request.type === 'disable') {
        return this.disableTwoFactor(request, deviceInfo);
      }

      // For login verification
      if (!user.twoFactorEnabled || !user.twoFactorSecret) {
        throw new ValidationError('Two-factor authentication is not enabled');
      }

      const isValid = await this.verifyTwoFactorCode(user.id, request.token);
      
      if (!isValid) {
        // Log failed 2FA attempt
        await this.logSecurityEvent({
          type: 'LOGIN_FAILURE',
          userId: user.id,
          deviceInfo,
          metadata: { reason: 'invalid_2fa_code' },
          timestamp: new Date(),
        });

        throw new AuthenticationError('Invalid two-factor authentication code');
      }

      return {
        success: true,
        message: 'Two-factor authentication verified successfully',
      };
    } catch (error) {
      logger.error('2FA verification failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Two-factor authentication verification failed', 500);
    }
  }

  /**
   * Refresh access token using refresh token
   */
  public async refreshTokens(request: RefreshTokenRequest, deviceInfo: DeviceInfo): Promise<TokenPair> {
    try {
      const verification = await JWTService.verifyRefreshToken(
        request.refreshToken,
        deviceInfo.ipAddress
      );

      if (!verification.valid || !verification.userId) {
        await blacklistToken(request.refreshToken, 86400); // Blacklist for 24 hours
        throw new AuthenticationError('Invalid refresh token');
      }

      const user = await prisma.user.findUnique({
        where: { id: verification.userId },
      });

      if (!user || !user.isActive) {
        throw new AuthenticationError('User account is not active');
      }

      // Check if token is blacklisted
      if (await isTokenBlacklisted(request.refreshToken)) {
        throw new AuthenticationError('Token has been revoked');
      }

      // Generate new token pair
      const tokens = await JWTService.refreshAccessToken(
        request.refreshToken,
        deviceInfo.ipAddress,
        deviceInfo.userAgent
      );

      if (!tokens) {
        throw new AuthenticationError('Failed to refresh tokens');
      }

      // Log token refresh
      await this.logSecurityEvent({
        type: 'TOKEN_REFRESH',
        userId: user.id,
        deviceInfo,
        metadata: { oldToken: request.refreshToken.substring(0, 10) + '...' },
        timestamp: new Date(),
      });

      return tokens;
    } catch (error) {
      logger.error('Token refresh failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Token refresh failed', 500);
    }
  }

  /**
   * Logout user with comprehensive cleanup
   */
  public async logout(request: LogoutRequest, userId: string, deviceInfo: DeviceInfo): Promise<LogoutResponse> {
    try {
      if (request.logoutAll) {
        // Logout from all devices
        await JWTService.revokeAllUserTokens(userId);
        
        // Clear all sessions
        const sessions = await redis.keys(`session:*`);
        for (const sessionKey of sessions) {
          const sessionData = await getSession(sessionKey.split(':')[1]);
          if (sessionData && sessionData.userId === userId) {
            await deleteSession(sessionKey.split(':')[1]);
          }
        }
      } else if (request.refreshToken) {
        // Logout from specific device
        await JWTService.revokeRefreshToken(request.refreshToken);
      }

      // Log logout
      await this.logSecurityEvent({
        type: 'LOGOUT',
        userId,
        deviceInfo,
        metadata: { logoutAll: request.logoutAll },
        timestamp: new Date(),
      });

      // Create audit log
      await this.createAuditLog({
        userId,
        action: request.logoutAll ? 'LOGOUT_ALL_DEVICES' : 'LOGOUT',
        category: 'AUTH',
        severity: 'LOW',
        metadata: { logoutFrom: deviceInfo.ipAddress },
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
      });

      return {
        message: request.logoutAll 
          ? 'Successfully logged out from all devices' 
          : 'Successfully logged out',
        success: true,
      };
    } catch (error) {
      logger.error('Logout failed:', error);
      throw new AppError('Logout failed', 500);
    }
  }

  /**
   * Get user session information
   */
  public async getSessionInfo(sessionId: string): Promise<SessionInfo | null> {
    try {
      const sessionData = await getSession(sessionId);
      
      if (!sessionData) {
        return null;
      }

      return {
        sessionId,
        userId: sessionData.userId,
        deviceInfo: sessionData.deviceInfo,
        createdAt: new Date(sessionData.loginTime),
        lastActivityAt: new Date(sessionData.lastActivity),
        expiresAt: new Date(Date.now() + this.options.sessionTimeout),
        isActive: true,
      };
    } catch (error) {
      logger.error('Get session info failed:', error);
      return null;
    }
  }

  /**
   * Update session activity
   */
  public async updateSessionActivity(sessionId: string, userId: string): Promise<void> {
    try {
      const sessionData = await getSession(sessionId);
      
      if (sessionData && sessionData.userId === userId) {
        sessionData.lastActivity = new Date();
        await createSession(
          sessionId,
          userId,
          sessionData,
          this.options.sessionTimeout / 1000
        );
      }
    } catch (error) {
      logger.error('Update session activity failed:', error);
    }
  }

  /**
   * Get account status including locks and verification status
   */
  public async getAccountStatus(userId: string): Promise<AccountStatusResponse> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new NotFoundError('User not found');
      }

      const isLocked = user.lockedUntil && user.lockedUntil > new Date();
      const requiresVerification = !user.isVerified || !user.emailVerified;
      const verificationTypes: ('email' | 'phone')[] = [];

      if (!user.emailVerified) {
        verificationTypes.push('email');
      }
      if (user.phone && !user.phoneVerified) {
        verificationTypes.push('phone');
      }

      return {
        isLocked: !!isLocked,
        lockReason: isLocked ? 'Too many failed login attempts' : undefined,
        lockedUntil: user.lockedUntil || undefined,
        loginAttempts: user.loginAttempts,
        maxLoginAttempts: this.options.maxLoginAttempts,
        requiresVerification,
        verificationTypes,
      };
    } catch (error) {
      logger.error('Get account status failed:', error);
      if (error instanceof AppError) throw error;
      throw new AppError('Failed to get account status', 500);
    }
  }

  // Private helper methods...

  private async validateRegistrationRequest(request: RegisterUserRequest): Promise<void> {
    const errors: string[] = [];

    // Basic validation
    if (!request.studentId || request.studentId.length < 5) {
      errors.push('Student ID must be at least 5 characters long');
    }

    if (!request.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(request.email)) {
      errors.push('Valid email address is required');
    }

    if (!request.firstName || request.firstName.length < 2) {
      errors.push('First name must be at least 2 characters long');
    }

    if (!request.lastName || request.lastName.length < 2) {
      errors.push('Last name must be at least 2 characters long');
    }

    if (!request.password || request.password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (request.password !== request.confirmPassword) {
      errors.push('Passwords do not match');
    }

    // Password strength validation
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(request.password)) {
      errors.push('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character');
    }

    if (!request.faculty || !request.department || !request.course) {
      errors.push('Faculty, department, and course are required');
    }

    if (!request.yearOfStudy || request.yearOfStudy < 1 || request.yearOfStudy > 6) {
      errors.push('Year of study must be between 1 and 6');
    }

    if (!request.admissionYear || request.admissionYear < 2015 || request.admissionYear > new Date().getFullYear()) {
      errors.push('Admission year must be valid');
    }

    if (request.phone && !/^\+?[\d\s\-\(\)]+$/.test(request.phone)) {
      errors.push('Invalid phone number format');
    }

    if (errors.length > 0) {
      throw new ValidationError(errors.join(', '));
    }
  }

  private async checkRateLimit(key: string, limit: number, window: number): Promise<void> {
    const current = await incrementRateLimit(key, window);
    if (current > limit) {
      logger.warn(`Rate limit exceeded for ${key}`, { current, limit });
      throw new RateLimitError(`Too many requests. Please try again later.`);
    }
  }

  private async checkAccountLock(user: User): Promise<void> {
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const lockDuration = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
      throw new AuthenticationError(
        `Account is temporarily locked. Please try again in ${lockDuration} minutes.`
      );
    }

    if (!user.isActive) {
      throw new AuthenticationError('Account has been deactivated. Please contact support.');
    }
  }

  private async handleFailedLogin(userIdOrEmail: string, deviceInfo: DeviceInfo, reason: string): Promise<void> {
    try {
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { id: userIdOrEmail },
            { email: userIdOrEmail },
            { studentId: userIdOrEmail },
          ],
        },
      });

      if (user) {
        const newAttempts = user.loginAttempts + 1;
        const shouldLock = newAttempts >= this.options.maxLoginAttempts;

        await prisma.user.update({
          where: { id: user.id },
          data: {
            loginAttempts: newAttempts,
            lockedUntil: shouldLock 
              ? new Date(Date.now() + this.options.lockoutDuration)
              : undefined,
          },
        });

        // Log security event
        await this.logSecurityEvent({
          type: 'LOGIN_FAILURE',
          userId: user.id,
          deviceInfo,
          metadata: { reason, attempt: newAttempts, locked: shouldLock },
          timestamp: new Date(),
        });

        // Send security alert if account is locked
        if (shouldLock) {
          await this.sendAccountLockNotification(user, deviceInfo);
        }
      }
    } catch (error) {
      logger.error('Failed to handle failed login:', error);
    }
  }

  private async verifyTwoFactorCode(userId: string, token: string): Promise<boolean> {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user || !user.twoFactorSecret) {
        return false;
      }

      // Decrypt the stored secret
      const secret = encryptionService.decrypt(user.twoFactorSecret);

      // Verify TOTP token
      const isValid = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 2, // Allow 2 time steps (60 seconds) tolerance
      });

      return isValid;
    } catch (error) {
      logger.error('2FA code verification failed:', error);
      return false;
    }
  }

  private async completeTwoFactorSetup(request: TwoFactorVerificationRequest, deviceInfo: DeviceInfo): Promise<TwoFactorVerificationResponse> {
    // Get setup data from Redis
    const setupData = await redis.get(`2fa_setup:${request.userId}`);
    if (!setupData) {
      throw new ValidationError('Two-factor setup session has expired. Please start over.');
    }

    const { secret, backupCodes } = JSON.parse(setupData);

    // Verify the provided token
    const decryptedSecret = encryptionService.decrypt(secret);
    const isValid = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32',
      token: request.token,
      window: 2,
    });

    if (!isValid) {
      throw new ValidationError('Invalid verification code. Please try again.');
    }

    // Enable 2FA for the user
    await prisma.user.update({
      where: { id: request.userId },
      data: {
        twoFactorEnabled: true,
        twoFactorSecret: secret,
      },
    });

    // Store encrypted backup codes
    const backupCodesData = backupCodes.map((encryptedCode: string, index: number) => ({
      userId: request.userId,
      code: encryptedCode,
      used: false,
      createdAt: new Date(),
    }));

    // Clean up setup data
    await redis.del(`2fa_setup:${request.userId}`);

    // Log 2FA enablement
    await this.logSecurityEvent({
      type: 'TWO_FACTOR_ENABLED',
      userId: request.userId,
      deviceInfo,
      metadata: { setupCompletedFrom: deviceInfo.ipAddress },
      timestamp: new Date(),
    });

    // Create audit log
    await this.createAuditLog({
      userId: request.userId,
      action: 'TWO_FACTOR_ENABLED',
      category: 'SECURITY',
      severity: 'HIGH',
      metadata: { enabledFrom: deviceInfo.ipAddress },
      ipAddress: deviceInfo.ipAddress,
      userAgent: deviceInfo.userAgent,
    });

    return {
      success: true,
      message: 'Two-factor authentication has been successfully enabled',
      backupCodes: backupCodes.map((code: string) => encryptionService.decrypt(code)),
    };
  }

  private async disableTwoFactor(request: TwoFactorVerificationRequest, deviceInfo: DeviceInfo): Promise<TwoFactorVerificationResponse> {
    const user = await prisma.user.findUnique({
      where: { id: request.userId },
    });

    if (!user || !user.twoFactorEnabled) {
      throw new ValidationError('Two-factor authentication is not enabled');
    }

    // Verify current password or 2FA code
    const isValid = await this.verifyTwoFactorCode(request.userId, request.token);
    if (!isValid) {
      throw new ValidationError('Invalid verification code');
    }

    // Disable 2FA
    await prisma.user.update({
      where: { id: request.userId },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
      },
    });

    // Log 2FA disablement
    await this.logSecurityEvent({
      type: 'TWO_FACTOR_DISABLED',
      userId: request.userId,
      deviceInfo,
      metadata: { disabledFrom: deviceInfo.ipAddress },
      timestamp: new Date(),
    });

    // Create audit log
    await this.createAuditLog({
      userId: request.userId,
      action: 'TWO_FACTOR_DISABLED',
      category: 'SECURITY',
      severity: 'HIGH',
      metadata: { disabledFrom: deviceInfo.ipAddress },
      ipAddress: deviceInfo.ipAddress,
      userAgent: deviceInfo.userAgent,
    });

    return {
      success: true,
      message: 'Two-factor authentication has been disabled',
    };
  }

  private async handleDeviceTracking(user: User, deviceInfo: DeviceInfo): Promise<void> {
    const deviceFingerprint = encryptionService.generateDeviceFingerprint(
      deviceInfo.userAgent,
      deviceInfo.ipAddress,
      deviceInfo.platform || ''
    );

    // Check if this is a new device
    const recentLogins = await redis.get(`device:${user.id}`);
    const knownDevices = recentLogins ? JSON.parse(recentLogins) : [];

    const isNewDevice = !knownDevices.some((device: any) => 
      device.fingerprint === deviceFingerprint
    );

    if (isNewDevice) {
      // Send new device notification
      await this.sendNewDeviceNotification(user, deviceInfo);

      // Store device info
      knownDevices.push({
        fingerprint: deviceFingerprint,
        userAgent: deviceInfo.userAgent,
        ipAddress: deviceInfo.ipAddress,
        lastSeen: new Date(),
      });

      // Keep only last 10 devices
      const trimmedDevices = knownDevices.slice(-10);
      await redis.setex(`device:${user.id}`, 2592000, JSON.stringify(trimmedDevices)); // 30 days
    }
  }

  private async sendWelcomeAndVerificationEmail(user: User, verificationToken: string): Promise<boolean> {
    try {
      const verificationUrl = `${process.env.FRONTEND_URL}/auth/verify-email?token=${verificationToken}`;
      const verificationCode = verificationToken.substring(0, 8).toUpperCase();

      // Send verification email
      await emailService.sendVerificationEmail(
        {
          email: user.email,
          firstName: user.firstName,
        },
        verificationUrl,
        verificationCode
      );

      return true;
    } catch (error) {
      logger.error('Failed to send welcome/verification email:', error);
      return false;
    }
  }

  private async sendAccountLockNotification(user: User, deviceInfo: DeviceInfo): Promise<void> {
    try {
      // Send email notification
      await emailService.sendEmail({
        to: user.email,
        subject: 'Account Temporarily Locked - JKUAT Voting System',
        template: 'account-locked',
        data: {
          firstName: user.firstName,
          lockTime: new Date().toLocaleString(),
          ipAddress: deviceInfo.ipAddress,
          unlockTime: new Date(Date.now() + this.options.lockoutDuration).toLocaleString(),
        },
      });

      // Send SMS if available
      if (user.phone) {
        await smsService.sendSecurityAlert(
          user.phone,
          'suspicious_activity',
          `Account locked due to multiple failed login attempts from ${deviceInfo.ipAddress}`
        );
      }
    } catch (error) {
      logger.error('Failed to send account lock notification:', error);
    }
  }

  private async sendNewDeviceNotification(user: User, deviceInfo: DeviceInfo): Promise<void> {
    try {
      // Send email notification
      await emailService.sendEmail({
        to: user.email,
        subject: 'New Device Login - JKUAT Voting System',
        template: 'new-device-login',
        data: {
          firstName: user.firstName,
          deviceInfo: deviceInfo.userAgent,
          ipAddress: deviceInfo.ipAddress,
          loginTime: new Date().toLocaleString(),
          location: deviceInfo.location || 'Unknown',
        },
      });

      // Send SMS if available
      if (user.phone) {
        await smsService.sendSecurityAlert(
          user.phone,
          'login',
          `New login from ${deviceInfo.ipAddress} at ${new Date().toLocaleString()}`
        );
      }
    } catch (error) {
      logger.error('Failed to send new device notification:', error);
    }
  }

  private toSafeUser(user: User): SafeUser {
    return {
      id: user.id,
      studentId: user.studentId,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      middleName: user.middleName ?? undefined,
      phone: user.phone ?? undefined,
      profileImage: user.profileImage ?? undefined,
      faculty: user.faculty,
      department: user.department,
      course: user.course,
      yearOfStudy: user.yearOfStudy,
      admissionYear: user.admissionYear,
      role: user.role,
      permissions: user.permissions,
      isActive: user.isActive,
      isVerified: user.isVerified,
      emailVerified: user.emailVerified ?? undefined,
      phoneVerified: user.phoneVerified ?? undefined,
      twoFactorEnabled: user.twoFactorEnabled,
      lastLogin: user.lastLogin ?? undefined,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  private async logSecurityEvent(event: SecurityEvent): Promise<void> {
    try {
      await redis.lpush(
        `security_events:${event.userId}`,
        JSON.stringify({
          ...event,
          id: encryptionService.generateToken(16),
        })
      );

      // Keep only last 100 events per user
      await redis.ltrim(`security_events:${event.userId}`, 0, 99);

      // Set expiry (30 days)
      await redis.expire(`security_events:${event.userId}`, 2592000);

      logger.info('Security event logged', {
        type: event.type,
        userId: event.userId,
        ipAddress: event.deviceInfo.ipAddress,
      });
    } catch (error) {
      logger.error('Failed to log security event:', error);
    }
  }

  private async createAuditLog(logData: {
    userId?: string;
    action: string;
    category: 'AUTH' | 'SECURITY';
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    metadata: Record<string, any>;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    try {
      await prisma.auditLog.create({
        data: {
          userId: logData.userId,
          action: logData.action,
          category: logData.category,
          severity: logData.severity,
          metadata: logData.metadata,
          ipAddress: logData.ipAddress,
          userAgent: logData.userAgent,
          requestId: encryptionService.generateToken(16),
        },
      });
    } catch (error) {
      logger.error('Failed to create audit log:', error);
    }
  }
}

// Export singleton instance
export const authService = AuthService.getInstance();

export default authService;