import jwt from 'jsonwebtoken';
import { User } from '@prisma/client';
import { logger } from './logger';
import { prisma } from '../config/database';
import crypto from 'crypto';

export interface JWTPayload {
  userId: string;
  email: string;
  role: string;
  sessionId?: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

export class JWTService {
  private static readonly ACCESS_TOKEN_SECRET = process.env.JWT_SECRET || 'default-secret';
  private static readonly REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_SECRET || 'default-refresh-secret';
  private static readonly ACCESS_TOKEN_EXPIRY = process.env.JWT_EXPIRES_IN || '15m';
  private static readonly REFRESH_TOKEN_EXPIRY = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

  /**
   * Generate access token
   */
  public static generateAccessToken(payload: JWTPayload): string {
    return jwt.sign(payload as object, this.ACCESS_TOKEN_SECRET, {
      expiresIn: this.ACCESS_TOKEN_EXPIRY as string,
      issuer: 'jkuat-voting',
      audience: 'jkuat-students',
    } as jwt.SignOptions);
  }

  /**
   * Generate refresh token
   */
  public static async generateRefreshToken(
    userId: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<string> {
    const token = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    // Store refresh token in database
    await prisma.refreshToken.create({
      data: {
        token,
        userId,
        expiresAt,
        ipAddress,
        userAgent,
      },
    });

    return token;
  }

  /**
   * Generate token pair
   */
  public static async generateTokenPair(
    user: Pick<User, 'id' | 'email' | 'role'>,
    ipAddress?: string,
    userAgent?: string
  ): Promise<TokenPair> {
    const payload: JWTPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId: crypto.randomUUID(),
    };

    const accessToken = this.generateAccessToken(payload);
    const refreshToken = await this.generateRefreshToken(
      user.id,
      ipAddress,
      userAgent
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: 900, // 15 minutes in seconds
      tokenType: 'Bearer',
    };
  }

  /**
   * Verify access token
   */
  public static verifyAccessToken(token: string): JWTPayload {
    try {
      const decoded = jwt.verify(token, this.ACCESS_TOKEN_SECRET, {
        issuer: 'jkuat-voting',
        audience: 'jkuat-students',
      }) as JWTPayload;

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid token');
      }
      throw error;
    }
  }

  /**
   * Verify refresh token
   */
  public static async verifyRefreshToken(
    token: string,
    ipAddress?: string
  ): Promise<{ valid: boolean; userId?: string }> {
    try {
      const refreshToken = await prisma.refreshToken.findUnique({
        where: { token },
        include: { user: true },
      });

      if (!refreshToken) {
        return { valid: false };
      }

      // Check if token is expired
      if (new Date() > refreshToken.expiresAt) {
        await prisma.refreshToken.delete({
          where: { id: refreshToken.id },
        });
        return { valid: false };
      }

      // Check if token has been revoked
      if (refreshToken.revokedAt) {
        logger.warn('Attempted to use revoked refresh token', {
          tokenId: refreshToken.id,
          userId: refreshToken.userId,
          ipAddress,
        });
        return { valid: false };
      }

      return { valid: true, userId: refreshToken.userId };
    } catch (error) {
      logger.error('Refresh token verification failed:', error);
      return { valid: false };
    }
  }

  /**
   * Refresh access token
   */
  public static async refreshAccessToken(
    refreshToken: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<TokenPair | null> {
    try {
      const verification = await this.verifyRefreshToken(refreshToken, ipAddress);
      
      if (!verification.valid || !verification.userId) {
        return null;
      }

      const user = await prisma.user.findUnique({
        where: { id: verification.userId },
      });

      if (!user || !user.isActive) {
        return null;
      }

      // Rotate refresh token
      await this.revokeRefreshToken(refreshToken, true);

      return this.generateTokenPair(user, ipAddress, userAgent);
    } catch (error) {
      logger.error('Token refresh failed:', error);
      return null;
    }
  }

  /**
   * Revoke refresh token
   */
  public static async revokeRefreshToken(
    token: string,
    isRotation: boolean = false
  ): Promise<void> {
    try {
      const refreshToken = await prisma.refreshToken.findUnique({
        where: { token },
      });

      if (refreshToken && !refreshToken.revokedAt) {
        await prisma.refreshToken.update({
          where: { id: refreshToken.id },
          data: {
            revokedAt: new Date(),
            replacedByToken: isRotation ? crypto.randomBytes(40).toString('hex') : null,
          },
        });
      }
    } catch (error) {
      logger.error('Failed to revoke refresh token:', error);
    }
  }

  /**
   * Revoke all user tokens
   */
  public static async revokeAllUserTokens(userId: string): Promise<void> {
    try {
      await prisma.refreshToken.updateMany({
        where: {
          userId,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });
    } catch (error) {
      logger.error('Failed to revoke user tokens:', error);
    }
  }

  /**
   * Clean up expired tokens
   */
  public static async cleanupExpiredTokens(): Promise<void> {
    try {
      const result = await prisma.refreshToken.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { 
              revokedAt: { 
                lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
              } 
            },
          ],
        },
      });

      logger.info(`Cleaned up ${result.count} expired tokens`);
    } catch (error) {
      logger.error('Token cleanup failed:', error);
    }
  }

  /**
   * Decode token without verification (for debugging)
   */
  public static decodeToken(token: string): any {
    return jwt.decode(token);
  }

  /**
   * Generate email verification token
   */
  public static generateEmailToken(email: string): string {
    return jwt.sign(
      { email, type: 'email_verification' },
      this.ACCESS_TOKEN_SECRET,
      { expiresIn: '24h' }
    );
  }

  /**
   * Generate password reset token
   */
  public static generatePasswordResetToken(userId: string): string {
    return jwt.sign(
      { userId, type: 'password_reset' },
      this.ACCESS_TOKEN_SECRET,
      { expiresIn: '1h' }
    );
  }

  /**
   * Verify special purpose token
   */
  public static verifySpecialToken(token: string, expectedType: string): any {
    try {
      const decoded = jwt.verify(token, this.ACCESS_TOKEN_SECRET) as any;
      
      if (decoded.type !== expectedType) {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid token');
      }
      throw error;
    }
  }
}

// Export as default
export default JWTService;