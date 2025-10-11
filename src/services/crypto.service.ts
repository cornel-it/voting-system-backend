// backend/src/services/crypto.service.ts

import * as crypto from 'crypto';
import * as bcrypt from 'bcryptjs';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { AppError } from '../utils/errors';

interface VoteData {
  electionId: string;
  positionId: string;
  candidateId: string | null;
  voterId: string;
  timestamp: string;
}

interface ReceiptData {
  sessionId: string;
  completedAt: Date;
  voteHashes: string[];
}

export class CryptoService {
  private static instance: CryptoService;
  private readonly algorithm = 'aes-256-gcm';
  private readonly saltRounds = 12;
  private readonly encryptionKey: Buffer;
  private readonly hmacKey: string;

  private constructor() {
    // Initialize encryption keys from environment variables
    if (!process.env.ENCRYPTION_KEY || !process.env.HMAC_KEY) {
      throw new Error('Encryption keys not configured');
    }

    this.encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    this.hmacKey = process.env.HMAC_KEY;

    // Validate key length
    if (this.encryptionKey.length !== 32) {
      throw new Error('Invalid encryption key length. Expected 32 bytes.');
    }
  }

  public static getInstance(): CryptoService {
    if (!CryptoService.instance) {
      CryptoService.instance = new CryptoService();
    }
    return CryptoService.instance;
  }

  /**
   * Hash a password using bcrypt
   */
  async hashPassword(password: string): Promise<string> {
    if (!password || password.length < 8) {
      throw new AppError('Password must be at least 8 characters long', 400);
    }

    const salt = await bcrypt.genSalt(this.saltRounds);
    return bcrypt.hash(password, salt);
  }

  /**
   * Verify a password against a hash
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  /**
   * Generate a secure random token
   */
  generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate a session token
   */
  generateSessionToken(): string {
    const timestamp = Date.now().toString();
    const random = this.generateToken(16);
    const data = `${timestamp}.${random}`;
    const signature = this.createHmac(data);
    return `${data}.${signature}`;
  }

  /**
   * Validate a session token
   */
  validateSessionToken(token: string): boolean {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return false;

      const [timestamp, random, signature] = parts;
      const data = `${timestamp}.${random}`;
      const expectedSignature = this.createHmac(data);

      // Validate signature
      if (!this.timingSafeEqual(signature, expectedSignature)) {
        return false;
      }

      // Check token age (max 24 hours)
      const tokenAge = Date.now() - parseInt(timestamp);
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours
      
      return tokenAge <= maxAge;
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate a cryptographic hash for vote data
   */
  generateVoteHash(voteData: VoteData): string {
    const dataString = JSON.stringify(voteData, Object.keys(voteData).sort());
    const hash = crypto.createHash('sha256');
    hash.update(dataString);
    hash.update(this.hmacKey);
    return hash.digest('hex');
  }

  /**
   * Encrypt vote data
   */
  encryptVote(voteData: VoteData): string {
    try {
      const dataString = JSON.stringify(voteData);
      
      // Generate IV
      const iv = crypto.randomBytes(16);
      
      // Create cipher
      const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv);
      
      // Encrypt data
      const encrypted = Buffer.concat([
        cipher.update(dataString, 'utf8'),
        cipher.final()
      ]);
      
      // Get auth tag
      const authTag = cipher.getAuthTag();
      
      // Combine IV + authTag + encrypted data
      const combined = Buffer.concat([iv, authTag, encrypted]);
      
      return combined.toString('base64');
    } catch (error) {
      throw new AppError('Failed to encrypt vote data', 500);
    }
  }

  /**
   * Decrypt vote data
   */
  decryptVote(encryptedData: string): VoteData {
    try {
      const combined = Buffer.from(encryptedData, 'base64');
      
      // Extract components
      const iv = combined.slice(0, 16);
      const authTag = combined.slice(16, 32);
      const encrypted = combined.slice(32);
      
      // Create decipher
      const decipher = crypto.createDecipheriv(this.algorithm, this.encryptionKey, iv);
      decipher.setAuthTag(authTag);
      
      // Decrypt data
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]);
      
      return JSON.parse(decrypted.toString('utf8'));
    } catch (error) {
      throw new AppError('Failed to decrypt vote data', 500);
    }
  }

  /**
   * Generate a receipt hash
   */
  generateReceiptHash(receiptData: ReceiptData): string {
    const dataString = JSON.stringify({
      sessionId: receiptData.sessionId,
      completedAt: receiptData.completedAt.toISOString(),
      voteHashes: receiptData.voteHashes.sort()
    });
    
    const hash = crypto.createHash('sha256');
    hash.update(dataString);
    hash.update(this.hmacKey);
    return hash.digest('hex');
  }

  /**
   * Generate device fingerprint
   */
  generateFingerprint(ipAddress: string, userAgent: string): string {
    const data = `${ipAddress}:${userAgent}`;
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex').substring(0, 16);
  }

  /**
   * Generate 2FA secret
   */
  generate2FASecret(userId: string, studentId: string): { secret: string; otpauth: string } {
    const secret = speakeasy.generateSecret({
      length: 32,
      name: `JKUAT Voting (${studentId})`,
      issuer: 'JKUAT Voting System'
    });

    return {
      secret: secret.base32,
      otpauth: secret.otpauth_url || ''
    };
  }

  /**
   * Generate QR code for 2FA
   */
  async generateQRCode(data: string): Promise<string> {
    try {
      return await QRCode.toDataURL(data, {
        errorCorrectionLevel: 'M',
        type: 'image/png',
        width: 256,
        margin: 1
      });
    } catch (error) {
      throw new AppError('Failed to generate QR code', 500);
    }
  }

  /**
   * Verify 2FA token
   */
  verify2FAToken(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2 // Allow 2 time steps for clock skew
    });
  }

  /**
   * Generate backup codes for 2FA
   */
  generateBackupCodes(count: number = 10): string[] {
    const codes = [];
    for (let i = 0; i < count; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
    }
    return codes;
  }

  /**
   * Hash backup code for storage
   */
  hashBackupCode(code: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(code.replace('-', '').toLowerCase());
    return hash.digest('hex');
  }

  /**
   * Create HMAC signature
   */
  private createHmac(data: string): string {
    const hmac = crypto.createHmac('sha256', this.hmacKey);
    hmac.update(data);
    return hmac.digest('hex');
  }

  /**
   * Timing safe comparison of strings
   */
  private timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    return crypto.timingSafeEqual(bufA, bufB);
  }

  /**
   * Generate a secure OTP
   */
  generateOTP(length: number = 6): string {
    const digits = '0123456789';
    let otp = '';
    
    for (let i = 0; i < length; i++) {
      const randomByte = crypto.randomBytes(1)[0];
      otp += digits[randomByte % 10];
    }
    
    return otp;
  }

  /**
   * Generate email verification token
   */
  generateEmailVerificationToken(userId: string): string {
    const timestamp = Date.now();
    const random = this.generateToken(16);
    const data = `${userId}.${timestamp}.${random}`;
    const signature = this.createHmac(data);
    return Buffer.from(`${data}.${signature}`).toString('base64url');
  }

  /**
   * Validate email verification token
   */
  validateEmailVerificationToken(token: string): { valid: boolean; userId?: string; expired?: boolean } {
    try {
      const decoded = Buffer.from(token, 'base64url').toString();
      const parts = decoded.split('.');
      
      if (parts.length !== 4) {
        return { valid: false };
      }

      const [userId, timestamp, random, signature] = parts;
      const data = `${userId}.${timestamp}.${random}`;
      const expectedSignature = this.createHmac(data);

      // Validate signature
      if (!this.timingSafeEqual(signature, expectedSignature)) {
        return { valid: false };
      }

      // Check token age (max 24 hours)
      const tokenAge = Date.now() - parseInt(timestamp);
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours
      
      if (tokenAge > maxAge) {
        return { valid: false, expired: true };
      }

      return { valid: true, userId };
    } catch (error) {
      return { valid: false };
    }
  }

  /**
   * Generate password reset token
   */
  generatePasswordResetToken(userId: string): string {
    const timestamp = Date.now();
    const random = this.generateToken(16);
    const data = `reset.${userId}.${timestamp}.${random}`;
    const signature = this.createHmac(data);
    return Buffer.from(`${data}.${signature}`).toString('base64url');
  }

  /**
   * Validate password reset token
   */
  validatePasswordResetToken(token: string): { valid: boolean; userId?: string; expired?: boolean } {
    try {
      const decoded = Buffer.from(token, 'base64url').toString();
      const parts = decoded.split('.');
      
      if (parts.length !== 5 || parts[0] !== 'reset') {
        return { valid: false };
      }

      const [_, userId, timestamp, random, signature] = parts;
      const data = `reset.${userId}.${timestamp}.${random}`;
      const expectedSignature = this.createHmac(data);

      // Validate signature
      if (!this.timingSafeEqual(signature, expectedSignature)) {
        return { valid: false };
      }

      // Check token age (max 1 hour)
      const tokenAge = Date.now() - parseInt(timestamp);
      const maxAge = 60 * 60 * 1000; // 1 hour
      
      if (tokenAge > maxAge) {
        return { valid: false, expired: true };
      }

      return { valid: true, userId };
    } catch (error) {
      return { valid: false };
    }
  }

  /**
   * Encrypt sensitive data for storage
   */
  encryptData(data: string): { encrypted: string; iv: string; authTag: string } {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  /**
   * Decrypt sensitive data
   */
  decryptData(encrypted: string, iv: string, authTag: string): string {
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      this.encryptionKey,
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Generate verification code for votes
   */
  generateVerificationCode(): string {
    // Generate a unique, human-readable code
    const prefix = 'JKV'; // JKUAT Voting
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(3).toString('hex').toUpperCase();
    return `${prefix}-${timestamp}-${random}`;
  }

  /**
   * Generate secure random string for various uses
   */
  generateSecureString(length: number = 32, charset?: string): string {
    const defaultCharset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const chars = charset || defaultCharset;
    let result = '';
    
    const randomBytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
      result += chars[randomBytes[i] % chars.length];
    }
    
    return result;
  }

  /**
   * Create a challenge for additional security verification
   */
  createChallenge(): { challenge: string; expires: Date } {
    const challenge = this.generateSecureString(64);
    const expires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    
    return { challenge, expires };
  }

  /**
   * Verify a challenge response
   */
  verifyChallenge(challenge: string, response: string, secret: string): boolean {
    const expected = this.createHmac(`${challenge}.${secret}`);
    return this.timingSafeEqual(response, expected);
  }
}