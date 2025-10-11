import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { logger } from './logger';

const SALT_ROUNDS = 12;

export class HashingService {
  /**
   * Hash a password using bcrypt
   */
  public static async hashPassword(password: string): Promise<string> {
    try {
      const salt = await bcrypt.genSalt(SALT_ROUNDS);
      return await bcrypt.hash(password, salt);
    } catch (error) {
      logger.error('Password hashing failed:', error);
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Compare password with hash
   */
  public static async comparePassword(
    password: string,
    hash: string
  ): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error('Password comparison failed:', error);
      return false;
    }
  }

  /**
   * Generate a random salt
   */
  public static generateSalt(length: number = 16): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Hash data with SHA256
   */
  public static hashSHA256(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Hash data with SHA512
   */
  public static hashSHA512(data: string): string {
    return crypto.createHash('sha512').update(data).digest('hex');
  }

  /**
   * Generate HMAC
   */
  public static generateHMAC(data: string, secret: string): string {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
  }

  /**
   * Verify HMAC
   */
  public static verifyHMAC(
    data: string,
    hmac: string,
    secret: string
  ): boolean {
    const computedHmac = this.generateHMAC(data, secret);
    return crypto.timingSafeEqual(
      Buffer.from(computedHmac),
      Buffer.from(hmac)
    );
  }

  /**
   * Generate a secure random string
   */
  public static generateRandomString(length: number = 32): string {
    return crypto.randomBytes(length).toString('base64url');
  }

  /**
   * Generate UUID v4
   */
  public static generateUUID(): string {
    return crypto.randomUUID();
  }

  /**
   * Hash email for anonymization
   */
  public static hashEmail(email: string): string {
    const normalized = email.toLowerCase().trim();
    return this.hashSHA256(normalized);
  }

  /**
   * Generate a fingerprint from multiple data points
   */
  public static generateFingerprint(...data: string[]): string {
    const combined = data.join('-');
    return this.hashSHA256(combined);
  }

  /**
   * Create a time-based token
   */
  public static createTimeBasedToken(
    data: string,
    expirationMinutes: number = 60
  ): string {
    const expiration = Date.now() + expirationMinutes * 60 * 1000;
    const token = `${data}.${expiration}`;
    const signature = this.hashSHA256(token + process.env.JWT_SECRET);
    return Buffer.from(`${token}.${signature}`).toString('base64');
  }

  /**
   * Verify a time-based token
   */
  public static verifyTimeBasedToken(token: string): {
    valid: boolean;
    data?: string;
    expired?: boolean;
  } {
    try {
      const decoded = Buffer.from(token, 'base64').toString();
      const parts = decoded.split('.');
      
      if (parts.length !== 3) {
        return { valid: false };
      }

      const [data, expiration, signature] = parts;
      const expectedSignature = this.hashSHA256(
        `${data}.${expiration}` + process.env.JWT_SECRET
      );

      if (signature !== expectedSignature) {
        return { valid: false };
      }

      const expirationTime = parseInt(expiration, 10);
      if (Date.now() > expirationTime) {
        return { valid: false, expired: true };
      }

      return { valid: true, data };
    } catch (error) {
      logger.error('Token verification failed:', error);
      return { valid: false };
    }
  }

  /**
   * Generate a secure OTP
   */
  public static generateOTP(length: number = 6): string {
    const digits = '0123456789';
    let otp = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, digits.length);
      otp += digits[randomIndex];
    }
    
    return otp;
  }

  /**
   * Hash and salt sensitive data
   */
  public static async hashWithSalt(data: string): Promise<{
    hash: string;
    salt: string;
  }> {
    const salt = this.generateSalt();
    const hash = crypto
      .pbkdf2Sync(data, salt, 100000, 64, 'sha512')
      .toString('hex');
    
    return { hash, salt };
  }

  /**
   * Verify hashed and salted data
   */
  public static verifyHashWithSalt(
    data: string,
    hash: string,
    salt: string
  ): boolean {
    const computedHash = crypto
      .pbkdf2Sync(data, salt, 100000, 64, 'sha512')
      .toString('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(computedHash),
      Buffer.from(hash)
    );
  }
}

// Export as default
export default HashingService;