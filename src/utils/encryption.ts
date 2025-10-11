import crypto from 'crypto';
import { logger } from './logger';

const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 32;
const TAG_LENGTH = 16;
const IV_LENGTH = 16;
const ITERATIONS = 100000;

export class EncryptionService {
  private static instance: EncryptionService;
  private encryptionKey: Buffer;
  private voteEncryptionKey: Buffer;

  private constructor() {
    // Initialize encryption keys from environment
    const key = process.env.ENCRYPTION_KEY || 'default-32-char-encryption-key!!';
    const voteKey = process.env.VOTE_ENCRYPTION_KEY || 'default-vote-encryption-key-32ch';

    if (!key || key.length !== 32) {
      logger.warn('ENCRYPTION_KEY must be exactly 32 characters, using default');
    }

    if (!voteKey || voteKey.length !== 32) {
      logger.warn('VOTE_ENCRYPTION_KEY must be exactly 32 characters, using default');
    }

    this.encryptionKey = Buffer.from(key.padEnd(32, '!').slice(0, 32));
    this.voteEncryptionKey = Buffer.from(voteKey.padEnd(32, '!').slice(0, 32));
  }

  public static getInstance(): EncryptionService {
    if (!EncryptionService.instance) {
      EncryptionService.instance = new EncryptionService();
    }
    return EncryptionService.instance;
  }

  /**
   * Encrypt sensitive data
   */
  public encrypt(text: string, useVoteKey: boolean = false): string {
    try {
      const key = useVoteKey ? this.voteEncryptionKey : this.encryptionKey;
      const iv = crypto.randomBytes(IV_LENGTH);
      const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag();

      // Combine iv, authTag, and encrypted data
      const combined = Buffer.concat([
        iv,
        authTag,
        Buffer.from(encrypted, 'hex')
      ]);

      return combined.toString('base64');
    } catch (error) {
      logger.error('Encryption failed:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypt sensitive data
   */
  public decrypt(encryptedData: string, useVoteKey: boolean = false): string {
    try {
      const key = useVoteKey ? this.voteEncryptionKey : this.encryptionKey;
      const combined = Buffer.from(encryptedData, 'base64');

      // Extract components
      const iv = combined.slice(0, IV_LENGTH);
      const authTag = combined.slice(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
      const encrypted = combined.slice(IV_LENGTH + TAG_LENGTH);

      const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encrypted, undefined, 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      logger.error('Decryption failed:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  /**
   * Generate a secure random token
   */
  public generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate a secure verification code
   */
  public generateVerificationCode(length: number = 6): string {
    const chars = '0123456789';
    let code = '';
    const randomBytes = crypto.randomBytes(length);
    
    for (let i = 0; i < length; i++) {
      code += chars[randomBytes[i] % chars.length];
    }
    
    return code;
  }

  /**
   * Generate a unique vote hash
   */
  public generateVoteHash(
    electionId: string,
    voterId: string,
    candidateId: string,
    timestamp: Date
  ): string {
    const data = `${electionId}-${voterId}-${candidateId}-${timestamp.toISOString()}`;
    return crypto
      .createHash('sha256')
      .update(data)
      .update(crypto.randomBytes(16))
      .digest('hex');
  }

  /**
   * Encrypt vote data for storage
   */
  public encryptVote(voteData: any): {
    encryptedData: string;
    verificationHash: string;
  } {
    const jsonData = JSON.stringify(voteData);
    const encryptedData = this.encrypt(jsonData, true);
    const verificationHash = crypto
      .createHash('sha256')
      .update(jsonData)
      .digest('hex');

    return { encryptedData, verificationHash };
  }

  /**
   * Decrypt vote data
   */
  public decryptVote(encryptedData: string): any {
    const jsonData = this.decrypt(encryptedData, true);
    return JSON.parse(jsonData);
  }

  /**
   * Verify vote integrity
   */
  public verifyVoteIntegrity(
    encryptedData: string,
    verificationHash: string
  ): boolean {
    try {
      const decryptedData = this.decrypt(encryptedData, true);
      const computedHash = crypto
        .createHash('sha256')
        .update(decryptedData)
        .digest('hex');

      return computedHash === verificationHash;
    } catch (error) {
      logger.error('Vote integrity verification failed:', error);
      return false;
    }
  }

  /**
   * Generate secure session token
   */
  public generateSessionToken(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  /**
   * Hash sensitive data (one-way)
   */
  public hashData(data: string): string {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Compare hashed data
   */
  public compareHash(data: string, hash: string): boolean {
    const dataHash = this.hashData(data);
    return crypto.timingSafeEqual(
      Buffer.from(dataHash),
      Buffer.from(hash)
    );
  }

  /**
   * Generate device fingerprint
   */
  public generateDeviceFingerprint(
    userAgent: string,
    ipAddress: string,
    additionalData?: string
  ): string {
    const data = `${userAgent}-${ipAddress}-${additionalData || ''}`;
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Encrypt sensitive user data
   */
  public encryptUserData(data: Record<string, any>): string {
    const jsonData = JSON.stringify(data);
    return this.encrypt(jsonData);
  }

  /**
   * Decrypt sensitive user data
   */
  public decryptUserData(encryptedData: string): Record<string, any> {
    const jsonData = this.decrypt(encryptedData);
    return JSON.parse(jsonData);
  }

  /**
   * Generate QR code data for 2FA
   */
  public generate2FASecret(): {
    secret: string;
    qrCode: string;
  } {
    const secret = this.generateToken(20);
    const appName = process.env.TWO_FACTOR_APP_NAME || 'JKUAT Voting';
    const qrCode = `otpauth://totp/${appName}?secret=${secret}`;

    return { secret, qrCode };
  }

  /**
   * Mask sensitive data for logging
   */
  public maskSensitiveData(data: string, visibleChars: number = 4): string {
    if (data.length <= visibleChars * 2) {
      return '*'.repeat(data.length);
    }

    const start = data.slice(0, visibleChars);
    const end = data.slice(-visibleChars);
    const masked = '*'.repeat(Math.max(0, data.length - visibleChars * 2));

    return `${start}${masked}${end}`;
  }
}

// Export singleton instance
export const encryptionService = EncryptionService.getInstance();

// Export default
export default encryptionService;