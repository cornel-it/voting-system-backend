import { User, UserRole, TokenType } from '@prisma/client';

// User Registration Types
export interface RegisterUserRequest {
  studentId: string;
  email: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  password: string;
  confirmPassword: string;
  phone?: string;
  faculty: string;
  department: string;
  course: string;
  yearOfStudy: number;
  admissionYear: number;
}

// Permission Types
export const PERMISSIONS = {
  // User Management
  USER_CREATE: 'user:create',
  USER_READ: 'user:read',
  USER_UPDATE: 'user:update',
  USER_DELETE: 'user:delete',
  USER_MANAGE_ROLES: 'user:manage_roles',

  // Election Management
  ELECTION_CREATE: 'election:create',
  ELECTION_READ: 'election:read',
  ELECTION_UPDATE: 'election:update',
  ELECTION_DELETE: 'election:delete',
  ELECTION_PUBLISH: 'election:publish',
  ELECTION_ARCHIVE: 'election:archive',

  // Voting Management
  VOTE_READ: 'vote:read',
  VOTE_VERIFY: 'vote:verify',
  VOTE_AUDIT: 'vote:audit',

  // Candidate Management
  CANDIDATE_APPROVE: 'candidate:approve',
  CANDIDATE_REJECT: 'candidate:reject',
  CANDIDATE_DISQUALIFY: 'candidate:disqualify',

  // Results Management
  RESULT_READ: 'result:read',
  RESULT_PUBLISH: 'result:publish',
  RESULT_EXPORT: 'result:export',

  // System Administration
  SYSTEM_CONFIG: 'system:config',
  SYSTEM_BACKUP: 'system:backup',
  SYSTEM_MONITOR: 'system:monitor',
  SYSTEM_AUDIT: 'system:audit',

  // Reports and Analytics
  REPORT_GENERATE: 'report:generate',
  ANALYTICS_VIEW: 'analytics:view',
  ANALYTICS_EXPORT: 'analytics:export',
} as const;

export type Permission = typeof PERMISSIONS[keyof typeof PERMISSIONS];

// Role-based permission mapping
export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  SUPER_ADMIN: Object.values(PERMISSIONS),
  ADMIN: [
    PERMISSIONS.USER_READ,
    PERMISSIONS.USER_UPDATE,
    PERMISSIONS.USER_MANAGE_ROLES,
    PERMISSIONS.ELECTION_CREATE,
    PERMISSIONS.ELECTION_READ,
    PERMISSIONS.ELECTION_UPDATE,
    PERMISSIONS.ELECTION_PUBLISH,
    PERMISSIONS.ELECTION_ARCHIVE,
    PERMISSIONS.VOTE_READ,
    PERMISSIONS.VOTE_VERIFY,
    PERMISSIONS.VOTE_AUDIT,
    PERMISSIONS.CANDIDATE_APPROVE,
    PERMISSIONS.CANDIDATE_REJECT,
    PERMISSIONS.CANDIDATE_DISQUALIFY,
    PERMISSIONS.RESULT_READ,
    PERMISSIONS.RESULT_PUBLISH,
    PERMISSIONS.RESULT_EXPORT,
    PERMISSIONS.REPORT_GENERATE,
    PERMISSIONS.ANALYTICS_VIEW,
    PERMISSIONS.ANALYTICS_EXPORT,
  ],
  MODERATOR: [
    PERMISSIONS.USER_READ,
    PERMISSIONS.ELECTION_READ,
    PERMISSIONS.VOTE_READ,
    PERMISSIONS.CANDIDATE_APPROVE,
    PERMISSIONS.CANDIDATE_REJECT,
    PERMISSIONS.RESULT_READ,
    PERMISSIONS.REPORT_GENERATE,
    PERMISSIONS.ANALYTICS_VIEW,
  ],
  VOTER: [
    PERMISSIONS.ELECTION_READ,
    PERMISSIONS.RESULT_READ,
  ],
};

export interface RegisterUserResponse {
  user: SafeUser;
  tokens: TokenPair;
  emailVerificationSent: boolean;
}

// Login Types
export interface LoginRequest {
  identifier: string; // email or studentId
  password: string;
  deviceInfo?: DeviceInfo;
  twoFactorCode?: string;
}

export interface LoginResponse {
  user: SafeUser;
  tokens: TokenPair;
  requiresTwoFactor: boolean;
  sessionId: string;
}

// Password Reset Types
export interface PasswordResetRequest {
  email: string;
}

export interface PasswordResetConfirm {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

export interface PasswordResetResponse {
  message: string;
  success: boolean;
}

// Email Verification Types
export interface EmailVerificationRequest {
  token: string;
  userId?: string;
}

export interface EmailVerificationResponse {
  message: string;
  success: boolean;
}

export interface ResendVerificationRequest {
  email: string;
}

// Two-Factor Authentication Types
export interface TwoFactorSetupResponse {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

export interface TwoFactorVerificationRequest {
  userId: string;
  token: string;
  type: 'setup' | 'login' | 'disable';
}

export interface TwoFactorVerificationResponse {
  success: boolean;
  message: string;
  backupCodes?: string[];
}

// Token Types
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

export interface RefreshTokenRequest {
  refreshToken: string;
  deviceInfo?: DeviceInfo;
}

// Session Types
export interface SessionInfo {
  sessionId: string;
  userId: string;
  deviceInfo: DeviceInfo;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  isActive: boolean;
}

export interface DeviceInfo {
  userAgent: string;
  ipAddress: string;
  deviceFingerprint?: string;
  platform?: string;
  browser?: string;
  location?: string;
}

// Logout Types
export interface LogoutRequest {
  refreshToken?: string;
  logoutAll?: boolean;
}

export interface LogoutResponse {
  message: string;
  success: boolean;
}

// Safe User Type (without sensitive data)
export interface SafeUser {
  id: string;
  studentId: string;
  email: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  phone?: string;
  profileImage?: string;
  faculty: string;
  department: string;
  course: string;
  yearOfStudy: number;
  admissionYear: number;
  role: UserRole;
  permissions: string[];
  isActive: boolean;
  isVerified: boolean;
  emailVerified?: Date;
  phoneVerified?: Date;
  twoFactorEnabled: boolean;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// Account Status Types
export interface AccountStatusResponse {
  isLocked: boolean;
  lockReason?: string;
  lockedUntil?: Date;
  loginAttempts: number;
  maxLoginAttempts: number;
  requiresVerification: boolean;
  verificationTypes: ('email' | 'phone')[];
}

// Security Types
export interface SecurityEventType {
  LOGIN_SUCCESS: 'login_success';
  LOGIN_FAILURE: 'login_failure';
  PASSWORD_CHANGE: 'password_change';
  PASSWORD_RESET: 'password_reset';
  TWO_FACTOR_ENABLED: 'two_factor_enabled';
  TWO_FACTOR_DISABLED: 'two_factor_disabled';
  ACCOUNT_LOCKED: 'account_locked';
  ACCOUNT_UNLOCKED: 'account_unlocked';
  SUSPICIOUS_ACTIVITY: 'suspicious_activity';
  TOKEN_REFRESH: 'token_refresh';
  LOGOUT: 'logout';
}

export interface SecurityEvent {
  type: keyof SecurityEventType;
  userId: string;
  deviceInfo: DeviceInfo;
  metadata?: Record<string, any>;
  timestamp: Date;
}

// Rate Limiting Types
export interface RateLimitInfo {
  key: string;
  windowStart: Date;
  windowEnd: Date;
  requests: number;
  limit: number;
  remaining: number;
  resetTime: Date;
}

// Verification Token Types
export interface VerificationTokenInfo {
  id: string;
  token: string;
  userId: string;
  type: TokenType;
  expiresAt: Date;
  used: boolean;
  usedAt?: Date;
}

// Auth Service Options
export interface AuthServiceOptions {
  enableTwoFactor?: boolean;
  enableDeviceTracking?: boolean;
  enableRateLimit?: boolean;
  maxLoginAttempts?: number;
  lockoutDuration?: number;
  sessionTimeout?: number;
  tokenRefreshThreshold?: number;
}

// JWT Payload (extended from jwt utils)
export interface ExtendedJWTPayload {
  userId: string;
  email: string;
  role: UserRole;
  sessionId: string;
  deviceFingerprint?: string;
  permissions?: string[];
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

// Account Recovery Types
export interface AccountRecoveryRequest {
  identifier: string; // email or studentId
  method: 'email' | 'phone' | 'security_questions';
}

export interface AccountRecoveryResponse {
  success: boolean;
  message: string;
  method: string;
  nextStep?: string;
}

// Batch Operations Types
export interface BatchUserUpdate {
  userIds: string[];
  updates: Partial<Pick<User, 'isActive' | 'role' | 'permissions'>>;
  reason?: string;
}

export interface BatchUpdateResponse {
  success: number;
  failed: number;
  errors: Array<{
    userId: string;
    error: string;
  }>;
}

// Admin Types
export interface UserManagementRequest {
  action: 'activate' | 'deactivate' | 'lock' | 'unlock' | 'reset_password' | 'force_logout';
  userId: string;
  reason?: string;
  metadata?: Record<string, any>;
}

export interface UserManagementResponse {
  success: boolean;
  message: string;
  user?: SafeUser;
}

// Audit Types
export interface AuthAuditLog {
  userId?: string;
  action: string;
  category: 'AUTH' | 'SECURITY';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  metadata: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
}