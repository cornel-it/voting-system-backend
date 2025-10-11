import { Request } from 'express';
import { ValidationError } from 'joi';

/**
 * Format validation errors for response
 */
export const formatValidationErrors = (error: ValidationError) => {
  return error.details.map((detail) => ({
    field: detail.path.join('.'),
    message: detail.message.replace(/"/g, ''),
  }));
};

/**
 * Paginate query results
 */
export interface PaginationOptions {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface PaginatedResult<T> {
  data: T[];
  pagination: {
    currentPage: number;
    totalPages: number;
    totalItems: number;
    itemsPerPage: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
}

export const paginate = <T>(
  data: T[],
  totalItems: number,
  options: PaginationOptions
): PaginatedResult<T> => {
  const page = Math.max(1, options.page || 1);
  const limit = Math.min(100, Math.max(1, options.limit || 10));
  const totalPages = Math.ceil(totalItems / limit);

  return {
    data,
    pagination: {
      currentPage: page,
      totalPages,
      totalItems,
      itemsPerPage: limit,
      hasNext: page < totalPages,
      hasPrevious: page > 1,
    },
  };
};

/**
 * Get client IP address
 */
export const getClientIp = (req: Request): string => {
  const forwarded = req.headers['x-forwarded-for'] as string;
  const ip = forwarded
    ? forwarded.split(',')[0].trim()
    : req.socket.remoteAddress || 'unknown';
  
  // Remove IPv6 prefix if present
  return ip.replace('::ffff:', '');
};

/**
 * Get user agent from request
 */
export const getUserAgent = (req: Request): string => {
  return req.headers['user-agent'] || 'unknown';
};

/**
 * Generate random string
 */
export const generateRandomString = (
  length: number,
  charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
): string => {
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return result;
};

/**
 * Sleep utility for delays
 */
export const sleep = (ms: number): Promise<void> => {
  return new Promise((resolve) => setTimeout(resolve, ms));
};

/**
 * Retry function with exponential backoff
 */
export const retryWithBackoff = async <T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  initialDelay: number = 1000
): Promise<T> => {
  let lastError: Error;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (i < maxRetries - 1) {
        const delay = initialDelay * Math.pow(2, i);
        await sleep(delay);
      }
    }
  }
  
  throw lastError!;
};

/**
 * Sanitize user input
 */
export const sanitizeInput = (input: string): string => {
  return input
    .trim()
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .replace(/on\w+="[^"]*"/gi, '')
    .replace(/on\w+='[^']*'/gi, '');
};

/**
 * Validate email format
 */
export const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate JKUAT student ID
 */
export const isValidStudentId = (studentId: string): boolean => {
  // JKUAT student ID format: e.g., SCT211-0001/2020
  const studentIdRegex = /^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/;
  return studentIdRegex.test(studentId);
};

/**
 * Format date for display
 */
export const formatDate = (date: Date | string): string => {
  const d = new Date(date);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

/**
 * Calculate percentage
 */
export const calculatePercentage = (
  value: number,
  total: number,
  decimals: number = 2
): number => {
  if (total === 0) return 0;
  return Number(((value / total) * 100).toFixed(decimals));
};

/**
 * Group array by key
 */
export const groupBy = <T>(
  array: T[],
  key: keyof T
): Record<string, T[]> => {
  return array.reduce((result, item) => {
    const group = String(item[key]);
    if (!result[group]) {
      result[group] = [];
    }
    result[group].push(item);
    return result;
  }, {} as Record<string, T[]>);
};

/**
 * Remove duplicate objects from array
 */
export const removeDuplicates = <T>(
  array: T[],
  key: keyof T
): T[] => {
  const seen = new Set();
  return array.filter((item) => {
    const value = item[key];
    if (seen.has(value)) {
      return false;
    }
    seen.add(value);
    return true;
  });
};

/**
 * Check if time is within range
 */
export const isWithinTimeRange = (
  startTime: Date,
  endTime: Date,
  currentTime: Date = new Date()
): boolean => {
  return currentTime >= startTime && currentTime <= endTime;
};

/**
 * Format file size
 */
export const formatFileSize = (bytes: number): string => {
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  if (bytes === 0) return '0 Bytes';
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
};

/**
 * Validate file type
 */
export const isAllowedFileType = (
  mimeType: string,
  allowedTypes: string[]
): boolean => {
  return allowedTypes.includes(mimeType);
};

/**
 * Generate slug from string
 */
export const generateSlug = (text: string): string => {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
};

/**
 * Parse boolean from string
 */
export const parseBoolean = (value: string | boolean | undefined): boolean => {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    return value.toLowerCase() === 'true' || value === '1';
  }
  return false;
};

/**
 * Deep clone object
 */
export const deepClone = <T>(obj: T): T => {
  return JSON.parse(JSON.stringify(obj));
};

/**
 * Mask sensitive data
 */
export const maskData = (data: string, visibleChars: number = 4): string => {
  if (data.length <= visibleChars * 2) {
    return '*'.repeat(data.length);
  }
  const start = data.slice(0, visibleChars);
  const end = data.slice(-visibleChars);
  const masked = '*'.repeat(data.length - visibleChars * 2);
  return `${start}${masked}${end}`;
};

/**
 * Calculate age from date of birth
 */
export const calculateAge = (dateOfBirth: Date): number => {
  const today = new Date();
  const birthDate = new Date(dateOfBirth);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  
  return age;
};

/**
 * Check if user is eligible based on criteria
 */
export const checkEligibility = (
  user: any,
  criteria: {
    faculties?: string[];
    departments?: string[];
    courses?: string[];
    years?: number[];
    minAge?: number;
    maxAge?: number;
  }
): boolean => {
  if (criteria.faculties && !criteria.faculties.includes(user.faculty)) {
    return false;
  }
  
  if (criteria.departments && !criteria.departments.includes(user.department)) {
    return false;
  }
  
  if (criteria.courses && !criteria.courses.includes(user.course)) {
    return false;
  }
  
  if (criteria.years && !criteria.years.includes(user.yearOfStudy)) {
    return false;
  }
  
  if (criteria.minAge || criteria.maxAge) {
    const age = calculateAge(user.dateOfBirth);
    if (criteria.minAge && age < criteria.minAge) return false;
    if (criteria.maxAge && age > criteria.maxAge) return false;
  }
  
  return true;
};

/**
 * Generate a unique ID
 */
export const generateUniqueId = (prefix?: string): string => {
  const timestamp = Date.now().toString(36);
  const random = generateRandomString(8);
  return prefix ? `${prefix}_${timestamp}_${random}` : `${timestamp}_${random}`;
};

/**
 * Generate a verification code for voting
 */
export const generateVerificationCode = (length: number = 12): string => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = 'JKV'; // JKUAT Voting prefix
  
  for (let i = 3; i < length; i++) {
    if (i === 6) {
      code += '-'; // Add separator
    } else {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
  }
  
  return code;
};

export default {
  formatValidationErrors,
  paginate,
  getClientIp,
  getUserAgent,
  generateRandomString,
  sleep,
  retryWithBackoff,
  sanitizeInput,
  isValidEmail,
  isValidStudentId,
  formatDate,
  calculatePercentage,
  groupBy,
  removeDuplicates,
  isWithinTimeRange,
  formatFileSize,
  isAllowedFileType,
  generateSlug,
  parseBoolean,
  deepClone,
  maskData,
  calculateAge,
  checkEligibility,
  generateUniqueId,
  generateVerificationCode,
};