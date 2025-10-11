// backend/src/validators/voter.validator.ts

import { body, param, query } from 'express-validator';
import { UserRole } from '@prisma/client';

const STUDENT_ID_REGEX = /^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/;
const PHONE_REGEX = /^(\+254|0)[17]\d{8}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Voter Profile Update Validation
export const validateVoterProfileUpdate = [
  param('id')
    .isUUID()
    .withMessage('Invalid voter ID'),

  body('firstName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('First name can only contain letters, spaces, hyphens, and apostrophes')
    .customSanitizer(value => value?.trim()),

  body('lastName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Last name can only contain letters, spaces, hyphens, and apostrophes')
    .customSanitizer(value => value?.trim()),

  body('middleName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Middle name must not exceed 50 characters')
    .matches(/^[a-zA-Z\s'-]*$/)
    .withMessage('Middle name can only contain letters, spaces, hyphens, and apostrophes')
    .customSanitizer(value => value?.trim() || undefined),

  body('phone')
    .optional()
    .matches(PHONE_REGEX)
    .withMessage('Invalid phone number format. Use format: +254712345678 or 0712345678')
    .customSanitizer(value => {
      if (!value) return undefined;
      if (value.startsWith('0')) {
        return '+254' + value.substring(1);
      }
      return value;
    }),

  body('bio')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Bio must not exceed 500 characters')
    .customSanitizer(value => value?.trim()),

  body('profilePictureUrl')
    .optional()
    .isURL()
    .withMessage('Invalid profile picture URL'),
];

// Voter Status Update Validation (Admin only)
export const validateVoterStatusUpdate = [
  param('id')
    .isUUID()
    .withMessage('Invalid voter ID'),

  body('status')
    .isIn(['ACTIVE', 'SUSPENDED', 'INACTIVE', 'DELETED'])
    .withMessage('Invalid voter status'),

  body('reason')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Reason must not exceed 500 characters')
    .customSanitizer(value => value?.trim()),

  body('suspensionEndDate')
    .optional()
    .isISO8601()
    .withMessage('Suspension end date must be a valid ISO 8601 date')
    .custom((value) => {
      if (value) {
        const suspensionEndDate = new Date(value);
        const now = new Date();

        if (suspensionEndDate <= now) {
          throw new Error('Suspension end date must be in the future');
        }

        const maxSuspension = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year max
        if (suspensionEndDate > maxSuspension) {
          throw new Error('Suspension cannot exceed 1 year');
        }
      }
      return true;
    }),
];

// Voter Eligibility Check Validation
export const validateVoterEligibilityCheck = [
  param('id')
    .isUUID()
    .withMessage('Invalid voter ID'),

  query('electionId')
    .optional()
    .isUUID()
    .withMessage('Invalid election ID'),

  query('positionId')
    .optional()
    .isUUID()
    .withMessage('Invalid position ID'),
];

// Voter Search Validation
export const validateVoterSearch = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),

  query('search')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Search term must be between 2 and 100 characters')
    .customSanitizer(value => value?.trim()),

  query('faculty')
    .optional()
    .isIn([
      'School of Engineering',
      'School of Computing and Information Technology',
      'School of Agriculture and Food Sciences',
      'School of Business and Management Sciences',
      'School of Human Resource Development',
      'College of Health Sciences',
      'School of Architecture and Building Sciences',
      'School of Education'
    ])
    .withMessage('Invalid faculty'),

  query('department')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Department must be between 2 and 100 characters'),

  query('yearOfStudy')
    .optional()
    .isInt({ min: 1, max: 6 })
    .withMessage('Year of study must be between 1 and 6'),

  query('admissionYear')
    .optional()
    .isInt({ min: 2000, max: new Date().getFullYear() })
    .withMessage(`Admission year must be between 2000 and ${new Date().getFullYear()}`),

  query('status')
    .optional()
    .isIn(['ACTIVE', 'SUSPENDED', 'INACTIVE', 'DELETED'])
    .withMessage('Invalid user status'),

  query('role')
    .optional()
    .isIn(Object.values(UserRole))
    .withMessage('Invalid user role'),

  query('isVerified')
    .optional()
    .isBoolean()
    .withMessage('Is verified must be a boolean'),

  query('hasTwoFactorAuth')
    .optional()
    .isBoolean()
    .withMessage('Has two factor auth must be a boolean'),

  query('sortBy')
    .optional()
    .isIn(['name', 'studentId', 'email', 'createdAt', 'lastLoginAt'])
    .withMessage('Invalid sort field'),

  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be asc or desc'),
];

// Voter Bulk Operations Validation
export const validateVoterBulkOperation = [
  body('operation')
    .isIn(['activate', 'suspend', 'verify', 'delete', 'export'])
    .withMessage('Invalid bulk operation'),

  body('voterIds')
    .isArray({ min: 1, max: 1000 })
    .withMessage('Voter IDs must be an array with 1-1000 items'),

  body('voterIds.*')
    .isUUID()
    .withMessage('Each voter ID must be a valid UUID'),

  body('reason')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Reason must not exceed 500 characters'),

  body('suspensionEndDate')
    .if(body('operation').equals('suspend'))
    .isISO8601()
    .withMessage('Suspension end date is required for suspend operation')
    .custom((value) => {
      const suspensionEndDate = new Date(value);
      const now = new Date();

      if (suspensionEndDate <= now) {
        throw new Error('Suspension end date must be in the future');
      }

      const maxSuspension = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year max
      if (suspensionEndDate > maxSuspension) {
        throw new Error('Suspension cannot exceed 1 year');
      }

      return true;
    }),
];

// Voter Import Validation
export const validateVoterImport = [
  body('format')
    .isIn(['csv', 'xlsx'])
    .withMessage('Import format must be csv or xlsx'),

  body('overwriteExisting')
    .optional()
    .isBoolean()
    .withMessage('Overwrite existing must be a boolean'),

  body('sendWelcomeEmails')
    .optional()
    .isBoolean()
    .withMessage('Send welcome emails must be a boolean'),

  body('defaultPassword')
    .optional()
    .isLength({ min: 8, max: 128 })
    .withMessage('Default password must be between 8 and 128 characters'),
];

// Voter Export Validation
export const validateVoterExport = [
  query('format')
    .isIn(['csv', 'xlsx', 'pdf'])
    .withMessage('Export format must be csv, xlsx, or pdf'),

  query('includePersonalData')
    .optional()
    .isBoolean()
    .withMessage('Include personal data must be a boolean'),

  query('includeVotingHistory')
    .optional()
    .isBoolean()
    .withMessage('Include voting history must be a boolean'),

  query('includeStatistics')
    .optional()
    .isBoolean()
    .withMessage('Include statistics must be a boolean'),

  query('faculty')
    .optional()
    .isIn([
      'School of Engineering',
      'School of Computing and Information Technology',
      'School of Agriculture and Food Sciences',
      'School of Business and Management Sciences',
      'School of Human Resource Development',
      'College of Health Sciences',
      'School of Architecture and Building Sciences',
      'School of Education'
    ])
    .withMessage('Invalid faculty'),

  query('yearOfStudy')
    .optional()
    .isInt({ min: 1, max: 6 })
    .withMessage('Year of study must be between 1 and 6'),

  query('status')
    .optional()
    .isIn(['ACTIVE', 'SUSPENDED', 'INACTIVE', 'DELETED'])
    .withMessage('Invalid user status'),
];

// Voter Statistics Validation
export const validateVoterStatistics = [
  query('period')
    .optional()
    .isIn(['day', 'week', 'month', 'quarter', 'year', 'all'])
    .withMessage('Invalid period'),

  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),

  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date')
    .custom((value, { req }) => {
      if (value && req.query && req.query.startDate) {
        const endDate = new Date(value);
        const startDate = new Date(req.query.startDate as string);

        if (endDate <= startDate) {
          throw new Error('End date must be after start date');
        }
      }
      return true;
    }),

  query('groupBy')
    .optional()
    .isIn(['faculty', 'department', 'yearOfStudy', 'admissionYear', 'status'])
    .withMessage('Invalid group by field'),
];

// Voter Registration Validation
export const validateVoterRegistration = [
  body('studentId')
    .matches(STUDENT_ID_REGEX)
    .withMessage('Invalid student ID format. Expected format: ABC123-1234/2023')
    .customSanitizer(value => value?.toUpperCase()),

  body('email')
    .isEmail()
    .withMessage('Invalid email format')
    .matches(EMAIL_REGEX)
    .withMessage('Invalid email format')
    .customSanitizer(value => value?.toLowerCase()),

  body('firstName')
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('First name can only contain letters, spaces, hyphens, and apostrophes')
    .customSanitizer(value => value?.trim()),

  body('lastName')
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Last name can only contain letters, spaces, hyphens, and apostrophes')
    .customSanitizer(value => value?.trim()),

  body('middleName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Middle name must not exceed 50 characters')
    .matches(/^[a-zA-Z\s'-]*$/)
    .withMessage('Middle name can only contain letters, spaces, hyphens, and apostrophes')
    .customSanitizer(value => value?.trim() || undefined),

  body('phone')
    .optional()
    .matches(PHONE_REGEX)
    .withMessage('Invalid phone number format. Use format: +254712345678 or 0712345678')
    .customSanitizer(value => {
      if (!value) return undefined;
      if (value.startsWith('0')) {
        return '+254' + value.substring(1);
      }
      return value;
    }),

  body('faculty')
    .isIn([
      'School of Engineering',
      'School of Computing and Information Technology',
      'School of Agriculture and Food Sciences',
      'School of Business and Management Sciences',
      'School of Human Resource Development',
      'College of Health Sciences',
      'School of Architecture and Building Sciences',
      'School of Education'
    ])
    .withMessage('Invalid faculty'),

  body('department')
    .isLength({ min: 2, max: 100 })
    .withMessage('Department must be between 2 and 100 characters')
    .customSanitizer(value => value?.trim()),

  body('course')
    .isLength({ min: 2, max: 100 })
    .withMessage('Course must be between 2 and 100 characters')
    .customSanitizer(value => value?.trim()),

  body('yearOfStudy')
    .isInt({ min: 1, max: 6 })
    .withMessage('Year of study must be between 1 and 6'),

  body('admissionYear')
    .isInt({ min: 2000, max: new Date().getFullYear() })
    .withMessage(`Admission year must be between 2000 and ${new Date().getFullYear()}`),

  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character'),

  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    }),
];

// Email Verification Validation
export const validateEmailVerification = [
  param('token')
    .isLength({ min: 32, max: 64 })
    .withMessage('Invalid verification token format')
    .isAlphanumeric()
    .withMessage('Verification token must be alphanumeric'),
];

// Resend Verification Validation
export const validateResendVerification = [
  // No additional validation needed as it uses authenticated user ID
];

// Preferences Update Validation
export const validatePreferencesUpdate = [
  body('emailNotifications')
    .optional()
    .isBoolean()
    .withMessage('Email notifications must be a boolean'),

  body('smsNotifications')
    .optional()
    .isBoolean()
    .withMessage('SMS notifications must be a boolean'),

  body('pushNotifications')
    .optional()
    .isBoolean()
    .withMessage('Push notifications must be a boolean'),

  body('reminderFrequency')
    .optional()
    .isIn(['never', 'daily', 'weekly', 'election_only'])
    .withMessage('Invalid reminder frequency'),

  body('language')
    .optional()
    .isIn(['en', 'sw'])
    .withMessage('Language must be en or sw'),

  body('theme')
    .optional()
    .isIn(['light', 'dark', 'system'])
    .withMessage('Theme must be light, dark, or system'),

  body('accessibility.highContrast')
    .optional()
    .isBoolean()
    .withMessage('High contrast must be a boolean'),

  body('accessibility.largeText')
    .optional()
    .isBoolean()
    .withMessage('Large text must be a boolean'),

  body('accessibility.screenReader')
    .optional()
    .isBoolean()
    .withMessage('Screen reader must be a boolean'),
];

// Voter ID Validation
export const validateVoterId = [
  param('id')
    .isUUID()
    .withMessage('Invalid voter ID format'),
];

// Delete Voter Validation
export const validateDeleteVoter = [
  param('id')
    .isUUID()
    .withMessage('Invalid voter ID format'),

  body('reason')
    .isLength({ min: 10, max: 500 })
    .withMessage('Deletion reason must be between 10 and 500 characters')
    .customSanitizer(value => value?.trim()),

  body('hardDelete')
    .optional()
    .isBoolean()
    .withMessage('Hard delete must be a boolean'),
];

// Analytics Report Validation
export const validateAnalyticsReport = [
  query('reportType')
    .optional()
    .isIn(['comprehensive', 'summary', 'demographic', 'participation', 'trends'])
    .withMessage('Invalid report type'),

  query('period')
    .optional()
    .isIn(['last_7_days', 'last_30_days', 'last_90_days', 'last_year', 'custom'])
    .withMessage('Invalid period'),

  query('includeCharts')
    .optional()
    .isBoolean()
    .withMessage('Include charts must be a boolean'),

  query('format')
    .optional()
    .isIn(['pdf', 'xlsx', 'json'])
    .withMessage('Format must be pdf, xlsx, or json'),

  query('startDate')
    .if(query('period').equals('custom'))
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),

  query('endDate')
    .if(query('period').equals('custom'))
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date')
    .custom((value, { req }) => {
      if (value && req.query && req.query.startDate) {
        const endDate = new Date(value);
        const startDate = new Date(req.query.startDate as string);

        if (endDate <= startDate) {
          throw new Error('End date must be after start date');
        }

        const maxPeriod = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year max
        if (endDate > maxPeriod) {
          throw new Error('Date range cannot exceed 1 year');
        }
      }
      return true;
    }),
];

export default {
  validateVoterProfileUpdate,
  validateVoterStatusUpdate,
  validateVoterEligibilityCheck,
  validateVoterSearch,
  validateVoterBulkOperation,
  validateVoterImport,
  validateVoterExport,
  validateVoterStatistics,
  validateVoterRegistration,
  validateEmailVerification,
  validateResendVerification,
  validatePreferencesUpdate,
  validateVoterId,
  validateDeleteVoter,
  validateAnalyticsReport,
};