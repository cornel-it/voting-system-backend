// backend/src/validators/auth.validator.ts

import { body, param, query } from 'express-validator';
import { UserRole } from '@prisma/client';

// JKUAT student ID format: ABC123-1234/2023
const STUDENT_ID_REGEX = /^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/;
const PHONE_REGEX = /^(\+254|0)[17]\d{8}$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// User Registration Validation
export const validateRegister = [
  body('studentId')
    .notEmpty()
    .withMessage('Student ID is required')
    .matches(STUDENT_ID_REGEX)
    .withMessage('Invalid student ID format. Expected format: ABC123-1234/2023')
    .customSanitizer(value => value?.toUpperCase().trim()),

  body('email')
    .isEmail()
    .withMessage('Valid email is required')
    .normalizeEmail()
    .custom(async (email) => {
      const allowedDomains = [
        'students.jkuat.ac.ke',
        'jkuat.ac.ke',
        'gmail.com',
        'yahoo.com',
        'outlook.com',
        'hotmail.com'
      ];

      const domain = email.split('@')[1];
      if (process.env.ENFORCE_JKUAT_EMAIL === 'true' && !['students.jkuat.ac.ke', 'jkuat.ac.ke'].includes(domain)) {
        throw new Error('Please use your JKUAT institutional email address');
      }

      if (!allowedDomains.includes(domain)) {
        throw new Error('Email domain not allowed');
      }

      return true;
    }),

  body('firstName')
    .notEmpty()
    .withMessage('First name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('First name can only contain letters, spaces, hyphens, and apostrophes')
    .customSanitizer(value => value?.trim()),

  body('lastName')
    .notEmpty()
    .withMessage('Last name is required')
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
      // Normalize to +254 format
      if (value.startsWith('0')) {
        return '+254' + value.substring(1);
      }
      return value;
    }),

  body('faculty')
    .notEmpty()
    .withMessage('Faculty is required')
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
    .withMessage('Invalid faculty selected'),

  body('department')
    .notEmpty()
    .withMessage('Department is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Department must be between 2 and 100 characters'),

  body('course')
    .notEmpty()
    .withMessage('Course is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Course must be between 2 and 100 characters'),

  body('yearOfStudy')
    .isInt({ min: 1, max: 6 })
    .withMessage('Year of study must be between 1 and 6'),

  body('admissionYear')
    .isInt({ min: 2000, max: new Date().getFullYear() })
    .withMessage(`Admission year must be between 2000 and ${new Date().getFullYear()}`),

  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(PASSWORD_REGEX)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),

  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    }),
];

// User Login Validation
export const validateLogin = [
  body('identifier')
    .notEmpty()
    .withMessage('Email or Student ID is required')
    .customSanitizer(value => value?.trim()),

  body('password')
    .notEmpty()
    .withMessage('Password is required'),

  body('twoFactorCode')
    .optional()
    .isLength({ min: 6, max: 6 })
    .withMessage('Two-factor code must be 6 digits')
    .isNumeric()
    .withMessage('Two-factor code must be numeric'),

  body('rememberMe')
    .optional()
    .isBoolean()
    .withMessage('Remember me must be a boolean'),
];

// Password Reset Request Validation
export const validatePasswordResetRequest = [
  body('email')
    .isEmail()
    .withMessage('Valid email is required')
    .normalizeEmail(),
];

// Password Reset Confirm Validation
export const validatePasswordResetConfirm = [
  body('token')
    .notEmpty()
    .withMessage('Reset token is required')
    .isLength({ min: 32, max: 128 })
    .withMessage('Invalid reset token format'),

  body('newPassword')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(PASSWORD_REGEX)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),

  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match new password');
      }
      return true;
    }),
];

// Password Change Validation
export const validatePasswordChange = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),

  body('newPassword')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(PASSWORD_REGEX)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character')
    .custom((value, { req }) => {
      if (value === req.body.currentPassword) {
        throw new Error('New password must be different from current password');
      }
      return true;
    }),

  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match new password');
      }
      return true;
    }),
];

// Email Verification Validation
export const validateEmailVerification = [
  body('token')
    .notEmpty()
    .withMessage('Verification token is required')
    .isLength({ min: 32, max: 128 })
    .withMessage('Invalid verification token format'),
];

// Two-Factor Authentication Validation
export const validateTwoFactorVerification = [
  body('token')
    .notEmpty()
    .withMessage('Two-factor token is required')
    .isLength({ min: 6, max: 6 })
    .withMessage('Two-factor token must be 6 digits')
    .isNumeric()
    .withMessage('Two-factor token must be numeric'),

  body('type')
    .isIn(['setup', 'login', 'disable'])
    .withMessage('Invalid verification type'),

  body('backupCode')
    .optional()
    .isLength({ min: 8, max: 16 })
    .withMessage('Invalid backup code format'),
];

// Profile Update Validation
export const validateProfileUpdate = [
  body('firstName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('First name can only contain letters, spaces, hyphens, and apostrophes'),

  body('lastName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Last name can only contain letters, spaces, hyphens, and apostrophes'),

  body('middleName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Middle name must not exceed 50 characters'),

  body('phone')
    .optional()
    .matches(PHONE_REGEX)
    .withMessage('Invalid phone number format'),
];

// Refresh Token Validation
export const validateRefreshToken = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required')
    .isJWT()
    .withMessage('Invalid refresh token format'),
];

export default {
  validateRegister,
  validateLogin,
  validatePasswordResetRequest,
  validatePasswordResetConfirm,
  validatePasswordChange,
  validateEmailVerification,
  validateTwoFactorVerification,
  validateProfileUpdate,
  validateRefreshToken,
};