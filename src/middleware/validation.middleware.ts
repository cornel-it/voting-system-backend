// backend/src/middleware/validation.middleware.ts

import { Request, Response, NextFunction } from 'express';
import { body, param, query, validationResult, ValidationChain } from 'express-validator';
import { AppError } from '../utils/errors';

/**
 * Handle validation errors
 */
export const handleValidationErrors = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => ({
      field: error.type === 'field' ? (error as any).path : undefined,
      message: error.msg,
      value: (error as any).value
    }));

    throw new AppError('Validation failed', 400, 'VALIDATION_ERROR', errorMessages);
  }
  
  next();
};

/**
 * Authentication validation rules
 */
export const authValidation = {
  register: [
    body('studentId')
      .trim()
      .notEmpty().withMessage('Student ID is required')
      .matches(/^[A-Z]{2,3}\/\d{5}\/\d{2}$/).withMessage('Invalid JKUAT student ID format'),
    body('email')
      .trim()
      .notEmpty().withMessage('Email is required')
      .isEmail().withMessage('Invalid email format')
      .normalizeEmail()
      .matches(/@students\.jkuat\.ac\.ke$/).withMessage('Must use JKUAT student email'),
    body('password')
      .notEmpty().withMessage('Password is required')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain uppercase, lowercase, number and special character'),
    body('confirmPassword')
      .notEmpty().withMessage('Password confirmation is required')
      .custom((value, { req }) => value === req.body.password)
      .withMessage('Passwords do not match'),
    body('firstName')
      .trim()
      .notEmpty().withMessage('First name is required')
      .isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters')
      .matches(/^[a-zA-Z\s'-]+$/).withMessage('First name contains invalid characters'),
    body('lastName')
      .trim()
      .notEmpty().withMessage('Last name is required')
      .isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters')
      .matches(/^[a-zA-Z\s'-]+$/).withMessage('Last name contains invalid characters'),
    body('middleName')
      .optional()
      .trim()
      .isLength({ max: 50 }).withMessage('Middle name must not exceed 50 characters')
      .matches(/^[a-zA-Z\s'-]*$/).withMessage('Middle name contains invalid characters'),
    body('phone')
      .optional()
      .trim()
      .matches(/^(\+254|0)[17]\d{8}$/).withMessage('Invalid Kenyan phone number'),
    body('faculty')
      .trim()
      .notEmpty().withMessage('Faculty is required')
      .isIn(['ENGINEERING', 'SCIENCE', 'COPAS', 'SABS', 'SHSS', 'MEDICINE'])
      .withMessage('Invalid faculty'),
    body('department')
      .trim()
      .notEmpty().withMessage('Department is required'),
    body('course')
      .trim()
      .notEmpty().withMessage('Course is required'),
    body('yearOfStudy')
      .notEmpty().withMessage('Year of study is required')
      .isInt({ min: 1, max: 6 }).withMessage('Year of study must be between 1 and 6'),
    body('admissionYear')
      .notEmpty().withMessage('Admission year is required')
      .isInt({ min: 2000, max: new Date().getFullYear() })
      .withMessage('Invalid admission year'),
    handleValidationErrors
  ],

  login: [
    body('studentId')
      .trim()
      .notEmpty().withMessage('Student ID is required')
      .matches(/^[A-Z]{2,3}\/\d{5}\/\d{2}$/).withMessage('Invalid student ID format'),
    body('password')
      .notEmpty().withMessage('Password is required'),
    body('twoFactorCode')
      .optional()
      .isLength({ min: 6, max: 6 }).withMessage('2FA code must be 6 digits')
      .isNumeric().withMessage('2FA code must be numeric'),
    body('deviceFingerprint')
      .optional()
      .isString(),
    handleValidationErrors
  ],

  forgotPassword: [
    body('email')
      .trim()
      .notEmpty().withMessage('Email is required')
      .isEmail().withMessage('Invalid email format')
      .normalizeEmail(),
    handleValidationErrors
  ],

  resetPassword: [
    param('token')
      .notEmpty().withMessage('Reset token is required'),
    body('password')
      .notEmpty().withMessage('Password is required')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain uppercase, lowercase, number and special character'),
    body('confirmPassword')
      .notEmpty().withMessage('Password confirmation is required')
      .custom((value, { req }) => value === req.body.password)
      .withMessage('Passwords do not match'),
    handleValidationErrors
  ],

  changePassword: [
    body('currentPassword')
      .notEmpty().withMessage('Current password is required'),
    body('newPassword')
      .notEmpty().withMessage('New password is required')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain uppercase, lowercase, number and special character')
      .custom((value, { req }) => value !== req.body.currentPassword)
      .withMessage('New password must be different from current password'),
    handleValidationErrors
  ],

  verify2FA: [
    body('token')
      .notEmpty().withMessage('2FA token is required')
      .isLength({ min: 6, max: 6 }).withMessage('2FA token must be 6 digits')
      .isNumeric().withMessage('2FA token must be numeric'),
    handleValidationErrors
  ]
};

/**
 * Election validation rules
 */
export const electionValidation = {
  create: [
    body('title')
      .trim()
      .notEmpty().withMessage('Title is required')
      .isLength({ min: 5, max: 200 }).withMessage('Title must be 5-200 characters'),
    body('description')
      .trim()
      .notEmpty().withMessage('Description is required')
      .isLength({ min: 10, max: 2000 }).withMessage('Description must be 10-2000 characters'),
    body('type')
      .notEmpty().withMessage('Election type is required')
      .isIn(['PRESIDENTIAL', 'DEPARTMENTAL', 'FACULTY', 'CLUB', 'SOCIETY', 'REFERENDUM', 'POLL'])
      .withMessage('Invalid election type'),
    body('startDate')
      .notEmpty().withMessage('Start date is required')
      .isISO8601().withMessage('Invalid date format')
      .custom((value) => new Date(value) > new Date())
      .withMessage('Start date must be in the future'),
    body('endDate')
      .notEmpty().withMessage('End date is required')
      .isISO8601().withMessage('Invalid date format')
      .custom((value, { req }) => new Date(value) > new Date(req.body.startDate))
      .withMessage('End date must be after start date'),
    body('eligibleFaculties')
      .optional()
      .isArray().withMessage('Eligible faculties must be an array'),
    body('eligibleDepartments')
      .optional()
      .isArray().withMessage('Eligible departments must be an array'),
    body('eligibleCourses')
      .optional()
      .isArray().withMessage('Eligible courses must be an array'),
    body('eligibleYears')
      .optional()
      .isArray().withMessage('Eligible years must be an array')
      .custom((value) => value.every((year: any) => year >= 1 && year <= 6))
      .withMessage('Invalid year values'),
    body('positions')
      .notEmpty().withMessage('Positions are required')
      .isArray({ min: 1 }).withMessage('At least one position is required'),
    body('positions.*.name')
      .trim()
      .notEmpty().withMessage('Position name is required')
      .isLength({ min: 2, max: 100 }).withMessage('Position name must be 2-100 characters'),
    body('positions.*.maxSelections')
      .optional()
      .isInt({ min: 1 }).withMessage('Max selections must be at least 1'),
    body('requireTwoFactor')
      .optional()
      .isBoolean().withMessage('Require 2FA must be boolean'),
    body('allowAbstain')
      .optional()
      .isBoolean().withMessage('Allow abstain must be boolean'),
    body('showLiveResults')
      .optional()
      .isBoolean().withMessage('Show live results must be boolean'),
    handleValidationErrors
  ],

  update: [
    param('id')
      .notEmpty().withMessage('Election ID is required')
      .isUUID().withMessage('Invalid election ID'),
    body('title')
      .optional()
      .trim()
      .isLength({ min: 5, max: 200 }).withMessage('Title must be 5-200 characters'),
    body('description')
      .optional()
      .trim()
      .isLength({ min: 10, max: 2000 }).withMessage('Description must be 10-2000 characters'),
    body('startDate')
      .optional()
      .isISO8601().withMessage('Invalid date format'),
    body('endDate')
      .optional()
      .isISO8601().withMessage('Invalid date format'),
    handleValidationErrors
  ],

  getById: [
    param('id')
      .notEmpty().withMessage('Election ID is required')
      .isUUID().withMessage('Invalid election ID'),
    handleValidationErrors
  ],

  list: [
    query('page')
      .optional()
      .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('status')
      .optional()
      .isIn(['DRAFT', 'SCHEDULED', 'ACTIVE', 'PAUSED', 'COMPLETED', 'CANCELLED', 'ARCHIVED'])
      .withMessage('Invalid status'),
    query('type')
      .optional()
      .isIn(['PRESIDENTIAL', 'DEPARTMENTAL', 'FACULTY', 'CLUB', 'SOCIETY', 'REFERENDUM', 'POLL'])
      .withMessage('Invalid type'),
    query('sortBy')
      .optional()
      .isIn(['createdAt', 'startDate', 'endDate', 'title'])
      .withMessage('Invalid sort field'),
    query('order')
      .optional()
      .isIn(['asc', 'desc']).withMessage('Order must be asc or desc'),
    handleValidationErrors
  ]
};

/**
 * Voting validation rules
 */
export const votingValidation = {
  createSession: [
    body('electionId')
      .notEmpty().withMessage('Election ID is required')
      .isUUID().withMessage('Invalid election ID'),
    body('deviceFingerprint')
      .optional()
      .isString(),
    handleValidationErrors
  ],

  castVote: [
    body('sessionId')
      .notEmpty().withMessage('Session ID is required')
      .isUUID().withMessage('Invalid session ID'),
    body('positionId')
      .notEmpty().withMessage('Position ID is required')
      .isUUID().withMessage('Invalid position ID'),
    body('candidateIds')
      .isArray().withMessage('Candidate IDs must be an array'),
    body('candidateIds.*')
      .optional()
      .isUUID().withMessage('Invalid candidate ID'),
    handleValidationErrors
  ],

  completeSession: [
    param('sessionId')
      .notEmpty().withMessage('Session ID is required')
      .isUUID().withMessage('Invalid session ID'),
    handleValidationErrors
  ],

  verifyVote: [
    body('verificationCode')
      .notEmpty().withMessage('Verification code is required')
      .matches(/^JKV-[A-Z0-9]{6,}-[A-Z0-9]{6}$/).withMessage('Invalid verification code format'),
    handleValidationErrors
  ]
};

/**
 * Candidate validation rules
 */
export const candidateValidation = {
  create: [
    body('electionId')
      .notEmpty().withMessage('Election ID is required')
      .isUUID().withMessage('Invalid election ID'),
    body('positionId')
      .notEmpty().withMessage('Position ID is required')
      .isUUID().withMessage('Invalid position ID'),
    body('studentId')
      .trim()
      .notEmpty().withMessage('Student ID is required')
      .matches(/^[A-Z]{2,3}\/\d{5}\/\d{2}$/).withMessage('Invalid student ID format'),
    body('manifesto')
      .trim()
      .notEmpty().withMessage('Manifesto is required')
      .isLength({ min: 100, max: 5000 }).withMessage('Manifesto must be 100-5000 characters'),
    body('slogan')
      .optional()
      .trim()
      .isLength({ max: 100 }).withMessage('Slogan must not exceed 100 characters'),
    body('runningMateId')
      .optional()
      .isUUID().withMessage('Invalid running mate ID'),
    handleValidationErrors
  ],

  update: [
    param('id')
      .notEmpty().withMessage('Candidate ID is required')
      .isUUID().withMessage('Invalid candidate ID'),
    body('manifesto')
      .optional()
      .trim()
      .isLength({ min: 100, max: 5000 }).withMessage('Manifesto must be 100-5000 characters'),
    body('slogan')
      .optional()
      .trim()
      .isLength({ max: 100 }).withMessage('Slogan must not exceed 100 characters'),
    body('status')
      .optional()
      .isIn(['PENDING', 'APPROVED', 'REJECTED', 'DISQUALIFIED', 'WITHDRAWN'])
      .withMessage('Invalid status'),
    handleValidationErrors
  ],

  approve: [
    param('id')
      .notEmpty().withMessage('Candidate ID is required')
      .isUUID().withMessage('Invalid candidate ID'),
    handleValidationErrors
  ],

  reject: [
    param('id')
      .notEmpty().withMessage('Candidate ID is required')
      .isUUID().withMessage('Invalid candidate ID'),
    body('reason')
      .trim()
      .notEmpty().withMessage('Rejection reason is required')
      .isLength({ min: 10, max: 500 }).withMessage('Reason must be 10-500 characters'),
    handleValidationErrors
  ]
};

/**
 * User validation rules
 */
export const userValidation = {
  updateProfile: [
    body('firstName')
      .optional()
      .trim()
      .isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters')
      .matches(/^[a-zA-Z\s'-]+$/).withMessage('First name contains invalid characters'),
    body('lastName')
      .optional()
      .trim()
      .isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters')
      .matches(/^[a-zA-Z\s'-]+$/).withMessage('Last name contains invalid characters'),
    body('phone')
      .optional()
      .trim()
      .matches(/^(\+254|0)[17]\d{8}$/).withMessage('Invalid Kenyan phone number'),
    body('yearOfStudy')
      .optional()
      .isInt({ min: 1, max: 6 }).withMessage('Year of study must be between 1 and 6'),
    handleValidationErrors
  ],

  updateRole: [
    param('id')
      .notEmpty().withMessage('User ID is required')
      .isUUID().withMessage('Invalid user ID'),
    body('role')
      .notEmpty().withMessage('Role is required')
      .isIn(['SUPER_ADMIN', 'ADMIN', 'MODERATOR', 'VOTER'])
      .withMessage('Invalid role'),
    handleValidationErrors
  ],

  updatePermissions: [
    param('id')
      .notEmpty().withMessage('User ID is required')
      .isUUID().withMessage('Invalid user ID'),
    body('permissions')
      .isArray().withMessage('Permissions must be an array'),
    body('permissions.*')
      .isString().withMessage('Each permission must be a string'),
    handleValidationErrors
  ]
};

/**
 * File upload validation
 */
export const fileValidation = {
  image: (fieldName: string) => [
    body(fieldName)
      .custom((value, { req }) => {
        if (!req.file) {
          throw new Error(`${fieldName} is required`);
        }
        
        const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (!allowedMimes.includes(req.file.mimetype)) {
          throw new Error('Invalid image format. Only JPEG, PNG, GIF, and WebP are allowed');
        }
        
        const maxSize = 5 * 1024 * 1024; // 5MB
        if (req.file.size > maxSize) {
          throw new Error('Image size must not exceed 5MB');
        }
        
        return true;
      }),
    handleValidationErrors
  ],

  csv: (fieldName: string) => [
    body(fieldName)
      .custom((value, { req }) => {
        if (!req.file) {
          throw new Error(`${fieldName} is required`);
        }
        
        const allowedMimes = ['text/csv', 'application/csv', 'application/vnd.ms-excel'];
        if (!allowedMimes.includes(req.file.mimetype)) {
          throw new Error('Invalid file format. Only CSV files are allowed');
        }
        
        const maxSize = 10 * 1024 * 1024; // 10MB
        if (req.file.size > maxSize) {
          throw new Error('File size must not exceed 10MB');
        }
        
        return true;
      }),
    handleValidationErrors
  ]
};

/**
 * Pagination validation
 */
export const paginationValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('search')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('Search query too long'),
  handleValidationErrors
];

/**
 * ID parameter validation
 */
export const idParamValidation = [
  param('id')
    .notEmpty().withMessage('ID is required')
    .isUUID().withMessage('Invalid ID format'),
  handleValidationErrors
];

export default {
  authValidation,
  electionValidation,
  votingValidation,
  candidateValidation,
  userValidation,
  fileValidation,
  paginationValidation,
  idParamValidation,
  handleValidationErrors
};