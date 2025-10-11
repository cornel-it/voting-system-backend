// backend/src/validators/candidate.validator.ts

import { body, param, query } from 'express-validator';
import { CandidateStatus } from '@prisma/client';

const STUDENT_ID_REGEX = /^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/;
const PHONE_REGEX = /^(\+254|0)[17]\d{8}$/;
const URL_REGEX = /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/;

// Create Candidate Validation
export const validateCreateCandidate = [
  body('electionId')
    .isUUID()
    .withMessage('Invalid election ID'),

  body('positionId')
    .isUUID()
    .withMessage('Invalid position ID'),

  body('studentId')
    .notEmpty()
    .withMessage('Student ID is required')
    .matches(STUDENT_ID_REGEX)
    .withMessage('Invalid student ID format')
    .customSanitizer(value => value?.toUpperCase().trim()),

  body('firstName')
    .notEmpty()
    .withMessage('First name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),

  body('lastName')
    .notEmpty()
    .withMessage('Last name is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),

  body('email')
    .isEmail()
    .withMessage('Valid email is required')
    .normalizeEmail(),

  body('manifesto')
    .notEmpty()
    .withMessage('Manifesto is required')
    .isLength({ min: 100, max: 10000 })
    .withMessage('Manifesto must be between 100 and 10,000 characters'),

  body('phone')
    .notEmpty()
    .withMessage('Phone number is required')
    .matches(PHONE_REGEX)
    .withMessage('Invalid phone number format'),

  body('faculty')
    .notEmpty()
    .withMessage('Faculty is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Faculty must be between 2 and 100 characters'),

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
    .isInt({ min: 1, max: 8 })
    .withMessage('Year of study must be between 1 and 8'),

  body('middleName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('Middle name must be between 2 and 50 characters'),

  body('slogan')
    .optional()
    .isLength({ max: 200 })
    .withMessage('Slogan must not exceed 200 characters'),

  body('socialMedia.facebook')
    .optional()
    .matches(URL_REGEX)
    .withMessage('Invalid Facebook URL'),

  body('socialMedia.twitter')
    .optional()
    .matches(URL_REGEX)
    .withMessage('Invalid Twitter URL'),

  body('socialMedia.instagram')
    .optional()
    .matches(URL_REGEX)
    .withMessage('Invalid Instagram URL'),

  body('socialMedia.linkedin')
    .optional()
    .matches(URL_REGEX)
    .withMessage('Invalid LinkedIn URL'),
];

export const validateUpdateCandidateProfile = [
  param('id')
    .isUUID()
    .withMessage('Invalid candidate ID'),

  body('manifesto')
    .optional()
    .isLength({ min: 100, max: 10000 })
    .withMessage('Manifesto must be between 100 and 10,000 characters'),

  body('slogan')
    .optional()
    .isLength({ max: 200 })
    .withMessage('Slogan must not exceed 200 characters'),

  body('runningMateId')
    .optional()
    .custom((value) => {
      if (value === null) return true;
      if (typeof value === 'string' && value.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
        return true;
      }
      throw new Error('Invalid running mate ID format');
    }),
];

export const validateCandidateStatusUpdate = [
  param('id')
    .isUUID()
    .withMessage('Invalid candidate ID'),

  body('status')
    .isIn(Object.values(CandidateStatus))
    .withMessage('Invalid candidate status'),

  body('reason')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Reason must not exceed 500 characters'),
];

// Parameter validators
export const validateCandidateId = [
  param('id')
    .isUUID()
    .withMessage('Invalid candidate ID'),
];

export const validateElectionId = [
  param('electionId')
    .isUUID()
    .withMessage('Invalid election ID'),
];

export const validatePositionId = [
  param('positionId')
    .isUUID()
    .withMessage('Invalid position ID'),
];

// Running mate validation
export const validateRunningMate = [
  body('runningMateId')
    .isUUID()
    .withMessage('Invalid running mate candidate ID'),
];

// Photo upload validation
export const validatePhotoUpload = [
  // This will be handled by multer middleware, but we can add additional checks
];

// Bulk operations validation
export const validateBulkApproval = [
  body('candidateIds')
    .isArray({ min: 1, max: 100 })
    .withMessage('Candidate IDs must be an array with 1-100 items'),

  body('candidateIds.*')
    .isUUID()
    .withMessage('Each candidate ID must be a valid UUID'),

  body('reason')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Reason must not exceed 500 characters'),
];

export const validateBulkRejection = [
  body('candidateIds')
    .isArray({ min: 1, max: 100 })
    .withMessage('Candidate IDs must be an array with 1-100 items'),

  body('candidateIds.*')
    .isUUID()
    .withMessage('Each candidate ID must be a valid UUID'),

  body('reason')
    .notEmpty()
    .withMessage('Reason is required for bulk rejection')
    .isLength({ min: 10, max: 500 })
    .withMessage('Reason must be between 10 and 500 characters'),
];

// Export parameters validation
export const validateExportParams = [
  query('format')
    .optional()
    .isIn(['csv', 'json', 'xlsx'])
    .withMessage('Format must be csv, json, or xlsx'),

  query('status')
    .optional()
    .isIn(Object.values(CandidateStatus))
    .withMessage('Invalid candidate status'),

  query('includePersonalData')
    .optional()
    .isBoolean()
    .withMessage('includePersonalData must be boolean'),

  query('includeManifestos')
    .optional()
    .isBoolean()
    .withMessage('includeManifestos must be boolean'),
];

// Search parameters validation
export const validateSearchParams = [
  query('search')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Search term must be between 1 and 100 characters'),

  query('status')
    .optional()
    .isIn(Object.values(CandidateStatus))
    .withMessage('Invalid candidate status'),

  query('faculty')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Faculty must be between 1 and 100 characters'),

  query('department')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Department must be between 1 and 100 characters'),

  query('course')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Course must be between 1 and 100 characters'),

  query('yearOfStudy')
    .optional()
    .isInt({ min: 1, max: 8 })
    .withMessage('Year of study must be between 1 and 8'),

  query('electionId')
    .optional()
    .isUUID()
    .withMessage('Invalid election ID'),

  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 200 })
    .withMessage('Limit must be between 1 and 200'),

  query('sortBy')
    .optional()
    .isIn(['createdAt', 'firstName', 'lastName', 'status', 'faculty', 'department', 'yearOfStudy'])
    .withMessage('Invalid sort field'),

  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be asc or desc'),
];

// Analytics parameters validation
export const validateAnalyticsParams = [
  query('includeVoteAnalysis')
    .optional()
    .isBoolean()
    .withMessage('includeVoteAnalysis must be boolean'),

  query('includeDemographics')
    .optional()
    .isBoolean()
    .withMessage('includeDemographics must be boolean'),

  query('includePerformanceMetrics')
    .optional()
    .isBoolean()
    .withMessage('includePerformanceMetrics must be boolean'),
];

// Additional validation for specific routes
export const validateCandidateQuery = [
  query('useCache')
    .optional()
    .isBoolean()
    .withMessage('useCache must be boolean'),

  query('includeVotes')
    .optional()
    .isBoolean()
    .withMessage('includeVotes must be boolean'),

  query('includeResults')
    .optional()
    .isBoolean()
    .withMessage('includeResults must be boolean'),
];

export const validateElectionCandidatesQuery = [
  query('positionId')
    .optional()
    .isUUID()
    .withMessage('Invalid position ID'),

  query('status')
    .optional()
    .isIn(Object.values(CandidateStatus))
    .withMessage('Invalid candidate status'),

  query('faculty')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Faculty must be between 1 and 100 characters'),

  query('department')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Department must be between 1 and 100 characters'),

  query('course')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Course must be between 1 and 100 characters'),

  query('yearOfStudy')
    .optional()
    .isInt({ min: 1, max: 8 })
    .withMessage('Year of study must be between 1 and 8'),

  query('search')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Search term must be between 1 and 100 characters'),

  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 200 })
    .withMessage('Limit must be between 1 and 200'),

  query('useCache')
    .optional()
    .isBoolean()
    .withMessage('useCache must be boolean'),
];

export default {
  validateCreateCandidate,
  validateUpdateCandidateProfile,
  validateCandidateStatusUpdate,
  validateCandidateId,
  validateElectionId,
  validatePositionId,
  validateRunningMate,
  validatePhotoUpload,
  validateBulkApproval,
  validateBulkRejection,
  validateExportParams,
  validateSearchParams,
  validateAnalyticsParams,
  validateCandidateQuery,
  validateElectionCandidatesQuery,
};