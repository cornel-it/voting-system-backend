// backend/src/validators/vote.validator.ts

import { body, param, query } from 'express-validator';

// ============================================================================
// VOTING SESSION VALIDATORS
// ============================================================================

export const validateStartVotingSession = [
  body('electionId')
    .isUUID()
    .withMessage('Invalid election ID format'),

  body('deviceFingerprint')
    .optional()
    .isString()
    .isLength({ min: 10, max: 500 })
    .withMessage('Device fingerprint must be between 10 and 500 characters')
];

export const validateCompleteSession = [
  param('sessionId')
    .isUUID()
    .withMessage('Invalid session ID format')
];

export const validateExtendSession = [
  param('sessionId')
    .isUUID()
    .withMessage('Invalid session ID format'),

  body('extensionMinutes')
    .optional()
    .isInt({ min: 5, max: 30 })
    .withMessage('Extension must be between 5 and 30 minutes')
];

// ============================================================================
// VOTING VALIDATORS
// ============================================================================

export const validateCastVote = [
  body('sessionId')
    .isUUID()
    .withMessage('Invalid session ID format'),

  body('ballot')
    .isArray({ min: 1 })
    .withMessage('Ballot must be an array with at least one position'),

  body('ballot.*.positionId')
    .isUUID()
    .withMessage('Invalid position ID format'),

  body('ballot.*.candidateIds')
    .isArray()
    .withMessage('Candidate IDs must be an array'),

  body('ballot.*.candidateIds.*')
    .isUUID()
    .withMessage('Invalid candidate ID format'),

  body('ballot.*.ranking')
    .optional()
    .isArray()
    .withMessage('Ranking must be an array'),

  body('ballot.*.ranking.*')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Ranking values must be positive integers'),

  body('ballot.*.abstain')
    .optional()
    .isBoolean()
    .withMessage('Abstain must be a boolean value'),

  body('twoFactorToken')
    .optional()
    .isString()
    .isLength({ min: 6, max: 8 })
    .withMessage('Two-factor token must be between 6 and 8 characters')
    .matches(/^[0-9]+$/)
    .withMessage('Two-factor token must contain only numbers')
];

export const validateVerifyVote = [
  body('verificationCode')
    .notEmpty()
    .withMessage('Verification code is required')
    .isString()
    .isLength({ min: 8, max: 64 })
    .withMessage('Verification code must be between 8 and 64 characters')
    .matches(/^[A-Za-z0-9]+$/)
    .withMessage('Verification code must contain only alphanumeric characters')
];

export const validateBallotStructure = [
  body('electionId')
    .isUUID()
    .withMessage('Invalid election ID format'),

  body('ballot')
    .isArray({ min: 1 })
    .withMessage('Ballot must be an array with at least one position'),

  body('ballot.*.positionId')
    .isUUID()
    .withMessage('Invalid position ID format'),

  body('ballot.*.candidateIds')
    .isArray()
    .withMessage('Candidate IDs must be an array'),

  body('ballot.*.candidateIds.*')
    .isUUID()
    .withMessage('Invalid candidate ID format')
];

// ============================================================================
// ELECTION AND BALLOT VALIDATORS
// ============================================================================

export const validateElectionId = [
  param('electionId')
    .isUUID()
    .withMessage('Invalid election ID format')
];

export const validateSessionId = [
  param('sessionId')
    .isUUID()
    .withMessage('Invalid session ID format')
];

export const validateVerificationCode = [
  param('verificationCode')
    .notEmpty()
    .withMessage('Verification code is required')
    .isString()
    .isLength({ min: 8, max: 64 })
    .withMessage('Invalid verification code format')
];

export const validateReceiptHash = [
  param('receiptHash')
    .notEmpty()
    .withMessage('Receipt hash is required')
    .isString()
    .isLength({ min: 32, max: 128 })
    .withMessage('Invalid receipt hash format')
    .matches(/^[A-Fa-f0-9]+$/)
    .withMessage('Receipt hash must be a valid hexadecimal string')
];

// ============================================================================
// REPORTING VALIDATORS
// ============================================================================

export const validateReportIssue = [
  body('electionId')
    .isUUID()
    .withMessage('Invalid election ID format'),

  body('sessionId')
    .optional()
    .isUUID()
    .withMessage('Invalid session ID format'),

  body('issueType')
    .isIn([
      'TECHNICAL_ERROR',
      'BALLOT_ISSUE',
      'AUTHENTICATION_PROBLEM',
      'SESSION_TIMEOUT',
      'DISPLAY_ISSUE',
      'PERFORMANCE_ISSUE',
      'SECURITY_CONCERN',
      'OTHER'
    ])
    .withMessage('Invalid issue type'),

  body('description')
    .isString()
    .isLength({ min: 20, max: 1000 })
    .withMessage('Description must be between 20 and 1000 characters')
    .trim()
];

// ============================================================================
// ADMIN VALIDATORS
// ============================================================================

export const validateVotingProgress = [
  param('electionId')
    .isUUID()
    .withMessage('Invalid election ID format')
];

export const validateTallyVotes = [
  param('electionId')
    .isUUID()
    .withMessage('Invalid election ID format'),

  query('includePartial')
    .optional()
    .isBoolean()
    .withMessage('Include partial must be a boolean value')
];

export const validateInvalidateVote = [
  param('voteId')
    .isUUID()
    .withMessage('Invalid vote ID format'),

  body('reason')
    .isString()
    .isLength({ min: 10, max: 500 })
    .withMessage('Reason must be between 10 and 500 characters')
    .trim()
];

export const validateExportData = [
  param('electionId')
    .isUUID()
    .withMessage('Invalid election ID format'),

  query('format')
    .optional()
    .isIn(['json', 'csv', 'xlsx'])
    .withMessage('Format must be one of: json, csv, xlsx'),

  query('includePersonalData')
    .optional()
    .isBoolean()
    .withMessage('Include personal data must be a boolean value')
];

// ============================================================================
// QUERY VALIDATORS
// ============================================================================

export const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),

  query('includeDetails')
    .optional()
    .isBoolean()
    .withMessage('Include details must be a boolean value')
];

export const validateVoteSearch = [
  ...validatePagination,

  query('electionId')
    .optional()
    .isUUID()
    .withMessage('Invalid election ID format'),

  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),

  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),

  query('verified')
    .optional()
    .isBoolean()
    .withMessage('Verified must be a boolean value')
];

// ============================================================================
// COMMON VALIDATORS
// ============================================================================

export const validateUUID = (fieldName: string) => [
  param(fieldName)
    .isUUID()
    .withMessage(`Invalid ${fieldName} format`)
];

export const validateOptionalUUID = (fieldName: string) => [
  body(fieldName)
    .optional()
    .isUUID()
    .withMessage(`Invalid ${fieldName} format`)
];

export const validateRequiredString = (fieldName: string, minLength: number = 1, maxLength: number = 255) => [
  body(fieldName)
    .isString()
    .isLength({ min: minLength, max: maxLength })
    .withMessage(`${fieldName} must be between ${minLength} and ${maxLength} characters`)
    .trim()
];

export const validateOptionalString = (fieldName: string, minLength: number = 1, maxLength: number = 255) => [
  body(fieldName)
    .optional()
    .isString()
    .isLength({ min: minLength, max: maxLength })
    .withMessage(`${fieldName} must be between ${minLength} and ${maxLength} characters`)
    .trim()
];

export const validateBoolean = (fieldName: string, optional: boolean = false) => [
  optional ? body(fieldName).optional() : body(fieldName),
  body(fieldName)
    .isBoolean()
    .withMessage(`${fieldName} must be a boolean value`)
];

export const validateInteger = (fieldName: string, min?: number, max?: number, optional: boolean = false) => [
  optional ? body(fieldName).optional() : body(fieldName),
  body(fieldName)
    .isInt({ min, max })
    .withMessage(`${fieldName} must be an integer${min !== undefined ? ` >= ${min}` : ''}${max !== undefined ? ` <= ${max}` : ''}`)
];

export const validateArray = (fieldName: string, minLength?: number, maxLength?: number) => [
  body(fieldName)
    .isArray({ min: minLength, max: maxLength })
    .withMessage(`${fieldName} must be an array${minLength ? ` with at least ${minLength} items` : ''}${maxLength ? ` and at most ${maxLength} items` : ''}`)
];

// ============================================================================
// CUSTOM VALIDATORS
// ============================================================================

export const validateVotingBallot = [
  body('ballot')
    .custom((ballot) => {
      if (!Array.isArray(ballot)) {
        throw new Error('Ballot must be an array');
      }

      for (const item of ballot) {
        // Validate each ballot item structure
        if (!item.positionId || typeof item.positionId !== 'string') {
          throw new Error('Each ballot item must have a valid positionId');
        }

        if (!Array.isArray(item.candidateIds)) {
          throw new Error('Each ballot item must have candidateIds array');
        }

        // If abstain is true, candidateIds should be empty
        if (item.abstain === true && item.candidateIds.length > 0) {
          throw new Error('Cannot have both abstain and candidate selections');
        }

        // If not abstaining, must have at least one candidate
        if (item.abstain !== true && item.candidateIds.length === 0) {
          throw new Error('Must select at least one candidate or choose to abstain');
        }

        // Validate ranking if provided
        if (item.ranking && Array.isArray(item.ranking)) {
          if (item.ranking.length !== item.candidateIds.length) {
            throw new Error('Ranking array length must match candidateIds array length');
          }

          // Check for duplicate rankings
          const rankingSet = new Set(item.ranking);
          if (rankingSet.size !== item.ranking.length) {
            throw new Error('Ranking values must be unique');
          }
        }
      }

      return true;
    })
];

export const validateDeviceFingerprint = [
  body('deviceFingerprint')
    .optional()
    .custom((fingerprint) => {
      if (typeof fingerprint !== 'string') {
        throw new Error('Device fingerprint must be a string');
      }

      // Basic validation for device fingerprint format
      if (fingerprint.length < 10 || fingerprint.length > 500) {
        throw new Error('Device fingerprint must be between 10 and 500 characters');
      }

      // Check for potentially malicious content
      const suspiciousPatterns = [
        /<script/i,
        /javascript:/i,
        /data:text\/html/i,
        /vbscript:/i
      ];

      for (const pattern of suspiciousPatterns) {
        if (pattern.test(fingerprint)) {
          throw new Error('Invalid device fingerprint format');
        }
      }

      return true;
    })
];

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Session validators
  validateStartVotingSession,
  validateCompleteSession,
  validateExtendSession,

  // Voting validators
  validateCastVote,
  validateVerifyVote,
  validateBallotStructure,
  validateVotingBallot,

  // Parameter validators
  validateElectionId,
  validateSessionId,
  validateVerificationCode,
  validateReceiptHash,

  // Admin validators
  validateVotingProgress,
  validateTallyVotes,
  validateInvalidateVote,
  validateExportData,

  // Reporting validators
  validateReportIssue,

  // Query validators
  validatePagination,
  validateVoteSearch,

  // Common validators
  validateUUID,
  validateOptionalUUID,
  validateRequiredString,
  validateOptionalString,
  validateBoolean,
  validateInteger,
  validateArray,

  // Custom validators
  validateDeviceFingerprint
};