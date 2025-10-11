// backend/src/validators/result.validator.ts

import { body, param, query } from 'express-validator';

// Common validations for election ID
export const validateElectionId = [
  param('electionId')
    .isUUID()
    .withMessage('Election ID must be a valid UUID')
    .notEmpty()
    .withMessage('Election ID is required')
];

// Common validations for position ID
export const validatePositionId = [
  param('positionId')
    .isUUID()
    .withMessage('Position ID must be a valid UUID')
    .notEmpty()
    .withMessage('Position ID is required')
];

// Common validations for candidate ID
export const validateCandidateId = [
  param('candidateId')
    .isUUID()
    .withMessage('Candidate ID must be a valid UUID')
    .notEmpty()
    .withMessage('Candidate ID is required')
];

// Calculate Results Validation
export const validateCalculateResults = [
  body('isDraft')
    .optional()
    .isBoolean()
    .withMessage('isDraft must be a boolean value')
    .customSanitizer(value => {
      if (typeof value === 'string') {
        return value.toLowerCase() === 'true';
      }
      return Boolean(value);
    })
];

// Publish Results Validation
export const validatePublishResults = [
  body('confirmPublication')
    .optional()
    .isBoolean()
    .withMessage('confirmPublication must be a boolean value'),

  body('sendNotifications')
    .optional()
    .isBoolean()
    .withMessage('sendNotifications must be a boolean value')
    .customSanitizer(value => {
      if (typeof value === 'string') {
        return value.toLowerCase() === 'true';
      }
      return Boolean(value);
    })
];

// Export Results Validation
export const validateExportResults = [
  query('format')
    .optional()
    .isIn(['pdf', 'csv', 'xlsx', 'json'])
    .withMessage('Export format must be one of: pdf, csv, xlsx, json'),

  query('includeAnalytics')
    .optional()
    .isBoolean()
    .withMessage('includeAnalytics must be a boolean value'),

  query('includeDemographics')
    .optional()
    .isBoolean()
    .withMessage('includeDemographics must be a boolean value'),

  query('includeCharts')
    .optional()
    .isBoolean()
    .withMessage('includeCharts must be a boolean value')
];

// Generate Certificate Validation
export const validateGenerateCertificate = [
  body('candidateId')
    .optional()
    .isUUID()
    .withMessage('Candidate ID must be a valid UUID'),

  body('certificateType')
    .optional()
    .isIn(['winner', 'participation', 'runner_up', 'all'])
    .withMessage('Certificate type must be one of: winner, participation, runner_up, all'),

  body('includeQRCode')
    .optional()
    .isBoolean()
    .withMessage('includeQRCode must be a boolean value'),

  body('includeWatermark')
    .optional()
    .isBoolean()
    .withMessage('includeWatermark must be a boolean value')
];

// Compare Results Validation
export const validateCompareResults = [
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date')
    .custom((value) => {
      if (value) {
        const date = new Date(value);
        if (isNaN(date.getTime())) {
          throw new Error('Start date must be a valid date');
        }
        if (date > new Date()) {
          throw new Error('Start date cannot be in the future');
        }
      }
      return true;
    }),

  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date')
    .custom((value, { req }) => {
      if (value) {
        const endDate = new Date(value);
        if (isNaN(endDate.getTime())) {
          throw new Error('End date must be a valid date');
        }
        if (endDate > new Date()) {
          throw new Error('End date cannot be in the future');
        }

        if (req.query && req.query.startDate) {
          const startDate = new Date(req.query.startDate as string);
          if (endDate <= startDate) {
            throw new Error('End date must be after start date');
          }
        }
      }
      return true;
    }),

  query('comparisonType')
    .optional()
    .isIn(['hourly', 'daily', 'weekly', 'monthly'])
    .withMessage('Comparison type must be one of: hourly, daily, weekly, monthly')
];

// Get Election Results Validation
export const validateGetElectionResults = [
  query('includeUnpublished')
    .optional()
    .isBoolean()
    .withMessage('includeUnpublished must be a boolean value'),

  query('useCache')
    .optional()
    .isBoolean()
    .withMessage('useCache must be a boolean value')
];

// Get Voting Analytics Validation
export const validateGetVotingAnalytics = [
  query('useCache')
    .optional()
    .isBoolean()
    .withMessage('useCache must be a boolean value'),

  query('includeDemographics')
    .optional()
    .isBoolean()
    .withMessage('includeDemographics must be a boolean value'),

  query('dateRange')
    .optional()
    .isIn(['today', 'yesterday', 'last_7_days', 'last_30_days', 'all_time'])
    .withMessage('Date range must be one of: today, yesterday, last_7_days, last_30_days, all_time')
];

// Get Position Results Validation
export const validateGetPositionResults = [
  query('includeDemographics')
    .optional()
    .isBoolean()
    .withMessage('includeDemographics must be a boolean value'),

  query('includeVoteTrends')
    .optional()
    .isBoolean()
    .withMessage('includeVoteTrends must be a boolean value')
];

// Get Historical Comparison Validation
export const validateGetHistoricalComparison = [
  query('compareWith')
    .optional()
    .isUUID()
    .withMessage('compareWith must be a valid election UUID'),

  query('metrics')
    .optional()
    .isIn(['all', 'turnout', 'votes', 'demographics', 'timeline'])
    .withMessage('Metrics must be one of: all, turnout, votes, demographics, timeline')
];

// Verify Results Integrity Validation
export const validateVerifyResultsIntegrity = [
  body('performDeepCheck')
    .optional()
    .isBoolean()
    .withMessage('performDeepCheck must be a boolean value'),

  body('checkVoteSignatures')
    .optional()
    .isBoolean()
    .withMessage('checkVoteSignatures must be a boolean value'),

  body('validateEncryption')
    .optional()
    .isBoolean()
    .withMessage('validateEncryption must be a boolean value')
];

// Get Result Summary Validation
export const validateGetResultSummary = [
  query('includeCharts')
    .optional()
    .isBoolean()
    .withMessage('includeCharts must be a boolean value'),

  query('format')
    .optional()
    .isIn(['basic', 'detailed', 'extended'])
    .withMessage('Format must be one of: basic, detailed, extended')
];

// Pagination validation (common for list endpoints)
export const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer')
    .toInt(),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
    .toInt(),

  query('sortBy')
    .optional()
    .isIn(['createdAt', 'updatedAt', 'title', 'turnout', 'totalVotes'])
    .withMessage('sortBy must be one of: createdAt, updatedAt, title, turnout, totalVotes'),

  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('sortOrder must be either asc or desc')
];

// Search validation
export const validateSearchResults = [
  query('q')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Search query must be between 2 and 100 characters')
    .customSanitizer(value => value?.trim()),

  query('searchFields')
    .optional()
    .isIn(['title', 'description', 'candidates', 'positions', 'all'])
    .withMessage('searchFields must be one of: title, description, candidates, positions, all')
];

// Date range validation
export const validateDateRange = [
  query('from')
    .optional()
    .isISO8601()
    .withMessage('From date must be a valid ISO 8601 date'),

  query('to')
    .optional()
    .isISO8601()
    .withMessage('To date must be a valid ISO 8601 date')
    .custom((value, { req }) => {
      if (value && req.query && req.query.from) {
        const toDate = new Date(value);
        const fromDate = new Date(req.query.from as string);

        if (toDate <= fromDate) {
          throw new Error('To date must be after from date');
        }

        const daysDiff = (toDate.getTime() - fromDate.getTime()) / (1000 * 3600 * 24);
        if (daysDiff > 365) {
          throw new Error('Date range cannot exceed 365 days');
        }
      }
      return true;
    })
];

// Demographic filters validation
export const validateDemographicFilters = [
  query('faculty')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Faculty must be between 2 and 100 characters'),

  query('department')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Department must be between 2 and 100 characters'),

  query('yearOfStudy')
    .optional()
    .isInt({ min: 1, max: 7 })
    .withMessage('Year of study must be between 1 and 7')
    .toInt(),

  query('course')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Course must be between 2 and 100 characters')
];

export default {
  validateElectionId,
  validatePositionId,
  validateCandidateId,
  validateCalculateResults,
  validatePublishResults,
  validateExportResults,
  validateGenerateCertificate,
  validateCompareResults,
  validateGetElectionResults,
  validateGetVotingAnalytics,
  validateGetPositionResults,
  validateGetHistoricalComparison,
  validateVerifyResultsIntegrity,
  validateGetResultSummary,
  validatePagination,
  validateSearchResults,
  validateDateRange,
  validateDemographicFilters
};