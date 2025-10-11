// backend/src/validators/election.validator.ts

import { body, param, query } from 'express-validator';
import { ElectionType, ElectionStatus } from '@prisma/client';

// Create Election Validation
export const validateCreateElection = [
  body('title')
    .notEmpty()
    .withMessage('Election title is required')
    .isLength({ min: 5, max: 200 })
    .withMessage('Election title must be between 5 and 200 characters')
    .customSanitizer(value => value?.trim()),

  body('description')
    .notEmpty()
    .withMessage('Election description is required')
    .isLength({ min: 10, max: 2000 })
    .withMessage('Election description must be between 10 and 2000 characters')
    .customSanitizer(value => value?.trim()),

  body('type')
    .isIn(Object.values(ElectionType))
    .withMessage('Invalid election type'),

  body('startDate')
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date')
    .custom((value) => {
      const startDate = new Date(value);
      const now = new Date();
      const minStartDate = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour from now

      if (startDate <= minStartDate) {
        throw new Error('Start date must be at least 1 hour from now');
      }
      return true;
    }),

  body('endDate')
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date')
    .custom((value, { req }) => {
      const endDate = new Date(value);
      const startDate = new Date(req.body.startDate);
      const minDuration = 2 * 60 * 60 * 1000; // 2 hours minimum

      if (endDate <= startDate) {
        throw new Error('End date must be after start date');
      }

      const duration = endDate.getTime() - startDate.getTime();
      if (duration < minDuration) {
        throw new Error('Election must run for at least 2 hours');
      }

      return true;
    }),

  body('positions')
    .isArray({ min: 1, max: 20 })
    .withMessage('An election must have 1-20 positions'),

  body('positions.*.name')
    .notEmpty()
    .withMessage('Position name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Position name must be between 2 and 100 characters'),

  body('positions.*.order')
    .isInt({ min: 1, max: 100 })
    .withMessage('Position order must be between 1 and 100'),

  body('positions.*.maxSelections')
    .isInt({ min: 1, max: 10 })
    .withMessage('Max selections must be between 1 and 10'),
];

export const validateUpdateElection = [
  param('id')
    .isUUID()
    .withMessage('Invalid election ID'),

  body('title')
    .optional()
    .isLength({ min: 5, max: 200 })
    .withMessage('Election title must be between 5 and 200 characters'),

  body('description')
    .optional()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Election description must be between 10 and 2000 characters'),

  body('status')
    .optional()
    .isIn(Object.values(ElectionStatus))
    .withMessage('Invalid election status'),
];

export const validateElectionSearch = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),

  query('type')
    .optional()
    .isIn(Object.values(ElectionType))
    .withMessage('Invalid election type'),

  query('status')
    .optional()
    .isIn(Object.values(ElectionStatus))
    .withMessage('Invalid election status'),
];

export default {
  validateCreateElection,
  validateUpdateElection,
  validateElectionSearch,
};