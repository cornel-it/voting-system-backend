// backend/src/routes/voter.routes.ts

import { Router } from 'express';
import { VoterController } from '../controllers/voter.controller';
import { authenticate, authorize, checkPermission } from '../middleware/auth.middleware';
import { registrationRateLimit, uploadRateLimit, bulkRateLimit } from '../middleware/rateLimit.middleware';
import { body, param, query } from 'express-validator';

const router = Router();
const voterController = new VoterController();

// ============================================================================
// PUBLIC ROUTES
// ============================================================================

/**
 * @route   POST /api/voters/register
 * @desc    Register a new voter
 * @access  Public
 */
router.post(
  '/register',
  registrationRateLimit,
  [
    body('studentId').notEmpty().matches(/^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/).withMessage('Invalid student ID format'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('firstName').notEmpty().isString().trim().withMessage('First name is required'),
    body('lastName').notEmpty().isString().trim().withMessage('Last name is required'),
  ],
  voterController.registerVoter.bind(voterController)
);

/**
 * @route   GET /api/voters/verify-email/:token
 * @desc    Verify voter email with token
 * @access  Public
 */
router.get(
  '/verify-email/:token',
  [
    param('token').notEmpty().isString().withMessage('Verification token is required'),
  ],
  voterController.verifyEmail.bind(voterController)
);

// ============================================================================
// VOTER ROUTES (Authenticated)
// ============================================================================

/**
 * @route   GET /api/voters/profile
 * @desc    Get current voter's profile
 * @access  Private (Voter)
 */
router.get(
  '/profile',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  voterController.getVoterProfile.bind(voterController)
);

/**
 * @route   PUT /api/voters/profile
 * @desc    Update current voter's profile
 * @access  Private (Voter)
 */
router.put(
  '/profile',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  [
    body('firstName').optional().isString().trim().withMessage('First name must be a string'),
    body('lastName').optional().isString().trim().withMessage('Last name must be a string'),
    body('phone').optional().isMobilePhone('any').withMessage('Invalid phone number'),
  ],
  voterController.updateVoterProfile.bind(voterController)
);

/**
 * @route   POST /api/voters/profile/picture
 * @desc    Upload voter profile picture
 * @access  Private (Voter)
 */
router.post(
  '/profile/picture',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  uploadRateLimit,
  voterController.uploadProfilePicture.bind(voterController)
);

/**
 * @route   GET /api/voters/eligibility/:electionId
 * @desc    Check voter eligibility for an election
 * @access  Private (Voter)
 */
router.get(
  '/eligibility/:electionId',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  voterController.checkElectionEligibility.bind(voterController)
);

/**
 * @route   GET /api/voters/voting-history
 * @desc    Get voter's voting history
 * @access  Private (Voter)
 */
router.get(
  '/voting-history',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  voterController.getVotingHistory.bind(voterController)
);

/**
 * @route   POST /api/voters/resend-verification
 * @desc    Resend email verification
 * @access  Private (Voter)
 */
router.post(
  '/resend-verification',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  voterController.resendEmailVerification.bind(voterController)
);

/**
 * @route   GET /api/voters/preferences
 * @desc    Get voter preferences
 * @access  Private (Voter)
 */
router.get(
  '/preferences',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  voterController.getPreferences.bind(voterController)
);

/**
 * @route   PUT /api/voters/preferences
 * @desc    Update voter preferences
 * @access  Private (Voter)
 */
router.put(
  '/preferences',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  [
    body('emailNotifications').optional().isBoolean().withMessage('emailNotifications must be a boolean'),
    body('smsNotifications').optional().isBoolean().withMessage('smsNotifications must be a boolean'),
  ],
  voterController.updatePreferences.bind(voterController)
);

// ============================================================================
// ADMIN ROUTES
// ============================================================================

/**
 * @route   GET /api/voters/statistics
 * @desc    Get voter statistics
 * @access  Private (Admin/Moderator)
 */
router.get(
  '/statistics',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
  ],
  voterController.getVoterStatistics.bind(voterController)
);

/**
 * @route   GET /api/voters/search
 * @desc    Search voters with filters
 * @access  Private (Admin/Moderator)
 */
router.get(
  '/search',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    query('search').optional().isString().withMessage('Search must be a string'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  ],
  voterController.searchVoters.bind(voterController)
);

/**
 * @route   GET /api/voters/:id
 * @desc    Get voter by ID
 * @access  Private (Admin/Moderator)
 */
router.get(
  '/:id',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid voter ID is required'),
  ],
  voterController.getVoterById.bind(voterController)
);

/**
 * @route   PUT /api/voters/:id/status
 * @desc    Update voter status
 * @access  Private (Admin)
 */
router.put(
  '/:id/status',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid voter ID is required'),
    body('isActive').isBoolean().withMessage('isActive must be a boolean'),
    body('reason').optional().isString().withMessage('Reason must be a string'),
  ],
  voterController.updateVoterStatus.bind(voterController)
);

/**
 * @route   POST /api/voters/import
 * @desc    Import voters from file
 * @access  Private (Admin)
 */
router.post(
  '/import',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  bulkRateLimit,
  voterController.importVoters.bind(voterController)
);

/**
 * @route   POST /api/voters/bulk-import
 * @desc    Bulk import voters from parsed JSON data
 * @access  Private (Admin)
 */
router.post(
  '/bulk-import',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  bulkRateLimit,
  [
    body('voters').isArray().withMessage('Voters must be an array'),
  ],
  voterController.bulkImportVoters.bind(voterController)
);

/**
 * @route   GET /api/voters/export
 * @desc    Export voters data
 * @access  Private (Admin)
 */
router.get(
  '/export',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    query('format').optional().isIn(['json', 'csv', 'xlsx']).withMessage('Invalid format'),
  ],
  voterController.exportVoters.bind(voterController)
);

/**
 * @route   POST /api/voters/bulk-operations
 * @desc    Perform bulk operations on voters
 * @access  Private (Admin)
 */
router.post(
  '/bulk-operations',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  bulkRateLimit,
  [
    body('operation').notEmpty().isIn(['activate', 'deactivate', 'delete']).withMessage('Invalid operation'),
    body('voterIds').isArray().withMessage('voterIds must be an array'),
  ],
  voterController.bulkVoterOperations.bind(voterController)
);

/**
 * @route   DELETE /api/voters/:id
 * @desc    Delete voter account
 * @access  Private (Super Admin only)
 */
router.delete(
  '/:id',
  authenticate,
  authorize('SUPER_ADMIN'),
  checkPermission('DELETE_VOTERS'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid voter ID is required'),
    body('reason').notEmpty().isString().isLength({ min: 10 }).withMessage('Reason must be at least 10 characters'),
  ],
  voterController.deleteVoter.bind(voterController)
);

/**
 * @route   GET /api/voters/analytics/report
 * @desc    Generate voter analytics report
 * @access  Private (Admin)
 */
router.get(
  '/analytics/report',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    query('period').optional().isIn(['day', 'week', 'month', 'year']).withMessage('Invalid period'),
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
  ],
  voterController.generateAnalyticsReport.bind(voterController)
);

export default router;
