// backend/src/routes/vote.routes.ts

import { Router } from 'express';
import { VoteController } from '../controllers/vote.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { votingRateLimit } from '../middleware/rateLimit.middleware';
import { body, param, query } from 'express-validator';

const router = Router();
const voteController = VoteController.getInstance();

// ============================================================================
// VOTING SESSION ROUTES
// ============================================================================

/**
 * POST /api/votes/sessions/start
 * Start a new voting session
 */
router.post(
  '/sessions/start',
  votingRateLimit,
  authenticate,
  authorize('VOTER'),
  [
    body('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
    body('deviceFingerprint').optional().isString().withMessage('Device fingerprint must be a string'),
  ],
  voteController.startVotingSession.bind(voteController)
);

/**
 * PUT /api/votes/sessions/:sessionId/end
 * End an active voting session
 */
router.put(
  '/sessions/:sessionId/end',
  authenticate,
  authorize('VOTER'),
  [
    param('sessionId').notEmpty().isUUID().withMessage('Valid session ID is required'),
    body('reason').optional().isString().withMessage('Reason must be a string'),
  ],
  voteController.endVotingSession.bind(voteController)
);

/**
 * GET /api/votes/sessions/:sessionId
 * Get voting session details
 */
router.get(
  '/sessions/:sessionId',
  authenticate,
  authorize('VOTER'),
  [
    param('sessionId').notEmpty().isUUID().withMessage('Valid session ID is required'),
  ],
  voteController.getVotingSession.bind(voteController)
);

/**
 * PUT /api/votes/sessions/:sessionId/extend
 * Extend voting session duration
 */
router.put(
  '/sessions/:sessionId/extend',
  authenticate,
  authorize('VOTER'),
  [
    param('sessionId').notEmpty().isUUID().withMessage('Valid session ID is required'),
    body('extensionMinutes').optional().isInt({ min: 5, max: 30 }).withMessage('Extension must be between 5 and 30 minutes'),
  ],
  voteController.extendVotingSession.bind(voteController)
);

/**
 * POST /api/votes/sessions/:sessionId/complete
 * Complete voting session and generate receipt
 */
router.post(
  '/sessions/:sessionId/complete',
  authenticate,
  authorize('VOTER'),
  [
    param('sessionId').notEmpty().isUUID().withMessage('Valid session ID is required'),
  ],
  voteController.completeVotingSession.bind(voteController)
);

// ============================================================================
// VOTING ROUTES
// ============================================================================

/**
 * POST /api/votes/cast
 * Cast votes for multiple positions
 */
router.post(
  '/cast',
  votingRateLimit,
  authenticate,
  authorize('VOTER'),
  [
    body('sessionId').notEmpty().isUUID().withMessage('Valid session ID is required'),
    body('ballot').isArray().withMessage('Ballot must be an array'),
    body('ballot.*.positionId').notEmpty().isUUID().withMessage('Valid position ID is required'),
    body('ballot.*.candidateId').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
    body('twoFactorToken').optional().isString().withMessage('Two-factor token must be a string'),
  ],
  voteController.castVote.bind(voteController)
);

/**
 * POST /api/votes/verify
 * Verify a vote using verification code
 */
router.post(
  '/verify',
  votingRateLimit,
  [
    body('verificationCode').notEmpty().isString().withMessage('Verification code is required'),
  ],
  voteController.verifyVote.bind(voteController)
);

/**
 * GET /api/votes/verify/:verificationCode/status
 * Get verification status without full verification
 */
router.get(
  '/verify/:verificationCode/status',
  votingRateLimit,
  [
    param('verificationCode').notEmpty().isString().withMessage('Verification code is required'),
  ],
  voteController.getVerificationStatus.bind(voteController)
);

/**
 * POST /api/votes/validate-ballot
 * Validate ballot structure before submission
 */
router.post(
  '/validate-ballot',
  authenticate,
  authorize('VOTER'),
  [
    body('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
    body('ballot').isArray().withMessage('Ballot must be an array'),
  ],
  voteController.validateBallot.bind(voteController)
);

// ============================================================================
// ELECTION AND BALLOT ROUTES
// ============================================================================

/**
 * GET /api/votes/elections/:electionId/ballot
 * Get election ballot for voting
 */
router.get(
  '/elections/:electionId/ballot',
  authenticate,
  authorize('VOTER'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  voteController.getElectionBallot.bind(voteController)
);

/**
 * GET /api/votes/elections/:electionId/status
 * Check if user has voted in an election
 */
router.get(
  '/elections/:electionId/status',
  authenticate,
  authorize('VOTER'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  voteController.checkVotingStatus.bind(voteController)
);

// ============================================================================
// RECEIPT AND VERIFICATION ROUTES
// ============================================================================

/**
 * GET /api/votes/receipts/:receiptHash
 * Get voting receipt using receipt hash
 */
router.get(
  '/receipts/:receiptHash',
  votingRateLimit,
  [
    param('receiptHash').notEmpty().isString().withMessage('Receipt hash is required'),
  ],
  voteController.getVoteReceipt.bind(voteController)
);

// ============================================================================
// USER VOTING HISTORY
// ============================================================================

/**
 * GET /api/votes/history
 * Get user's voting history
 */
router.get(
  '/history',
  authenticate,
  authorize('VOTER', 'ADMIN', 'SUPER_ADMIN'),
  [
    query('includeDetails').optional().isBoolean().withMessage('includeDetails must be a boolean'),
  ],
  voteController.getVoteHistory.bind(voteController)
);

// ============================================================================
// ISSUE REPORTING
// ============================================================================

/**
 * POST /api/votes/report-issue
 * Report voting issue
 */
router.post(
  '/report-issue',
  votingRateLimit,
  authenticate,
  authorize('VOTER'),
  [
    body('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
    body('sessionId').optional().isUUID().withMessage('Valid session ID required if provided'),
    body('issueType').notEmpty().isString().withMessage('Issue type is required'),
    body('description').notEmpty().isString().isLength({ min: 20 }).withMessage('Description must be at least 20 characters'),
  ],
  voteController.reportVotingIssue.bind(voteController)
);

// ============================================================================
// ADMIN ROUTES
// ============================================================================

/**
 * GET /api/votes/elections/:electionId/progress
 * Get voting progress for an election (Admin/Moderator only)
 */
router.get(
  '/elections/:electionId/progress',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  voteController.getVotingProgress.bind(voteController)
);

/**
 * GET /api/votes/elections/:electionId/stats/realtime
 * Get real-time voting statistics (Admin/Moderator only)
 */
router.get(
  '/elections/:electionId/stats/realtime',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  voteController.getRealTimeStats.bind(voteController)
);

/**
 * GET /api/votes/elections/:electionId/analytics
 * Get comprehensive voting analytics (Admin/Moderator only)
 */
router.get(
  '/elections/:electionId/analytics',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  voteController.getVotingAnalytics.bind(voteController)
);

/**
 * POST /api/votes/elections/:electionId/tally
 * Tally votes for an election (Admin only)
 */
router.post(
  '/elections/:electionId/tally',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
    query('includePartial').optional().isBoolean().withMessage('includePartial must be a boolean'),
  ],
  voteController.tallyVotes.bind(voteController)
);

/**
 * PUT /api/votes/:voteId/invalidate
 * Invalidate a vote (Admin only)
 */
router.put(
  '/:voteId/invalidate',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('voteId').notEmpty().isUUID().withMessage('Valid vote ID is required'),
    body('reason').notEmpty().isString().isLength({ min: 10 }).withMessage('Reason must be at least 10 characters'),
  ],
  voteController.invalidateVote.bind(voteController)
);

/**
 * GET /api/votes/elections/:electionId/emergency-options
 * Get emergency voting options (Admin only)
 */
router.get(
  '/elections/:electionId/emergency-options',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  voteController.getEmergencyVotingOptions.bind(voteController)
);

/**
 * GET /api/votes/elections/:electionId/export
 * Export voting data (Admin only)
 */
router.get(
  '/elections/:electionId/export',
  votingRateLimit,
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
    query('format').optional().isIn(['json', 'csv', 'xlsx']).withMessage('Invalid format'),
    query('includePersonalData').optional().isBoolean().withMessage('includePersonalData must be a boolean'),
  ],
  voteController.exportVotingData.bind(voteController)
);

export default router;
