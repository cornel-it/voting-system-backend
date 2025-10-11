// backend/src/routes/candidate.routes.ts

import { Router } from 'express';
import { CandidateController } from '../controllers/candidate.controller';
import { AuditService } from '../services/audit.service';
import { NotificationService } from '../services/notification.service';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { generalRateLimit, uploadRateLimit } from '../middleware/rateLimit.middleware';
import { body, param, query } from 'express-validator';

const router = Router();
const candidateController = new CandidateController(AuditService, NotificationService);

// Public routes (no authentication required)
router.get(
  '/election/:electionId',
  generalRateLimit,
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  candidateController.getCandidatesByElection.bind(candidateController)
);

router.get(
  '/position/:positionId',
  generalRateLimit,
  [
    param('positionId').notEmpty().isUUID().withMessage('Valid position ID is required'),
  ],
  candidateController.getCandidatesByPosition.bind(candidateController)
);

router.get(
  '/:id',
  generalRateLimit,
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
  ],
  candidateController.getCandidateById.bind(candidateController)
);

// Student routes - Create and manage own candidate applications
router.post(
  '/',
  authenticate,
  [
    body('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
    body('positionId').notEmpty().isUUID().withMessage('Valid position ID is required'),
    body('manifesto').notEmpty().isString().withMessage('Manifesto is required'),
  ],
  candidateController.createCandidate.bind(candidateController)
);

router.put(
  '/:id/profile',
  authenticate,
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
    body('manifesto').optional().isString().withMessage('Manifesto must be a string'),
  ],
  candidateController.updateCandidateProfile.bind(candidateController)
);

router.post(
  '/:id/photo',
  authenticate,
  uploadRateLimit,
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
  ],
  candidateController.uploadCandidatePhoto.bind(candidateController)
);

router.post(
  '/:id/withdraw',
  authenticate,
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
    body('reason').notEmpty().isString().withMessage('Withdrawal reason is required'),
  ],
  candidateController.withdrawCandidate.bind(candidateController)
);

// Admin/Moderator routes - Candidate management
router.put(
  '/:id/approve',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
  ],
  candidateController.approveCandidate.bind(candidateController)
);

router.put(
  '/:id/reject',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
    body('reason').notEmpty().isString().withMessage('Rejection reason is required'),
  ],
  candidateController.rejectCandidate.bind(candidateController)
);

router.put(
  '/:id/disqualify',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
    body('reason').notEmpty().isString().withMessage('Disqualification reason is required'),
  ],
  candidateController.disqualifyCandidate.bind(candidateController)
);

router.put(
  '/:id/status',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
    body('status').notEmpty().isIn(['PENDING', 'APPROVED', 'REJECTED', 'DISQUALIFIED', 'WITHDRAWN']).withMessage('Valid status is required'),
  ],
  candidateController.updateCandidateStatus.bind(candidateController)
);

// Running mate management
router.post(
  '/:id/running-mate',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
    body('runningMateId').notEmpty().isUUID().withMessage('Valid running mate ID is required'),
  ],
  candidateController.addRunningMate.bind(candidateController)
);

router.delete(
  '/:id/running-mate',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('id').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
  ],
  candidateController.removeRunningMate.bind(candidateController)
);

// Statistics and analytics
router.get(
  '/election/:electionId/stats',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  candidateController.getCandidateStats.bind(candidateController)
);

router.get(
  '/election/:electionId/analytics',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
  ],
  candidateController.getCandidateAnalytics.bind(candidateController)
);

// Search and filtering (Admin only)
router.get(
  '/search/all',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  [
    query('search').optional().isString().withMessage('Search must be a string'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  ],
  candidateController.searchCandidates.bind(candidateController)
);

// Bulk operations (Admin only)
router.post(
  '/bulk/approve',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    body('candidateIds').isArray().withMessage('Candidate IDs must be an array'),
  ],
  candidateController.bulkApproveCandidate.bind(candidateController)
);

router.post(
  '/bulk/reject',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    body('candidateIds').isArray().withMessage('Candidate IDs must be an array'),
    body('reason').notEmpty().isString().withMessage('Rejection reason is required'),
  ],
  candidateController.bulkRejectCandidate.bind(candidateController)
);

// Data export (Admin only)
router.get(
  '/election/:electionId/export',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
    query('format').optional().isIn(['json', 'csv', 'xlsx']).withMessage('Invalid format'),
  ],
  candidateController.exportCandidates.bind(candidateController)
);

export default router;
