import { Router } from 'express';
import { AuditController } from '../controllers/audit.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { body, query, param } from 'express-validator';
import { generalRateLimit } from '../middleware/rateLimit.middleware';

const router = Router();

/**
 * @route GET /api/audit/logs
 * @desc Get audit logs with advanced filtering
 * @access Admin, Super Admin, Moderator
 */
router.get(
  '/logs',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  generalRateLimit,
  [
    query('userId').optional().isUUID().withMessage('Invalid user ID format'),
    query('userRole').optional().isIn(['VOTER', 'ADMIN', 'SUPER_ADMIN', 'MODERATOR']).withMessage('Invalid user role'),
    query('category').optional().isString().trim().withMessage('Category must be a string'),
    query('action').optional().isString().trim().withMessage('Action must be a string'),
    query('severity').optional().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).withMessage('Invalid severity level'),
    query('entityType').optional().isString().trim().withMessage('Entity type must be a string'),
    query('entityId').optional().isString().trim().withMessage('Entity ID must be a string'),
    query('electionId').optional().isUUID().withMessage('Invalid election ID format'),
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
    query('ipAddress').optional().isIP().withMessage('Invalid IP address format'),
    query('search').optional().isString().trim().isLength({ min: 2, max: 100 }).withMessage('Search term must be 2-100 characters'),
    query('risk').optional().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).withMessage('Invalid risk level'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('sortBy').optional().isIn(['createdAt', 'action', 'severity', 'category']).withMessage('Invalid sort field'),
    query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc'),
  ],
  AuditController.getAuditLogs
);

/**
 * @route GET /api/audit/security-events
 * @desc Get security events
 * @access Admin, Super Admin
 */
router.get(
  '/security-events',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    query('resolved').optional().isBoolean().withMessage('Resolved must be a boolean'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50'),
  ],
  AuditController.getSecurityEvents
);

/**
 * @route GET /api/audit/compliance-report
 * @desc Generate compliance report
 * @access Admin, Super Admin
 */
router.get(
  '/compliance-report',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    query('startDate').notEmpty().isISO8601().withMessage('Valid start date is required'),
    query('endDate').notEmpty().isISO8601().withMessage('Valid end date is required'),
  ],
  AuditController.generateComplianceReport
);

/**
 * @route GET /api/audit/analytics
 * @desc Get audit analytics
 * @access Admin, Super Admin
 */
router.get(
  '/analytics',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    query('startDate').notEmpty().isISO8601().withMessage('Valid start date is required'),
    query('endDate').notEmpty().isISO8601().withMessage('Valid end date is required'),
  ],
  AuditController.getAuditAnalytics
);

/**
 * @route GET /api/audit/export
 * @desc Export audit logs
 * @access Admin, Super Admin
 */
router.get(
  '/export',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    query('userId').optional().isUUID().withMessage('Invalid user ID format'),
    query('category').optional().isString().trim().withMessage('Category must be a string'),
    query('action').optional().isString().trim().withMessage('Action must be a string'),
    query('severity').optional().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).withMessage('Invalid severity level'),
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
    query('format').optional().isIn(['json', 'excel', 'csv']).withMessage('Invalid format. Supported: json, excel, csv'),
  ],
  AuditController.exportAuditLogs
);

/**
 * @route POST /api/audit/cleanup
 * @desc Cleanup old audit logs
 * @access Super Admin only
 */
router.post(
  '/cleanup',
  authenticate,
  authorize('SUPER_ADMIN'),
  generalRateLimit,
  AuditController.cleanupOldLogs
);

/**
 * @route GET /api/audit/integrity
 * @desc Verify audit integrity
 * @access Admin, Super Admin
 */
router.get(
  '/integrity',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  AuditController.verifyAuditIntegrity
);

/**
 * @route GET /api/audit/logs/:logId
 * @desc Get specific audit log details
 * @access Admin, Super Admin, Moderator
 */
router.get(
  '/logs/:logId',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  generalRateLimit,
  [
    param('logId').notEmpty().isUUID().withMessage('Valid audit log ID is required'),
  ],
  AuditController.getAuditLogDetails
);

/**
 * @route POST /api/audit/manual-entry
 * @desc Create manual audit entry
 * @access Admin, Super Admin
 */
router.post(
  '/manual-entry',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    body('action').notEmpty().isString().trim().isLength({ min: 3, max: 100 }).withMessage('Action is required and must be 3-100 characters'),
    body('category').notEmpty().isString().trim().isLength({ min: 3, max: 50 }).withMessage('Category is required and must be 3-50 characters'),
    body('severity').notEmpty().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).withMessage('Valid severity level is required'),
    body('entityType').optional().isString().trim().isLength({ max: 50 }).withMessage('Entity type must be max 50 characters'),
    body('entityId').optional().isString().trim().withMessage('Entity ID must be a string'),
    body('electionId').optional().isUUID().withMessage('Invalid election ID format'),
    body('description').optional().isString().trim().isLength({ max: 500 }).withMessage('Description must be max 500 characters'),
    body('metadata').optional().isObject().withMessage('Metadata must be an object'),
  ],
  AuditController.createManualAuditEntry
);

/**
 * @route GET /api/audit/statistics
 * @desc Get audit statistics summary
 * @access Admin, Super Admin, Moderator
 */
router.get(
  '/statistics',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  generalRateLimit,
  [
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
  ],
  AuditController.getAuditStatistics
);

/**
 * @route POST /api/audit/security-events/:eventId/resolve
 * @desc Resolve security event
 * @access Admin, Super Admin
 */
router.post(
  '/security-events/:eventId/resolve',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    param('eventId').notEmpty().isUUID().withMessage('Valid event ID is required'),
    body('resolution').notEmpty().isString().trim().isLength({ min: 10, max: 1000 }).withMessage('Resolution is required and must be 10-1000 characters'),
    body('notes').optional().isString().trim().isLength({ max: 2000 }).withMessage('Notes must be max 2000 characters'),
  ],
  AuditController.resolveSecurityEvent
);

export default router;
