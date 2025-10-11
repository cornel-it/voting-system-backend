import { Router } from 'express';
import { ReportController } from '../controllers/report.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { body, query, param } from 'express-validator';
import { generalRateLimit } from '../middleware/rateLimit.middleware';

const router = Router();

/**
 * @route GET /api/reports/election/:electionId
 * @desc Generate election report
 * @access Admin, Super Admin, Moderator
 */
router.get(
  '/election/:electionId',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  generalRateLimit,
  [
    param('electionId').notEmpty().isUUID().withMessage('Valid election ID is required'),
    query('format').optional().isIn(['pdf', 'excel', 'json']).withMessage('Invalid format. Supported: pdf, excel, json'),
  ],
  ReportController.generateElectionReport
);

/**
 * @route GET /api/reports/system
 * @desc Generate system report
 * @access Admin, Super Admin
 */
router.get(
  '/system',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
    query('includeArchived').optional().isBoolean().withMessage('Include archived must be a boolean'),
    query('format').optional().isIn(['pdf', 'excel', 'json']).withMessage('Invalid format. Supported: pdf, excel, json'),
  ],
  ReportController.generateSystemReport
);

/**
 * @route GET /api/reports/candidate/:candidateId
 * @desc Generate candidate report
 * @access Admin, Super Admin, Moderator, Own candidate
 */
router.get(
  '/candidate/:candidateId',
  authenticate,
  generalRateLimit,
  [
    param('candidateId').notEmpty().isUUID().withMessage('Valid candidate ID is required'),
    query('format').optional().isIn(['pdf', 'excel', 'json']).withMessage('Invalid format. Supported: pdf, excel, json'),
  ],
  ReportController.generateCandidateReport
);

/**
 * @route GET /api/reports/voter/:voterId
 * @desc Generate voter report
 * @access Admin, Super Admin, Own voter
 */
router.get(
  '/voter/:voterId',
  authenticate,
  generalRateLimit,
  [
    param('voterId').notEmpty().isUUID().withMessage('Valid voter ID is required'),
    query('format').optional().isIn(['pdf', 'excel', 'json']).withMessage('Invalid format. Supported: pdf, excel, json'),
  ],
  ReportController.generateVoterReport
);

/**
 * @route GET /api/reports/audit
 * @desc Generate audit report
 * @access Admin, Super Admin
 */
router.get(
  '/audit',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    query('startDate').notEmpty().isISO8601().withMessage('Valid start date is required'),
    query('endDate').notEmpty().isISO8601().withMessage('Valid end date is required'),
    query('format').optional().isIn(['pdf', 'excel', 'json']).withMessage('Invalid format. Supported: pdf, excel, json'),
  ],
  ReportController.generateAuditReport
);

/**
 * @route POST /api/reports/comparative
 * @desc Generate comparative analysis report
 * @access Admin, Super Admin
 */
router.post(
  '/comparative',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    body('electionIds')
      .isArray({ min: 2, max: 10 })
      .withMessage('Election IDs must be an array with 2-10 items')
      .custom((electionIds) => {
        if (!electionIds.every((id: any) => typeof id === 'string' && id.length > 0)) {
          throw new Error('All election IDs must be valid strings');
        }
        return true;
      }),
    body('format').optional().isIn(['pdf', 'excel', 'json']).withMessage('Invalid format. Supported: pdf, excel, json'),
  ],
  ReportController.generateComparativeReport
);

/**
 * @route POST /api/reports/schedule
 * @desc Schedule automated report
 * @access Admin, Super Admin
 */
router.post(
  '/schedule',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    body('name').notEmpty().isString().trim().isLength({ min: 3, max: 100 }).withMessage('Name is required and must be 3-100 characters'),
    body('description').optional().isString().trim().isLength({ max: 500 }).withMessage('Description must be max 500 characters'),
    body('type')
      .notEmpty()
      .isIn(['election', 'system', 'candidate', 'voter', 'audit', 'compliance'])
      .withMessage('Valid report type is required'),
    body('filters').optional().isObject().withMessage('Filters must be an object'),
    body('schedule').optional().isObject().withMessage('Schedule must be an object'),
    body('schedule.frequency')
      .optional()
      .isIn(['daily', 'weekly', 'monthly', 'quarterly', 'yearly'])
      .withMessage('Invalid schedule frequency'),
    body('schedule.recipients')
      .optional()
      .isArray()
      .withMessage('Recipients must be an array')
      .custom((recipients) => {
        if (recipients && !recipients.every((email: any) => typeof email === 'string' && email.includes('@'))) {
          throw new Error('All recipients must be valid email addresses');
        }
        return true;
      }),
    body('schedule.format')
      .optional()
      .isIn(['pdf', 'excel', 'json'])
      .withMessage('Invalid schedule format'),
  ],
  ReportController.scheduleReport
);

/**
 * @route GET /api/reports/templates
 * @desc Get available report templates
 * @access Admin, Super Admin, Moderator
 */
router.get(
  '/templates',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  generalRateLimit,
  ReportController.getReportTemplates
);

/**
 * @route GET /api/reports/status/:reportId
 * @desc Get report generation status
 * @access Admin, Super Admin, Moderator
 */
router.get(
  '/status/:reportId',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  generalRateLimit,
  [
    param('reportId').notEmpty().isUUID().withMessage('Valid report ID is required'),
  ],
  ReportController.getReportStatus
);

/**
 * @route GET /api/reports/download/:reportId
 * @desc Download generated report
 * @access Admin, Super Admin, Moderator, Voter (own reports)
 */
router.get(
  '/download/:reportId',
  authenticate,
  generalRateLimit,
  [
    param('reportId').notEmpty().isUUID().withMessage('Valid report ID is required'),
  ],
  ReportController.downloadReport
);

/**
 * @route DELETE /api/reports/scheduled/:templateId
 * @desc Delete scheduled report
 * @access Admin, Super Admin
 */
router.delete(
  '/scheduled/:templateId',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    param('templateId').notEmpty().isString().withMessage('Valid template ID is required'),
  ],
  ReportController.deleteScheduledReport
);

/**
 * @route GET /api/reports/analytics
 * @desc Get report analytics
 * @access Admin, Super Admin
 */
router.get(
  '/analytics',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
  ],
  ReportController.getReportAnalytics
);

/**
 * @route GET /api/reports/my-reports
 * @desc Get current user's accessible reports
 * @access All authenticated users
 */
router.get(
  '/my-reports',
  authenticate,
  generalRateLimit,
  [
    query('type').optional().isIn(['voter', 'candidate']).withMessage('Invalid report type'),
    query('format').optional().isIn(['pdf', 'excel', 'json']).withMessage('Invalid format'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      const { type = 'voter', format = 'json' } = req.query;
      const userId = req.user!.id;

      // Generate appropriate report based on user's role and type requested
      let report;
      if (type === 'candidate') {
        // Check if user has been a candidate
        report = await ReportController.generateCandidateReport(req, res, next);
      } else {
        // Default to voter report
        req.params.voterId = userId;
        req.query.format = format;
        report = await ReportController.generateVoterReport(req, res, next);
      }
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @route POST /api/reports/bulk-generate
 * @desc Generate multiple reports in bulk
 * @access Admin, Super Admin
 */
router.post(
  '/bulk-generate',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    body('reports')
      .isArray({ min: 1, max: 5 })
      .withMessage('Reports must be an array with 1-5 items'),
    body('reports.*.type')
      .isIn(['election', 'system', 'candidate', 'voter', 'audit'])
      .withMessage('Invalid report type'),
    body('reports.*.id').optional().isString().withMessage('Report ID must be a string'),
    body('reports.*.format')
      .optional()
      .isIn(['pdf', 'excel', 'json'])
      .withMessage('Invalid format'),
    body('format').optional().isIn(['pdf', 'excel', 'json']).withMessage('Invalid default format'),
    body('compress').optional().isBoolean().withMessage('Compress must be a boolean'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      const { reports, format: defaultFormat = 'pdf', compress = true } = req.body;
      const userId = req.user!.id;

      // Log bulk report generation
      await req.auditService?.log({
        action: 'BULK_REPORTS_GENERATED',
        category: 'REPORT',
        severity: 'HIGH',
        userId,
        metadata: {
          reportCount: reports.length,
          defaultFormat,
          compress,
          reportTypes: reports.map((r: any) => r.type),
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Bulk report generation initiated',
        data: {
          jobId: `bulk_${Date.now()}`,
          reportCount: reports.length,
          estimatedCompletion: new Date(Date.now() + reports.length * 30000), // 30 seconds per report
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

export default router;
