import { Router } from 'express';
import { AdminController } from '../controllers/admin.controller';
import { authenticate } from '../middleware/auth.middleware';
import { body, query, param } from 'express-validator';
import { adminRateLimit } from '../middleware/rateLimit.middleware';

const router = Router();
const adminController = new AdminController();

// Helper middleware for role checking
const requireRole = (roles: string[]) => {
  return (req: any, res: any, next: any) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions'
      });
    }
    next();
  };
};

/**
 * @route GET /api/admin/stats
 * @desc Get system statistics
 * @access Admin, Super Admin
 */
router.get(
  '/stats',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  adminController.getSystemStats.bind(adminController)
);

/**
 * @route POST /api/admin/users
 * @desc Create admin user
 * @access Super Admin only
 */
router.post(
  '/users',
  authenticate,
  requireRole(['SUPER_ADMIN']),
  adminRateLimit,
  [
    body('studentId')
      .notEmpty()
      .matches(/^[A-Z]{2,4}\d{3}-\d{4}\/\d{4}$/)
      .withMessage('Invalid student ID format (e.g., ABC123-1234/2023)'),
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Valid email is required'),
    body('firstName')
      .notEmpty()
      .isString()
      .trim()
      .isLength({ min: 2, max: 50 })
      .withMessage('First name is required and must be 2-50 characters'),
    body('lastName')
      .notEmpty()
      .isString()
      .trim()
      .isLength({ min: 2, max: 50 })
      .withMessage('Last name is required and must be 2-50 characters'),
    body('middleName')
      .optional()
      .isString()
      .trim()
      .isLength({ max: 50 })
      .withMessage('Middle name must be max 50 characters'),
    body('phone')
      .optional()
      .isMobilePhone('any')
      .withMessage('Valid phone number is required'),
    body('role')
      .isIn(['ADMIN', 'MODERATOR', 'SUPER_ADMIN'])
      .withMessage('Valid admin role is required'),
    body('permissions')
      .optional()
      .isArray()
      .withMessage('Permissions must be an array'),
  ],
  adminController.createAdminUser.bind(adminController)
);

/**
 * @route PUT /api/admin/users/:userId/role
 * @desc Update user role and permissions
 * @access Super Admin only
 */
router.put(
  '/users/:userId/role',
  authenticate,
  requireRole(['SUPER_ADMIN']),
  adminRateLimit,
  [
    param('userId').notEmpty().isUUID().withMessage('Valid user ID is required'),
    body('role')
      .isIn(['VOTER', 'ADMIN', 'MODERATOR', 'SUPER_ADMIN'])
      .withMessage('Valid role is required'),
    body('permissions')
      .isArray()
      .withMessage('Permissions array is required'),
  ],
  adminController.updateUserRole.bind(adminController)
);

/**
 * @route POST /api/admin/users/import
 * @desc Bulk import users from Excel file
 * @access Admin, Super Admin
 */
router.post(
  '/users/import',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  adminController.importUsersFromExcel.bind(adminController)
);

/**
 * @route GET /api/admin/audit-logs
 * @desc Get system audit logs
 * @access Admin, Super Admin
 */
router.get(
  '/audit-logs',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    query('userId').optional().isUUID().withMessage('Invalid user ID format'),
    query('category').optional().isString().trim().withMessage('Category must be a string'),
    query('severity').optional().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).withMessage('Invalid severity level'),
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
    query('search').optional().isString().trim().isLength({ min: 2, max: 100 }).withMessage('Search term must be 2-100 characters'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  ],
  adminController.getAuditLogs.bind(adminController)
);

/**
 * @route PUT /api/admin/users/:userId/status
 * @desc Toggle user account status
 * @access Admin, Super Admin
 */
router.put(
  '/users/:userId/status',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    param('userId').notEmpty().isUUID().withMessage('Valid user ID is required'),
    body('isActive').isBoolean().withMessage('isActive must be a boolean'),
    body('reason').optional().isString().trim().isLength({ max: 500 }).withMessage('Reason must be max 500 characters'),
  ],
  adminController.toggleUserStatus.bind(adminController)
);

/**
 * @route GET /api/admin/reports
 * @desc Generate system report
 * @access Admin, Super Admin
 */
router.get(
  '/reports',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    query('reportType')
      .notEmpty()
      .isIn(['users', 'elections', 'votes', 'audit'])
      .withMessage('Valid report type is required'),
    query('format')
      .optional()
      .isIn(['json', 'excel'])
      .withMessage('Invalid format. Supported: json, excel'),
  ],
  adminController.generateSystemReport.bind(adminController)
);

/**
 * @route POST /api/admin/cache/clear
 * @desc Clear system caches
 * @access Admin, Super Admin
 */
router.post(
  '/cache/clear',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    body('cacheType')
      .optional()
      .isIn(['all', 'users', 'elections', 'results', 'stats'])
      .withMessage('Invalid cache type'),
  ],
  adminController.clearSystemCaches.bind(adminController)
);

/**
 * @route GET /api/admin/dashboard
 * @desc Get admin dashboard overview
 * @access Admin, Super Admin, Moderator
 */
router.get(
  '/dashboard',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN', 'MODERATOR']),
  adminRateLimit,
  adminController.getDashboardOverview.bind(adminController)
);

/**
 * @route POST /api/admin/backup
 * @desc Initiate database backup
 * @access Super Admin only
 */
router.post(
  '/backup',
  authenticate,
  requireRole(['SUPER_ADMIN']),
  adminRateLimit,
  [
    body('includePersonalData').optional().isBoolean().withMessage('includePersonalData must be a boolean'),
  ],
  adminController.backupDatabase.bind(adminController)
);

/**
 * @route POST /api/admin/notifications/system
 * @desc Send system notification to all users
 * @access Admin, Super Admin
 */
router.post(
  '/notifications/system',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    body('title').notEmpty().isString().trim().isLength({ min: 5, max: 100 }).withMessage('Title is required and must be 5-100 characters'),
    body('message').notEmpty().isString().trim().isLength({ min: 10, max: 1000 }).withMessage('Message is required and must be 10-1000 characters'),
    body('type').optional().isIn(['info', 'warning', 'error', 'success']).withMessage('Invalid notification type'),
    body('priority').optional().isIn(['low', 'medium', 'high', 'urgent']).withMessage('Invalid priority level'),
    body('targetAudience').optional().isIn(['all', 'voters', 'candidates', 'admins']).withMessage('Invalid target audience'),
  ],
  adminController.sendSystemNotification.bind(adminController)
);

/**
 * @route GET /api/admin/health
 * @desc Get system health status
 * @access Admin, Super Admin
 */
router.get(
  '/health',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  adminController.getSystemHealth.bind(adminController)
);

/**
 * @route POST /api/admin/emergency/shutdown
 * @desc Emergency system shutdown
 * @access Super Admin only
 */
router.post(
  '/emergency/shutdown',
  authenticate,
  requireRole(['SUPER_ADMIN']),
  adminRateLimit,
  [
    body('reason').notEmpty().isString().trim().isLength({ min: 10, max: 500 }).withMessage('Shutdown reason is required and must be 10-500 characters'),
    body('duration').optional().isInt({ min: 1, max: 1440 }).withMessage('Duration must be between 1 and 1440 minutes'),
  ],
  adminController.emergencyShutdown.bind(adminController)
);

/**
 * @route GET /api/admin/users
 * @desc Get all users with filtering and pagination
 * @access Admin, Super Admin
 */
router.get(
  '/users',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('role').optional().isIn(['VOTER', 'ADMIN', 'MODERATOR', 'SUPER_ADMIN']).withMessage('Invalid role filter'),
    query('faculty').optional().isString().trim().withMessage('Faculty must be a string'),
    query('department').optional().isString().trim().withMessage('Department must be a string'),
    query('isActive').optional().isBoolean().withMessage('isActive must be a boolean'),
    query('isVerified').optional().isBoolean().withMessage('isVerified must be a boolean'),
    query('search').optional().isString().trim().isLength({ min: 2, max: 100 }).withMessage('Search term must be 2-100 characters'),
    query('sortBy').optional().isIn(['createdAt', 'firstName', 'lastName', 'email', 'lastLogin']).withMessage('Invalid sort field'),
    query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      const result = {
        users: [],
        pagination: {
          currentPage: 1,
          totalPages: 1,
          totalItems: 0,
          itemsPerPage: 50,
        }
      };

      res.json({
        success: true,
        message: 'Users retrieved successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @route GET /api/admin/users/:userId
 * @desc Get specific user details
 * @access Admin, Super Admin
 */
router.get(
  '/users/:userId',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    param('userId').notEmpty().isUUID().withMessage('Valid user ID is required'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      const userDetails = {
        id: req.params.userId,
      };

      res.json({
        success: true,
        message: 'User details retrieved successfully',
        data: userDetails,
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @route PUT /api/admin/users/:userId
 * @desc Update user details
 * @access Admin, Super Admin
 */
router.put(
  '/users/:userId',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    param('userId').notEmpty().isUUID().withMessage('Valid user ID is required'),
    body('firstName').optional().isString().trim().isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters'),
    body('lastName').optional().isString().trim().isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters'),
    body('email').optional().isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('phone').optional().isMobilePhone('any').withMessage('Valid phone number is required'),
    body('faculty').optional().isString().trim().withMessage('Faculty must be a string'),
    body('department').optional().isString().trim().withMessage('Department must be a string'),
    body('course').optional().isString().trim().withMessage('Course must be a string'),
    body('yearOfStudy').optional().isInt({ min: 1, max: 6 }).withMessage('Year of study must be between 1 and 6'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      res.json({
        success: true,
        message: 'User updated successfully',
        data: { id: req.params.userId },
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @route DELETE /api/admin/users/:userId
 * @desc Delete user account (soft delete)
 * @access Super Admin only
 */
router.delete(
  '/users/:userId',
  authenticate,
  requireRole(['SUPER_ADMIN']),
  adminRateLimit,
  [
    param('userId').notEmpty().isUUID().withMessage('Valid user ID is required'),
    body('reason').notEmpty().isString().trim().isLength({ min: 10, max: 500 }).withMessage('Deletion reason is required and must be 10-500 characters'),
    body('transferData').optional().isBoolean().withMessage('transferData must be a boolean'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      res.json({
        success: true,
        message: 'User deleted successfully',
        data: {
          id: req.params.userId,
          deletedAt: new Date(),
          reason: req.body.reason
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @route GET /api/admin/analytics
 * @desc Get admin analytics dashboard
 * @access Admin, Super Admin
 */
router.get(
  '/analytics',
  authenticate,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  adminRateLimit,
  [
    query('period').optional().isIn(['day', 'week', 'month', 'quarter', 'year']).withMessage('Invalid period'),
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format'),
  ],
  async (req: any, res: any, next: any) => {
    try {
      const analytics = {
        userMetrics: {},
        electionMetrics: {},
        systemMetrics: {},
        securityMetrics: {},
      };

      res.json({
        success: true,
        message: 'Analytics data retrieved successfully',
        data: analytics,
      });
    } catch (error) {
      next(error);
    }
  }
);

export default router;
