// backend/src/routes/notification.routes.ts

import { Router } from 'express';
import { NotificationController } from '../controllers/notification.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { generalRateLimit } from '../middleware/rateLimit.middleware';
import { body, query, param } from 'express-validator';

const router = Router();

/**
 * @route GET /api/v1/notifications
 * @desc Get user notifications with pagination
 * @access Private
 */
router.get(
  '/',
  authenticate,
  generalRateLimit,
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('unreadOnly').optional().isBoolean().withMessage('unreadOnly must be a boolean'),
    query('type').optional().isIn(['ELECTION', 'SYSTEM', 'REMINDER', 'SECURITY', 'CAMPAIGN', 'CANDIDATE']).withMessage('Invalid notification type')
  ],
  NotificationController.getUserNotifications
);

/**
 * @route GET /api/v1/notifications/summary
 * @desc Get notification summary for dashboard
 * @access Private
 */
router.get(
  '/summary',
  authenticate,
  generalRateLimit,
  NotificationController.getNotificationSummary
);

/**
 * @route PUT /api/v1/notifications/:id/read
 * @desc Mark notification as read
 * @access Private
 */
router.put(
  '/:id/read',
  authenticate,
  generalRateLimit,
  [
    param('id').notEmpty().isUUID().withMessage('Valid notification ID is required'),
  ],
  NotificationController.markAsRead
);

/**
 * @route PUT /api/v1/notifications/read-multiple
 * @desc Mark multiple notifications as read
 * @access Private
 */
router.put(
  '/read-multiple',
  authenticate,
  generalRateLimit,
  [
    body('notificationIds')
      .isArray({ min: 1, max: 50 })
      .withMessage('notificationIds must be an array with 1-50 items'),
    body('notificationIds.*')
      .isUUID()
      .withMessage('Each notification ID must be a valid UUID')
  ],
  NotificationController.markMultipleAsRead
);

/**
 * @route PUT /api/v1/notifications/read-all
 * @desc Mark all notifications as read
 * @access Private
 */
router.put(
  '/read-all',
  authenticate,
  generalRateLimit,
  NotificationController.markAllAsRead
);

/**
 * @route DELETE /api/v1/notifications/:id
 * @desc Delete notification
 * @access Private
 */
router.delete(
  '/:id',
  authenticate,
  generalRateLimit,
  [
    param('id').notEmpty().isUUID().withMessage('Valid notification ID is required'),
  ],
  NotificationController.deleteNotification
);

/**
 * @route GET /api/v1/notifications/preferences
 * @desc Get notification preferences
 * @access Private
 */
router.get(
  '/preferences',
  authenticate,
  generalRateLimit,
  NotificationController.getNotificationPreferences
);

/**
 * @route PUT /api/v1/notifications/preferences
 * @desc Update notification preferences
 * @access Private
 */
router.put(
  '/preferences',
  authenticate,
  generalRateLimit,
  [
    body('emailNotifications').optional().isBoolean().withMessage('emailNotifications must be a boolean'),
    body('smsNotifications').optional().isBoolean().withMessage('smsNotifications must be a boolean'),
    body('pushNotifications').optional().isBoolean().withMessage('pushNotifications must be a boolean'),
    body('notificationTypes').optional().isArray().withMessage('notificationTypes must be an array'),
    body('notificationTypes.*').optional().isIn(['ELECTION', 'SYSTEM', 'REMINDER', 'SECURITY', 'CAMPAIGN', 'CANDIDATE']).withMessage('Invalid notification type')
  ],
  NotificationController.updateNotificationPreferences
);

// Admin only routes
/**
 * @route POST /api/v1/notifications/admin/maintenance
 * @desc Send system maintenance notification (Admin only)
 * @access Private (Admin/Super Admin)
 */
router.post(
  '/admin/maintenance',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    body('title').notEmpty().isLength({ min: 5, max: 100 }).withMessage('Title must be 5-100 characters'),
    body('message').notEmpty().isLength({ min: 10, max: 500 }).withMessage('Message must be 10-500 characters'),
    body('scheduledTime').optional().isISO8601().withMessage('scheduledTime must be a valid ISO 8601 date')
  ],
  NotificationController.sendMaintenanceNotification
);

/**
 * @route POST /api/v1/notifications/admin/security-alert
 * @desc Send security alert (Admin only)
 * @access Private (Admin/Super Admin)
 */
router.post(
  '/admin/security-alert',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN'),
  generalRateLimit,
  [
    body('eventType').notEmpty().isLength({ min: 5, max: 100 }).withMessage('Event type must be 5-100 characters'),
    body('details').isObject().withMessage('Details must be an object'),
    body('severity').optional().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).withMessage('Invalid severity level')
  ],
  NotificationController.sendSecurityAlert
);

/**
 * @route GET /api/v1/notifications/admin/stats
 * @desc Get notification statistics (Admin/Moderator only)
 * @access Private (Admin/Super Admin/Moderator)
 */
router.get(
  '/admin/stats',
  authenticate,
  authorize('ADMIN', 'SUPER_ADMIN', 'MODERATOR'),
  generalRateLimit,
  NotificationController.getNotificationStats
);

export default router;
