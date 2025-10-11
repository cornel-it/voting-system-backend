// backend/src/controllers/notification.controller.ts

import { Request, Response, NextFunction } from 'express';
import { NotificationService } from '../services/notification.service';
import { AppError } from '../utils/errors';
import { UserRole, NotificationType } from '@prisma/client';
import { validationResult } from 'express-validator';

interface AuthRequest extends Request {
  user?: {
    id: string;
    studentId: string;
    role: UserRole;
    permissions: string[];
  };
}

export class NotificationController {

  /**
   * Get user notifications with pagination
   */
  static async getUserNotifications(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;
      const { page = 1, limit = 20, unreadOnly = false, type } = req.query;

      const pageNum = parseInt(page as string);
      const limitNum = parseInt(limit as string);
      const offset = (pageNum - 1) * limitNum;

      const notifications = await NotificationService.getUserNotifications(
        userId,
        {
          offset,
          limit: limitNum,
          read: unreadOnly === 'true' ? false : undefined,
          type: type as NotificationType | undefined
        }
      );

      res.json({
        success: true,
        data: notifications
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get notification summary for dashboard
   */
  static async getNotificationSummary(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;

      const summary = await NotificationService.getNotificationSummary(userId);

      res.json({
        success: true,
        data: summary
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Mark notification as read
   */
  static async markAsRead(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userId = req.user!.id;

      if (!id) {
        throw new AppError('Notification ID is required', 400);
      }

      await NotificationService.markNotificationAsRead(id, userId);

      res.json({
        success: true,
        message: 'Notification marked as read'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Mark multiple notifications as read
   */
  static async markMultipleAsRead(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { notificationIds } = req.body;
      const userId = req.user!.id;

      if (!notificationIds || !Array.isArray(notificationIds)) {
        throw new AppError('Notification IDs array is required', 400);
      }

      await NotificationService.markMultipleAsRead(notificationIds, userId);

      res.json({
        success: true,
        message: `${notificationIds.length} notifications marked as read`
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Mark all notifications as read
   */
  static async markAllAsRead(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;

      const count = await NotificationService.markAllAsRead(userId);

      res.json({
        success: true,
        message: `${count} notifications marked as read`
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Delete notification
   */
  static async deleteNotification(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userId = req.user!.id;

      if (!id) {
        throw new AppError('Notification ID is required', 400);
      }

      await NotificationService.deleteNotification(id, userId);

      res.json({
        success: true,
        message: 'Notification deleted successfully'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get notification preferences
   */
  static async getNotificationPreferences(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;

      const preferences = await NotificationService.getUserNotificationPreferences(userId);

      res.json({
        success: true,
        data: preferences
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update notification preferences
   */
  static async updateNotificationPreferences(req: AuthRequest, res: Response, next: NextFunction): Promise<Response | void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const userId = req.user!.id;
      const preferences = req.body;

      const updatedPreferences = await NotificationService.updateNotificationPreferences(
        userId,
        preferences
      );

      return res.json({
        success: true,
        message: 'Notification preferences updated successfully',
        data: updatedPreferences
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Admin only: Send system maintenance notification
   */
  static async sendMaintenanceNotification(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions', 403);
      }

      const { title, message, scheduledTime } = req.body;

      if (!title || !message) {
        throw new AppError('Title and message are required', 400);
      }

      await NotificationService.notifyAdminsSystemMaintenance(
        title,
        message,
        scheduledTime ? new Date(scheduledTime) : undefined
      );

      res.json({
        success: true,
        message: 'System maintenance notification sent successfully'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Admin only: Send security alert
   */
  static async sendSecurityAlert(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions', 403);
      }

      const { eventType, details, severity = 'MEDIUM' } = req.body;

      if (!eventType || !details) {
        throw new AppError('Event type and details are required', 400);
      }

      if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity)) {
        throw new AppError('Invalid severity level', 400);
      }

      await NotificationService.notifyAdminsSecurityEvent(
        eventType,
        details,
        severity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
      );

      res.json({
        success: true,
        message: 'Security alert sent successfully'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Admin only: Get notification statistics
   */
  static async getNotificationStats(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions', 403);
      }

      const stats = await NotificationService.getNotificationStatistics();

      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }
}