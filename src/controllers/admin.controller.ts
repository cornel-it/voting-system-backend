// backend/src/controllers/admin.controller.ts

import { Request, Response, NextFunction } from 'express';
import { AdminService } from '../services/admin.service';
import { AuditService } from '../services/audit.service';
import { NotificationService } from '../services/notification.service';
import { AppError } from '../utils/errors';
import { UserRole } from '@prisma/client';
import { validationResult } from 'express-validator';

interface AuthRequest extends Request {
  user?: {
    id: string;
    studentId: string;
    role: UserRole;
    permissions: string[];
  };
}

export class AdminController {
  /**
   * Get system statistics (Admin/Super Admin only)
   */
  async getSystemStats(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view system statistics', 403);
      }

      const stats = await AdminService.getSystemStats();

      res.json({
        success: true,
        message: 'System statistics retrieved successfully',
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Create admin user (Super Admin only)
   */
  async createAdminUser(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const userRole = req.user!.role;
      const createdBy = req.user!.id;

      if (userRole !== 'SUPER_ADMIN') {
        throw new AppError('Only Super Admins can create admin users', 403);
      }

      const userData = req.body;

      // Validate role assignment permissions
      if (userData.role === 'SUPER_ADMIN' && userRole !== 'SUPER_ADMIN') {
        throw new AppError('Cannot create Super Admin users', 403);
      }

      const newAdmin = await AdminService.createAdminUser(userData, createdBy);

      await AuditService.logAction({
        action: 'ADMIN_USER_CREATED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: createdBy,
        metadata: {
          newAdminId: newAdmin.id,
          newAdminRole: userData.role,
          newAdminEmail: userData.email
        }
      });

      res.status(201).json({
        success: true,
        message: 'Admin user created successfully',
        data: {
          id: newAdmin.id,
          studentId: newAdmin.studentId,
          email: newAdmin.email,
          firstName: newAdmin.firstName,
          lastName: newAdmin.lastName,
          role: newAdmin.role,
          isActive: newAdmin.isActive
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update user role and permissions (Super Admin only)
   */
  async updateUserRole(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { userId } = req.params;
      const { role, permissions } = req.body;
      const updatedBy = req.user!.id;
      const userRole = req.user!.role;

      if (userRole !== 'SUPER_ADMIN') {
        throw new AppError('Only Super Admins can update user roles', 403);
      }

      if (!userId) {
        throw new AppError('User ID is required', 400);
      }

      const updatedUser = await AdminService.updateUserRole(userId, role, permissions, updatedBy);

      await AuditService.logAction({
        action: 'USER_ROLE_UPDATED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: updatedBy,
        metadata: {
          targetUserId: userId,
          newRole: role,
          newPermissions: permissions
        }
      });

      res.json({
        success: true,
        message: 'User role updated successfully',
        data: {
          id: updatedUser.id,
          role: updatedUser.role,
          permissions: updatedUser.permissions
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Bulk import users from Excel file (Admin only)
   */
  async importUsersFromExcel(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;
      const importedBy = req.user!.id;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to import users', 403);
      }

      if (!req.file) {
        throw new AppError('Excel file is required', 400);
      }

      const result = await AdminService.importUsersFromExcel(
        req.file.buffer,
        req.file.originalname,
        importedBy
      );

      await AuditService.logAction({
        action: 'BULK_USER_IMPORT',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: importedBy,
        metadata: {
          fileName: req.file.originalname,
          totalProcessed: result.totalProcessed,
          successful: result.successful,
          failed: result.failed,
          duplicates: result.duplicates
        }
      });

      res.json({
        success: true,
        message: 'User import completed',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get system audit logs (Admin only)
   */
  async getAuditLogs(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view audit logs', 403);
      }

      const {
        userId,
        category,
        severity,
        startDate,
        endDate,
        search,
        page = 1,
        limit = 50
      } = req.query;

      const filters: any = {};
      if (userId) filters.userId = userId as string;
      if (category) filters.category = category as string;
      if (severity) filters.severity = severity as string;
      if (startDate) filters.startDate = new Date(startDate as string);
      if (endDate) filters.endDate = new Date(endDate as string);
      if (search) filters.search = search as string;

      const result = await AdminService.getAuditLogs(
        filters,
        Number(page),
        Number(limit)
      );

      res.json({
        success: true,
        message: 'Audit logs retrieved successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Toggle user account status (Admin only)
   */
  async toggleUserStatus(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { userId } = req.params;
      const { isActive, reason } = req.body;
      const actionBy = req.user!.id;
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to modify user status', 403);
      }

      if (!userId) {
        throw new AppError('User ID is required', 400);
      }

      if (typeof isActive !== 'boolean') {
        throw new AppError('isActive must be a boolean value', 400);
      }

      const updatedUser = await AdminService.toggleUserStatus(userId, isActive, actionBy, reason);

      await AuditService.logAction({
        action: isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: actionBy,
        metadata: {
          targetUserId: userId,
          reason,
          newStatus: isActive
        }
      });

      res.json({
        success: true,
        message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
        data: {
          id: updatedUser.id,
          isActive: updatedUser.isActive
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate system report (Admin only)
   */
  async generateSystemReport(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;
      const generatedBy = req.user!.id;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate reports', 403);
      }

      const { reportType, format = 'json' } = req.query;
      const filters = req.body || {};

      if (!reportType || !['users', 'elections', 'votes', 'audit'].includes(reportType as string)) {
        throw new AppError('Invalid report type. Supported: users, elections, votes, audit', 400);
      }

      if (!['json', 'excel'].includes(format as string)) {
        throw new AppError('Invalid format. Supported: json, excel', 400);
      }

      const report = await AdminService.generateSystemReport(
        reportType as any,
        filters,
        format as any
      );

      await AuditService.logAction({
        action: 'SYSTEM_REPORT_GENERATED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: generatedBy,
        metadata: {
          reportType,
          format,
          recordCount: Array.isArray(report.data) ? report.data.length : 'N/A'
        }
      });

      if (format === 'excel') {
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${reportType}_report_${new Date().toISOString().split('T')[0]}.xlsx"`);
        res.send(report);
      } else {
        res.json({
          success: true,
          message: 'System report generated successfully',
          data: report
        });
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Clear system caches (Admin only)
   */
  async clearSystemCaches(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;
      const clearedBy = req.user!.id;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to clear caches', 403);
      }

      const { cacheType = 'all' } = req.body;

      if (!['all', 'users', 'elections', 'results', 'stats'].includes(cacheType)) {
        throw new AppError('Invalid cache type. Supported: all, users, elections, results, stats', 400);
      }

      const result = await AdminService.clearSystemCaches(cacheType, clearedBy);

      await AuditService.logAction({
        action: 'SYSTEM_CACHE_CLEARED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: clearedBy,
        metadata: {
          cacheType,
          keysCleared: result.cleared
        }
      });

      res.json({
        success: true,
        message: 'System caches cleared successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get admin dashboard overview (Admin only)
   */
  async getDashboardOverview(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view dashboard', 403);
      }

      // Get comprehensive dashboard data
      const [systemStats, recentAuditLogs] = await Promise.all([
        AdminService.getSystemStats(),
        AdminService.getAuditLogs({}, 1, 10) // Recent 10 activities
      ]);

      res.json({
        success: true,
        message: 'Dashboard overview retrieved successfully',
        data: {
          systemStats,
          recentActivity: recentAuditLogs.auditLogs,
          lastUpdated: new Date()
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Backup database (Super Admin only)
   */
  async backupDatabase(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;
      const initiatedBy = req.user!.id;

      if (userRole !== 'SUPER_ADMIN') {
        throw new AppError('Only Super Admins can initiate database backups', 403);
      }

      const { includePersonalData = false } = req.body;

      // This would typically integrate with your backup service
      const backup = await AdminService.initiateBackup({
        includePersonalData,
        initiatedBy
      });

      await AuditService.logAction({
        action: 'DATABASE_BACKUP_INITIATED',
        category: 'SYSTEM',
        severity: 'HIGH',
        userId: initiatedBy,
        metadata: {
          includePersonalData,
          backupId: backup.id
        }
      });

      res.json({
        success: true,
        message: 'Database backup initiated successfully',
        data: backup
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Send system notification to all users (Admin only)
   */
  async sendSystemNotification(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const userRole = req.user!.role;
      const sentBy = req.user!.id;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to send system notifications', 403);
      }

      const { title, message, type, priority, targetAudience } = req.body;

      if (!title || !message) {
        throw new AppError('Title and message are required', 400);
      }

      const result = await NotificationService.sendSystemNotification({
        title,
        message,
        type,
        priority,
        targetAudience,
        sentBy
      });

      await AuditService.logAction({
        action: 'SYSTEM_NOTIFICATION_SENT',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: sentBy,
        metadata: {
          title,
          type,
          priority,
          targetAudience,
          recipientCount: result.recipientCount
        }
      });

      res.json({
        success: true,
        message: 'System notification sent successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get system health status (Admin only)
   */
  async getSystemHealth(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view system health', 403);
      }

      const health = await AdminService.getSystemHealth();

      res.json({
        success: true,
        message: 'System health status retrieved successfully',
        data: {
          ...health,
          timestamp: new Date(),
          overallStatus: Object.values(health).every(status => status) ? 'healthy' : 'degraded'
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Emergency system shutdown (Super Admin only)
   */
  async emergencyShutdown(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;
      const initiatedBy = req.user!.id;

      if (userRole !== 'SUPER_ADMIN') {
        throw new AppError('Only Super Admins can initiate emergency shutdown', 403);
      }

      const { reason, duration } = req.body;

      if (!reason) {
        throw new AppError('Shutdown reason is required', 400);
      }

      const result = await AdminService.initiateEmergencyShutdown({
        reason,
        duration,
        initiatedBy
      });

      await AuditService.logAction({
        action: 'EMERGENCY_SHUTDOWN_INITIATED',
        category: 'SYSTEM',
        severity: 'CRITICAL',
        userId: initiatedBy,
        metadata: {
          reason,
          duration,
          shutdownId: result.id
        }
      });

      res.json({
        success: true,
        message: 'Emergency shutdown initiated successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }
}