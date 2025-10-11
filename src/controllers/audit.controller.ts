import { Request, Response, NextFunction } from 'express';
import { AuditService } from '../services/audit.service';
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
  ipAddress?: string;
  userAgent?: string;
}

export class AuditController {
  /**
   * Get audit logs with advanced filtering
   */
  public static async getAuditLogs(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view audit logs', 403);
      }

      const {
        userId,
        userRole: filterRole,
        category,
        action,
        severity,
        entityType,
        entityId,
        electionId,
        startDate,
        endDate,
        ipAddress,
        search,
        risk,
        flags,
        page = 1,
        limit = 50,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      const filters: any = {};
      if (userId) filters.userId = userId as string;
      if (filterRole) filters.userRole = filterRole as UserRole;
      if (category) filters.category = category as string;
      if (action) filters.action = action as string;
      if (severity) filters.severity = severity as string;
      if (entityType) filters.entityType = entityType as string;
      if (entityId) filters.entityId = entityId as string;
      if (electionId) filters.electionId = electionId as string;
      if (ipAddress) filters.ipAddress = ipAddress as string;
      if (search) filters.search = search as string;
      if (risk) filters.risk = risk as string;
      if (flags) filters.flags = Array.isArray(flags) ? flags as string[] : [flags as string];

      if (startDate) filters.startDate = new Date(startDate as string);
      if (endDate) filters.endDate = new Date(endDate as string);

      const result = await AuditService.getAuditLogs(
        filters,
        Number(page),
        Number(limit),
        sortBy as string,
        sortOrder as 'asc' | 'desc'
      );

      // Log audit access
      await AuditService.logAction({
        action: 'AUDIT_LOGS_ACCESSED',
        category: 'AUDIT',
        severity: 'LOW',
        userId: req.user!.id,
        metadata: {
          filters,
          resultCount: result.auditLogs.length,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Audit logs retrieved successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get security events
   */
  public static async getSecurityEvents(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view security events', 403);
      }

      const {
        resolved,
        page = 1,
        limit = 20
      } = req.query;

      const filters: any = {};
      if (resolved !== undefined) filters.resolved = resolved === 'true';

      const result = await AuditService.getSecurityEvents(
        filters,
        Number(page),
        Number(limit)
      );

      // Log security events access
      await AuditService.logAction({
        action: 'SECURITY_EVENTS_ACCESSED',
        category: 'SECURITY',
        severity: 'MEDIUM',
        userId: req.user!.id,
        metadata: {
          filters,
          eventCount: result.events.length,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Security events retrieved successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate compliance report
   */
  public static async generateComplianceReport(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate compliance reports', 403);
      }

      const {
        startDate,
        endDate
      } = req.query;

      if (!startDate || !endDate) {
        throw new AppError('Start date and end date are required', 400);
      }

      const start = new Date(startDate as string);
      const end = new Date(endDate as string);

      if (start >= end) {
        throw new AppError('Start date must be before end date', 400);
      }

      const report = await AuditService.generateComplianceReport(start, end);

      // Log compliance report generation
      await AuditService.logAction({
        action: 'COMPLIANCE_REPORT_GENERATED',
        category: 'AUDIT',
        severity: 'HIGH',
        userId: req.user!.id,
        metadata: {
          reportPeriod: { start, end },
          totalActions: report.summary.totalActions,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Compliance report generated successfully',
        data: report,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get audit analytics
   */
  public static async getAuditAnalytics(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view audit analytics', 403);
      }

      const {
        startDate,
        endDate
      } = req.query;

      if (!startDate || !endDate) {
        throw new AppError('Start date and end date are required', 400);
      }

      const start = new Date(startDate as string);
      const end = new Date(endDate as string);

      if (start >= end) {
        throw new AppError('Start date must be before end date', 400);
      }

      const analytics = await AuditService.getAuditAnalytics(start, end);

      // Log analytics access
      await AuditService.logAction({
        action: 'AUDIT_ANALYTICS_ACCESSED',
        category: 'AUDIT',
        severity: 'LOW',
        userId: req.user!.id,
        metadata: {
          analyticsPeriod: { start, end },
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Audit analytics retrieved successfully',
        data: analytics,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Export audit logs
   */
  public static async exportAuditLogs(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to export audit logs', 403);
      }

      const {
        userId,
        category,
        action,
        severity,
        startDate,
        endDate,
        format = 'excel'
      } = req.query;

      const filters: any = {};
      if (userId) filters.userId = userId as string;
      if (category) filters.category = category as string;
      if (action) filters.action = action as string;
      if (severity) filters.severity = severity as string;
      if (startDate) filters.startDate = new Date(startDate as string);
      if (endDate) filters.endDate = new Date(endDate as string);

      if (!['json', 'excel', 'csv'].includes(format as string)) {
        throw new AppError('Invalid format. Supported: json, excel, csv', 400);
      }

      const exportData = await AuditService.exportAuditLogs(
        filters,
        format as 'json' | 'excel' | 'csv'
      );

      // Log audit export
      await AuditService.logAction({
        action: 'AUDIT_LOGS_EXPORTED',
        category: 'AUDIT',
        severity: 'HIGH',
        userId: req.user!.id,
        metadata: {
          filters,
          format,
          exportSize: Buffer.isBuffer(exportData) ? exportData.length : Array.isArray(exportData) ? exportData.length : 0,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (format === 'json') {
        res.json({
          success: true,
          message: 'Audit logs exported successfully',
          data: exportData,
        });
      } else {
        const fileExtension = format === 'excel' ? 'xlsx' : 'csv';
        const mimeType = format === 'excel'
          ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
          : 'text/csv';

        res.setHeader('Content-Type', mimeType);
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="audit_logs_${new Date().toISOString().split('T')[0]}.${fileExtension}"`
        );
        res.send(exportData);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Cleanup old audit logs
   */
  public static async cleanupOldLogs(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (userRole !== 'SUPER_ADMIN') {
        throw new AppError('Only Super Admins can cleanup audit logs', 403);
      }

      const result = await AuditService.cleanupOldLogs();

      // Log cleanup action
      await AuditService.logAction({
        action: 'AUDIT_LOGS_CLEANUP',
        category: 'SYSTEM',
        severity: 'HIGH',
        userId: req.user!.id,
        metadata: {
          deletedCount: result.deleted,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Audit logs cleanup completed successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify audit integrity
   */
  public static async verifyAuditIntegrity(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to verify audit integrity', 403);
      }

      const result = await AuditService.verifyAuditIntegrity();

      // Log integrity check
      await AuditService.logAction({
        action: 'AUDIT_INTEGRITY_CHECK',
        category: 'AUDIT',
        severity: 'MEDIUM',
        userId: req.user!.id,
        metadata: {
          integrityScore: result.integrityScore,
          totalLogs: result.totalLogs,
          corruptedLogs: result.corruptedLogs,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Audit integrity verification completed',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get audit log details by ID
   */
  public static async getAuditLogDetails(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view audit log details', 403);
      }

      const { logId } = req.params;

      if (!logId) {
        throw new AppError('Audit log ID is required', 400);
      }

      // Get specific audit log with related data
      const auditLog = await AuditService.getAuditLogs(
        { entityId: logId },
        1,
        1
      );

      if (!auditLog.auditLogs || auditLog.auditLogs.length === 0) {
        throw new AppError('Audit log not found', 404);
      }

      // Log access to specific audit log
      await AuditService.logAction({
        action: 'AUDIT_LOG_ACCESSED',
        category: 'AUDIT',
        severity: 'LOW',
        userId: req.user!.id,
        entityType: 'AuditLog',
        entityId: logId,
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Audit log details retrieved successfully',
        data: auditLog.auditLogs[0],
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Create manual audit entry (Admin only)
   */
  public static async createManualAuditEntry(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
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

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to create manual audit entries', 403);
      }

      const {
        action,
        category,
        severity,
        entityType,
        entityId,
        electionId,
        description,
        metadata
      } = req.body;

      if (!action || !category || !severity) {
        throw new AppError('Action, category, and severity are required', 400);
      }

      const auditEntry = await AuditService.logAction({
        action,
        category,
        severity,
        userId: req.user!.id,
        entityType,
        entityId,
        electionId,
        metadata: {
          ...metadata,
          description,
          manualEntry: true,
          createdBy: req.user!.id,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.status(201).json({
        success: true,
        message: 'Manual audit entry created successfully',
        data: {
          id: auditEntry.id,
          action: auditEntry.action,
          category: auditEntry.category,
          severity: auditEntry.severity,
          timestamp: auditEntry.createdAt,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get audit statistics summary
   */
  public static async getAuditStatistics(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view audit statistics', 403);
      }

      const {
        startDate,
        endDate
      } = req.query;

      const start = startDate ? new Date(startDate as string) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const end = endDate ? new Date(endDate as string) : new Date();

      // Get basic audit statistics
      const analytics = await AuditService.getAuditAnalytics(start, end);

      const statistics = {
        period: { start, end },
        summary: {
          totalLogs: analytics.activityTrends.reduce((sum, trend) => sum + trend.count, 0),
          averageDailyActivity: analytics.activityTrends.length > 0
            ? analytics.activityTrends.reduce((sum, trend) => sum + trend.count, 0) / analytics.activityTrends.length
            : 0,
          securityEvents: analytics.securityAnalysis.failedLogins + analytics.securityAnalysis.suspiciousIPs.length,
          mostActiveHour: analytics.userBehaviorAnalysis.accessPatterns.reduce(
            (max, pattern) => pattern.count > max.count ? pattern : max,
            { hour: 0, count: 0 }
          ).hour,
        },
        trends: analytics.activityTrends,
        security: analytics.securityAnalysis,
        dataIntegrity: analytics.dataIntegrity,
      };

      res.json({
        success: true,
        message: 'Audit statistics retrieved successfully',
        data: statistics,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Resolve security event
   */
  public static async resolveSecurityEvent(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to resolve security events', 403);
      }

      const { eventId } = req.params;
      const { resolution, notes } = req.body;

      if (!eventId) {
        throw new AppError('Event ID is required', 400);
      }

      if (!resolution) {
        throw new AppError('Resolution is required', 400);
      }

      // Create resolution audit entry
      await AuditService.logAction({
        action: 'SECURITY_EVENT_RESOLVED',
        category: 'SECURITY',
        severity: 'MEDIUM',
        userId: req.user!.id,
        entityType: 'SecurityEvent',
        entityId: eventId,
        metadata: {
          resolution,
          notes,
          resolvedBy: req.user!.id,
          resolvedAt: new Date(),
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Security event resolved successfully',
        data: {
          eventId,
          resolution,
          resolvedBy: req.user!.id,
          resolvedAt: new Date(),
        },
      });
    } catch (error) {
      next(error);
    }
  }
}

export default AuditController;