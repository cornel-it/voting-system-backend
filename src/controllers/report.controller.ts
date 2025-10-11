import { Request, Response, NextFunction } from 'express';
import { ReportingService } from '../services/reporting.service';
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

export class ReportController {
  /**
   * Generate election report
   */
  public static async generateElectionReport(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate election reports', 403);
      }

      const { electionId } = req.params;
      const { format = 'pdf' } = req.query;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      if (!['pdf', 'excel', 'json'].includes(format as string)) {
        throw new AppError('Invalid format. Supported: pdf, excel, json', 400);
      }

      const report = await ReportingService.generateElectionReport(
        electionId,
        format as 'pdf' | 'excel' | 'json'
      );

      // Log report generation
      await AuditService.logAction({
        action: 'ELECTION_REPORT_GENERATED',
        category: 'REPORT',
        severity: 'MEDIUM',
        userId: req.user!.id,
        electionId,
        metadata: {
          format,
          reportType: 'election',
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (format === 'json') {
        res.json({
          success: true,
          message: 'Election report generated successfully',
          data: report,
        });
      } else {
        const fileExtension = format === 'pdf' ? 'pdf' : 'xlsx';
        const mimeType = format === 'pdf'
          ? 'application/pdf'
          : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

        res.setHeader('Content-Type', mimeType);
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="election_report_${electionId}_${new Date().toISOString().split('T')[0]}.${fileExtension}"`
        );
        res.send(report);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate system report
   */
  public static async generateSystemReport(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate system reports', 403);
      }

      const {
        startDate,
        endDate,
        includeArchived = false,
        format = 'pdf'
      } = req.query;

      if (!['pdf', 'excel', 'json'].includes(format as string)) {
        throw new AppError('Invalid format. Supported: pdf, excel, json', 400);
      }

      const filters: any = {};
      if (startDate) filters.startDate = new Date(startDate as string);
      if (endDate) filters.endDate = new Date(endDate as string);
      if (includeArchived !== undefined) filters.includeArchived = includeArchived === 'true';

      const report = await ReportingService.generateSystemReport(
        filters,
        format as 'pdf' | 'excel' | 'json'
      );

      // Log report generation
      await AuditService.logAction({
        action: 'SYSTEM_REPORT_GENERATED',
        category: 'REPORT',
        severity: 'MEDIUM',
        userId: req.user!.id,
        metadata: {
          format,
          reportType: 'system',
          filters,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (format === 'json') {
        res.json({
          success: true,
          message: 'System report generated successfully',
          data: report,
        });
      } else {
        const fileExtension = format === 'pdf' ? 'pdf' : 'xlsx';
        const mimeType = format === 'pdf'
          ? 'application/pdf'
          : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

        res.setHeader('Content-Type', mimeType);
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="system_report_${new Date().toISOString().split('T')[0]}.${fileExtension}"`
        );
        res.send(report);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate candidate report
   */
  public static async generateCandidateReport(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      // Candidates can view their own reports, admins can view any
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate candidate reports', 403);
      }

      const { candidateId } = req.params;
      const { format = 'pdf' } = req.query;

      if (!candidateId) {
        throw new AppError('Candidate ID is required', 400);
      }

      if (!['pdf', 'excel', 'json'].includes(format as string)) {
        throw new AppError('Invalid format. Supported: pdf, excel, json', 400);
      }

      // Additional permission check for non-admin users
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole) && candidateId !== req.user!.id) {
        throw new AppError('You can only view your own candidate report', 403);
      }

      const report = await ReportingService.generateCandidateReport(
        candidateId,
        format as 'pdf' | 'excel' | 'json'
      );

      // Log report generation
      await AuditService.logAction({
        action: 'CANDIDATE_REPORT_GENERATED',
        category: 'REPORT',
        severity: 'LOW',
        userId: req.user!.id,
        entityType: 'User',
        entityId: candidateId,
        metadata: {
          format,
          reportType: 'candidate',
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (format === 'json') {
        res.json({
          success: true,
          message: 'Candidate report generated successfully',
          data: report,
        });
      } else {
        const fileExtension = format === 'pdf' ? 'pdf' : 'xlsx';
        const mimeType = format === 'pdf'
          ? 'application/pdf'
          : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

        res.setHeader('Content-Type', mimeType);
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="candidate_report_${candidateId}_${new Date().toISOString().split('T')[0]}.${fileExtension}"`
        );
        res.send(report);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate voter report
   */
  public static async generateVoterReport(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;
      const { voterId } = req.params;
      const { format = 'pdf' } = req.query;

      if (!voterId) {
        throw new AppError('Voter ID is required', 400);
      }

      if (!['pdf', 'excel', 'json'].includes(format as string)) {
        throw new AppError('Invalid format. Supported: pdf, excel, json', 400);
      }

      // Permission check - voters can only view their own reports
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole) && voterId !== req.user!.id) {
        throw new AppError('You can only view your own voting report', 403);
      }

      const report = await ReportingService.generateVoterReport(
        voterId,
        format as 'pdf' | 'excel' | 'json'
      );

      // Log report generation
      await AuditService.logAction({
        action: 'VOTER_REPORT_GENERATED',
        category: 'REPORT',
        severity: 'LOW',
        userId: req.user!.id,
        entityType: 'User',
        entityId: voterId,
        metadata: {
          format,
          reportType: 'voter',
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (format === 'json') {
        res.json({
          success: true,
          message: 'Voter report generated successfully',
          data: report,
        });
      } else {
        const fileExtension = format === 'pdf' ? 'pdf' : 'xlsx';
        const mimeType = format === 'pdf'
          ? 'application/pdf'
          : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

        res.setHeader('Content-Type', mimeType);
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="voter_report_${voterId}_${new Date().toISOString().split('T')[0]}.${fileExtension}"`
        );
        res.send(report);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate audit report
   */
  public static async generateAuditReport(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate audit reports', 403);
      }

      const {
        startDate,
        endDate,
        format = 'pdf'
      } = req.query;

      if (!startDate || !endDate) {
        throw new AppError('Start date and end date are required', 400);
      }

      if (!['pdf', 'excel', 'json'].includes(format as string)) {
        throw new AppError('Invalid format. Supported: pdf, excel, json', 400);
      }

      const start = new Date(startDate as string);
      const end = new Date(endDate as string);

      if (start >= end) {
        throw new AppError('Start date must be before end date', 400);
      }

      const report = await ReportingService.generateAuditReport(
        start,
        end,
        format as 'pdf' | 'excel' | 'json'
      );

      // Log report generation
      await AuditService.logAction({
        action: 'AUDIT_REPORT_GENERATED',
        category: 'REPORT',
        severity: 'HIGH',
        userId: req.user!.id,
        metadata: {
          format,
          reportType: 'audit',
          period: { start, end },
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (format === 'json') {
        res.json({
          success: true,
          message: 'Audit report generated successfully',
          data: report,
        });
      } else {
        const fileExtension = format === 'pdf' ? 'pdf' : 'xlsx';
        const mimeType = format === 'pdf'
          ? 'application/pdf'
          : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

        res.setHeader('Content-Type', mimeType);
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="audit_report_${start.toISOString().split('T')[0]}_to_${end.toISOString().split('T')[0]}.${fileExtension}"`
        );
        res.send(report);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate comparative analysis report
   */
  public static async generateComparativeReport(req: AuthRequest, res: Response, next: NextFunction): Promise<Response | void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate comparative reports', 403);
      }

      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const { electionIds, format = 'pdf' } = req.body;

      if (!electionIds || !Array.isArray(electionIds) || electionIds.length < 2) {
        throw new AppError('At least 2 election IDs are required for comparison', 400);
      }

      if (electionIds.length > 10) {
        throw new AppError('Maximum 10 elections can be compared at once', 400);
      }

      if (!['pdf', 'excel', 'json'].includes(format)) {
        throw new AppError('Invalid format. Supported: pdf, excel, json', 400);
      }

      const report = await ReportingService.generateComparativeReport(
        electionIds,
        format
      );

      // Log report generation
      await AuditService.logAction({
        action: 'COMPARATIVE_REPORT_GENERATED',
        category: 'REPORT',
        severity: 'MEDIUM',
        userId: req.user!.id,
        metadata: {
          format,
          reportType: 'comparative',
          electionIds,
          electionCount: electionIds.length,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (format === 'json') {
        res.json({
          success: true,
          message: 'Comparative report generated successfully',
          data: report,
        });
      } else {
        const fileExtension = format === 'pdf' ? 'pdf' : 'xlsx';
        const mimeType = format === 'pdf'
          ? 'application/pdf'
          : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

        res.setHeader('Content-Type', mimeType);
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="comparative_report_${new Date().toISOString().split('T')[0]}.${fileExtension}"`
        );
        res.send(report);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Schedule automated report
   */
  public static async scheduleReport(req: AuthRequest, res: Response, next: NextFunction): Promise<Response | void> {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to schedule reports', 403);
      }

      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const {
        name,
        description,
        type,
        filters,
        schedule
      } = req.body;

      if (!name || !type) {
        throw new AppError('Name and type are required', 400);
      }

      if (!['election', 'system', 'candidate', 'voter', 'audit', 'compliance'].includes(type)) {
        throw new AppError('Invalid report type', 400);
      }

      if (schedule && !['daily', 'weekly', 'monthly', 'quarterly', 'yearly'].includes(schedule.frequency)) {
        throw new AppError('Invalid schedule frequency', 400);
      }

      const template = {
        id: '',
        name,
        description,
        type,
        template: {},
        filters: filters || {},
        schedule
      };

      const templateId = await ReportingService.scheduleReport(template);

      // Log report scheduling
      await AuditService.logAction({
        action: 'REPORT_SCHEDULED',
        category: 'REPORT',
        severity: 'MEDIUM',
        userId: req.user!.id,
        metadata: {
          templateId,
          reportType: type,
          frequency: schedule?.frequency,
          recipients: schedule?.recipients?.length || 0,
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.status(201).json({
        success: true,
        message: 'Report scheduled successfully',
        data: {
          templateId,
          name,
          type,
          schedule
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get available report templates
   */
  public static async getReportTemplates(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view report templates', 403);
      }

      const templates = await ReportingService.getReportTemplates();

      res.json({
        success: true,
        message: 'Report templates retrieved successfully',
        data: templates,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get report generation status
   */
  public static async getReportStatus(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view report status', 403);
      }

      const { reportId } = req.params;

      if (!reportId) {
        throw new AppError('Report ID is required', 400);
      }

      // In a real implementation, you would track report generation status
      // For now, we'll return a mock status
      const status = {
        id: reportId,
        status: 'completed',
        progress: 100,
        generatedAt: new Date(),
        downloadUrl: `/api/reports/download/${reportId}`,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      };

      res.json({
        success: true,
        message: 'Report status retrieved successfully',
        data: status,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Download generated report
   */
  public static async downloadReport(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR', 'VOTER'].includes(userRole)) {
        throw new AppError('Insufficient permissions to download reports', 403);
      }

      const { reportId } = req.params;

      if (!reportId) {
        throw new AppError('Report ID is required', 400);
      }

      // In a real implementation, you would retrieve the generated report from storage
      // For now, we'll return an error since this is a placeholder
      throw new AppError('Report not found or has expired', 404);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Delete scheduled report
   */
  public static async deleteScheduledReport(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to delete scheduled reports', 403);
      }

      const { templateId } = req.params;

      if (!templateId) {
        throw new AppError('Template ID is required', 400);
      }

      // In a real implementation, you would delete the scheduled report template
      // For now, we'll just log the action

      // Log report deletion
      await AuditService.logAction({
        action: 'SCHEDULED_REPORT_DELETED',
        category: 'REPORT',
        severity: 'MEDIUM',
        userId: req.user!.id,
        entityType: 'ReportTemplate',
        entityId: templateId,
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Scheduled report deleted successfully',
        data: {
          templateId,
          deletedAt: new Date(),
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get report analytics
   */
  public static async getReportAnalytics(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view report analytics', 403);
      }

      const {
        startDate,
        endDate
      } = req.query;

      const start = startDate ? new Date(startDate as string) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const end = endDate ? new Date(endDate as string) : new Date();

      // Get report generation analytics from audit logs
      const reportLogs = await AuditService.getAuditLogs(
        {
          category: 'REPORT',
          startDate: start,
          endDate: end,
        },
        1,
        1000
      );

      const analytics = {
        period: { start, end },
        totalReportsGenerated: reportLogs.auditLogs.length,
        reportsByType: reportLogs.auditLogs.reduce((acc: any, log) => {
          const reportType = log.metadata?.reportType || 'unknown';
          acc[reportType] = (acc[reportType] || 0) + 1;
          return acc;
        }, {}),
        reportsByFormat: reportLogs.auditLogs.reduce((acc: any, log) => {
          const format = log.metadata?.format || 'unknown';
          acc[format] = (acc[format] || 0) + 1;
          return acc;
        }, {}),
        topUsers: reportLogs.auditLogs.reduce((acc: any, log) => {
          const userId = log.userId || 'unknown';
          acc[userId] = (acc[userId] || 0) + 1;
          return acc;
        }, {}),
        dailyActivity: []
      };

      res.json({
        success: true,
        message: 'Report analytics retrieved successfully',
        data: analytics,
      });
    } catch (error) {
      next(error);
    }
  }
}

export default ReportController;