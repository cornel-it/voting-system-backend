import { Request, Response, NextFunction } from 'express';
import { dashboardService } from '../services/dashboard.service';
import { auditService } from '../services/audit.service';
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

export class DashboardController {
  /**
   * Get voter dashboard data
   */
  public static async getVoterDashboard(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Check if user is authorized to view voter dashboard
      if (userRole !== UserRole.VOTER && !['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to access voter dashboard', 403);
      }

      // Parse filters from query parameters
      const filters: any = {
        dateRange: (req.query.startDate || req.query.endDate) ? {
          startDate: req.query.startDate ? new Date(req.query.startDate as string) : new Date(),
          endDate: req.query.endDate ? new Date(req.query.endDate as string) : new Date(),
        } : undefined,
        electionTypes: req.query.electionType ? [req.query.electionType as any] : undefined,
        faculties: req.query.faculty ? [req.query.faculty as string] : undefined,
        departments: req.query.department ? [req.query.department as string] : undefined,
      };

      // Check for cached data first
      const cachedData = await dashboardService.getCachedDashboardData(userId, userRole);
      if (cachedData && !req.query.refresh) {
        res.json({
          success: true,
          message: 'Voter dashboard data retrieved successfully (cached)',
          data: cachedData,
          cached: true,
        });
      }

      const dashboardData = await dashboardService.getVoterDashboard(userId, filters);

      // Cache the data
      await dashboardService.cacheDashboardData(userId, userRole, dashboardData);

      // Log dashboard access
      await auditService.logAction({
        action: 'VOTER_DASHBOARD_ACCESSED',
        category: 'USER',
        severity: 'LOW',
        userId,
        metadata: {
          filters,
          dataSource: 'live',
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Voter dashboard data retrieved successfully',
        data: dashboardData,
        cached: false,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get candidate dashboard data
   */
  public static async getCandidateDashboard(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Check if user is authorized to view candidate dashboard
      if (!['ADMIN', 'SUPER_ADMIN', 'VOTER'].includes(userRole)) {
        throw new AppError('Insufficient permissions to access candidate dashboard', 403);
      }

      // Check for cached data first
      const cachedData = await dashboardService.getCachedDashboardData(userId, UserRole.VOTER);
      if (cachedData && !req.query.refresh) {
        res.json({
          success: true,
          message: 'Candidate dashboard data retrieved successfully (cached)',
          data: cachedData,
          cached: true,
        });
      }

      const dashboardData = await dashboardService.getCandidateDashboard(userId);

      // Cache the data
      await dashboardService.cacheDashboardData(userId, UserRole.VOTER, dashboardData);

      // Log dashboard access
      await auditService.logAction({
        action: 'CANDIDATE_DASHBOARD_ACCESSED',
        category: 'CANDIDATE',
        severity: 'LOW',
        userId,
        metadata: {
          dataSource: 'live',
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Candidate dashboard data retrieved successfully',
        data: dashboardData,
        cached: false,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get admin dashboard data
   */
  public static async getAdminDashboard(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Check if user is authorized to view admin dashboard
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to access admin dashboard', 403);
      }

      // Check for cached data first
      const cachedData = await dashboardService.getCachedDashboardData(userId, userRole);
      if (cachedData && !req.query.refresh) {
        res.json({
          success: true,
          message: 'Admin dashboard data retrieved successfully (cached)',
          data: cachedData,
          cached: true,
        });
      }

      const dashboardData = await dashboardService.getAdminDashboard(userId);

      // Cache the data
      await dashboardService.cacheDashboardData(userId, userRole, dashboardData);

      // Log dashboard access
      await auditService.logAction({
        action: 'ADMIN_DASHBOARD_ACCESSED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId,
        metadata: {
          adminRole: userRole,
          dataSource: 'live',
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Admin dashboard data retrieved successfully',
        data: dashboardData,
        cached: false,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get real-time dashboard updates
   */
  public static async getDashboardUpdates(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const userId = req.user!.id;
      const userRole = req.user!.role;

      const updates = await dashboardService.getDashboardUpdates(userId, userRole);

      res.json({
        success: true,
        message: 'Dashboard updates retrieved successfully',
        data: updates,
        timestamp: new Date(),
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Refresh dashboard cache
   */
  public static async refreshDashboardCache(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Get fresh data based on user role
      let dashboardData;

      if (userRole === UserRole.VOTER) {
        dashboardData = await dashboardService.getVoterDashboard(userId);
      } else if (['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        dashboardData = await dashboardService.getAdminDashboard(userId);
      } else {
        // Try to get candidate dashboard for other roles
        dashboardData = await dashboardService.getCandidateDashboard(userId);
      }

      // Update cache
      await dashboardService.cacheDashboardData(userId, userRole, dashboardData);

      // Log cache refresh
      await auditService.logAction({
        action: 'DASHBOARD_CACHE_REFRESHED',
        category: 'SYSTEM',
        severity: 'LOW',
        userId,
        metadata: {
          userRole,
          refreshTime: new Date(),
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      res.json({
        success: true,
        message: 'Dashboard cache refreshed successfully',
        data: dashboardData,
        refreshedAt: new Date(),
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get dashboard statistics summary
   */
  public static async getDashboardStats(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Parse filters from query parameters
      const filters = {
        startDate: req.query.startDate ? new Date(req.query.startDate as string) : undefined,
        endDate: req.query.endDate ? new Date(req.query.endDate as string) : undefined,
        electionType: req.query.electionType as any,
      };

      let stats;

      if (userRole === UserRole.VOTER) {
        const voterData = await dashboardService.getVoterDashboard(userId, filters as any);
        stats = {
          type: 'voter',
          totalElections: voterData.eligibleElections.length,
          participationRate: voterData.statistics.participationRate,
          lastVoteDate: voterData.statistics.lastVoteDate,
          totalNotifications: voterData.notifications.length,
          unreadNotifications: voterData.notifications.filter(n => !n.read).length,
        };
      } else if (['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        const adminData = await dashboardService.getAdminDashboard(userId);
        stats = {
          type: 'admin',
          totalUsers: adminData.overview.totalUsers,
          totalElections: adminData.overview.totalElections,
          totalVotes: adminData.overview.totalVotes,
          activeElections: adminData.overview.activeElections,
          systemHealth: adminData.system.overall,
          pendingCandidates: adminData.overview.pendingCandidates,
        };
      } else {
        const candidateData = await dashboardService.getCandidateDashboard(userId);
        stats = {
          type: 'candidate',
          totalApplications: candidateData.applications.length,
          approvedApplications: candidateData.applications.filter(app => app.status === 'APPROVED').length,
          totalCampaigns: candidateData.campaigns.length,
          totalNotifications: candidateData.notifications.length,
          unreadNotifications: candidateData.notifications.filter(n => !n.read).length,
        };
      }

      res.json({
        success: true,
        message: 'Dashboard statistics retrieved successfully',
        data: stats,
        generatedAt: new Date(),
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get dashboard notifications
   */
  public static async getDashboardNotifications(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const userId = req.user!.id;
      const userRole = req.user!.role;
      const { limit = 10, offset = 0, unreadOnly = false } = req.query;

      // Get notifications based on user role
      let dashboardData;

      if (userRole === UserRole.VOTER) {
        dashboardData = await dashboardService.getVoterDashboard(userId);
      } else if (['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        dashboardData = await dashboardService.getAdminDashboard(userId);
      } else {
        dashboardData = await dashboardService.getCandidateDashboard(userId);
      }

      let notifications = (dashboardData as any).notifications || [];

      // Filter unread only if requested
      if (unreadOnly === 'true') {
        notifications = notifications.filter((n: any) => !n.read);
      }

      // Apply pagination
      const startIndex = parseInt(offset as string);
      const limitNum = parseInt(limit as string);
      const paginatedNotifications = notifications.slice(startIndex, startIndex + limitNum);

      res.json({
        success: true,
        message: 'Dashboard notifications retrieved successfully',
        data: {
          notifications: paginatedNotifications,
          pagination: {
            total: notifications.length,
            limit: limitNum,
            offset: startIndex,
            hasMore: startIndex + limitNum < notifications.length,
          },
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Export dashboard data
   */
  public static async exportDashboardData(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
      }

      const userId = req.user!.id;
      const userRole = req.user!.role;
      const { format = 'json' } = req.query;

      if (!['json', 'csv'].includes(format as string)) {
        throw new AppError('Invalid format. Supported: json, csv', 400);
      }

      // Get dashboard data based on role
      let dashboardData;
      let exportType;

      if (userRole === UserRole.VOTER) {
        dashboardData = await dashboardService.getVoterDashboard(userId);
        exportType = 'voter';
      } else if (['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        dashboardData = await dashboardService.getAdminDashboard(userId);
        exportType = 'admin';
      } else {
        dashboardData = await dashboardService.getCandidateDashboard(userId);
        exportType = 'candidate';
      }

      // Log export action
      await auditService.logAction({
        action: 'DASHBOARD_DATA_EXPORTED',
        category: 'USER',
        severity: 'MEDIUM',
        userId,
        metadata: {
          exportType,
          format,
          timestamp: new Date(),
        },
        ipAddress: req.ipAddress,
        userAgent: req.userAgent,
      });

      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="${exportType}_dashboard_${new Date().toISOString().split('T')[0]}.json"`
        );
        res.json(dashboardData);
      } else {
        // CSV format would require additional processing
        // For now, we'll return JSON with a message about CSV support
        res.json({
          success: false,
          message: 'CSV export not yet implemented. Please use JSON format.',
          data: null,
        });
      }
    } catch (error) {
      next(error);
    }
  }
}

export default DashboardController;