// backend/src/controllers/voter.controller.ts

import { Request, Response, NextFunction } from 'express';
import { VoterService } from '../services/voter.service';
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

export class VoterController {
  private voterService = VoterService.getInstance();

  /**
   * Register a new voter
   */
  async registerVoter(req: Request, res: Response, next: NextFunction): Promise<Response | void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const voterData = req.body;

      // Register voter with comprehensive validation
      const result = await this.voterService.registerVoter(voterData);

      // Log registration
      await AuditService.logAction({
        action: 'VOTER_REGISTERED',
        category: 'VOTER',
        severity: 'LOW',
        metadata: {
          studentId: result.voter.studentId,
          email: result.voter.email,
          faculty: result.voter.faculty,
          department: result.voter.department
        },
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      });

      res.status(201).json({
        success: true,
        message: 'Voter registered successfully. Please check your email for verification.',
        data: {
          id: result.voter.id,
          studentId: result.voter.studentId,
          email: result.voter.email,
          firstName: result.voter.firstName,
          lastName: result.voter.lastName,
          isVerified: result.voter.isVerified
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voter profile
   */
  async getVoterProfile(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;

      // Get comprehensive voter profile
      const profile = await this.voterService.getVoterProfile(userId);

      res.json({
        success: true,
        message: 'Voter profile retrieved successfully',
        data: profile
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update voter profile
   */
  async updateVoterProfile(req: AuthRequest, res: Response, next: NextFunction): Promise<Response | void> {
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
      const updates = req.body;

      // Prevent updating sensitive fields
      delete updates.studentId;
      delete updates.email;
      delete updates.role;
      delete updates.permissions;
      delete updates.isVerified;
      delete updates.isActive;

      // Update voter profile
      const updatedProfile = await this.voterService.updateVoterProfile(userId, updates);

      // Log profile update
      await AuditService.logAction({
        action: 'VOTER_PROFILE_UPDATED',
        category: 'VOTER',
        severity: 'LOW',
        userId,
        metadata: {
          updatedFields: Object.keys(updates)
        }
      });

      res.json({
        success: true,
        message: 'Voter profile updated successfully',
        data: updatedProfile
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Upload voter profile picture
   */
  async uploadProfilePicture(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;

      if (!req.file) {
        throw new AppError('Profile picture file is required', 400);
      }

      // Upload and process profile picture
      const result = await this.voterService.uploadProfilePicture(userId, req.file);

      res.json({
        success: true,
        message: 'Profile picture uploaded successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voter eligibility for an election
   */
  async checkElectionEligibility(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;
      const { electionId } = req.params;

      if (!electionId) {
        throw new AppError('Election ID is required', 400);
      }

      // Check comprehensive eligibility
      const eligibility = await this.voterService.checkElectionEligibility(userId, electionId);

      res.json({
        success: true,
        message: 'Eligibility check completed',
        data: eligibility
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voter's voting history
   */
  async getVotingHistory(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;
      const {
        page = 1,
        limit = 10,
        electionType,
        fromDate,
        toDate,
        includeDetails = false
      } = req.query;

      // Get comprehensive voting history
      const history = await this.voterService.getVotingHistory(
        userId,
        {
          electionType: electionType as string,
          fromDate: fromDate ? new Date(fromDate as string) : undefined,
          toDate: toDate ? new Date(toDate as string) : undefined,
        },
        Number(page),
        Number(limit)
      );

      res.json({
        success: true,
        message: 'Voting history retrieved successfully',
        data: history
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voter statistics (Admin/Moderator only)
   */
  async getVoterStatistics(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view voter statistics', 403);
      }

      const {
        faculty,
        department,
        yearOfStudy,
        admissionYear,
        period = 'all'
      } = req.query;

      // Get comprehensive voter statistics
      const stats = await this.voterService.getVoterStatisticsWithFilters({
        faculty: faculty as string,
        department: department as string,
        yearOfStudy: yearOfStudy ? Number(yearOfStudy) : undefined,
        admissionYear: admissionYear ? Number(admissionYear) : undefined,
        period: period as string
      });

      res.json({
        success: true,
        message: 'Voter statistics retrieved successfully',
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Search voters (Admin/Moderator only)
   */
  async searchVoters(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to search voters', 403);
      }

      const {
        search,
        faculty,
        department,
        course,
        yearOfStudy,
        admissionYear,
        isVerified,
        isActive,
        hasVoted,
        electionId,
        page = 1,
        limit = 50,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query;

      // Search voters with filters
      const results = await this.voterService.searchVoters({
        search: search as string,
        faculty: faculty as string,
        department: department as string,
        course: course as string,
        yearOfStudy: yearOfStudy ? Number(yearOfStudy) : undefined,
        admissionYear: admissionYear ? Number(admissionYear) : undefined,
        isVerified: isVerified === 'true' ? true : isVerified === 'false' ? false : undefined,
        isActive: isActive === 'true' ? true : isActive === 'false' ? false : undefined,
        hasVoted: hasVoted === 'true' ? true : hasVoted === 'false' ? false : undefined,
        electionId: electionId as string,
        page: Number(page),
        limit: Number(limit),
        sortBy: sortBy as string,
        sortOrder: sortOrder as 'asc' | 'desc'
      });

      res.json({
        success: true,
        message: 'Voter search completed successfully',
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update voter status (Admin only)
   */
  async updateVoterStatus(req: AuthRequest, res: Response, next: NextFunction): Promise<Response | void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { id } = req.params;
      const { status, reason, suspensionEndDate } = req.body;
      const adminId = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to update voter status', 403);
      }

      if (!id) {
        throw new AppError('Voter ID is required', 400);
      }

      // Update voter status
      const result = await this.voterService.updateVoterStatus(id, {
        status,
        reason,
        suspensionEndDate: suspensionEndDate ? new Date(suspensionEndDate) : undefined,
        updatedBy: adminId
      });

      // Log status update
      await AuditService.logAction({
        action: 'VOTER_STATUS_UPDATED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: adminId,
        metadata: {
          targetVoterId: id,
          newStatus: status,
          reason,
          suspensionEndDate
        }
      });

      res.json({
        success: true,
        message: 'Voter status updated successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify voter email
   */
  async verifyEmail(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.params;

      if (!token) {
        throw new AppError('Verification token is required', 400);
      }

      // Verify email with token
      const result = await this.voterService.verifyEmail(token);

      res.json({
        success: true,
        message: 'Email verified successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Resend email verification
   */
  async resendEmailVerification(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;

      // Resend verification email
      await this.voterService.resendEmailVerification(userId);

      res.json({
        success: true,
        message: 'Verification email sent successfully'
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Update voter preferences
   */
  async updatePreferences(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;
      const preferences = req.body;

      // Update voter preferences
      const result = await this.voterService.updatePreferences(userId, preferences);

      res.json({
        success: true,
        message: 'Preferences updated successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voter preferences
   */
  async getPreferences(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user!.id;

      // Get voter preferences
      const preferences = await this.voterService.getPreferences(userId);

      res.json({
        success: true,
        message: 'Preferences retrieved successfully',
        data: preferences
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Import voters from file (Admin only)
   */
  async importVoters(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;
      const adminId = req.user!.id;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to import voters', 403);
      }

      if (!req.file) {
        throw new AppError('Import file is required', 400);
      }

      const { format, overwriteExisting = false, sendWelcomeEmails = true } = req.body;

      // Import voters from file
      const result = await this.voterService.importVoters(req.file, {
        format,
        overwriteExisting: overwriteExisting === 'true',
        sendWelcomeEmails: sendWelcomeEmails === 'true',
        importedBy: adminId
      });

      // Log import operation
      await AuditService.logAction({
        action: 'VOTERS_IMPORTED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: adminId,
        metadata: {
          fileName: req.file.originalname,
          totalRecords: result.totalRecords,
          successfulImports: result.successfulImports,
          failedImports: result.failedImports,
          format
        }
      });

      res.json({
        success: true,
        message: 'Voters imported successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Bulk import voters from parsed JSON data (Admin only)
   */
  async bulkImportVoters(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;
      const adminId = req.user!.id;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to import voters', 403);
      }

      const { voters, options } = req.body;

      if (!voters || !Array.isArray(voters) || voters.length === 0) {
        throw new AppError('Voters array is required and must not be empty', 400);
      }

      if (voters.length > 1000) {
        throw new AppError('Maximum 1000 voters can be imported at once', 400);
      }

      // Perform bulk import
      const result = await this.voterService.bulkImportVotersData({
        voters,
        options: {
          overwriteExisting: options?.overwriteExisting || false,
          sendWelcomeEmails: options?.sendWelcomeEmails || true,
          defaultPassword: options?.defaultPassword,
          importedBy: adminId
        }
      });

      // Log import operation
      await AuditService.logAction({
        action: 'VOTERS_BULK_IMPORTED',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: adminId,
        metadata: {
          totalRecords: result.totalRecords,
          successfulImports: result.successfulImports,
          failedImports: result.failedImports
        }
      });

      res.json({
        success: true,
        message: 'Voters imported successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Export voters data (Admin only)
   */
  async exportVoters(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;
      const adminId = req.user!.id;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to export voters', 403);
      }

      const {
        format = 'csv',
        includePersonalData = false,
        includeVotingHistory = false,
        includeStatistics = false,
        faculty,
        department,
        yearOfStudy,
        status
      } = req.query;

      // Export voters data
      const exportData = await this.voterService.exportVoters({
        format: format as string,
        includePersonalData: includePersonalData === 'true',
        includeVotingHistory: includeVotingHistory === 'true',
        includeStatistics: includeStatistics === 'true',
        filters: {
          faculty: faculty as string,
          department: department as string,
          yearOfStudy: yearOfStudy ? Number(yearOfStudy) : undefined,
          status: status as string
        },
        exportedBy: adminId
      });

      // Log export operation
      await AuditService.logAction({
        action: 'VOTERS_EXPORTED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: adminId,
        metadata: {
          format,
          includePersonalData,
          includeVotingHistory,
          recordCount: exportData.recordCount
        }
      });

      // Set appropriate headers for file download
      res.setHeader('Content-Type', exportData.mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${exportData.filename}"`);

      if (format === 'json') {
        res.json({
          success: true,
          data: exportData.data
        });
      } else {
        res.send(exportData.buffer);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Bulk operations on voters (Admin only)
   */
  async bulkVoterOperations(req: AuthRequest, res: Response, next: NextFunction): Promise<Response | void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const userRole = req.user!.role;
      const adminId = req.user!.id;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions for bulk operations', 403);
      }

      const { operation, voterIds, reason, suspensionEndDate } = req.body;

      if (!operation || !voterIds || !Array.isArray(voterIds)) {
        throw new AppError('Operation and voter IDs are required', 400);
      }

      if (voterIds.length === 0 || voterIds.length > 1000) {
        throw new AppError('Voter IDs array must contain 1-1000 items', 400);
      }

      // Perform bulk operation
      const result = await this.voterService.bulkVoterOperations({
        operation,
        voterIds,
        reason,
        suspensionEndDate: suspensionEndDate ? new Date(suspensionEndDate) : undefined,
        operatedBy: adminId
      });

      // Log bulk operation
      await AuditService.logAction({
        action: 'BULK_VOTER_OPERATION',
        category: 'ADMIN',
        severity: 'HIGH',
        userId: adminId,
        metadata: {
          operation,
          voterCount: voterIds.length,
          successfulOperations: result.successfulOperations,
          failedOperations: result.failedOperations,
          reason
        }
      });

      res.json({
        success: true,
        message: `Bulk ${operation} operation completed`,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get voter by ID (Admin/Moderator only)
   */
  async getVoterById(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const userRole = req.user!.role;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN', 'MODERATOR'].includes(userRole)) {
        throw new AppError('Insufficient permissions to view voter details', 403);
      }

      if (!id) {
        throw new AppError('Voter ID is required', 400);
      }

      // Get voter by ID with detailed information
      const voter = await this.voterService.getVoterById(id, {
        includeVotingHistory: true,
        includeEligibility: true,
        includeAuditLog: userRole === 'SUPER_ADMIN'
      });

      res.json({
        success: true,
        message: 'Voter details retrieved successfully',
        data: voter
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Delete voter account (Admin only)
   */
  async deleteVoter(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { reason, hardDelete = false } = req.body;
      const adminId = req.user!.id;
      const userRole = req.user!.role;

      // Check permissions - only super admin can hard delete
      if (userRole !== 'SUPER_ADMIN') {
        throw new AppError('Insufficient permissions to delete voters', 403);
      }

      if (!id) {
        throw new AppError('Voter ID is required', 400);
      }

      if (!reason || reason.trim().length < 10) {
        throw new AppError('Detailed reason is required (minimum 10 characters)', 400);
      }

      // Delete voter account
      const result = await this.voterService.deleteVoter(id, {
        reason,
        hardDelete: hardDelete === true,
        deletedBy: adminId
      });

      // Log deletion
      await AuditService.logAction({
        action: 'VOTER_DELETED',
        category: 'ADMIN',
        severity: 'CRITICAL',
        userId: adminId,
        metadata: {
          deletedVoterId: id,
          reason,
          hardDelete,
          voterStudentId: result.studentId
        }
      });

      res.json({
        success: true,
        message: 'Voter account deleted successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate voter analytics report (Admin only)
   */
  async generateAnalyticsReport(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userRole = req.user!.role;
      const adminId = req.user!.id;

      // Check permissions
      if (!['ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
        throw new AppError('Insufficient permissions to generate analytics reports', 403);
      }

      const {
        reportType = 'comprehensive',
        period = 'last_30_days',
        includeCharts = true,
        format = 'pdf'
      } = req.query;

      // Generate analytics report
      const report = await this.voterService.generateAnalyticsReport({
        reportType: reportType as string,
        period: period as string,
        includeCharts: includeCharts === 'true',
        format: format as string,
        generatedBy: adminId
      });

      // Log report generation
      await AuditService.logAction({
        action: 'ANALYTICS_REPORT_GENERATED',
        category: 'ADMIN',
        severity: 'MEDIUM',
        userId: adminId,
        metadata: {
          reportType,
          period,
          format,
          reportSize: report.size
        }
      });

      if (format === 'json') {
        res.json({
          success: true,
          data: report.data
        });
      } else {
        res.setHeader('Content-Type', report.mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
        res.send(report.buffer);
      }
    } catch (error) {
      next(error);
    }
  }
}